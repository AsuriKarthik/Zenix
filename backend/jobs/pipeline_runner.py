"""
Pipeline Runner — executes the end-to-end SBOM analysis pipeline for a job.

Steps executed:
  1. Parse CycloneDX JSON SBOM -> Component rows
  2. Reachability resolution (psutil + optional ETW)
  3. For each Component -> query CVE matcher (OSV + NVD) -> Vulnerability rows
  4. For each Vulnerability -> enrich via EPSS & KEV -> update Vulnerability fields
  5. Compute deterministic RiskScore for each Vulnerability -> RiskScore rows
  6. Generate CycloneDX VEX documents
  7. Finalize Job status='done', persist result summary in result_json

All error states (parsing errors, API degradations, unexpected failures) update the
Job status and error fields explicitly in the database.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional, Any

from db import db, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore
from pipeline.sbom_parser import parse_cyclonedx_json, SBOMParseError
from pipeline.cve_matcher import find_cves_for_component, find_cves_for_components_batch, CVEMatch

from pipeline.enricher import enrich_cve, enrich_cves_batch
from pipeline.scorer import compute_risk_score
from pipeline.vex_generator import generate_vex_documents_for_job
from agents.reachability_resolver import resolve_reachability

log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def run_sbom_job(app: Any, job_id: str, sbom_bytes: bytes) -> None:
    """
    Execute full SBOM processing pipeline inside app context.

    Updates job status in database at each transition stage:
      - 'running' when started
      - 'done' on complete success
      - 'failed' on unhandled error or parse error (with detailed error_msg)
    """
    with app.app_context():
        job: Optional[Job] = db.session.get(Job, job_id)
        if not job:
            log.error("Pipeline runner invoked for non-existent job ID %s", job_id)
            return

        now = _utcnow()
        job.status = 'running'
        job.progress_pct = 5
        job.error_code = None
        job.error_msg = None
        job.started_at = now
        job.updated_at = now
        db.session.commit()

        pipeline_start = time.perf_counter()
        log.info("[Job %s] Pipeline started", job_id)

        try:
            _execute_pipeline(job, sbom_bytes)

            actual_job_id = getattr(job, 'id')

            # Generate and sign CycloneDX VEX documents for all findings
            vex_start = time.perf_counter()
            log.info("[Job %s] Stage: VEX generation — starting", job_id)
            generate_vex_documents_for_job(actual_job_id)
            log.info("[Job %s] Stage: VEX generation — done (%.2fs)", job_id, time.perf_counter() - vex_start)

            now_done = _utcnow()
            job.status = 'done'
            job.progress_pct = 100
            job.finished_at = now_done
            job.updated_at = now_done

            # Set versioned SBOM baseline tag (v1, v2, v3, etc.)
            try:
                user_job_count = Job.query.filter_by(status='done').count()
                job.sbom_version_tag = f"v{user_job_count + 1}"
            except Exception:
                job.sbom_version_tag = "v1"

            # Reconcile existing persistent RuntimeInventory entries against new SBOM
            try:
                from agents.reachability_resolver import reconcile_runtime_inventory_with_sbom
                reconcile_runtime_inventory_with_sbom(actual_job_id)
            except Exception as rec_err:
                log.warning("Post-scan runtime inventory reconciliation error: %s", rec_err)

            # Build result summary snapshot
            job.result_json = json.dumps(_build_job_result_summary(actual_job_id))
            db.session.commit()

            total_elapsed = max(time.perf_counter() - pipeline_start, 0.001)
            comp_cnt = job.component_count
            throughput = comp_cnt / total_elapsed
            log.info("[Job %s] Pipeline completed successfully in %.2fs (Throughput: %.1f components/sec)",
                     actual_job_id, total_elapsed, throughput)

        except SBOMParseError as parse_err:
            db.session.rollback()
            job = db.session.get(Job, job_id)
            if job:
                now_fail = _utcnow()
                job.status = 'failed'
                job.error_code = 'PARSER_ERROR'
                job.error_msg = f"SBOM Parse Error: {parse_err}"
                job.finished_at = now_fail
                job.updated_at = now_fail
                db.session.commit()
            log.warning("[Job %s] Failed due to SBOMParseError: %s", job_id, parse_err)

        except Exception as exc:
            db.session.rollback()
            job = db.session.get(Job, job_id)
            if job:
                now_fail = _utcnow()
                job.status = 'failed'
                err_str = str(exc)
                code = 'API_TIMEOUT' if 'timeout' in err_str.lower() or 'timed out' in err_str.lower() else 'PIPELINE_ERROR'
                job.error_code = code
                job.error_msg = f"Pipeline failure ({code}): {err_str}"
                job.finished_at = now_fail
                job.updated_at = now_fail
                db.session.commit()
            log.exception("[Job %s] Unhandled error after %.2fs", job_id, time.perf_counter() - pipeline_start)


def _execute_pipeline(job: Job, sbom_bytes: bytes) -> None:
    """Core steps of the pipeline with per-stage timing and progress updates."""
    job_id = getattr(job, 'id')

    # ── Step 1: Parse SBOM ───────────────────────────────────────────────────
    t0 = time.perf_counter()
    log.info("[Job %s] Stage 1: SBOM Parse — starting", job_id)
    parsed_components = parse_cyclonedx_json(sbom_bytes)
    log.info("[Job %s] Stage 1: SBOM Parse — done, %d components (%.2fs)",
             job_id, len(parsed_components), time.perf_counter() - t0)

    unscannable_count = 0
    component_models: list[Component] = []
    for parsed in parsed_components:
        is_scannable = True
        reason = None
        if not parsed.name or not parsed.name.strip():
            is_scannable = False
            reason = "Malformed component name"
            unscannable_count += 1

        comp = Component(
            job_id=job_id,
            name=parsed.name or "unnamed-component",
            version=parsed.version,
            purl=parsed.purl,
            ecosystem=parsed.ecosystem,
            file_hash=parsed.file_hash,
            is_scannable=is_scannable,
            unscannable_reason=reason,
        )
        db.session.add(comp)
        component_models.append(comp)

    db.session.flush()  # assign IDs to component_models

    job.progress_pct = 20
    job.unscannable_count = unscannable_count
    job.updated_at = _utcnow()
    db.session.commit()

    # ── Step 2: Reachability Resolution (psutil + optional ETW) ───────────────
    t1 = time.perf_counter()
    log.info("[Job %s] Stage 2: Reachability Resolution — starting (psutil scan, up to 20s timeout)", job_id)
    reachability_map = resolve_reachability(component_models)
    log.info("[Job %s] Stage 2: Reachability Resolution — done (%.2fs)", job_id, time.perf_counter() - t1)

    job.progress_pct = 40
    job.updated_at = _utcnow()
    db.session.commit()

    # ── Step 3: High-Performance OSV Batch CVE Matching ─────────────────────
    t3 = time.perf_counter()
    log.info("[Job %s] Stage 3: Batch CVE Matching for %d components — starting", job_id, len(component_models))

    components_metadata = [
        {
            'name': getattr(c, 'name'),
            'version': getattr(c, 'version'),
            'purl': getattr(c, 'purl'),
            'ecosystem': getattr(c, 'ecosystem'),
        }
        for c in component_models
    ]

    all_batch_cve_matches = find_cves_for_components_batch(components_metadata)

    comp_matches: list[tuple[Component, ReachabilityVerdict, list[CVEMatch]]] = []
    all_cve_ids: list[str] = []

    for idx, comp in enumerate(component_models):
        comp_id_val = getattr(comp, 'id')
        verdict = reachability_map.get(comp_id_val)
        if not verdict:
            verdict = ReachabilityVerdict(
                component_id=comp_id_val,
                status='UNKNOWN',
                confidence='low',
                evidence_source='none',
                matched_event_ids_json='[]',
                raw_evidence_json='{}',
                determined_at=_utcnow(),
            )
            db.session.add(verdict)
            db.session.flush()

        cve_matches = all_batch_cve_matches[idx] if idx < len(all_batch_cve_matches) else []
        comp_matches.append((comp, verdict, cve_matches))
        for m in cve_matches:
            all_cve_ids.append(m.cve_id)

    job.progress_pct = 70
    job.updated_at = _utcnow()
    db.session.commit()
    log.info("[Job %s] Stage 3: Batch CVE Matching — done, %d total CVEs collected (%.2fs)", job_id, len(all_cve_ids), time.perf_counter() - t3)

    # Batch enrich all collected CVEs at once
    t_enrich = time.perf_counter()
    log.info("[Job %s] Stage 4: Batch EPSS & KEV Enrichment for %d CVEs — starting", job_id, len(all_cve_ids))
    enrichment_map = enrich_cves_batch(all_cve_ids)
    log.info("[Job %s] Stage 4: Batch EPSS & KEV Enrichment — done (%.2fs)", job_id, time.perf_counter() - t_enrich)

    job.progress_pct = 85
    job.updated_at = _utcnow()
    db.session.commit()

    # Score vulnerabilities
    total_vulns = 0
    for comp, verdict, cve_matches in comp_matches:

        comp_id_val = getattr(comp, 'id')
        verdict_status = getattr(verdict, 'status', 'UNKNOWN')
        verdict_evidence_source = getattr(verdict, 'evidence_source', 'none')

        for match in cve_matches:
            enrichment = enrichment_map.get(match.cve_id)
            if not enrichment:
                enrichment = enrich_cve(match.cve_id)

            # Merge degradation notes
            all_degradation_notes = list(match.degradation_notes) + list(enrichment.degradation_notes)

            vuln = Vulnerability(
                cve_id=match.cve_id,
                component_id=comp_id_val,
                cvss=match.cvss,
                cvss_version=getattr(match, 'cvss_version', None),
                cvss_severity=getattr(match, 'cvss_severity', None),
                cvss_vector=match.cvss_vector,
                epss=enrichment.epss,
                epss_percentile=enrichment.epss_percentile,
                is_kev=enrichment.is_kev,
                kev_status=enrichment.kev_status,
                description=match.description,
                source=match.source,
                cvss_source=getattr(match, 'cvss_source', 'NVD'),
                epss_source='FIRST EPSS',
                kev_source='CISA KEV',
                runtime_source=verdict_evidence_source,
                data_quality=match.data_quality if not all_degradation_notes else 'degraded',
                degradation_notes_json=json.dumps(all_degradation_notes),
                nvd_fetched_at=match.nvd_fetched_at,
                epss_fetched_at=enrichment.epss_fetched_at,
                kev_cached_at=_utcnow(),
                shodan_exposed_hosts=enrichment.shodan_exposed_hosts,
                virustotal_detections=enrichment.virustotal_detections,
            )
            db.session.add(vuln)
            db.session.flush()  # assign vuln.id

            vuln_id_val = getattr(vuln, 'id')

            # Score risk deterministically
            scoring = compute_risk_score(
                cvss=match.cvss,
                epss=enrichment.epss,
                is_kev=enrichment.is_kev,
                kev_status=enrichment.kev_status,
                reachability_status=verdict_status,
                evidence_source=verdict_evidence_source,
                epss_reason=getattr(enrichment, 'epss_reason', None),
                epss_next_action=getattr(enrichment, 'epss_next_action', None),
                kev_reason=getattr(enrichment, 'kev_reason', None),
                kev_next_action=getattr(enrichment, 'kev_next_action', None),
            )

            score_record = RiskScore(
                vulnerability_id=vuln_id_val,
                cvss_input=scoring.cvss_input,
                epss_input=scoring.epss_input,
                kev_input=scoring.kev_input,
                reachability_input=scoring.reachability_input,
                evidence_source=scoring.evidence_source,
                cvss_contrib=scoring.cvss_contrib,
                epss_contrib=scoring.epss_contrib,
                kev_contrib=scoring.kev_contrib,
                base_score=scoring.base_score,
                reachability_multiplier=scoring.reachability_multiplier,
                final_score=scoring.final_score,
                confidence=scoring.confidence,
                confidence_notes_json=json.dumps(scoring.confidence_notes),
                reason=scoring.reason,
                scored_at=_utcnow(),
            )
            db.session.add(score_record)
            total_vulns += 1

        # Heartbeat per component processing
        job.updated_at = _utcnow()
        db.session.commit()

    log.info("[Job %s] Stage 3-5: All %d components processed, %d total vulnerabilities scored",
             job_id, len(component_models), total_vulns)


def _build_job_result_summary(job_id: str) -> dict[str, Any]:
    """Build summary dictionary of job execution results."""
    components = db.session.query(Component).filter_by(job_id=job_id).all()
    comp_ids = [getattr(c, 'id') for c in components]

    vulns = db.session.query(Vulnerability).filter(Vulnerability.component_id.in_(comp_ids)).all() if comp_ids else []
    vuln_ids = [getattr(v, 'id') for v in vulns]

    scores = db.session.query(RiskScore).filter(RiskScore.vulnerability_id.in_(vuln_ids)).all() if vuln_ids else []

    high_risk = sum(1 for s in scores if getattr(s, 'final_score', 0.0) >= 7.0)
    medium_risk = sum(1 for s in scores if 4.0 <= getattr(s, 'final_score', 0.0) < 7.0)
    low_risk = sum(1 for s in scores if getattr(s, 'final_score', 0.0) < 4.0)

    degraded_vulns = sum(1 for v in vulns if getattr(v, 'data_quality') == 'degraded')

    return {
        "component_count": len(components),
        "vulnerability_count": len(vulns),
        "high_risk_count": high_risk,
        "medium_risk_count": medium_risk,
        "low_risk_count": low_risk,
        "degraded_data_count": degraded_vulns,
    }
