"""
Pipeline Runner — executes the end-to-end SBOM analysis pipeline for a job.

Steps executed:
  1. Parse CycloneDX JSON SBOM -> Component rows
  2. For each Component -> query CVE matcher (OSV + NVD) -> Vulnerability rows
  3. For each Vulnerability -> enrich via EPSS & KEV -> update Vulnerability fields
  4. Create baseline ReachabilityVerdict (status='UNKNOWN', evidence_source='none')
  5. Compute deterministic RiskScore for each Vulnerability -> RiskScore rows
  6. Finalize Job status='done', persist result summary in result_json

All error states (parsing errors, API degradations, unexpected failures) update the
Job status and error fields explicitly in the database.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from db import db, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore
from pipeline.sbom_parser import parse_cyclonedx_json, SBOMParseError
from pipeline.cve_matcher import find_cves_for_component
from pipeline.enricher import enrich_cve
from pipeline.scorer import compute_risk_score

log = logging.getLogger(__name__)

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def run_sbom_job(app, job_id: str, sbom_bytes: bytes) -> None:
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
        job.started_at = now
        job.updated_at = now
        db.session.commit()

        try:
            _execute_pipeline(job, sbom_bytes)

            # Generate and sign CycloneDX VEX documents for all findings
            from pipeline.vex_generator import generate_vex_documents_for_job
            generate_vex_documents_for_job(job.id)

            now_done = _utcnow()
            job.status = 'done'
            job.finished_at = now_done
            job.updated_at = now_done

            # Build result summary snapshot
            job.result_json = json.dumps(_build_job_result_summary(job.id))
            db.session.commit()
            log.info("Job %s completed successfully", job.id)

        except SBOMParseError as parse_err:
            db.session.rollback()
            job = db.session.get(Job, job_id)
            if job:
                now_fail = _utcnow()
                job.status = 'failed'
                job.error_msg = f"SBOM Parse Error: {parse_err}"
                job.finished_at = now_fail
                job.updated_at = now_fail
                db.session.commit()
            log.warning("Job %s failed due to SBOMParseError: %s", job_id, parse_err)

        except Exception as exc:
            db.session.rollback()
            job = db.session.get(Job, job_id)
            if job:
                now_fail = _utcnow()
                job.status = 'failed'
                job.error_msg = f"Pipeline failure: {str(exc)}"
                job.finished_at = now_fail
                job.updated_at = now_fail
                db.session.commit()
            log.exception("Unhandled error processing job %s", job_id)


def _execute_pipeline(job: Job, sbom_bytes: bytes) -> None:
    """Core steps of the pipeline."""
    # ── Step 1: Parse SBOM ───────────────────────────────────────────────────
    parsed_components = parse_cyclonedx_json(sbom_bytes)

    component_models: list[Component] = []
    for parsed in parsed_components:
        comp = Component(
            job_id=job.id,
            name=parsed.name,
            version=parsed.version,
            purl=parsed.purl,
            ecosystem=parsed.ecosystem,
            file_hash=parsed.file_hash,
        )
        db.session.add(comp)
        component_models.append(comp)

    db.session.flush()  # assign IDs to component_models

    # Update job timestamp
    job.updated_at = _utcnow()
    db.session.commit()

    # ── Step 2: Reachability Resolution (psutil + optional ETW tier) ───────────
    from agents.reachability_resolver import resolve_reachability
    reachability_map = resolve_reachability(component_models)

    for comp in component_models:
        verdict = reachability_map.get(comp.id)
        if not verdict:
            verdict = ReachabilityVerdict(
                component_id=comp.id,
                status='UNKNOWN',
                confidence='low',
                evidence_source='none',
                matched_event_ids_json='[]',
                raw_evidence_json='{}',
                determined_at=_utcnow(),
            )
        db.session.add(verdict)
        db.session.flush()

        # Match CVEs
        cve_matches = find_cves_for_component(
            name=comp.name,
            version=comp.version,
            purl=comp.purl,
            ecosystem=comp.ecosystem,
        )

        for match in cve_matches:
            # Enrich CVE with EPSS + KEV
            enrichment = enrich_cve(match.cve_id)

            # Merge degradation notes
            all_degradation_notes = list(match.degradation_notes) + list(enrichment.degradation_notes)

            vuln = Vulnerability(
                cve_id=match.cve_id,
                component_id=comp.id,
                cvss=match.cvss,
                cvss_vector=match.cvss_vector,
                epss=enrichment.epss,
                epss_percentile=enrichment.epss_percentile,
                is_kev=enrichment.is_kev,
                kev_status=enrichment.kev_status,
                description=match.description,
                source=match.source,
                data_quality=match.data_quality if not all_degradation_notes else 'degraded',
                degradation_notes_json=json.dumps(all_degradation_notes),
                nvd_fetched_at=match.nvd_fetched_at,
                epss_fetched_at=enrichment.epss_fetched_at,
                kev_cached_at=_utcnow(),
            )
            db.session.add(vuln)
            db.session.flush()  # assign vuln.id

            # Score risk deterministically
            scoring = compute_risk_score(
                cvss=match.cvss,
                epss=enrichment.epss,
                is_kev=enrichment.is_kev,
                kev_status=enrichment.kev_status,
                reachability_status=verdict.status,
                evidence_source=verdict.evidence_source,
            )

            score_record = RiskScore(
                vulnerability_id=vuln.id,
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

        # Heartbeat per component processing
        job.updated_at = _utcnow()
        db.session.commit()


def _build_job_result_summary(job_id: str) -> dict:
    """Build summary dictionary of job execution results."""
    components = Component.query.filter_by(job_id=job_id).all()
    comp_ids = [c.id for c in components]

    vulns = Vulnerability.query.filter(Vulnerability.component_id.in_(comp_ids)).all() if comp_ids else []
    vuln_ids = [v.id for v in vulns]

    scores = RiskScore.query.filter(RiskScore.vulnerability_id.in_(vuln_ids)).all() if vuln_ids else []

    high_risk = sum(1 for s in scores if s.final_score >= 7.0)
    medium_risk = sum(1 for s in scores if 4.0 <= s.final_score < 7.0)
    low_risk = sum(1 for s in scores if s.final_score < 4.0)

    degraded_vulns = sum(1 for v in vulns if v.data_quality == 'degraded')

    return {
        "component_count": len(components),
        "vulnerability_count": len(vulns),
        "high_risk_count": high_risk,
        "medium_risk_count": medium_risk,
        "low_risk_count": low_risk,
        "degraded_data_count": degraded_vulns,
    }
