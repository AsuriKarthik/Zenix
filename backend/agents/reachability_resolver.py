"""
Reachability Resolver — coordinates Step 6 (psutil) and Step 7 (ETW) reachability tiers.

Resolution rules:
  1. Evaluate psutil tier (default, no elevated privileges required).
  2. Evaluate ETW tier if available (elevated, Windows-only).
  3. Compare verdicts per component:
     - ETW verdict ceiling ('high') > psutil verdict ceiling ('medium').
     - Highest confidence verdict is selected as primary for RiskScore computation.
     - Supporting evidence from both tiers is preserved in ReachabilityVerdict.raw_evidence_json.
"""

from __future__ import annotations

import json
import logging
from typing import List, Dict

from db import Component, ReachabilityVerdict
from agents.reachability_psutil import evaluate_psutil_reachability, get_active_memory_maps
from agents.etw_collector import etw_collector

log = logging.getLogger(__name__)

_CONFIDENCE_RANK = {'low': 0, 'medium': 1, 'high': 2}


def resolve_reachability(
    components: list[Component],
    memory_maps=None
) -> dict[int, ReachabilityVerdict]:
    """
    Evaluate reachability using all available tiers and select the highest confidence verdict per component.

    Returns:
        Dict mapping component.id -> ReachabilityVerdict model instance.
    """
    # ── Step 6: psutil tier ───────────────────────────────────────────────────
    psutil_verdicts = evaluate_psutil_reachability(components, memory_maps=memory_maps)

    # ── Step 7: ETW tier (if available) ───────────────────────────────────────
    etw_verdicts: dict[int, ReachabilityVerdict] = {}
    if etw_collector.is_available:
        try:
            etw_verdicts = etw_collector.evaluate_etw_reachability(components)
        except Exception as exc:
            log.warning("ETW reachability evaluation encountered an error: %s", exc)

    final_verdicts: dict[int, ReachabilityVerdict] = {}

    for comp in components:
        comp_id_val = getattr(comp, 'id', None)
        if comp_id_val is None:
            continue
        comp_id = int(comp_id_val)
        psutil_v = psutil_verdicts.get(comp_id)
        etw_v = etw_verdicts.get(comp_id)

        if etw_v and psutil_v:
            # Dual-tier case: compare confidence levels
            # pyrefly: ignore [no-matching-overload]
            psutil_rank = _CONFIDENCE_RANK.get(psutil_v.confidence, 0)
            # pyrefly: ignore [no-matching-overload]
            etw_rank = _CONFIDENCE_RANK.get(etw_v.confidence, 0)

            if etw_rank >= psutil_rank:
                primary = etw_v
                secondary = psutil_v
            else:
                primary = psutil_v
                secondary = etw_v

            # Merge raw evidence details so neither tier's findings are lost
            try:
                primary_raw = json.loads(str(primary.raw_evidence_json or '{}'))
                secondary_raw = json.loads(str(secondary.raw_evidence_json or '{}'))
                primary_raw["supporting_tier_evidence"] = {
                    "source": secondary.evidence_source,
                    "status": secondary.status,
                    "confidence": secondary.confidence,
                    "details": secondary_raw,
                }
                primary.raw_evidence_json = json.dumps(primary_raw)
            except Exception as json_err:
                log.debug("Error merging dual-tier raw evidence: %s", json_err)

            final_verdicts[comp_id] = primary

        elif etw_v:
            final_verdicts[comp_id] = etw_v
        elif psutil_v:
            final_verdicts[comp_id] = psutil_v
        else:
            # Fallback (should not occur)
            final_verdicts[comp_id] = ReachabilityVerdict(
                component_id=comp_id,
                status='UNKNOWN',
                confidence='low',
                evidence_source='none',
                matched_event_ids_json='[]',
                raw_evidence_json='{}',
            )

    return final_verdicts


def get_vulnerable_watchlist(job_id: str | None = None, user_id: int | None = None) -> list[dict]:
    """
    Build the Runtime Correlation Watchlist from uploaded SBOM scan results.
    Only components with known vulnerabilities are included in the watchlist.

    Returns:
        List of dicts representing vulnerable watchlist components.
    """
    from db import db, Job, Component, Vulnerability

    try:
        query = (
            db.session.query(Component)
            .join(Job, Component.job_id == Job.id)
            .join(Vulnerability, Component.id == Vulnerability.component_id)
            .filter(Job.status == 'done')
        )

        if job_id:
            query = query.filter(Component.job_id == job_id)
        if user_id:
            query = query.filter(Job.user_id == user_id)

        vulnerable_components = query.distinct().all()
        watchlist = []

        for comp in vulnerable_components:
            vulns = Vulnerability.query.filter_by(component_id=comp.id).all()
            if not vulns:
                continue

            vuln_list = []
            for v in vulns:
                vuln_list.append({
                    "vulnerability_id": v.id,
                    "cve_id": v.cve_id,
                    "cvss": v.cvss,
                    "cvss_severity": getattr(v, 'cvss_severity', None),
                    "epss": v.epss,
                    "is_kev": bool(v.is_kev),
                    "description": v.description,
                })

            watchlist.append({
                "component_id": comp.id,
                "job_id": comp.job_id,
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
                "file_hash": comp.file_hash,
                "vulnerabilities": vuln_list,
            })

        return watchlist
    except Exception as exc:
        log.warning("Error fetching vulnerable watchlist: %s", exc)
        return []


def correlate_event_with_watchlist(
    image_path: str | None,
    process_name: str | None,
    image_hash: str | None,
    watchlist: list[dict]
) -> dict | None:
    """
    Correlate a single runtime telemetry observation (image load/process event)
    against the Vulnerable Runtime Watchlist using strong identifiers.

    Identifiers checked:
      1. Component name / module path matching
      2. Exact or compatible version matching
      3. Cryptographic hash matching
      4. PURL identifier matching

    Returns:
        Matched watchlist entry dict + specific matching vulnerability details, or None if no match.
    """
    if not image_path and not process_name and not image_hash:
        return None

    path_lower = (image_path or '').lower().replace('/', '\\')
    proc_lower = (process_name or '').lower()
    hash_lower = (image_hash or '').lower()
    mod_name_lower = path_lower.split('\\')[-1] if path_lower else ''

    for item in watchlist:
        comp_name = item["name"].lower() if item.get("name") else ""
        comp_ver = item.get("version") or ""
        comp_hash = item.get("file_hash", "").lower() if item.get("file_hash") else ""
        comp_purl = item.get("purl", "").lower() if item.get("purl") else ""

        if not comp_name:
            continue

        is_name_matched = False

        # 1. Exact or substring module/path match
        if comp_name in mod_name_lower or comp_name in path_lower or comp_name == proc_lower:
            is_name_matched = True

        # 2. Hash match
        elif comp_hash and hash_lower and comp_hash == hash_lower:
            is_name_matched = True

        # 3. PURL match fragment
        elif comp_purl and comp_purl in path_lower:
            is_name_matched = True

        if not is_name_matched:
            continue

        # Version check logic (strong matching)
        if comp_ver:
            # If path contains version string, verify compatibility (e.g. log4j-core-2.14.1.jar)
            ver_clean = comp_ver.lower()
            if ver_clean in path_lower or ver_clean in mod_name_lower:
                pass  # Strong version match
            elif any(c.isdigit() for c in ver_clean):
                # Check if path contains a conflicting version string for the same library
                # e.g. path has 3.2.0 but component is 3.0.1
                import re
                path_versions = re.findall(r'\d+\.\d+(?:\.\d+)?', mod_name_lower)
                if path_versions and ver_clean not in path_versions:
                    # Clear version mismatch — skip false positive correlation match
                    continue

        # Matched! Return details
        first_vuln = item["vulnerabilities"][0] if item.get("vulnerabilities") else {}
        return {
            "watchlist_item": item,
            "matched_vuln": first_vuln,
            "component_id": item["component_id"],
            "component_name": item["name"],
            "component_version": item["version"],
            "cve_id": first_vuln.get("cve_id", "VULNERABILITY"),
            "cvss": first_vuln.get("cvss"),
            "epss": first_vuln.get("epss"),
            "is_kev": first_vuln.get("is_kev", False),
            "description": first_vuln.get("description"),
        }

    return None


SYSTEM_OS_DLL_NAMES = {
    'ntdll', 'kernel32', 'kernelbase', 'user32', 'gdi32', 'advapi32', 'sechost',
    'rpcrt4', 'combase', 'ole32', 'oleaut32', 'shlwapi', 'shell32', 'msvcrt',
    'ucrtbase', 'imm32', 'ws2_32', 'dnsapi', 'iphlpapi', 'crypt32', 'wintrust',
    'bcrypt', 'ncrypt', 'clbcatq', 'version', 'profapi', 'setupapi', 'cfgmgr32',
    'devobj', 'bcryptprimitives', 'dwmapi', 'uxtheme', 'dxgi', 'gdi32full',
    'msvcp_win', 'secref', 'sspicli', 'userenv', 'powrprof', 'winmm', 'winspool'
}

def is_system_os_dll(image_path: str, comp_name: str) -> bool:
    path_lower = (image_path or '').lower().replace('/', '\\')
    name_lower = (comp_name or '').lower()
    if name_lower in SYSTEM_OS_DLL_NAMES:
        return True
    if any(p in path_lower for p in [r'c:\windows\system32', r'c:\windows\syswow64', r'c:\windows\winsxs']):
        return True
    return False


LEGITIMATE_KNOWN_SOFTWARE = {
    'chrome', 'chrome_elf', 'msedge', 'msedge_elf', 'msedgewebview2', 'd3dcompiler_47',
    'icudtl', 'sortdefault', 'directxapps', 'firefox', 'vlc', 'git', 'python', 'node',
    'code', 'cmd', 'powershell', 'explorer', 'taskmgr', 'conhost', 'svchost'
}

def resolve_component_identity(executable_path: str, process_name: str, comp_name: str) -> tuple[str, str]:
    """
    Returns (identity_confidence, label)
      identity_confidence: 'KNOWN' | 'PARTIALLY_IDENTIFIED' | 'UNKNOWN'
    """
    path_lower = (executable_path or '').lower().replace('/', '\\')
    proc_lower = (process_name or '').lower()
    name_lower = (comp_name or '').lower()

    if any(k in name_lower or k in proc_lower for k in LEGITIMATE_KNOWN_SOFTWARE):
        return 'KNOWN', comp_name or process_name
    if any(k in path_lower for k in ['program files', 'appdata', 'windowsapps', 'system32', 'syswow64']):
        return 'KNOWN', comp_name or process_name
    if comp_name and comp_name.lower() not in ('unknown', 'unnamed', 'system', 'idle', 'unverified'):
        return 'PARTIALLY_IDENTIFIED', comp_name
    return 'UNKNOWN', 'Unverified Binary'


def sync_runtime_inventory_from_telemetry(obs: dict) -> None:
    """
    Ingest a live telemetry observation (ETW/PSUTIL process or module load)
    into the persistent RuntimeInventory table.

    Performs:
      1. Component identity & version extraction.
      2. Comparison against the latest versioned SBOM baseline.
      3. Drift classification (DECLARED vs INVENTORY_DRIFT vs UNKNOWN_IDENTIFICATION_REQUIRED).
      4. Database upsert preserving historical first_seen/last_seen timestamps.
    """
    from db import db, Job, Component, Vulnerability, RuntimeInventory, _utcnow

    if not obs or not obs.get("image_path"):
        return

    image_path = obs["image_path"]
    proc_name = obs.get("process_name") or "unknown"
    pid = obs.get("pid")
    file_hash = obs.get("image_hash")

    mod_name = image_path.split('\\')[-1].split('/')[-1] if image_path else proc_name
    comp_name = mod_name.split('.')[0] if '.' in mod_name else mod_name

    identity_conf, label = resolve_component_identity(image_path, proc_name, comp_name)

    # Determine if component can be identified reliably
    is_unknown = (identity_conf == 'UNKNOWN')
    is_sys_dll = is_system_os_dll(image_path, comp_name)

    # Fetch latest completed SBOM baseline job
    latest_job = Job.query.filter_by(status='done').order_by(db.desc(Job.submitted_at)).first()

    matched_sbom_comp = None
    if latest_job and not is_unknown:
        matched_sbom_comp = Component.query.filter(
            Component.job_id == latest_job.id,
            (Component.name.ilike(f"%{comp_name}%") | Component.name.ilike(f"%{proc_name}%"))
        ).first()

    # Determine drift status & category (INVENTORY_DRIFT = INFORMATIONAL / NOT_SUSPICIOUS, NOT SUSPICIOUS!)
    if is_unknown:
        drift_status = 'UNKNOWN_IDENTIFICATION_REQUIRED'
        category = 'UNKNOWN_RUNTIME_COMPONENT'
    elif matched_sbom_comp:
        drift_status = 'DECLARED'
        category = 'RUNTIME_ACTIVE_VULNERABILITY' if matched_sbom_comp.vulnerabilities.count() > 0 else 'DECLARED'
    elif is_sys_dll:
        drift_status = 'DECLARED'
        category = 'DECLARED'
    else:
        drift_status = 'INVENTORY_DRIFT'
        category = 'INVENTORY_DRIFT'

    try:
        now_time = _utcnow()
        # Find primary parent process record (group by process_name and PID)
        existing_parent = RuntimeInventory.query.filter(
            RuntimeInventory.process_name == proc_name,
            db.or_(RuntimeInventory.pid == pid, RuntimeInventory.pid.is_(None))
        ).first()

        if not existing_parent:
            # Fallback lookup by process_name
            existing_parent = RuntimeInventory.query.filter_by(process_name=proc_name).first()

        if existing_parent:
            existing_parent.last_seen = now_time
            existing_parent.status = 'ACTIVE'
            if pid and not existing_parent.pid:
                existing_parent.pid = pid
            if existing_parent.drift_status != 'DRIFT_RESOLVED':
                existing_parent.drift_status = drift_status
                existing_parent.finding_category = category
            if matched_sbom_comp:
                existing_parent.matched_sbom_component_id = matched_sbom_comp.id

            # Aggregate child modules/resources into parent process record
            if mod_name and mod_name.lower() != proc_name.lower():
                try:
                    mods = json.loads(str(existing_parent.loaded_modules_json or '[]'))
                    if mod_name not in mods:
                        mods.append(mod_name)
                        existing_parent.loaded_modules_json = json.dumps(mods)
                except Exception:
                    pass
        else:
            exec_p = image_path if image_path else proc_name
            mods_arr = [mod_name] if mod_name and mod_name.lower() != proc_name.lower() else []
            rec = RuntimeInventory(
                process_name=proc_name,
                executable_path=exec_p,
                component_name=comp_name,
                module_name=mod_name,
                version=obs.get("version"),
                file_hash=file_hash,
                pid=pid,
                status='ACTIVE',
                drift_status=drift_status,
                finding_category=category,
                matched_sbom_component_id=matched_sbom_comp.id if matched_sbom_comp else None,
                first_seen=now_time,
                last_seen=now_time,
            )
            rec.loaded_modules_json = json.dumps(mods_arr)
            db.session.add(rec)
        db.session.commit()
    except Exception as exc:
        log.warning("Error syncing runtime inventory entry: %s", exc)


def reconcile_runtime_inventory_with_sbom(job_id: str) -> int:
    """
    Reconcile existing persistent RuntimeInventory entries against a newly uploaded SBOM job.
    Updates previously undeclared INVENTORY_DRIFT items to DRIFT_RESOLVED while preserving telemetry history.
    """
    from db import db, Component, RuntimeInventory

    resolved_count = 0
    try:
        sbom_components = Component.query.filter_by(job_id=job_id).all()
        if not sbom_components:
            return 0

        drift_items = RuntimeInventory.query.filter(
            RuntimeInventory.drift_status.in_(['INVENTORY_DRIFT', 'UNKNOWN_IDENTIFICATION_REQUIRED'])
        ).all()

        for item in drift_items:
            item_name = (item.component_name or item.process_name or '').lower()
            for comp in sbom_components:
                c_name = comp.name.lower()
                if c_name in item_name or item_name in c_name:
                    item.drift_status = 'DRIFT_RESOLVED'
                    item.matched_sbom_component_id = comp.id
                    item.finding_category = 'RUNTIME_ACTIVE_VULNERABILITY' if comp.vulnerabilities.count() > 0 else 'DECLARED'
                    resolved_count += 1
                    break

        db.session.commit()
        log.info("Reconciled SBOM %s with runtime inventory: %d drift items resolved.", job_id[:8], resolved_count)
        return resolved_count
    except Exception as exc:
        log.warning("Error reconciling runtime inventory with SBOM %s: %s", job_id, exc)
        return 0


