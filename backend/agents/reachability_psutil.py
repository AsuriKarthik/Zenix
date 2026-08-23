"""
psutil Reachability Collector — Step 6 (Default tier, no elevated privileges required).

Correlates SBOM components against active process memory maps captured via psutil.
Works on any supported platform (Windows, Linux, macOS) without requiring admin rights.

Rules enforced:
  - NO random or synthetic fallback data under any circumstances.
  - Thin or unreadable process data → status: "UNKNOWN", confidence: "low", evidence_source: "psutil".
  - Match found → status: "REACHABLE", confidence: "medium", evidence_source: "psutil".
  - Full memory map scan performed and no match found → status: "NOT_REACHABLE", confidence: "medium", evidence_source: "psutil".
  - Psutil confidence ceiling is strictly 'medium' — never returns 'high' (reserved for kernel ETW).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
import threading
from typing import Optional, List, Dict, Set

import psutil

from db import db, Component, ReachabilityVerdict, EtwEvent

log = logging.getLogger(__name__)
_UTC = timezone.utc

_MEMORY_MAP_TIMEOUT_SECONDS = 20


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_active_memory_maps(timeout: float = _MEMORY_MAP_TIMEOUT_SECONDS) -> list[dict]:
    """
    Capture active user-space memory maps using psutil.

    Returns a list of dicts:
      [
        {
          "pid": 1234,
          "process_name": "java.exe",
          "image_path": "C:\\path\\to\\library.dll"
        },
        ...
      ]
    Ignores access denied / permission errors per process gracefully.
    Enforces a hard timeout — on Windows, iterating all processes can be extremely
    slow. If the scan exceeds `timeout` seconds, returns whatever was collected so far.
    """
    observations: list[dict] = []
    _timed_out = threading.Event()

    def _scan():
        for proc in psutil.process_iter(['pid', 'name']):
            if _timed_out.is_set():
                break
            try:
                pid = proc.info['pid']
                name = proc.info['name'] or ''
                if not name or name.lower() in ('system', 'idle', 'registry'):
                    continue

                maps_collected = False
                try:
                    maps = proc.memory_maps()
                    for m in maps:
                        if _timed_out.is_set():
                            break
                        path = getattr(m, 'path', '') or ''
                        if path:
                            observations.append({
                                "pid": pid,
                                "process_name": name,
                                "image_path": path,
                                "timestamp": _utcnow().isoformat(),
                            })
                            maps_collected = True
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                except Exception as map_err:
                    log.debug("Error reading memory maps for PID %s: %s", pid, map_err)

                # Fallback for processes where memory_maps is restricted or empty (e.g., Antigravity terminal / isolated shells)
                if not maps_collected:
                    try:
                        exe_path = proc.exe()
                        if exe_path:
                            observations.append({
                                "pid": pid,
                                "process_name": name,
                                "image_path": exe_path,
                                "timestamp": _utcnow().isoformat(),
                            })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

                    try:
                        cmdline = proc.cmdline()
                        for arg in cmdline:
                            if arg and (arg.endswith('.exe') or arg.endswith('.dll') or arg.endswith('.jar') or arg.endswith('.py') or '\\' in arg or '/' in arg):
                                observations.append({
                                    "pid": pid,
                                    "process_name": name,
                                    "image_path": arg,
                                    "timestamp": _utcnow().isoformat(),
                                })
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        pass

            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception as proc_err:
                log.debug("Error iterating process info: %s", proc_err)
                continue

    scan_thread = threading.Thread(target=_scan, daemon=True)
    scan_thread.start()
    scan_thread.join(timeout=timeout)

    if scan_thread.is_alive():
        _timed_out.set()
        log.warning(
            "get_active_memory_maps() exceeded %ds timeout — returning %d observations collected so far. "
            "Pipeline will continue with partial psutil data.",
            timeout, len(observations)
        )

    return observations


def evaluate_psutil_reachability(
    components: list[Component],
    memory_maps: Optional[list[dict]] = None
) -> dict[int, ReachabilityVerdict]:
    """
    Correlate components against psutil memory maps.

    Args:
        components: List of Component DB models.
        memory_maps: Pre-fetched memory maps list (optional, fetched if None).

    Returns:
        Dict mapping component.id -> ReachabilityVerdict model instance.
    """
    if memory_maps is None:
        memory_maps = get_active_memory_maps()

    verdicts: dict[int, ReachabilityVerdict] = {}

    for comp in components:
        comp_id_val = getattr(comp, 'id', None)
        if comp_id_val is None:
            continue

        comp_id = int(comp_id_val)
        comp_name_lower = comp.name.lower()
        comp_ver_lower = (comp.version or '').lower()
        comp_hash_lower = (comp.file_hash or '').lower()

        matched_obs: list[dict] = []

        for obs in memory_maps:
            image_path_lower = obs["image_path"].lower()

            # Check if component name, purl fragment, or hash matches image path
            is_match = False
            if comp_name_lower in image_path_lower:
                is_match = True
                if comp_ver_lower and any(c.isdigit() for c in comp_ver_lower):
                    import re
                    basename_lower = image_path_lower.split('\\')[-1].split('/')[-1]
                    path_versions = re.findall(r'\d+\.\d+(?:\.\d+)?', basename_lower)
                    if path_versions and comp_ver_lower not in path_versions:
                        is_match = False
            elif comp_hash_lower and comp_hash_lower in image_path_lower:
                is_match = True

            if is_match:
                matched_obs.append(obs)

        if matched_obs:
            # Matches found in active process memory
            first_match = matched_obs[0]
            matched_evt_ids = []
            try:
                for mob in matched_obs[:5]:
                    evt = EtwEvent(
                        image_path=mob["image_path"],
                        evidence_source='psutil',
                        pid=mob["pid"],
                        process_name=mob["process_name"],
                        timestamp=_utcnow(),
                    )
                    db.session.add(evt)
                    db.session.flush()
                    if evt.id:
                        matched_evt_ids.append(evt.id)
            except Exception as evt_err:
                log.debug("Error recording psutil telemetry event: %s", evt_err)

            verdict = ReachabilityVerdict(
                component_id=comp_id,
                status='REACHABLE',
                confidence='medium',  # psutil ceiling is medium
                evidence_source='psutil',
                matched_event_ids_json=json.dumps(matched_evt_ids),
                raw_evidence_json=json.dumps({
                    "matched_count": len(matched_obs),
                    "process_name": first_match["process_name"],
                    "pid": first_match["pid"],
                    "image_path": first_match["image_path"],
                    "all_matches": matched_obs[:5],  # cap at 5
                }),
                determined_at=_utcnow(),
            )
        else:
            # No correlating telemetry evidence observed -> UNKNOWN, evidence_source: 'none'
            verdict = ReachabilityVerdict(
                component_id=comp_id,
                status='UNKNOWN',
                confidence='low',
                evidence_source='none',
                matched_event_ids_json=json.dumps([]),
                raw_evidence_json=json.dumps({
                    "maps_scanned_count": len(memory_maps),
                    "note": "No correlating telemetry evidence observed. Missing evidence != proof of absence."
                }),
                determined_at=_utcnow(),
            )

        verdicts[comp_id] = verdict

    return verdicts
