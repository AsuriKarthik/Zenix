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
from typing import Optional, List, Dict, Set

import psutil

from db import Component, ReachabilityVerdict

log = logging.getLogger(__name__)
_UTC = timezone.utc


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_active_memory_maps() -> list[dict]:
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
    """
    observations: list[dict] = []

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or ''
            if not name or name.lower() in ('system', 'idle', 'registry'):
                continue

            try:
                maps = proc.memory_maps()
                for m in maps:
                    path = getattr(m, 'path', '') or ''
                    if path:
                        observations.append({
                            "pid": pid,
                            "process_name": name,
                            "image_path": path,
                            "timestamp": _utcnow().isoformat(),
                        })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
            except Exception as map_err:
                log.debug("Error reading memory maps for PID %s: %s", pid, map_err)
                continue

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        except Exception as proc_err:
            log.debug("Error iterating process info: %s", proc_err)
            continue

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
    maps_inspected = len(memory_maps) > 0

    for comp in components:
        comp_name_lower = comp.name.lower()
        comp_hash_lower = (comp.file_hash or '').lower()

        matched_obs: list[dict] = []

        for obs in memory_maps:
            image_path_lower = obs["image_path"].lower()

            # Check if component name, purl fragment, or hash matches image path
            is_match = False
            if comp_name_lower in image_path_lower:
                is_match = True
            elif comp_hash_lower and comp_hash_lower in image_path_lower:
                is_match = True

            if is_match:
                matched_obs.append(obs)

        if matched_obs:
            # Matches found in active process memory
            first_match = matched_obs[0]
            verdict = ReachabilityVerdict(
                component_id=comp.id,
                status='REACHABLE',
                confidence='medium',  # psutil ceiling is medium
                evidence_source='psutil',
                matched_event_ids_json=json.dumps([]),
                raw_evidence_json=json.dumps({
                    "matched_count": len(matched_obs),
                    "process_name": first_match["process_name"],
                    "pid": first_match["pid"],
                    "image_path": first_match["image_path"],
                    "all_matches": matched_obs[:5],  # cap at 5
                }),
                determined_at=_utcnow(),
            )
        elif maps_inspected:
            # Memory maps scanned, but component was not loaded in any process
            verdict = ReachabilityVerdict(
                component_id=comp.id,
                status='NOT_REACHABLE',
                confidence='medium',
                evidence_source='psutil',
                matched_event_ids_json=json.dumps([]),
                raw_evidence_json=json.dumps({
                    "maps_scanned_count": len(memory_maps),
                    "note": "Component name/hash not observed in any active memory map."
                }),
                determined_at=_utcnow(),
            )
        else:
            # Unable to inspect memory maps (permission denied / thin data) -> UNKNOWN
            verdict = ReachabilityVerdict(
                component_id=comp.id,
                status='UNKNOWN',
                confidence='low',
                evidence_source='psutil',
                matched_event_ids_json=json.dumps([]),
                raw_evidence_json=json.dumps({
                    "note": "Insufficient process memory map data captured by psutil."
                }),
                determined_at=_utcnow(),
            )

        verdicts[comp.id] = verdict

    return verdicts
