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
        comp_id = comp.id
        psutil_v = psutil_verdicts.get(comp_id)
        etw_v = etw_verdicts.get(comp_id)

        if etw_v and psutil_v:
            # Dual-tier case: compare confidence levels
            psutil_rank = _CONFIDENCE_RANK.get(psutil_v.confidence, 0)
            etw_rank = _CONFIDENCE_RANK.get(etw_v.confidence, 0)

            if etw_rank >= psutil_rank:
                primary = etw_v
                secondary = psutil_v
            else:
                primary = psutil_v
                secondary = etw_v

            # Merge raw evidence details so neither tier's findings are lost
            try:
                primary_raw = json.loads(primary.raw_evidence_json)
                secondary_raw = json.loads(secondary.raw_evidence_json)
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
