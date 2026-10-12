"""
Risk Scorer — deterministic formula, fully auditable.

Formula
-------
  base  = (cvss_effective * 0.2) + (epss_scaled * 0.5) + (kev_value * 0.3)
  final = base * reachability_multiplier

  Where:
    cvss_effective  = cvss if present, else 0.0 (recorded as 'missing' in notes)
    epss_scaled     = epss * 10.0   (EPSS is 0–1; scale to match CVSS 0–10 domain)
    kev_value       = 10.0 if is_kev else 0.0

  Reachability multipliers:
    REACHABLE     → 1.00  (full risk)
    UNKNOWN       → 0.50  (no evidence either way; treat as partially risky)
    NOT_REACHABLE → 0.05  (not zero — imperfect evidence; leaves margin for error)

Confidence ceiling rules
------------------------
  evidence_source='etw'    → ceiling 'high'
  evidence_source='psutil' → ceiling 'medium'
  evidence_source='none'   → ceiling 'low'

  Confidence degrades from the ceiling when:
    - reachability is UNKNOWN → floor at 'low'
    - cvss is None            → floor at 'low'
    - epss is None            → floor at 'medium' (high→medium)
    - kev_status is stale or unavailable → floor at 'medium'

  Final confidence = min(ceiling, all degradation floors).

Output
------
  Every ScoringResult records:
    - The four inputs (cvss_input, epss_input, kev_input, reachability_input)
    - The evidence_source
    - Each term's contribution to the base score
    - The reachability multiplier applied
    - The final score (clamped to [0.0, 10.0])
    - Confidence level + notes list explaining it
    - A one-line reason string suitable for analyst display

  This means every score can be reproduced from its own row, and any analyst
  can verify the arithmetic without having to re-run the pipeline.
"""

from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

CVSS_WEIGHT: float = 0.2
EPSS_WEIGHT: float = 0.5    # applied to EPSS *after* scaling to [0, 10]
KEV_WEIGHT: float = 0.3

EPSS_SCALE: float = 10.0    # EPSS is 0–1; scale factor to put it in the same domain as CVSS

REACHABILITY_MULTIPLIER: dict[str, float] = {
    'REACHABLE': 1.00,
    'UNKNOWN': 0.50,
    'NOT_REACHABLE': 0.05,
}

# Maximum confidence achievable given an evidence source
EVIDENCE_CONFIDENCE_CEILING: dict[str, str] = {
    'etw': 'high',
    'psutil': 'medium',
    'none': 'low',
}

# Ordered from weakest to strongest (for min() comparisons)
_CONFIDENCE_RANK: dict[str, int] = {'low': 0, 'medium': 1, 'high': 2}
_CONFIDENCE_LEVELS: list[str] = ['low', 'medium', 'high']


def _min_confidence(a: str, b: str) -> str:
    """Return the lower of two confidence level strings."""
    ra = _CONFIDENCE_RANK.get(a, 0)
    rb = _CONFIDENCE_RANK.get(b, 0)
    return _CONFIDENCE_LEVELS[min(ra, rb)]


# ─────────────────────────────────────────────────────────────────────────────
# Output type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScoringResult:
    """
    The complete, auditable output of one scoring computation.

    This is not just a number — every field needed to independently verify
    the score is included. The RiskScore DB row is a direct projection of this.
    """

    # ── Inputs (verbatim; preserved for auditability) ─────────────────────────
    cvss_input: Optional[float]     # None if NVD was unreachable
    epss_input: Optional[float]     # None if EPSS feed was unreachable
    kev_input: bool
    reachability_input: str         # 'REACHABLE' | 'NOT_REACHABLE' | 'UNKNOWN'
    evidence_source: str            # 'etw' | 'psutil' | 'none'

    # ── Score breakdown ───────────────────────────────────────────────────────
    cvss_contrib: float             # cvss_effective * CVSS_WEIGHT
    epss_contrib: float             # epss_scaled * EPSS_WEIGHT
    kev_contrib: float              # kev_value * KEV_WEIGHT
    base_score: float               # sum of the three contributions
    reachability_multiplier: float  # the multiplier that was applied
    final_score: float              # base * multiplier, clamped to [0.0, 10.0]

    # ── Explainability ────────────────────────────────────────────────────────
    confidence: str                 # 'high' | 'medium' | 'low'
    confidence_notes: list[str]     # why confidence is what it is
    reason: str                     # one-liner for analyst display


# ─────────────────────────────────────────────────────────────────────────────
# Scoring function
# ─────────────────────────────────────────────────────────────────────────────

def compute_risk_score(
    *,
    cvss: Optional[float],
    epss: Optional[float],
    is_kev: bool,
    kev_status: str,
    reachability_status: str,
    evidence_source: str,
) -> ScoringResult:
    """
    Compute a deterministic risk score from the four pipeline inputs.

    Args:
        cvss:                CVSS base score (0.0–10.0), or None if NVD was unavailable
        epss:                EPSS probability (0.0–1.0), or None if feed was unavailable
        is_kev:              True if CVE is confirmed in CISA KEV
        kev_status:          freshness status of the KEV check
                             ('confirmed_fresh' | 'confirmed_not_kev' | 'stale_present' |
                              'stale_absent' | 'unavailable')
        reachability_status: 'REACHABLE' | 'NOT_REACHABLE' | 'UNKNOWN'
        evidence_source:     'etw' | 'psutil' | 'none'

    Returns:
        ScoringResult with all inputs, breakdown, confidence, and reason.
        Never raises.
    """
    notes: list[str] = []

    # ── Resolve missing inputs ────────────────────────────────────────────────

    # CVSS: use 0.0 as effective value when None, but record the absence
    if cvss is None:
        cvss_effective = 0.0
        notes.append(
            "CVSS missing (NVD unreachable during fetch). "
            "Score uses cvss_effective=0.0 and will underestimate risk."
        )
    else:
        cvss_effective = float(cvss)

    # EPSS: scale to [0, 10] for formula; use 0.0 when None
    if epss is None:
        epss_effective_scaled = 0.0
        notes.append(
            "EPSS missing (feed unreachable or CVE not yet modelled). "
            "Score uses epss_effective=0.0."
        )
    else:
        epss_effective_scaled = float(epss) * EPSS_SCALE

    # KEV: treat as False when unavailable, but note it
    kev_value = 10.0 if is_kev else 0.0

    if kev_status == 'unavailable':
        notes.append(
            "KEV status unknown (CISA feed unavailable, no prior cache). "
            "Treated as not-KEV."
        )
    elif kev_status == 'stale_absent':
        notes.append(
            "KEV cache stale — CVE was NOT in KEV at last check, "
            "but this cannot be confirmed current."
        )
    elif kev_status == 'stale_present':
        notes.append(
            "KEV cache stale — CVE WAS in KEV at last check (treated as in-KEV)."
        )
    # 'confirmed_fresh' and 'confirmed_not_kev' require no note

    # ── Compute base score ────────────────────────────────────────────────────
    cvss_contrib = cvss_effective * CVSS_WEIGHT
    epss_contrib = epss_effective_scaled * EPSS_WEIGHT
    kev_contrib = kev_value * KEV_WEIGHT
    base_score = cvss_contrib + epss_contrib + kev_contrib

    # ── Apply reachability multiplier ─────────────────────────────────────────
    multiplier = REACHABILITY_MULTIPLIER.get(reachability_status, 0.5)
    raw_final = base_score * multiplier
    final_score = round(min(max(raw_final, 0.0), 10.0), 2)

    # ── Determine confidence ──────────────────────────────────────────────────

    # Start at the ceiling set by the evidence source
    ceiling = EVIDENCE_CONFIDENCE_CEILING.get(evidence_source, 'low')
    confidence = ceiling

    # Degrade for unknown reachability (the biggest uncertainty)
    if reachability_status == 'UNKNOWN':
        confidence = _min_confidence(confidence, 'low')
        notes.append(
            "Reachability unknown — no observation confirms whether this "
            "component is loaded at runtime."
        )

    # Degrade for missing score data
    if cvss is None:
        confidence = _min_confidence(confidence, 'low')

    if epss is None:
        confidence = _min_confidence(confidence, 'medium')

    # Degrade for stale/unavailable KEV
    if kev_status in ('stale_present', 'stale_absent', 'unavailable'):
        confidence = _min_confidence(confidence, 'medium')

    # ── Build one-line reason ─────────────────────────────────────────────────
    parts: list[str] = []

    cvss_label = f"CVSS {cvss:.1f}" if cvss is not None else "CVSS N/A"
    parts.append(cvss_label)

    if epss is not None:
        parts.append(f"EPSS {epss:.3f}")
    else:
        parts.append("EPSS N/A")

    parts.append("KEV ✓" if is_kev else "KEV ✗")

    reach_labels = {
        'REACHABLE': f"REACHABLE [{evidence_source}]",
        'NOT_REACHABLE': f"NOT_REACHABLE [{evidence_source}]",
        'UNKNOWN': "REACHABILITY UNKNOWN",
    }
    parts.append(reach_labels.get(reachability_status, reachability_status))
    parts.append(f"→ {final_score:.2f} ({confidence})")

    reason = " | ".join(parts)

    return ScoringResult(
        cvss_input=cvss,
        epss_input=epss,
        kev_input=is_kev,
        reachability_input=reachability_status,
        evidence_source=evidence_source,
        cvss_contrib=round(cvss_contrib, 4),
        epss_contrib=round(epss_contrib, 4),
        kev_contrib=round(kev_contrib, 4),
        base_score=round(base_score, 4),
        reachability_multiplier=multiplier,
        final_score=final_score,
        confidence=confidence,
        confidence_notes=notes,
        reason=reason,
    )
