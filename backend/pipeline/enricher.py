"""
Score Enricher — EPSS scores and CISA KEV status for known CVEs.

Data sources:
  - FIRST EPSS API  (https://api.first.org/data/v1/epss)
  - CISA KEV feed   (bulk JSON, cached in-memory for 6 h)

Caching model:
  - EPSS: one API call per CVE per invocation; callers cache results in the
    Vulnerability table with epss_fetched_at timestamp.
  - KEV: module-level in-memory cache of the full CVE ID set, refreshed every
    CISA_KEV_CACHE_HOURS hours. Survives for the process lifetime.
    On restart: the cache is cold until the first enrich_cve() call triggers
    a fresh download.

Degradation semantics (must be propagated to scoring without silent truncation):
  - EPSS unavailable → EnrichmentResult.epss = None
      Scorer uses 0.0 in the formula; confidence is reduced.
  - KEV feed unavailable, no prior cache → kev_status = 'unavailable'
      Scorer treats as is_kev=False with confidence note.
  - KEV feed unavailable, stale cache → kev_status = 'stale_present' or 'stale_absent'
      'stale_present' → use True (conservative; keep alert active)
      'stale_absent'  → use False but mark confidence note (cannot confirm safe)
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

import requests

from config import Config

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Public output type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EnrichmentResult:
    """
    EPSS + KEV data for one CVE.

    All nullable fields are None when the relevant feed was unavailable —
    never zero. Callers must forward None into RiskScore and document it
    via confidence_notes.
    """
    cve_id: str

    # EPSS
    epss: Optional[float]               # 0.0–1.0, or None if feed was down
    epss_percentile: Optional[float]    # 0.0–1.0, or None
    epss_fetched_at: Optional[datetime] # UTC timestamp, or None if not fetched

    # KEV
    is_kev: bool                        # True if CVE is in CISA KEV
    # One of:
    #   'confirmed_fresh'   — cache was fresh; CVE is in KEV
    #   'confirmed_not_kev' — cache was fresh; CVE is NOT in KEV
    #   'stale_present'     — cache stale; CVE was in KEV last time checked
    #   'stale_absent'      — cache stale; CVE was NOT in KEV last time checked
    #   'unavailable'       — no KEV data at all (first run, no download succeeded)
    kev_status: str

    # Human-readable notes for analyst view and confidence computation
    degradation_notes: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# EPSS
# ─────────────────────────────────────────────────────────────────────────────

def fetch_epss(cve_id: str) -> tuple[Optional[float], Optional[float]]:
    """
    Fetch EPSS score and percentile for one CVE from the FIRST EPSS API.

    Returns (epss_score, percentile), both None on any failure.
    Does not raise — callers must handle None.
    """
    time.sleep(Config.EPSS_RATE_LIMIT_DELAY)

    url = f"{Config.EPSS_API_BASE}?cve={cve_id}"
    try:
        resp = requests.get(url, timeout=12)
        resp.raise_for_status()
        data = resp.json()
        rows = data.get('data', [])
        if not rows:
            # CVE exists but has no EPSS model score yet (common for very new CVEs)
            log.debug("No EPSS score for %s (CVE not yet in model).", cve_id)
            return None, None
        first = rows[0]
        return float(first.get('epss', 0)), float(first.get('percentile', 0))

    except requests.exceptions.Timeout:
        log.warning("EPSS API timed out for %s.", cve_id)
    except requests.exceptions.ConnectionError:
        log.warning("EPSS API unreachable for %s.", cve_id)
    except requests.exceptions.HTTPError as exc:
        log.warning("EPSS API HTTP %s for %s.", exc.response.status_code, cve_id)
    except Exception as exc:
        log.error("Unexpected error fetching EPSS for %s: %s", cve_id, exc)

    return None, None


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV
# ─────────────────────────────────────────────────────────────────────────────

# Module-level in-memory cache (survives for the process lifetime)
_kev_set: Optional[set] = None
_kev_loaded_at: Optional[datetime] = None


def _kev_is_fresh() -> bool:
    if _kev_set is None or _kev_loaded_at is None:
        return False
    return (datetime.utcnow() - _kev_loaded_at) < timedelta(hours=Config.CISA_KEV_CACHE_HOURS)


def _download_kev() -> Optional[set]:
    """
    Download and parse the CISA KEV JSON.
    Returns a set of CVE ID strings, or None if download fails.
    """
    try:
        resp = requests.get(Config.CISA_KEV_URL, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        ids = {v['cveID'] for v in data.get('vulnerabilities', []) if 'cveID' in v}
        log.info("CISA KEV refreshed: %d entries.", len(ids))
        return ids
    except requests.exceptions.Timeout:
        log.warning("CISA KEV download timed out.")
    except requests.exceptions.ConnectionError:
        log.warning("CISA KEV unreachable.")
    except Exception as exc:
        log.error("Unexpected error downloading CISA KEV: %s", exc)
    return None


def _refresh_kev_if_needed() -> bool:
    """
    Refresh the in-memory KEV cache if it is stale or absent.

    Returns True if the cache is now fresh (was already fresh, or refresh succeeded).
    Returns False if the refresh failed.
      - If a stale cache exists: False is returned but _kev_set is still usable.
      - If no cache exists at all: _kev_set remains None.
    """
    global _kev_set, _kev_loaded_at

    if _kev_is_fresh():
        return True

    new_set = _download_kev()
    if new_set is not None:
        _kev_set = new_set
        _kev_loaded_at = datetime.utcnow()
        return True

    # Refresh failed
    if _kev_set is not None:
        log.warning(
            "CISA KEV refresh failed; using stale cache from %s (%d entries).",
            _kev_loaded_at, len(_kev_set),
        )
    else:
        log.warning("CISA KEV unavailable and no prior cache exists.")
    return False


def _check_kev(cve_id: str) -> tuple[bool, str]:
    """
    Check KEV membership and return (is_kev, kev_status).

    kev_status semantics are documented on EnrichmentResult.kev_status.
    """
    cache_fresh = _refresh_kev_if_needed()

    if _kev_set is None:
        # No cache at all — cannot make any claim
        return False, 'unavailable'

    present = cve_id in _kev_set

    if cache_fresh:
        return present, 'confirmed_fresh' if present else 'confirmed_not_kev'
    else:
        return present, 'stale_present' if present else 'stale_absent'


# ─────────────────────────────────────────────────────────────────────────────
# Public interface
# ─────────────────────────────────────────────────────────────────────────────

def enrich_cve(cve_id: str) -> EnrichmentResult:
    """
    Fetch EPSS score and CISA KEV status for a single CVE.

    Returns an EnrichmentResult with whatever data could be retrieved.
    Never raises — all feed failures are captured as degradation_notes.
    """
    notes: list[str] = []

    # ── EPSS ──────────────────────────────────────────────────────────────────
    epss, epss_percentile = fetch_epss(cve_id)
    epss_fetched_at = datetime.utcnow() if epss is not None else None

    if epss is None:
        notes.append(
            f"EPSS unavailable for {cve_id} (feed unreachable or CVE not yet modelled). "
            "Scoring will use epss_effective=0.0 with reduced confidence."
        )

    # ── KEV ───────────────────────────────────────────────────────────────────
    is_kev, kev_status = _check_kev(cve_id)

    if kev_status == 'unavailable':
        notes.append(
            f"CISA KEV unavailable for {cve_id} — treated as not-KEV with reduced confidence."
        )
    elif kev_status == 'stale_absent':
        notes.append(
            f"CISA KEV cache is stale (>{Config.CISA_KEV_CACHE_HOURS}h old). "
            f"{cve_id} was NOT in KEV at last check — cannot confirm this is still accurate."
        )
    elif kev_status == 'stale_present':
        notes.append(
            f"CISA KEV cache is stale. {cve_id} WAS in KEV at last check — "
            "treating as in-KEV (conservative)."
        )

    return EnrichmentResult(
        cve_id=cve_id,
        epss=epss,
        epss_percentile=epss_percentile,
        epss_fetched_at=epss_fetched_at,
        is_kev=is_kev,
        kev_status=kev_status,
        degradation_notes=notes,
    )
