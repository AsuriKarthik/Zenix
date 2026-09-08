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
from datetime import datetime, timedelta, timezone
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
    epss_reason: Optional[str] = None
    epss_next_action: Optional[str] = None

    # KEV
    is_kev: bool = False                # True if CVE is in CISA KEV
    kev_status: str = 'unavailable'
    kev_reason: Optional[str] = None
    kev_next_action: Optional[str] = None

    # Live Threat Intelligence Feeds
    shodan_exposed_hosts: Optional[int] = None
    virustotal_detections: Optional[int] = None

    # Human-readable notes for analyst view and confidence computation
    degradation_notes: list = field(default_factory=list)


def update_feed_status(
    feed_name: str,
    source_url: str,
    status: str,
    error_message: Optional[str] = None,
    records_updated: int = 0
) -> None:
    """Helper to update FeedStatus table in DB."""
    try:
        from db import db, FeedStatus
        now_time = datetime.now(timezone.utc).replace(tzinfo=None)
        feed_rec = FeedStatus.query.filter_by(feed_name=feed_name).first()
        if not feed_rec:
            feed_rec = FeedStatus(
                feed_name=feed_name,
                source_url=source_url,
                status=status,
                error_message=error_message,
                records_updated=records_updated,
                updated_at=now_time,
            )
            db.session.add(feed_rec)
        else:
            feed_rec.source_url = source_url
            feed_rec.status = status
            feed_rec.error_message = error_message
            if status == 'ONLINE':
                feed_rec.last_successful_sync = now_time
                if records_updated > 0:
                    feed_rec.records_updated = records_updated
            else:
                feed_rec.last_failed_attempt = now_time
            feed_rec.updated_at = now_time
        db.session.commit()
    except Exception as exc:
        log.debug("Could not update FeedStatus for %s: %s", feed_name, exc)


# ─────────────────────────────────────────────────────────────────────────────
# Live Shodan & VirusTotal Threat Intelligence
# ─────────────────────────────────────────────────────────────────────────────

_shodan_cache: dict[str, Optional[int]] = {}
_vt_cache: dict[str, Optional[int]] = {}


def query_shodan_vulnerability(cve_id: str) -> Optional[int]:
    """
    Query Shodan for total live exposed hosts vulnerable to `cve_id`.
    Uses Shodan `count(f"vuln:{cve_id}")` which queries the Shodan indexed internet
    without consuming export credits on Shodan developer accounts.
    Returns integer count of exposed hosts, or None if Shodan is unconfigured or failed.
    """
    api_key = getattr(Config, 'SHODAN_API_KEY', None)
    if not api_key:
        return None
    if cve_id in _shodan_cache:
        return _shodan_cache[cve_id]
    try:
        import shodan
        api = shodan.Shodan(api_key)
        res = api.count(f"vuln:{cve_id}")
        count = int(res.get("total", 0))
        _shodan_cache[cve_id] = count
        update_feed_status("Shodan Intelligence", "https://api.shodan.io", "ONLINE", records_updated=1)
        return count
    except Exception as exc:
        log.warning("Shodan query error for %s: %s", cve_id, exc)
        update_feed_status("Shodan Intelligence", "https://api.shodan.io", "OFFLINE", error_message=str(exc))
        _shodan_cache[cve_id] = None
        return None


def query_virustotal_threat(indicator: str) -> Optional[int]:
    """
    Query VirusTotal v3 for live threat detection intelligence.
    - If indicator is a file hash (MD5/SHA1/SHA256), inspects /files/{hash} for malicious engine detections.
    - If indicator is a CVE ID or software identifier, queries /search?query={indicator} for indexed threat reports.
    Returns detection count or matched threat records, or None if VT is unconfigured or failed.
    """
    api_key = getattr(Config, 'VIRUSTOTAL_API_KEY', None)
    if not api_key:
        return None
    if indicator in _vt_cache:
        return _vt_cache[indicator]
    try:
        import vt
        with vt.Client(api_key) as client:
            is_hex = len(indicator) in (32, 40, 64) and all(c in '0123456789abcdefABCDEF' for c in indicator)
            if is_hex:
                obj = client.get_object(f"/files/{indicator}")
                stats = getattr(obj, "last_analysis_stats", {}) or {}
                detections = int(stats.get("malicious", 0))
            else:
                res = client.get_json(f"/search?query={indicator}")
                data = res.get("data", [])
                detections = 0
                for item in data:
                    item_stats = item.get("attributes", {}).get("last_analysis_stats") or {}
                    mal = int(item_stats.get("malicious", 0))
                    if mal > 0:
                        detections = max(detections, mal)
                if detections == 0 and data:
                    detections = len(data)

            _vt_cache[indicator] = detections
            update_feed_status("VirusTotal Intelligence", "https://www.virustotal.com/api/v3", "ONLINE", records_updated=1)
            return detections
    except Exception as exc:
        log.warning("VirusTotal query error for %s: %s", indicator, exc)
        update_feed_status("VirusTotal Intelligence", "https://www.virustotal.com/api/v3", "OFFLINE", error_message=str(exc))
        _vt_cache[indicator] = None
        return None


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
        update_feed_status("FIRST EPSS", Config.EPSS_API_BASE, "ONLINE", records_updated=len(rows))
        if not rows:
            # CVE exists but has no EPSS model score yet (common for very new CVEs)
            log.debug("No EPSS score for %s (CVE not yet in model).", cve_id)
            return None, None
        first = rows[0]
        return float(first.get('epss', 0)), float(first.get('percentile', 0))

    except requests.exceptions.Timeout:
        log.warning("EPSS API timed out for %s.", cve_id)
        update_feed_status("FIRST EPSS", Config.EPSS_API_BASE, "OFFLINE", error_message="Request timeout")
    except requests.exceptions.ConnectionError:
        log.warning("EPSS API unreachable for %s.", cve_id)
        update_feed_status("FIRST EPSS", Config.EPSS_API_BASE, "OFFLINE", error_message="Connection error")
    except requests.exceptions.HTTPError as exc:
        log.warning("EPSS API HTTP %s for %s.", exc.response.status_code, cve_id)
        update_feed_status("FIRST EPSS", Config.EPSS_API_BASE, "OFFLINE", error_message=f"HTTP {exc.response.status_code}")
    except Exception as exc:
        log.error("Unexpected error fetching EPSS for %s: %s", cve_id, exc)
        update_feed_status("FIRST EPSS", Config.EPSS_API_BASE, "OFFLINE", error_message=str(exc))

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
        update_feed_status("CISA KEV", Config.CISA_KEV_URL, "ONLINE", records_updated=len(ids))
        return ids
    except requests.exceptions.Timeout:
        log.warning("CISA KEV download timed out.")
        update_feed_status("CISA KEV", Config.CISA_KEV_URL, "OFFLINE", error_message="Request timeout")
    except requests.exceptions.ConnectionError:
        log.warning("CISA KEV unreachable.")
        update_feed_status("CISA KEV", Config.CISA_KEV_URL, "OFFLINE", error_message="Connection error")
    except Exception as exc:
        log.error("Unexpected error downloading CISA KEV: %s", exc)
        update_feed_status("CISA KEV", Config.CISA_KEV_URL, "OFFLINE", error_message=str(exc))
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


def fetch_epss_batch(cve_ids: list[str]) -> dict[str, tuple[Optional[float], Optional[float]]]:
    """
    Fetch EPSS scores and percentiles for a list of CVE IDs in batched HTTP requests.
    Supports up to 50 CVE IDs per HTTP GET request, eliminating individual delays.
    """
    if not cve_ids:
        return {}

    unique_cves = sorted(list(set(cve_ids)))
    results: dict[str, tuple[Optional[float], Optional[float]]] = {}
    chunk_size = 50

    for i in range(0, len(unique_cves), chunk_size):
        chunk = unique_cves[i:i + chunk_size]
        url = f"{Config.EPSS_API_BASE}?cve={','.join(chunk)}"
        try:
            resp = requests.get(url, timeout=12)
            resp.raise_for_status()
            data = resp.json()
            for row in data.get('data', []):
                cid = row.get('cve')
                if cid:
                    try:
                        epss_val = float(row.get('epss', 0))
                        pct_val = float(row.get('percentile', 0))
                        results[cid] = (epss_val, pct_val)
                    except (ValueError, TypeError):
                        pass
        except Exception as exc:
            log.warning("Batch EPSS API request failed for %d CVEs: %s", len(chunk), exc)

    return results


def enrich_cves_batch(cve_ids: list[str]) -> dict[str, EnrichmentResult]:
    """
    Batch-enrich a list of CVE IDs with EPSS and CISA KEV data in a single optimized pass.
    """
    if not cve_ids:
        return {}

    unique_cves = list(set(cve_ids))
    epss_map = fetch_epss_batch(unique_cves)
    now = datetime.now(timezone.utc)

    results: dict[str, EnrichmentResult] = {}
    for cid in unique_cves:
        notes: list[str] = []
        epss_tuple = epss_map.get(cid)
        epss, epss_percentile = epss_tuple if epss_tuple else (None, None)
        epss_fetched_at = now if epss is not None else None

        if epss is None:
            epss_reason = f"EPSS record for {cid} is unavailable (feed unreachable or CVE not yet modelled)."
            epss_next_action = "Re-check FIRST EPSS API endpoint or retry enrichment when feed is updated."
            notes.append(
                f"EPSS unavailable for {cid} (feed unreachable or CVE not yet modelled). "
                "Scoring will use epss_effective=0.0 with reduced confidence."
            )
        else:
            pct_str = f" ({epss_percentile*100:.1f}th percentile)" if epss_percentile is not None else ""
            epss_reason = f"FIRST EPSS score {epss:.4f}{pct_str} active."
            epss_next_action = "No action required; EPSS score is active."

        is_kev, kev_status = _check_kev(cid)

        if kev_status == 'confirmed_fresh':
            kev_reason = f"CISA KEV catalog confirmed {'PRESENT' if is_kev else 'ABSENT'} for {cid}."
            kev_next_action = "No action required; KEV status verified against official CISA feed."
        elif kev_status == 'confirmed_not_kev':
            kev_reason = f"CISA KEV catalog confirmed ABSENT for {cid}."
            kev_next_action = "No action required; KEV status verified."
        elif kev_status == 'unavailable':
            kev_reason = f"CISA KEV catalog feed is unavailable."
            kev_next_action = "Check network connectivity to CISA KEV JSON catalog endpoint."
            notes.append(f"CISA KEV unavailable for {cid} — treated as not-KEV with reduced confidence.")
        elif kev_status == 'stale_absent':
            kev_reason = f"CISA KEV cache is stale (>{Config.CISA_KEV_CACHE_HOURS}h old)."
            kev_next_action = "Refresh CISA KEV feed cache."
            notes.append(
                f"CISA KEV cache is stale (>{Config.CISA_KEV_CACHE_HOURS}h old). "
                f"{cid} was NOT in KEV at last check — cannot confirm this is still accurate."
            )
        elif kev_status == 'stale_present':
            kev_reason = f"CISA KEV cache is stale. {cid} was in KEV at last check."
            kev_next_action = "Refresh CISA KEV feed cache to confirm current status."
            notes.append(
                f"CISA KEV cache is stale. {cid} WAS in KEV at last check — treating as in-KEV (conservative)."
            )
        else:
            kev_reason = f"CISA KEV status: {kev_status}."
            kev_next_action = "Verify KEV feed configuration."

        shodan_hosts = query_shodan_vulnerability(cid)
        vt_threats = query_virustotal_threat(cid)

        results[cid] = EnrichmentResult(
            cve_id=cid,
            epss=epss,
            epss_percentile=epss_percentile,
            epss_fetched_at=epss_fetched_at,
            epss_reason=epss_reason,
            epss_next_action=epss_next_action,
            is_kev=is_kev,
            kev_status=kev_status,
            kev_reason=kev_reason,
            kev_next_action=kev_next_action,
            shodan_exposed_hosts=shodan_hosts,
            virustotal_detections=vt_threats,
            degradation_notes=notes,
        )

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Public interface
# ─────────────────────────────────────────────────────────────────────────────

def enrich_cve(cve_id: str) -> EnrichmentResult:
    """
    Fetch EPSS score, CISA KEV status, and live Shodan/VT intelligence for a single CVE.
    """
    batch_res = enrich_cves_batch([cve_id])
    if cve_id in batch_res:
        return batch_res[cve_id]

    notes: list[str] = []
    epss, epss_percentile = fetch_epss(cve_id)
    epss_fetched_at = datetime.now(timezone.utc) if epss is not None else None

    if epss is None:
        epss_reason = f"EPSS record for {cve_id} is unavailable."
        epss_next_action = "Re-check FIRST EPSS endpoint."
        notes.append(f"EPSS unavailable for {cve_id}.")
    else:
        epss_reason = f"FIRST EPSS score {epss:.4f} active."
        epss_next_action = "No action required."

    is_kev, kev_status = _check_kev(cve_id)
    kev_reason = f"CISA KEV status: {kev_status}."
    kev_next_action = "No action required." if 'confirmed' in kev_status else "Check KEV feed connectivity."

    shodan_hosts = query_shodan_vulnerability(cve_id)
    vt_threats = query_virustotal_threat(cve_id)

    return EnrichmentResult(
        cve_id=cve_id,
        epss=epss,
        epss_percentile=epss_percentile,
        epss_fetched_at=epss_fetched_at,
        epss_reason=epss_reason,
        epss_next_action=epss_next_action,
        is_kev=is_kev,
        kev_status=kev_status,
        kev_reason=kev_reason,
        kev_next_action=kev_next_action,
        shodan_exposed_hosts=shodan_hosts,
        virustotal_detections=vt_threats,
        degradation_notes=notes,
    )

