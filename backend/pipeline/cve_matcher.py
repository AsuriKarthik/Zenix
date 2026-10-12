"""
CVE Matcher — finds CVEs affecting SBOM components via OSV.dev and NVD.

Data flow per component:
  1. Query OSV.dev (primary) — returns OSV vulnerability records with CVE aliases
  2. For each CVE ID found → query NVD (authoritative CVSS v3.1 + description)
  3. Combine into CVEMatch objects; caller writes to DB

Graceful degradation rules (all enforced here, not left to callers):
  - OSV down → return [] with a degradation note; log at WARNING, do NOT fail the job
  - NVD down for a specific CVE → cvss = None, data_quality = 'degraded', continue
  - NVD 429 (rate limit) → wait 35s, retry once; if still fails, mark degraded
  - Empty OSV result → could mean "no CVEs" or "query failed"; callers cannot distinguish
    these cases from the return value alone — they must check the degradation_notes field
    on each CVEMatch (or the absence of results combined with a logged warning)

Rate limiting:
  - NVD: 7 s/request without key, 0.65 s/request with key (set in config.py)
  - OSV: 0.5 s polite delay

Caching:
  - Caching against the DB is the caller's responsibility (the pipeline runner
    checks the Vulnerability table before calling this module).
  - This module is stateless and makes live HTTP calls every time it runs.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

_UTC = timezone.utc
from typing import Optional

import requests

from config import Config

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Public output type
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CVEMatch:
    """
    One CVE affecting a specific component, with all fetched data.

    Fields that could not be retrieved because a feed was unavailable are
    set to None — never to zero or a default value. Callers must propagate
    None through the scoring step (where it reduces confidence).
    """
    cve_id: str
    component_name: str
    component_version: Optional[str]

    # From NVD (None if NVD was unreachable or returned no data for this CVE)
    cvss: Optional[float]
    cvss_vector: Optional[str]
    description: Optional[str]

    # Provenance
    # 'osv'      — only OSV data available (NVD was down or CVE not in NVD)
    # 'nvd'      — NVD only (unusual; only if OSV record had no CVE alias and we queried NVD directly)
    # 'osv+nvd'  — both sources consulted; NVD data takes precedence for CVSS
    source: str = 'osv'

    # 'fresh'    — fetched within cache window, no degradation
    # 'degraded' — one or more feeds was unreachable; some data may be absent
    data_quality: str = 'fresh'

    nvd_fetched_at: Optional[datetime] = None

    # Human-readable notes explaining any degradation; shown to analysts
    degradation_notes: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter
# ─────────────────────────────────────────────────────────────────────────────

class _RateLimiter:
    """
    Simple monotonic-clock rate limiter.
    Ensures at least `delay_seconds` between consecutive calls.
    Not thread-safe — intended for single-worker use.
    """

    def __init__(self, delay_seconds: float):
        self._delay = delay_seconds
        self._last: float = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last
        if elapsed < self._delay:
            time.sleep(self._delay - elapsed)
        self._last = time.monotonic()


_nvd_limiter = _RateLimiter(Config.NVD_RATE_LIMIT_DELAY)
_osv_limiter = _RateLimiter(Config.OSV_RATE_LIMIT_DELAY)


# ─────────────────────────────────────────────────────────────────────────────
# OSV.dev
# ─────────────────────────────────────────────────────────────────────────────

# Map our normalized ecosystem names to OSV ecosystem names.
# OSV is case-sensitive for some ecosystems (e.g., 'PyPI' not 'pypi').
_OSV_ECOSYSTEM_MAP: dict[str, str] = {
    'npm': 'npm',
    'pypi': 'PyPI',
    'maven': 'Maven',
    'cargo': 'crates.io',
    'gem': 'RubyGems',
    'nuget': 'NuGet',
    'golang': 'Go',
    'packagist': 'Packagist',
    'hex': 'Hex',
    'pub': 'Pub',
    'swift': 'SwiftURL',
}


def _osv_ecosystem_name(ecosystem: Optional[str]) -> Optional[str]:
    if not ecosystem:
        return None
    return _OSV_ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)


def _query_osv(
    purl: Optional[str],
    name: str,
    version: Optional[str],
    ecosystem: Optional[str],
) -> list[dict]:
    """
    Query OSV.dev for vulnerabilities affecting a package.

    Prefers PURL-based queries (most precise).
    Falls back to name + ecosystem + version.
    Returns raw OSV vulnerability objects, or [] on any failure.

    OSV returning [] means either "no vulnerabilities found" or "query failed" —
    both are indistinguishable at the protocol level. Log accordingly.
    """
    _osv_limiter.wait()

    if purl:
        # PURL query — version is embedded in the PURL
        payload: dict = {'package': {'purl': purl}}
    else:
        osv_eco = _osv_ecosystem_name(ecosystem)
        if not name or not osv_eco:
            log.debug(
                "Cannot query OSV for '%s': no PURL and insufficient metadata "
                "(ecosystem='%s'). Skipping.",
                name, ecosystem,
            )
            return []

        payload = {'package': {'name': name, 'ecosystem': osv_eco}}
        if version:
            payload['version'] = version
        else:
            log.warning(
                "Querying OSV for '%s' without version — results will cover all versions "
                "and may include already-patched CVEs. Provide a version for precision.",
                name,
            )

    url = f"{Config.OSV_API_BASE}/query"
    try:
        resp = requests.post(url, json=payload, timeout=12)
        resp.raise_for_status()
        return resp.json().get('vulns', [])

    except requests.exceptions.Timeout:
        log.warning("OSV.dev query timed out for '%s'.", name)
    except requests.exceptions.ConnectionError:
        log.warning("OSV.dev is unreachable for '%s'. CVE matching will be incomplete.", name)
    except requests.exceptions.HTTPError as exc:
        log.warning("OSV.dev returned HTTP %s for '%s'.", exc.response.status_code, name)
    except Exception as exc:
        log.error("Unexpected error querying OSV for '%s': %s", name, exc)

    return []


def _extract_cve_ids(osv_vuln: dict) -> list[str]:
    """
    Extract CVE IDs from an OSV vulnerability record.

    OSV records can surface CVEs in two places:
      - osv_vuln['id'] — sometimes is itself a CVE ID
      - osv_vuln['aliases'] — list of IDs including CVE-XXXX-YYYY entries
    """
    cve_ids: list[str] = []

    primary = osv_vuln.get('id', '')
    if primary.startswith('CVE-'):
        cve_ids.append(primary)

    for alias in osv_vuln.get('aliases', []):
        if isinstance(alias, str) and alias.startswith('CVE-') and alias not in cve_ids:
            cve_ids.append(alias)

    return cve_ids


def _osv_cvss(osv_vuln: dict) -> tuple[Optional[float], Optional[str]]:
    """
    Try to extract a CVSS v3 score from an OSV severity field.

    OSV severity format (when present):
      [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}]

    Some providers also include the numerical score as a prefix:
      "9.8 CVSS:3.1/AV:N/..."

    Returns (score_float, vector_string), both None if not present or unparseable.
    NVD is authoritative; this is only used when NVD is unavailable.
    """
    for sev in osv_vuln.get('severity', []):
        if not isinstance(sev, dict):
            continue
        type_ = sev.get('type', '')
        if 'CVSS_V3' in type_ or 'CVSS_V31' in type_:
            raw_score = sev.get('score', '')
            score = _try_parse_cvss_prefix(raw_score)
            vector = raw_score if 'CVSS:' in raw_score else None
            return score, vector
    return None, None


def _try_parse_cvss_prefix(s: str) -> Optional[float]:
    """
    Some providers prefix the CVSS vector string with the numerical score:
    e.g., '9.8 CVSS:3.1/AV:N/...'

    Try to parse the leading number; return None if not found.
    """
    if not s:
        return None
    parts = s.strip().split()
    if parts:
        try:
            val = float(parts[0])
            if 0.0 <= val <= 10.0:
                return val
        except ValueError:
            pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# NVD API v2
# ─────────────────────────────────────────────────────────────────────────────

def _query_nvd(cve_id: str) -> Optional[dict]:
    """
    Query NVD API v2 for a specific CVE.

    Returns the raw NVD CVE object dict, or None if:
      - CVE not found in NVD (HTTP 404)
      - NVD is unreachable or returns an error
      - Rate limit hit and retry also failed

    Caller must treat None as "NVD data unavailable" and mark data_quality='degraded'.
    """
    _nvd_limiter.wait()

    params: dict = {'cveId': cve_id}
    if Config.NVD_API_KEY:
        params['apiKey'] = Config.NVD_API_KEY

    def _do_request() -> Optional[requests.Response]:
        try:
            return requests.get(Config.NVD_API_BASE, params=params, timeout=15)
        except requests.exceptions.Timeout:
            log.warning("NVD request timed out for %s.", cve_id)
        except requests.exceptions.ConnectionError:
            log.warning("NVD API unreachable for %s.", cve_id)
        except Exception as exc:
            log.error("Unexpected error querying NVD for %s: %s", cve_id, exc)
        return None

    resp = _do_request()
    if resp is None:
        return None

    if resp.status_code == 404:
        log.debug("%s not found in NVD.", cve_id)
        return None

    if resp.status_code == 403:
        log.warning("NVD API 403 for %s — key invalid or permanently rate-limited.", cve_id)
        return None

    if resp.status_code == 429:
        log.warning("NVD rate limit hit for %s. Waiting 35 s then retrying once.", cve_id)
        time.sleep(35)
        resp = _do_request()
        if resp is None or resp.status_code != 200:
            log.warning("NVD retry also failed for %s.", cve_id)
            return None

    try:
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return None
        return vulns[0].get('cve', {})
    except Exception as exc:
        log.error("Error parsing NVD response for %s: %s", cve_id, exc)
        return None


def _parse_nvd_cvss(nvd_cve: dict) -> tuple[Optional[float], Optional[str]]:
    """
    Extract the best available CVSS v3.x base score and vector from an NVD CVE object.

    Preference order: CVSS v3.1 → CVSS v3.0 → CVSS v2 (last resort).
    Returns (score_float, vector_string), both None if no metrics are present.
    """
    metrics = nvd_cve.get('metrics', {})

    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        for metric in metrics.get(key, []):
            cvss_data = metric.get('cvssData', {})
            score = cvss_data.get('baseScore')
            vector = cvss_data.get('vectorString')
            if score is not None:
                return float(score), vector

    return None, None


def _parse_nvd_description(nvd_cve: dict) -> Optional[str]:
    """Return the English description from an NVD CVE object, or None."""
    for desc in nvd_cve.get('descriptions', []):
        if isinstance(desc, dict) and desc.get('lang') == 'en':
            val = desc.get('value', '').strip()
            return val if val else None
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Public interface
# ─────────────────────────────────────────────────────────────────────────────

def find_cves_for_component(
    name: str,
    version: Optional[str],
    purl: Optional[str],
    ecosystem: Optional[str],
) -> list[CVEMatch]:
    """
    Find all CVEs affecting a given component.

    This is the main entry point. Call once per Component row.

    Args:
        name:      Component name (e.g., 'log4j-core')
        version:   Component version string (e.g., '2.14.1'), or None
        purl:      Package URL if available in the SBOM (preferred for OSV queries)
        ecosystem: Normalized ecosystem name (e.g., 'maven', 'npm'), or None

    Returns:
        List of CVEMatch objects. May be empty if:
          - No CVEs affect this component at this version (legitimate result)
          - OSV was unreachable (cannot distinguish from above — check logs)

    Each CVEMatch has:
        - cve_id, cvss, cvss_vector, description — from NVD where available
        - data_quality = 'degraded' if NVD was unavailable for that specific CVE
        - degradation_notes — human-readable list; shown to analysts, empty if clean
    """
    osv_vulns = _query_osv(purl, name, version, ecosystem)

    if not osv_vulns:
        # This is logged at debug; a WARNING was already emitted inside _query_osv
        # if the query actually failed (vs. returning empty results legitimately).
        return []

    # Deduplicate CVE IDs across OSV records
    # (the same CVE may appear in multiple OSV entries for the same package)
    seen: dict[str, dict] = {}   # cve_id → the first OSV vuln that carried it
    for osv_vuln in osv_vulns:
        for cve_id in _extract_cve_ids(osv_vuln):
            if cve_id not in seen:
                seen[cve_id] = osv_vuln

    results: list[CVEMatch] = []
    for cve_id, osv_vuln in seen.items():
        match = _build_match(cve_id, osv_vuln, name, version)
        results.append(match)

    return results


def _build_match(
    cve_id: str,
    osv_vuln: dict,
    component_name: str,
    component_version: Optional[str],
) -> CVEMatch:
    """
    Build a CVEMatch by combining an OSV record with an NVD lookup.

    NVD data is authoritative. OSV data is used as fallback when NVD is
    unavailable, and degradation_notes record exactly what happened.
    """
    notes: list[str] = []

    # Preliminary CVSS from OSV (often present as a vector in severity[])
    osv_score, osv_vector = _osv_cvss(osv_vuln)

    # Authoritative data from NVD
    nvd_data = _query_nvd(cve_id)
    nvd_fetched_at = datetime.now(_UTC)

    if nvd_data is not None:
        nvd_score, nvd_vector = _parse_nvd_cvss(nvd_data)
        description = _parse_nvd_description(nvd_data)

        # Use NVD score; fall back to OSV score only if NVD had no metrics
        cvss = nvd_score if nvd_score is not None else osv_score
        cvss_vector = nvd_vector if nvd_vector is not None else osv_vector
        source = 'osv+nvd'
        data_quality = 'fresh'

        if nvd_score is None and osv_score is not None:
            notes.append(
                f"NVD has no CVSS metrics for {cve_id}; "
                "using OSV-derived score (less authoritative)."
            )
            data_quality = 'degraded'
        elif nvd_score is None:
            notes.append(f"No CVSS score available for {cve_id} from NVD or OSV.")
            data_quality = 'degraded'
    else:
        # NVD was unavailable — use whatever OSV provided
        cvss = osv_score
        cvss_vector = osv_vector
        description = (osv_vuln.get('summary') or osv_vuln.get('details', '')).strip() or None
        source = 'osv'
        data_quality = 'degraded'
        nvd_fetched_at = None  # noqa: we explicitly mark no fetch
        notes.append(
            f"NVD was unreachable or {cve_id} was not found in NVD. "
            "CVSS score and description sourced from OSV only."
        )

    return CVEMatch(
        cve_id=cve_id,
        component_name=component_name,
        component_version=component_version,
        cvss=cvss,
        cvss_vector=cvss_vector,
        description=description,
        source=source,
        data_quality=data_quality,
        nvd_fetched_at=nvd_fetched_at,
        degradation_notes=notes,
    )
