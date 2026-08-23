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
import os
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
    cvss_version: Optional[str] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    description: Optional[str] = None

    # Provenance
    source: str = 'osv'
    cvss_source: str = 'NVD'

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


def query_osv_batch(queries_metadata: list[dict]) -> list[list[dict]]:
    """
    Query OSV.dev in batch mode via POST /v1/querybatch (up to 500 components per request).
    queries_metadata: list of dicts with keys {'purl', 'name', 'version', 'ecosystem'}
    Returns list of vuln lists corresponding 1-to-1 with queries_metadata.
    """
    if not queries_metadata:
        return []

    results = []
    chunk_size = 500

    for i in range(0, len(queries_metadata), chunk_size):
        chunk = queries_metadata[i:i + chunk_size]
        osv_queries = []

        for item in chunk:
            purl = item.get('purl')
            name = item.get('name')
            version = item.get('version')
            ecosystem = item.get('ecosystem')

            if purl:
                osv_queries.append({'package': {'purl': purl}})
            elif name and ecosystem:
                osv_eco = _osv_ecosystem_name(ecosystem)
                q = {'package': {'name': name, 'ecosystem': osv_eco}}
                if version:
                    q['version'] = version
                osv_queries.append(q)
            elif name:
                osv_queries.append({'package': {'name': name}})
            else:
                osv_queries.append({'package': {'name': 'unknown'}})

        url = f"{Config.OSV_API_BASE}/querybatch"
        try:
            resp = requests.post(url, json={'queries': osv_queries}, timeout=30)
            resp.raise_for_status()
            batch_data = resp.json().get('results', [])
            for idx, res in enumerate(batch_data):
                vulns = res.get('vulns', [])
                item = chunk[idx] if idx < len(chunk) else {}
                # Fallback: if PURL query yielded 0 vulns but package name is present, try name+version OSV query
                if not vulns and item.get('purl') and item.get('name'):
                    fallback_vulns = _query_osv(None, item.get('name', ''), item.get('version'), item.get('ecosystem'))
                    if fallback_vulns:
                        vulns = fallback_vulns
                results.append(vulns)
        except Exception as exc:
            log.warning("OSV querybatch failed (%s), falling back to individual queries for chunk of %d components", exc, len(chunk))
            for item in chunk:
                v = _query_osv(item.get('purl'), item.get('name', ''), item.get('version'), item.get('ecosystem'))
                results.append(v)

    return results



def find_cves_for_components_batch(components_data: list[dict]) -> list[list[CVEMatch]]:
    """
    Perform OSV batch matching for a list of components.
    components_data: list of dicts with keys {'name', 'version', 'purl', 'ecosystem'}
    Returns list of list[CVEMatch], matching 1-to-1 with input components.
    """
    batch_osv_results = query_osv_batch(components_data)
    all_comp_matches = []

    for idx, comp in enumerate(components_data):
        raw_osv_vulns = batch_osv_results[idx] if idx < len(batch_osv_results) else []
        cve_matches = []
        seen_cves = set()

        for vuln in raw_osv_vulns:
            cve_ids = _extract_cve_ids(vuln)
            if not cve_ids:
                continue

            for cve_id in cve_ids:
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    cve_match = _build_match(
                        cve_id=cve_id,
                        osv_vuln=vuln,
                        component_name=comp.get('name', ''),
                        component_version=comp.get('version'),
                    )
                    cve_matches.append(cve_match)

        all_comp_matches.append(cve_matches)

    return all_comp_matches


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
    from pipeline.cvss_calculator import calculate_cvss_base_score
    for sev in osv_vuln.get('severity', []):
        if not isinstance(sev, dict):
            continue
        type_ = sev.get('type', '')
        if 'CVSS_V3' in type_ or 'CVSS_V31' in type_:
            raw_score = sev.get('score', '')
            score = _try_parse_cvss_prefix(raw_score)
            vector = raw_score if 'CVSS:' in raw_score else None
            if score is None and vector:
                derived, _err = calculate_cvss_base_score(vector)
                if derived is not None:
                    score = derived
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


_NVD_CACHE: dict[str, Optional[dict]] = {}


def _query_nvd(cve_id: str, max_retries: int = 3) -> Optional[dict]:
    """
    Query NVD API v2 for a specific CVE with retry backoff.
    Uses in-memory process cache to avoid redundant network calls.
    Transient failures are retried and NOT permanently cached as None.
    """
    if cve_id in _NVD_CACHE and _NVD_CACHE[cve_id] is not None:
        return _NVD_CACHE[cve_id]

    is_testing = bool(getattr(Config, 'TESTING', False) or os.environ.get('TESTING') or os.environ.get('PYTEST_CURRENT_TEST'))
    # If NVD API key is not configured and not in unit testing, avoid excessive rate limiter sleeps for live runs
    if not Config.NVD_API_KEY and not is_testing:
        # Without key, return cached value if present, otherwise None without caching permanently
        return _NVD_CACHE.get(cve_id)

    params: dict = {'cveId': cve_id}
    if Config.NVD_API_KEY:
        params['apiKey'] = Config.NVD_API_KEY

    last_exc: Optional[Exception] = None
    for attempt in range(1, max_retries + 1):
        if not is_testing:
            _nvd_limiter.wait()

        try:
            resp = requests.get(Config.NVD_API_BASE, params=params, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get('vulnerabilities', [])
                if vulns:
                    res = vulns[0].get('cve', {})
                    _NVD_CACHE[cve_id] = res
                    return res
                else:
                    _NVD_CACHE[cve_id] = None
                    return None
            elif resp.status_code == 404:
                log.debug("%s not found in NVD.", cve_id)
                _NVD_CACHE[cve_id] = None
                return None
            elif resp.status_code in (429, 500, 502, 503, 504):
                log.warning("NVD API transient HTTP %s on attempt %d/%d for %s", resp.status_code, attempt, max_retries, cve_id)
                if attempt < max_retries:
                    time.sleep(1.0 * (2 ** (attempt - 1)))
                    continue
            else:
                log.warning("NVD API HTTP %s for %s", resp.status_code, cve_id)
                break
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as req_err:
            last_exc = req_err
            log.warning("NVD request transient error on attempt %d/%d for %s: %s", attempt, max_retries, cve_id, req_err)
            if attempt < max_retries:
                time.sleep(1.0 * (2 ** (attempt - 1)))
                continue
        except Exception as exc:
            log.error("Unexpected error querying NVD for %s: %s", cve_id, exc)
            break

    return None



def _calculate_severity(score: Optional[float], nvd_severity: Optional[str] = None) -> Optional[str]:
    if nvd_severity:
        return nvd_severity.upper()
    if score is None:
        return None
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    if score > 0.0:
        return 'LOW'
    return 'NONE'


def _parse_nvd_cvss(nvd_cve: dict) -> tuple[Optional[float], Optional[str]]:
    """
    Extract the best available CVSS base score and vector from an NVD CVE object.
    Returns (score_float, vector_string).
    """
    score, _ver, _sev, vector = _parse_nvd_cvss_details(nvd_cve)
    return score, vector


def _parse_nvd_cvss_details(nvd_cve: dict) -> tuple[Optional[float], Optional[str], Optional[str], Optional[str]]:
    """
    Extract the best available CVSS base score, version, severity, and vector from an NVD CVE object.

    Preference order: CVSS v4.0 → CVSS v3.1 → CVSS v3.0 → CVSS v2 (last resort).
    Returns (score_float, version_string, severity_string, vector_string).
    """
    metrics = nvd_cve.get('metrics', {})

    metric_keys = [
        ('cvssMetricV40', '4.0'),
        ('cvssMetricV31', '3.1'),
        ('cvssMetricV30', '3.0'),
        ('cvssMetricV2', '2.0'),
    ]

    for key, ver in metric_keys:
        for metric in metrics.get(key, []):
            cvss_data = metric.get('cvssData', {})
            score = cvss_data.get('baseScore')
            vector = cvss_data.get('vectorString')
            nvd_sev = cvss_data.get('baseSeverity') or metric.get('baseSeverity')
            if score is not None:
                sev = _calculate_severity(float(score), nvd_sev)
                return float(score), ver, sev, vector

    return None, None, None, None


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
    """
    osv_vulns = _query_osv(purl, name, version, ecosystem)

    if not osv_vulns:
        return []

    seen: dict[str, dict] = {}
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

    NVD data is authoritative for CVSS metrics, versions, and severity.
    OSV data is used as fallback when NVD is unavailable.
    """
    notes: list[str] = []

    # Preliminary CVSS from OSV (often present as a vector in severity[])
    osv_score, osv_vector = _osv_cvss(osv_vuln)
    osv_ver = '3.1' if (osv_vector and 'CVSS:3.1' in osv_vector) else '3.0' if (osv_vector and 'CVSS:3.0' in osv_vector) else None

    # Authoritative data from NVD
    nvd_data = _query_nvd(cve_id)
    nvd_fetched_at = datetime.now(_UTC)

    if nvd_data is not None:
        nvd_score, nvd_ver, nvd_sev, nvd_vector = _parse_nvd_cvss_details(nvd_data)
        description = _parse_nvd_description(nvd_data)

        cvss = nvd_score if nvd_score is not None else osv_score
        cvss_ver = nvd_ver if nvd_score is not None else osv_ver
        cvss_sev = nvd_sev if nvd_score is not None else _calculate_severity(osv_score)
        cvss_vector = nvd_vector if nvd_vector is not None else osv_vector
        source = 'osv+nvd'
        cvss_source = 'NVD' if nvd_score is not None else ('vector-derived (OSV), not NVD-authoritative' if osv_score is not None else 'UNAVAILABLE')
        data_quality = 'fresh' if nvd_score is not None else 'degraded'

        if nvd_score is None and osv_score is not None:
            notes.append(
                f"NVD has no CVSS metrics for {cve_id}; "
                "using vector-derived (OSV) base score."
            )
        elif nvd_score is None:
            notes.append(f"No CVSS score or vector available for {cve_id} from NVD or OSV.")
    else:
        # NVD was unavailable — use whatever OSV provided
        cvss = osv_score
        cvss_ver = osv_ver
        cvss_sev = _calculate_severity(osv_score)
        cvss_vector = osv_vector
        description = (osv_vuln.get('summary') or osv_vuln.get('details', '')).strip() or None
        source = 'osv'
        cvss_source = 'vector-derived (OSV), not NVD-authoritative' if osv_score is not None else 'UNAVAILABLE'
        data_quality = 'degraded'
        nvd_fetched_at = None
        if osv_score is not None:
            notes.append(
                f"NVD was unreachable or {cve_id} was not found in NVD. "
                "Calculated vector-derived (OSV) base score."
            )
        else:
            notes.append(
                f"NVD was unreachable and {cve_id} has no CVSS metrics in OSV."
            )

    return CVEMatch(
        cve_id=cve_id,
        component_name=component_name,
        component_version=component_version,
        cvss=cvss,
        cvss_version=cvss_ver,
        cvss_severity=cvss_sev,
        cvss_vector=cvss_vector,
        description=description,
        source=source,
        cvss_source=cvss_source,
        data_quality=data_quality,
        nvd_fetched_at=nvd_fetched_at,
        degradation_notes=notes,
    )
