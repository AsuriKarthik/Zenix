"""
Tests for pipeline/cve_matcher.py

All HTTP calls to OSV.dev and NVD are mocked with the `responses` library.
No real network calls are made.

Fixtures use realistic OSV and NVD response payloads so that the parsing
logic is tested against the same structure the real APIs return.
"""

import json
from datetime import datetime
from typing import Optional

import pytest
import responses as resp_lib

from pipeline.cve_matcher import (
    CVEMatch,
    find_cves_for_component,
    _extract_cve_ids,
    _osv_cvss,
    _parse_nvd_cvss,
    _parse_nvd_description,
    _NVD_CACHE,
)
from pipeline.sbom_parser import _ecosystem_from_purl
from config import Config


@pytest.fixture(autouse=True)
def clear_nvd_cache():
    _NVD_CACHE.clear()
    yield
    _NVD_CACHE.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Realistic API response payloads (trimmed for clarity)
# ─────────────────────────────────────────────────────────────────────────────

OSV_LOG4J_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-jfh8-c2jp-hdp2",
            "aliases": ["CVE-2021-44228"],
            "summary": "Remote code execution in Log4j 2",
            "details": "Log4Shell — remote code execution via JNDI lookup.",
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}]
                }
            ]
        }
    ]
}

NVD_LOG4J_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "sourceIdentifier": "security@apache.org",
                "published": "2021-12-10T10:15:00.000",
                "lastModified": "2023-04-03T20:15:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features allow RCE."
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL"
                            },
                            "impactScore": 6.0,
                            "exploitabilityScore": 3.9
                        }
                    ]
                }
            }
        }
    ]
}

OSV_EMPTY_RESPONSE = {"vulns": []}

NVD_NOT_FOUND_RESPONSE = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "vulnerabilities": []
}


# ─────────────────────────────────────────────────────────────────────────────
# Unit tests for internal parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestCVEIdExtraction:

    def test_extracts_cve_from_aliases(self):
        vuln = {'id': 'GHSA-xxxx', 'aliases': ['CVE-2021-44228', 'CVE-2021-45046']}
        assert _extract_cve_ids(vuln) == ['CVE-2021-44228', 'CVE-2021-45046']

    def test_extracts_cve_from_id_field(self):
        vuln = {'id': 'CVE-2021-99999', 'aliases': []}
        assert _extract_cve_ids(vuln) == ['CVE-2021-99999']

    def test_deduplicates_cve_in_id_and_aliases(self):
        vuln = {'id': 'CVE-2021-44228', 'aliases': ['CVE-2021-44228']}
        result = _extract_cve_ids(vuln)
        assert result.count('CVE-2021-44228') == 1

    def test_ignores_non_cve_aliases(self):
        vuln = {'id': 'GHSA-xxxx', 'aliases': ['GHSA-yyyy', 'PYSEC-2021-1']}
        assert _extract_cve_ids(vuln) == []

    def test_empty_vuln_returns_empty_list(self):
        assert _extract_cve_ids({}) == []


class TestOSVCVSSParsing:

    def test_parses_cvss_with_numeric_prefix(self):
        vuln = {
            'severity': [
                {'type': 'CVSS_V3', 'score': '9.8 CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}
            ]
        }
        score, vector = _osv_cvss(vuln)
        assert score == 9.8
        assert 'CVSS:3.1' in (vector or "")

    def test_returns_none_when_no_severity(self):
        assert _osv_cvss({}) == (None, None)
        assert _osv_cvss({'severity': []}) == (None, None)

    def test_ignores_cvss_v2_severity(self):
        vuln = {
            'severity': [
                {'type': 'CVSS_V2', 'score': '7.5 AV:N/AC:L/Au:N/C:P/I:P/A:P'}
            ]
        }
        score, vector = _osv_cvss(vuln)
        assert score is None


class TestNVDParsing:

    def test_parses_cvss_v31(self):
        nvd_cve = NVD_LOG4J_RESPONSE['vulnerabilities'][0]['cve']
        score, vector = _parse_nvd_cvss(nvd_cve)
        assert score == 10.0
        assert 'CVSS:3.1' in (vector or "")

    def test_returns_none_for_no_metrics(self):
        nvd_cve = {'metrics': {}}
        assert _parse_nvd_cvss(nvd_cve) == (None, None)

    def test_parses_english_description(self):
        nvd_cve = NVD_LOG4J_RESPONSE['vulnerabilities'][0]['cve']
        desc = _parse_nvd_description(nvd_cve)
        assert desc is not None
        assert 'Log4j' in desc

    def test_returns_none_when_no_english_description(self):
        nvd_cve = {
            'descriptions': [{'lang': 'es', 'value': 'Descripción en español'}]
        }
        assert _parse_nvd_description(nvd_cve) is None


# ─────────────────────────────────────────────────────────────────────────────
# Integration tests (mocked HTTP)
# ─────────────────────────────────────────────────────────────────────────────

class TestFindCVEsForComponent:

    @resp_lib.activate
    def test_finds_log4j_cve(self):
        """Happy path: OSV returns a hit, NVD confirms with CVSS."""
        resp_lib.add(
            resp_lib.POST,
            f"{Config.OSV_API_BASE}/query",
            json=OSV_LOG4J_RESPONSE,
            status=200,
        )
        resp_lib.add(
            resp_lib.GET,
            Config.NVD_API_BASE,
            json=NVD_LOG4J_RESPONSE,
            status=200,
        )

        results = find_cves_for_component(
            name='log4j-core',
            version='2.14.1',
            purl='pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            ecosystem='maven',
        )

        assert len(results) == 1
        match = results[0]
        assert match.cve_id == 'CVE-2021-44228'
        assert match.cvss == 10.0
        assert match.cvss_vector is not None
        assert match.description is not None
        assert match.source == 'osv+nvd'
        assert match.data_quality == 'fresh'
        assert match.degradation_notes == []

    @resp_lib.activate
    def test_returns_empty_when_osv_has_no_results(self):
        resp_lib.add(
            resp_lib.POST,
            f"{Config.OSV_API_BASE}/query",
            json=OSV_EMPTY_RESPONSE,
            status=200,
        )

        results = find_cves_for_component(
            name='some-safe-lib',
            version='1.0.0',
            purl='pkg:npm/some-safe-lib@1.0.0',
            ecosystem='npm',
        )
        assert results == []

    @resp_lib.activate
    def test_degraded_when_nvd_unreachable(self):
        """OSV finds a CVE but NVD is down — should return degraded match, not fail."""
        resp_lib.add(
            resp_lib.POST,
            f"{Config.OSV_API_BASE}/query",
            json=OSV_LOG4J_RESPONSE,
            status=200,
        )
        resp_lib.add(
            resp_lib.GET,
            Config.NVD_API_BASE,
            body=Exception("Connection refused"),
        )

        results = find_cves_for_component(
            name='log4j-core',
            version='2.14.1',
            purl='pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            ecosystem='maven',
        )

        assert len(results) == 1
        match = results[0]
        assert match.cve_id == 'CVE-2021-44228'
        assert match.source == 'osv'
        assert match.data_quality == 'degraded'
        assert len(match.degradation_notes) > 0
        # CVSS from OSV severity field (9.8 prefix) should be used as fallback
        assert match.cvss == 9.8

    @resp_lib.activate
    def test_degraded_when_osv_returns_500(self):
        """OSV server error — return empty, don't crash."""
        resp_lib.add(
            resp_lib.POST,
            f"{Config.OSV_API_BASE}/query",
            status=500,
        )

        results = find_cves_for_component(
            name='some-lib',
            version='1.0.0',
            purl='pkg:npm/some-lib@1.0.0',
            ecosystem='npm',
        )
        assert results == []

    @resp_lib.activate
    def test_deduplicates_cve_across_multiple_osv_records(self):
        """If two OSV records both alias the same CVE, only one CVEMatch is returned."""
        osv_response = {
            "vulns": [
                {"id": "GHSA-aaaa", "aliases": ["CVE-2021-44228"], "severity": []},
                {"id": "GHSA-bbbb", "aliases": ["CVE-2021-44228"], "severity": []},
            ]
        }
        resp_lib.add(
            resp_lib.POST,
            f"{Config.OSV_API_BASE}/query",
            json=osv_response,
            status=200,
        )
        resp_lib.add(
            resp_lib.GET,
            Config.NVD_API_BASE,
            json=NVD_LOG4J_RESPONSE,
            status=200,
        )

        results = find_cves_for_component(
            name='log4j-core', version='2.14.1',
            purl='pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
            ecosystem='maven',
        )
        cve_ids = [r.cve_id for r in results]
        assert cve_ids.count('CVE-2021-44228') == 1

    def test_returns_empty_when_insufficient_metadata(self):
        """No PURL, no ecosystem — cannot query OSV meaningfully."""
        results = find_cves_for_component(
            name='some-lib',
            version=None,
            purl=None,
            ecosystem=None,
        )
        assert results == []
