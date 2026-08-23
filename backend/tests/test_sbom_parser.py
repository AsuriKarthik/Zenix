"""Tests for pipeline/sbom_parser.py"""

import json
import pytest

from pipeline.sbom_parser import (
    SBOMParseError,
    ParsedComponent,
    parse_cyclonedx_json,
    compute_sbom_sha256,
    _ecosystem_from_purl,
    _extract_sha256_hash,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _encode(obj: dict) -> bytes:
    return json.dumps(obj).encode('utf-8')


def _make_sbom(**overrides) -> dict:
    base = {
        'bomFormat': 'CycloneDX',
        'specVersion': '1.4',
        'components': [],
    }
    base.update(overrides)
    return base


def _make_component(**overrides) -> dict:
    base = {
        'type': 'library',
        'name': 'example-lib',
        'version': '1.0.0',
        'purl': 'pkg:npm/example-lib@1.0.0',
    }
    base.update(overrides)
    return base


# ─────────────────────────────────────────────────────────────────────────────
# Format validation
# ─────────────────────────────────────────────────────────────────────────────

class TestFormatValidation:

    def test_rejects_non_json(self):
        with pytest.raises(SBOMParseError, match="not valid JSON"):
            parse_cyclonedx_json(b"this is not json")

    def test_rejects_json_array_root(self):
        with pytest.raises(SBOMParseError, match="root must be a JSON object"):
            parse_cyclonedx_json(b"[1, 2, 3]")

    def test_rejects_spdx_with_helpful_message(self):
        sbom = _make_sbom(bomFormat='SPDX')
        with pytest.raises(SBOMParseError, match="SPDX"):
            parse_cyclonedx_json(_encode(sbom))

    def test_rejects_unknown_format(self):
        sbom = _make_sbom(bomFormat='CustomFormat')
        with pytest.raises(SBOMParseError, match="Unrecognised SBOM format"):
            parse_cyclonedx_json(_encode(sbom))

    def test_rejects_unsupported_spec_version(self):
        sbom = _make_sbom(specVersion='1.0')
        with pytest.raises(SBOMParseError, match="Unsupported CycloneDX specVersion"):
            parse_cyclonedx_json(_encode(sbom))

    def test_accepts_supported_spec_versions(self):
        for version in ('1.2', '1.3', '1.4', '1.5', '1.6', '1.7'):
            sbom = _make_sbom(specVersion=version)
            result = parse_cyclonedx_json(_encode(sbom))
            assert result == [], f"Expected empty list for v{version} with no components"

    def test_rejects_components_not_array(self):
        sbom = _make_sbom(components={'not': 'a list'})
        with pytest.raises(SBOMParseError, match="'components' field must be a JSON array"):
            parse_cyclonedx_json(_encode(sbom))

    def test_rejects_component_not_object(self):
        sbom = _make_sbom(components=['a string, not an object'])
        with pytest.raises(SBOMParseError, match="index 0 is not a JSON object"):
            parse_cyclonedx_json(_encode(sbom))


# ─────────────────────────────────────────────────────────────────────────────
# Component extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestComponentExtraction:

    def test_extracts_basic_component(self, sample_sbom_bytes):
        components = parse_cyclonedx_json(sample_sbom_bytes)
        assert len(components) == 4

        names = [c.name for c in components]
        assert 'log4j-core' in names
        assert 'jackson-databind' in names
        assert 'requests' in names
        assert 'lodash' in names

    def test_extracts_version(self, sample_sbom_bytes):
        components = parse_cyclonedx_json(sample_sbom_bytes)
        log4j = next(c for c in components if c.name == 'log4j-core')
        assert log4j.version == '2.14.1'

    def test_extracts_purl(self, sample_sbom_bytes):
        components = parse_cyclonedx_json(sample_sbom_bytes)
        log4j = next(c for c in components if c.name == 'log4j-core')
        assert log4j.purl == 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1'

    def test_extracts_sha256_hash(self, sample_sbom_bytes):
        components = parse_cyclonedx_json(sample_sbom_bytes)
        log4j = next(c for c in components if c.name == 'log4j-core')
        assert log4j.file_hash is not None
        assert len(log4j.file_hash) == 64  # SHA-256 hex

    def test_component_without_hash_has_none(self, sample_sbom_bytes):
        components = parse_cyclonedx_json(sample_sbom_bytes)
        requests_comp = next(c for c in components if c.name == 'requests')
        assert requests_comp.file_hash is None

    def test_skips_component_without_name(self):
        sbom = _make_sbom(components=[
            _make_component(name='valid-lib'),
            {'type': 'library', 'version': '1.0.0'},   # no name
        ])
        result = parse_cyclonedx_json(_encode(sbom))
        assert len(result) == 1
        assert result[0].name == 'valid-lib'

    def test_skips_unsupported_types(self):
        sbom = _make_sbom(components=[
            _make_component(type='container'),
            _make_component(type='device'),
            _make_component(type='library', name='kept-lib'),
        ])
        result = parse_cyclonedx_json(_encode(sbom))
        assert len(result) == 1
        assert result[0].name == 'kept-lib'

    def test_empty_components_returns_empty_list(self):
        sbom = _make_sbom(components=[])
        result = parse_cyclonedx_json(_encode(sbom))
        assert result == []

    def test_version_none_when_absent(self):
        sbom = _make_sbom(components=[
            {'type': 'library', 'name': 'no-version-lib'}
        ])
        result = parse_cyclonedx_json(_encode(sbom))
        assert result[0].version is None

    def test_purl_none_when_absent(self):
        sbom = _make_sbom(components=[
            {'type': 'library', 'name': 'no-purl-lib', 'version': '1.0.0'}
        ])
        result = parse_cyclonedx_json(_encode(sbom))
        assert result[0].purl is None
        assert result[0].ecosystem is None


# ─────────────────────────────────────────────────────────────────────────────
# Ecosystem extraction from PURL
# ─────────────────────────────────────────────────────────────────────────────

class TestEcosystemExtraction:

    @pytest.mark.parametrize('purl,expected', [
        ('pkg:npm/lodash@4.17.20',                                        'npm'),
        ('pkg:pypi/requests@2.28.0',                                      'pypi'),
        ('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',         'maven'),
        ('pkg:cargo/serde@1.0.152',                                       'cargo'),
        ('pkg:gem/rails@7.0.0',                                           'gem'),
        ('pkg:nuget/Newtonsoft.Json@13.0.1',                              'nuget'),
        ('pkg:golang/github.com/gorilla/mux@v1.8.0',                     'golang'),
    ])
    def test_extracts_ecosystem(self, purl, expected):
        assert _ecosystem_from_purl(purl) == expected

    def test_returns_none_for_invalid_purl(self):
        assert _ecosystem_from_purl('not-a-purl') is None
        assert _ecosystem_from_purl('') is None
        assert _ecosystem_from_purl(None) is None  # type: ignore

    def test_ecosystem_is_lowercase(self):
        # PURL types are case-insensitive per spec; we normalise to lower
        assert _ecosystem_from_purl('pkg:NPM/lodash@4.0.0') == 'npm'


# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 extraction
# ─────────────────────────────────────────────────────────────────────────────

class TestHashExtraction:

    def test_extracts_sha256(self):
        hashes = [{'alg': 'SHA-256', 'content': 'abc123def456'}]
        assert _extract_sha256_hash(hashes) == 'abc123def456'

    def test_ignores_other_algorithms(self):
        hashes = [
            {'alg': 'MD5', 'content': 'md5hash'},
            {'alg': 'SHA-1', 'content': 'sha1hash'},
        ]
        assert _extract_sha256_hash(hashes) is None

    def test_prefers_sha256_over_others(self):
        hashes = [
            {'alg': 'MD5', 'content': 'md5hash'},
            {'alg': 'SHA-256', 'content': 'sha256hash'},
        ]
        assert _extract_sha256_hash(hashes) == 'sha256hash'

    def test_returns_none_for_empty_list(self):
        assert _extract_sha256_hash([]) is None

    def test_returns_none_for_non_list(self):
        assert _extract_sha256_hash(None) is None  # type: ignore


# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

def test_compute_sbom_sha256_is_deterministic():
    data = b'{"bomFormat": "CycloneDX"}'
    h1 = compute_sbom_sha256(data)
    h2 = compute_sbom_sha256(data)
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_compute_sbom_sha256_differs_for_different_content():
    assert compute_sbom_sha256(b'aaa') != compute_sbom_sha256(b'bbb')


# ─────────────────────────────────────────────────────────────────────────────
# SBOM Normalization & Manifest Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSbomNormalization:

    def test_unwraps_spdx_inside_sbom_wrapper(self):
        wrapped = {
            "sbom": {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "packages": [
                    {
                        "name": "log4j-core",
                        "versionInfo": "2.14.1",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                            }
                        ]
                    }
                ]
            }
        }
        res = parse_cyclonedx_json(_encode(wrapped))
        assert len(res) == 1
        assert res[0].name == "log4j-core"
        assert res[0].version == "2.14.1"
        assert res[0].purl == "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"

    def test_unwraps_cyclonedx_inside_sbom_wrapper(self):
        wrapped = {
            "sbom": _make_sbom(components=[_make_component(name="wrapped-lib")])
        }
        res = parse_cyclonedx_json(_encode(wrapped))
        assert len(res) == 1
        assert res[0].name == "wrapped-lib"

    def test_unwraps_nested_data_sbom_wrapper(self):
        wrapped = {
            "data": {
                "sbom": _make_sbom(components=[_make_component(name="deep-lib")])
            }
        }
        res = parse_cyclonedx_json(_encode(wrapped))
        assert len(res) == 1
        assert res[0].name == "deep-lib"

    def test_parses_requirements_txt(self):
        reqs = b"requests==2.28.0\nlodash>=4.17.20\nflask~=2.2.0\n"
        res = parse_cyclonedx_json(reqs)
        assert len(res) == 3
        names = [r.name for r in res]
        assert "requests" in names
        assert "lodash" in names
        assert "flask" in names

    def test_parses_go_mod(self):
        go_mod = b"module example.com/myapp\n\ngo 1.20\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/crypto v0.8.0\n)\n"
        res = parse_cyclonedx_json(go_mod)
        assert len(res) == 2
        names = [r.name for r in res]
        assert "gin" in names
        assert "crypto" in names

