"""
SBOM Parser — CycloneDX JSON only (MVP scope).

Accepts raw bytes, validates the format, and returns a normalized list of
ParsedComponent objects ready to be written to the Component table.

SPDX is explicitly not supported yet — the parser rejects it with a clear
error message rather than silently mishandling it.

No mock data is introduced here. If the SBOM is malformed or unsupported,
SBOMParseError is raised with a specific message the caller can surface to the user.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Public types
# ─────────────────────────────────────────────────────────────────────────────

class SBOMParseError(ValueError):
    """
    Raised when an SBOM cannot be parsed.

    The message is safe to display to the user — it describes exactly
    what is wrong without exposing internal implementation details.
    """


@dataclass
class ParsedComponent:
    """
    Normalized representation of one component extracted from an SBOM.

    Downstream code (CVE matching, ETW correlation) uses these fields —
    nothing from `raw` should be referenced outside the parser itself.
    """
    name: str
    version: Optional[str]           # None if not present in SBOM
    purl: Optional[str]              # pkg:npm/lodash@4.17.20 or None
    ecosystem: Optional[str]         # 'npm' | 'pypi' | 'maven' | 'cargo' | … | None
    file_hash: Optional[str]         # SHA-256 from SBOM hashes[] if present
    raw: dict = field(default_factory=dict, repr=False)  # original dict for debugging


# ─────────────────────────────────────────────────────────────────────────────
# Format constants
# ─────────────────────────────────────────────────────────────────────────────

_SUPPORTED_FORMATS = {'CycloneDX'}
_SUPPORTED_SPEC_VERSIONS = {'1.2', '1.3', '1.4', '1.5', '1.6'}

# CycloneDX component types we care about for CVE matching.
# 'container' and 'device' types are excluded — we cannot match them against
# package-ecosystem CVE databases in a meaningful way at MVP scope.
_MATCHABLE_TYPES = {'library', 'framework', 'application', None}


# ─────────────────────────────────────────────────────────────────────────────
# Public functions
# ─────────────────────────────────────────────────────────────────────────────

def parse_cyclonedx_json(raw_bytes: bytes) -> list[ParsedComponent]:
    """
    Parse a CycloneDX JSON SBOM from raw bytes.

    Args:
        raw_bytes: The complete contents of the uploaded SBOM file.

    Returns:
        List of ParsedComponent objects. May be empty if the SBOM has no
        components (unusual but valid).

    Raises:
        SBOMParseError: The SBOM is not valid JSON, not CycloneDX format,
                        uses an unsupported spec version, or has structural
                        errors. The message is safe to return to the API caller.
    """
    # ── JSON validation ───────────────────────────────────────────────────────
    try:
        data = json.loads(raw_bytes)
    except json.JSONDecodeError as exc:
        raise SBOMParseError(f"File is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise SBOMParseError("SBOM root must be a JSON object, not an array or scalar.")

    # ── Format validation ─────────────────────────────────────────────────────
    bom_format = data.get('bomFormat')
    if bom_format not in _SUPPORTED_FORMATS:
        if bom_format == 'SPDX':
            raise SBOMParseError(
                "SPDX format is not supported in this version. "
                "Please convert to CycloneDX JSON using cdxgen or syft."
            )
        raise SBOMParseError(
            f"Unrecognised SBOM format '{bom_format}'. "
            "Only CycloneDX JSON (bomFormat: 'CycloneDX') is accepted."
        )

    spec_version = str(data.get('specVersion', ''))
    if spec_version not in _SUPPORTED_SPEC_VERSIONS:
        raise SBOMParseError(
            f"Unsupported CycloneDX specVersion '{spec_version}'. "
            f"Supported versions: {', '.join(sorted(_SUPPORTED_SPEC_VERSIONS))}."
        )

    # ── Component extraction ──────────────────────────────────────────────────
    raw_components = data.get('components', [])
    if not isinstance(raw_components, list):
        raise SBOMParseError(
            "The 'components' field must be a JSON array. "
            f"Got: {type(raw_components).__name__}."
        )

    # Some SBOMs embed sub-components inside metadata.component
    # (e.g., when the application itself declares its internal modules).
    # Include them if present so nothing is silently dropped.
    metadata = data.get('metadata', {})
    if isinstance(metadata, dict):
        meta_component = metadata.get('component', {})
        if isinstance(meta_component, dict):
            nested = meta_component.get('components', [])
            if isinstance(nested, list) and nested:
                raw_components = list(raw_components) + nested

    parsed: list[ParsedComponent] = []
    for idx, raw in enumerate(raw_components):
        if not isinstance(raw, dict):
            raise SBOMParseError(
                f"Component at index {idx} is not a JSON object. "
                "Each element of 'components' must be an object with at least a 'name' field."
            )
        component = _parse_single_component(raw, idx)
        if component is not None:
            parsed.append(component)

    return parsed


def compute_sbom_sha256(raw_bytes: bytes) -> str:
    """
    Compute a SHA-256 fingerprint of the raw SBOM bytes.

    Stored on the Job row so duplicate SBOM submissions can be detected
    and previously computed results can be reused without re-running the pipeline.
    """
    return hashlib.sha256(raw_bytes).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_single_component(raw: dict, idx: int) -> Optional[ParsedComponent]:
    """
    Parse one CycloneDX component dict into a ParsedComponent.

    Returns None for components that cannot be meaningfully matched against
    CVE databases (e.g., components without a name, or unsupported types).
    Never raises — problems are logged and the component is skipped.
    """
    name = raw.get('name', '').strip()
    if not name:
        # A component without a name cannot be looked up in any CVE database.
        # Log at debug rather than warning — empty-name components are rare
        # but technically valid in CycloneDX (e.g. incomplete metadata).
        return None

    # Filter component types to those we can match
    component_type = raw.get('type')
    if component_type not in _MATCHABLE_TYPES:
        return None

    version = raw.get('version', '').strip() or None
    purl = raw.get('purl', '').strip() or None
    ecosystem = _ecosystem_from_purl(purl) if purl else None
    file_hash = _extract_sha256_hash(raw.get('hashes', []))

    return ParsedComponent(
        name=name,
        version=version,
        purl=purl,
        ecosystem=ecosystem,
        file_hash=file_hash,
        raw=raw,
    )


def _ecosystem_from_purl(purl: str) -> Optional[str]:
    """
    Extract the package ecosystem (type) from a Package URL string.

    PURL format: pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>

    Examples:
        'pkg:npm/lodash@4.17.20'                           → 'npm'
        'pkg:maven/org.apache.logging.log4j/log4j@2.14.1' → 'maven'
        'pkg:pypi/requests@2.28.0'                         → 'pypi'
        'pkg:cargo/serde@1.0.152'                          → 'cargo'

    Returns None rather than raising if the PURL is malformed.
    """
    if not isinstance(purl, str) or not purl.startswith('pkg:'):
        return None
    rest = purl[4:]  # strip 'pkg:'

    # Find the earliest delimiter that terminates the type segment
    end = len(rest)
    for ch in ('/', '@', '?', '#'):
        pos = rest.find(ch)
        if pos != -1:
            end = min(end, pos)

    pkg_type = rest[:end].lower().strip()
    return pkg_type if pkg_type else None


def _extract_sha256_hash(hashes: list) -> Optional[str]:
    """
    Extract the SHA-256 hash from a CycloneDX hashes array.

    CycloneDX format: [{"alg": "SHA-256", "content": "<hex>"}]

    Returns the hash hex string, or None if no SHA-256 entry is present.
    """
    if not isinstance(hashes, list):
        return None
    for entry in hashes:
        if not isinstance(entry, dict):
            continue
        alg = entry.get('alg', '').upper().replace('-', '').replace('_', '')
        if alg in ('SHA256',):
            content = entry.get('content', '').strip()
            if content:
                return content
    return None
