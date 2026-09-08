"""
Multi-Format Universal SBOM Parser.

Supports:
  - CycloneDX JSON (.json, .cdx.json) - All versions (1.0 through 1.7+)
  - CycloneDX XML (.xml, .cdx.xml)
  - SPDX JSON (.json, .spdx.json)
  - SPDX Tag/Value / Text (.spdx, .txt)
  - SPDX XML (.xml, .spdx.xml)
  - Generic SBOM JSON / XML / Text
  - Package lockfiles / tool scan outputs (Trivy, Syft, Grype, NPM, PyPI)
"""

from __future__ import annotations

import hashlib
import json
import re
try:
    import defusedxml.ElementTree as defused_ET
    HAS_DEFUSEDXML = True
except ImportError:
    HAS_DEFUSEDXML = False
    import xml.etree.ElementTree as ET  # nosec B314
from dataclasses import dataclass, field
from typing import Optional, Any


class SBOMParseError(ValueError):
    """Raised when an SBOM cannot be parsed."""


@dataclass
class ParsedComponent:
    name: str
    version: Optional[str]
    purl: Optional[str]
    ecosystem: Optional[str]
    file_hash: Optional[str]
    raw: dict = field(default_factory=dict, repr=False)


_SUPPORTED_SPEC_VERSIONS = {'1.2', '1.3', '1.4', '1.5', '1.6', '1.7'}


def _normalize_json_sbom(data: Any) -> Any:
    """
    Normalization layer: automatically unwraps outer wrapper objects 
    (e.g., {"sbom": {...}}, {"document": {...}}, {"data": {...}}) or single-element 
    lists containing an SBOM to expose the root SBOM or package manifest document.
    """
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
        first = data[0]
        indicators = (
            'bomFormat', 'bom_format', 'BOMFormat', 'spdxVersion', 'spdx_version', 
            'SPDXVersion', 'spdxDocId', 'SPDXID', 'components', 'Components', 
            'packages', 'Packages', 'dependencies', 'devDependencies'
        )
        if any(k in first for k in indicators) or 'sbom' in first or 'document' in first:
            data = first

    if not isinstance(data, dict):
        return data

    curr = data
    for _ in range(5):  # Max 5 levels of unwrapping
        if not isinstance(curr, dict):
            break

        # Check if direct SBOM/package indicators are at the current level
        indicators = (
            'bomFormat', 'bom_format', 'BOMFormat', 'spdxVersion', 'spdx_version', 
            'SPDXVersion', 'spdxDocId', 'SPDXID', 'components', 'Components', 
            'packages', 'Packages', 'dependencies', 'devDependencies', 'node_modules', 
            'lockfileVersion', 'results', 'Results'
        )
        if any(key in curr for key in indicators):
            break

        # Look for wrapper keys
        wrapper_keys = ('sbom', 'document', 'sbom_data', 'data', 'payload', 'content', 'report', 'scan', 'target', 'output')
        unwrapped = None
        for wk in wrapper_keys:
            if wk in curr and isinstance(curr[wk], dict):
                unwrapped = curr[wk]
                break

        if unwrapped is not None:
            curr = unwrapped
        else:
            if len(curr) == 1:
                sole_val = list(curr.values())[0]
                if isinstance(sole_val, dict):
                    curr = sole_val
                    continue
            break

    return curr


def parse_sbom(raw_bytes: bytes, filename: str = "") -> list[ParsedComponent]:
    """
    Universal SBOM parser supporting CycloneDX JSON/XML, SPDX JSON/XML/Tag-Value, and generic formats.
    """
    if not raw_bytes or not raw_bytes.strip():
        raise SBOMParseError("Uploaded SBOM file is empty.")

    is_json = False
    json_data = None
    json_err = None

    try:
        json_data = json.loads(raw_bytes)
        is_json = True
    except Exception as exc:
        json_err = exc

    if is_json:
        # Apply Normalization Layer to unwrap outer wrappers like {"sbom": {...}}
        json_data = _normalize_json_sbom(json_data)

        if isinstance(json_data, list):
            parsed_list = _parse_generic_json_list(json_data)
            if parsed_list:
                return parsed_list
            raise SBOMParseError("SBOM root must be a JSON object, not an array or scalar.")

        if not isinstance(json_data, dict):
            raise SBOMParseError("SBOM root must be a JSON object.")

        bom_format = json_data.get('bomFormat') or json_data.get('bom_format') or json_data.get('BOMFormat')
        bom_format_str = str(bom_format).strip() if bom_format else ""

        # CycloneDX JSON
        if bom_format_str.lower() == 'cyclonedx':
            spec_version = str(json_data.get('specVersion', json_data.get('spec_version', '1.4'))).strip()
            if spec_version and spec_version not in _SUPPORTED_SPEC_VERSIONS:
                raise SBOMParseError(
                    f"Unsupported CycloneDX specVersion '{spec_version}'. "
                    f"Supported versions: {', '.join(sorted(_SUPPORTED_SPEC_VERSIONS))}."
                )

            raw_components = json_data.get('components') or json_data.get('Components') or []
            if not isinstance(raw_components, list):
                raise SBOMParseError("The 'components' field must be a JSON array.")

            metadata = json_data.get('metadata') or json_data.get('Metadata') or {}
            if isinstance(metadata, dict):
                meta_comp = metadata.get('component') or metadata.get('Component') or {}
                if isinstance(meta_comp, dict):
                    nested = meta_comp.get('components') or meta_comp.get('Components') or []
                    if isinstance(nested, list) and nested:
                        raw_components = list(raw_components) + nested

            parsed: list[ParsedComponent] = []
            for idx, raw in enumerate(raw_components):
                if not isinstance(raw, dict):
                    raise SBOMParseError(f"Component at index {idx} is not a JSON object.")
                comp = _parse_single_cyclonedx_component(raw)
                if comp:
                    parsed.append(comp)

            return parsed

        # SPDX JSON
        if bom_format_str.upper() == 'SPDX' or 'spdxVersion' in json_data or 'spdx_version' in json_data or 'SPDXVersion' in json_data or 'packages' in json_data or 'Packages' in json_data or 'hasFiles' in json_data:
            spdx_parsed = _parse_spdx_json_dict(json_data)
            if spdx_parsed:
                return spdx_parsed
            if bom_format_str.upper() == 'SPDX':
                raise SBOMParseError(
                    "SPDX format is not supported in CycloneDX mode — no SPDX packages found. "
                    "Please convert to CycloneDX JSON using cdxgen or syft."
                )

        # Try generic JSON parsing for any JSON document
        generic_parsed = _parse_generic_json(json_data)
        if generic_parsed:
            return generic_parsed

        if bom_format_str and bom_format_str.lower() not in ('cyclonedx', 'spdx'):
            raise SBOMParseError(f"Unrecognised SBOM format '{bom_format}'.")

        # Valid JSON syntax, but no components/dependencies were found
        raise SBOMParseError(
            "Could not extract any valid software components or dependencies from this JSON file. "
            "Please ensure the file is a valid CycloneDX, SPDX, lockfile, or package manifest JSON document."
        )

    text_content = ""
    try:
        text_content = raw_bytes.decode('utf-8', errors='ignore')
    except Exception:
        pass

    # Try XML parsing (CycloneDX XML, SPDX XML, Maven pom.xml)
    if text_content and text_content.strip().startswith('<'):
        try:
            if HAS_DEFUSEDXML:
                root = defused_ET.fromstring(text_content)
            else:
                root = ET.fromstring(text_content)  # nosec B314
            components = _parse_xml_sbom(root)
            if components:
                return components
        except Exception:
            pass

    # Try SPDX Tag/Value text parsing
    if text_content and ('SPDXVersion' in text_content or 'PackageName' in text_content or 'FileName' in text_content or 'Package:' in text_content):
        try:
            spdx_components = _parse_spdx_tag_value(text_content)
            if spdx_components:
                return spdx_components
        except Exception:
            pass

    # Try requirements.txt parsing
    if filename.lower().endswith(('requirements.txt', '.txt')) or ('==' in text_content or '>=' in text_content or '~=' in text_content):
        req_components = _parse_requirements_txt(text_content)
        if req_components:
            return req_components

    # Try go.mod parsing
    if filename.lower().endswith('go.mod') or ('module ' in text_content and 'require (' in text_content):
        go_components = _parse_go_mod(text_content)
        if go_components:
            return go_components

    if json_err is not None and text_content and not text_content.strip().startswith('<') and not ('PackageName' in text_content):
        raise SBOMParseError(f"File is not valid JSON: {json_err}")

    raise SBOMParseError(
        "Could not parse SBOM file format. Please ensure the file is a valid "
        "CycloneDX (JSON/XML), SPDX (JSON/XML/Tag-Value), or standard SBOM document."
    )



def parse_cyclonedx_json(raw_bytes: bytes) -> list[ParsedComponent]:
    """Backwards compatibility alias for CycloneDX / universal parsing."""
    return parse_sbom(raw_bytes)


def _parse_spdx_json_dict(data: dict) -> list[ParsedComponent]:
    packages = data.get('packages', [])
    if not isinstance(packages, list):
        return []

    parsed: list[ParsedComponent] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        name = pkg.get('name', '').strip()
        if not name:
            continue
        version = pkg.get('versionInfo') or pkg.get('version') or None
        if version:
            version = str(version).strip()

        purl = None
        for ref in pkg.get('externalRefs', []):
            if isinstance(ref, dict) and ref.get('referenceType') in ('purl', 'pkg:'):
                purl = ref.get('referenceLocator')
                break

        file_hash = None
        for chk in pkg.get('checksums', []):
            if isinstance(chk, dict) and str(chk.get('algorithm', '')).upper() in ('SHA256', 'SHA-256'):
                file_hash = chk.get('checksumValue')
                break

        ecosystem = _ecosystem_from_purl(purl) if purl else None
        parsed.append(ParsedComponent(
            name=name,
            version=version,
            purl=purl,
            ecosystem=ecosystem,
            file_hash=file_hash,
            raw=pkg,
        ))

    return parsed


def _parse_generic_json(json_data: Any) -> list[ParsedComponent]:
    if isinstance(json_data, list):
        return _parse_generic_json_list(json_data)

    if not isinstance(json_data, dict):
        return []

    # 1. Direct array or dict keys (case-insensitive check)
    norm_map = {str(k).lower(): (k, v) for k, v in json_data.items()}
    target_keys = (
        'components', 'packages', 'dependencies', 'items', 'artifacts', 
        'files', 'modules', 'libraries', 'software', 'targets', 
        'node_modules', 'graph', 'results', 'devdependencies', 'requires',
        'vulnerabilities', 'records', 'nodes'
    )

    for target in target_keys:
        if target in norm_map:
            orig_k, val = norm_map[target]
            if isinstance(val, list):
                res = _parse_generic_json_list(val)
                if res:
                    return res
            elif isinstance(val, dict):
                res = _parse_dict_mapping(val)
                if res:
                    return res

    # 2. Deep scan any list or dict in root dict
    for k, v in json_data.items():
        k_lower = str(k).lower()
        if isinstance(v, list) and v:
            res = _parse_generic_json_list(v)
            if res:
                return res
        elif isinstance(v, dict) and v and k_lower in ('dependencies', 'devdependencies', 'requires', 'packages', 'components'):
            res = _parse_dict_mapping(v)
            if res:
                return res

    # 3. If root dict itself is a component (has 'name')
    name = (
        json_data.get('name') or json_data.get('packageName') or json_data.get('PackageName') or
        json_data.get('Name') or json_data.get('title') or json_data.get('Title')
    )
    if name and isinstance(name, str):
        return _parse_generic_json_list([json_data])

    return []


def _parse_dict_mapping(mapping: dict) -> list[ParsedComponent]:
    parsed: list[ParsedComponent] = []
    for key, val in mapping.items():
        if not key or not isinstance(key, str):
            continue

        clean_key = key.strip()
        if 'node_modules/' in clean_key:
            clean_key = clean_key.rsplit('node_modules/', 1)[-1]
        elif 'node_modules\\' in clean_key:
            clean_key = clean_key.rsplit('node_modules\\', 1)[-1]

        if clean_key.startswith('@'):
            name = clean_key
        else:
            name = clean_key.split('/')[-1].split('\\')[-1].strip()

        if not name:
            continue

        version = None
        purl = None
        file_hash = None

        if isinstance(val, str):
            version = val.lstrip('^~>=<').strip()
        elif isinstance(val, dict):
            version = str(val.get('version') or val.get('versionInfo') or val.get('Version') or '').lstrip('^~>=<').strip() or None
            purl = val.get('purl') or val.get('Purl') or val.get('PURL')
            file_hash = _extract_sha256_hash(val.get('hashes') or val.get('checksums') or []) if ('hashes' in val or 'checksums' in val) else None

        parsed.append(ParsedComponent(
            name=name,
            version=version,
            purl=purl,
            ecosystem=_ecosystem_from_purl(purl) if purl else None,
            file_hash=file_hash,
            raw={'name': name, 'version': version},
        ))
    return parsed


def _parse_generic_json_list(items: list) -> list[ParsedComponent]:
    parsed: list[ParsedComponent] = []
    for item in items:
        if isinstance(item, str):
            parts = item.split('@')
            name = parts[0].strip()
            version = parts[1].strip() if len(parts) > 1 else None
            if name:
                parsed.append(ParsedComponent(name=name, version=version, purl=None, ecosystem=None, file_hash=None, raw={'name': name}))
            continue

        if not isinstance(item, dict):
            continue

        # Check if item is a target object containing a list of sub-components (e.g. Trivy scan target)
        found_sub = False
        for sub_key in ('packages', 'Packages', 'components', 'Components', 'dependencies', 'Dependencies', 'items', 'Items', 'artifacts', 'Artifacts'):
            if sub_key in item and isinstance(item[sub_key], list):
                sub_res = _parse_generic_json_list(item[sub_key])
                if sub_res:
                    parsed.extend(sub_res)
                    found_sub = True
        if found_sub:
            continue

        target = (
            item.get('artifact') or item.get('component') or item.get('package') or
            item.get('Artifact') or item.get('Component') or item.get('Package') or item
        )
        if not isinstance(target, dict):
            target = item

        name = (
            target.get('name') or target.get('packageName') or target.get('PackageName') or
            target.get('Name') or target.get('title') or target.get('Title') or target.get('id') or
            target.get('ID') or target.get('pkgName') or target.get('package') or ''
        )
        purl = target.get('purl') or target.get('Purl') or target.get('PURL') or None
        if isinstance(purl, str):
            purl = purl.strip() or None

        if not name and purl:
            match = re.search(r'pkg:[^/]+/(?:([^/@]+)/)?([^/@]+)', purl)
            if match:
                ns, p_name = match.groups()
                name = f"{ns}/{p_name}" if ns else p_name

        name = str(name).strip()
        if not name:
            continue

        version = (
            target.get('version') or target.get('versionInfo') or target.get('Version') or
            target.get('pkgVersion') or target.get('PkgVersion') or target.get('revision') or None
        )
        if version is not None:
            version = str(version).strip()

        file_hash = None
        if 'hashes' in target:
            file_hash = _extract_sha256_hash(target.get('hashes', []))
        elif 'checksums' in target:
            file_hash = _extract_sha256_hash(target.get('checksums', []))

        ecosystem = _ecosystem_from_purl(purl) if purl else None
        parsed.append(ParsedComponent(
            name=name,
            version=version,
            purl=purl,
            ecosystem=ecosystem,
            file_hash=file_hash,
            raw=target,
        ))
    return parsed


def _parse_requirements_txt(text: str) -> list[ParsedComponent]:
    parsed: list[ParsedComponent] = []
    lines = text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        parts = re.split(r'==|>=|<=|~=|!=|>|<|@', line, maxsplit=1)
        name = parts[0].strip()
        if not name or ' ' in name:
            continue
        version = parts[1].strip() if len(parts) > 1 else None
        if version:
            version = version.split(';')[0].split('#')[0].strip()
        purl = f"pkg:pypi/{name}@{version}" if version else f"pkg:pypi/{name}"
        parsed.append(ParsedComponent(
            name=name,
            version=version,
            purl=purl,
            ecosystem="pypi",
            file_hash=None,
            raw={'name': name, 'version': version},
        ))
    return parsed


def _parse_go_mod(text: str) -> list[ParsedComponent]:
    parsed: list[ParsedComponent] = []
    lines = text.splitlines()
    in_require = False
    for line in lines:
        line = line.strip()
        if line.startswith('require ('):
            in_require = True
            continue
        if in_require and line == ')':
            in_require = False
            continue

        if in_require or line.startswith('require '):
            clean = line.replace('require ', '').strip()
            parts = clean.split()
            if len(parts) >= 2:
                mod_path = parts[0].strip()
                version = parts[1].strip().lstrip('v')
                name = mod_path.split('/')[-1]
                purl = f"pkg:golang/{mod_path}@{version}"
                parsed.append(ParsedComponent(
                    name=name,
                    version=version,
                    purl=purl,
                    ecosystem="golang",
                    file_hash=None,
                    raw={'name': name, 'version': version, 'mod_path': mod_path},
                ))
    return parsed


def _parse_xml_sbom(root: ET.Element) -> list[ParsedComponent]:
    parsed: list[ParsedComponent] = []

    for elem in root.iter():
        tag = elem.tag.split('}')[-1].lower()
        if tag in ('component', 'package', 'dependency', 'item', 'artifact'):
            name = ''
            version = None
            purl = None
            file_hash = None

            for child in elem:
                ctag = child.tag.split('}')[-1].lower()
                if ctag in ('name', 'packagename', 'title', 'id'):
                    name = (child.text or '').strip()
                elif ctag in ('version', 'versioninfo', 'packageversion', 'pkgversion'):
                    version = (child.text or '').strip()
                elif ctag == 'purl':
                    purl = (child.text or '').strip()
                elif ctag in ('hash', 'checksum'):
                    val = (child.text or '').strip()
                    if len(val) == 64:
                        file_hash = val

            if name:
                ecosystem = _ecosystem_from_purl(purl) if purl else None
                parsed.append(ParsedComponent(
                    name=name,
                    version=version,
                    purl=purl,
                    ecosystem=ecosystem,
                    file_hash=file_hash,
                    raw={'name': name, 'version': version},
                ))

    return parsed


def _parse_spdx_tag_value(text: str) -> list[ParsedComponent]:
    parsed: list[ParsedComponent] = []
    lines = text.splitlines()

    curr_name = None
    curr_version = None
    curr_purl = None
    curr_hash = None

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        if ':' in line:
            tag, val = line.split(':', 1)
            tag = tag.strip()
            val = val.strip()

            if tag in ('PackageName', 'FileName', 'Package', 'Name'):
                if curr_name:
                    parsed.append(ParsedComponent(
                        name=curr_name,
                        version=curr_version,
                        purl=curr_purl,
                        ecosystem=_ecosystem_from_purl(curr_purl) if curr_purl else None,
                        file_hash=curr_hash,
                        raw={'name': curr_name},
                    ))
                    curr_version = None
                    curr_purl = None
                    curr_hash = None
                curr_name = val
            elif tag in ('PackageVersion', 'FileVersion', 'Version'):
                curr_version = val
            elif tag in ('PackageChecksum', 'Checksum') and 'SHA256' in val.upper():
                parts = val.split()
                if len(parts) >= 2:
                    curr_hash = parts[-1]
            elif tag in ('ExternalRef', 'PURL') and 'purl' in val.lower():
                parts = val.split()
                if len(parts) >= 3:
                    curr_purl = parts[-1]
                else:
                    curr_purl = val

    if curr_name:
        parsed.append(ParsedComponent(
            name=curr_name,
            version=curr_version,
            purl=curr_purl,
            ecosystem=_ecosystem_from_purl(curr_purl) if curr_purl else None,
            file_hash=curr_hash,
            raw={'name': curr_name},
        ))

    return parsed


_MATCHABLE_TYPES = {'library', 'framework', 'application', 'package', None}


def _parse_single_cyclonedx_component(raw: dict) -> Optional[ParsedComponent]:
    name = raw.get('name', '').strip()
    purl = raw.get('purl', '').strip() or None

    if not name and purl:
        match = re.search(r'pkg:[^/]+/(?:([^/@]+)/)?([^/@]+)', purl)
        if match:
            ns, p_name = match.groups()
            name = f"{ns}/{p_name}" if ns else p_name

    if not name:
        return None

    component_type = raw.get('type')
    if component_type not in _MATCHABLE_TYPES:
        return None

    version = raw.get('version', '').strip() or None
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


def compute_sbom_sha256(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def _ecosystem_from_purl(purl: str) -> Optional[str]:
    if not isinstance(purl, str) or not purl.startswith('pkg:'):
        return None
    rest = purl[4:]
    end = len(rest)
    for ch in ('/', '@', '?', '#'):
        pos = rest.find(ch)
        if pos != -1:
            end = min(end, pos)
    pkg_type = rest[:end].lower().strip()
    return pkg_type if pkg_type else None


def _extract_sha256_hash(hashes: list) -> Optional[str]:
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
