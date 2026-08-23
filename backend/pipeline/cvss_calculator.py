"""
CVSS v3.0 / v3.1 Vector Calculator

Calculates standard CVSS base scores directly from vector strings when NVD score is absent
(e.g., when NVD is unreachable but OSV or SBOM provides a CVSS vector).
"""

import math
from typing import Optional, Tuple


def calculate_cvss_base_score(vector_str: str) -> Tuple[Optional[float], Optional[str]]:
    """
    Parse a CVSS v3.0 or v3.1 vector string and return (base_score, error_message).

    Example vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    Returns (10.0, None) or (None, "Reason...") if invalid.
    """
    if not vector_str or not isinstance(vector_str, str):
        return None, "Vector string is empty or invalid"

    v_str = vector_str.strip()
    if "CVSS:" in v_str:
        # Extract starting from CVSS: if prefix exists
        v_str = v_str[v_str.index("CVSS:"):]

    parts = v_str.split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        return None, f"Unsupported or invalid CVSS version in vector: {vector_str}"

    metrics = {}
    for part in parts[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()

    req_metrics = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [m for m in req_metrics if m not in metrics]
    if missing:
        return None, f"Missing required CVSS v3 metrics: {', '.join(missing)}"

    scope = metrics["S"]
    if scope not in ("U", "C"):
        return None, f"Invalid Scope metric: {scope}"

    # Metric weight tables
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    try:
        av = av_weights[metrics["AV"]]
        ac = ac_weights[metrics["AC"]]
        pr = pr_weights[scope][metrics["PR"]]
        ui = ui_weights[metrics["UI"]]
        c = cia_weights[metrics["C"]]
        i = cia_weights[metrics["I"]]
        a = cia_weights[metrics["A"]]
    except KeyError as exc:
        return None, f"Invalid CVSS metric value: {exc}"

    # ISS (Impact Sub-Score)
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # Impact
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        raw = min(impact + exploitability, 10.0)
        base_score = _cvss_roundup(raw)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)
        base_score = _cvss_roundup(raw)

    return base_score, None


def _cvss_roundup(val: float) -> float:
    """
    Standard CVSS v3.1 roundup function: ceil to 1 decimal place.
    """
    int_val = round(val * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000.0
    return math.ceil(round(val, 9) * 10.0) / 10.0
