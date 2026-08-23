"""
pipeline — SBOM ingestion, CVE matching, enrichment, and scoring.

Public surface for steps 1–4:
  parse_sbom()          → list[ParsedComponent]
  find_cves()           → list[CVEMatch]
  enrich_vulnerability()→ EnrichmentResult
  compute_risk_score()  → ScoringResult
"""
