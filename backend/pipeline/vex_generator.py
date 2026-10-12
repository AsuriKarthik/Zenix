"""
CycloneDX VEX Generator — Pure-Python Asymmetric RSA (2048-bit) Signing (Requirement 3).

Generates evidence-backed CycloneDX VEX documents from real RiskScore + ReachabilityVerdict
+ Vulnerability database records.

Asymmetric Cryptography Architecture (Pure Python Standard Library):
  - Private Key (n, d, e): Kept server-side secret, used exclusively by Zenix backend to sign generated VEX reports.
  - Public Key (n, e): Exposed publicly via /api/vex/public-key for external auditors & clients to verify signature authenticity.
  - Verification: pow(signature_int, e, n) recovers PKCS#1 v1.5 padded SHA-256 digest.
  - Leak Safety: Even if the Public Key or session secrets are exposed, third parties CANNOT forge official Zenix VEX reports.
  - Portability: Pure Python standard library (hashlib, secrets, base64) — zero unapproved C-extension DLLs.

Rules enforced:
  - Evidence-driven status mapping:
      * NOT_REACHABLE (high/medium confidence) -> status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path', evidence_ref attached.
      * REACHABLE -> status: 'affected', matched runtime process evidence attached.
      * UNKNOWN (low confidence / thin evidence) -> status: 'under_investigation'.
        NEVER collapses UNKNOWN into 'not_affected'.
  - Signing: Asymmetric RSA (2048-bit + SHA256 PKCS#1 v1.5).
  - Persisted in VexDocument table, linked to Job and Component.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, List, Tuple

from config import Config
from db import db, Job, Component, Vulnerability, ReachabilityVerdict, RiskScore, VexDocument

log = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# PKCS#1 v1.5 SHA-256 DigestInfo prefix (ASN.1 DER encoding of SHA-256 algorithm identifier)
_SHA256_ASN1_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _is_prime(n: int, k: int = 8) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int = 1024) -> int:
    """Generate a random probable prime of specified bit length."""
    while True:
        p = secrets.randbits(bits)
        p |= (1 << (bits - 1)) | 1  # ensure exact bit length and odd
        if _is_prime(p):
            return p


class RsaKeyPair:
    """
    Pure-Python RSA 2048-bit Key Pair.
    """

    def __init__(self, n: int, e: int, d: Optional[int] = None):
        self.n = n
        self.e = e
        self.d = d

    @classmethod
    def generate(cls, key_size: int = 2048) -> RsaKeyPair:
        e = 65537
        half_bits = key_size // 2
        p = _generate_prime(half_bits)
        q = _generate_prime(half_bits)
        while p == q:
            q = _generate_prime(half_bits)

        n = p * q
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        return cls(n, e, d)

    def public_key_pem(self) -> str:
        """Export RSA Public Key in JSON/PEM string format for verification."""
        pub_dict = {"kty": "RSA", "n": hex(self.n), "e": hex(self.e)}
        return json.dumps(pub_dict, indent=2)

    def sign(self, message_bytes: bytes) -> str:
        """Sign message bytes using RSA Private Key (PKCS#1 v1.5 + SHA-256)."""
        if self.d is None:
            raise ValueError("Private key exponent 'd' is required for signing.")

        digest = hashlib.sha256(message_bytes).digest()
        data_block = _SHA256_ASN1_PREFIX + digest

        key_bytes_len = (self.n.bit_length() + 7) // 8
        ps_len = key_bytes_len - len(data_block) - 3
        if ps_len < 8:
            raise ValueError("RSA key size too small for SHA-256 PKCS#1 v1.5 signing.")

        padded = b"\x00\x01" + (b"\xff" * ps_len) + b"\x00" + data_block
        padded_int = int.from_bytes(padded, byteorder="big")

        sig_int = pow(padded_int, self.d, self.n)
        sig_bytes = sig_int.to_bytes(key_bytes_len, byteorder="big")
        return base64.b64encode(sig_bytes).decode("utf-8")

    def verify(self, message_bytes: bytes, signature_b64: str) -> bool:
        """Verify RSA signature using Public Key (n, e)."""
        try:
            sig_bytes = base64.b64decode(signature_b64.encode("utf-8"))
            sig_int = int.from_bytes(sig_bytes, byteorder="big")

            padded_int = pow(sig_int, self.e, self.n)
            key_bytes_len = (self.n.bit_length() + 7) // 8
            padded = padded_int.to_bytes(key_bytes_len, byteorder="big")

            digest = hashlib.sha256(message_bytes).digest()
            expected_data_block = _SHA256_ASN1_PREFIX + digest

            if not padded.startswith(b"\x00\x01"):
                return False

            if not padded.endswith(expected_data_block):
                return False

            return True
        except Exception:
            return False


# Global cached in-memory RSA key pair
_CACHED_RSA_KEYPAIR: Optional[RsaKeyPair] = None


def get_vex_keypair() -> RsaKeyPair:
    """
    Get or generate server-side RSA 2048-bit keypair for VEX document signing.
    """
    global _CACHED_RSA_KEYPAIR
    if _CACHED_RSA_KEYPAIR is None:
        log.info("Generating server-side pure-Python RSA 2048-bit keypair for VEX signing...")
        _CACHED_RSA_KEYPAIR = RsaKeyPair.generate(2048)
    return _CACHED_RSA_KEYPAIR


def get_vex_public_key_pem() -> str:
    """
    Export server-side RSA Public Key string for public verification.
    """
    keypair = get_vex_keypair()
    return keypair.public_key_pem()


def sign_vex_document(document_json: str, keypair: Optional[RsaKeyPair] = None) -> str:
    """
    Sign a VEX JSON document using server-side RSA Private Key.

    Returns Base64-encoded signature string.
    """
    if keypair is None:
        keypair = get_vex_keypair()

    return keypair.sign(document_json.encode("utf-8"))


def verify_vex_signature(
    document_json: str,
    signature_b64: str,
    keypair: Optional[RsaKeyPair] = None
) -> bool:
    """
    Verify asymmetric RSA signature of a VEX JSON document using Public Key.
    """
    if keypair is None:
        keypair = get_vex_keypair()

    return keypair.verify(document_json.encode("utf-8"), signature_b64)


def map_reachability_to_vex_status(reachability_status: str, confidence: str) -> tuple[str, str]:
    """
    Determine VEX status and justification from reachability status and confidence level.

    Returns:
        (vex_status, justification)
    """
    if reachability_status == 'NOT_REACHABLE' and confidence in ('high', 'medium'):
        return ('not_affected', 'vulnerable_code_not_in_execute_path')

    if reachability_status == 'REACHABLE':
        return ('affected', 'code_in_executable_path')

    # UNKNOWN or low-confidence NOT_REACHABLE -> under_investigation
    return ('under_investigation', 'under_investigation')


def generate_vex_documents_for_job(job_id: str) -> List[VexDocument]:
    """
    Generate and persist signed CycloneDX VEX documents for all vulnerabilities in a job.

    Returns:
        List of created VexDocument DB model instances.
    """
    job: Optional[Job] = db.session.get(Job, job_id)
    if not job:
        log.error("Cannot generate VEX documents: Job '%s' not found.", job_id)
        return []

    components = Component.query.filter_by(job_id=job.id).all()
    created_docs: List[VexDocument] = []
    keypair = get_vex_keypair()
    pub_pem = get_vex_public_key_pem()

    for comp in components:
        verdict: Optional[ReachabilityVerdict] = comp.reachability_verdict
        reach_status = verdict.status if verdict else 'UNKNOWN'
        confidence = verdict.confidence if verdict else 'low'
        evidence_source = verdict.evidence_source if verdict else 'none'

        raw_evidence = json.loads(verdict.raw_evidence_json) if (verdict and verdict.raw_evidence_json) else {}

        for vuln in comp.vulnerabilities:
            score: Optional[RiskScore] = vuln.risk_score
            vex_status, justification = map_reachability_to_vex_status(reach_status, confidence)

            vex_uuid = f"VEX-{datetime.now().strftime('%Y')}-{str(uuid.uuid4())[:8].upper()}"

            evidence_summary = (
                f"Component: {comp.name}@{comp.version} | CVE: {vuln.cve_id} | "
                f"Reachability: {reach_status} via {evidence_source} (confidence: {confidence}) | "
                f"Risk Score: {score.final_score if score else 'N/A'}"
            )

            # Build standard CycloneDX 1.4/1.5 VEX JSON structure
            cyclonedx_doc = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "version": 1,
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "metadata": {
                    "timestamp": _utcnow().isoformat() + "Z",
                    "tools": [{
                        "vendor": "Zenix AppSec",
                        "name": "Zenix VEX Engine",
                        "version": "1.0.0",
                        "public_key": pub_pem,
                    }],
                    "component": {
                        "name": comp.name,
                        "version": comp.version or "0.0.0",
                        "purl": comp.purl or f"pkg:generic/{comp.name}@{comp.version}",
                    }
                },
                "vulnerabilities": [{
                    "id": vuln.cve_id,
                    "source": {"name": vuln.source.upper() if vuln.source else "NVD"},
                    "description": vuln.description or "N/A",
                    "analysis": {
                        "state": vex_status,
                        "justification": justification,
                        "detail": evidence_summary,
                        "responses": ["will_not_fix" if vex_status == "not_affected" else "update"]
                    },
                    "affects": [{
                        "ref": comp.purl or f"pkg:generic/{comp.name}@{comp.version}"
                    }],
                    "evidence": {
                        "source": evidence_source,
                        "confidence": confidence,
                        "reachability_verdict_id": verdict.id if verdict else None,
                        "raw": raw_evidence,
                    }
                }]
            }

            doc_json = json.dumps(cyclonedx_doc, indent=2)
            signature_b64 = sign_vex_document(doc_json, keypair=keypair)

            vex_model = VexDocument(
                job_id=job.id,
                vex_id=vex_uuid,
                cve_id=vuln.cve_id,
                justification=justification,
                status=vex_status,
                evidence_summary=evidence_summary,
                cyclonedx_vex_json=doc_json,
                signature=signature_b64,
                component_id=comp.id,
                generated_at=_utcnow(),
            )
            db.session.add(vex_model)
            created_docs.append(vex_model)

    if created_docs:
        db.session.commit()
        log.info("Generated and signed %d VEX document(s) with RSA for job %s", len(created_docs), job.id)

    return created_docs
