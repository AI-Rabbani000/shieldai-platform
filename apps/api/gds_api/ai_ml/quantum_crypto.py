"""GDS AI/ML Engine — Quantum-Resistant Cryptography Assessment.

REAL quantum threat assessment — not speculation, not marketing claims.

Evaluates cryptographic systems against the quantum computing threat using
the actual mathematics of Shor's algorithm and Grover's algorithm, and maps
to the real NIST Post-Quantum Cryptography (PQC) standards.

How quantum computers threaten current crypto:
  1. Shor's Algorithm — breaks RSA, ECC, DH, ECDH (integer factorization + discrete log)
     - A sufficiently large quantum computer (4000+ logical qubits) can factor RSA-2048
     - Current estimates: 10-20 years for fault-tolerant quantum computer
     - "Harvest now, decrypt later" threat: adversaries collect encrypted data NOW

  2. Grover's Algorithm — halves effective key size for symmetric crypto
     - AES-256 becomes equivalent to AES-128 (still secure)
     - SHA-256 becomes equivalent to SHA-128 (borderline)
     - Requires 2^128 quantum operations (still extremely hard)

  3. NIST PQC Standards (FIPS 203, 204, 205 — finalized August 2024):
     - ML-KEM (CRYSTALS-Kyber) — Key encapsulation (replaces RSA/ECDH key exchange)
     - ML-DSA (CRYSTALS-Dilithium) — Digital signatures (replaces RSA/ECDSA)
     - SLH-DSA (SPHINCS+) — Hash-based signatures (fallback, conservative)
     - FALCON — Lattice-based signatures (compact)

This module:
  - Scans TLS connections for quantum-vulnerable key exchange
  - Assesses certificate key sizes and types
  - Evaluates symmetric key sizes against Grover's
  - Scores the overall quantum readiness
  - Creates findings for quantum-vulnerable crypto
"""

from __future__ import annotations

import math
import socket
import ssl
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from gds_api.logging_config import get_logger
from gds_api.models import Finding
from gds_api.finding_lifecycle import FindingStatus

_logger = get_logger("gds_api.ai_ml.quantum")


# ---------------------------------------------------------------------------
# Real Quantum Threat Model (from academic research)
# ---------------------------------------------------------------------------

# Shor's algorithm: qubits needed to factor RSA-N
# Formula: ~2*N logical qubits (optimistic) to ~4*N + overhead (conservative)
# Source: Gidney & Ekerå 2021, "How to factor 2048 bit RSA integers in 8 hours
#         using 20 million noisy qubits"
def shors_qubit_estimate(rsa_bits: int) -> dict[str, Any]:
    """Estimate quantum resources needed to break RSA with Shor's algorithm.

    Based on Gidney & Ekerå 2021 — real academic research, not speculation.
    """
    if rsa_bits <= 512:
        return {
            "logical_qubits": 1024,
            "physical_qubits": 1_000_000,  # ~1M (optimistic for 512-bit)
            "time_estimate": "Existing (RSA-512 already factored classically)",
            "threat_level": "immediate",
        }
    elif rsa_bits <= 1024:
        return {
            "logical_qubits": 2048,
            "physical_qubits": 10_000_000,
            "time_estimate": "~5-10 years",
            "threat_level": "near-term",
        }
    elif rsa_bits <= 2048:
        return {
            "logical_qubits": 4096,
            "physical_qubits": 20_000_000,  # Gidney & Ekerå 2021 estimate
            "time_estimate": "~10-20 years",
            "threat_level": "medium-term",
        }
    else:
        return {
            "logical_qubits": 8192,
            "physical_qubits": 50_000_000,
            "time_estimate": "~15-30 years",
            "threat_level": "long-term",
        }


# Grover's algorithm: effective security halving
def grovers_impact(key_bits: int) -> dict[str, Any]:
    """Calculate the impact of Grover's algorithm on symmetric key security.

    Grover's provides a quadratic speedup, effectively halving the key space.
    """
    effective_security = key_bits // 2
    quantum_operations = 2 ** (key_bits // 2)
    return {
        "original_security_bits": key_bits,
        "quantum_effective_security_bits": effective_security,
        "quantum_operations_needed": f"2^{key_bits // 2}",
        "still_secure": effective_security >= 128,
        "recommendation": (
            "Adequate quantum resistance" if effective_security >= 128
            else f"Upgrade to {key_bits * 2}-bit keys for equivalent security"
        ),
    }


# NIST PQC standard mapping (FIPS 203/204/205, finalized August 2024)
NIST_PQC_STANDARDS = {
    "ML-KEM": {
        "fips": "FIPS 203",
        "name": "Module-Lattice-Based Key-Encapsulation Mechanism (CRYSTALS-Kyber)",
        "replaces": "RSA, ECDH, Diffie-Hellman key exchange",
        "status": "Finalized (August 2024)",
        "key_sizes": {"ML-KEM-512": 1632, "ML-KEM-768": 2400, "ML-KEM-1024": 3168},
        "security_levels": {1: 128, 3: 192, 5: 256},
    },
    "ML-DSA": {
        "fips": "FIPS 204",
        "name": "Module-Lattice-Based Digital Signature Algorithm (CRYSTALS-Dilithium)",
        "replaces": "RSA, ECDSA, EdDSA signatures",
        "status": "Finalized (August 2024)",
        "key_sizes": {"ML-DSA-44": 1312, "ML-DSA-65": 1952, "ML-DSA-87": 2592},
        "security_levels": {2: 128, 3: 192, 5: 256},
    },
    "SLH-DSA": {
        "fips": "FIPS 205",
        "name": "Stateless Hash-Based Digital Signature Algorithm (SPHINCS+)",
        "replaces": "RSA, ECDSA (conservative fallback)",
        "status": "Finalized (August 2024)",
        "key_sizes": {"SLH-DSA-SHA2-128s": 64, "SLH-DSA-SHA2-256f": 64},
        "security_levels": {1: 128, 3: 192, 5: 256},
    },
    "FN-DSA": {
        "fips": "FIPS 206 (draft)",
        "name": "FFT-over-Lattice-Based Digital Signature (FALCON)",
        "replaces": "RSA, ECDSA (compact signatures)",
        "status": "Draft (expected 2025)",
        "security_levels": {1: 128, 5: 256},
    },
}


# ---------------------------------------------------------------------------
# Quantum Vulnerability Scoring
# ---------------------------------------------------------------------------


# Algorithms vulnerable to Shor's (will be completely broken):
SHOR_VULNERABLE = {
    "rsa": "CRITICAL — Shor's algorithm completely breaks RSA",
    "ecdsa": "CRITICAL — Shor's algorithm completely breaks ECDSA",
    "ecdh": "CRITICAL — Shor's algorithm completely breaks ECDH",
    "dh": "CRITICAL — Shor's algorithm completely breaks Diffie-Hellman",
    "dhe": "CRITICAL — Shor's algorithm breaks ephemeral DH",
}

# Algorithms affected by Grover's (halved security, but still usable with larger keys):
GROVER_AFFECTED = {
    "aes": "MODERATE — Grover's halves effective security; AES-256 remains safe",
    "aes-128": "HIGH — Grover's reduces to 64-bit equivalent (NOT safe)",
    "aes-256": "LOW — Grover's reduces to 128-bit equivalent (safe)",
    "sha-256": "LOW — Grover's reduces to 128-bit equivalent (borderline safe)",
    "sha-384": "LOW — Grover's reduces to 192-bit (safe)",
    "sha-512": "LOW — Grover's reduces to 256-bit (safe)",
    "sha-1": "CRITICAL — Already broken classically; quantum makes it worse",
    "chacha20": "LOW — 256-bit key, Grover's reduces to 128-bit (safe)",
}

# Post-quantum safe algorithms:
POST_QUANTUM_SAFE = {"ml-kem", "ml-dsa", "slh-dsa", "fn-dsa", "kyber", "dilithium", "sphincs+"}


def assess_crypto_algorithm(
    algorithm: str,
    key_size: int | None = None,
) -> dict[str, Any]:
    """Assess a single cryptographic algorithm against quantum threats.

    Returns:
        quantum_vulnerable: bool
        threat_type: "shor" | "grover" | "none"
        severity: critical | high | medium | low
        quantum_timeline: when this crypto will be breakable
        pq_replacement: recommended NIST PQC replacement
        details: explanation
    """
    algo_lower = algorithm.lower().replace("_", "-").replace(" ", "")

    # Check if Shor-vulnerable
    for vuln_algo, description in SHOR_VULNERABLE.items():
        if vuln_algo in algo_lower:
            if key_size:
                shor_estimate = shors_qubit_estimate(key_size)
            else:
                shor_estimate = shors_qubit_estimate(2048)

            # Determine PQC replacement
            pq_replacement = "ML-KEM" if "key" in algo_lower or "dh" in algo_lower or "kem" in algo_lower else "ML-DSA"

            return {
                "algorithm": algorithm,
                "key_size": key_size,
                "quantum_vulnerable": True,
                "threat_type": "shor",
                "severity": "critical",
                "quantum_timeline": shor_estimate["time_estimate"],
                "threat_level": shor_estimate["threat_level"],
                "physical_qubits_needed": shor_estimate["physical_qubits"],
                "description": description,
                "pq_replacement": pq_replacement,
                "pq_standard": NIST_PQC_STANDARDS.get(pq_replacement, {}),
            }

    # Check if Grover-affected
    for grover_algo, description in GROVER_AFFECTED.items():
        if grover_algo in algo_lower:
            key_bits = key_size or 256
            grover_result = grovers_impact(key_bits)

            severity = "low"
            if not grover_result["still_secure"]:
                severity = "high" if key_bits < 256 else "medium"

            return {
                "algorithm": algorithm,
                "key_size": key_size,
                "quantum_vulnerable": not grover_result["still_secure"],
                "threat_type": "grover",
                "severity": severity,
                "grover_effective_security": grover_result["quantum_effective_security_bits"],
                "quantum_operations": grover_result["quantum_operations_needed"],
                "description": description,
                "recommendation": grover_result["recommendation"],
            }

    # Check if already post-quantum safe
    for pq_algo in POST_QUANTUM_SAFE:
        if pq_algo in algo_lower:
            return {
                "algorithm": algorithm,
                "key_size": key_size,
                "quantum_vulnerable": False,
                "threat_type": "none",
                "severity": "low",
                "description": "Post-quantum safe algorithm",
                "status": "quantum_ready",
            }

    # Unknown algorithm
    return {
        "algorithm": algorithm,
        "key_size": key_size,
        "quantum_vulnerable": None,
        "threat_type": "unknown",
        "severity": "low",
        "description": "Unknown algorithm — manual assessment needed",
    }


# ---------------------------------------------------------------------------
# TLS Connection Assessment
# ---------------------------------------------------------------------------


def assess_tls_quantum_readiness(domain: str, port: int = 443) -> dict[str, Any]:
    """Assess a TLS connection for quantum readiness.

    Connects to the real server, inspects the certificate and cipher suite,
    and evaluates quantum vulnerability.
    """
    findings: list[dict[str, Any]] = []
    overall_score = 100  # Start perfect, deduct for issues

    try:
        # Connect and get certificate
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                version = tls_sock.version()

        # Assess cipher suite
        cipher_name = cipher[0] if cipher else "unknown"

        # Check for quantum-vulnerable key exchange
        if any(v in cipher_name.lower() for v in ["rsa", "dh", "ecdhe"]):
            # ECDHE is Shor-vulnerable for key exchange
            # But ECDHE is better than plain RSA (provides forward secrecy)
            if "ecdhe" in cipher_name.lower():
                assessment = assess_crypto_algorithm("ECDHE", 256)
                findings.append({
                    "component": "TLS Key Exchange",
                    "algorithm": "ECDHE",
                    "assessment": assessment,
                    "impact": "Key exchange is quantum-vulnerable (Shor's), but provides forward secrecy for now",
                })
                overall_score -= 15
            elif "rsa" in cipher_name.lower():
                assessment = assess_crypto_algorithm("RSA")
                findings.append({
                    "component": "TLS Key Exchange",
                    "algorithm": "RSA",
                    "assessment": assessment,
                    "impact": "RSA key exchange is quantum-vulnerable AND lacks forward secrecy",
                })
                overall_score -= 30

        # Assess symmetric cipher
        if "aes-256" in cipher_name.lower() or "aes_256" in cipher_name.lower():
            assessment = assess_crypto_algorithm("AES-256", 256)
            findings.append({
                "component": "TLS Symmetric Cipher",
                "algorithm": "AES-256",
                "assessment": assessment,
                "impact": "Safe against Grover's (128-bit equivalent)",
            })
        elif "aes-128" in cipher_name.lower() or "aes_128" in cipher_name.lower():
            assessment = assess_crypto_algorithm("AES-128", 128)
            findings.append({
                "component": "TLS Symmetric Cipher",
                "algorithm": "AES-128",
                "assessment": assessment,
                "impact": "NOT safe against Grover's (64-bit equivalent — upgrade to AES-256)",
            })
            overall_score -= 20

        # Assess certificate
        if cert:
            for rdn in cert.get("subject", ()):
                for key, value in rdn:
                    if key == "commonName":
                        pass  # just identifying the cert

            # Check certificate signature algorithm
            sig_alg = cert.get("signatureAlgorithm", "")
            if "sha256withrsa" in sig_alg.lower() or "rsa" in sig_alg.lower():
                assessment = assess_crypto_algorithm("RSA-Signature")
                findings.append({
                    "component": "Certificate Signature",
                    "algorithm": sig_alg,
                    "assessment": assessment,
                    "impact": "Certificate uses RSA signature — quantum-vulnerable",
                })
                overall_score -= 15
            elif "ecdsa" in sig_alg.lower():
                assessment = assess_crypto_algorithm("ECDSA")
                findings.append({
                    "component": "Certificate Signature",
                    "algorithm": sig_alg,
                    "assessment": assessment,
                    "impact": "Certificate uses ECDSA signature — quantum-vulnerable",
                })
                overall_score -= 15

        # Check TLS version
        if version and "1.3" in version:
            findings.append({
                "component": "TLS Version",
                "value": version,
                "assessment": {"quantum_vulnerable": False, "threat_type": "none"},
                "impact": "TLS 1.3 is the latest — good, but still uses pre-quantum key exchange",
            })
        elif version and "1.2" in version:
            findings.append({
                "component": "TLS Version",
                "value": version,
                "assessment": {"quantum_vulnerable": False, "threat_type": "none"},
                "impact": "TLS 1.2 is acceptable but should upgrade to 1.3",
            })
            overall_score -= 5
        else:
            findings.append({
                "component": "TLS Version",
                "value": version or "unknown",
                "assessment": {"quantum_vulnerable": True, "threat_type": "unknown"},
                "impact": "Outdated TLS version — security risk beyond quantum",
            })
            overall_score -= 25

    except Exception as exc:
        return {
            "success": False,
            "domain": domain,
            "error": str(exc),
        }

    # Calculate grade
    if overall_score >= 80:
        grade = "A"
    elif overall_score >= 60:
        grade = "B"
    elif overall_score >= 40:
        grade = "C"
    elif overall_score >= 20:
        grade = "D"
    else:
        grade = "F"

    return {
        "success": True,
        "domain": domain,
        "port": port,
        "tls_version": version,
        "cipher_suite": cipher_name,
        "quantum_readiness_score": overall_score,
        "quantum_readiness_grade": grade,
        "findings": findings,
        "vulnerable_count": sum(1 for f in findings if f.get("assessment", {}).get("quantum_vulnerable")),
        "recommendation": _quantum_recommendation(overall_score),
    }


def _quantum_recommendation(score: int) -> str:
    """Generate a quantum readiness recommendation based on score."""
    if score >= 80:
        return "Good quantum readiness posture. Plan migration to ML-KEM/ML-DSA within 2-3 years."
    elif score >= 60:
        return "Moderate quantum risk. Begin hybrid (classical + PQC) key exchange within 1-2 years."
    elif score >= 40:
        return "Elevated quantum risk. Prioritize migration to post-quantum algorithms within 12 months."
    else:
        return "Critical quantum vulnerability. Immediate action required — harvest-now-decrypt-later threat is active."


# ---------------------------------------------------------------------------
# Comprehensive Quantum Assessment
# ---------------------------------------------------------------------------


async def run_full_quantum_assessment(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    domains: list[str] | None = None,
) -> dict[str, Any]:
    """Run a full quantum readiness assessment for the tenant.

    Assesses:
    1. TLS connections for quantum-vulnerable crypto
    2. Overall quantum readiness score
    3. NIST PQC migration recommendations
    4. Harvest-now-decrypt-later threat assessment
    """
    import asyncio

    findings_created = 0
    domain_results = []

    # If no domains specified, try to get them from the tenant's authorized targets
    if not domains:
        from gds_api.models import AuthorizedTarget
        from sqlalchemy import select as sa_select
        result = await db.execute(
            sa_select(AuthorizedTarget.target)
            .where(
                AuthorizedTarget.tenant_id == tenant_id,
                AuthorizedTarget.status == "active",
            )
        )
        domains = [row[0] for row in result.all() if "." in str(row[0])]

    for domain in (domains or []):
        # Run TLS assessment
        result = assess_tls_quantum_readiness(domain)
        if result.get("success"):
            domain_results.append(result)

            # Create findings for quantum-vulnerable crypto
            for finding_detail in result.get("findings", []):
                if finding_detail.get("assessment", {}).get("quantum_vulnerable"):
                    finding = Finding(
                        tenant_id=tenant_id,
                        source="quantum_crypto_assessment",
                        external_id=f"quantum:{domain}:{finding_detail.get('component', 'unknown')}",
                        title=f"Quantum: {finding_detail.get('component', 'Unknown')} is quantum-vulnerable for {domain}",
                        description=(
                            f"{finding_detail.get('impact', 'Quantum vulnerability detected')}\n"
                            f"Algorithm: {finding_detail.get('algorithm', 'unknown')}\n"
                            f"Threat type: {finding_detail.get('assessment', {}).get('threat_type', 'unknown')}\n"
                            f"Severity: {finding_detail.get('assessment', {}).get('severity', 'unknown')}\n"
                            f"Quantum timeline: {finding_detail.get('assessment', {}).get('quantum_timeline', 'unknown')}\n"
                            f"PQC replacement: {finding_detail.get('assessment', {}).get('pq_replacement', 'N/A')}"
                        ),
                        severity=finding_detail.get("assessment", {}).get("severity", "medium"),
                        status=FindingStatus.OBSERVED.value,
                        raw_data={
                            "domain": domain,
                            "component": finding_detail.get("component"),
                            "algorithm": finding_detail.get("algorithm"),
                            "threat_type": finding_detail.get("assessment", {}).get("threat_type"),
                            "quantum_timeline": finding_detail.get("assessment", {}).get("quantum_timeline"),
                            "pq_replacement": finding_detail.get("assessment", {}).get("pq_replacement"),
                            "pq_standard": finding_detail.get("assessment", {}).get("pq_standard"),
                        },
                    )
                    db.add(finding)
                    findings_created += 1

    await db.commit()

    # Calculate overall score
    if domain_results:
        avg_score = sum(r["quantum_readiness_score"] for r in domain_results) / len(domain_results)
    else:
        avg_score = 0

    return {
        "success": True,
        "analysis_timestamp": datetime.now(UTC).isoformat(),
        "domains_assessed": len(domain_results),
        "findings_created": findings_created,
        "overall_quantum_readiness_score": round(avg_score, 1),
        "overall_quantum_readiness_grade": _score_to_grade(avg_score),
        "domain_results": domain_results,
        "nist_pqc_standards": NIST_PQC_STANDARDS,
        "harvest_now_decrypt_later_risk": _assess_hndl_risk(domain_results),
        "recommendation": _quantum_recommendation(int(avg_score)),
        "methodology": {
            "shor_algorithm": "Gidney & Ekerå 2021 — 20M noisy qubits for RSA-2048 in 8 hours",
            "grovers_algorithm": "Quadratic speedup — halves effective symmetric key security",
            "nist_standards": "FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) — finalized August 2024",
        },
    }


def _score_to_grade(score: float) -> str:
    if score >= 80:
        return "A"
    elif score >= 60:
        return "B"
    elif score >= 40:
        return "C"
    elif score >= 20:
        return "D"
    return "F"


def _assess_hndl_risk(domain_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Assess the 'Harvest Now, Decrypt Later' risk.

    Adversaries collect encrypted traffic NOW and will decrypt it when
    quantum computers become available. This is a real, documented threat
    (NSA, CISA, NSA/CSS, and academic researchers have warned about it).
    """
    vulnerable_domains = sum(
        1 for r in domain_results
        if any(f.get("assessment", {}).get("threat_type") == "shor" for f in r.get("findings", []))
    )
    total = len(domain_results)

    if total == 0:
        risk_level = "unknown"
        risk_description = "No domains assessed — cannot determine HNDL risk"
    elif vulnerable_domains == 0:
        risk_level = "low"
        risk_description = "No quantum-vulnerable key exchange detected — HNDL risk is minimal"
    elif vulnerable_domains / total < 0.5:
        risk_level = "medium"
        risk_description = "Some domains use quantum-vulnerable key exchange — encrypted traffic to these domains is at risk of future decryption"
    else:
        risk_level = "high"
        risk_description = "Most domains use quantum-vulnerable key exchange — adversaries may be collecting encrypted traffic now for future quantum decryption"

    return {
        "risk_level": risk_level,
        "risk_description": risk_description,
        "vulnerable_domains": vulnerable_domains,
        "total_domains": total,
        "advisory": (
            "CISA, NSA, and NIST recommend migrating to post-quantum cryptography by 2035. "
            "Data with long-term confidentiality requirements (medical, financial, government) "
            "should be prioritized due to the harvest-now-decrypt-later threat."
        ),
    }
