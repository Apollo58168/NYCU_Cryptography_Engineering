from __future__ import annotations

from pqc_audit.models import (
    CryptoEvidence,
    MigrationRecommendation,
    RiskAssessment,
    SemanticAnalysis,
    UsageType,
)


class MigrationRecommender:
    def recommend(
        self,
        evidence_items: list[CryptoEvidence],
        analyses: list[SemanticAnalysis],
        risks: list[RiskAssessment],
    ) -> list[MigrationRecommendation]:
        analyses_by_id = {analysis.evidence_id: analysis for analysis in analyses}
        risks_by_id = {risk.evidence_id: risk for risk in risks}

        return [
            self._recommend_for_evidence(
                evidence,
                analyses_by_id.get(evidence.evidence_id),
                risks_by_id.get(evidence.evidence_id),
            )
            for evidence in evidence_items
        ]

    def _recommend_for_evidence(
        self,
        evidence: CryptoEvidence,
        analysis: SemanticAnalysis | None,
        risk: RiskAssessment | None,
    ) -> MigrationRecommendation:
        algorithm = self._normalized_algorithm(analysis.algorithm if analysis else None)
        if not algorithm:
            algorithm = self._normalized_algorithm(evidence.algorithm)

        usage_type = self._usage_type(evidence, analysis)
        risk_label = risk.risk_level if risk else "unknown"
        guidance = self._guidance_for(algorithm, usage_type, risk_label)

        summary = (
            f"{evidence.evidence_id}: {algorithm or 'Unknown algorithm'} used for "
            f"{usage_type}; risk level is {risk_label}."
        )

        return MigrationRecommendation(
            evidence_id=evidence.evidence_id,
            summary=summary,
            recommended_action=guidance["recommended_action"],
            candidate_pqc_algorithms=guidance["candidate_pqc_algorithms"],
            compatibility_notes=guidance["compatibility_notes"],
            developer_steps=guidance["developer_steps"],
        )

    def _usage_type(
        self,
        evidence: CryptoEvidence,
        analysis: SemanticAnalysis | None,
    ) -> UsageType:
        if analysis and analysis.usage_type:
            return analysis.usage_type
        return evidence.usage_type

    def _normalized_algorithm(self, algorithm: str | None) -> str | None:
        if not algorithm:
            return None
        return algorithm.strip().upper().replace("-", "")

    def _guidance_for(
        self,
        algorithm: str | None,
        usage_type: UsageType,
        risk_level: str = "unknown",
    ) -> dict[str, list[str] | str]:
        if risk_level == "quantum_safe" or algorithm in {"AES", "HMAC", "SHA2", "SHA3"}:
            return {
                "recommended_action": "No PQC migration is required for this symmetric, hashing, or MAC usage based on the current quantum-risk model.",
                "candidate_pqc_algorithms": [],
                "compatibility_notes": [
                    "Grover-style considerations may require adequate symmetric key or digest sizes, but this is not a Shor-vulnerable public-key usage."
                ],
                "developer_steps": [
                    "Confirm that the usage is not combined with RSA, ECC, ECDSA, ECDH, DH, or DSA in the same protocol path.",
                    "Keep AES key sizes and SHA/HMAC digest sizes aligned with the intended security level.",
                ],
            }

        if usage_type == "tls_configuration":
            return {
                "recommended_action": "Review the TLS stack and configuration for PQC or hybrid key exchange support.",
                "candidate_pqc_algorithms": ["ML-KEM", "Hybrid TLS key exchange"],
                "compatibility_notes": [
                    "PQC TLS support depends on the deployed TLS library, protocol version, and peer compatibility."
                ],
                "developer_steps": [
                    "Inventory the TLS library and version.",
                    "Check whether hybrid key exchange groups are supported.",
                    "Plan an interoperability test with expected clients and servers.",
                ],
            }

        if usage_type == "certificate_handling":
            return {
                "recommended_action": "Review certificate chain and signature algorithm requirements before migration.",
                "candidate_pqc_algorithms": ["ML-DSA", "SLH-DSA"],
                "compatibility_notes": [
                    "Certificate migration depends on CA, client, server, and trust-store support."
                ],
                "developer_steps": [
                    "Identify where certificates are generated, validated, and pinned.",
                    "Check signature algorithm constraints across the certificate chain.",
                    "Plan a staged certificate compatibility test.",
                ],
            }

        if usage_type == "unknown" or not algorithm:
            return {
                "recommended_action": "Manually confirm the cryptographic context before selecting a PQC migration path.",
                "candidate_pqc_algorithms": ["Context-dependent PQC algorithm selection"],
                "compatibility_notes": [
                    "The correct PQC replacement depends on whether this usage is encryption, signatures, or key exchange."
                ],
                "developer_steps": [
                    "Confirm the real cryptographic usage.",
                    "Identify protocol and interoperability constraints.",
                    "Map the confirmed usage to an approved PQC algorithm family.",
                ],
            }

        if usage_type in ("encryption", "key_generation") and algorithm == "RSA":
            return {
                "recommended_action": "Replace RSA encryption or key transport with ML-KEM or a hybrid key establishment design.",
                "candidate_pqc_algorithms": ["ML-KEM", "Hybrid RSA + ML-KEM key establishment"],
                "compatibility_notes": [
                    "Hybrid key establishment may be needed while peers and protocols transition to PQC."
                ],
                "developer_steps": [
                    "Confirm whether RSA is used for encryption, key wrapping, or key transport.",
                    "Select an ML-KEM parameter set that matches the security requirement.",
                    "Design and test a hybrid migration path if classical compatibility is required.",
                ],
            }

        if usage_type == "key_exchange" and algorithm in ("ECDH", "DH", "RSA"):
            return {
                "recommended_action": "Migrate classical key exchange to a PQC KEM or hybrid key exchange.",
                "candidate_pqc_algorithms": ["ML-KEM", "Hybrid classical + ML-KEM key exchange"],
                "compatibility_notes": [
                    "Key exchange migration requires protocol support on both endpoints."
                ],
                "developer_steps": [
                    "Identify every peer participating in the key exchange.",
                    "Check protocol support for PQC KEM or hybrid key exchange.",
                    "Add interoperability tests before rollout.",
                ],
            }

        if usage_type == "signature" and algorithm in ("RSA", "ECDSA", "DSA"):
            return {
                "recommended_action": "Migrate classical signatures to ML-DSA or SLH-DSA where protocol support allows.",
                "candidate_pqc_algorithms": ["ML-DSA", "SLH-DSA"],
                "compatibility_notes": [
                    "Signature migration must account for verifier, certificate, and artifact format support."
                ],
                "developer_steps": [
                    "Identify all signers and verifiers.",
                    "Choose ML-DSA for general-purpose signatures or SLH-DSA where stateless hash-based signatures are required.",
                    "Test signature size and format impact on storage and protocols.",
                ],
            }

        return {
            "recommended_action": "Manually confirm the cryptographic context before selecting a PQC migration path.",
            "candidate_pqc_algorithms": ["Context-dependent PQC algorithm selection"],
            "compatibility_notes": [
                "No direct migration mapping is available for this algorithm and usage combination."
            ],
            "developer_steps": [
                "Confirm the algorithm and usage type.",
                "Check protocol and library constraints.",
                "Select the PQC replacement from the confirmed usage category.",
            ],
        }
