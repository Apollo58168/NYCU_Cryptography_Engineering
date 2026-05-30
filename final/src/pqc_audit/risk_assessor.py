from __future__ import annotations

import re

from pqc_audit.models import CryptoEvidence, RiskAssessment, RiskLevel, SemanticAnalysis, UsageType


class RiskAssessor:
    def assess(
        self,
        evidence_items: list[CryptoEvidence],
        analyses: list[SemanticAnalysis],
    ) -> list[RiskAssessment]:
        analysis_by_id = {analysis.evidence_id: analysis for analysis in analyses}
        return [
            self._assess_one(evidence, analysis_by_id.get(evidence.evidence_id))
            for evidence in evidence_items
        ]

    def _assess_one(
        self,
        evidence: CryptoEvidence,
        analysis: SemanticAnalysis | None,
    ) -> RiskAssessment:
        if analysis is not None and not analysis.is_real_crypto_usage:
            return RiskAssessment(
                evidence_id=evidence.evidence_id,
                risk_level="unknown",
                risk_score=0,
                risk_factors=["semantic_analysis_not_real_crypto_usage"],
                reason="Semantic analysis indicates this is not real crypto usage.",
            )

        algorithm = self._select_algorithm(evidence, analysis)
        usage_type = self._select_usage_type(evidence, analysis)
        is_security_sensitive = analysis.is_security_sensitive if analysis is not None else True
        is_test_or_example = (
            analysis.is_test_or_example
            if analysis is not None
            else self._looks_like_test_or_example(evidence)
        )
        confidence = analysis.confidence if analysis is not None else 1.0

        risk_level = self._classify(algorithm, usage_type, is_security_sensitive)
        risk_factors = self._risk_factors(
            risk_level=risk_level,
            algorithm=algorithm,
            usage_type=usage_type,
            is_security_sensitive=is_security_sensitive,
            is_test_or_example=is_test_or_example,
            confidence=confidence,
            used_fallback=analysis is None,
        )
        risk_score = self._score(
            risk_level=risk_level,
            usage_type=usage_type,
            is_test_or_example=is_test_or_example,
            confidence=confidence,
        )

        return RiskAssessment(
            evidence_id=evidence.evidence_id,
            risk_level=risk_level,
            risk_score=risk_score,
            risk_factors=risk_factors,
            reason=self._reason(risk_level, algorithm, usage_type, risk_factors),
        )

    def _select_algorithm(
        self,
        evidence: CryptoEvidence,
        analysis: SemanticAnalysis | None,
    ) -> str | None:
        if analysis is not None and analysis.algorithm:
            return analysis.algorithm
        return evidence.algorithm

    def _select_usage_type(
        self,
        evidence: CryptoEvidence,
        analysis: SemanticAnalysis | None,
    ) -> UsageType:
        if analysis is not None and analysis.usage_type:
            return analysis.usage_type
        return evidence.usage_type

    def _classify(
        self,
        algorithm: str | None,
        usage_type: UsageType,
        is_security_sensitive: bool,
    ) -> RiskLevel:
        algorithm_kind = self._algorithm_kind(algorithm)
        if algorithm_kind == "quantum_vulnerable":
            return "quantum_vulnerable"
        if algorithm_kind == "quantum_safe":
            return "quantum_safe"
        if usage_type in {"tls_configuration", "certificate_handling"}:
            return "partially_vulnerable"
        if is_security_sensitive:
            return "unknown"
        return "unknown"

    def _algorithm_kind(self, algorithm: str | None) -> RiskLevel | None:
        normalized = self._normalize_algorithm(algorithm)
        if not normalized:
            return None

        if any(token in normalized for token in ("ECDSA", "ECDH")):
            return "quantum_vulnerable"
        if "RSA" in normalized:
            return "quantum_vulnerable"
        if "ELLIPTIC CURVE" in normalized or re.search(r"\bECC\b", normalized):
            return "quantum_vulnerable"
        if "DIFFIE HELLMAN" in normalized or re.search(r"\bDH\b", normalized):
            return "quantum_vulnerable"
        if re.search(r"\bDSA\b", normalized):
            return "quantum_vulnerable"

        if "AES" in normalized:
            return "quantum_safe"
        if "SHA 256" in normalized or "SHA256" in normalized:
            return "quantum_safe"
        return None

    def _score(
        self,
        risk_level: RiskLevel,
        usage_type: UsageType,
        is_test_or_example: bool,
        confidence: float,
    ) -> int:
        score_by_level = {
            "quantum_vulnerable": 90,
            "partially_vulnerable": 60,
            "unknown": 35,
            "quantum_safe": 10,
        }
        score = score_by_level[risk_level]
        if usage_type == "key_exchange":
            score += 15
        elif usage_type == "signature":
            score += 10
        elif usage_type == "key_generation":
            score += 8

        if is_test_or_example:
            score -= 30
        if confidence < 0.5:
            score -= 20

        return max(0, min(100, score))

    def _risk_factors(
        self,
        risk_level: RiskLevel,
        algorithm: str | None,
        usage_type: UsageType,
        is_security_sensitive: bool,
        is_test_or_example: bool,
        confidence: float,
        used_fallback: bool,
    ) -> list[str]:
        factors = [f"risk_level:{risk_level}", f"usage_type:{usage_type}"]
        if algorithm:
            factors.append(f"algorithm:{algorithm}")
        else:
            factors.append("algorithm:unknown")
        if is_security_sensitive:
            factors.append("security_sensitive")
        if is_test_or_example:
            factors.append("test_or_example_reduced_score")
        if confidence < 0.5:
            factors.append("low_confidence_reduced_score")
        if used_fallback:
            factors.append("semantic_analysis_missing_static_fallback")
        return factors

    def _reason(
        self,
        risk_level: RiskLevel,
        algorithm: str | None,
        usage_type: UsageType,
        risk_factors: list[str],
    ) -> str:
        algorithm_text = algorithm or "unknown algorithm"
        reason_by_level = {
            "quantum_vulnerable": (
                f"{algorithm_text} used for {usage_type} is considered quantum-vulnerable."
            ),
            "partially_vulnerable": (
                f"{usage_type} uses an unknown public-key algorithm, so it is partially vulnerable."
            ),
            "quantum_safe": (
                f"{algorithm_text} used for {usage_type} is treated as quantum-safe for this audit."
            ),
            "unknown": (
                f"{algorithm_text} used for {usage_type} cannot be classified with available evidence."
            ),
        }
        return f"{reason_by_level[risk_level]} Factors: {', '.join(risk_factors)}."

    def _normalize_algorithm(self, algorithm: str | None) -> str:
        if algorithm is None:
            return ""
        return re.sub(r"[^A-Z0-9]+", " ", algorithm.upper()).strip()

    def _looks_like_test_or_example(self, evidence: CryptoEvidence) -> bool:
        text = " ".join(
            [
                evidence.file_path,
                evidence.snippet,
                evidence.source,
            ]
        ).lower()
        return "test" in text or "example" in text
