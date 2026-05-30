from __future__ import annotations

from pqc_audit.models import CryptoEvidence, SemanticAnalysis
from pqc_audit.risk_assessor import RiskAssessor


def evidence(
    evidence_id: str = "ev-1",
    algorithm: str | None = "RSA",
    usage_type: str = "encryption",
    file_path: str = "src/app.py",
) -> CryptoEvidence:
    return CryptoEvidence(
        evidence_id=evidence_id,
        file_path=file_path,
        start_line=1,
        end_line=1,
        snippet=f"use {algorithm}",
        algorithm=algorithm,
        library=None,
        usage_type=usage_type,  # type: ignore[arg-type]
        source="static",
    )


def analysis(
    evidence_id: str = "ev-1",
    algorithm: str | None = "RSA",
    usage_type: str | None = "encryption",
    is_real_crypto_usage: bool = True,
    is_security_sensitive: bool = True,
    is_test_or_example: bool = False,
    confidence: float = 0.9,
) -> SemanticAnalysis:
    return SemanticAnalysis(
        evidence_id=evidence_id,
        is_real_crypto_usage=is_real_crypto_usage,
        is_security_sensitive=is_security_sensitive,
        algorithm=algorithm,
        usage_type=usage_type,  # type: ignore[arg-type]
        is_test_or_example=is_test_or_example,
        explanation="semantic result",
        confidence=confidence,
        raw_model_output="{}",
    )


def test_rsa_is_quantum_vulnerable() -> None:
    result = RiskAssessor().assess([evidence(algorithm="RSA")], [analysis(algorithm="RSA")])

    assessment = result[0]
    assert assessment.evidence_id == "ev-1"
    assert assessment.risk_level == "quantum_vulnerable"
    assert assessment.risk_score == 90
    assert "algorithm:RSA" in assessment.risk_factors


def test_ecdh_key_exchange_is_quantum_vulnerable() -> None:
    result = RiskAssessor().assess(
        [evidence(algorithm="ECDH", usage_type="key_exchange")],
        [analysis(algorithm="ECDH", usage_type="key_exchange")],
    )

    assessment = result[0]
    assert assessment.risk_level == "quantum_vulnerable"
    assert assessment.risk_score == 100
    assert "usage_type:key_exchange" in assessment.risk_factors


def test_tls_unknown_public_key_algorithm_is_partially_vulnerable() -> None:
    result = RiskAssessor().assess(
        [evidence(algorithm=None, usage_type="tls_configuration")],
        [analysis(algorithm=None, usage_type="tls_configuration")],
    )

    assessment = result[0]
    assert assessment.risk_level == "partially_vulnerable"
    assert assessment.risk_score == 60
    assert "algorithm:unknown" in assessment.risk_factors


def test_test_or_example_reduces_score() -> None:
    result = RiskAssessor().assess(
        [evidence(algorithm="RSA", file_path="tests/test_keys.py")],
        [analysis(algorithm="RSA", is_test_or_example=True)],
    )

    assessment = result[0]
    assert assessment.risk_level == "quantum_vulnerable"
    assert assessment.risk_score == 60
    assert "test_or_example_reduced_score" in assessment.risk_factors


def test_score_is_clamped_to_zero_and_one_hundred() -> None:
    high_risk = RiskAssessor().assess(
        [evidence(evidence_id="high", algorithm="ECDH", usage_type="key_exchange")],
        [analysis(evidence_id="high", algorithm="ECDH", usage_type="key_exchange")],
    )[0]
    low_risk = RiskAssessor().assess(
        [evidence(evidence_id="low", algorithm="SHA-256")],
        [
            analysis(
                evidence_id="low",
                algorithm="SHA-256",
                is_test_or_example=True,
                confidence=0.1,
            )
        ],
    )[0]

    assert high_risk.risk_score == 100
    assert low_risk.risk_score == 0


def test_missing_semantic_analysis_uses_static_evidence_fallback() -> None:
    result = RiskAssessor().assess(
        [evidence(algorithm="RSA", usage_type="signature")],
        [],
    )

    assessment = result[0]
    assert assessment.risk_level == "quantum_vulnerable"
    assert assessment.risk_score == 100
    assert "semantic_analysis_missing_static_fallback" in assessment.risk_factors


def test_non_real_crypto_usage_is_unknown() -> None:
    result = RiskAssessor().assess(
        [evidence(algorithm="RSA")],
        [analysis(algorithm="RSA", is_real_crypto_usage=False)],
    )

    assessment = result[0]
    assert assessment.risk_level == "unknown"
    assert assessment.risk_score == 0
    assert "semantic_analysis_not_real_crypto_usage" in assessment.risk_factors
