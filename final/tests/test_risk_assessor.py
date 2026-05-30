from __future__ import annotations

from pqc_audit.models import CryptoEvidence, SemanticAnalysis
from pqc_audit.risk_assessor import RiskAssessor


def evidence(
    evidence_id: str = "ev-1",
    algorithm: str | None = "RSA",
    usage_type: str = "encryption",
    file_path: str = "src/app.py",
    evidence_type: str = "api_call",
    source_kind: str = "code",
    confidence: str = "high",
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
        evidence_type=evidence_type,  # type: ignore[arg-type]
        source_kind=source_kind,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
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
    assert assessment.finding_category == "vulnerability"
    assert assessment.confidence == "high"
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
    assert assessment.finding_category == "needs_review"
    assert "algorithm:unknown" in assessment.risk_factors


def test_test_or_example_reduces_score() -> None:
    result = RiskAssessor().assess(
        [evidence(algorithm="RSA", file_path="tests/test_keys.py")],
        [analysis(algorithm="RSA", is_test_or_example=True)],
    )

    assessment = result[0]
    assert assessment.risk_level == "quantum_vulnerable"
    assert assessment.risk_score == 60
    assert assessment.finding_category == "low_confidence"
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
    assert assessment.finding_category == "low_confidence"
    assert "semantic_analysis_not_real_crypto_usage" in assessment.risk_factors


def test_quantum_safe_algorithms_are_classified_for_frontend() -> None:
    results = RiskAssessor().assess(
        [
            evidence(evidence_id="aes", algorithm="AES", usage_type="symmetric_encryption"),
            evidence(evidence_id="sha", algorithm="SHA-2", usage_type="hashing"),
            evidence(evidence_id="hmac", algorithm="HMAC", usage_type="mac"),
        ],
        [
            analysis(evidence_id="aes", algorithm="AES", usage_type="symmetric_encryption"),
            analysis(evidence_id="sha", algorithm="SHA-2", usage_type="hashing"),
            analysis(evidence_id="hmac", algorithm="HMAC", usage_type="mac"),
        ],
    )

    assert [result.risk_level for result in results] == [
        "quantum_safe",
        "quantum_safe",
        "quantum_safe",
    ]
    assert all(result.finding_category == "quantum_safe" for result in results)
    assert all(result.display_priority >= 80 for result in results)


def test_import_keyword_and_comment_matches_are_low_confidence() -> None:
    results = RiskAssessor().assess(
        [
            evidence(evidence_id="import", evidence_type="import", confidence="medium"),
            evidence(
                evidence_id="comment",
                evidence_type="keyword",
                source_kind="comment",
                confidence="low",
            ),
        ],
        [
            analysis(evidence_id="import", confidence=0.65),
            analysis(evidence_id="comment", confidence=0.35),
        ],
    )

    assert results[0].finding_category == "low_confidence"
    assert results[0].risk_score == 70
    assert "import_only_reduced_score" in results[0].risk_factors
    assert results[1].finding_category == "low_confidence"
    assert results[1].risk_score == 0
    assert "comment_or_string_reduced_score" in results[1].risk_factors
