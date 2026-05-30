from pqc_audit.migration_recommender import MigrationRecommender
from pqc_audit.models import CryptoEvidence, RiskAssessment, SemanticAnalysis, UsageType


def make_evidence(
    evidence_id: str,
    algorithm: str | None,
    usage_type: UsageType,
) -> CryptoEvidence:
    return CryptoEvidence(
        evidence_id=evidence_id,
        file_path="app.py",
        start_line=1,
        end_line=1,
        snippet=algorithm or "crypto",
        algorithm=algorithm,
        library=None,
        usage_type=usage_type,
        source="static",
    )


def make_analysis(
    evidence_id: str,
    algorithm: str | None,
    usage_type: UsageType,
) -> SemanticAnalysis:
    return SemanticAnalysis(
        evidence_id=evidence_id,
        is_real_crypto_usage=True,
        is_security_sensitive=True,
        algorithm=algorithm,
        usage_type=usage_type,
        is_test_or_example=False,
        explanation="real crypto usage",
        confidence=0.9,
        raw_model_output="{}",
    )


def make_risk(evidence_id: str, risk_score: int = 90) -> RiskAssessment:
    return RiskAssessment(
        evidence_id=evidence_id,
        risk_level="quantum_vulnerable",
        risk_score=risk_score,
        risk_factors=["classical crypto"],
        reason="classical public-key cryptography is vulnerable to quantum attacks",
    )


def make_safe_risk(evidence_id: str) -> RiskAssessment:
    return RiskAssessment(
        evidence_id=evidence_id,
        risk_level="quantum_safe",
        risk_score=10,
        risk_factors=["quantum_safe"],
        reason="symmetric crypto is quantum-safe for this audit",
        finding_category="quantum_safe",
        display_priority=90,
        confidence="high",
    )


def recommend_one(
    evidence: CryptoEvidence,
    analysis: SemanticAnalysis | None = None,
    risk: RiskAssessment | None = None,
):
    return MigrationRecommender().recommend(
        [evidence],
        [analysis] if analysis else [],
        [risk] if risk else [],
    )[0]


def test_rsa_key_exchange_recommends_ml_kem_or_hybrid() -> None:
    evidence = make_evidence("app.py:1-1", "RSA", "encryption")
    recommendation = recommend_one(evidence, make_analysis(evidence.evidence_id, "RSA", "encryption"), make_risk(evidence.evidence_id))

    assert recommendation.evidence_id == evidence.evidence_id
    assert "ML-KEM" in recommendation.candidate_pqc_algorithms
    assert "hybrid" in recommendation.recommended_action.lower()
    assert recommendation.compatibility_notes
    assert recommendation.developer_steps


def test_ecdsa_signature_recommends_ml_dsa_or_slh_dsa() -> None:
    evidence = make_evidence("app.py:2-2", "ECDSA", "signature")
    recommendation = recommend_one(evidence, make_analysis(evidence.evidence_id, "ECDSA", "signature"), make_risk(evidence.evidence_id))

    assert recommendation.candidate_pqc_algorithms == ["ML-DSA", "SLH-DSA"]
    assert "signatures" in recommendation.recommended_action


def test_tls_configuration_recommends_tls_stack_review() -> None:
    evidence = make_evidence("app.py:3-3", "TLS", "tls_configuration")
    recommendation = recommend_one(evidence, make_analysis(evidence.evidence_id, "TLS", "tls_configuration"), make_risk(evidence.evidence_id))

    assert "TLS stack" in recommendation.recommended_action
    assert "ML-KEM" in recommendation.candidate_pqc_algorithms
    assert any("TLS" in note for note in recommendation.compatibility_notes)


def test_unknown_usage_recommends_manual_context_confirmation() -> None:
    evidence = make_evidence("app.py:4-4", None, "unknown")
    recommendation = recommend_one(evidence)

    assert "Manually confirm" in recommendation.recommended_action
    assert recommendation.candidate_pqc_algorithms == ["Context-dependent PQC algorithm selection"]
    assert recommendation.developer_steps


def test_quantum_safe_usage_does_not_recommend_pqc_migration() -> None:
    evidence = make_evidence("app.py:8-8", "AES", "symmetric_encryption")
    recommendation = recommend_one(
        evidence,
        make_analysis(evidence.evidence_id, "AES", "symmetric_encryption"),
        make_safe_risk(evidence.evidence_id),
    )

    assert "No PQC migration is required" in recommendation.recommended_action
    assert recommendation.candidate_pqc_algorithms == []


def test_high_risk_finding_has_recommended_action() -> None:
    evidence = make_evidence("app.py:5-5", "DH", "key_exchange")
    recommendation = recommend_one(evidence, make_analysis(evidence.evidence_id, "DH", "key_exchange"), make_risk(evidence.evidence_id, 95))

    assert recommendation.recommended_action
    assert "ML-KEM" in recommendation.candidate_pqc_algorithms


def test_recommendations_are_aligned_by_evidence_id() -> None:
    rsa_evidence = make_evidence("app.py:6-6", "RSA", "encryption")
    ecdsa_evidence = make_evidence("app.py:7-7", "ECDSA", "signature")

    recommendations = MigrationRecommender().recommend(
        [rsa_evidence, ecdsa_evidence],
        [
            make_analysis(ecdsa_evidence.evidence_id, "ECDSA", "signature"),
            make_analysis(rsa_evidence.evidence_id, "RSA", "encryption"),
        ],
        [
            make_risk(ecdsa_evidence.evidence_id),
            make_risk(rsa_evidence.evidence_id),
        ],
    )

    assert [recommendation.evidence_id for recommendation in recommendations] == [
        rsa_evidence.evidence_id,
        ecdsa_evidence.evidence_id,
    ]
    assert "ML-KEM" in recommendations[0].candidate_pqc_algorithms
    assert recommendations[1].candidate_pqc_algorithms == ["ML-DSA", "SLH-DSA"]
