from pathlib import Path

from pqc_audit.models import SourceFile, StaticMatch
from pqc_audit.pattern_extractor import PatternExtractor


def make_source(lines: list[str]) -> SourceFile:
    content = "\n".join(lines) + "\n"
    return SourceFile(Path("app.py"), "app.py", content, len(lines))


def make_match(
    line_number: int,
    *,
    rule_id: str = "crypto",
    matched_text: str = "RSA",
    algorithm_hint: str | None = "RSA",
    library_hint: str | None = "cryptography",
    line_text: str | None = None,
) -> StaticMatch:
    return StaticMatch(
        "app.py",
        line_number,
        rule_id,
        matched_text,
        algorithm_hint,
        library_hint,
        "high",
        line_text or matched_text,
    )


def test_extracts_snippet_with_bounded_start_and_end_lines() -> None:
    source = make_source(["line 1", "line 2", "line 3", "line 4", "line 5"])
    extractor = PatternExtractor(max_snippet_lines=3, context_lines=2)

    evidence = extractor.extract([source], [make_match(1)])

    assert len(evidence) == 1
    assert evidence[0].start_line == 1
    assert evidence[0].end_line == 3
    assert evidence[0].snippet == "line 1\nline 2\nline 3"


def test_nearby_matches_are_merged_into_one_evidence() -> None:
    source = make_source(["line 1", "line 2", "line 3", "line 4", "line 5", "line 6"])
    matches = [make_match(2), make_match(4, matched_text="ECDSA", algorithm_hint="ECDSA")]
    extractor = PatternExtractor(max_snippet_lines=5, context_lines=1)

    evidence = extractor.extract([source], matches)

    assert len(evidence) == 1
    assert evidence[0].start_line == 1
    assert evidence[0].end_line == 5
    assert [match.line_number for match in evidence[0].static_matches] == [2, 4]


def test_far_matches_are_split_when_span_exceeds_snippet_limit() -> None:
    source = make_source([f"line {index}" for index in range(1, 11)])
    matches = [make_match(2), make_match(8, matched_text="ECDH", algorithm_hint="ECDH")]
    extractor = PatternExtractor(max_snippet_lines=4, context_lines=1)

    evidence = extractor.extract([source], matches)

    assert len(evidence) == 2
    assert [[match.line_number for match in item.static_matches] for item in evidence] == [[2], [8]]
    assert all(item.end_line - item.start_line + 1 <= 4 for item in evidence)


def test_evidence_id_is_stable_for_same_inputs() -> None:
    source = make_source(["line 1", "key = RSA.generate_private_key()", "line 3"])
    matches = [make_match(2, matched_text="RSA.generate_private_key")]
    extractor = PatternExtractor(max_snippet_lines=3, context_lines=1)

    first = extractor.extract([source], matches)
    second = extractor.extract([source], matches)

    assert first[0].evidence_id == second[0].evidence_id


def test_algorithm_uses_high_risk_priority_when_multiple_hints_exist() -> None:
    source = make_source(["crypto line"])
    matches = [
        make_match(
            1,
            matched_text="mixed",
            algorithm_hint="DSA ECDH RSA",
            library_hint="hazmat",
        )
    ]
    extractor = PatternExtractor()

    evidence = extractor.extract([source], matches)

    assert evidence[0].algorithm == "RSA"
    assert evidence[0].library == "hazmat"


def test_usage_type_inference() -> None:
    source = make_source(
        [
            "private_key = rsa.generate_private_key()",
            "signature = private_key.sign(data, padding, hash)",
            "shared = private_key.exchange(ec.ECDH(), peer)",
            "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)",
            "RSA",
        ]
    )
    matches = [
        make_match(1, matched_text="generate_private_key"),
        make_match(2, matched_text="sign"),
        make_match(3, matched_text="exchange", algorithm_hint="ECDH"),
        make_match(4, matched_text="SSLContext", algorithm_hint=None),
        make_match(5, matched_text="RSA", line_text="RSA"),
    ]
    extractor = PatternExtractor(max_snippet_lines=1, context_lines=0)

    evidence = extractor.extract([source], matches)

    assert [item.usage_type for item in evidence] == [
        "key_generation",
        "signature",
        "key_exchange",
        "tls_configuration",
        "unknown",
    ]


def test_usage_type_inference_for_non_python_rules() -> None:
    source = make_source(
        [
            "generateKeyPairSync('rsa', {});",
            "KeyAgreement.getInstance(\"ECDH\");",
            "Signature.getInstance(\"SHA256withRSA\");",
            "Cipher.getInstance(\"RSA/ECB/OAEPWithSHA-256AndMGF1Padding\");",
            "RSA_generate_key_ex(rsa, 2048, e, NULL);",
            "KeyStore.getInstance(\"PKCS12\");",
            "SSLContext.getInstance(\"TLSv1.3\");",
            "EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);",
            "EVP_PKEY_derive_init(ctx);",
            "EVP_PKEY_encrypt_init(ctx);",
            "hashlib.sha256(data).digest();",
            "hmac.new(key, data, 'sha256');",
            "algorithms.AES(key);",
        ]
    )
    matches = [
        make_match(1, rule_id="js_crypto_generate_keypair_rsa", matched_text="generateKeyPairSync('rsa')"),
        make_match(2, rule_id="java_keyagreement_ecdh", matched_text='KeyAgreement.getInstance("ECDH")', algorithm_hint="ECDH"),
        make_match(3, rule_id="java_signature_rsa", matched_text='Signature.getInstance("SHA256withRSA")'),
        make_match(4, rule_id="java_cipher_rsa", matched_text='Cipher.getInstance("RSA")'),
        make_match(5, rule_id="openssl_rsa_generate_key_ex", matched_text="RSA_generate_key_ex"),
        make_match(6, rule_id="java_keystore_getinstance", matched_text="KeyStore.getInstance", algorithm_hint=None),
        make_match(7, rule_id="java_sslcontext_getinstance", matched_text="SSLContext.getInstance", algorithm_hint=None),
        make_match(8, rule_id="openssl_evp_digest_sign", matched_text="EVP_DigestSignInit", algorithm_hint=None),
        make_match(9, rule_id="openssl_evp_pkey_derive", matched_text="EVP_PKEY_derive_init", algorithm_hint=None),
        make_match(10, rule_id="openssl_evp_pkey_encrypt", matched_text="EVP_PKEY_encrypt_init", algorithm_hint=None),
        make_match(11, rule_id="py_hashlib_sha2", matched_text="hashlib.sha256", algorithm_hint="SHA-2"),
        make_match(12, rule_id="py_hmac_new", matched_text="hmac.new", algorithm_hint="HMAC"),
        make_match(13, rule_id="py_cryptography_aes", matched_text="algorithms.AES", algorithm_hint="AES"),
    ]
    extractor = PatternExtractor(max_snippet_lines=1, context_lines=0)

    evidence = extractor.extract([source], matches)

    assert [item.usage_type for item in evidence] == [
        "key_generation",
        "key_exchange",
        "signature",
        "encryption",
        "key_generation",
        "certificate_handling",
        "tls_configuration",
        "signature",
        "key_exchange",
        "encryption",
        "hashing",
        "mac",
        "symmetric_encryption",
    ]


def test_infers_frontend_metadata_from_static_matches() -> None:
    source = make_source(["from cryptography.hazmat.primitives.asymmetric import rsa"])
    matches = [
        make_match(
            1,
            rule_id="cryptography_import_rsa",
            matched_text="rsa",
            line_text="from cryptography.hazmat.primitives.asymmetric import rsa",
            library_hint="cryptography",
        )
    ]
    matches[0].evidence_type = "import"
    matches[0].source_kind = "code"
    matches[0].confidence = "medium"

    evidence = PatternExtractor(max_snippet_lines=1, context_lines=0).extract([source], matches)[0]

    assert evidence.evidence_type == "import"
    assert evidence.source_kind == "code"
    assert evidence.confidence == "medium"
