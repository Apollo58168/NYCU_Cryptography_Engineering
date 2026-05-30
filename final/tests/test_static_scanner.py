from pathlib import Path

from pqc_audit.models import SourceFile, StaticMatch
from pqc_audit.static_scanner import StaticScanner


def source_file(content: str, relative_path: str = "app.py") -> SourceFile:
    return SourceFile(Path(relative_path), relative_path, content, len(content.splitlines()))


def scan(content: str) -> list[StaticMatch]:
    return StaticScanner().scan([source_file(content)])


def assert_has_match(
    matches: list[StaticMatch],
    rule_id: str,
    algorithm_hint: str,
    library_hint: str | None,
) -> StaticMatch:
    for match in matches:
        if (
            match.rule_id == rule_id
            and match.algorithm_hint == algorithm_hint
            and match.library_hint == library_hint
        ):
            return match
    raise AssertionError(f"missing match: {rule_id}")


def test_detects_cryptography_rsa_import_and_key_generation() -> None:
    matches = scan(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )

    import_match = assert_has_match(matches, "cryptography_import_rsa", "RSA", "cryptography")
    call_match = assert_has_match(matches, "cryptography_rsa_generate_private_key", "RSA", "cryptography")

    assert import_match.line_number == 1
    assert import_match.line_text == "from cryptography.hazmat.primitives.asymmetric import rsa"
    assert call_match.line_number == 2
    assert call_match.matched_text == "rsa.generate_private_key"


def test_detects_ec_import_key_generation_and_ecc_keyword() -> None:
    matches = scan(
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "private_key = ec.generate_private_key(ec.SECP256R1())\n"
        "mode = 'ECC'\n"
        "signature = 'ECDSA'\n"
        "shared = 'ECDH'\n"
    )

    assert_has_match(matches, "cryptography_import_ec", "ECC", "cryptography")
    assert_has_match(matches, "cryptography_ec_generate_private_key", "ECC", "cryptography")
    assert_has_match(matches, "keyword_ecc", "ECC", None)
    assert_has_match(matches, "keyword_ecdsa", "ECDSA", None)
    assert_has_match(matches, "keyword_ecdh", "ECDH", None)


def test_detects_dh_import_generate_parameters_and_keywords() -> None:
    matches = scan(
        "from cryptography.hazmat.primitives.asymmetric import dh\n"
        "parameters = dh.generate_parameters(generator=2, key_size=2048)\n"
        "# Diffie-Hellman and DH are candidates\n"
    )

    assert_has_match(matches, "cryptography_import_dh", "Diffie-Hellman", "cryptography")
    assert_has_match(matches, "cryptography_dh_generate_parameters", "Diffie-Hellman", "cryptography")
    assert_has_match(matches, "keyword_diffie_hellman", "Diffie-Hellman", None)
    assert_has_match(matches, "keyword_dh", "DH", None)


def test_detects_ssl_context_rules() -> None:
    matches = scan(
        "import ssl\n"
        "server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
        "client_context = ssl.create_default_context()\n"
    )

    assert_has_match(matches, "ssl_context", "TLS", "ssl")
    assert_has_match(matches, "ssl_create_default_context", "TLS", "ssl")


def test_detects_pycryptodome_rsa_rules() -> None:
    matches = scan(
        "from Crypto.PublicKey import RSA\n"
        "import Cryptodome.PublicKey.RSA\n"
    )

    assert_has_match(matches, "pycryptodome_import_rsa", "RSA", "PyCryptodome")
    assert_has_match(matches, "pycryptodome_cryptodome_rsa", "RSA", "PyCryptodome")


def test_comments_and_strings_become_candidates() -> None:
    matches = scan(
        "# RSA in a comment should still be a candidate\n"
        "label = 'ECC certificate'\n"
    )

    rsa_match = assert_has_match(matches, "keyword_rsa", "RSA", None)
    ecc_match = assert_has_match(matches, "keyword_ecc", "ECC", None)

    assert rsa_match.line_number == 1
    assert ecc_match.line_number == 2


def test_syntax_error_falls_back_to_text_scan() -> None:
    matches = scan("def broken(:\n    # RSA fallback\n")

    assert_has_match(matches, "keyword_rsa", "RSA", None)


def test_unrelated_code_produces_no_matches() -> None:
    matches = scan("def add(left, right):\n    return left + right\n")

    assert matches == []
