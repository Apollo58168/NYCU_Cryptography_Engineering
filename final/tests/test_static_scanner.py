from pathlib import Path

from pqc_audit.models import SourceFile, StaticMatch
from pqc_audit.static_scanner import StaticScanner


def source_file(content: str, relative_path: str = "app.py") -> SourceFile:
    return SourceFile(Path(relative_path), relative_path, content, len(content.splitlines()))


def scan(content: str) -> list[StaticMatch]:
    return StaticScanner().scan([source_file(content)])


def scan_file(content: str, relative_path: str) -> list[StaticMatch]:
    return StaticScanner().scan([source_file(content, relative_path)])


def assert_has_match(
    matches: list[StaticMatch],
    rule_id: str,
    algorithm_hint: str | None,
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


def test_detects_python_quantum_safe_rules() -> None:
    matches = scan(
        "import hashlib\n"
        "import hmac\n"
        "from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac\n"
        "from cryptography.hazmat.primitives.ciphers import algorithms\n"
        "digest = hashlib.sha256(data).digest()\n"
        "tag = hmac.new(key, data, 'sha256').digest()\n"
        "hashes.SHA3_256()\n"
        "crypto_hmac.HMAC(key, hashes.SHA256())\n"
        "algorithms.AES(key)\n"
        "from Crypto.Cipher import AES\n"
    )

    hash_match = assert_has_match(matches, "py_hashlib_sha2", "SHA-2", "hashlib")
    assert_has_match(matches, "py_hmac_new", "HMAC", "hmac")
    assert_has_match(matches, "py_cryptography_hashes_sha3", "SHA-3", "cryptography")
    assert_has_match(matches, "py_cryptography_aes", "AES", "cryptography")
    assert_has_match(matches, "pycryptodome_import_aes", "AES", "PyCryptodome")

    assert hash_match.evidence_type == "api_call"
    assert hash_match.source_kind == "code"
    assert hash_match.confidence == "high"


def test_detects_javascript_typescript_crypto_rules() -> None:
    matches = scan_file(
        "const { generateKeyPairSync, createECDH } = require('crypto');\n"
        "generateKeyPairSync('rsa', { modulusLength: 2048 });\n"
        "crypto.generateKeyPair('ec', { namedCurve: 'P-256' }, cb);\n"
        "createECDH('prime256v1');\n"
        "await crypto.subtle.generateKey({ name: 'RSA-PSS' }, true, ['sign']);\n",
        "app.ts",
    )

    assert_has_match(matches, "js_crypto_generate_keypair_rsa", "RSA", "node:crypto")
    assert_has_match(matches, "js_crypto_generate_keypair_ec", "ECC", "node:crypto")
    assert_has_match(matches, "js_crypto_create_ecdh", "ECDH", "node:crypto")
    assert_has_match(matches, "js_webcrypto_rsa", "RSA", "WebCrypto")


def test_detects_jose_jsonwebtoken_and_node_forge_rules() -> None:
    matches = scan_file(
        "import { generateKeyPair, importPKCS8 } from 'jose';\n"
        "await generateKeyPair('RS256');\n"
        "await generateKeyPair('ES256');\n"
        "await importPKCS8(privatePem, 'PS256');\n"
        "jwt.sign(payload, privateKey, { algorithm: 'RS256' });\n"
        "jwt.verify(token, publicKey, { algorithms: ['ES256'] });\n"
        "forge.pki.rsa.generateKeyPair({ bits: 2048 });\n"
        "forge.pki.publicKeyFromPem(pem);\n",
        "auth.ts",
    )

    assert_has_match(matches, "js_jose_generate_keypair_rsa", "RSA", "jose")
    assert_has_match(matches, "js_jose_generate_keypair_ecdsa", "ECDSA", "jose")
    assert_has_match(matches, "js_jose_import_rsa_key", "RSA", "jose")
    assert_has_match(matches, "js_jsonwebtoken_rsa_algorithm", "RSA", "jsonwebtoken")
    assert_has_match(matches, "js_jsonwebtoken_ecdsa_algorithm", "ECDSA", "jsonwebtoken")
    assert_has_match(matches, "js_node_forge_rsa_generate_keypair", "RSA", "node-forge")
    assert_has_match(matches, "js_node_forge_rsa_key_from_pem", "RSA", "node-forge")


def test_detects_javascript_quantum_safe_rules() -> None:
    matches = scan_file(
        "crypto.createHash('sha256').update(data).digest('hex');\n"
        "crypto.createHmac('sha512', key).update(data).digest();\n"
        "await crypto.subtle.digest('SHA-256', data);\n"
        "await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);\n"
        "await crypto.subtle.importKey('raw', key, { name: 'HMAC' }, false, ['sign']);\n",
        "crypto.ts",
    )

    assert_has_match(matches, "js_crypto_create_hash_sha2", "SHA-2", "node:crypto")
    assert_has_match(matches, "js_crypto_create_hmac", "HMAC", "node:crypto")
    assert_has_match(matches, "js_webcrypto_digest_sha2", "SHA-2", "WebCrypto")
    assert_has_match(matches, "js_webcrypto_aes", "AES", "WebCrypto")
    assert_has_match(matches, "js_webcrypto_hmac", "HMAC", "WebCrypto")


def test_detects_java_jca_rules() -> None:
    matches = scan_file(
        'KeyPairGenerator.getInstance("RSA");\n'
        'Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");\n'
        'Signature.getInstance("SHA256withECDSA");\n'
        'KeyAgreement.getInstance("ECDH");\n',
        "App.java",
    )

    assert_has_match(matches, "java_keypairgenerator_rsa", "RSA", "Java JCA")
    assert_has_match(matches, "java_cipher_rsa", "RSA", "Java JCE")
    assert_has_match(matches, "java_signature_ecdsa", "ECDSA", "Java JCA")
    assert_has_match(matches, "java_keyagreement_ecdh", "ECDH", "Java JCA")


def test_detects_java_keystore_tls_and_bouncycastle_rules() -> None:
    matches = scan_file(
        'KeyStore.getInstance("PKCS12");\n'
        'SSLContext.getInstance("TLSv1.3");\n'
        "HttpsURLConnection connection = null;\n"
        "Security.addProvider(new BouncyCastleProvider());\n"
        'converter.setProvider("BC");\n'
        "new RSAKeyPairGenerator();\n"
        "new ECKeyPairGenerator();\n"
        "new ECDSASigner();\n"
        "new ECDHBasicAgreement();\n"
        "new PEMParser(reader);\n"
        'KeyPairGenerator.getInstance("RSA", "BC");\n',
        "App.java",
    )

    assert_has_match(matches, "java_keystore_getinstance", None, "Java KeyStore")
    assert_has_match(matches, "java_sslcontext_getinstance", None, "Java JSSE")
    assert_has_match(matches, "java_https_tls_config", None, "Java JSSE")
    assert_has_match(matches, "java_bouncycastle_provider", None, "BouncyCastle")
    assert_has_match(matches, "java_bouncycastle_rsa_keypair_generator", "RSA", "BouncyCastle")
    assert_has_match(matches, "java_bouncycastle_ec_keypair_generator", "ECC", "BouncyCastle")
    assert_has_match(matches, "java_bouncycastle_ecdsa_signer", "ECDSA", "BouncyCastle")
    assert_has_match(matches, "java_bouncycastle_ecdh_agreement", "ECDH", "BouncyCastle")
    assert_has_match(matches, "java_bouncycastle_pem_parser", None, "BouncyCastle")
    assert_has_match(matches, "java_keypairgenerator_rsa", "RSA", "Java JCA")


def test_detects_java_quantum_safe_rules() -> None:
    matches = scan_file(
        'MessageDigest.getInstance("SHA-256");\n'
        'Mac.getInstance("HmacSHA256");\n'
        'Cipher.getInstance("AES/GCM/NoPadding");\n'
        'KeyGenerator.getInstance("AES");\n',
        "App.java",
    )

    assert_has_match(matches, "java_message_digest_sha2", "SHA-2", "Java JCA")
    assert_has_match(matches, "java_mac_hmac_sha2", "HMAC", "Java JCA")
    assert_has_match(matches, "java_cipher_aes", "AES", "Java JCE")
    assert_has_match(matches, "java_keygenerator_aes", "AES", "Java JCA")


def test_detects_c_cpp_openssl_rules() -> None:
    matches = scan_file(
        "RSA_generate_key_ex(rsa, 2048, e, NULL);\n"
        "EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa);\n"
        "EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);\n"
        "ECDSA_sign(0, digest, digest_len, sig, &sig_len, ec_key);\n"
        "ECDH_compute_key(secret, secret_len, peer, ec_key, NULL);\n"
        "DH_generate_parameters_ex(dh, 2048, 2, NULL);\n",
        "crypto.cpp",
    )

    assert_has_match(matches, "openssl_rsa_generate_key_ex", "RSA", "OpenSSL")
    assert_has_match(matches, "openssl_evp_pkey_rsa", "RSA", "OpenSSL")
    assert_has_match(matches, "openssl_ec_key_new_by_curve_name", "ECC", "OpenSSL")
    assert_has_match(matches, "openssl_ecdsa_sign", "ECDSA", "OpenSSL")
    assert_has_match(matches, "openssl_ecdh_compute_key", "ECDH", "OpenSSL")
    assert_has_match(matches, "openssl_dh_generate_parameters_ex", "DH", "OpenSSL")


def test_detects_openssl_evp_rules() -> None:
    matches = scan_file(
        "EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);\n"
        "EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);\n"
        "EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);\n"
        "EVP_PKEY_keygen_init(ctx);\n"
        "EVP_PKEY_keygen(ctx, &pkey);\n"
        "EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);\n"
        "EVP_DigestSignInit(ctx, NULL, md, NULL, pkey);\n"
        "EVP_DigestVerifyFinal(ctx, sig, sig_len);\n"
        "EVP_PKEY_derive_init(ctx);\n"
        "EVP_PKEY_encrypt_init(ctx);\n"
        "EVP_PKEY_decrypt(ctx, out, &out_len, in, in_len);\n"
        "EVP_PKEY_set1_RSA(pkey, rsa);\n"
        "PEM_read_bio_RSAPrivateKey(bp, NULL, NULL, NULL);\n"
        "d2i_RSAPrivateKey(NULL, &ptr, len);\n",
        "crypto.cpp",
    )

    assert_has_match(matches, "openssl_evp_pkey_ctx_new_id_rsa", "RSA", "OpenSSL")
    assert_has_match(matches, "openssl_evp_pkey_ctx_new_id_ec", "ECC", "OpenSSL")
    assert_has_match(matches, "openssl_evp_pkey_ctx_new_id_dh", "DH", "OpenSSL")
    assert_has_match(matches, "openssl_evp_pkey_keygen", None, "OpenSSL")
    assert_has_match(matches, "openssl_evp_rsa_keygen_bits", "RSA", "OpenSSL")
    assert_has_match(matches, "openssl_evp_digest_sign", None, "OpenSSL")
    assert_has_match(matches, "openssl_evp_digest_verify", None, "OpenSSL")
    assert_has_match(matches, "openssl_evp_pkey_derive", None, "OpenSSL")
    assert_has_match(matches, "openssl_evp_pkey_encrypt", None, "OpenSSL")
    assert_has_match(matches, "openssl_evp_pkey_decrypt", None, "OpenSSL")
    assert_has_match(matches, "openssl_evp_set_rsa_key", "RSA", "OpenSSL")
    assert_has_match(matches, "openssl_pem_read_rsa_key", "RSA", "OpenSSL")
    assert_has_match(matches, "openssl_der_read_rsa_key", "RSA", "OpenSSL")


def test_detects_openssl_quantum_safe_rules() -> None:
    matches = scan_file(
        "EVP_sha256();\n"
        "HMAC(EVP_sha256(), key, key_len, data, data_len, out, &out_len);\n"
        "EVP_aes_256_gcm();\n",
        "crypto.cpp",
    )

    assert_has_match(matches, "openssl_evp_sha2", "SHA-2", "OpenSSL")
    assert_has_match(matches, "openssl_hmac", "HMAC", "OpenSSL")
    assert_has_match(matches, "openssl_evp_aes", "AES", "OpenSSL")


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
    assert rsa_match.source_kind == "comment"
    assert rsa_match.confidence == "low"
    assert ecc_match.line_number == 2
    assert ecc_match.source_kind == "string"
    assert ecc_match.confidence == "low"


def test_syntax_error_falls_back_to_text_scan() -> None:
    matches = scan("def broken(:\n    # RSA fallback\n")

    assert_has_match(matches, "keyword_rsa", "RSA", None)


def test_unrelated_code_produces_no_matches() -> None:
    matches = scan("def add(left, right):\n    return left + right\n")

    assert matches == []
