from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass

from pqc_audit.models import SourceFile, StaticMatch


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    algorithm_hint: str | None
    library_hint: str | None


_TEXT_RULES: tuple[_Rule, ...] = (
    # JavaScript / TypeScript Node.js crypto and WebCrypto APIs.
    _Rule(
        "js_crypto_generate_keypair_rsa",
        re.compile(r"\b(?:crypto\.)?generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]", re.IGNORECASE),
        "RSA",
        "node:crypto",
    ),
    _Rule(
        "js_crypto_generate_keypair_ec",
        re.compile(r"\b(?:crypto\.)?generateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"]", re.IGNORECASE),
        "ECC",
        "node:crypto",
    ),
    _Rule(
        "js_crypto_create_ecdh",
        re.compile(r"\b(?:crypto\.)?createECDH\s*\(", re.IGNORECASE),
        "ECDH",
        "node:crypto",
    ),
    _Rule(
        "js_crypto_diffie_hellman",
        re.compile(r"\b(?:crypto\.)?diffieHellman\s*\(", re.IGNORECASE),
        "DH",
        "node:crypto",
    ),
    _Rule(
        "js_crypto_create_sign_rsa",
        re.compile(r"\b(?:crypto\.)?createSign\s*\(\s*['\"][^'\"]*RSA[^'\"]*['\"]", re.IGNORECASE),
        "RSA",
        "node:crypto",
    ),
    _Rule(
        "js_webcrypto_rsa",
        re.compile(r"\b(?:RSA-PSS|RSASSA-PKCS1-v1_5|RSA-OAEP)\b", re.IGNORECASE),
        "RSA",
        "WebCrypto",
    ),
    _Rule(
        "js_webcrypto_ecdsa",
        re.compile(r"\bECDSA\b", re.IGNORECASE),
        "ECDSA",
        "WebCrypto",
    ),
    _Rule(
        "js_webcrypto_ecdh",
        re.compile(r"\bECDH\b", re.IGNORECASE),
        "ECDH",
        "WebCrypto",
    ),
    _Rule(
        "js_jose_generate_keypair_rsa",
        re.compile(r"\bgenerateKeyPair\s*\(\s*['\"](?:RS|PS)\d{3}['\"]", re.IGNORECASE),
        "RSA",
        "jose",
    ),
    _Rule(
        "js_jose_generate_keypair_ecdsa",
        re.compile(r"\bgenerateKeyPair\s*\(\s*['\"]ES\d{3}['\"]", re.IGNORECASE),
        "ECDSA",
        "jose",
    ),
    _Rule(
        "js_jose_ecdh_algorithm",
        re.compile(r"\bECDH-ES\b", re.IGNORECASE),
        "ECDH",
        "jose",
    ),
    _Rule(
        "js_jose_import_rsa_key",
        re.compile(r"\bimport(?:PKCS8|SPKI|JWK)\s*\([^;\n]*['\"](?:RS|PS)\d{3}['\"]", re.IGNORECASE),
        "RSA",
        "jose",
    ),
    _Rule(
        "js_jose_import_ecdsa_key",
        re.compile(r"\bimport(?:PKCS8|SPKI|JWK)\s*\([^;\n]*['\"]ES\d{3}['\"]", re.IGNORECASE),
        "ECDSA",
        "jose",
    ),
    _Rule(
        "js_jsonwebtoken_rsa_algorithm",
        re.compile(r"\balgorithms?\s*:\s*(?:\[[^\]]*)?['\"](?:RS|PS)\d{3}['\"]", re.IGNORECASE),
        "RSA",
        "jsonwebtoken",
    ),
    _Rule(
        "js_jsonwebtoken_ecdsa_algorithm",
        re.compile(r"\balgorithms?\s*:\s*(?:\[[^\]]*)?['\"]ES\d{3}['\"]", re.IGNORECASE),
        "ECDSA",
        "jsonwebtoken",
    ),
    _Rule(
        "js_node_forge_rsa_generate_keypair",
        re.compile(r"\bforge\.pki\.rsa\.generateKeyPair\s*\(", re.IGNORECASE),
        "RSA",
        "node-forge",
    ),
    _Rule(
        "js_node_forge_rsa_key_from_pem",
        re.compile(r"\bforge\.pki\.(?:publicKeyFromPem|privateKeyFromPem|rsa\.setPublicKey|rsa\.setPrivateKey)\s*\(", re.IGNORECASE),
        "RSA",
        "node-forge",
    ),
    # Java JCA / JCE APIs.
    _Rule(
        "java_keypairgenerator_rsa",
        re.compile(r"\bKeyPairGenerator\.getInstance\s*\(\s*['\"]RSA['\"](?:\s*,[^)]*)?\)"),
        "RSA",
        "Java JCA",
    ),
    _Rule(
        "java_keypairgenerator_ec",
        re.compile(r"\bKeyPairGenerator\.getInstance\s*\(\s*['\"]EC['\"](?:\s*,[^)]*)?\)"),
        "ECC",
        "Java JCA",
    ),
    _Rule(
        "java_keypairgenerator_dh",
        re.compile(r"\bKeyPairGenerator\.getInstance\s*\(\s*['\"]DH['\"](?:\s*,[^)]*)?\)"),
        "DH",
        "Java JCA",
    ),
    _Rule(
        "java_cipher_rsa",
        re.compile(r"\bCipher\.getInstance\s*\(\s*['\"][^'\"]*RSA[^'\"]*['\"]\s*\)"),
        "RSA",
        "Java JCE",
    ),
    _Rule(
        "java_signature_rsa",
        re.compile(r"\bSignature\.getInstance\s*\(\s*['\"][^'\"]*RSA[^'\"]*['\"]\s*\)"),
        "RSA",
        "Java JCA",
    ),
    _Rule(
        "java_signature_ecdsa",
        re.compile(r"\bSignature\.getInstance\s*\(\s*['\"][^'\"]*ECDSA[^'\"]*['\"]\s*\)"),
        "ECDSA",
        "Java JCA",
    ),
    _Rule(
        "java_keyagreement_ecdh",
        re.compile(r"\bKeyAgreement\.getInstance\s*\(\s*['\"]ECDH['\"](?:\s*,[^)]*)?\)"),
        "ECDH",
        "Java JCA",
    ),
    _Rule(
        "java_keyagreement_dh",
        re.compile(r"\bKeyAgreement\.getInstance\s*\(\s*['\"]DH['\"](?:\s*,[^)]*)?\)"),
        "DH",
        "Java JCA",
    ),
    _Rule(
        "java_keystore_getinstance",
        re.compile(r"\bKeyStore\.getInstance\s*\(\s*['\"](?:JKS|PKCS12|PKCS11|BKS)['\"]", re.IGNORECASE),
        None,
        "Java KeyStore",
    ),
    _Rule(
        "java_sslcontext_getinstance",
        re.compile(r"\bSSLContext\.getInstance\s*\(\s*['\"]TLS(?:v1\.[23])?['\"]", re.IGNORECASE),
        None,
        "Java JSSE",
    ),
    _Rule(
        "java_https_tls_config",
        re.compile(r"\b(?:HttpsURLConnection|SSLSocketFactory|SSLParameters)\b"),
        None,
        "Java JSSE",
    ),
    _Rule(
        "java_bouncycastle_provider",
        re.compile(r"\b(?:BouncyCastleProvider|Security\.addProvider\s*\([^)]*BC|setProvider\s*\(\s*['\"]BC['\"]\s*\))"),
        None,
        "BouncyCastle",
    ),
    _Rule(
        "java_bouncycastle_rsa_keypair_generator",
        re.compile(r"\bRSAKeyPairGenerator\b"),
        "RSA",
        "BouncyCastle",
    ),
    _Rule(
        "java_bouncycastle_ec_keypair_generator",
        re.compile(r"\bECKeyPairGenerator\b"),
        "ECC",
        "BouncyCastle",
    ),
    _Rule(
        "java_bouncycastle_ecdsa_signer",
        re.compile(r"\bECDSASigner\b"),
        "ECDSA",
        "BouncyCastle",
    ),
    _Rule(
        "java_bouncycastle_ecdh_agreement",
        re.compile(r"\bECDHBasicAgreement\b"),
        "ECDH",
        "BouncyCastle",
    ),
    _Rule(
        "java_bouncycastle_pem_parser",
        re.compile(r"\b(?:PEMParser|JcaPEMKeyConverter)\b"),
        None,
        "BouncyCastle",
    ),
    # C / C++ OpenSSL APIs.
    _Rule(
        "openssl_rsa_generate_key_ex",
        re.compile(r"\bRSA_generate_key_ex\s*\("),
        "RSA",
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_rsa",
        re.compile(r"\bEVP_PKEY_(?:RSA|RSA_PSS)\b"),
        "RSA",
        "OpenSSL",
    ),
    _Rule(
        "openssl_ec_key_new_by_curve_name",
        re.compile(r"\bEC_KEY_new_by_curve_name\s*\("),
        "ECC",
        "OpenSSL",
    ),
    _Rule(
        "openssl_ecdsa_sign",
        re.compile(r"\bECDSA_sign\s*\("),
        "ECDSA",
        "OpenSSL",
    ),
    _Rule(
        "openssl_ecdh_compute_key",
        re.compile(r"\bECDH_compute_key\s*\("),
        "ECDH",
        "OpenSSL",
    ),
    _Rule(
        "openssl_dh_generate_parameters_ex",
        re.compile(r"\bDH_generate_parameters_ex\s*\("),
        "DH",
        "OpenSSL",
    ),
    _Rule(
        "openssl_dh_compute_key",
        re.compile(r"\bDH_compute_key\s*\("),
        "DH",
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_ctx_new_id_rsa",
        re.compile(r"\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_(?:RSA|RSA_PSS)\b"),
        "RSA",
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_ctx_new_id_ec",
        re.compile(r"\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_EC\b"),
        "ECC",
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_ctx_new_id_dh",
        re.compile(r"\bEVP_PKEY_CTX_new_id\s*\(\s*EVP_PKEY_DH\b"),
        "DH",
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_keygen",
        re.compile(r"\bEVP_PKEY_keygen(?:_init)?\s*\("),
        None,
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_rsa_keygen_bits",
        re.compile(r"\bEVP_PKEY_CTX_set_rsa_keygen_bits\s*\("),
        "RSA",
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_digest_sign",
        re.compile(r"\bEVP_DigestSign(?:Init|Update|Final)?\s*\("),
        None,
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_digest_verify",
        re.compile(r"\bEVP_DigestVerify(?:Init|Update|Final)?\s*\("),
        None,
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_derive",
        re.compile(r"\bEVP_PKEY_derive(?:_init)?\s*\("),
        None,
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_encrypt",
        re.compile(r"\bEVP_PKEY_encrypt(?:_init)?\s*\("),
        None,
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_pkey_decrypt",
        re.compile(r"\bEVP_PKEY_decrypt(?:_init)?\s*\("),
        None,
        "OpenSSL",
    ),
    _Rule(
        "openssl_evp_set_rsa_key",
        re.compile(r"\bEVP_PKEY_(?:assign_RSA|set1_RSA)\s*\("),
        "RSA",
        "OpenSSL",
    ),
    _Rule(
        "openssl_pem_read_rsa_key",
        re.compile(r"\bPEM_read(?:_bio)?_RSA(?:PrivateKey|PUBKEY|PublicKey)\s*\("),
        "RSA",
        "OpenSSL",
    ),
    _Rule(
        "openssl_der_read_rsa_key",
        re.compile(r"\bd2i_RSA(?:PrivateKey|PUBKEY|PublicKey)\s*\("),
        "RSA",
        "OpenSSL",
    ),
    _Rule(
        "pycryptodome_crypto_rsa",
        re.compile(r"\bCrypto\.PublicKey\.RSA\b"),
        "RSA",
        "PyCryptodome",
    ),
    _Rule(
        "pycryptodome_cryptodome_rsa",
        re.compile(r"\bCryptodome\.PublicKey\.RSA\b"),
        "RSA",
        "PyCryptodome",
    ),
    _Rule("keyword_diffie_hellman", re.compile(r"\bDiffie-Hellman\b"), "Diffie-Hellman", None),
    _Rule("keyword_ecdsa", re.compile(r"\bECDSA\b"), "ECDSA", None),
    _Rule("keyword_ecdh", re.compile(r"\bECDH\b"), "ECDH", None),
    _Rule("keyword_rsa", re.compile(r"\bRSA\b"), "RSA", None),
    _Rule("keyword_ecc", re.compile(r"\bECC\b"), "ECC", None),
    _Rule("keyword_dh", re.compile(r"\bDH\b"), "DH", None),
)

_CRYPTOGRAPHY_IMPORTS = {
    "rsa": ("cryptography_import_rsa", "RSA"),
    "ec": ("cryptography_import_ec", "ECC"),
    "dh": ("cryptography_import_dh", "Diffie-Hellman"),
}

_CALL_RULES = {
    ("rsa", "generate_private_key"): ("cryptography_rsa_generate_private_key", "RSA", "cryptography"),
    ("ec", "generate_private_key"): ("cryptography_ec_generate_private_key", "ECC", "cryptography"),
    ("dh", "generate_parameters"): ("cryptography_dh_generate_parameters", "Diffie-Hellman", "cryptography"),
    ("ssl", "SSLContext"): ("ssl_context", "TLS", "ssl"),
    ("ssl", "create_default_context"): ("ssl_create_default_context", "TLS", "ssl"),
}


class StaticScanner:
    def scan(self, source_files: Iterable[SourceFile]) -> list[StaticMatch]:
        matches: list[StaticMatch] = []

        for source_file in source_files:
            file_matches: list[StaticMatch] = []
            if source_file.relative_path.endswith(".py"):
                try:
                    tree = ast.parse(source_file.content, filename=source_file.relative_path)
                except SyntaxError:
                    tree = None

                if tree is not None:
                    file_matches.extend(self._scan_ast(source_file, tree))

            file_matches.extend(self._scan_text(source_file))
            matches.extend(self._dedupe(file_matches))

        return matches

    def _scan_ast(self, source_file: SourceFile, tree: ast.AST) -> list[StaticMatch]:
        matches: list[StaticMatch] = []
        lines = source_file.content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                matches.extend(self._match_import_from(source_file, lines, node))
            elif isinstance(node, ast.Import):
                matches.extend(self._match_import(source_file, lines, node))
            elif isinstance(node, ast.Call):
                match = self._match_call(source_file, lines, node)
                if match is not None:
                    matches.append(match)

        return matches

    def _match_import_from(
        self,
        source_file: SourceFile,
        lines: list[str],
        node: ast.ImportFrom,
    ) -> list[StaticMatch]:
        matches: list[StaticMatch] = []

        if node.module == "cryptography.hazmat.primitives.asymmetric":
            for alias in node.names:
                rule = _CRYPTOGRAPHY_IMPORTS.get(alias.name)
                if rule is None:
                    continue
                rule_id, algorithm_hint = rule
                matches.append(
                    self._build_match(
                        source_file,
                        node.lineno,
                        rule_id,
                        alias.name,
                        algorithm_hint,
                        "cryptography",
                        lines,
                    )
                )

        if node.module in {"Crypto.PublicKey", "Cryptodome.PublicKey"}:
            for alias in node.names:
                if alias.name == "RSA":
                    matches.append(
                        self._build_match(
                            source_file,
                            node.lineno,
                            "pycryptodome_import_rsa",
                            alias.name,
                            "RSA",
                            "PyCryptodome",
                            lines,
                        )
                    )

        return matches

    def _match_import(
        self,
        source_file: SourceFile,
        lines: list[str],
        node: ast.Import,
    ) -> list[StaticMatch]:
        matches: list[StaticMatch] = []

        for alias in node.names:
            if alias.name in {"Crypto.PublicKey.RSA", "Cryptodome.PublicKey.RSA"}:
                matches.append(
                    self._build_match(
                        source_file,
                        node.lineno,
                        "pycryptodome_import_rsa",
                        alias.name,
                        "RSA",
                        "PyCryptodome",
                        lines,
                    )
                )

        return matches

    def _match_call(
        self,
        source_file: SourceFile,
        lines: list[str],
        node: ast.Call,
    ) -> StaticMatch | None:
        call_name = self._attribute_parts(node.func)
        if len(call_name) < 2:
            return None

        rule = _CALL_RULES.get((call_name[-2], call_name[-1]))
        if rule is None:
            return None

        rule_id, algorithm_hint, library_hint = rule
        return self._build_match(
            source_file,
            node.lineno,
            rule_id,
            ".".join(call_name[-2:]),
            algorithm_hint,
            library_hint,
            lines,
        )

    def _scan_text(self, source_file: SourceFile) -> list[StaticMatch]:
        matches: list[StaticMatch] = []
        lines = source_file.content.splitlines()

        for line_number, line in enumerate(lines, start=1):
            for rule in _TEXT_RULES:
                for match in rule.pattern.finditer(line):
                    matches.append(
                        self._build_match(
                            source_file,
                            line_number,
                            rule.rule_id,
                            match.group(0),
                            rule.algorithm_hint,
                            rule.library_hint,
                            lines,
                        )
                    )

        return matches

    def _attribute_parts(self, node: ast.AST) -> tuple[str, ...]:
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            return (*self._attribute_parts(node.value), node.attr)
        return ()

    def _build_match(
        self,
        source_file: SourceFile,
        line_number: int,
        rule_id: str,
        matched_text: str,
        algorithm_hint: str | None,
        library_hint: str | None,
        lines: list[str],
    ) -> StaticMatch:
        line_text = lines[line_number - 1].strip() if 0 < line_number <= len(lines) else ""
        return StaticMatch(
            source_file.relative_path,
            line_number,
            rule_id,
            matched_text,
            algorithm_hint,
            library_hint,
            "high",
            line_text,
        )

    def _dedupe(self, matches: list[StaticMatch]) -> list[StaticMatch]:
        seen: set[tuple[str, int, str, str]] = set()
        deduped: list[StaticMatch] = []

        for match in matches:
            key = (match.file_path, match.line_number, match.rule_id, match.matched_text)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(match)

        return deduped
