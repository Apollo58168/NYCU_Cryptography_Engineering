from pathlib import Path

from pqc_audit.config import AppConfig
from pqc_audit.gemini_analyzer import SemanticAnalyzer, build_prompt
from pqc_audit.models import CryptoEvidence


class FakeTransport:
    def __init__(self, response: str | Exception) -> None:
        self.response = response
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def make_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        target_path=tmp_path,
        output_dir=tmp_path / "reports",
        gemini_api_key="fake",
    )


def make_evidence() -> CryptoEvidence:
    return CryptoEvidence(
        "src/key.py:1-3",
        "src/key.py",
        1,
        3,
        "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        "RSA",
        "cryptography",
        "key_generation",
        "static",
        [],
    )


def test_prompt_contains_metadata_and_snippet() -> None:
    prompt = build_prompt(make_evidence())

    assert "src/key.py:1-3" in prompt
    assert "src/key.py" in prompt
    assert "start_line: 1" in prompt
    assert "RSA" in prompt
    assert "rsa.generate_private_key" in prompt


def test_valid_json_response_is_parsed(tmp_path: Path) -> None:
    transport = FakeTransport(
        """{
            "is_real_crypto_usage": true,
            "is_security_sensitive": true,
            "algorithm": "RSA",
            "usage_type": "key_generation",
            "is_test_or_example": false,
            "explanation": "Generates an RSA key.",
            "confidence": 0.91
        }"""
    )
    analyzer = SemanticAnalyzer(make_config(tmp_path), transport)

    result = analyzer.analyze([make_evidence()])[0]

    assert result.algorithm == "RSA"
    assert result.confidence == 0.91
    assert result.is_real_crypto_usage is True


def test_markdown_json_response_is_parsed(tmp_path: Path) -> None:
    transport = FakeTransport(
        """```json
        {
            "is_real_crypto_usage": true,
            "is_security_sensitive": true,
            "algorithm": "RSA",
            "usage_type": "key_generation",
            "is_test_or_example": false,
            "explanation": "Generates an RSA key.",
            "confidence": 0.8
        }
        ```"""
    )

    result = SemanticAnalyzer(make_config(tmp_path), transport).analyze([make_evidence()])[0]

    assert result.confidence == 0.8


def test_malformed_json_returns_fallback(tmp_path: Path) -> None:
    result = SemanticAnalyzer(make_config(tmp_path), FakeTransport("not json")).analyze([make_evidence()])[0]

    assert result.confidence == 0.0
    assert result.algorithm == "RSA"
    assert "Gemini analysis failed" in result.explanation


def test_api_failure_returns_fallback(tmp_path: Path) -> None:
    result = SemanticAnalyzer(make_config(tmp_path), FakeTransport(RuntimeError("down"))).analyze(
        [make_evidence()]
    )[0]

    assert result.confidence == 0.0
    assert result.usage_type == "key_generation"

