from pathlib import Path
from io import BytesIO
from urllib.error import HTTPError

from pqc_audit.config import AppConfig
from pqc_audit.gemini_analyzer import GeminiRestTransport, SemanticAnalyzer, build_prompt
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


class FakeResponse:
    def __init__(self, body: str) -> None:
        self.body = body.encode("utf-8")

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class FakeUrlopen:
    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.calls = 0

    def __call__(self, request, timeout: int) -> object:
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


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


def http_error(status: int, body: str) -> HTTPError:
    return HTTPError(
        "https://example.test",
        status,
        "error",
        {},
        BytesIO(body.encode("utf-8")),
    )


def test_gemini_transport_retries_transient_429() -> None:
    urlopen = FakeUrlopen(
        [
            http_error(
                429,
                '{"error": {"status": "RESOURCE_EXHAUSTED", "message": "Rate limit exceeded"}}',
            ),
            FakeResponse(
                """{
                    "candidates": [
                        {"content": {"parts": [{"text": "{\\"ok\\": true}"}]}}
                    ]
                }"""
            ),
        ]
    )
    sleeps: list[float] = []
    transport = GeminiRestTransport(
        "key",
        "model",
        initial_retry_delay=0.5,
        sleep=sleeps.append,
        urlopen=urlopen,
    )

    result = transport.generate("prompt")

    assert result == '{"ok": true}'
    assert urlopen.calls == 2
    assert sleeps == [0.5]


def test_gemini_transport_does_not_retry_403() -> None:
    urlopen = FakeUrlopen(
        [
            http_error(
                403,
                '{"error": {"status": "PERMISSION_DENIED", "message": "Forbidden"}}',
            )
        ]
    )
    transport = GeminiRestTransport("key", "model", sleep=lambda _: None, urlopen=urlopen)

    try:
        transport.generate("prompt")
    except RuntimeError as exc:
        assert "PERMISSION_DENIED" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")

    assert urlopen.calls == 1


def test_gemini_transport_does_not_retry_depleted_prepayment_429() -> None:
    urlopen = FakeUrlopen(
        [
            http_error(
                429,
                '{"error": {"status": "RESOURCE_EXHAUSTED", "message": "Your prepayment credits are depleted."}}',
            )
        ]
    )
    transport = GeminiRestTransport("key", "model", sleep=lambda _: None, urlopen=urlopen)

    try:
        transport.generate("prompt")
    except RuntimeError as exc:
        assert "prepayment credits are depleted" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")

    assert urlopen.calls == 1
