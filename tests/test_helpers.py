import os
import json
import types
import pytest

from src.tools import helpers


def test_env_str_and_env_float(monkeypatch):
    monkeypatch.setenv("TEST_STR", "  value  ")
    assert helpers.env_str("TEST_STR") == "value"

    monkeypatch.setenv("TEST_FLOAT", "3.14")
    assert helpers.env_float("TEST_FLOAT", 0.0) == 3.14

    # Invalid float falls back to default
    monkeypatch.setenv("TEST_FLOAT", "not-a-number")
    assert helpers.env_float("TEST_FLOAT", 2.5) == 2.5


@pytest.mark.parametrize(
    "value,expected",
    [
        ("a" * 64, "sha256"),
        ("b" * 32, "md5"),
        ("192.168.1.10", "ip"),
        ("http://example.com/path", "url"),
        ("sub.domain.co", "domain"),
        ("???", "unknown"),
    ],
)
def test_detect_ioc_type(value, expected):
    assert helpers.detect_ioc_type(value) == expected


def test_safe_json_prefers_resp_json():
    class Resp:
        def json(self):
            return {"a": 1}

    out = helpers.safe_json(Resp())
    assert out == {"a": 1}


def test_safe_json_fallback_to_text_json():
    payload = {"hello": "world"}
    text = json.dumps(payload)

    class Resp:
        def json(self):
            raise ValueError("boom")

    r = Resp()
    r.text = text
    out = helpers.safe_json(r)
    assert out == payload


def test_safe_json_empty_on_invalid():
    class Resp:
        def json(self):
            raise ValueError("boom")

        text = "not-json"

    out = helpers.safe_json(Resp())
    assert out == {}


def test_set_get_current_file_roundtrip():
    with pytest.raises(RuntimeError):
        helpers.get_current_file()

    helpers.set_current_file("/tmp/file.bin")
    assert helpers.get_current_file().endswith("/tmp/file.bin")
