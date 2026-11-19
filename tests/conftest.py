from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml


def _build_fake_tokens() -> dict[str, str]:
    """Construct synthetic secret tokens dynamically to avoid literal key patterns."""
    return {
        "anthropic": "sk-ant-" + "a" * 32,
        "openai": "sk-" + "b" * 32,
        "github": "ghp_" + "c" * 36,
        "aws": "AKIA" + "B" * 16,
        "jwt": (
            "eyJ"
            + "hbGciOiJIUzI1NiJ9."
            + "eyJ"
            + "zdWIiOiIxMjM0NTY3ODkwIn0."
            + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ),
        "email": "alice.dev" + "@" + "example.com",
    }


@pytest.fixture
def fake_tokens() -> dict[str, str]:
    """Return dynamically constructed synthetic tokens and PII for tests."""
    return _build_fake_tokens()


@pytest.fixture
def sample_cassette_dict(fake_tokens: dict[str, str]) -> dict[str, Any]:
    """Return a valid VCR v1 cassette dict containing secrets, cookies, and PII."""
    req_payload = {
        "model": "claude-sonnet",
        "credentials": {
            "api_key": fake_tokens["anthropic"],
            "client_secret": "super-secret-value",
        },
        "user": {
            "email": fake_tokens["email"],
            "note": f"backup token {fake_tokens['aws']}",
        },
    }
    req_body = json.dumps(req_payload)
    resp_payload = {
        "status": "ok",
        "access_token": fake_tokens["jwt"],
        "repo_token": fake_tokens["github"],
        "contact": fake_tokens["email"],
    }
    resp_body = json.dumps(resp_payload)

    cassette: dict[str, Any] = {
        "version": 1,
        "interactions": [
            {
                "request": {
                    "method": "POST",
                    "uri": (
                        "https://api.example.com/v1/messages"
                        f"?api_key={fake_tokens['openai']}&token=rawtok123&page=1"
                    ),
                    "body": req_body,
                    "headers": {
                        "Authorization": [f"Bearer {fake_tokens['anthropic']}"],
                        "Cookie": ["session=sec123; theme=dark"],
                        "X-Api-Key": [fake_tokens["aws"]],
                        "Content-Type": ["application/json"],
                        "Content-Length": [str(len(req_body.encode("utf-8")))],
                    },
                },
                "response": {
                    "status": {"code": 200, "message": "OK"},
                    "headers": {
                        "Set-Cookie": ["auth_token=tok999; Path=/; HttpOnly"],
                        "Content-Type": ["application/json"],
                        "Content-Length": [str(len(resp_body.encode("utf-8")))],
                    },
                    "body": {"string": resp_body},
                },
            }
        ],
    }
    return copy.deepcopy(cassette)


@pytest.fixture
def clean_cassette_dict() -> dict[str, Any]:
    """Return an already clean VCR v1 cassette dict with no secrets or PII."""
    body_text = json.dumps({"ok": True, "items": [1, 2, 3]})
    return {
        "version": 1,
        "interactions": [
            {
                "request": {
                    "method": "GET",
                    "uri": "https://api.example.com/v1/items?page=1",
                    "body": None,
                    "headers": {
                        "Accept": ["application/json"],
                        "User-Agent": ["pytest-client/1.0"],
                    },
                },
                "response": {
                    "status": {"code": 200, "message": "OK"},
                    "headers": {
                        "Content-Type": ["application/json"],
                        "Content-Length": [str(len(body_text.encode("utf-8")))],
                    },
                    "body": {"string": body_text},
                },
            }
        ],
    }


@pytest.fixture
def yaml_cassette_path(
    tmp_path: Path, sample_cassette_dict: dict[str, Any]
) -> Path:
    """Write a dirty VCR v1 YAML cassette to tmp_path and return its path."""
    cassettes_dir = tmp_path / "cassettes"
    cassettes_dir.mkdir(parents=True, exist_ok=True)
    path = cassettes_dir / "dirty_cassette.yaml"
    path.write_text(
        yaml.safe_dump(sample_cassette_dict, sort_keys=False),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def json_cassette_path(
    tmp_path: Path, sample_cassette_dict: dict[str, Any]
) -> Path:
    """Write a dirty VCR v1 JSON cassette to tmp_path and return its path."""
    cassettes_dir = tmp_path / "cassettes"
    cassettes_dir.mkdir(parents=True, exist_ok=True)
    path = cassettes_dir / "dirty_cassette.json"
    path.write_text(
        json.dumps(sample_cassette_dict, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def clean_yaml_cassette_path(
    tmp_path: Path, clean_cassette_dict: dict[str, Any]
) -> Path:
    """Write a clean VCR v1 YAML cassette to tmp_path and return its path."""
    cassettes_dir = tmp_path / "cassettes"
    cassettes_dir.mkdir(parents=True, exist_ok=True)
    path = cassettes_dir / "clean_cassette.yaml"
    path.write_text(
        yaml.safe_dump(clean_cassette_dict, sort_keys=False),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def non_cassette_yaml_path(tmp_path: Path) -> Path:
    """Write a regular non-VCR YAML file to tmp_path and return its path."""
    path = tmp_path / "workflow.yaml"
    path.write_text(
        yaml.safe_dump({"name": "ci", "on": ["push"]}, sort_keys=False),
        encoding="utf-8",
    )
    return path
