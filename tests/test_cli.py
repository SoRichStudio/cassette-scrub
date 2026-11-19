from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest
import yaml

from cassette_scrub.cli import main


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class TestCliCheckAndFix:
    """Tests for --check, --fix, and --exit-zero-on-fix CLI flags."""

    def test_check_dirty_returns_1_without_modifying_and_clean_returns_0(
        self,
        yaml_cassette_path: Path,
        json_cassette_path: Path,
        clean_yaml_cassette_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        yaml_before = yaml_cassette_path.read_text(encoding="utf-8")
        json_before = json_cassette_path.read_text(encoding="utf-8")

        assert main(["--check", str(yaml_cassette_path)]) == 1
        assert yaml_cassette_path.read_text(encoding="utf-8") == yaml_before
        out = capsys.readouterr().out
        assert "dirty_cassette.yaml" in out

        # Default mode without --check or --fix also checks without modifying
        assert main([str(json_cassette_path)]) == 1
        assert json_cassette_path.read_text(encoding="utf-8") == json_before

        assert main(["--check", str(clean_yaml_cassette_path)]) == 0

    def test_fix_updates_yaml_and_json_and_followup_check_passes(
        self,
        yaml_cassette_path: Path,
        json_cassette_path: Path,
        fake_tokens: dict[str, str],
    ) -> None:
        assert main(["--fix", str(yaml_cassette_path)]) == 1
        yaml_after = yaml_cassette_path.read_text(encoding="utf-8")
        for secret in fake_tokens.values():
            assert secret not in yaml_after
        assert "<REDACTED>" in yaml_after
        assert "<REDACTED_EMAIL>" in yaml_after
        assert main(["--check", str(yaml_cassette_path)]) == 0
        assert main(["--fix", str(yaml_cassette_path)]) == 0

        assert main(["--fix", str(json_cassette_path)]) == 1
        json_after = json_cassette_path.read_text(encoding="utf-8")
        for secret in fake_tokens.values():
            assert secret not in json_after
        assert "<REDACTED>" in json_after
        assert "<REDACTED_EMAIL>" in json_after
        assert main(["--check", str(json_cassette_path)]) == 0
        assert main(["--fix", str(json_cassette_path)]) == 0

    def test_fix_with_exit_zero_on_fix_scrubs_and_returns_0(
        self,
        yaml_cassette_path: Path,
        json_cassette_path: Path,
        fake_tokens: dict[str, str],
    ) -> None:
        rc = main(
            [
                "--fix",
                "--exit-zero-on-fix",
                str(yaml_cassette_path),
                str(json_cassette_path),
            ]
        )
        assert rc == 0

        for path in (yaml_cassette_path, json_cassette_path):
            content = path.read_text(encoding="utf-8")
            for secret in fake_tokens.values():
                assert secret not in content
            assert main(["--check", str(path)]) == 0

    def test_no_pii_preserves_emails_while_redacting_tokens_and_headers(
        self,
        tmp_path: Path,
        yaml_cassette_path: Path,
        fake_tokens: dict[str, str],
    ) -> None:
        email_only = tmp_path / "cassettes" / "email_only.yaml"
        _write_yaml(
            email_only,
            {
                "version": 1,
                "interactions": [
                    {
                        "request": {
                            "method": "POST",
                            "uri": "https://api.example.com/v1/users",
                            "body": json.dumps({"email": fake_tokens["email"]}),
                            "headers": {"Content-Type": ["application/json"]},
                        },
                        "response": {
                            "status": {"code": 200, "message": "OK"},
                            "headers": {},
                            "body": {"string": "ok"},
                        },
                    }
                ],
            },
        )
        assert main(["--check", "--no-pii", str(email_only)]) == 0
        assert main(["--check", str(email_only)]) == 1

        assert main(["--fix", "--no-pii", str(yaml_cassette_path)]) == 1
        fixed_data = yaml.safe_load(yaml_cassette_path.read_text(encoding="utf-8"))
        interaction = fixed_data["interactions"][0]

        assert interaction["request"]["headers"]["Authorization"] == [
            "Bearer <REDACTED>"
        ]
        assert interaction["request"]["headers"]["X-Api-Key"] == ["<REDACTED>"]

        req_body = json.loads(interaction["request"]["body"])
        resp_body = json.loads(interaction["response"]["body"]["string"])
        assert req_body["credentials"]["api_key"] == "<REDACTED>"
        assert req_body["user"]["email"] == fake_tokens["email"]
        assert resp_body["contact"] == fake_tokens["email"]

        assert main(["--check", "--no-pii", str(yaml_cassette_path)]) == 0
        assert main(["--check", str(yaml_cassette_path)]) == 1


class TestCliDirectoryTraversalAndConfig:
    """Tests for recursive directory traversal and pyproject.toml configuration."""

    def test_directory_traversal_skips_non_cassettes_and_ignored_dirs(
        self,
        tmp_path: Path,
        sample_cassette_dict: dict[str, Any],
        non_cassette_yaml_path: Path,
        fake_tokens: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        dirty_yaml = tmp_path / "cassettes" / "one.yaml"
        dirty_yml = tmp_path / "cassettes" / "nested" / "two.yml"
        dirty_json = tmp_path / "cassettes" / "nested" / "three.json"
        _write_yaml(dirty_yaml, sample_cassette_dict)
        _write_yaml(dirty_yml, sample_cassette_dict)
        _write_json(dirty_json, sample_cassette_dict)

        non_cassette_json = tmp_path / "package.json"
        non_cassette_json.write_text(
            json.dumps(
                {
                    "name": "app",
                    "author": fake_tokens["email"],
                    "token": fake_tokens["github"],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        # Cassettes inside ignored directories must not be touched
        git_cassette = tmp_path / ".git" / "ignored.yaml"
        venv_cassette = tmp_path / ".venv" / "ignored.json"
        node_cassette = tmp_path / "node_modules" / "ignored.yml"
        _write_yaml(git_cassette, sample_cassette_dict)
        _write_json(venv_cassette, sample_cassette_dict)
        _write_yaml(node_cassette, sample_cassette_dict)

        workflow_before = non_cassette_yaml_path.read_text(encoding="utf-8")
        pkg_before = non_cassette_json.read_text(encoding="utf-8")
        git_before = git_cassette.read_text(encoding="utf-8")
        venv_before = venv_cassette.read_text(encoding="utf-8")
        node_before = node_cassette.read_text(encoding="utf-8")

        monkeypatch.chdir(tmp_path)
        assert main(["--check"]) == 1
        assert main(["--fix"]) == 1
        assert main(["--check"]) == 0

        for path in (dirty_yaml, dirty_yml, dirty_json):
            text = path.read_text(encoding="utf-8")
            for secret in fake_tokens.values():
                assert secret not in text

        assert non_cassette_yaml_path.read_text(encoding="utf-8") == workflow_before
        assert non_cassette_json.read_text(encoding="utf-8") == pkg_before
        assert git_cassette.read_text(encoding="utf-8") == git_before
        assert venv_cassette.read_text(encoding="utf-8") == venv_before
        assert node_cassette.read_text(encoding="utf-8") == node_before

    def test_nearest_pyproject_toml_config_integration(
        self,
        tmp_path: Path,
        fake_tokens: dict[str, str],
    ) -> None:
        root_pyproject = tmp_path / "pyproject.toml"
        root_pyproject.write_text(
            "\n".join(
                [
                    "[tool.cassette-scrub]",
                    'extra_headers = ["X-Root-Secret"]',
                    'extra_query_keys = ["root_tok"]',
                    'extra_body_keys = ["root_pin"]',
                    "scrub_pii = true",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        sub_dir = tmp_path / "subproject"
        sub_dir.mkdir(parents=True, exist_ok=True)
        sub_pyproject = sub_dir / "pyproject.toml"
        sub_pyproject.write_text(
            "\n".join(
                [
                    "[tool.cassette-scrub]",
                    'extra_headers = ["X-Sub-Secret"]',
                    'extra_query_keys = ["sub_tok"]',
                    'extra_body_keys = ["sub_pin"]',
                    "scrub_pii = false",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        sub_cassette = sub_dir / "tests" / "cassettes" / "service.yaml"
        _write_yaml(
            sub_cassette,
            {
                "version": 1,
                "interactions": [
                    {
                        "request": {
                            "method": "POST",
                            "uri": "https://api.example.com/v1/do?sub_tok=s123&page=1",
                            "body": json.dumps(
                                {
                                    "sub_pin": "1111",
                                    "root_pin": "2222",
                                    "email": fake_tokens["email"],
                                }
                            ),
                            "headers": {
                                "X-Sub-Secret": ["sub-secret-val"],
                                "X-Root-Secret": ["root-secret-val"],
                                "Content-Type": ["application/json"],
                            },
                        },
                        "response": {
                            "status": {"code": 200, "message": "OK"},
                            "headers": {},
                            "body": {"string": "ok"},
                        },
                    }
                ],
            },
        )

        root_cassette = tmp_path / "cassettes" / "root_service.yaml"
        _write_yaml(
            root_cassette,
            {
                "version": 1,
                "interactions": [
                    {
                        "request": {
                            "method": "POST",
                            "uri": "https://api.example.com/v1/root?root_tok=r123&page=2",
                            "body": json.dumps(
                                {
                                    "root_pin": "3333",
                                    "email": fake_tokens["email"],
                                }
                            ),
                            "headers": {
                                "X-Root-Secret": ["root-secret-val"],
                                "Content-Type": ["application/json"],
                            },
                        },
                        "response": {
                            "status": {"code": 200, "message": "OK"},
                            "headers": {},
                            "body": {"string": "ok"},
                        },
                    }
                ],
            },
        )

        assert main(["--fix", "--exit-zero-on-fix", str(sub_cassette)]) == 0
        sub_data = yaml.safe_load(sub_cassette.read_text(encoding="utf-8"))
        sub_req = sub_data["interactions"][0]["request"]
        assert sub_req["headers"]["X-Sub-Secret"] == ["<REDACTED>"]
        # Nearest pyproject.toml overrides root; X-Root-Secret and email stay untouched
        assert sub_req["headers"]["X-Root-Secret"] == ["root-secret-val"]
        sub_params = dict(parse_qsl(urlsplit(sub_req["uri"]).query))
        assert sub_params == {"sub_tok": "<REDACTED>", "page": "1"}
        sub_body = json.loads(sub_req["body"])
        assert sub_body == {
            "sub_pin": "<REDACTED>",
            "root_pin": "2222",
            "email": fake_tokens["email"],
        }

        assert main(["--fix", "--exit-zero-on-fix", str(root_cassette)]) == 0
        root_data = yaml.safe_load(root_cassette.read_text(encoding="utf-8"))
        root_req = root_data["interactions"][0]["request"]
        assert root_req["headers"]["X-Root-Secret"] == ["<REDACTED>"]
        root_params = dict(parse_qsl(urlsplit(root_req["uri"]).query))
        assert root_params == {"root_tok": "<REDACTED>", "page": "2"}
        root_body = json.loads(root_req["body"])
        assert root_body == {
            "root_pin": "<REDACTED>",
            "email": "<REDACTED_EMAIL>",
        }
