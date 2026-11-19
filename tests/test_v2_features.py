from __future__ import annotations

import json
import os
import subprocess
import tkinter as tk
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest
import yaml

from cassette_scrub import __version__
from cassette_scrub.config import load_config
from cassette_scrub.types import Finding, InstallResult, ScrubConfig


def _v2_tokens() -> dict[str, str]:
    """Build v0.2.0 synthetic tokens dynamically without literal key patterns."""
    return {
        "stripe_live": "sk_" + "live_" + "a" * 24,
        "stripe_restricted": "rk_" + "test_" + "b" * 24,
        "slack_bot": "xox" + "b-" + "1234567890-abcdef123456",
        "slack_user": "xox" + "p-" + "1234567890-abcdef123456",
        "slack_app": "xox" + "a-" + "1234567890-abcdef123456",
        "slack_webhook": (
            "https://hooks."
            + "slack.com/"
            + "services/"
            + "T12345ABC/"
            + "B67890DEF/"
            + "xYz1234567890abcd"
        ),
        "gcp_key": "AI" + "za" + "B" * 35,
        "gcp_oauth": "ya" + "29." + "a0AfH6SM" + "B" * 20,
        "sendgrid": "SG" + "." + "c" * 22 + "." + "d" * 22,
        "twilio": "SK" + "0123456789abcdef" + "0123456789abcdef",
        "discord_webhook": (
            "https://discord"
            + ".com/api/"
            + "webhooks/"
            + "123456789012345678/"
            + "abcDEF_123456-xyz"
        ),
        "discord_canary_webhook": (
            "https://canary.discord"
            + "app.com/api/"
            + "webhooks/"
            + "987654321098765432/"
            + "tok_987654321-xyz"
        ),
        "pem_rsa": (
            "-----BEGIN "
            + "RSA "
            + "PRIVATE KEY-----\n"
            + "MIIEowIBAAKCAQEAtestpayload\n"
            + "-----END "
            + "RSA "
            + "PRIVATE KEY-----"
        ),
        "pem_ec": (
            "-----BEGIN "
            + "EC "
            + "PRIVATE KEY-----\n"
            + "MHcCAQEEItestpayload\n"
            + "-----END "
            + "EC "
            + "PRIVATE KEY-----"
        ),
        "pem_openssh": (
            "-----BEGIN "
            + "OPENSSH "
            + "PRIVATE KEY-----\n"
            + "b3BlbnNzaC1rZXktdjEAAAA=\n"
            + "-----END "
            + "OPENSSH "
            + "PRIVATE KEY-----"
        ),
        "pem_pkcs8": (
            "-----BEGIN "
            + "PRIVATE KEY-----\n"
            + "MIIEvQIBADANBgkqhkiG\n"
            + "-----END "
            + "PRIVATE KEY-----"
        ),
        "email": "v2.tester" + "@" + "example.com",
    }


def _make_cassette(
    *,
    method: str = "POST",
    uri: str = "https://api.example.com/v1/test",
    req_headers: dict[str, list[str]] | None = None,
    req_body: Any = None,
    resp_headers: dict[str, list[str]] | None = None,
    resp_body: Any = None,
) -> dict[str, Any]:
    return {
        "version": 1,
        "interactions": [
            {
                "request": {
                    "method": method,
                    "uri": uri,
                    "body": req_body,
                    "headers": req_headers if req_headers is not None else {},
                },
                "response": {
                    "status": {"code": 200, "message": "OK"},
                    "headers": resp_headers if resp_headers is not None else {},
                    "body": resp_body if resp_body is not None else {"string": ""},
                },
            }
        ],
    }


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class TestExpandedSecretDetectors:
    """Tests for v0.2.0 expanded secret detectors in scrubber.py."""

    @pytest.mark.parametrize(
        "token_key",
        [
            "stripe_live",
            "stripe_restricted",
            "slack_bot",
            "slack_user",
            "slack_app",
            "slack_webhook",
            "gcp_key",
            "gcp_oauth",
            "sendgrid",
            "twilio",
            "discord_webhook",
            "discord_canary_webhook",
            "pem_rsa",
            "pem_ec",
            "pem_openssh",
            "pem_pkcs8",
        ],
    )
    def test_expanded_detectors_in_body_headers_and_query(
        self, token_key: str
    ) -> None:
        from cassette_scrub.scrubber import scrub_cassette

        tokens = _v2_tokens()
        secret = tokens[token_key]
        body_payload = json.dumps({"note": f"prefix {secret} suffix"})

        cassette = _make_cassette(
            uri=f"https://api.example.com/v1/hook?dest={secret}&page=1",
            req_headers={
                "X-Trace-Note": [f"val={secret}"],
                "Content-Type": ["application/json"],
                "Content-Length": [str(len(body_payload.encode("utf-8")))],
            },
            req_body=body_payload,
            resp_body={"string": f"raw={secret}"},
        )

        result = scrub_cassette(cassette, "v2_secrets.yaml", ScrubConfig())
        assert result.modified is True
        assert result.updated_data is not None
        assert len(result.findings) >= 4
        assert all(isinstance(f, Finding) for f in result.findings)

        interaction = result.updated_data["interactions"][0]
        assert secret not in interaction["request"]["uri"]
        assert interaction["request"]["headers"]["X-Trace-Note"] == ["val=<REDACTED>"]
        parsed_req = json.loads(interaction["request"]["body"])
        assert parsed_req["note"] == "prefix <REDACTED> suffix"
        assert interaction["response"]["body"]["string"] == "raw=<REDACTED>"
        assert interaction["request"]["headers"]["Content-Length"] == [
            str(len(interaction["request"]["body"].encode("utf-8")))
        ]

        # Idempotent on repeat run
        repeat = scrub_cassette(result.updated_data, "v2_secrets.yaml", ScrubConfig())
        assert repeat.modified is False
        assert repeat.findings == []
        assert repeat.updated_data is None

    @pytest.mark.parametrize(
        "webhook_key",
        ["slack_webhook", "discord_webhook", "discord_canary_webhook"],
    )
    def test_webhook_urls_redacted_when_used_directly_as_request_uri(
        self, webhook_key: str
    ) -> None:
        from cassette_scrub.scrubber import scrub_cassette

        tokens = _v2_tokens()
        webhook_url = tokens[webhook_key]
        cassette = _make_cassette(uri=f"{webhook_url}?wait=true")

        result = scrub_cassette(cassette, "webhook_uri.yaml", ScrubConfig())
        assert result.modified is True
        assert result.updated_data is not None
        new_uri = result.updated_data["interactions"][0]["request"]["uri"]
        assert webhook_url not in new_uri
        assert new_uri == "<REDACTED>?wait=true"

        repeat = scrub_cassette(result.updated_data, "webhook_uri.yaml", ScrubConfig())
        assert repeat.modified is False
        assert repeat.findings == []


class TestCustomPatternsAndAllowlist:
    """Tests for custom_patterns and allowlist in ScrubConfig and load_config."""

    def test_load_config_reads_custom_patterns_and_allowlist(
        self, tmp_path: Path
    ) -> None:
        tokens = _v2_tokens()
        allowed_case = "Allow_Exact_Case_Token"
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "\n".join(
                [
                    "[tool.cassette-scrub]",
                    'extra_headers = ["X-Custom-Auth"]',
                    'custom_patterns = ["INTERNAL-[0-9]{6}", "  corp_[a-z]+_tok  "]',
                    f'allowlist = ["{allowed_case}", "{tokens["email"]}"]',
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        cfg = load_config(start_dir=tmp_path)
        assert cfg.extra_headers == {"x-custom-auth"}
        assert cfg.custom_patterns == ("INTERNAL-[0-9]{6}", "corp_[a-z]+_tok")
        assert cfg.allowlist == {allowed_case, tokens["email"]}
        assert "allow_exact_case_token" not in cfg.allowlist

    def test_custom_patterns_across_surfaces_and_invalid_regex_ignored(
        self,
    ) -> None:
        from cassette_scrub.scrubber import scrub_cassette

        cassette = _make_cassette(
            uri="https://api.example.com/items/INTERNAL-123456?ref=INTERNAL-654321&ok=1",
            req_headers={
                "Host": ["api.example.com"],
                "Content-Type": ["application/json"],
                "X-Internal-Id": ["id=INTERNAL-111222"],
            },
            req_body=json.dumps({"tag": "INTERNAL-333444", "safe": "plain"}),
            resp_body={"string": "plain response INTERNAL-555666"},
        )
        cfg = ScrubConfig(
            custom_patterns=("[unclosed-regex", r"INTERNAL-[0-9]{6}", "   ")
        )

        result = scrub_cassette(cassette, "custom.yaml", cfg)
        assert result.modified is True
        assert result.updated_data is not None

        interaction = result.updated_data["interactions"][0]
        assert "/items/<REDACTED>" in interaction["request"]["uri"]
        params = dict(
            parse_qsl(
                urlsplit(interaction["request"]["uri"]).query,
                keep_blank_values=True,
            )
        )
        assert params == {"ref": "<REDACTED>", "ok": "1"}
        assert interaction["request"]["headers"]["Host"] == ["api.example.com"]
        assert interaction["request"]["headers"]["X-Internal-Id"] == ["id=<REDACTED>"]
        assert json.loads(interaction["request"]["body"]) == {
            "tag": "<REDACTED>",
            "safe": "plain",
        }
        assert interaction["response"]["body"]["string"] == "plain response <REDACTED>"

        # Idempotent
        repeat = scrub_cassette(result.updated_data, "custom.yaml", cfg)
        assert repeat.modified is False
        assert repeat.findings == []

    def test_allowlist_preserves_exact_matches_while_redacting_others(self) -> None:
        from cassette_scrub.scrubber import scrub_cassette

        tokens = _v2_tokens()
        allowed_stripe = tokens["stripe_live"]
        blocked_sendgrid = tokens["sendgrid"]
        allowed_email = "public.support" + "@" + "example.com"
        blocked_email = tokens["email"]
        allowed_header_val = "PUBLIC_DEMO_KEY"

        cassette = _make_cassette(
            uri=(
                "https://user:"
                f"{allowed_header_val}@api.example.com/v1/pay"
                f"?api_key={allowed_header_val}&token=secret_tok"
            ),
            req_headers={
                "Authorization": [f"Bearer {allowed_header_val}"],
                "X-Api-Key": [allowed_header_val],
                "X-Auth-Token": ["blocked_auth_token"],
                "Content-Type": ["application/json"],
            },
            req_body=json.dumps(
                {
                    "api_key": allowed_header_val,
                    "secret": "real_secret_val",
                    "stripe": allowed_stripe,
                    "sendgrid": blocked_sendgrid,
                    "support": allowed_email,
                    "user_email": blocked_email,
                }
            ),
            resp_body={
                "string": f"public={allowed_stripe} email={allowed_email} blocked={blocked_sendgrid}"
            },
        )
        cfg = ScrubConfig(
            allowlist={allowed_header_val, allowed_stripe, allowed_email},
        )

        result = scrub_cassette(cassette, "allowlist.yaml", cfg)
        assert result.modified is True
        assert result.updated_data is not None

        interaction = result.updated_data["interactions"][0]
        assert allowed_header_val in interaction["request"]["uri"]
        params = dict(parse_qsl(urlsplit(interaction["request"]["uri"]).query))
        assert params == {"api_key": allowed_header_val, "token": "<REDACTED>"}
        assert interaction["request"]["headers"]["Authorization"] == [
            f"Bearer {allowed_header_val}"
        ]
        assert interaction["request"]["headers"]["X-Api-Key"] == [allowed_header_val]
        assert interaction["request"]["headers"]["X-Auth-Token"] == ["<REDACTED>"]

        req_json = json.loads(interaction["request"]["body"])
        assert req_json["api_key"] == allowed_header_val
        assert req_json["secret"] == "<REDACTED>"
        assert req_json["stripe"] == allowed_stripe
        assert req_json["sendgrid"] == "<REDACTED>"
        assert req_json["support"] == allowed_email
        assert req_json["user_email"] == "<REDACTED_EMAIL>"

        assert (
            interaction["response"]["body"]["string"]
            == f"public={allowed_stripe} email={allowed_email} blocked=<REDACTED>"
        )

        # Entirely allowlisted cassette produces zero findings and modified=False
        only_allowed = _make_cassette(
            req_headers={"X-Api-Key": [allowed_header_val]},
            req_body=f"stripe={allowed_stripe} email={allowed_email}",
        )
        clean_res = scrub_cassette(only_allowed, "only_allowed.yaml", cfg)
        assert clean_res.modified is False
        assert clean_res.findings == []
        assert clean_res.updated_data is None


class TestFormatCassetteDiff:
    """Tests for format_cassette_diff unified diff generation."""

    def test_unified_diff_yaml_json_bytes_and_identical(
        self,
        sample_cassette_dict: dict[str, Any],
        clean_cassette_dict: dict[str, Any],
    ) -> None:
        from cassette_scrub.scrubber import format_cassette_diff, scrub_cassette

        scrubbed = scrub_cassette(
            sample_cassette_dict, "cassettes/demo.yaml", ScrubConfig()
        )
        assert scrubbed.modified is True
        assert scrubbed.updated_data is not None

        yaml_diff = format_cassette_diff(
            sample_cassette_dict,
            scrubbed.updated_data,
            "yaml",
            file_path="cassettes/demo.yaml",
        )
        assert "--- a/cassettes/demo.yaml" in yaml_diff
        assert "+++ b/cassettes/demo.yaml" in yaml_diff
        assert "@@" in yaml_diff
        assert "<REDACTED>" in yaml_diff

        json_diff = format_cassette_diff(
            sample_cassette_dict,
            scrubbed.updated_data,
            "json",
            file_path="cassettes/demo.json",
        )
        assert "--- a/cassettes/demo.json" in json_diff
        assert "+++ b/cassettes/demo.json" in json_diff
        assert "@@" in json_diff
        assert "<REDACTED>" in json_diff

        # Bytes bodies inside cassettes serialize safely for JSON and YAML diffs
        tokens = _v2_tokens()
        bytes_cassette = _make_cassette(
            resp_body={"string": json.dumps({"stripe": tokens["stripe_live"]}).encode("utf-8")}
        )
        bytes_scrubbed = scrub_cassette(bytes_cassette, "bytes.json", ScrubConfig())
        assert bytes_scrubbed.updated_data is not None
        bytes_json_diff = format_cassette_diff(
            bytes_cassette, bytes_scrubbed.updated_data, "json", file_path="bytes.json"
        )
        assert "<REDACTED>" in bytes_json_diff

        empty_diff = format_cassette_diff(
            clean_cassette_dict,
            clean_cassette_dict,
            "yaml",
            file_path="cassettes/clean.yaml",
        )
        assert empty_diff == ""

        with pytest.raises(ValueError):
            format_cassette_diff(clean_cassette_dict, clean_cassette_dict, "toml")


class TestCliV2Modes:
    """Tests for v0.2.0 CLI flags (--json, --diff, --install-*, --build-exe)."""

    def test_json_mode_check_and_fix_schema_and_exit_codes(
        self,
        yaml_cassette_path: Path,
        clean_yaml_cassette_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cassette_scrub.cli import main

        rc_clean = main(["--check", "--json", str(clean_yaml_cassette_path)])
        assert rc_clean == 0
        clean_payload = json.loads(capsys.readouterr().out)
        assert clean_payload["version"] == __version__
        assert clean_payload["modified"] is False
        assert clean_payload["files_scanned"] == 1
        assert clean_payload["files_with_findings"] == 0
        assert clean_payload["findings"] == []

        rc_dirty = main(["--check", "--json", str(yaml_cassette_path)])
        assert rc_dirty == 1
        dirty_payload = json.loads(capsys.readouterr().out)
        assert dirty_payload["version"] == __version__
        assert dirty_payload["modified"] is False
        assert dirty_payload["files_scanned"] == 1
        assert dirty_payload["files_with_findings"] == 1
        assert len(dirty_payload["findings"]) >= 1
        first = dirty_payload["findings"][0]
        assert set(first.keys()) == {
            "file_path",
            "interaction_index",
            "location",
            "preview",
        }

        rc_fix_nonzero = main(["--fix", "--json", str(yaml_cassette_path)])
        assert rc_fix_nonzero == 1
        fix_payload = json.loads(capsys.readouterr().out)
        assert fix_payload["modified"] is True
        assert fix_payload["files_with_findings"] == 1

        # Follow-up --fix --exit-zero-on-fix on now-clean file returns 0 with modified=False
        rc_fix_clean = main(
            ["--fix", "--exit-zero-on-fix", "--json", str(yaml_cassette_path)]
        )
        assert rc_fix_clean == 0
        clean_after = json.loads(capsys.readouterr().out)
        assert clean_after["modified"] is False
        assert clean_after["findings"] == []

    def test_diff_mode_prints_unified_diff_without_modifying(
        self,
        yaml_cassette_path: Path,
        json_cassette_path: Path,
        clean_yaml_cassette_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cassette_scrub.cli import main

        yaml_before = yaml_cassette_path.read_text(encoding="utf-8")
        json_before = json_cassette_path.read_text(encoding="utf-8")

        rc_dirty = main(
            ["--diff", str(yaml_cassette_path), str(json_cassette_path)]
        )
        assert rc_dirty == 1
        diff_out = capsys.readouterr().out
        assert "---" in diff_out
        assert "+++" in diff_out
        assert "@@" in diff_out
        assert "<REDACTED>" in diff_out
        assert yaml_cassette_path.read_text(encoding="utf-8") == yaml_before
        assert json_cassette_path.read_text(encoding="utf-8") == json_before

        rc_clean = main(["--diff", str(clean_yaml_cassette_path)])
        assert rc_clean == 0
        assert capsys.readouterr().out == ""

    def test_cli_install_skill_mcp_and_hook(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cassette_scrub.cli import main

        fake_home = tmp_path / "home"
        fake_home.mkdir(parents=True, exist_ok=True)
        proj = tmp_path / "proj"
        proj.mkdir(parents=True, exist_ok=True)

        monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
        monkeypatch.chdir(proj)

        rc_skill = main(["--install-skill", "antigravity", "project"])
        assert rc_skill == 0
        capsys.readouterr()
        assert (
            fake_home
            / ".gemini"
            / "config"
            / "skills"
            / "cassette-scrub"
            / "SKILL.md"
        ).is_file()
        assert (
            proj / ".agent" / "skills" / "cassette-scrub" / "SKILL.md"
        ).is_file()

        rc_mcp = main(["--install-mcp", "antigravity", "project", "--json"])
        assert rc_mcp == 0
        mcp_payload = json.loads(capsys.readouterr().out)
        assert mcp_payload["success"] is True
        assert mcp_payload["version"] == __version__
        ag_mcp = json.loads(
            (fake_home / ".gemini" / "config" / "mcp_config.json").read_text(
                encoding="utf-8"
            )
        )
        assert "cassette-scrub" in ag_mcp["mcpServers"]
        proj_mcp = json.loads(
            (proj / ".mcp.json").read_text(encoding="utf-8")
        )
        assert "cassette-scrub" in proj_mcp["mcpServers"]

        rc_hook = main(["--install-hook", str(proj)])
        assert rc_hook == 0
        capsys.readouterr()
        precommit_cfg = proj / ".pre-commit-config.yaml"
        assert precommit_cfg.is_file()
        assert "cassette-scrub" in precommit_cfg.read_text(encoding="utf-8")

    def test_cli_build_exe(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from cassette_scrub.cli import main

        proj = tmp_path / "build_proj"
        proj.mkdir(parents=True, exist_ok=True)
        monkeypatch.chdir(proj)

        rc_exe = main(["--build-exe"])
        assert rc_exe == 0
        exe_out = capsys.readouterr().out
        assert "cassette-scrub.exe" in exe_out
        assert (proj / "dist" / "cassette-scrub.exe").is_file()
        assert (proj / "dist" / "cassette-scrub-gui.exe").is_file()


class TestMcpServer:
    """Tests for JSON-RPC 2.0 MCP server request handling."""

    def test_initialize_ping_notification_tools_list_and_errors(self) -> None:
        from cassette_scrub.mcp_server import handle_mcp_request

        init_resp = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            }
        )
        assert init_resp is not None
        assert init_resp["id"] == 1
        assert init_resp["result"]["protocolVersion"] == "2024-11-05"
        assert init_resp["result"]["capabilities"] == {"tools": {}}
        assert init_resp["result"]["serverInfo"]["name"] == "cassette-scrub"
        assert init_resp["result"]["serverInfo"]["version"] == __version__

        ping_resp = handle_mcp_request(
            {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        )
        assert ping_resp == {"jsonrpc": "2.0", "id": 2, "result": {}}

        notif_resp = handle_mcp_request(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}
        )
        assert notif_resp is None

        list_resp = handle_mcp_request(
            {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}
        )
        assert list_resp is not None
        tools = list_resp["result"]["tools"]
        tool_names = {tool["name"] for tool in tools}
        assert tool_names == {
            "cassette_scrub_scan",
            "cassette_scrub_fix",
            "cassette_scrub_diff",
            "cassette_scrub_install",
        }

        unknown_method = handle_mcp_request(
            {"jsonrpc": "2.0", "id": 4, "method": "nonexistent/method"}
        )
        assert unknown_method is not None
        assert unknown_method["error"]["code"] == -32601

        unknown_tool = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "no_such_tool", "arguments": {}},
            }
        )
        assert unknown_tool is not None
        assert unknown_tool["error"]["code"] == -32602

    def test_tools_call_scan_diff_fix_and_install(
        self,
        tmp_path: Path,
        yaml_cassette_path: Path,
    ) -> None:
        from cassette_scrub.mcp_server import handle_mcp_request

        before_text = yaml_cassette_path.read_text(encoding="utf-8")

        scan_resp = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "cassette_scrub_scan",
                    "arguments": {"paths": [str(yaml_cassette_path)]},
                },
            }
        )
        assert scan_resp is not None
        assert scan_resp["result"]["isError"] is False
        scan_payload = json.loads(scan_resp["result"]["content"][0]["text"])
        assert scan_payload["modified"] is False
        assert scan_payload["files_scanned"] == 1
        assert scan_payload["files_with_findings"] == 1
        assert scan_payload["finding_count"] >= 1
        assert yaml_cassette_path.read_text(encoding="utf-8") == before_text

        diff_resp = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "cassette_scrub_diff",
                    "arguments": {"paths": [str(yaml_cassette_path)]},
                },
            }
        )
        assert diff_resp is not None
        diff_text = "\n".join(
            c.get("text", "") for c in diff_resp["result"]["content"]
        )
        assert "---" in diff_text
        assert "+++" in diff_text
        assert "<REDACTED>" in diff_text
        assert yaml_cassette_path.read_text(encoding="utf-8") == before_text

        fix_resp = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "cassette_scrub_fix",
                    "arguments": {"paths": [str(yaml_cassette_path)]},
                },
            }
        )
        assert fix_resp is not None
        fix_payload = json.loads(fix_resp["result"]["content"][0]["text"])
        assert fix_payload["modified"] is True
        assert str(yaml_cassette_path) in fix_payload["modified_files"]
        assert yaml_cassette_path.read_text(encoding="utf-8") != before_text
        assert "<REDACTED>" in yaml_cassette_path.read_text(encoding="utf-8")

        fake_home = tmp_path / "mcp_home"
        fake_home.mkdir(parents=True, exist_ok=True)
        proj = tmp_path / "mcp_proj"
        proj.mkdir(parents=True, exist_ok=True)

        install_resp = handle_mcp_request(
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "cassette_scrub_install",
                    "arguments": {
                        "action": "all",
                        "targets": ["antigravity", "project"],
                        "home_dir": str(fake_home),
                        "project_dir": str(proj),
                        "command": "C:/tools/cassette-scrub.exe",
                    },
                },
            }
        )
        assert install_resp is not None
        assert install_resp["result"]["isError"] is False
        install_payload = json.loads(install_resp["result"]["content"][0]["text"])
        assert install_payload["success"] is True
        assert (
            fake_home
            / ".gemini"
            / "config"
            / "skills"
            / "cassette-scrub"
            / "SKILL.md"
        ).is_file()
        assert (
            proj / ".agent" / "skills" / "cassette-scrub" / "SKILL.md"
        ).is_file()
        assert (fake_home / ".gemini" / "config" / "mcp_config.json").is_file()
        assert (proj / ".mcp.json").is_file()
        assert (proj / ".pre-commit-config.yaml").is_file()


class TestInstaller:
    """Tests for multi-agent skill, MCP, and pre-commit config installer."""

    def test_supported_targets_and_skill_markdown(self) -> None:
        from cassette_scrub.installer import SUPPORTED_TARGETS, get_skill_markdown

        assert SUPPORTED_TARGETS == (
            "antigravity",
            "claude",
            "codex",
            "cursor",
            "windsurf",
            "vscode",
            "project",
        )
        md = get_skill_markdown()
        assert "name: cassette-scrub" in md
        assert "cassette-scrub" in md

    def test_install_skill_all_targets(self, tmp_path: Path) -> None:
        from cassette_scrub.installer import install_skill

        proj = tmp_path / "proj"
        proj.mkdir(parents=True, exist_ok=True)

        results = install_skill(
            targets=[
                "antigravity",
                "claude",
                "codex",
                "cursor",
                "windsurf",
                "vscode",
                "project",
            ],
            home_dir=tmp_path,
            project_dir=proj,
        )
        assert all(isinstance(r, InstallResult) for r in results)
        assert all(r.success for r in results)

        expected_files = [
            tmp_path / ".gemini" / "config" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path / ".claude" / "commands" / "cassette-scrub.md",
            tmp_path / ".codex" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path / ".cursor" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path
            / ".codeium"
            / "windsurf"
            / "skills"
            / "cassette-scrub"
            / "SKILL.md",
            proj / ".agent" / "skills" / "cassette-scrub" / "SKILL.md",
            proj / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
        ]
        for file_path in expected_files:
            assert file_path.is_file(), f"Missing installed skill file: {file_path}"
            assert "cassette-scrub" in file_path.read_text(encoding="utf-8")

    def test_install_mcp_preserves_existing_entries_across_all_targets(
        self, tmp_path: Path
    ) -> None:
        from cassette_scrub.installer import install_mcp

        proj = tmp_path / "proj"
        proj.mkdir(parents=True, exist_ok=True)

        target_files: list[tuple[Path, str]] = [
            (tmp_path / ".gemini" / "config" / "mcp_config.json", "mcpServers"),
            (tmp_path / ".claude.json", "mcpServers"),
            (
                tmp_path
                / "AppData"
                / "Roaming"
                / "Claude"
                / "claude_desktop_config.json",
                "mcpServers",
            ),
            (tmp_path / ".codex" / "mcp.json", "mcpServers"),
            (tmp_path / ".cursor" / "mcp.json", "mcpServers"),
            (
                tmp_path / ".codeium" / "windsurf" / "mcp_config.json",
                "mcpServers",
            ),
            (
                tmp_path / "AppData" / "Roaming" / "Code" / "User" / "mcp.json",
                "servers",
            ),
            (proj / ".mcp.json", "mcpServers"),
        ]

        for path, root_key in target_files:
            _write_json(
                path,
                {
                    "customFlag": True,
                    root_key: {
                        "existing-tool": {
                            "command": "existing-bin",
                            "args": ["--serve"],
                        }
                    },
                },
            )

        results = install_mcp(
            targets=[
                "antigravity",
                "claude",
                "codex",
                "cursor",
                "windsurf",
                "vscode",
                "project",
            ],
            command="C:/tools/cassette-scrub.exe",
            home_dir=tmp_path,
            project_dir=proj,
        )
        assert all(isinstance(r, InstallResult) and r.success for r in results)

        for path, root_key in target_files:
            data = json.loads(path.read_text(encoding="utf-8"))
            assert data["customFlag"] is True
            assert data[root_key]["existing-tool"] == {
                "command": "existing-bin",
                "args": ["--serve"],
            }
            assert data[root_key]["cassette-scrub"] == {
                "command": "C:/tools/cassette-scrub.exe",
                "args": ["--mcp"],
            }

    def test_install_mcp_malformed_json_does_not_overwrite(
        self, tmp_path: Path
    ) -> None:
        from cassette_scrub.installer import install_mcp

        broken = tmp_path / ".cursor" / "mcp.json"
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.write_text("{broken json", encoding="utf-8")

        results = install_mcp(targets=["cursor"], home_dir=tmp_path)
        assert len(results) == 1
        assert results[0].success is False
        assert broken.read_text(encoding="utf-8") == "{broken json"

    def test_install_pre_commit_config_creates_and_preserves(
        self, tmp_path: Path
    ) -> None:
        from cassette_scrub.installer import install_pre_commit_config

        proj = tmp_path / "proj"
        proj.mkdir(parents=True, exist_ok=True)
        precommit_path = proj / ".pre-commit-config.yaml"
        _write_yaml(
            precommit_path,
            {
                "repos": [
                    {
                        "repo": "https://github.com/pre-commit/pre-commit-hooks",
                        "rev": "v4.6.0",
                        "hooks": [{"id": "end-of-file-fixer"}],
                    }
                ]
            },
        )

        res = install_pre_commit_config(proj)
        assert isinstance(res, InstallResult)
        assert res.success is True

        parsed = yaml.safe_load(precommit_path.read_text(encoding="utf-8"))
        repos = parsed["repos"]
        assert len(repos) == 2
        assert repos[0]["repo"] == "https://github.com/pre-commit/pre-commit-hooks"
        assert repos[1]["repo"] == "https://github.com/SoRichStudio/cassette-scrub"
        assert repos[1]["hooks"] == [{"id": "cassette-scrub-check"}]


class TestBuilderStandaloneExe:
    """Tests for building and running standalone Windows .exe launchers."""

    def test_build_standalone_exe_and_run_cli(
        self,
        tmp_path: Path,
        yaml_cassette_path: Path,
        clean_yaml_cassette_path: Path,
    ) -> None:
        from cassette_scrub.builder import build_standalone_exe

        dist_dir = tmp_path / "dist"
        out = build_standalone_exe(dist_dir)

        assert set(out.keys()) == {"cli_exe", "gui_exe"}
        cli_exe = out["cli_exe"]
        gui_exe = out["gui_exe"]
        assert cli_exe.is_file()
        assert gui_exe.is_file()
        assert cli_exe.read_bytes().startswith(b"MZ")
        assert gui_exe.read_bytes().startswith(b"MZ")

        help_proc = subprocess.run(
            [str(cli_exe), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert help_proc.returncode == 0
        assert "cassette-scrub" in help_proc.stdout
        assert "--check" in help_proc.stdout

        dirty_before = yaml_cassette_path.read_text(encoding="utf-8")
        dirty_proc = subprocess.run(
            [str(cli_exe), "--check", str(yaml_cassette_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert dirty_proc.returncode == 1
        assert "dirty_cassette.yaml" in dirty_proc.stdout
        assert yaml_cassette_path.read_text(encoding="utf-8") == dirty_before

        clean_proc = subprocess.run(
            [str(cli_exe), "--check", str(clean_yaml_cassette_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert clean_proc.returncode == 0

        json_proc = subprocess.run(
            [str(cli_exe), "--check", "--json", str(yaml_cassette_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert json_proc.returncode == 1
        exe_json = json.loads(json_proc.stdout)
        assert exe_json["version"] == __version__
        assert exe_json["files_with_findings"] == 1

        clean_only_dir = tmp_path / "clean_only"
        clean_only_dir.mkdir(parents=True, exist_ok=True)
        _write_yaml(
            clean_only_dir / "ok.yaml",
            {
                "version": 1,
                "interactions": [
                    {
                        "request": {
                            "method": "GET",
                            "uri": "https://api.example.com/v1/ok",
                            "body": None,
                            "headers": {},
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
        no_gui_env = dict(os.environ)
        no_gui_env["CASSETTE_SCRUB_NO_GUI"] = "1"
        bare_clean_proc = subprocess.run(
            [str(cli_exe)],
            cwd=clean_only_dir,
            env=no_gui_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert bare_clean_proc.returncode == 0

        bare_dirty_proc = subprocess.run(
            [str(cli_exe)],
            cwd=clean_yaml_cassette_path.parent,
            env=no_gui_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert bare_dirty_proc.returncode == 1
        assert "dirty_cassette.yaml" in bare_dirty_proc.stdout


class TestGuiApp:
    """Smoke tests for the dark utilitarian Tkinter GUI application."""

    def test_gui_scan_populates_findings_and_diff_viewer(
        self, yaml_cassette_path: Path
    ) -> None:
        from cassette_scrub.gui import CassetteScrubApp

        try:
            root = tk.Tk()
        except tk.TclError as exc:
            pytest.skip(f"Tkinter display unavailable: {exc}")

        root.withdraw()
        try:
            app = CassetteScrubApp(root, initial_path=str(yaml_cassette_path))
            app.scan()
            assert app.findings_listbox.size() >= 1
            diff_content = app.diff_text.get("1.0", tk.END)
            assert "<REDACTED>" in diff_content
            report = app._build_json_report()
            assert report["version"] == __version__
            assert report["files_scanned"] == 1
            assert report["files_with_findings"] == 1
            assert len(report["findings"]) >= 1
        finally:
            root.destroy()

