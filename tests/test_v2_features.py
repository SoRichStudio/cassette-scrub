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
from cassette_scrub.cli import main
from cassette_scrub.config import load_config
from cassette_scrub.gui import CassetteScrubApp
from cassette_scrub.installer import (
    SUPPORTED_TARGETS,
    get_skill_markdown,
    install_mcp,
    install_pre_commit_config,
    install_skill,
)
from cassette_scrub.mcp_server import handle_mcp_request
from cassette_scrub.scrubber import format_cassette_diff, scrub_cassette
from cassette_scrub.types import Finding, InstallResult, ScrubConfig


def _v2_tokens() -> dict[str, str]:
    return {
        "stripe_live": "sk_" + "live_" + "a" * 24,
        "stripe_restricted": "rk_" + "test_" + "b" * 24,
        "slack_bot": "xox" + "b-" + "1234567890-abcdef123456",
        "slack_user": "xox" + "p-" + "1234567890-abcdef123456",
        "slack_app": "xox" + "a-" + "1234567890-abcdef123456",
        "slack_webhook": "https://hooks." + "slack.com/" + "services/T12345ABC/B67890DEF/xYz1234567890abcd",
        "gcp_key": "AI" + "za" + "B" * 35,
        "gcp_oauth": "ya" + "29." + "a0AfH6SM" + "B" * 20,
        "sendgrid": "SG" + "." + "c" * 22 + "." + "d" * 22,
        "twilio": "SK" + "0123456789abcdef" + "0123456789abcdef",
        "discord_webhook": "https://discord" + ".com/api/webhooks/123456789012345678/abcDEF_123456-xyz",
        "discord_canary_webhook": "https://canary.discord" + "app.com/api/webhooks/987654321098765432/tok_987654321-xyz",
        "pem_rsa": "-----BEGIN " + "RSA " + "PRIVATE KEY-----\nMIIEowIBAAKCAQEAtestpayload\n-----END " + "RSA " + "PRIVATE KEY-----",
        "pem_ec": "-----BEGIN " + "EC " + "PRIVATE KEY-----\nMHcCAQEEItestpayload\n-----END " + "EC " + "PRIVATE KEY-----",
        "pem_openssh": "-----BEGIN " + "OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA=\n-----END " + "OPENSSH " + "PRIVATE KEY-----",
        "pem_pkcs8": "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG\n-----END " + "PRIVATE KEY-----",
        "email": "v2.tester" + "@" + "example.com",
    }


def _cassette(
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
                "request": {"method": method, "uri": uri, "body": req_body, "headers": req_headers or {}},
                "response": {"status": {"code": 200, "message": "OK"}, "headers": resp_headers or {}, "body": resp_body if resp_body is not None else {"string": ""}},
            }
        ],
    }


def _write_yaml(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class TestExpandedSecretDetectors:
    @pytest.mark.parametrize(
        "token_key",
        [
            "stripe_live", "stripe_restricted", "slack_bot", "slack_user", "slack_app",
            "slack_webhook", "gcp_key", "gcp_oauth", "sendgrid", "twilio",
            "discord_webhook", "discord_canary_webhook", "pem_rsa", "pem_ec", "pem_openssh", "pem_pkcs8",
        ],
    )
    def test_expanded_detectors_in_body_headers_and_query(self, token_key: str) -> None:
        secret = _v2_tokens()[token_key]
        body_payload = json.dumps({"note": f"prefix {secret} suffix"})
        cassette = _cassette(
            uri=f"https://api.example.com/v1/hook?dest={secret}&page=1",
            req_headers={"X-Trace-Note": [f"val={secret}"], "Content-Type": ["application/json"], "Content-Length": [str(len(body_payload.encode("utf-8")))]},
            req_body=body_payload,
            resp_body={"string": f"raw={secret}"},
        )
        result = scrub_cassette(cassette, "v2_secrets.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        assert len(result.findings) >= 4 and all(isinstance(f, Finding) for f in result.findings)
        inter = result.updated_data["interactions"][0]
        assert secret not in inter["request"]["uri"]
        assert inter["request"]["headers"]["X-Trace-Note"] == ["val=<REDACTED>"]
        assert json.loads(inter["request"]["body"])["note"] == "prefix <REDACTED> suffix"
        assert inter["response"]["body"]["string"] == "raw=<REDACTED>"
        assert inter["request"]["headers"]["Content-Length"] == [str(len(inter["request"]["body"].encode("utf-8")))]
        assert not scrub_cassette(result.updated_data, "v2_secrets.yaml", ScrubConfig()).modified

    @pytest.mark.parametrize("webhook_key", ["slack_webhook", "discord_webhook", "discord_canary_webhook"])
    def test_webhook_urls_redacted_when_used_directly_as_request_uri(self, webhook_key: str) -> None:
        webhook_url = _v2_tokens()[webhook_key]
        result = scrub_cassette(_cassette(uri=f"{webhook_url}?wait=true"), "webhook_uri.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        new_uri = result.updated_data["interactions"][0]["request"]["uri"]
        assert webhook_url not in new_uri and new_uri == "<REDACTED>?wait=true"
        assert not scrub_cassette(result.updated_data, "webhook_uri.yaml", ScrubConfig()).modified


class TestCustomPatternsAndAllowlist:
    def test_load_config_reads_custom_patterns_and_allowlist(self, tmp_path: Path) -> None:
        tokens = _v2_tokens()
        allowed_case = "Allow_Exact_Case_Token"
        (tmp_path / "pyproject.toml").write_text(
            f'[tool.cassette-scrub]\nextra_headers = ["X-Custom-Auth"]\ncustom_patterns = ["INTERNAL-[0-9]{{6}}", "  corp_[a-z]+_tok  "]\nallowlist = ["{allowed_case}", "{tokens["email"]}"]\n',
            encoding="utf-8",
        )
        cfg = load_config(start_dir=tmp_path)
        assert cfg.extra_headers == {"x-custom-auth"}
        assert cfg.custom_patterns == ("INTERNAL-[0-9]{6}", "corp_[a-z]+_tok")
        assert cfg.allowlist == {allowed_case, tokens["email"]}
        assert "allow_exact_case_token" not in cfg.allowlist

    def test_custom_patterns_across_surfaces_and_invalid_regex_ignored(self) -> None:
        cassette = _cassette(
            uri="https://api.example.com/items/INTERNAL-123456?ref=INTERNAL-654321&ok=1",
            req_headers={"Host": ["api.example.com"], "Content-Type": ["application/json"], "X-Internal-Id": ["id=INTERNAL-111222"]},
            req_body=json.dumps({"tag": "INTERNAL-333444", "safe": "plain"}),
            resp_body={"string": "plain response INTERNAL-555666"},
        )
        cfg = ScrubConfig(custom_patterns=("[unclosed-regex", r"INTERNAL-[0-9]{6}", "   "))
        result = scrub_cassette(cassette, "custom.yaml", cfg)
        assert result.modified is True and result.updated_data is not None
        inter = result.updated_data["interactions"][0]
        assert "/items/<REDACTED>" in inter["request"]["uri"]
        assert dict(parse_qsl(urlsplit(inter["request"]["uri"]).query, keep_blank_values=True)) == {"ref": "<REDACTED>", "ok": "1"}
        assert inter["request"]["headers"]["Host"] == ["api.example.com"]
        assert inter["request"]["headers"]["X-Internal-Id"] == ["id=<REDACTED>"]
        assert json.loads(inter["request"]["body"]) == {"tag": "<REDACTED>", "safe": "plain"}
        assert inter["response"]["body"]["string"] == "plain response <REDACTED>"
        assert not scrub_cassette(result.updated_data, "custom.yaml", cfg).modified

    def test_allowlist_preserves_exact_matches_while_redacting_others(self) -> None:
        tokens = _v2_tokens()
        allowed_stripe, blocked_sendgrid = tokens["stripe_live"], tokens["sendgrid"]
        allowed_email, blocked_email = "public.support" + "@" + "example.com", tokens["email"]
        allowed_val = "PUBLIC_DEMO_KEY"
        cassette = _cassette(
            uri=f"https://user:{allowed_val}@api.example.com/v1/pay?api_key={allowed_val}&token=secret_tok",
            req_headers={"Authorization": [f"Bearer {allowed_val}"], "X-Api-Key": [allowed_val], "X-Auth-Token": ["blocked_auth_token"], "Content-Type": ["application/json"]},
            req_body=json.dumps({"api_key": allowed_val, "secret": "real_secret_val", "stripe": allowed_stripe, "sendgrid": blocked_sendgrid, "support": allowed_email, "user_email": blocked_email}),
            resp_body={"string": f"public={allowed_stripe} email={allowed_email} blocked={blocked_sendgrid}"},
        )
        cfg = ScrubConfig(allowlist={allowed_val, allowed_stripe, allowed_email})
        result = scrub_cassette(cassette, "allowlist.yaml", cfg)
        assert result.modified is True and result.updated_data is not None
        inter = result.updated_data["interactions"][0]
        assert allowed_val in inter["request"]["uri"]
        assert dict(parse_qsl(urlsplit(inter["request"]["uri"]).query)) == {"api_key": allowed_val, "token": "<REDACTED>"}
        assert inter["request"]["headers"]["Authorization"] == [f"Bearer {allowed_val}"]
        assert inter["request"]["headers"]["X-Api-Key"] == [allowed_val]
        assert inter["request"]["headers"]["X-Auth-Token"] == ["<REDACTED>"]
        assert json.loads(inter["request"]["body"]) == {
            "api_key": allowed_val, "secret": "<REDACTED>", "stripe": allowed_stripe,
            "sendgrid": "<REDACTED>", "support": allowed_email, "user_email": "<REDACTED_EMAIL>",
        }
        assert inter["response"]["body"]["string"] == f"public={allowed_stripe} email={allowed_email} blocked=<REDACTED>"

        clean_res = scrub_cassette(_cassette(req_headers={"X-Api-Key": [allowed_val]}, req_body=f"stripe={allowed_stripe} email={allowed_email}"), "only_allowed.yaml", cfg)
        assert not clean_res.modified and clean_res.findings == [] and clean_res.updated_data is None


class TestFormatCassetteDiff:
    def test_unified_diff_yaml_json_bytes_and_identical(self, sample_cassette_dict: dict[str, Any], clean_cassette_dict: dict[str, Any]) -> None:
        scrubbed = scrub_cassette(sample_cassette_dict, "cassettes/demo.yaml", ScrubConfig())
        assert scrubbed.modified is True and scrubbed.updated_data is not None

        for fmt, fp in (("yaml", "cassettes/demo.yaml"), ("json", "cassettes/demo.json")):
            diff = format_cassette_diff(sample_cassette_dict, scrubbed.updated_data, fmt, file_path=fp)
            assert f"--- a/{fp}" in diff and f"+++ b/{fp}" in diff and "@@" in diff and "<REDACTED>" in diff

        bytes_cass = _cassette(resp_body={"string": json.dumps({"stripe": _v2_tokens()["stripe_live"]}).encode("utf-8")})
        bytes_scrubbed = scrub_cassette(bytes_cass, "bytes.json", ScrubConfig())
        assert bytes_scrubbed.updated_data is not None
        assert "<REDACTED>" in format_cassette_diff(bytes_cass, bytes_scrubbed.updated_data, "json", file_path="bytes.json")
        assert format_cassette_diff(clean_cassette_dict, clean_cassette_dict, "yaml", file_path="cassettes/clean.yaml") == ""
        with pytest.raises(ValueError):
            format_cassette_diff(clean_cassette_dict, clean_cassette_dict, "toml")


class TestCliV2Modes:
    def test_json_mode_check_and_fix_schema_and_exit_codes(self, yaml_cassette_path: Path, clean_yaml_cassette_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--check", "--json", str(clean_yaml_cassette_path)]) == 0
        assert json.loads(capsys.readouterr().out) == {"version": __version__, "modified": False, "files_scanned": 1, "files_with_findings": 0, "findings": []}

        assert main(["--check", "--json", str(yaml_cassette_path)]) == 1
        dirty = json.loads(capsys.readouterr().out)
        assert dirty["version"] == __version__ and dirty["modified"] is False and dirty["files_with_findings"] == 1
        assert set(dirty["findings"][0].keys()) == {"file_path", "interaction_index", "location", "preview"}

        assert main(["--fix", "--json", str(yaml_cassette_path)]) == 1
        assert json.loads(capsys.readouterr().out)["modified"] is True

        assert main(["--fix", "--exit-zero-on-fix", "--json", str(yaml_cassette_path)]) == 0
        after = json.loads(capsys.readouterr().out)
        assert after["modified"] is False and after["findings"] == []

    def test_diff_mode_prints_unified_diff_without_modifying(self, yaml_cassette_path: Path, json_cassette_path: Path, clean_yaml_cassette_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        yaml_before, json_before = yaml_cassette_path.read_text(encoding="utf-8"), json_cassette_path.read_text(encoding="utf-8")
        assert main(["--diff", str(yaml_cassette_path), str(json_cassette_path)]) == 1
        out = capsys.readouterr().out
        assert "---" in out and "+++" in out and "@@" in out and "<REDACTED>" in out
        assert yaml_cassette_path.read_text(encoding="utf-8") == yaml_before
        assert json_cassette_path.read_text(encoding="utf-8") == json_before
        assert main(["--diff", str(clean_yaml_cassette_path)]) == 0 and capsys.readouterr().out == ""

    def test_cli_install_skill_mcp_and_hook(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        fake_home, proj = tmp_path / "home", tmp_path / "proj"
        fake_home.mkdir()
        proj.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
        monkeypatch.chdir(proj)

        assert main(["--install-skill", "antigravity", "project"]) == 0
        capsys.readouterr()
        assert (fake_home / ".gemini" / "config" / "skills" / "cassette-scrub" / "SKILL.md").is_file()
        assert (proj / ".agent" / "skills" / "cassette-scrub" / "SKILL.md").is_file()

        assert main(["--install-mcp", "antigravity", "project", "--json"]) == 0
        mcp_payload = json.loads(capsys.readouterr().out)
        assert mcp_payload["success"] is True and mcp_payload["version"] == __version__
        assert "cassette-scrub" in json.loads((fake_home / ".gemini" / "config" / "mcp_config.json").read_text(encoding="utf-8"))["mcpServers"]
        assert "cassette-scrub" in json.loads((proj / ".mcp.json").read_text(encoding="utf-8"))["mcpServers"]

        assert main(["--install-hook", str(proj)]) == 0
        capsys.readouterr()
        assert "cassette-scrub" in (proj / ".pre-commit-config.yaml").read_text(encoding="utf-8")

    def test_cli_build_exe(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
        proj = tmp_path / "build_proj"
        proj.mkdir()
        monkeypatch.chdir(proj)
        assert main(["--build-exe"]) == 0
        assert "cassette-scrub.exe" in capsys.readouterr().out
        assert (proj / "dist" / "cassette-scrub.exe").is_file() and (proj / "dist" / "cassette-scrub-gui.exe").is_file()


class TestMcpServer:
    def test_initialize_ping_notification_tools_list_and_errors(self) -> None:
        init_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
        assert init_resp and init_resp["result"]["protocolVersion"] == "2024-11-05"
        assert init_resp["result"]["serverInfo"] == {"name": "cassette-scrub", "version": __version__}
        assert handle_mcp_request({"jsonrpc": "2.0", "id": 2, "method": "ping"}) == {"jsonrpc": "2.0", "id": 2, "result": {}}
        assert handle_mcp_request({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
        list_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        assert list_resp and {t["name"] for t in list_resp["result"]["tools"]} == {"cassette_scrub_scan", "cassette_scrub_fix", "cassette_scrub_diff", "cassette_scrub_install"}
        assert handle_mcp_request({"jsonrpc": "2.0", "id": 4, "method": "nonexistent/method"})["error"]["code"] == -32601  # type: ignore[index]
        assert handle_mcp_request({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "no_such_tool", "arguments": {}}})["error"]["code"] == -32602  # type: ignore[index]

    def test_tools_call_scan_diff_fix_and_install(self, tmp_path: Path, yaml_cassette_path: Path) -> None:
        before = yaml_cassette_path.read_text(encoding="utf-8")
        scan_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "cassette_scrub_scan", "arguments": {"paths": [str(yaml_cassette_path)]}}})
        assert scan_resp and not scan_resp["result"]["isError"]
        scan_data = json.loads(scan_resp["result"]["content"][0]["text"])
        assert scan_data["modified"] is False and scan_data["files_with_findings"] == 1 and yaml_cassette_path.read_text(encoding="utf-8") == before

        diff_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "cassette_scrub_diff", "arguments": {"paths": [str(yaml_cassette_path)]}}})
        assert diff_resp and "---" in diff_resp["result"]["content"][0]["text"] and "<REDACTED>" in diff_resp["result"]["content"][0]["text"]
        assert yaml_cassette_path.read_text(encoding="utf-8") == before

        fix_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "cassette_scrub_fix", "arguments": {"paths": [str(yaml_cassette_path)]}}})
        assert fix_resp and json.loads(fix_resp["result"]["content"][0]["text"])["modified"] is True
        assert "<REDACTED>" in yaml_cassette_path.read_text(encoding="utf-8")

        fake_home, proj = tmp_path / "mcp_home", tmp_path / "mcp_proj"
        fake_home.mkdir()
        proj.mkdir()
        inst_resp = handle_mcp_request({"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {"name": "cassette_scrub_install", "arguments": {"action": "all", "targets": ["antigravity", "project"], "home_dir": str(fake_home), "project_dir": str(proj), "command": "C:/tools/cassette-scrub.exe"}}})
        assert inst_resp and json.loads(inst_resp["result"]["content"][0]["text"])["success"] is True
        assert (fake_home / ".gemini" / "config" / "skills" / "cassette-scrub" / "SKILL.md").is_file()
        assert (proj / ".agent" / "skills" / "cassette-scrub" / "SKILL.md").is_file()
        assert (fake_home / ".gemini" / "config" / "mcp_config.json").is_file()
        assert (proj / ".mcp.json").is_file() and (proj / ".pre-commit-config.yaml").is_file()


class TestInstaller:
    def test_supported_targets_and_skill_markdown(self) -> None:
        assert SUPPORTED_TARGETS == ("antigravity", "claude", "codex", "cursor", "windsurf", "vscode", "project")
        md = get_skill_markdown()
        assert "name: cassette-scrub" in md and "cassette-scrub" in md

    def test_install_skill_all_targets(self, tmp_path: Path) -> None:
        proj = tmp_path / "proj"
        proj.mkdir()
        results = install_skill(targets=list(SUPPORTED_TARGETS), home_dir=tmp_path, project_dir=proj)
        assert all(isinstance(r, InstallResult) and r.success for r in results)
        expected = [
            tmp_path / ".gemini" / "config" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path / ".claude" / "commands" / "cassette-scrub.md",
            tmp_path / ".codex" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path / ".cursor" / "skills" / "cassette-scrub" / "SKILL.md",
            tmp_path / ".codeium" / "windsurf" / "skills" / "cassette-scrub" / "SKILL.md",
            proj / ".agent" / "skills" / "cassette-scrub" / "SKILL.md",
            proj / ".claude" / "skills" / "cassette-scrub" / "SKILL.md",
        ]
        for p in expected:
            assert p.is_file() and "cassette-scrub" in p.read_text(encoding="utf-8")

    def test_install_mcp_preserves_existing_entries_across_all_targets(self, tmp_path: Path) -> None:
        proj = tmp_path / "proj"
        proj.mkdir()
        target_files = [
            (tmp_path / ".gemini" / "config" / "mcp_config.json", "mcpServers"),
            (tmp_path / ".claude.json", "mcpServers"),
            (tmp_path / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json", "mcpServers"),
            (tmp_path / ".codex" / "mcp.json", "mcpServers"),
            (tmp_path / ".cursor" / "mcp.json", "mcpServers"),
            (tmp_path / ".codeium" / "windsurf" / "mcp_config.json", "mcpServers"),
            (tmp_path / "AppData" / "Roaming" / "Code" / "User" / "mcp.json", "servers"),
            (proj / ".mcp.json", "mcpServers"),
        ]
        for p, key in target_files:
            _write_json(p, {"customFlag": True, key: {"existing-tool": {"command": "existing-bin", "args": ["--serve"]}}})

        results = install_mcp(targets=list(SUPPORTED_TARGETS), command="C:/tools/cassette-scrub.exe", home_dir=tmp_path, project_dir=proj)
        assert all(isinstance(r, InstallResult) and r.success for r in results)
        for p, key in target_files:
            data = json.loads(p.read_text(encoding="utf-8"))
            assert data["customFlag"] is True and data[key]["existing-tool"]["command"] == "existing-bin"
            assert data[key]["cassette-scrub"] == {"command": "C:/tools/cassette-scrub.exe", "args": ["--mcp"]}

    def test_install_mcp_malformed_json_does_not_overwrite(self, tmp_path: Path) -> None:
        broken = tmp_path / ".cursor" / "mcp.json"
        broken.parent.mkdir(parents=True)
        broken.write_text("{broken json", encoding="utf-8")
        results = install_mcp(targets=["cursor"], home_dir=tmp_path)
        assert len(results) == 1 and results[0].success is False and broken.read_text(encoding="utf-8") == "{broken json"

    def test_install_pre_commit_config_creates_and_preserves(self, tmp_path: Path) -> None:
        proj = tmp_path / "proj"
        proj.mkdir()
        precommit = proj / ".pre-commit-config.yaml"
        _write_yaml(precommit, {"repos": [{"repo": "https://github.com/pre-commit/pre-commit-hooks", "rev": "v4.6.0", "hooks": [{"id": "end-of-file-fixer"}]}]})
        res = install_pre_commit_config(proj)
        assert isinstance(res, InstallResult) and res.success is True
        repos = yaml.safe_load(precommit.read_text(encoding="utf-8"))["repos"]
        assert len(repos) == 2 and repos[1]["hooks"] == [{"id": "cassette-scrub-check"}]


class TestBuilderStandaloneExe:
    def test_build_standalone_exe_and_run_cli(self, tmp_path: Path, yaml_cassette_path: Path, clean_yaml_cassette_path: Path) -> None:
        from cassette_scrub.builder import build_standalone_exe

        out = build_standalone_exe(tmp_path / "dist")
        assert set(out.keys()) == {"cli_exe", "gui_exe"}
        cli_exe, gui_exe = out["cli_exe"], out["gui_exe"]
        assert cli_exe.read_bytes().startswith(b"MZ") and gui_exe.read_bytes().startswith(b"MZ")

        help_proc = subprocess.run([str(cli_exe), "--help"], capture_output=True, text=True, check=False)
        assert help_proc.returncode == 0 and "--check" in help_proc.stdout

        before = yaml_cassette_path.read_text(encoding="utf-8")
        dirty_proc = subprocess.run([str(cli_exe), "--check", str(yaml_cassette_path)], capture_output=True, text=True, check=False)
        assert dirty_proc.returncode == 1 and "dirty_cassette.yaml" in dirty_proc.stdout and yaml_cassette_path.read_text(encoding="utf-8") == before
        assert subprocess.run([str(cli_exe), "--check", str(clean_yaml_cassette_path)], capture_output=True, text=True, check=False).returncode == 0

        json_proc = subprocess.run([str(cli_exe), "--check", "--json", str(yaml_cassette_path)], capture_output=True, text=True, check=False)
        assert json_proc.returncode == 1 and json.loads(json_proc.stdout)["files_with_findings"] == 1

        clean_dir = tmp_path / "clean_only"
        _write_yaml(clean_dir / "ok.yaml", _cassette(uri="https://api.example.com/v1/ok", resp_body={"string": "ok"}))
        no_gui = {**os.environ, "CASSETTE_SCRUB_NO_GUI": "1"}
        assert subprocess.run([str(cli_exe)], cwd=clean_dir, env=no_gui, capture_output=True, text=True, check=False).returncode == 0
        bare_dirty = subprocess.run([str(cli_exe)], cwd=clean_yaml_cassette_path.parent, env=no_gui, capture_output=True, text=True, check=False)
        assert bare_dirty.returncode == 1 and "dirty_cassette.yaml" in bare_dirty.stdout


class TestGuiApp:
    def test_gui_scan_populates_findings_and_diff_viewer(self, yaml_cassette_path: Path) -> None:
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            pytest.skip(f"Tkinter display unavailable: {exc}")
        root.withdraw()
        try:
            app = CassetteScrubApp(root, initial_path=str(yaml_cassette_path))
            app.scan()
            assert app.findings_listbox.size() >= 1
            assert "<REDACTED>" in app.diff_text.get("1.0", tk.END)
            report = app._build_json_report()
            assert report["version"] == __version__ and report["files_scanned"] == 1 and report["files_with_findings"] == 1 and report["findings"]
        finally:
            root.destroy()
