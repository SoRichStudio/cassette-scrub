from __future__ import annotations

import copy
import gzip
import json
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from cassette_scrub.scrubber import scrub_cassette
from cassette_scrub.types import Finding, ScrubConfig


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


class TestHeaderRedaction:
    def test_case_insensitive_sensitive_headers_and_prefixes(self, fake_tokens: dict[str, str]) -> None:
        cassette = _cassette(
            req_headers={
                "authorization": [f"Bearer {fake_tokens['anthropic']}"],
                "Proxy-Authorization": ["Basic dXNlcjpwYXNzd29yZA=="],
                "x-api-key": [fake_tokens["aws"]],
                "X-Auth-Token": ["secret-auth-tok"],
                "x-csrf-token": ["csrf-val-123"],
                "X-Amz-Security-Token": ["amz-sec-tok-999"],
                "Accept": ["application/json"],
            },
            resp_headers={
                "Authorization": ["bearer lower-secret-token"],
                "API-Key": ["resp-api-key-val"],
                "X-CSRF-TOKEN": ["resp-csrf-val"],
            },
        )
        original = copy.deepcopy(cassette)
        result = scrub_cassette(cassette, "headers.yaml", ScrubConfig())

        assert cassette == original
        assert result.modified is True and result.updated_data is not None
        assert len(result.findings) >= 9
        assert all(isinstance(f, Finding) and f.file_path == "headers.yaml" for f in result.findings)

        req_h = result.updated_data["interactions"][0]["request"]["headers"]
        assert req_h["authorization"] == ["Bearer <REDACTED>"]
        assert req_h["Proxy-Authorization"] == ["Basic <REDACTED>"]
        assert req_h["x-api-key"] == ["<REDACTED>"]
        assert req_h["X-Auth-Token"] == ["<REDACTED>"]
        assert req_h["x-csrf-token"] == ["<REDACTED>"]
        assert req_h["X-Amz-Security-Token"] == ["<REDACTED>"]
        assert req_h["Accept"] == ["application/json"]

        resp_h = result.updated_data["interactions"][0]["response"]["headers"]
        assert len(resp_h["Authorization"]) == 1
        assert resp_h["Authorization"][0].lower() == "bearer <redacted>"
        assert resp_h["Authorization"][0].endswith("<REDACTED>")
        assert resp_h["API-Key"] == ["<REDACTED>"]
        assert resp_h["X-CSRF-TOKEN"] == ["<REDACTED>"]

    def test_authorization_without_bearer_or_basic_prefix(self) -> None:
        cassette = _cassette(req_headers={"Authorization": ["Token raw-opaque-secret"]})
        result = scrub_cassette(cassette, "auth.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        assert result.updated_data["interactions"][0]["request"]["headers"]["Authorization"] == ["<REDACTED>"]

    def test_cookie_and_set_cookie_preserve_keys_and_attributes(self) -> None:
        cassette = _cassette(
            req_headers={"cookie": ["session=sec123; theme=dark; prefs=compact"]},
            resp_headers={
                "Set-Cookie": [
                    "auth_token=tok999; Path=/; HttpOnly",
                    "sid=xyz789; Domain=example.com; Max-Age=3600; SameSite=Lax; Secure; Partitioned",
                ]
            },
        )
        result = scrub_cassette(cassette, "cookies.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        inter = result.updated_data["interactions"][0]
        assert inter["request"]["headers"]["cookie"] == ["session=<REDACTED>; theme=<REDACTED>; prefs=<REDACTED>"]
        assert inter["response"]["headers"]["Set-Cookie"] == [
            "auth_token=<REDACTED>; Path=/; HttpOnly",
            "sid=<REDACTED>; Domain=example.com; Max-Age=3600; SameSite=Lax; Secure; Partitioned",
        ]

    def test_non_sensitive_headers_scrub_tokens_and_emails(self, fake_tokens: dict[str, str]) -> None:
        cassette = _cassette(
            req_headers={
                "Host": ["api.example.com"],
                "X-Custom-Note": [f"token={fake_tokens['github']}"],
                "X-User-Contact": [fake_tokens["email"]],
            }
        )
        result = scrub_cassette(cassette, "custom_hdr.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        req_h = result.updated_data["interactions"][0]["request"]["headers"]
        assert req_h["Host"] == ["api.example.com"]
        assert req_h["X-Custom-Note"] == ["token=<REDACTED>"]
        assert req_h["X-User-Contact"] == ["<REDACTED_EMAIL>"]


class TestUriQueryRedaction:
    def test_sensitive_query_params_redacted_and_benign_preserved(self, fake_tokens: dict[str, str]) -> None:
        uri = f"https://api.example.com/v1/messages?api_key={fake_tokens['openai']}&token=rawtok123&page=1&limit=25"
        result = scrub_cassette(_cassette(method="GET", uri=uri), "query.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        params = dict(parse_qsl(urlsplit(result.updated_data["interactions"][0]["request"]["uri"]).query, keep_blank_values=True))
        assert params == {"api_key": "<REDACTED>", "token": "<REDACTED>", "page": "1", "limit": "25"}

    def test_benign_query_key_with_token_or_email_value_scrubbed(self, fake_tokens: dict[str, str]) -> None:
        uri = f"https://api.example.com/v1/search?q={fake_tokens['anthropic']}&user={fake_tokens['email']}&page=2"
        result = scrub_cassette(_cassette(method="GET", uri=uri), "query_vals.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        params = dict(parse_qsl(urlsplit(result.updated_data["interactions"][0]["request"]["uri"]).query, keep_blank_values=True))
        assert params == {"q": "<REDACTED>", "user": "<REDACTED_EMAIL>", "page": "2"}


class TestBodyAndContentScrubbing:
    def test_nested_json_body_key_redaction_request_and_response(self, fake_tokens: dict[str, str]) -> None:
        req_str = json.dumps({
            "meta": {"request_id": "req-1"},
            "nested": {"items": [{"api_key": "inline-secret-key", "client_secret": "cs-999", "label": "public-label"}]},
        })
        resp_str = json.dumps({"auth": {"access_token": fake_tokens["jwt"], "refresh_token": "refresh-secret-abc"}, "ok": True})
        cassette = _cassette(
            req_headers={"Content-Type": ["application/json"], "Content-Length": [str(len(req_str.encode("utf-8")))]},
            req_body=req_str,
            resp_headers={"Content-Type": ["application/json"], "content-length": [str(len(resp_str.encode("utf-8")))]},
            resp_body={"string": resp_str},
        )
        result = scrub_cassette(cassette, "nested_json.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        inter = result.updated_data["interactions"][0]
        parsed_req = json.loads(inter["request"]["body"])
        assert parsed_req["nested"]["items"][0] == {"api_key": "<REDACTED>", "client_secret": "<REDACTED>", "label": "public-label"}
        assert parsed_req["meta"]["request_id"] == "req-1"
        assert json.loads(inter["response"]["body"]["string"]) == {"auth": {"access_token": "<REDACTED>", "refresh_token": "<REDACTED>"}, "ok": True}

    def test_form_urlencoded_body_redaction(self, fake_tokens: dict[str, str]) -> None:
        body = f"grant_type=client_credentials&client_secret=supersecret123&password=mypassword&note={fake_tokens['github']}&scope=read"
        cassette = _cassette(
            req_headers={"Content-Type": ["application/x-www-form-urlencoded"], "Content-Length": [str(len(body.encode("utf-8")))]},
            req_body=body,
        )
        result = scrub_cassette(cassette, "form.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        req = result.updated_data["interactions"][0]["request"]
        assert dict(parse_qsl(req["body"], keep_blank_values=True)) == {
            "grant_type": "client_credentials",
            "client_secret": "<REDACTED>",
            "password": "<REDACTED>",
            "note": "<REDACTED>",
            "scope": "read",
        }
        assert req["headers"]["Content-Length"] == [str(len(req["body"].encode("utf-8")))]

    def test_all_token_regex_patterns_and_email_pii(self, fake_tokens: dict[str, str]) -> None:
        plain = " ".join(f"{k}={fake_tokens[k]}" for k in ("anthropic", "openai", "github", "aws", "jwt", "email"))
        result = scrub_cassette(_cassette(req_headers={"Content-Type": ["text/plain"]}, req_body=plain), "tokens.yaml", ScrubConfig(scrub_pii=True))
        assert result.modified is True and result.updated_data is not None
        body = result.updated_data["interactions"][0]["request"]["body"]
        for k in ("anthropic", "openai", "github", "aws", "jwt", "email"):
            assert fake_tokens[k] not in body
        assert body == "anthropic=<REDACTED> openai=<REDACTED> github=<REDACTED> aws=<REDACTED> jwt=<REDACTED> email=<REDACTED_EMAIL>"

    def test_scrub_pii_false_preserves_emails_while_redacting_secrets(self, sample_cassette_dict: dict[str, Any], fake_tokens: dict[str, str]) -> None:
        result = scrub_cassette(sample_cassette_dict, "no_pii.yaml", ScrubConfig(scrub_pii=False))
        assert result.modified is True and result.updated_data is not None
        inter = result.updated_data["interactions"][0]
        req_json = json.loads(inter["request"]["body"])
        resp_json = json.loads(inter["response"]["body"]["string"])
        assert req_json["user"]["email"] == fake_tokens["email"]
        assert resp_json["contact"] == fake_tokens["email"]
        assert req_json["credentials"]["api_key"] == "<REDACTED>"
        assert req_json["credentials"]["client_secret"] == "<REDACTED>"
        assert req_json["user"]["note"] == "backup token <REDACTED>"
        assert resp_json["access_token"] == "<REDACTED>"
        assert resp_json["repo_token"] == "<REDACTED>"
        assert inter["request"]["headers"]["Authorization"] == ["Bearer <REDACTED>"]
        assert inter["request"]["headers"]["X-Api-Key"] == ["<REDACTED>"]

        repeat = scrub_cassette(result.updated_data, "no_pii.yaml", ScrubConfig(scrub_pii=False))
        assert not repeat.modified and repeat.findings == [] and repeat.updated_data is None

        with_pii = scrub_cassette(result.updated_data, "no_pii.yaml", ScrubConfig(scrub_pii=True))
        assert with_pii.modified is True and with_pii.updated_data is not None
        assert json.loads(with_pii.updated_data["interactions"][0]["request"]["body"])["user"]["email"] == "<REDACTED_EMAIL>"
        assert json.loads(with_pii.updated_data["interactions"][0]["response"]["body"]["string"])["contact"] == "<REDACTED_EMAIL>"

    def test_non_utf8_binary_and_gzipped_bytes_bodies_skipped_gracefully(self) -> None:
        cassette = _cassette(
            req_headers={"Content-Encoding": ["gzip"]},
            req_body=b"\xff\xfe\x00\x80\x81\xfe\xff",
            resp_headers={"Content-Encoding": ["gzip"]},
            resp_body={"string": gzip.compress(b'{"secret": "should-not-crash-binary"}')},
        )
        result = scrub_cassette(cassette, "binary.yaml", ScrubConfig())
        assert not result.modified and result.findings == [] and result.updated_data is None

    def test_utf8_bytes_body_is_scrubbed_and_kept_as_bytes(self, fake_tokens: dict[str, str]) -> None:
        raw_bytes = json.dumps({"api_key": fake_tokens["anthropic"]}).encode("utf-8")
        cassette = _cassette(
            resp_headers={"Content-Type": ["application/json"], "content-length": [str(len(raw_bytes))]},
            resp_body={"string": raw_bytes},
        )
        result = scrub_cassette(cassette, "utf8_bytes.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        resp = result.updated_data["interactions"][0]["response"]
        new_bytes = resp["body"]["string"]
        assert isinstance(new_bytes, bytes)
        assert json.loads(new_bytes.decode("utf-8")) == {"api_key": "<REDACTED>"}
        assert resp["headers"]["content-length"] == [str(len(new_bytes))]

    def test_content_length_recalculation_and_key_casing_preservation(self, fake_tokens: dict[str, str]) -> None:
        req_str = json.dumps({"label": "café 🚀", "api_key": fake_tokens["anthropic"]}, ensure_ascii=False)
        resp_str = json.dumps({"note": "naïve — résumé", "contact": fake_tokens["email"]}, ensure_ascii=False)
        cassette = _cassette(
            req_headers={"Content-Type": ["application/json"], "Content-Length": [str(len(req_str.encode("utf-8")))]},
            req_body=req_str,
            resp_headers={"Content-Type": ["application/json"], "content-length": [str(len(resp_str.encode("utf-8")))]},
            resp_body={"string": resp_str},
        )
        result = scrub_cassette(cassette, "content_length.yaml", ScrubConfig())
        assert result.modified is True and result.updated_data is not None
        inter = result.updated_data["interactions"][0]
        assert "Content-Length" in inter["request"]["headers"] and "content-length" not in inter["request"]["headers"]
        assert inter["request"]["headers"]["Content-Length"] == [str(len(inter["request"]["body"].encode("utf-8")))]
        assert "content-length" in inter["response"]["headers"] and "Content-Length" not in inter["response"]["headers"]
        assert inter["response"]["headers"]["content-length"] == [str(len(inter["response"]["body"]["string"].encode("utf-8")))]


class TestScrubConfigExtrasAndIdempotency:
    def test_extra_headers_query_keys_and_body_keys(self) -> None:
        body = json.dumps({"custom_pin": "9876", "nested": {"internal_secret": "top-secret"}, "safe_field": "ok"})
        cassette = _cassette(
            uri="https://api.example.com/v1/op?tenant_sig=abc123&page=1",
            req_headers={"X-Tenant-Secret": ["tenant-val-42"], "Content-Type": ["application/json"]},
            req_body=body,
        )
        cfg = ScrubConfig(extra_headers={"X-Tenant-Secret"}, extra_query_keys={"tenant_sig"}, extra_body_keys={"custom_pin", "internal_secret"})
        result = scrub_cassette(cassette, "extras.yaml", cfg)
        assert result.modified is True and result.updated_data is not None
        req = result.updated_data["interactions"][0]["request"]
        assert req["headers"]["X-Tenant-Secret"] == ["<REDACTED>"]
        assert dict(parse_qsl(urlsplit(req["uri"]).query, keep_blank_values=True)) == {"tenant_sig": "<REDACTED>", "page": "1"}
        assert json.loads(req["body"]) == {"custom_pin": "<REDACTED>", "nested": {"internal_secret": "<REDACTED>"}, "safe_field": "ok"}

    def test_idempotency_on_scrubbed_and_clean_cassettes(self, sample_cassette_dict: dict[str, Any], clean_cassette_dict: dict[str, Any]) -> None:
        clean_res = scrub_cassette(clean_cassette_dict, "clean.yaml", ScrubConfig())
        assert not clean_res.modified and clean_res.findings == [] and clean_res.updated_data is None

        first = scrub_cassette(sample_cassette_dict, "dirty.yaml", ScrubConfig())
        assert first.modified is True and first.updated_data is not None
        second = scrub_cassette(first.updated_data, "dirty.yaml", ScrubConfig())
        assert not second.modified and second.findings == [] and second.updated_data is None

        pre_redacted = _cassette(
            uri="https://api.example.com/v1/items?api_key=<REDACTED>&page=1",
            req_headers={"Authorization": ["Bearer <REDACTED>"], "Proxy-Authorization": ["Basic <REDACTED>"], "Cookie": ["session=<REDACTED>"], "X-Api-Key": ["<REDACTED>"]},
            req_body=json.dumps({"api_key": "<REDACTED>", "email": "<REDACTED_EMAIL>"}),
            resp_headers={"Set-Cookie": ["auth_token=<REDACTED>; Path=/; HttpOnly"]},
            resp_body={"string": "contact=<REDACTED_EMAIL> token=<REDACTED>"},
        )
        pre_res = scrub_cassette(pre_redacted, "pre.yaml", ScrubConfig())
        assert not pre_res.modified and pre_res.findings == [] and pre_res.updated_data is None

    def test_multi_interaction_finding_indices(self, fake_tokens: dict[str, str]) -> None:
        cassette = {
            "version": 1,
            "interactions": [
                {"request": {"method": "GET", "uri": "https://api.example.com/v1/ok", "body": None, "headers": {}}, "response": {"status": {"code": 200, "message": "OK"}, "headers": {}, "body": {"string": "ok"}}},
                {"request": {"method": "POST", "uri": "https://api.example.com/v1/fail", "body": None, "headers": {"X-Api-Key": [fake_tokens["anthropic"]]}}, "response": {"status": {"code": 200, "message": "OK"}, "headers": {}, "body": {"string": ""}}},
            ],
        }
        result = scrub_cassette(cassette, "multi.yaml", ScrubConfig())
        assert result.modified is True and len(result.findings) == 1
        assert result.findings[0].interaction_index == 1 and result.findings[0].file_path == "multi.yaml"
        assert result.findings[0].location and result.findings[0].preview
