from __future__ import annotations

import copy
import difflib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import yaml

from cassette_scrub.parser import _json_default
from cassette_scrub.types import Finding, ScrubConfig, ScrubResult

REDACTED = "<REDACTED>"
REDACTED_EMAIL = "<REDACTED_EMAIL>"

SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "cookie",
        "set-cookie",
        "x-csrf-token",
        "x-amz-security-token",
    }
)
SKIP_NON_SENSITIVE_HEADERS: frozenset[str] = frozenset(
    {"content-length", "content-type", "host"}
)
SENSITIVE_QUERY_KEYS: frozenset[str] = frozenset(
    {
        "api_key", "apikey", "api-key", "access_token", "refresh_token",
        "client_secret", "password", "passwd", "secret", "token", "auth_token",
        "id_token", "private_key", "aws_access_key_id", "aws_secret_access_key",
        "aws_key", "x-api-key", "authorization", "session", "session_id",
        "cookie", "csrf_token", "key", "sig", "signature",
    }
)
SENSITIVE_BODY_KEYS: frozenset[str] = frozenset(
    {
        "api_key", "apikey", "api-key", "access_token", "refresh_token",
        "client_secret", "client_id", "password", "passwd", "secret",
        "secret_key", "private_key", "token", "auth_token", "id_token",
        "bearer_token", "session_token", "authorization",
        "aws_access_key_id", "aws_secret_access_key", "ssn", "credit_card",
    }
)

_WEBHOOK_REGEX = re.compile(
    "|".join(
        [
            r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+",
            r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
        ]
    )
)
_TOKEN_REGEX = re.compile(
    "|".join(
        [
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----",
            _WEBHOOK_REGEX.pattern,
            r"(?<![A-Za-z0-9])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}",
            r"sk-ant-[A-Za-z0-9_-]{6,}",
            r"(?<![A-Za-z0-9])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{10,}",
            r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{20,})",
            r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,}",
            r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}",
            r"(?<![A-Za-z0-9])ya29\.[0-9A-Za-z_-]{10,}",
            r"(?<![A-Za-z0-9])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
            r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])",
            r"(?<![A-Za-z0-9])SK[0-9a-fA-F]{32}(?![A-Za-z0-9])",
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.(?:eyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?|[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})",
        ]
    )
)
_EMAIL_REGEX = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)
_FORM_BODY_REGEX = re.compile(
    r"^[A-Za-z0-9_.~%\[\]-]+=[^&\s]*(?:&[A-Za-z0-9_.~%\[\]-]+=[^&\s]*)*$"
)
_PLACEHOLDER_REGEX = re.compile(r"<REDACTED(?:_EMAIL)?>")
_AUTH_PREFIXES = ("bearer ", "basic ")


def _preview(raw: str, repl: str = REDACTED) -> str:
    s = raw.strip()
    return f"{s[:3]}... -> {repl}" if len(s) > 6 else f"*** -> {repl}"


def _is_redacted(val: str) -> bool:
    return val.strip() in ("", REDACTED, REDACTED_EMAIL)


def _split_auth(val: str) -> tuple[str, str] | None:
    s = val.strip()
    low = s.lower()
    for pfx in _AUTH_PREFIXES:
        if low.startswith(pfx):
            return s[: len(pfx) - 1], s[len(pfx) :].strip()
    return None


def _compile_patterns(raw_patterns: Any) -> tuple[re.Pattern[str], ...]:
    out: list[re.Pattern[str]] = []
    for item in raw_patterns or ():
        if isinstance(item, str) and item.strip():
            try:
                out.append(re.compile(item))
            except re.error:
                continue
    return tuple(out)


def _norm_keys(extra: set[str], base: frozenset[str]) -> frozenset[str]:
    return base | {k.strip().lower() for k in extra if k.strip()}


def _is_form(text: str, content_type: str) -> bool:
    if "=" not in text:
        return False
    if "application/x-www-form-urlencoded" in content_type:
        return True
    if any(t in content_type for t in ("json", "xml", "html", "javascript", "octet-stream")):
        return False
    s = text.strip()
    return bool(s and not s.startswith(("{", "[", "<")) and _FORM_BODY_REGEX.match(s))


class _Scrubber:
    def __init__(self, file_path: str, config: ScrubConfig) -> None:
        self.file_path = file_path
        self.scrub_pii = config.scrub_pii
        self.headers = _norm_keys(config.extra_headers, SENSITIVE_HEADERS)
        self.query_keys = _norm_keys(config.extra_query_keys, SENSITIVE_QUERY_KEYS)
        self.body_keys = _norm_keys(config.extra_body_keys, SENSITIVE_BODY_KEYS)
        self.custom = _compile_patterns(config.custom_patterns)
        self.allowlist = frozenset(s.strip() for s in config.allowlist if isinstance(s, str) and s.strip())
        self.findings: list[Finding] = []

    def allowed(self, val: str) -> bool:
        return bool(self.allowlist) and val.strip() in self.allowlist

    def record(self, idx: int, loc: str, raw: str, repl: str = REDACTED) -> None:
        self.findings.append(Finding(self.file_path, idx, loc, _preview(raw, repl)))

    def scrub_text(self, text: str, idx: int, loc: str) -> tuple[str, bool]:
        found: list[tuple[str, str]] = []
        updated = text

        def sub_regex(pattern: re.Pattern[str], repl: str, skip_spans: bool = False) -> None:
            nonlocal updated
            spans = [m.span() for m in _PLACEHOLDER_REGEX.finditer(updated)] if skip_spans else []

            def repl_fn(m: re.Match[str]) -> str:
                raw = m.group(0)
                if not raw or self.allowed(raw):
                    return raw
                if spans and any(m.start() < pe and ps < m.end() for ps, pe in spans):
                    return raw
                found.append((raw, repl))
                return repl

            updated = pattern.sub(repl_fn, updated)

        if self.scrub_pii:
            sub_regex(_EMAIL_REGEX, REDACTED_EMAIL)
        sub_regex(_TOKEN_REGEX, REDACTED)
        for pat in self.custom:
            sub_regex(pat, REDACTED, skip_spans=True)

        for raw, repl in found:
            self.record(idx, loc, raw, repl)
        return updated, bool(found)

    def _scrub_cookie(self, val: str, is_set_cookie: bool) -> tuple[str, str] | None:
        if _is_redacted(val) or self.allowed(val):
            return None
        parts = [p.strip() for p in val.split(";") if p.strip()]
        if not parts:
            return None

        if is_set_cookie:
            first, attrs = parts[0], parts[1:]
            if "=" in first:
                name, cval = (x.strip() for x in first.split("=", 1))
                if cval in ("", REDACTED) or self.allowed(cval) or self.allowed(first):
                    return None
                return "; ".join([f"{name}={REDACTED}", *attrs]), cval
            if first in ("", REDACTED) or self.allowed(first):
                return None
            return "; ".join([REDACTED, *attrs]), first

        rebuilt: list[str] = []
        first_raw = ""
        for item in parts:
            if "=" in item:
                name, cval = (x.strip() for x in item.split("=", 1))
                if cval in ("", REDACTED) or self.allowed(cval) or self.allowed(item):
                    rebuilt.append(item)
                else:
                    first_raw = first_raw or cval
                    rebuilt.append(f"{name}={REDACTED}")
            elif item == REDACTED or self.allowed(item):
                rebuilt.append(item)
            else:
                first_raw = first_raw or item
                rebuilt.append(REDACTED)
        return ("; ".join(rebuilt), first_raw) if first_raw else None

    def _scrub_header_val(self, name: str, val: str, idx: int, loc: str) -> tuple[str, bool]:
        h_low = name.lower()
        if h_low in ("authorization", "proxy-authorization"):
            s = val.strip()
            if _is_redacted(s) or self.allowed(s):
                return val, False
            auth = _split_auth(s)
            if auth:
                prefix, rest = auth
                if rest in ("", REDACTED) or self.allowed(rest):
                    return val, False
                new_val = f"{prefix} {REDACTED}"
                self.record(idx, loc, rest, new_val)
                return new_val, True
            self.record(idx, loc, s, REDACTED)
            return REDACTED, True

        if h_low in ("cookie", "set-cookie"):
            res = self._scrub_cookie(val, is_set_cookie=(h_low == "set-cookie"))
            if res is None:
                return val, False
            self.record(idx, loc, res[1], REDACTED)
            return res[0], True

        if h_low in self.headers:
            if _is_redacted(val) or self.allowed(val):
                return val, False
            self.record(idx, loc, val, REDACTED)
            return REDACTED, True

        if h_low in SKIP_NON_SENSITIVE_HEADERS or self.allowed(val):
            return val, False
        return self.scrub_text(val, idx, loc)

    def scrub_headers(self, headers: Any, section: str, idx: int) -> None:
        if not isinstance(headers, dict):
            return
        for name, raw in list(headers.items()):
            if not isinstance(name, str):
                continue
            loc = f"{section}.headers.{name}"
            if isinstance(raw, list):
                for i, item in enumerate(raw):
                    if isinstance(item, str):
                        new_val, changed = self._scrub_header_val(name, item, idx, loc)
                        if changed:
                            raw[i] = new_val
            elif isinstance(raw, str):
                new_val, changed = self._scrub_header_val(name, raw, idx, loc)
                if changed:
                    headers[name] = new_val

    def _scrub_pairs(self, raw: str, keys: frozenset[str], idx: int, base_loc: str) -> str | None:
        pairs = parse_qsl(raw, keep_blank_values=True)
        if not pairs:
            return None
        out: list[tuple[str, str]] = []
        changed = False
        for k, v in pairs:
            loc = f"{base_loc}.{k}"
            if k.lower() in keys:
                if _is_redacted(v) or self.allowed(v):
                    out.append((k, v))
                else:
                    out.append((k, REDACTED))
                    self.record(idx, loc, v, REDACTED)
                    changed = True
            elif self.allowed(v):
                out.append((k, v))
            else:
                nv, hit = self.scrub_text(v, idx, loc)
                out.append((k, nv))
                changed = changed or hit
        return urlencode(out, safe="<>@") if changed else None

    def scrub_uri(self, request: dict[str, Any], idx: int) -> None:
        uri = request.get("uri")
        if not isinstance(uri, str) or not uri or self.allowed(uri):
            return
        parts = urlsplit(uri)
        netloc, path, query, changed = parts.netloc, parts.path, parts.query, False

        if parts.password is not None and not _is_redacted(parts.password) and not self.allowed(parts.password):
            host = parts.netloc.rsplit("@", 1)[-1]
            netloc = f"{parts.username or ''}:{REDACTED}@{host}"
            self.record(idx, "request.uri.userinfo", parts.password, REDACTED)
            changed = True

        webhook_base: str | None = None
        if parts.scheme and parts.netloc:
            base_uri = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
            hits: list[str] = []

            def repl_hook(m: re.Match[str]) -> str:
                if self.allowed(m.group(0)):
                    return m.group(0)
                hits.append(m.group(0))
                return REDACTED

            cand = _WEBHOOK_REGEX.sub(repl_hook, base_uri)
            if hits:
                webhook_base = cand
                changed = True
                for h in hits:
                    self.record(idx, "request.uri", h, REDACTED)

        if webhook_base is None and path and not self.allowed(path):
            new_path, hit = self.scrub_text(path, idx, "request.uri.path")
            if hit:
                path, changed = new_path, True

        if parts.query:
            new_q = self._scrub_pairs(parts.query, self.query_keys, idx, "request.uri.query")
            if new_q is not None:
                query, changed = new_q, True

        if changed:
            if webhook_base is not None:
                request["uri"] = urlunsplit(("", "", webhook_base, query, parts.fragment))
            else:
                request["uri"] = urlunsplit((parts.scheme, netloc, path, query, parts.fragment))

    def _scrub_json(self, node: Any, path: str, idx: int, force: bool = False) -> tuple[Any, bool]:
        if isinstance(node, dict):
            changed = False
            for k, v in list(node.items()):
                cpath = f"{path}.{k}"
                sens = force or (isinstance(k, str) and k.lower() in self.body_keys)
                if sens and isinstance(v, str):
                    auth = _split_auth(v) if isinstance(k, str) and k.lower() == "authorization" else None
                    auth_ok = bool(auth and (auth[1] in ("", REDACTED) or self.allowed(auth[1])))
                    if not (_is_redacted(v) or self.allowed(v) or auth_ok):
                        node[k] = REDACTED
                        self.record(idx, cpath, v, REDACTED)
                        changed = True
                elif sens and isinstance(v, (int, float)) and not isinstance(v, bool):
                    if not self.allowed(str(v)):
                        node[k] = REDACTED
                        self.record(idx, cpath, str(v), REDACTED)
                        changed = True
                else:
                    nv, ch = self._scrub_json(v, cpath, idx, force=sens)
                    if ch:
                        node[k] = nv
                        changed = True
            return node, changed

        if isinstance(node, list):
            changed = False
            for i, item in enumerate(node):
                nv, ch = self._scrub_json(item, f"{path}[{i}]", idx, force=force)
                if ch:
                    node[i] = nv
                    changed = True
            return node, changed

        if isinstance(node, str):
            if force:
                if _is_redacted(node) or self.allowed(node):
                    return node, False
                self.record(idx, path, node, REDACTED)
                return REDACTED, True
            if self.allowed(node):
                return node, False
            return self.scrub_text(node, idx, path)

        if force and isinstance(node, (int, float)) and not isinstance(node, bool):
            if self.allowed(str(node)):
                return node, False
            self.record(idx, path, str(node), REDACTED)
            return REDACTED, True
        return node, False

    def scrub_body(self, message: dict[str, Any], section: str, idx: int) -> None:
        raw_body = message.get("body")
        if raw_body is None:
            return
        wrapped = isinstance(raw_body, dict) and "string" in raw_body
        payload: Any = raw_body["string"] if wrapped else raw_body
        if not isinstance(payload, (str, bytes)):
            return

        is_bytes = isinstance(payload, bytes)
        if is_bytes:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                return
            old_len = len(payload)
        else:
            text = payload
            old_len = len(payload.encode("utf-8"))

        if not text or self.allowed(text):
            return

        headers = message.get("headers")
        ctype = ""
        if isinstance(headers, dict):
            for k, v in headers.items():
                if isinstance(k, str) and k.lower() == "content-type":
                    ctype = ("; ".join(str(x) for x in v if isinstance(x, str)) if isinstance(v, list) else str(v)).lower()
                    break

        loc = f"{section}.body"
        new_text, modified = text, False
        if "json" in ctype or text.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                obj, changed = self._scrub_json(parsed, loc, idx)
                if not changed:
                    return
                indent = 2 if "\n" in text.strip() else None
                new_text = json.dumps(obj, indent=indent, ensure_ascii=False)
                if indent is not None and text.endswith("\n") and not new_text.endswith("\n"):
                    new_text += "\n"
                modified = True

        if not modified and _is_form(text, ctype):
            rebuilt = self._scrub_pairs(text, self.body_keys, idx, loc)
            if rebuilt is None:
                return
            new_text, modified = rebuilt, True

        if not modified:
            new_text, modified = self.scrub_text(text, idx, loc)
        if not modified:
            return

        new_bytes = new_text.encode("utf-8")
        out_payload: str | bytes = new_bytes if is_bytes else new_text
        if wrapped:
            raw_body["string"] = out_payload
        else:
            message["body"] = out_payload

        if len(new_bytes) != old_len and isinstance(headers, dict):
            for k in list(headers.keys()):
                if isinstance(k, str) and k.lower() == "content-length":
                    headers[k] = [str(len(new_bytes))] if isinstance(headers[k], list) else str(len(new_bytes))


def scrub_cassette(data: dict[str, Any], file_path: str, config: ScrubConfig) -> ScrubResult:
    """Scrub sensitive headers, query params, bodies, and PII from a VCR cassette."""
    scrubbed = copy.deepcopy(data)
    ctx = _Scrubber(file_path, config)
    interactions = scrubbed.get("interactions")
    if isinstance(interactions, list):
        for idx, entry in enumerate(interactions):
            if not isinstance(entry, dict):
                continue
            req = entry.get("request")
            if isinstance(req, dict):
                ctx.scrub_uri(req, idx)
                ctx.scrub_headers(req.get("headers"), "request", idx)
                ctx.scrub_body(req, "request", idx)
            resp = entry.get("response")
            if isinstance(resp, dict):
                ctx.scrub_headers(resp.get("headers"), "response", idx)
                ctx.scrub_body(resp, "response", idx)

    return ScrubResult(
        modified=bool(ctx.findings),
        findings=ctx.findings,
        updated_data=scrubbed if ctx.findings else None,
    )


def format_cassette_diff(
    original_data: dict[str, Any],
    updated_data: dict[str, Any],
    fmt: str,
    file_path: str = "cassette",
) -> str:
    """Return a unified diff between two cassette mappings in YAML or JSON."""
    if fmt == "yaml":
        orig = yaml.safe_dump(original_data, sort_keys=False, allow_unicode=True)
        upd = yaml.safe_dump(updated_data, sort_keys=False, allow_unicode=True)
    elif fmt == "json":
        orig = json.dumps(original_data, indent=2, default=_json_default) + "\n"
        upd = json.dumps(updated_data, indent=2, default=_json_default) + "\n"
    else:
        raise ValueError(f"Unsupported cassette format: {fmt!r}")
    lines = list(
        difflib.unified_diff(
            orig.splitlines(),
            upd.splitlines(),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )
    )
    return "\n".join(lines) + "\n" if lines else ""
