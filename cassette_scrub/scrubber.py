from __future__ import annotations

import copy
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
    {
        "content-length",
        "content-type",
        "host",
    }
)

SENSITIVE_QUERY_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "refresh_token",
        "client_secret",
        "password",
        "passwd",
        "secret",
        "token",
        "auth_token",
        "id_token",
        "private_key",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_key",
        "x-api-key",
        "authorization",
        "session",
        "session_id",
        "cookie",
        "csrf_token",
        "key",
        "sig",
        "signature",
    }
)

SENSITIVE_BODY_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "api-key",
        "access_token",
        "refresh_token",
        "client_secret",
        "client_id",
        "password",
        "passwd",
        "secret",
        "secret_key",
        "private_key",
        "token",
        "auth_token",
        "id_token",
        "bearer_token",
        "session_token",
        "authorization",
        "aws_access_key_id",
        "aws_secret_access_key",
        "ssn",
        "credit_card",
    }
)

_TOKEN_REGEX = re.compile(
    "|".join(
        [
            r"sk-ant-[A-Za-z0-9_-]{6,}",
            r"(?<![A-Za-z0-9])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{10,}",
            r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{10,}|github_pat_[A-Za-z0-9_]{20,})",
            r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])",
            (
                r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\."
                r"(?:eyJ[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?"
                r"|[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,})"
            ),
        ]
    )
)

_EMAIL_REGEX = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
)

_FORM_BODY_REGEX = re.compile(
    r"^[A-Za-z0-9_.~%\[\]-]+=[^&\s]*(?:&[A-Za-z0-9_.~%\[\]-]+=[^&\s]*)*$"
)


def _safe_preview(raw: str, replacement: str = REDACTED) -> str:
    """Create a non-secret preview string describing a scrubbed value."""
    stripped = raw.strip()
    if len(stripped) > 6:
        return f"{stripped[:3]}... -> {replacement}"
    return f"*** -> {replacement}"


def _is_already_redacted(value: str) -> bool:
    """Return True if value is empty or already a redaction placeholder."""
    stripped = value.strip()
    return stripped in ("", REDACTED, REDACTED_EMAIL)


def _is_redacted_auth_value(value: str) -> bool:
    """Return True if an auth value is empty or already redacted."""
    stripped = value.strip()
    if stripped in ("", REDACTED, REDACTED_EMAIL):
        return True
    lower = stripped.lower()
    for prefix in ("bearer ", "basic "):
        if lower.startswith(prefix):
            rest = stripped[len(prefix) :].strip()
            return rest in ("", REDACTED)
    return False


def _scrub_text_patterns(
    text: str, scrub_pii: bool
) -> tuple[str, list[tuple[str, str]]]:
    """Scrub email (when enabled) and token regex matches in free text."""
    matches: list[tuple[str, str]] = []
    updated = text

    if scrub_pii:

        def _replace_email(match: re.Match[str]) -> str:
            matches.append((match.group(0), REDACTED_EMAIL))
            return REDACTED_EMAIL

        updated = _EMAIL_REGEX.sub(_replace_email, updated)

    def _replace_token(match: re.Match[str]) -> str:
        matches.append((match.group(0), REDACTED))
        return REDACTED

    updated = _TOKEN_REGEX.sub(_replace_token, updated)
    return updated, matches


def _record_pattern_findings(
    matches: list[tuple[str, str]],
    file_path: str,
    interaction_index: int,
    location: str,
    findings: list[Finding],
) -> None:
    """Append Finding entries for regex-matched values at location."""
    for raw_match, repl in matches:
        findings.append(
            Finding(
                file_path=file_path,
                interaction_index=interaction_index,
                location=location,
                preview=_safe_preview(raw_match, repl),
            )
        )


def _scrub_auth_header_value(value: str) -> tuple[str, str] | None:
    """Scrub an Authorization/Proxy-Authorization header preserving Bearer/Basic prefix."""
    stripped = value.strip()
    if not stripped or stripped == REDACTED:
        return None

    lower = stripped.lower()
    for prefix_kw in ("bearer ", "basic "):
        if lower.startswith(prefix_kw):
            prefix_len = len(prefix_kw)
            rest = stripped[prefix_len:].strip()
            if not rest or rest == REDACTED:
                return None
            new_val = f"{stripped[: prefix_len - 1]} {REDACTED}"
            return new_val, _safe_preview(rest, new_val)

    return REDACTED, _safe_preview(stripped, REDACTED)


def _scrub_cookie_header_value(value: str) -> tuple[str, str] | None:
    """Scrub Cookie header values while preserving cookie key names."""
    if _is_already_redacted(value):
        return None

    parts = value.split(";")
    new_parts: list[str] = []
    changed = False
    first_raw = ""

    for part in parts:
        item = part.strip()
        if not item:
            continue
        if "=" in item:
            name, cval = item.split("=", 1)
            cval_stripped = cval.strip()
            if cval_stripped in ("", REDACTED):
                new_parts.append(item)
            else:
                if not first_raw:
                    first_raw = cval_stripped
                new_parts.append(f"{name.strip()}={REDACTED}")
                changed = True
        else:
            if item == REDACTED:
                new_parts.append(item)
            else:
                if not first_raw:
                    first_raw = item
                new_parts.append(REDACTED)
                changed = True

    if not changed:
        return None
    return "; ".join(new_parts), _safe_preview(first_raw, REDACTED)


def _scrub_set_cookie_header_value(value: str) -> tuple[str, str] | None:
    """Scrub leading name=value in Set-Cookie while preserving attributes."""
    if _is_already_redacted(value):
        return None

    parts = value.split(";")
    first = parts[0].strip()
    attrs = [p.strip() for p in parts[1:] if p.strip()]

    if "=" in first:
        name, cval = first.split("=", 1)
        cval_stripped = cval.strip()
        if cval_stripped in ("", REDACTED):
            return None
        new_first = f"{name.strip()}={REDACTED}"
        raw_secret = cval_stripped
    else:
        if first in ("", REDACTED):
            return None
        new_first = REDACTED
        raw_secret = first

    rebuilt = "; ".join([new_first, *attrs])
    return rebuilt, _safe_preview(raw_secret, REDACTED)


def _scrub_single_header_string(
    header_name: str,
    value: str,
    sensitive_headers: frozenset[str],
    scrub_pii: bool,
    location: str,
    interaction_index: int,
    file_path: str,
    findings: list[Finding],
) -> tuple[str, bool]:
    """Scrub one header string and append Finding(s) if modified."""
    h_lower = header_name.lower()

    if h_lower in ("authorization", "proxy-authorization"):
        res = _scrub_auth_header_value(value)
        if res is None:
            return value, False
        new_val, preview = res
        findings.append(
            Finding(
                file_path=file_path,
                interaction_index=interaction_index,
                location=location,
                preview=preview,
            )
        )
        return new_val, True

    if h_lower == "cookie":
        res = _scrub_cookie_header_value(value)
        if res is None:
            return value, False
        new_val, preview = res
        findings.append(
            Finding(
                file_path=file_path,
                interaction_index=interaction_index,
                location=location,
                preview=preview,
            )
        )
        return new_val, True

    if h_lower == "set-cookie":
        res = _scrub_set_cookie_header_value(value)
        if res is None:
            return value, False
        new_val, preview = res
        findings.append(
            Finding(
                file_path=file_path,
                interaction_index=interaction_index,
                location=location,
                preview=preview,
            )
        )
        return new_val, True

    if h_lower in sensitive_headers:
        if _is_already_redacted(value):
            return value, False
        findings.append(
            Finding(
                file_path=file_path,
                interaction_index=interaction_index,
                location=location,
                preview=_safe_preview(value, REDACTED),
            )
        )
        return REDACTED, True

    if h_lower in SKIP_NON_SENSITIVE_HEADERS:
        return value, False

    new_val, matches = _scrub_text_patterns(value, scrub_pii)
    if not matches:
        return value, False
    _record_pattern_findings(matches, file_path, interaction_index, location, findings)
    return new_val, True


def _scrub_headers(
    headers: Any,
    section: str,
    interaction_index: int,
    file_path: str,
    sensitive_headers: frozenset[str],
    scrub_pii: bool,
    findings: list[Finding],
) -> None:
    """Scrub request or response headers in place."""
    if not isinstance(headers, dict):
        return

    for header_name, raw_values in list(headers.items()):
        if not isinstance(header_name, str):
            continue
        location = f"{section}.headers.{header_name}"

        if isinstance(raw_values, list):
            for i, item in enumerate(raw_values):
                if not isinstance(item, str):
                    continue
                new_item, changed = _scrub_single_header_string(
                    header_name=header_name,
                    value=item,
                    sensitive_headers=sensitive_headers,
                    scrub_pii=scrub_pii,
                    location=location,
                    interaction_index=interaction_index,
                    file_path=file_path,
                    findings=findings,
                )
                if changed:
                    raw_values[i] = new_item
        elif isinstance(raw_values, str):
            new_item, changed = _scrub_single_header_string(
                header_name=header_name,
                value=raw_values,
                sensitive_headers=sensitive_headers,
                scrub_pii=scrub_pii,
                location=location,
                interaction_index=interaction_index,
                file_path=file_path,
                findings=findings,
            )
            if changed:
                headers[header_name] = new_item


def _scrub_urlencoded_pairs(
    raw: str,
    sensitive_keys: frozenset[str],
    base_location: str,
    interaction_index: int,
    file_path: str,
    scrub_pii: bool,
    findings: list[Finding],
) -> str | None:
    """Scrub urlencoded key/value pairs; return rebuilt string only if modified."""
    pairs = parse_qsl(raw, keep_blank_values=True)
    if not pairs:
        return None

    updated_pairs: list[tuple[str, str]] = []
    modified = False

    for key, val in pairs:
        location = f"{base_location}.{key}"
        if key.lower() in sensitive_keys:
            if _is_already_redacted(val):
                updated_pairs.append((key, val))
            else:
                updated_pairs.append((key, REDACTED))
                modified = True
                findings.append(
                    Finding(
                        file_path=file_path,
                        interaction_index=interaction_index,
                        location=location,
                        preview=_safe_preview(val, REDACTED),
                    )
                )
        else:
            new_val, matches = _scrub_text_patterns(val, scrub_pii)
            if matches:
                updated_pairs.append((key, new_val))
                modified = True
                _record_pattern_findings(
                    matches, file_path, interaction_index, location, findings
                )
            else:
                updated_pairs.append((key, val))

    if not modified:
        return None
    return urlencode(updated_pairs, safe="<>@")


def _scrub_uri(
    request: dict[str, Any],
    interaction_index: int,
    file_path: str,
    sensitive_query_keys: frozenset[str],
    scrub_pii: bool,
    findings: list[Finding],
) -> None:
    """Scrub sensitive query parameters (and URI userinfo/path tokens) on request['uri']."""
    uri = request.get("uri")
    if not isinstance(uri, str) or not uri:
        return

    parts = urlsplit(uri)
    new_netloc = parts.netloc
    new_path = parts.path
    new_query = parts.query
    uri_modified = False

    if parts.password is not None and not _is_already_redacted(parts.password):
        host_part = parts.netloc.rsplit("@", 1)[-1]
        user_part = parts.username or ""
        new_netloc = f"{user_part}:{REDACTED}@{host_part}"
        findings.append(
            Finding(
                file_path=file_path,
                interaction_index=interaction_index,
                location="request.uri.userinfo",
                preview=_safe_preview(parts.password, REDACTED),
            )
        )
        uri_modified = True

    if parts.path:
        scrubbed_path, path_matches = _scrub_text_patterns(parts.path, scrub_pii)
        if path_matches:
            new_path = scrubbed_path
            uri_modified = True
            _record_pattern_findings(
                path_matches, file_path, interaction_index, "request.uri.path", findings
            )

    if parts.query:
        rebuilt_query = _scrub_urlencoded_pairs(
            raw=parts.query,
            sensitive_keys=sensitive_query_keys,
            base_location="request.uri.query",
            interaction_index=interaction_index,
            file_path=file_path,
            scrub_pii=scrub_pii,
            findings=findings,
        )
        if rebuilt_query is not None:
            new_query = rebuilt_query
            uri_modified = True

    if uri_modified:
        request["uri"] = urlunsplit(
            (parts.scheme, new_netloc, new_path, new_query, parts.fragment)
        )


def _get_content_type(headers: Any) -> str:
    """Return lowercased Content-Type header value if present."""
    if not isinstance(headers, dict):
        return ""
    for key, val in headers.items():
        if isinstance(key, str) and key.lower() == "content-type":
            if isinstance(val, list):
                return "; ".join(str(v) for v in val if isinstance(v, str)).lower()
            if isinstance(val, str):
                return val.lower()
    return ""


def _update_content_length(headers: Any, new_byte_len: int) -> None:
    """Update existing Content-Length header case-insensitively while keeping key casing."""
    if not isinstance(headers, dict):
        return
    for key in list(headers.keys()):
        if isinstance(key, str) and key.lower() == "content-length":
            if isinstance(headers[key], list):
                headers[key] = [str(new_byte_len)]
            elif isinstance(headers[key], str):
                headers[key] = str(new_byte_len)


def _is_form_urlencoded(text: str, content_type: str) -> bool:
    """Return True if body should be treated as application/x-www-form-urlencoded."""
    if "=" not in text:
        return False
    if "application/x-www-form-urlencoded" in content_type:
        return True
    if any(
        blocked in content_type
        for blocked in ("json", "xml", "html", "javascript", "octet-stream")
    ):
        return False
    stripped = text.strip()
    if not stripped or stripped.startswith(("{", "[", "<")):
        return False
    return bool(_FORM_BODY_REGEX.match(stripped))


def _scrub_json_node(
    node: Any,
    path: str,
    interaction_index: int,
    file_path: str,
    sensitive_body_keys: frozenset[str],
    scrub_pii: bool,
    findings: list[Finding],
    force_redact: bool = False,
) -> tuple[Any, bool]:
    """Recursively scrub a decoded JSON value (dict, list, or scalar)."""
    if isinstance(node, dict):
        changed = False
        for key, val in list(node.items()):
            child_path = f"{path}.{key}"
            is_sensitive = force_redact or (
                isinstance(key, str) and key.lower() in sensitive_body_keys
            )
            if is_sensitive:
                if val is None or isinstance(val, bool):
                    continue
                if isinstance(val, str):
                    if _is_already_redacted(val) or (
                        isinstance(key, str)
                        and key.lower() == "authorization"
                        and _is_redacted_auth_value(val)
                    ):
                        continue
                    node[key] = REDACTED
                    changed = True
                    findings.append(
                        Finding(
                            file_path=file_path,
                            interaction_index=interaction_index,
                            location=child_path,
                            preview=_safe_preview(val, REDACTED),
                        )
                    )
                elif isinstance(val, (int, float)):
                    node[key] = REDACTED
                    changed = True
                    findings.append(
                        Finding(
                            file_path=file_path,
                            interaction_index=interaction_index,
                            location=child_path,
                            preview=_safe_preview(str(val), REDACTED),
                        )
                    )
                elif isinstance(val, (dict, list)):
                    new_child, child_changed = _scrub_json_node(
                        val,
                        child_path,
                        interaction_index,
                        file_path,
                        sensitive_body_keys,
                        scrub_pii,
                        findings,
                        force_redact=True,
                    )
                    if child_changed:
                        node[key] = new_child
                        changed = True
            else:
                new_child, child_changed = _scrub_json_node(
                    val,
                    child_path,
                    interaction_index,
                    file_path,
                    sensitive_body_keys,
                    scrub_pii,
                    findings,
                    force_redact=False,
                )
                if child_changed:
                    node[key] = new_child
                    changed = True
        return node, changed

    if isinstance(node, list):
        changed = False
        for idx, item in enumerate(node):
            item_path = f"{path}[{idx}]"
            new_item, item_changed = _scrub_json_node(
                item,
                item_path,
                interaction_index,
                file_path,
                sensitive_body_keys,
                scrub_pii,
                findings,
                force_redact=force_redact,
            )
            if item_changed:
                node[idx] = new_item
                changed = True
        return node, changed

    if isinstance(node, str):
        if force_redact:
            if _is_already_redacted(node):
                return node, False
            findings.append(
                Finding(
                    file_path=file_path,
                    interaction_index=interaction_index,
                    location=path,
                    preview=_safe_preview(node, REDACTED),
                )
            )
            return REDACTED, True

        new_str, matches = _scrub_text_patterns(node, scrub_pii)
        if not matches:
            return node, False
        _record_pattern_findings(
            matches, file_path, interaction_index, path, findings
        )
        return new_str, True

    if force_redact and isinstance(node, (int, float)) and not isinstance(node, bool):
        findings.append(
            Finding(
                file_path=file_path,
                interaction_index=interaction_index,
                location=path,
                preview=_safe_preview(str(node), REDACTED),
            )
        )
        return REDACTED, True

    return node, False


def _scrub_body_text(
    text: str,
    content_type: str,
    section: str,
    interaction_index: int,
    file_path: str,
    sensitive_body_keys: frozenset[str],
    scrub_pii: bool,
    findings: list[Finding],
) -> tuple[str, bool]:
    """Scrub a UTF-8 body string (JSON, form-urlencoded, or plain text)."""
    if not text:
        return text, False

    stripped = text.lstrip()
    base_location = f"{section}.body"

    if "json" in content_type or stripped.startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = None

        if isinstance(parsed, (dict, list)):
            scrubbed_obj, changed = _scrub_json_node(
                parsed,
                base_location,
                interaction_index,
                file_path,
                sensitive_body_keys,
                scrub_pii,
                findings,
            )
            if not changed:
                return text, False
            indent = 2 if "\n" in text.strip() else None
            dumped = json.dumps(scrubbed_obj, indent=indent, ensure_ascii=False)
            if indent is not None and text.endswith("\n") and not dumped.endswith("\n"):
                dumped += "\n"
            return dumped, True

    if _is_form_urlencoded(text, content_type):
        rebuilt_form = _scrub_urlencoded_pairs(
            raw=text,
            sensitive_keys=sensitive_body_keys,
            base_location=base_location,
            interaction_index=interaction_index,
            file_path=file_path,
            scrub_pii=scrub_pii,
            findings=findings,
        )
        if rebuilt_form is not None:
            return rebuilt_form, True
        return text, False

    new_text, matches = _scrub_text_patterns(text, scrub_pii)
    if not matches:
        return text, False
    _record_pattern_findings(
        matches, file_path, interaction_index, base_location, findings
    )
    return new_text, True


def _scrub_body(
    message: dict[str, Any],
    section: str,
    interaction_index: int,
    file_path: str,
    sensitive_body_keys: frozenset[str],
    scrub_pii: bool,
    findings: list[Finding],
) -> None:
    """Scrub request or response body (str, bytes, or {'string': ...}) and sync Content-Length."""
    raw_body = message.get("body")
    if raw_body is None:
        return

    is_wrapped = isinstance(raw_body, dict) and "string" in raw_body
    payload: Any = raw_body["string"] if is_wrapped else raw_body

    if payload is None:
        return

    is_bytes = isinstance(payload, bytes)
    if is_bytes:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            return
        old_byte_len = len(payload)
    elif isinstance(payload, str):
        text = payload
        old_byte_len = len(payload.encode("utf-8"))
    else:
        return

    headers = message.get("headers")
    content_type = _get_content_type(headers)
    new_text, modified = _scrub_body_text(
        text=text,
        content_type=content_type,
        section=section,
        interaction_index=interaction_index,
        file_path=file_path,
        sensitive_body_keys=sensitive_body_keys,
        scrub_pii=scrub_pii,
        findings=findings,
    )
    if not modified:
        return

    new_bytes = new_text.encode("utf-8")
    updated_payload: str | bytes = new_bytes if is_bytes else new_text
    if is_wrapped:
        raw_body["string"] = updated_payload
    else:
        message["body"] = updated_payload

    if len(new_bytes) != old_byte_len:
        _update_content_length(headers, len(new_bytes))


def scrub_cassette(
    data: dict[str, Any], file_path: str, config: ScrubConfig
) -> ScrubResult:
    """Scrub sensitive headers, query params, bodies, and PII from a VCR cassette dict."""
    scrubbed = copy.deepcopy(data)
    findings: list[Finding] = []

    sensitive_headers = SENSITIVE_HEADERS | {
        h.strip().lower() for h in config.extra_headers if h.strip()
    }
    sensitive_query_keys = SENSITIVE_QUERY_KEYS | {
        k.strip().lower() for k in config.extra_query_keys if k.strip()
    }
    sensitive_body_keys = SENSITIVE_BODY_KEYS | {
        k.strip().lower() for k in config.extra_body_keys if k.strip()
    }

    interactions = scrubbed.get("interactions")
    if isinstance(interactions, list):
        for idx, interaction in enumerate(interactions):
            if not isinstance(interaction, dict):
                continue

            request = interaction.get("request")
            if isinstance(request, dict):
                _scrub_uri(
                    request=request,
                    interaction_index=idx,
                    file_path=file_path,
                    sensitive_query_keys=sensitive_query_keys,
                    scrub_pii=config.scrub_pii,
                    findings=findings,
                )
                _scrub_headers(
                    headers=request.get("headers"),
                    section="request",
                    interaction_index=idx,
                    file_path=file_path,
                    sensitive_headers=sensitive_headers,
                    scrub_pii=config.scrub_pii,
                    findings=findings,
                )
                _scrub_body(
                    message=request,
                    section="request",
                    interaction_index=idx,
                    file_path=file_path,
                    sensitive_body_keys=sensitive_body_keys,
                    scrub_pii=config.scrub_pii,
                    findings=findings,
                )

            response = interaction.get("response")
            if isinstance(response, dict):
                _scrub_headers(
                    headers=response.get("headers"),
                    section="response",
                    interaction_index=idx,
                    file_path=file_path,
                    sensitive_headers=sensitive_headers,
                    scrub_pii=config.scrub_pii,
                    findings=findings,
                )
                _scrub_body(
                    message=response,
                    section="response",
                    interaction_index=idx,
                    file_path=file_path,
                    sensitive_body_keys=sensitive_body_keys,
                    scrub_pii=config.scrub_pii,
                    findings=findings,
                )

    modified = bool(findings)
    return ScrubResult(
        modified=modified,
        findings=findings,
        updated_data=scrubbed if modified else None,
    )
