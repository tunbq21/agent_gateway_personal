"""Local Windows runner for TunAI Personal Gateway (UI on :15000 + Data Plane on :3000).

Serves the TunAI UI (`ui/dist`), exposes Control Plane config and resource
CRUD APIs, evaluates CEL expressions, enforces HS256 JWT / Virtual API Key / Budget /
Guardrails / Transformation / Rate-Limit policies on `:3000`, and proxies MCP, LLM,
and HTTP route traffic to configured upstream servers.
"""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import hashlib
import hmac
import json
import math
import os
import random
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    import httpx2 as httpx
except ImportError:
    import httpx  # type: ignore[no-redef]
import uvicorn
import yaml
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"
UI_DIST_DIR = BASE_DIR / "ui" / "dist"
DEFAULT_MCP_TARGET = "http://127.0.0.1:8000/mcp"
DEFAULT_MCP_TARGET_NAME = "mcp-server"
DEFAULT_JWT_SECRET = os.environ.get("GATEWAY_JWT_SECRET") or secrets.token_urlsafe(32)
UI_READ_ONLY = os.environ.get("UI_READ_ONLY", "").lower() == "true"
MAX_LOGS = 500
DELIMITER = "_"

REQUEST_LOGS: list[dict[str, Any]] = []
LOG_SUBSCRIBERS: list[asyncio.Queue[dict[str, Any]]] = []
_RATE_BUCKETS: dict[tuple[str, str], tuple[float, float]] = {}
_BUDGET_USAGE: dict[tuple[str, str], float] = {}
_MCP_MULTIPLEX_SESSIONS: dict[str, dict[str, str]] = {}

SUPPORTED_RESOURCE_KINDS = {
    "modelCatalog",
    "llm.provider",
    "llm.model",
    "llm.virtualModel",
    "llm.apiKey",
    "llm.policy",
    "mcp.target",
    "mcp.policy",
    "llm.settings",
    "mcp.settings",
    "traffic.gateway",
    "traffic.route",
    "traffic.tcpRoute",
    "ui.policy",
    "frontend.policy",
}

MODEL_PRICING_PER_1M: dict[str, dict[str, tuple[float, float]]] = {
    "openai": {
        "gpt-4o": (2.50, 10.00),
        "gpt-4o-mini": (0.15, 0.60),
        "gpt-4.1": (2.00, 8.00),
    },
    "anthropic": {
        "claude-3-7-sonnet-latest": (3.00, 15.00),
        "claude-3-5-haiku-latest": (0.80, 4.00),
    },
    "gemini": {
        "gemini-2.5-flash": (0.15, 0.60),
        "gemini-2.5-pro": (1.25, 10.00),
    },
}

_BUILTIN_PII_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "email",
        "EMAIL_ADDRESS",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "<EMAIL_ADDRESS>",
    ),
    (
        "ssn",
        "US_SSN",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "<US_SSN>",
    ),
    (
        "caSin",
        "CA_SIN",
        re.compile(r"\b\d{3}-\d{3}-\d{3}\b"),
        "<CA_SIN>",
    ),
    (
        "creditCard",
        "CREDIT_CARD",
        re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))(?:[ -]?\d{4}){2,3}\d{0,4}\b"),
        "<CREDIT_CARD>",
    ),
    (
        "phoneNumber",
        "PHONE_NUMBER",
        re.compile(r"(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]\d{3,4}[\s.-]\d{3,4}\b"),
        "<PHONE_NUMBER>",
    ),
]


@dataclass
class GatewayLogRecord:
    """Structured telemetry record for MCP, LLM, and HTTP gateway requests."""

    operation_name: str
    provider_name: str
    request_model: str
    response_model: str
    started_at: str
    duration_ms: int
    http_status: int
    error: str | None
    user: str
    group: str
    user_agent: str
    extra_attributes: dict[str, Any]
    request_payload: Any
    response_preview: Any
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost: float = 0.0
    trace_id: str | None = None


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_iso_ts(raw: str | None) -> float | None:
    if not raw:
        return None
    try:
        text = str(raw).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None


def _expand_env_value(val: Any) -> Any:
    if isinstance(val, str):
        return os.path.expandvars(re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", lambda m: os.environ.get(m.group(1), m.group(0)), val))
    return val


def load_config_dict() -> dict[str, Any]:
    """Load `config.yaml` as a dict, returning `{}` when empty or missing."""
    if not CONFIG_PATH.exists():
        return {}
    raw = CONFIG_PATH.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    return data if isinstance(data, dict) else {}


def save_config_dict(cfg: dict[str, Any]) -> None:
    """Persist dict cleanly to `config.yaml`."""
    dumped = yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True)
    CONFIG_PATH.write_text(dumped, encoding="utf-8")


def _mcp_targets(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    targets = (cfg.get("mcp") or {}).get("targets") or []
    return [t for t in targets if isinstance(t, dict) and t.get("name")]


def resolve_mcp_target_url() -> str:
    """Resolve the primary upstream MCP host URL from `config.yaml`."""
    for target in _mcp_targets(load_config_dict()):
        url = _extract_target_url(target)
        if url:
            return url
    return DEFAULT_MCP_TARGET


def _extract_target_url(target: dict[str, Any]) -> str | None:
    for kind in ("mcp", "sse"):
        cfg = target.get(kind)
        if isinstance(cfg, dict) and cfg.get("host"):
            host = str(cfg["host"])
            port = cfg.get("port")
            path = cfg.get("path") or ("/sse" if kind == "sse" else "")
            if host.startswith("http://") or host.startswith("https://"):
                return host.rstrip("/") + (path if path and not host.endswith(path) else "")
            port_part = f":{port}" if port else ""
            return f"http://{host}{port_part}{path}"
    return None


def resolve_mcp_target_name() -> str:
    """Resolve the primary MCP target name from `config.yaml`."""
    targets = _mcp_targets(load_config_dict())
    if targets:
        return str(targets[0]["name"])
    return DEFAULT_MCP_TARGET_NAME


def resolve_mcp_port() -> int:
    """Resolve the gateway listen port from `config.yaml`, defaulting to 3000."""
    cfg = load_config_dict()
    mcp_port = (cfg.get("mcp") or {}).get("port")
    if isinstance(mcp_port, int):
        return mcp_port
    gateways = cfg.get("gateways") or {}
    if isinstance(gateways, dict):
        for gw in gateways.values():
            if isinstance(gw, dict) and isinstance(gw.get("port"), int):
                return gw["port"]
    return 3000


def resolve_mcp_authz_rules(cfg: dict[str, Any] | None = None) -> list[str]:
    """Read `mcp.policies.mcpAuthorization.rules` from config."""
    cfg = cfg if cfg is not None else load_config_dict()
    policies = (cfg.get("mcp") or {}).get("policies") or {}
    authz = policies.get("mcpAuthorization") or {}
    rules = authz.get("rules") or []
    if not isinstance(rules, list):
        return []
    out: list[str] = []
    for r in rules:
        if isinstance(r, str):
            out.append(r)
        elif isinstance(r, dict) and isinstance(r.get("allow"), str):
            out.append(r["allow"])
    return out


def _parse_duration_seconds(raw: Any) -> float:
    """Parse duration string like '60s', '5m', '1h', or numeric seconds."""
    if isinstance(raw, (int, float)):
        return max(float(raw), 0.1)
    text = str(raw).strip().lower()
    if text.endswith("ms"):
        return max(float(text[:-2]) / 1000.0, 0.05)
    if text.endswith("s"):
        return max(float(text[:-1]), 0.1)
    if text.endswith("m"):
        return max(float(text[:-1]) * 60.0, 0.1)
    if text.endswith("h"):
        return max(float(text[:-1]) * 3600.0, 0.1)
    if text.endswith("d"):
        return max(float(text[:-1]) * 86400.0, 0.1)
    return max(float(text), 0.1)


def check_rate_limit(client_key: str, rl_list: Any, scope: str = "mcp") -> bool:
    """Enforce `localRateLimit` rules using a token bucket. Returns True if allowed."""
    if not isinstance(rl_list, list) or not rl_list:
        return True

    now = time.monotonic()
    for idx, rule in enumerate(rl_list):
        if not isinstance(rule, dict):
            continue
        max_tokens = float(rule.get("maxTokens") or 0)
        tokens_per_fill = float(rule.get("tokensPerFill") or max_tokens)
        interval_sec = _parse_duration_seconds(rule.get("fillInterval") or "60s")
        if max_tokens <= 0:
            return False

        sig = f"{scope}:{idx}:{max_tokens}:{tokens_per_fill}:{interval_sec}"
        bucket_key = (sig, client_key)
        tokens, last_ts = _RATE_BUCKETS.get(bucket_key, (max_tokens, now))
        elapsed = max(0.0, now - last_ts)
        refill = (elapsed / interval_sec) * tokens_per_fill
        tokens = min(max_tokens, tokens + refill)
        if tokens < 1.0:
            _RATE_BUCKETS[bucket_key] = (tokens, now)
            return False
        _RATE_BUCKETS[bucket_key] = (tokens - 1.0, now)
    return True


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def sign_jwt_hs256(claims: dict[str, Any], secret: str = DEFAULT_JWT_SECRET) -> str:
    """Create an HS256-signed JWT string for local testing and policy verification."""
    header_b64 = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(sig)}"


def decode_jwt_payload(auth_header: str | None, secret: str = DEFAULT_JWT_SECRET) -> dict[str, Any]:
    """Verify HS256 JWT signature and time claims, returning claims dict or `{}` if invalid."""
    if not auth_header:
        return {}
    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return {}
    token = parts[1].strip()
    segments = token.split(".")
    if len(segments) != 3:
        return {}
    header_b64, payload_b64, sig_b64 = segments
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return {}
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        provided_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return {}
        claims = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if not isinstance(claims, dict):
            return {}
        now = time.time()
        if "exp" in claims:
            exp_val = claims["exp"]
            if not isinstance(exp_val, (int, float)) or isinstance(exp_val, bool) or float(exp_val) < now:
                return {}
        if "nbf" in claims:
            nbf_val = claims["nbf"]
            if not isinstance(nbf_val, (int, float)) or isinstance(nbf_val, bool) or float(nbf_val) > now + 5:
                return {}
        return claims
    except Exception:
        return {}


def _validate_jwt_policy(
    auth_header: str | None,
    jwt_policy: Any,
) -> tuple[bool, dict[str, Any]]:
    """Validate incoming Authorization bearer against `jwtAuth` policy if configured."""
    claims = decode_jwt_payload(auth_header)
    if not isinstance(jwt_policy, dict) or not jwt_policy:
        return True, claims
    mode = str(jwt_policy.get("mode") or "strict").lower()
    issuer = jwt_policy.get("issuer")
    audiences = jwt_policy.get("audiences") or []

    if not auth_header:
        return (mode in ("optional", "permissive")), {}
    if not claims:
        return (mode == "permissive"), {}
    if issuer and claims.get("iss") != issuer:
        return False, {}
    if audiences:
        aud = claims.get("aud")
        aud_list = aud if isinstance(aud, list) else ([aud] if aud else [])
        if not any(a in audiences for a in aud_list):
            return False, {}
    return True, claims


def render_ui_index_html() -> str:
    """Read `ui/dist/index.html` and inject `<base href="/ui/">`."""
    index_file = UI_DIST_DIR / "index.html"
    if not index_file.exists():
        return "<html><body><h1>TunAI UI build missing</h1><p>Run pnpm build inside ui/.</p></body></html>"
    html = index_file.read_text(encoding="utf-8")
    if "<base " not in html:
        html = html.replace("<head>", '<head>\n\t\t<base href="/ui/">', 1)
    return html


# ---------------------------------------------------------------------------
# CEL Expression Evaluator
# ---------------------------------------------------------------------------

_CEL_TOKEN_RE = re.compile(
    r"""
    \s*(?:
        (?P<OP>&&|\|\||==|!=|<=|>=|[!<>\(\)\[\]\{\},\.\?:\+\-\*/%])
      | (?P<STR>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
      | (?P<NUM>\d+(?:\.\d+)?)
      | (?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)
    )
    """,
    re.VERBOSE,
)


def _ensure_numeric(val: Any, op: str) -> int | float:
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise ValueError(f"Operator {op!r} requires numeric operand, got {type(val).__name__}")
    return val


class _CelParser:
    """Recursive-descent evaluator for CEL authorization, routing, and playground expressions."""

    def __init__(self, expr: str, data: dict[str, Any]) -> None:
        self.tokens: list[tuple[str, str]] = []
        pos = 0
        for m in _CEL_TOKEN_RE.finditer(expr):
            if m.start() != pos and expr[pos : m.start()].strip():
                raise ValueError(f"Unexpected syntax near: {expr[pos:m.start() + 12]!r}")
            pos = m.end()
            kind = m.lastgroup or ""
            self.tokens.append((kind, m.group(kind)))
        if pos < len(expr) and expr[pos:].strip():
            raise ValueError(f"Unexpected syntax near: {expr[pos:]!r}")
        if not self.tokens:
            raise ValueError("Empty CEL expression")
        self.idx = 0
        self.data = data

    def peek(self, offset: int = 0) -> tuple[str, str] | None:
        pos = self.idx + offset
        return self.tokens[pos] if 0 <= pos < len(self.tokens) else None

    def consume(self, expected_val: str | None = None) -> tuple[str, str]:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of expression")
        if expected_val is not None and tok[1] != expected_val:
            raise ValueError(f"Expected {expected_val!r}, got {tok[1]!r}")
        self.idx += 1
        return tok

    def parse(self) -> Any:
        val = self.parse_ternary()
        if self.peek() is not None:
            raise ValueError(f"Unexpected token: {self.peek()!r}")
        return val

    def parse_ternary(self) -> Any:
        cond = self.parse_or()
        if self.peek() == ("OP", "?"):
            self.consume("?")
            true_branch = self.parse_ternary()
            self.consume(":")
            false_branch = self.parse_ternary()
            return true_branch if bool(cond) else false_branch
        return cond

    def parse_or(self) -> Any:
        left = self.parse_and()
        while self.peek() == ("OP", "||"):
            self.consume()
            right = self.parse_and()
            left = bool(left) or bool(right)
        return left

    def parse_and(self) -> Any:
        left = self.parse_cmp()
        while self.peek() == ("OP", "&&"):
            self.consume()
            right = self.parse_cmp()
            left = bool(left) and bool(right)
        return left

    def parse_cmp(self) -> Any:
        left = self.parse_add()
        tok = self.peek()
        if tok and (tok[1] in ("==", "!=", "<", "<=", ">", ">=") or tok == ("IDENT", "in")):
            op = self.consume()[1]
            right = self.parse_add()
            if op == "==":
                if isinstance(left, bool) != isinstance(right, bool):
                    return False
                return left == right
            if op == "!=":
                if isinstance(left, bool) != isinstance(right, bool):
                    return True
                return left != right
            if op == "in":
                if isinstance(right, (list, dict, str)):
                    return left in right
                return False
            if left is None or right is None:
                return False
            if op == "<":
                return left < right
            if op == "<=":
                return left <= right
            if op == ">":
                return left > right
            if op == ">=":
                return left >= right
        return left

    def parse_add(self) -> Any:
        left = self.parse_mul()
        while self.peek() in (("OP", "+"), ("OP", "-")):
            op = self.consume()[1]
            right = self.parse_mul()
            if op == "+":
                if isinstance(left, str) and isinstance(right, str):
                    left = left + right
                elif isinstance(left, list) and isinstance(right, list):
                    left = left + right
                else:
                    left = _ensure_numeric(left, "+") + _ensure_numeric(right, "+")
            else:
                left = _ensure_numeric(left, "-") - _ensure_numeric(right, "-")
        return left

    def parse_mul(self) -> Any:
        left = self.parse_unary()
        while self.peek() in (("OP", "*"), ("OP", "/"), ("OP", "%")):
            op = self.consume()[1]
            right = self.parse_unary()
            lnum = _ensure_numeric(left, op)
            rnum = _ensure_numeric(right, op)
            if op == "*":
                left = lnum * rnum
            elif op == "/":
                if rnum == 0:
                    raise ValueError("Division by zero")
                left = lnum // rnum if isinstance(lnum, int) and isinstance(rnum, int) else lnum / rnum
            else:
                if rnum == 0:
                    raise ValueError("Modulo by zero")
                left = lnum % rnum
        return left

    def parse_unary(self) -> Any:
        if self.peek() == ("OP", "!"):
            self.consume()
            return not bool(self.parse_unary())
        if self.peek() == ("OP", "-"):
            self.consume()
            val = self.parse_unary()
            return -_ensure_numeric(val, "-")
        return self.parse_postfix()

    def _resolve_has(self) -> bool:
        self.consume("(")
        parts = [self.consume()[1]]
        while self.peek() == ("OP", "."):
            self.consume()
            parts.append(self.consume()[1])
        self.consume(")")
        cur: Any = self.data
        for part in parts:
            if isinstance(cur, dict) and part in cur and cur[part] is not None:
                cur = cur[part]
            else:
                return False
        return True

    def _resolve_builtin_call(self, name: str) -> Any:
        self.consume("(")
        args: list[Any] = []
        if self.peek() != ("OP", ")"):
            while True:
                args.append(self.parse_ternary())
                if self.peek() == ("OP", ","):
                    self.consume(",")
                    continue
                break
        self.consume(")")
        if name == "size":
            val = args[0] if args else None
            return len(val) if isinstance(val, (str, list, dict)) else 0
        if name == "default":
            if len(args) != 2:
                raise ValueError("default() requires 2 arguments")
            return args[1] if args[0] is None else args[0]
        if name == "string":
            return "" if not args or args[0] is None else str(args[0])
        if name == "int":
            return int(args[0]) if args and args[0] is not None else 0
        if name == "double":
            return float(args[0]) if args and args[0] is not None else 0.0
        if name == "bool":
            return bool(args[0]) if args else False
        raise ValueError(f"Unsupported function: {name}()")

    def parse_postfix(self) -> Any:
        tok = self.peek()
        if tok == ("IDENT", "has") and self.peek(1) == ("OP", "("):
            self.consume()
            return self._resolve_has()
        if tok and tok[0] == "IDENT" and self.peek(1) == ("OP", "("):
            self.consume()
            return self._resolve_builtin_call(tok[1])

        val = self.parse_primary()
        while True:
            nxt = self.peek()
            if nxt == ("OP", "."):
                self.consume()
                member = self.consume()[1]
                if self.peek() == ("OP", "("):
                    self.consume("(")
                    arg = self.parse_ternary() if self.peek() != ("OP", ")") else None
                    self.consume(")")
                    if member == "size":
                        val = len(val) if isinstance(val, (str, list, dict)) else 0
                        continue
                    sval = "" if val is None else str(val)
                    if member == "lowerAscii":
                        val = sval.lower()
                    elif member == "upperAscii":
                        val = sval.upper()
                    elif member == "trim":
                        val = sval.strip()
                    elif member == "split":
                        sep = "" if arg is None else str(arg)
                        val = sval.split(sep) if sep else list(sval)
                    else:
                        sarg = "" if arg is None else str(arg)
                        if member == "contains":
                            val = sarg in sval
                        elif member == "startsWith":
                            val = sval.startswith(sarg)
                        elif member == "endsWith":
                            val = sval.endswith(sarg)
                        elif member == "matches":
                            val = bool(re.search(sarg, sval))
                        else:
                            raise ValueError(f"Unsupported method: .{member}()")
                else:
                    val = val.get(member) if isinstance(val, dict) else None
            elif nxt == ("OP", "["):
                self.consume("[")
                key = self.parse_ternary()
                self.consume("]")
                if isinstance(val, dict):
                    val = val.get(key)
                elif isinstance(val, list) and isinstance(key, int) and 0 <= key < len(val):
                    val = val[key]
                else:
                    val = None
            else:
                break
        return val

    def parse_primary(self) -> Any:
        tok = self.peek()
        if tok is None:
            raise ValueError("Unexpected end of expression")
        kind, text = tok
        if text == "(":
            self.consume("(")
            val = self.parse_ternary()
            self.consume(")")
            return val
        if text == "[":
            self.consume("[")
            items: list[Any] = []
            while self.peek() != ("OP", "]"):
                items.append(self.parse_ternary())
                if self.peek() == ("OP", ","):
                    self.consume(",")
            self.consume("]")
            return items
        if text == "{":
            self.consume("{")
            mapping: dict[Any, Any] = {}
            while self.peek() != ("OP", "}"):
                key = self.parse_ternary()
                self.consume(":")
                val = self.parse_ternary()
                mapping[key] = val
                if self.peek() == ("OP", ","):
                    self.consume(",")
            self.consume("}")
            return mapping
        self.consume()
        if kind == "STR":
            return bytes(text[1:-1], "utf-8").decode("unicode_escape")
        if kind == "NUM":
            return float(text) if "." in text else int(text)
        if kind == "IDENT":
            if text == "true":
                return True
            if text == "false":
                return False
            if text == "null":
                return None
            return self.data.get(text)
        raise ValueError(f"Unexpected token: {text!r}")


def evaluate_cel_expr(expression: str, data: Any) -> Any:
    ctx = data if isinstance(data, dict) else {}
    return _CelParser(expression, ctx).parse()


# ---------------------------------------------------------------------------
# In-memory Request Logging & Analytics Helpers
# ---------------------------------------------------------------------------

def record_gateway_log(record: GatewayLogRecord) -> None:
    """Append a request log entry and notify SSE tail subscribers."""
    trace_id = record.trace_id or uuid.uuid4().hex[:16]
    attrs = {
        "agentgateway.user": record.user,
        "agentgateway.group": record.group,
        "user_agent.name": record.user_agent,
        **record.extra_attributes,
    }
    entry = {
        "id": uuid.uuid4().hex,
        "startedAt": record.started_at,
        "completedAt": iso_now(),
        "durationMs": record.duration_ms,
        "traceId": trace_id,
        "spanId": uuid.uuid4().hex[:8],
        "httpStatus": record.http_status,
        "error": record.error,
        "promptPreview": _build_prompt_preview(record),
        "genAi": {
            "operationName": record.operation_name,
            "providerName": record.provider_name,
            "requestModel": record.request_model,
            "responseModel": record.response_model,
        },
        "usage": {
            "inputTokens": record.input_tokens,
            "outputTokens": record.output_tokens,
            "totalTokens": record.total_tokens,
        },
        "cost": round(record.cost, 6),
        "hasPayload": True,
        "attributes": attrs,
        "payload": {
            "requestPrompt": record.request_payload,
            "responseCompletion": record.response_preview,
        },
    }
    REQUEST_LOGS.insert(0, entry)
    if len(REQUEST_LOGS) > MAX_LOGS:
        del REQUEST_LOGS[MAX_LOGS:]
    for q in list(LOG_SUBSCRIBERS):
        try:
            q.put_nowait(entry)
        except Exception:
            pass


def _build_prompt_preview(record: GatewayLogRecord) -> str:
    if record.operation_name == "chat" and isinstance(record.request_payload, dict):
        msgs = record.request_payload.get("messages")
        if isinstance(msgs, list):
            for msg in reversed(msgs):
                if isinstance(msg, dict) and msg.get("content"):
                    return str(msg["content"])[:160]
    tool_name = record.extra_attributes.get("mcp.tool.name")
    if record.operation_name.startswith("mcp:") or record.extra_attributes.get("mcp.method"):
        method = record.extra_attributes.get("mcp.method") or record.operation_name
        return f"mcp:{method}" + (f" ({tool_name})" if tool_name else "")
    return f"{record.operation_name}: {record.request_model}"


def _filter_logs(logs: list[dict[str, Any]], body: dict[str, Any]) -> list[dict[str, Any]]:
    time_range = body.get("timeRange") or {}
    from_ts = _parse_iso_ts(time_range.get("from"))
    to_ts = _parse_iso_ts(time_range.get("to"))
    filters = body.get("filters") or {}

    statuses = filters.get("httpStatus") or []
    providers = filters.get("provider") or []
    req_models = filters.get("requestModel") or []
    resp_models = filters.get("responseModel") or []
    trace_id = filters.get("traceId")
    has_payload = filters.get("hasPayload")
    attr_filters = filters.get("attributes") or {}

    out: list[dict[str, Any]] = []
    for entry in logs:
        ts = _parse_iso_ts(entry.get("startedAt"))
        if from_ts is not None and ts is not None and ts < from_ts:
            continue
        if to_ts is not None and ts is not None and ts > to_ts:
            continue
        if statuses and entry.get("httpStatus") not in statuses:
            continue
        genai = entry.get("genAi") or {}
        if providers and genai.get("providerName") not in providers:
            continue
        if req_models and genai.get("requestModel") not in req_models:
            continue
        if resp_models and genai.get("responseModel") not in resp_models:
            continue
        if trace_id and entry.get("traceId") != trace_id:
            continue
        if has_payload is not None and bool(entry.get("hasPayload")) != bool(has_payload):
            continue
        attrs = entry.get("attributes") or {}
        if isinstance(attr_filters, dict):
            matched_attrs = True
            for k, expected in attr_filters.items():
                actual = attrs.get(k)
                expected_list = expected if isinstance(expected, list) else [expected]
                if expected_list and actual not in expected_list:
                    matched_attrs = False
                    break
            if not matched_attrs:
                continue
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# File-Mode Config Resource Projection & CRUD (mirrors Rust `config_store.rs`)
# ---------------------------------------------------------------------------

def _file_api_key_id(value: dict[str, Any], index: int) -> str:
    meta = value.get("metadata")
    if isinstance(meta, dict):
        key_id = meta.get("agentgateway.dev/id")
        if isinstance(key_id, str) and key_id:
            return key_id
    return f"@index:{index}"


def _list_resources_from_cfg(cfg: dict[str, Any], kind: str | None = None) -> list[dict[str, Any]]:
    kinds = [kind] if kind else sorted(SUPPORTED_RESOURCE_KINDS)
    resources: list[dict[str, Any]] = []

    def add_list(res_kind: str, items: Any, id_fn: Any) -> None:
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    rid = id_fn(item)
                    if rid:
                        resources.append({"kind": res_kind, "id": rid, "value": item})

    def add_map(res_kind: str, mapping: Any, strip_api_keys: bool = False) -> None:
        if isinstance(mapping, dict):
            for rid, val in mapping.items():
                out_val = dict(val) if strip_api_keys and rid == "apiKey" and isinstance(val, dict) else val
                if strip_api_keys and rid == "apiKey" and isinstance(out_val, dict):
                    out_val.pop("keys", None)
                resources.append({"kind": res_kind, "id": str(rid), "value": out_val})

    for k in kinds:
        llm = cfg.get("llm") or {}
        mcp = cfg.get("mcp") or {}
        ui = cfg.get("ui") or {}
        if k == "llm.provider":
            add_list(k, llm.get("providers"), lambda v: v.get("name"))
        elif k == "llm.model":
            add_list(k, llm.get("models"), lambda v: v.get("id") or v.get("name"))
        elif k == "llm.virtualModel":
            add_list(k, llm.get("virtualModels"), lambda v: v.get("name"))
        elif k == "llm.policy":
            add_map(k, llm.get("policies"), strip_api_keys=True)
        elif k == "llm.apiKey":
            keys = (llm.get("policies") or {}).get("apiKey", {}).get("keys") or []
            if isinstance(keys, list):
                for idx, entry in enumerate(keys):
                    if isinstance(entry, dict):
                        resources.append({"kind": k, "id": _file_api_key_id(entry, idx), "value": entry})
        elif k == "mcp.target":
            add_list(k, mcp.get("targets"), lambda v: v.get("name"))
        elif k == "mcp.policy":
            add_map(k, mcp.get("policies"))
        elif k == "ui.policy":
            add_map(k, ui.get("policies"))
        elif k == "frontend.policy":
            add_map(k, cfg.get("frontendPolicies"))
        elif k == "traffic.gateway":
            add_map(k, cfg.get("gateways"))
        elif k == "traffic.route":
            add_list(k, cfg.get("routes"), lambda v: v.get("name"))
        elif k == "traffic.tcpRoute":
            add_list(k, cfg.get("tcpRoutes"), lambda v: v.get("name"))
    return resources


def _upsert_resource_in_cfg(
    cfg: dict[str, Any],
    kind: str,
    value: Any,
    previous_id: str | None = None,
) -> dict[str, Any]:
    list_specs: dict[str, tuple[list[str], Any]] = {
        "llm.provider": (["llm", "providers"], lambda v: v.get("name")),
        "llm.model": (["llm", "models"], lambda v: v.get("id") or v.get("name")),
        "llm.virtualModel": (["llm", "virtualModels"], lambda v: v.get("name")),
        "mcp.target": (["mcp", "targets"], lambda v: v.get("name")),
        "traffic.route": (["routes"], lambda v: v.get("name")),
        "traffic.tcpRoute": (["tcpRoutes"], lambda v: v.get("name")),
    }
    map_specs: dict[str, list[str]] = {
        "llm.policy": ["llm", "policies"],
        "mcp.policy": ["mcp", "policies"],
        "ui.policy": ["ui", "policies"],
        "frontend.policy": ["frontendPolicies"],
        "traffic.gateway": ["gateways"],
    }

    if kind in list_specs:
        if not isinstance(value, dict):
            raise ValueError(f"{kind} resource must be an object")
        path, id_fn = list_specs[kind]
        rid = str(id_fn(value) or "")
        if not rid:
            raise ValueError(f"{kind} resources require name/id")
        parent = cfg
        for p in path[:-1]:
            parent = parent.setdefault(p, {})
        arr = parent.setdefault(path[-1], [])
        if not isinstance(arr, list):
            raise ValueError(f"{'.'.join(path)} must be a list")
        lookup = previous_id or rid
        idx = next((i for i, item in enumerate(arr) if isinstance(item, dict) and str(id_fn(item) or "") == lookup), -1)
        if previous_id is not None and idx < 0:
            raise KeyError(f"config resource not found: {kind}/{previous_id}")
        if idx >= 0:
            arr[idx] = value
        else:
            arr.append(value)
        return {"kind": kind, "id": rid, "value": value}

    if kind in map_specs:
        path = map_specs[kind]
        parent = cfg
        for p in path[:-1]:
            parent = parent.setdefault(p, {})
        mapping = parent.setdefault(path[-1], {})
        if not isinstance(mapping, dict):
            raise ValueError(f"{'.'.join(path)} must be an object")
        if kind == "traffic.gateway":
            if not isinstance(value, dict) or not (previous_id or value.get("name")):
                raise ValueError("traffic.gateway requires name")
            rid = str(value.get("name") or previous_id)
            clean_val = {k: v for k, v in value.items() if k != "name"}
        else:
            if not previous_id:
                raise ValueError(f"{kind} resources require an item ID")
            rid = previous_id
            clean_val = dict(value) if isinstance(value, dict) else value
            if kind == "llm.policy" and rid == "apiKey" and isinstance(clean_val, dict):
                existing_keys = (mapping.get("apiKey") or {}).get("keys") or []
                clean_val.setdefault("keys", existing_keys)
        if previous_id and previous_id != rid and previous_id in mapping:
            del mapping[previous_id]
        mapping[rid] = clean_val
        return {"kind": kind, "id": rid, "value": value}

    if kind == "llm.apiKey":
        if not isinstance(value, dict):
            raise ValueError("llm.apiKey resource must be an object")
        keys = cfg.setdefault("llm", {}).setdefault("policies", {}).setdefault("apiKey", {}).setdefault("keys", [])
        val = dict(value)
        meta = dict(val.get("metadata") or {})
        rid = previous_id or meta.get("agentgateway.dev/id") or str(uuid.uuid4())
        if not str(rid).startswith("@index:"):
            meta["agentgateway.dev/id"] = rid
            meta.setdefault("agentgateway.dev/createdAt", int(time.time()))
        val["metadata"] = meta
        if previous_id:
            idx = next((i for i, item in enumerate(keys) if isinstance(item, dict) and _file_api_key_id(item, i) == previous_id), -1)
            if idx < 0:
                raise KeyError(f"config resource not found: llm.apiKey/{previous_id}")
            keys[idx] = val
        else:
            keys.append(val)
        return {"kind": kind, "id": rid, "value": val}

    if kind in ("llm.settings", "mcp.settings"):
        if not isinstance(value, dict):
            raise ValueError(f"{kind} must be an object")
        section = "llm" if kind == "llm.settings" else "mcp"
        allowed = (
            ("gateways", "port", "tls")
            if section == "llm"
            else ("gateways", "port", "statefulMode", "prefixMode", "failureMode", "sseKeepAlive", "dnsRebindingProtection", "server")
        )
        sec = cfg.setdefault(section, {})
        for field in allowed:
            if field in value:
                sec[field] = value[field]
            elif previous_id == "default":
                sec.pop(field, None)
        return {"kind": kind, "id": "default", "value": value}

    if kind == "modelCatalog":
        if not isinstance(value, dict):
            raise ValueError("modelCatalog must be an object")
        sources = cfg.setdefault("config", {}).setdefault("modelCatalog", [])
        sources[:] = [s for s in sources if not (isinstance(s, dict) and "inline" in s)]
        if "custom" in value and value["custom"] is not None:
            sources.append({"inline": value["custom"]})
        return {"kind": kind, "id": "default", "value": value}

    raise ValueError(f"unsupported config resource kind: {kind}")


def _delete_resource_in_cfg(cfg: dict[str, Any], kind: str, rid: str) -> bool:
    list_paths: dict[str, tuple[list[str], Any]] = {
        "llm.provider": (["llm", "providers"], lambda v: v.get("name")),
        "llm.model": (["llm", "models"], lambda v: v.get("id") or v.get("name")),
        "llm.virtualModel": (["llm", "virtualModels"], lambda v: v.get("name")),
        "mcp.target": (["mcp", "targets"], lambda v: v.get("name")),
        "traffic.route": (["routes"], lambda v: v.get("name")),
        "traffic.tcpRoute": (["tcpRoutes"], lambda v: v.get("name")),
    }
    map_paths: dict[str, list[str]] = {
        "llm.policy": ["llm", "policies"],
        "mcp.policy": ["mcp", "policies"],
        "ui.policy": ["ui", "policies"],
        "frontend.policy": ["frontendPolicies"],
        "traffic.gateway": ["gateways"],
    }
    if kind in list_paths:
        path, id_fn = list_paths[kind]
        cur: Any = cfg
        for p in path:
            cur = cur.get(p) if isinstance(cur, dict) else None
        if not isinstance(cur, list):
            return False
        before = len(cur)
        cur[:] = [x for x in cur if not (isinstance(x, dict) and str(id_fn(x) or "") == rid)]
        return len(cur) != before
    if kind in map_paths:
        cur = cfg
        for p in map_paths[kind]:
            cur = cur.get(p) if isinstance(cur, dict) else None
        if isinstance(cur, dict) and rid in cur:
            del cur[rid]
            return True
        return False
    if kind == "llm.apiKey":
        keys = ((cfg.get("llm") or {}).get("policies") or {}).get("apiKey", {}).get("keys")
        if not isinstance(keys, list):
            return False
        for idx, item in enumerate(keys):
            if isinstance(item, dict) and _file_api_key_id(item, idx) == rid:
                keys.pop(idx)
                return True
        return False
    if kind == "modelCatalog":
        sources = (cfg.get("config") or {}).get("modelCatalog")
        if not isinstance(sources, list):
            return False
        before = len(sources)
        sources[:] = [s for s in sources if not (isinstance(s, dict) and "inline" in s)]
        return len(sources) != before
    return False


# ---------------------------------------------------------------------------
# Admin UI & Control-Plane App (port 15000)
# ---------------------------------------------------------------------------

async def redirect_to_ui(_request: Request) -> Response:
    return RedirectResponse(url="/ui/", status_code=302)


async def api_auth_login(_request: Request) -> Response:
    return RedirectResponse(url="/ui", status_code=303)


async def api_runtime(_request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "user": {
                "subject": "admin",
                "name": "TunAI Admin",
                "email": "tunbq21@personal.local",
                "canLogout": False,
            },
            "build": {
                "version": "TunAI Personal v1.0",
                "gitRevision": "personal-main",
                "rustVersion": "1.86",
                "buildProfile": "release",
                "buildTarget": "x86_64",
            },
            "ui": {
                "gatewayMode": "standalone",
                "configStoreMode": "file",
            },
            "configReload": {
                "synchronized": True,
                "lastError": None,
            },
        }
    )


async def api_get_config(_request: Request) -> JSONResponse:
    return JSONResponse(load_config_dict())


async def api_write_config(request: Request) -> JSONResponse:
    if UI_READ_ONLY:
        return JSONResponse({"status": "error", "message": "Configuration is read-only (UI_READ_ONLY=true)"}, status_code=403)
    try:
        payload = await request.json()
        if not isinstance(payload, dict):
            return JSONResponse({"status": "error", "message": "Config must be a YAML/JSON object"}, status_code=400)
        save_config_dict(payload)
        return JSONResponse({"status": "ok", "message": "Configuration saved"})
    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=400)


async def api_get_raw_config(_request: Request) -> PlainTextResponse:
    text = CONFIG_PATH.read_text(encoding="utf-8") if CONFIG_PATH.exists() else "{}\n"
    return PlainTextResponse(text, media_type="application/yaml")


async def api_write_raw_config(request: Request) -> JSONResponse:
    if UI_READ_ONLY:
        return JSONResponse({"status": "error", "message": "Configuration is read-only (UI_READ_ONLY=true)"}, status_code=403)
    ctype = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
    if ctype and ctype != "application/yaml":
        return JSONResponse(
            {"status": "error", "message": "raw configuration must be sent as application/yaml"},
            status_code=415,
        )
    if not ctype:
        return JSONResponse(
            {"status": "error", "message": "raw configuration must be sent as application/yaml"},
            status_code=415,
        )
    try:
        raw_text = (await request.body()).decode("utf-8")
        parsed = yaml.safe_load(raw_text)
        if parsed is not None and not isinstance(parsed, dict):
            return JSONResponse({"status": "error", "message": "Root YAML must be a mapping"}, status_code=400)
        CONFIG_PATH.write_text(raw_text, encoding="utf-8")
        return JSONResponse({"status": "ok", "message": "Configuration saved"})
    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=400)


async def api_config_dump(_request: Request) -> JSONResponse:
    cfg = load_config_dict()
    gateways = cfg.get("gateways") or {}
    binds = []
    for name, gw in gateways.items():
        if isinstance(gw, dict):
            binds.append({"key": f"gateway/{name}", "address": f"127.0.0.1:{gw.get('port', 3000)}", "listeners": {}})
    models = (cfg.get("llm") or {}).get("models") or []
    return JSONResponse({"binds": binds, "backends": [], "policies": [], "services": [], "models": models})


async def api_config_resources(_request: Request) -> JSONResponse:
    cfg = load_config_dict()
    return JSONResponse({"resources": _list_resources_from_cfg(cfg)})


async def api_config_resources_by_kind(request: Request) -> JSONResponse:
    kind = request.path_params.get("kind", "")
    if kind not in SUPPORTED_RESOURCE_KINDS:
        return JSONResponse({"status": "error", "message": f"unsupported config resource kind: {kind}"}, status_code=400)
    cfg = load_config_dict()
    return JSONResponse({"resources": _list_resources_from_cfg(cfg, kind)})


async def api_put_config_resources_by_kind(request: Request) -> JSONResponse:
    kind = request.path_params.get("kind", "")
    if kind not in SUPPORTED_RESOURCE_KINDS:
        return JSONResponse({"status": "error", "message": f"unsupported config resource kind: {kind}"}, status_code=400)
    try:
        body = await request.json()
        items = body.get("resources") if isinstance(body, dict) else None
        if not isinstance(items, list):
            return JSONResponse({"status": "error", "message": "resources list required"}, status_code=400)
        cfg = load_config_dict()
        saved = []
        for entry in items:
            if not isinstance(entry, dict) or "value" not in entry:
                return JSONResponse({"status": "error", "message": "each resource must contain value"}, status_code=400)
            saved.append(_upsert_resource_in_cfg(cfg, kind, entry["value"]))
        save_config_dict(cfg)
        return JSONResponse({"resources": saved})
    except KeyError as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=404)
    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=400)


async def api_update_or_delete_config_resource(request: Request) -> JSONResponse:
    kind = request.path_params.get("kind", "")
    rid = request.path_params.get("id", "")
    if kind not in SUPPORTED_RESOURCE_KINDS:
        return JSONResponse({"status": "error", "message": f"unsupported config resource kind: {kind}"}, status_code=400)
    cfg = load_config_dict()
    if request.method == "DELETE":
        if not _delete_resource_in_cfg(cfg, kind, rid):
            return JSONResponse({"status": "error", "message": f"config resource not found: {kind}/{rid}"}, status_code=404)
        save_config_dict(cfg)
        return JSONResponse({"status": "success", "message": "Configuration resource deleted successfully"})
    try:
        body = await request.json()
        if not isinstance(body, dict) or "value" not in body:
            return JSONResponse({"status": "error", "message": "value field required"}, status_code=400)
        res = _upsert_resource_in_cfg(cfg, kind, body["value"], previous_id=rid)
        save_config_dict(cfg)
        return JSONResponse({"resources": [res]})
    except KeyError as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=404)
    except Exception as exc:
        return JSONResponse({"status": "error", "message": str(exc)}, status_code=400)


async def api_budgets_status(request: Request) -> JSONResponse:
    cfg = load_config_dict()
    filter_key = request.query_params.get("apiKeyName")
    keys = ((cfg.get("llm") or {}).get("policies") or {}).get("apiKey", {}).get("keys") or []
    now_ms = int(time.time() * 1000)
    statuses: list[dict[str, Any]] = []
    for idx, entry in enumerate(keys):
        if not isinstance(entry, dict):
            continue
        meta = entry.get("metadata") or {}
        api_key_name = str(meta.get("name") or _file_api_key_id(entry, idx))
        if filter_key and api_key_name != filter_key:
            continue
        key_id = _file_api_key_id(entry, idx)
        for b_idx, b in enumerate(entry.get("budgets") or []):
            if not isinstance(b, dict):
                continue
            b_name = str(b.get("name") or f"budget-{b_idx + 1}")
            unit = str(b.get("unit") or "Tokens")
            limit_amt = float(b.get("amount") or 0)
            used = float(_BUDGET_USAGE.get((key_id, b_name), 0.0))
            rem = max(0.0, limit_amt - used)
            statuses.append(
                {
                    "apiKeyName": api_key_name,
                    "name": b_name,
                    "limit": {"unit": unit, "amount": str(limit_amt)},
                    "usage": {"used": str(round(used, 6)), "remaining": str(round(rem, 6)), "exceeded": used >= limit_amt > 0},
                    "window": {"start": now_ms, "end": None, "durationMs": None, "expired": False},
                    "onBudgetExceeded": str(b.get("onBudgetExceeded") or "Block"),
                    "updatedAt": now_ms,
                }
            )
    return JSONResponse({"observedAt": now_ms, "budgets": statuses})


async def api_costs_models(_request: Request) -> JSONResponse:
    providers = [{"provider": p, "models": sorted(m.keys())} for p, m in sorted(MODEL_PRICING_PER_1M.items())]
    return JSONResponse({"loaded": True, "providers": providers})


async def api_costs_refresh_base(_request: Request) -> JSONResponse:
    model_count = sum(len(m) for m in MODEL_PRICING_PER_1M.values())
    return JSONResponse({"providers": len(MODEL_PRICING_PER_1M), "models": model_count})


async def api_logs_search(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    limit = int(body.get("limit") or 50)
    filtered = _filter_logs(REQUEST_LOGS, body)
    return JSONResponse({"logs": filtered[:limit], "nextCursor": None})


async def api_logs_get(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    target_id = body.get("id")
    found = next((entry for entry in REQUEST_LOGS if entry["id"] == target_id), None)
    return JSONResponse({"log": found})


async def api_logs_tail(request: Request) -> StreamingResponse:
    q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
    LOG_SUBSCRIBERS.append(q)

    async def event_stream():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    entry = await asyncio.wait_for(q.get(), timeout=15.0)
                    payload = json.dumps({"entry": entry, "cursor": entry["id"]})
                    yield f"event: log\ndata: {payload}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            if q in LOG_SUBSCRIBERS:
                LOG_SUBSCRIBERS.remove(q)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _extract_group_key(entry: dict[str, Any], group_specs: list[dict[str, Any]]) -> dict[str, Any]:
    if not group_specs:
        return {"provider": (entry.get("genAi") or {}).get("providerName") or "unknown"}
    out: dict[str, Any] = {}
    genai = entry.get("genAi") or {}
    attrs = entry.get("attributes") or {}
    for spec in group_specs:
        field = spec.get("field")
        key = spec.get("key")
        if field == "provider":
            out["provider"] = genai.get("providerName") or "unknown"
        elif field == "requestModel":
            out["requestModel"] = genai.get("requestModel") or "unknown"
        elif field == "responseModel":
            out["responseModel"] = genai.get("responseModel") or "unknown"
        elif field == "httpStatus":
            out["httpStatus"] = entry.get("httpStatus")
        elif field == "attributes" and key:
            out[key] = attrs.get(key) or "unknown"
    return out


async def api_logs_analytics(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}

    filtered = _filter_logs(REQUEST_LOGS, body)
    group_specs = body.get("groupBy") or []
    bucket_seconds = int(body.get("bucketSeconds") or 300)

    grouped: dict[str, dict[str, Any]] = {}
    for log_idx, entry in enumerate(filtered):
        gdict = _extract_group_key(entry, group_specs)
        gkey = json.dumps(gdict, sort_keys=True)
        bucket = grouped.setdefault(
            gkey,
            {
                "_first_idx": log_idx,
                "group": gdict,
                "requests": 0,
                "totalTokens": 0,
                "cost": 0.0,
                "inputTokens": 0,
                "outputTokens": 0,
                "errors": 0,
                "durationMs": 0,
                "ttftRequests": 0,
                "ttftMs": 0,
                "maxTtftMs": 0,
                "generationTokens": 0,
                "generationMs": 0,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0,
                "reasoningTokens": 0,
            },
        )
        usage = entry.get("usage") or {}
        bucket["requests"] += 1
        bucket["inputTokens"] += int(usage.get("inputTokens") or 0)
        bucket["outputTokens"] += int(usage.get("outputTokens") or 0)
        bucket["totalTokens"] += int(usage.get("totalTokens") or 0)
        bucket["cost"] += float(entry.get("cost") or 0.0)
        bucket["durationMs"] += int(entry.get("durationMs") or 0)
        if entry.get("error") or (entry.get("httpStatus") or 200) >= 400:
            bucket["errors"] += 1

    # Order groups so the most recently active group appears first (e.g., active MCP/LLM traffic).
    groups = [
        {k: v for k, v in item.items() if k != "_first_idx"}
        for item in sorted(grouped.values(), key=lambda x: x["_first_idx"])
    ]

    time_buckets_map: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in filtered:
        ts = _parse_iso_ts(entry.get("startedAt")) or time.time()
        b_start_sec = int(math.floor(ts / max(1, bucket_seconds)) * max(1, bucket_seconds))
        b_start_iso = datetime.fromtimestamp(b_start_sec, tz=timezone.utc).isoformat().replace("+00:00", "Z")
        gdict = _extract_group_key(entry, group_specs)
        gkey = json.dumps(gdict, sort_keys=True)
        tkey = (b_start_iso, gkey)
        tb = time_buckets_map.setdefault(
            tkey,
            {
                "start": b_start_iso,
                "group": gdict,
                "requests": 0,
                "totalTokens": 0,
                "cost": 0.0,
                "inputTokens": 0,
                "outputTokens": 0,
                "errors": 0,
                "durationMs": 0,
                "ttftRequests": 0,
                "ttftMs": 0,
                "maxTtftMs": 0,
                "generationTokens": 0,
                "generationMs": 0,
                "cacheReadTokens": 0,
                "cacheWriteTokens": 0,
                "reasoningTokens": 0,
            },
        )
        usage = entry.get("usage") or {}
        tb["requests"] += 1
        tb["inputTokens"] += int(usage.get("inputTokens") or 0)
        tb["outputTokens"] += int(usage.get("outputTokens") or 0)
        tb["totalTokens"] += int(usage.get("totalTokens") or 0)
        tb["cost"] += float(entry.get("cost") or 0.0)
        tb["durationMs"] += int(entry.get("durationMs") or 0)
        if entry.get("error") or (entry.get("httpStatus") or 200) >= 400:
            tb["errors"] += 1

    filter_options = {
        "provider": sorted({str((e.get("genAi") or {}).get("providerName")) for e in REQUEST_LOGS if (e.get("genAi") or {}).get("providerName")}),
        "requestModel": sorted({str((e.get("genAi") or {}).get("requestModel")) for e in REQUEST_LOGS if (e.get("genAi") or {}).get("requestModel")}),
        "agentgateway.user": sorted({str((e.get("attributes") or {}).get("agentgateway.user")) for e in REQUEST_LOGS if (e.get("attributes") or {}).get("agentgateway.user")}),
        "agentgateway.group": sorted({str((e.get("attributes") or {}).get("agentgateway.group")) for e in REQUEST_LOGS if (e.get("attributes") or {}).get("agentgateway.group")}),
        "user_agent.name": sorted({str((e.get("attributes") or {}).get("user_agent.name")) for e in REQUEST_LOGS if (e.get("attributes") or {}).get("user_agent.name")}),
    }

    return JSONResponse(
        {
            "timeRange": body.get("timeRange") or {},
            "bucketSeconds": bucket_seconds,
            "buckets": sorted(time_buckets_map.values(), key=lambda b: b["start"]),
            "groups": groups,
            "filterOptions": filter_options,
        }
    )


async def api_cel(request: Request) -> JSONResponse:
    try:
        body = await request.json()
        expr = str(body.get("expression", ""))
        data = body.get("data", {})
        result = evaluate_cel_expr(expr, data)
        return JSONResponse({"result": result, "error": None})
    except Exception as exc:
        return JSONResponse({"result": None, "error": str(exc)})


async def healthz(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


async def api_test_harness_ui_notes(_request: Request) -> Response:
    return PlainTextResponse("// Personal edition\n", media_type="application/javascript")


async def serve_ui_spa(request: Request) -> Response:
    subpath = request.path_params.get("path", "").lstrip("/")
    if subpath:
        candidate = (UI_DIST_DIR / subpath).resolve()
        if candidate.is_file() and UI_DIST_DIR.resolve() in candidate.parents:
            return FileResponse(candidate)
    return HTMLResponse(render_ui_index_html())


def build_admin_app() -> Starlette:
    routes: list[Any] = [
        Route("/", redirect_to_ui),
        Route("/ui", redirect_to_ui),
        Route("/api/auth/login", api_auth_login, methods=["GET"]),
        Route("/api/test-harness/ui-notes.js", api_test_harness_ui_notes, methods=["GET"]),
        Route("/healthz/ready", healthz),
        Route("/api/runtime", api_runtime, methods=["GET"]),
        Route("/api/config", api_get_config, methods=["GET"]),
        Route("/api/config", api_write_config, methods=["POST"]),
        Route("/api/config/effective", api_get_config, methods=["GET"]),
        Route("/api/config/raw", api_get_raw_config, methods=["GET"]),
        Route("/api/config/raw", api_write_raw_config, methods=["POST"]),
        Route("/config_dump", api_config_dump, methods=["GET"]),
        Route("/api/config/resources", api_config_resources, methods=["GET"]),
        Route("/api/config/resources/{kind}", api_config_resources_by_kind, methods=["GET"]),
        Route("/api/config/resources/{kind}", api_put_config_resources_by_kind, methods=["PUT"]),
        Route("/api/config/resources/{kind}/{id}", api_update_or_delete_config_resource, methods=["PUT", "DELETE"]),
        Route("/api/budgets/status", api_budgets_status, methods=["GET"]),
        Route("/api/costs/models", api_costs_models, methods=["GET"]),
        Route("/api/costs/refresh-base", api_costs_refresh_base, methods=["POST"]),
        Route("/api/logs/search", api_logs_search, methods=["POST"]),
        Route("/api/logs/get", api_logs_get, methods=["POST"]),
        Route("/api/logs/tail", api_logs_tail, methods=["POST"]),
        Route("/api/logs/analytics/summary", api_logs_analytics, methods=["POST"]),
        Route("/cel", api_cel, methods=["POST"]),
        Route("/api/cel", api_cel, methods=["POST"]),
    ]

    assets_dir = UI_DIST_DIR / "assets"
    if assets_dir.is_dir():
        routes.append(Mount("/ui/assets", app=StaticFiles(directory=str(assets_dir)), name="ui-assets"))

    routes.append(Route("/ui/", serve_ui_spa, methods=["GET"]))
    routes.append(Route("/ui/{path:path}", serve_ui_spa, methods=["GET"]))

    app = Starlette(routes=routes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:15000", "http://localhost:15000"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id", "mcp-session-id"],
    )
    return app


# ---------------------------------------------------------------------------
# Policy Helpers: Transformations, Guardrails, Auth & Routing
# ---------------------------------------------------------------------------

def _apply_header_transformations(
    headers: dict[str, str],
    transforms: Any,
    phase: str,
    cel_ctx: dict[str, Any],
) -> None:
    """Apply `add`, `set`, `remove` header transformations configured on a policy."""
    if not isinstance(transforms, dict):
        return
    section = transforms.get(phase)
    if not isinstance(section, dict):
        return
    for name in section.get("remove") or []:
        for existing in list(headers.keys()):
            if existing.lower() == str(name).lower():
                headers.pop(existing, None)
    for k, expr in (section.get("add") or {}).items():
        val = _eval_header_expr(expr, cel_ctx)
        if val is not None:
            headers[str(k)] = f"{headers[k]}, {val}" if str(k) in headers else str(val)
    for k, expr in (section.get("set") or {}).items():
        val = _eval_header_expr(expr, cel_ctx)
        if val is not None:
            headers[str(k)] = str(val)


def _eval_header_expr(expr: Any, cel_ctx: dict[str, Any]) -> str | None:
    if not isinstance(expr, str):
        return str(expr) if expr is not None else None
    try:
        res = evaluate_cel_expr(expr, cel_ctx)
        return None if res is None else str(res)
    except Exception:
        return expr


def _build_request_cel_ctx(request: Request, jwt_claims: dict[str, Any], api_key_meta: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "request": {
            "method": request.method,
            "path": request.url.path,
            "uri": str(request.url),
            "headers": {k.lower(): v for k, v in request.headers.items()},
        },
        "jwt": jwt_claims,
        "apiKey": api_key_meta or {},
    }


def _compile_regex_guard_rules(rules: list[dict[str, Any]]) -> list[tuple[re.Pattern[str], str]]:
    compiled: list[tuple[re.Pattern[str], str]] = []
    builtin_map = {name: (pat, f"<{entity}>") for name, entity, pat, _ in _BUILTIN_PII_PATTERNS}
    for r in rules:
        if not isinstance(r, dict):
            continue
        if "builtin" in r and r["builtin"] in builtin_map:
            compiled.append(builtin_map[r["builtin"]])
        elif "pattern" in r:
            try:
                compiled.append((re.compile(str(r["pattern"])), "<REDACTED>"))
            except re.error:
                continue
    return compiled


def _apply_regex_text_guard(
    text: str,
    compiled: list[tuple[re.Pattern[str], str]],
    action: str,
) -> tuple[str, bool, bool]:
    """Return `(new_text, matched, rejected)`."""
    matched = False
    new_text = text
    for pat, mask_label in compiled:
        if pat.search(new_text):
            matched = True
            if action == "reject":
                return text, True, True
            if action == "mask":
                new_text = pat.sub(mask_label, new_text)
    return new_text, matched, False


async def _run_llm_guardrails(
    guards: Any,
    phase: str,
    items: list[dict[str, Any]],
) -> tuple[bool, int, str]:
    """Run LLM `request` or `response` guardrails in-place on messages or choices."""
    if not isinstance(guards, dict):
        return False, 200, ""
    guard_list = guards.get(phase) or []
    if not isinstance(guard_list, list):
        return False, 200, ""

    for guard in guard_list:
        if not isinstance(guard, dict):
            continue
        rej = guard.get("rejection") or {}
        rej_status = int(rej.get("status") or 403)
        rej_body = str(rej.get("body") or "The request was rejected due to inappropriate content")

        if "regex" in guard and isinstance(guard["regex"], dict):
            rgx = guard["regex"]
            action = str(rgx.get("action") or "mask").lower()
            compiled = _compile_regex_guard_rules(rgx.get("rules") or [])
            for item in items:
                target = item.get("message") if phase == "response" and isinstance(item.get("message"), dict) else item
                content = target.get("content")
                if isinstance(content, str):
                    updated, _matched, rejected = _apply_regex_text_guard(content, compiled, action)
                    if rejected:
                        return True, rej_status, rej_body
                    target["content"] = updated

        elif "webhook" in guard and isinstance(guard["webhook"], dict):
            wh = guard["webhook"]
            target_cfg = wh.get("target") or {}
            host = str(target_cfg.get("host") or "")
            failure_mode = str(wh.get("failureMode") or "failClosed")
            wh_action = str(wh.get("action") or "reject")
            if host:
                url = host.rstrip("/") + ("/request" if phase == "request" else "/response")
                if not url.startswith("http"):
                    url = f"http://{url}"
                payload = {"body": {"messages": items}} if phase == "request" else {"body": {"choices": items}}
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(url, json=payload)
                    resp.raise_for_status()
                    verdict = resp.json() if resp.content else {}
                except Exception as exc:
                    if failure_mode == "failClosed":
                        return True, 500, f"Guardrail webhook unavailable: {exc}"
                    continue
                act = verdict.get("action") if isinstance(verdict, dict) else None
                if isinstance(act, dict):
                    if "status_code" in act and wh_action != "audit":
                        return True, int(act.get("status_code") or rej_status), str(act.get("body") or rej_body)
                    if "body" in act and isinstance(act["body"], dict):
                        replacement = act["body"].get("messages" if phase == "request" else "choices")
                        if isinstance(replacement, list) and len(replacement) == len(items):
                            items[:] = replacement
    return False, 200, ""


def _method_matches_pattern(method: str, patterns: dict[str, Any]) -> str | None:
    if method in patterns:
        return str(patterns[method])
    best_prefix = ""
    best_phase: str | None = None
    for pat, phase in patterns.items():
        if pat == "*" and not best_prefix:
            best_phase = str(phase)
        elif pat.endswith("/*") and method.startswith(pat[:-1]) and len(pat) > len(best_prefix):
            best_prefix = pat
            best_phase = str(phase)
    return best_phase


async def _run_mcp_guardrails(
    guardrails_cfg: Any,
    phase: str,
    method: str,
    backends: list[str],
    payload_params: dict[str, Any],
    req_ctx: dict[str, Any],
) -> tuple[bool, str | None, dict[str, Any]]:
    """Execute `mcp.policies.mcpGuardrails` (`expression` and HTTP-accessible `remote`)."""
    if not isinstance(guardrails_cfg, dict):
        return True, None, payload_params
    processors = guardrails_cfg.get("processors") or []
    current = dict(payload_params)
    for proc in processors:
        if not isinstance(proc, dict):
            continue
        matched_phase = _method_matches_pattern(method, proc.get("methods") or {})
        if matched_phase not in (phase, "full"):
            continue
        kind = str(proc.get("kind") or "")
        if kind == "expression":
            cel_ctx = {**req_ctx, "mcp": {"methodName": method, "params": current, "result": current}}
            cond = proc.get("condition")
            if cond:
                try:
                    if not bool(evaluate_cel_expr(str(cond), cel_ctx)):
                        continue
                except Exception:
                    return False, "MCP guardrail expression error", current
            if "reject" in proc and proc["reject"]:
                return False, str(proc["reject"]), current
            if "transform" in proc and proc["transform"]:
                try:
                    res = evaluate_cel_expr(str(proc["transform"]), cel_ctx)
                    if isinstance(res, dict):
                        current = {**current, **res} if phase == "request" else res
                except Exception:
                    return False, "MCP guardrail transform error", current
        elif kind == "remote":
            host = str(proc.get("host") or "")
            failure_mode = str(proc.get("failureMode") or "failClosed")
            if host.startswith("http://") or host.startswith("https://"):
                endpoint = f"{host.rstrip('/')}/check_{phase}"
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(
                            endpoint,
                            json={"serviceNames": backends, "method": method, "payload": current},
                        )
                    resp.raise_for_status()
                    data = resp.json()
                    if isinstance(data, dict) and data.get("reject"):
                        return False, str(data["reject"]), current
                    if isinstance(data, dict) and isinstance(data.get("mutated"), dict):
                        current = data["mutated"]
                except Exception as exc:
                    if failure_mode == "failClosed":
                        return False, f"Remote MCP guardrail unavailable: {exc}", current
    return True, None, current


# ---------------------------------------------------------------------------
# MCP Proxy Logic (Single & Multi-Target + Auth + CEL + Guardrails)
# ---------------------------------------------------------------------------

def _resolve_target_prefix(cfg: dict[str, Any], targets: list[dict[str, Any]]) -> bool:
    mode = str((cfg.get("mcp") or {}).get("prefixMode") or "conditional").lower()
    if mode == "always":
        return True
    if mode == "never":
        return False
    return len(targets) > 1


async def _handle_mcp_request(request: Request, cfg: dict[str, Any]) -> Response:
    started_at = iso_now()
    t0 = time.perf_counter()
    mcp_cfg = cfg.get("mcp") or {}
    policies = mcp_cfg.get("policies") or {}
    targets = _mcp_targets(cfg)
    primary_name = str(targets[0]["name"]) if targets else DEFAULT_MCP_TARGET_NAME
    user_agent = request.headers.get("user-agent") or "unknown"

    jwt_ok, jwt_claims = _validate_jwt_policy(request.headers.get("authorization"), policies.get("jwtAuth"))
    user_id = str(jwt_claims.get("sub") or "anonymous")
    user_group = str(jwt_claims.get("role") or "default")
    client_key = str(jwt_claims.get("sub") or (request.client.host if request.client else "anonymous"))
    req_ctx = _build_request_cel_ctx(request, jwt_claims)

    def mcp_err(req_id: Any, code: int, msg: str, status: int, method_n: str, tool_n: str | None, payload: Any) -> JSONResponse:
        err_body = {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": msg}}
        record_gateway_log(
            GatewayLogRecord(
                operation_name="execute_tool" if tool_n else method_n,
                provider_name=primary_name,
                request_model=tool_n or method_n,
                response_model=tool_n or method_n,
                started_at=started_at,
                duration_ms=int((time.perf_counter() - t0) * 1000),
                http_status=status,
                error=msg,
                user=user_id,
                group=user_group,
                user_agent=user_agent,
                extra_attributes={"mcp.method": method_n, "mcp.tool.name": tool_n},
                request_payload=payload,
                response_preview=err_body,
            )
        )
        return JSONResponse(err_body, status_code=status)

    body = await request.body()
    rpc_payload: dict[str, Any] | None = None
    method_name = request.method
    tool_name: str | None = None
    target_used = primary_name

    if not jwt_ok:
        return mcp_err(None, -32600, "JWT authentication failed", 401, request.method, None, None)

    if request.method == "POST":
        if not body:
            return mcp_err(None, -32700, "Parse error", 400, "POST", None, None)
        try:
            parsed = json.loads(body.decode("utf-8"))
        except Exception:
            return mcp_err(None, -32700, "Parse error", 400, "POST", None, body[:512].decode("utf-8", errors="replace"))
        if not isinstance(parsed, dict):
            return mcp_err(None, -32600, "Invalid Request: batch requests are not permitted", 400, "batch", None, parsed)

        rpc_payload = parsed
        method_name = str(parsed.get("method") or "")
        req_id = parsed.get("id")

        if not check_rate_limit(client_key, policies.get("localRateLimit"), scope="mcp"):
            return mcp_err(req_id, -32029, "Rate limit exceeded", 429, method_name, None, rpc_payload)

        if method_name == "tools/call":
            params = parsed.get("params")
            if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                return mcp_err(req_id, -32600, "Authorization denied by policy", 403, method_name, None, rpc_payload)
            tool_name = params["name"]
            tool_args = params.get("arguments")
            if not isinstance(tool_args, dict):
                tool_args = {}

            resolved_target, unprefixed_tool = _resolve_tool_target(tool_name, targets, _resolve_target_prefix(cfg, targets))
            target_used = str(resolved_target["name"]) if resolved_target else primary_name

            rules = resolve_mcp_authz_rules(cfg)
            if rules:
                cel_ctx = {
                    **req_ctx,
                    "mcp": {"tool": {"target": target_used, "name": unprefixed_tool, "arguments": tool_args}},
                }
                if not any(_safe_cel_bool(r, cel_ctx) for r in rules):
                    return mcp_err(req_id, -32600, "Authorization denied by policy", 403, method_name, tool_name, rpc_payload)

        # Request-phase MCP Guardrails
        guardrails_cfg = policies.get("mcpGuardrails")
        ok_gr, rej_msg, updated_params = await _run_mcp_guardrails(
            guardrails_cfg,
            "request",
            method_name,
            [str(t["name"]) for t in targets] or [primary_name],
            parsed.get("params") if isinstance(parsed.get("params"), dict) else {},
            req_ctx,
        )
        if not ok_gr:
            return mcp_err(req_id, -32003, rej_msg or "Blocked by MCP guardrail", 403, method_name, tool_name, rpc_payload)
        if updated_params and isinstance(parsed.get("params"), dict):
            parsed["params"] = updated_params
            body = json.dumps(parsed).encode("utf-8")

    # Multi-target multiplexing when >1 MCP/SSE HTTP target is configured
    http_targets = [t for t in targets if _extract_target_url(t)]
    if len(http_targets) > 1 and request.method == "POST" and rpc_payload is not None:
        return await _handle_multiplex_mcp(request, cfg, http_targets, rpc_payload, body, policies, req_ctx, started_at, t0, user_id, user_group, user_agent)

    # Single-target fast path (preserves native upstream SSE / streamable HTTP & session IDs)
    target_url = (_extract_target_url(http_targets[0]) if http_targets else None) or DEFAULT_MCP_TARGET
    forward_headers: dict[str, str] = {}
    for key in ("accept", "content-type", "authorization", "mcp-session-id", "mcp-protocol-version"):
        if key in request.headers:
            forward_headers[key] = request.headers[key]
    _apply_header_transformations(forward_headers, policies.get("transformations"), "request", req_ctx)

    async with httpx.AsyncClient(timeout=60.0) as client:
        upstream = await client.request(method=request.method, url=target_url, headers=forward_headers, content=body)

    resp_headers: dict[str, str] = {}
    for key in ("mcp-session-id", "cache-control"):
        if key in upstream.headers:
            resp_headers[key] = upstream.headers[key]
    _apply_header_transformations(resp_headers, policies.get("transformations"), "response", req_ctx)

    resp_content = upstream.content
    if rpc_payload is not None and policies.get("mcpGuardrails") and "application/json" in upstream.headers.get("content-type", ""):
        try:
            up_json = json.loads(resp_content.decode("utf-8"))
            if isinstance(up_json, dict) and isinstance(up_json.get("result"), dict):
                ok_r, rej_msg, new_res = await _run_mcp_guardrails(
                    policies.get("mcpGuardrails"),
                    "response",
                    method_name,
                    [target_used],
                    up_json["result"],
                    req_ctx,
                )
                if not ok_r:
                    return mcp_err(rpc_payload.get("id"), -32003, rej_msg or "Blocked by MCP guardrail", 403, method_name, tool_name, rpc_payload)
                up_json["result"] = new_res
                resp_content = json.dumps(up_json).encode("utf-8")
        except Exception:
            pass

    dur_ms = int((time.perf_counter() - t0) * 1000)
    if rpc_payload is not None and method_name in ("tools/call", "tools/list", "initialize"):
        preview_text = resp_content[:1000].decode("utf-8", errors="replace") if resp_content else ""
        record_gateway_log(
            GatewayLogRecord(
                operation_name="execute_tool" if tool_name else method_name,
                provider_name=target_used,
                request_model=tool_name or method_name,
                response_model=tool_name or method_name,
                started_at=started_at,
                duration_ms=dur_ms,
                http_status=upstream.status_code,
                error=None if upstream.status_code < 400 else f"HTTP {upstream.status_code}",
                user=user_id,
                group=user_group,
                user_agent=user_agent,
                extra_attributes={"mcp.method": method_name, "mcp.tool.name": tool_name},
                request_payload=rpc_payload,
                response_preview=preview_text,
            )
        )

    return Response(
        content=resp_content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/json"),
        headers=resp_headers,
    )


def _safe_cel_bool(expr: str, ctx: dict[str, Any]) -> bool:
    try:
        return bool(evaluate_cel_expr(expr, ctx))
    except Exception:
        return False


def _resolve_tool_target(tool_name: str, targets: list[dict[str, Any]], use_prefix: bool) -> tuple[dict[str, Any] | None, str]:
    if not targets:
        return None, tool_name
    if use_prefix and DELIMITER in tool_name:
        for t in targets:
            tname = str(t["name"])
            prefix = f"{tname}{DELIMITER}"
            if tool_name.startswith(prefix):
                return t, tool_name[len(prefix) :]
    return targets[0], tool_name


def _parse_mcp_json_body(resp: httpx.Response) -> dict[str, Any] | None:
    ctype = resp.headers.get("content-type", "")
    text = resp.text.strip()
    if not text:
        return None
    if "text/event-stream" in ctype:
        for block in text.split("\n\n"):
            lines = [ln[5:].strip() for ln in block.splitlines() if ln.startswith("data:")]
            if lines:
                try:
                    return json.loads("\n".join(lines))
                except Exception:
                    continue
        return None
    try:
        return resp.json()
    except Exception:
        return None


async def _handle_multiplex_mcp(
    request: Request,
    cfg: dict[str, Any],
    targets: list[dict[str, Any]],
    rpc_payload: dict[str, Any],
    raw_body: bytes,
    policies: dict[str, Any],
    req_ctx: dict[str, Any],
    started_at: str,
    t0: float,
    user_id: str,
    user_group: str,
    user_agent: str,
) -> Response:
    method_name = str(rpc_payload.get("method") or "")
    req_id = rpc_payload.get("id")
    use_prefix = _resolve_target_prefix(cfg, targets)
    client_sid = request.headers.get("mcp-session-id")
    base_headers = {k: request.headers[k] for k in ("accept", "content-type", "authorization", "mcp-protocol-version") if k in request.headers}
    _apply_header_transformations(base_headers, policies.get("transformations"), "request", req_ctx)

    async with httpx.AsyncClient(timeout=30.0) as client:
        if method_name == "initialize":
            mux_sid = uuid.uuid4().hex
            sid_map: dict[str, str] = {}
            first_result: dict[str, Any] | None = None
            for t in targets:
                tname = str(t["name"])
                url = _extract_target_url(t)
                if not url:
                    continue
                try:
                    r = await client.post(url, headers=base_headers, content=raw_body)
                    if r.status_code < 400 and "mcp-session-id" in r.headers:
                        sid_map[tname] = r.headers["mcp-session-id"]
                    parsed = _parse_mcp_json_body(r)
                    if first_result is None and isinstance(parsed, dict):
                        first_result = parsed
                except Exception:
                    continue
            _MCP_MULTIPLEX_SESSIONS[mux_sid] = sid_map
            body_out = first_result or {"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2025-03-26", "capabilities": {"tools": {}}, "serverInfo": {"name": "tunai-gateway", "version": "1.0"}}}
            resp_headers = {"mcp-session-id": mux_sid}
            _apply_header_transformations(resp_headers, policies.get("transformations"), "response", req_ctx)
            return JSONResponse(body_out, headers=resp_headers)

        sid_map = _MCP_MULTIPLEX_SESSIONS.get(client_sid or "", {})

        if method_name == "notifications/initialized":
            for t in targets:
                url = _extract_target_url(t)
                if not url:
                    continue
                h = {**base_headers}
                if str(t["name"]) in sid_map:
                    h["mcp-session-id"] = sid_map[str(t["name"])]
                try:
                    await client.post(url, headers=h, content=raw_body)
                except Exception:
                    pass
            return Response(status_code=202)

        if method_name == "tools/list":
            merged_tools: list[dict[str, Any]] = []
            for t in targets:
                tname = str(t["name"])
                url = _extract_target_url(t)
                if not url:
                    continue
                h = {**base_headers}
                if tname in sid_map:
                    h["mcp-session-id"] = sid_map[tname]
                try:
                    r = await client.post(url, headers=h, content=raw_body)
                    parsed = _parse_mcp_json_body(r) or {}
                    tools = ((parsed.get("result") or {}).get("tools")) or []
                    for tool in tools:
                        if isinstance(tool, dict) and tool.get("name"):
                            item = dict(tool)
                            if use_prefix:
                                item["name"] = f"{tname}{DELIMITER}{tool['name']}"
                            merged_tools.append(item)
                except Exception:
                    continue
            resp_headers = {"mcp-session-id": client_sid} if client_sid else {}
            _apply_header_transformations(resp_headers, policies.get("transformations"), "response", req_ctx)
            out = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": merged_tools}}
            record_gateway_log(
                GatewayLogRecord(
                    operation_name="tools/list",
                    provider_name=str(targets[0]["name"]),
                    request_model="tools/list",
                    response_model="tools/list",
                    started_at=started_at,
                    duration_ms=int((time.perf_counter() - t0) * 1000),
                    http_status=200,
                    error=None,
                    user=user_id,
                    group=user_group,
                    user_agent=user_agent,
                    extra_attributes={"mcp.method": "tools/list", "mcp.tool.name": None},
                    request_payload=rpc_payload,
                    response_preview=json.dumps(out)[:1000],
                )
            )
            return JSONResponse(out, headers=resp_headers)

        # Single-target dispatch for `tools/call` and other targeted RPCs
        params = rpc_payload.get("params") or {}
        tool_name = str(params.get("name") or "")
        chosen, unprefixed = _resolve_tool_target(tool_name, targets, use_prefix)
        assert chosen is not None
        tname = str(chosen["name"])
        url = _extract_target_url(chosen) or DEFAULT_MCP_TARGET
        h = {**base_headers}
        if tname in sid_map:
            h["mcp-session-id"] = sid_map[tname]
        forwarded_rpc = dict(rpc_payload)
        if method_name == "tools/call":
            forwarded_rpc["params"] = {**params, "name": unprefixed}
        upstream = await client.post(url, headers=h, json=forwarded_rpc)

    resp_headers = {"mcp-session-id": client_sid} if client_sid else {}
    _apply_header_transformations(resp_headers, policies.get("transformations"), "response", req_ctx)
    dur_ms = int((time.perf_counter() - t0) * 1000)
    record_gateway_log(
        GatewayLogRecord(
            operation_name="execute_tool" if tool_name else method_name,
            provider_name=tname,
            request_model=tool_name or method_name,
            response_model=tool_name or method_name,
            started_at=started_at,
            duration_ms=dur_ms,
            http_status=upstream.status_code,
            error=None if upstream.status_code < 400 else f"HTTP {upstream.status_code}",
            user=user_id,
            group=user_group,
            user_agent=user_agent,
            extra_attributes={"mcp.method": method_name, "mcp.tool.name": tool_name},
            request_payload=rpc_payload,
            response_preview=upstream.text[:1000] if upstream.content else "",
        )
    )
    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/json"),
        headers=resp_headers,
    )


# ---------------------------------------------------------------------------
# LLM Data Plane (`/v1/chat/completions`, `/v1/models`)
# ---------------------------------------------------------------------------

def _match_api_key(auth_header: str | None, api_key_policy: Any) -> tuple[bool, dict[str, Any] | None]:
    """Verify API Key policy (`strict` vs `optional`) against plaintext keys and sha256 hashes."""
    if not isinstance(api_key_policy, dict) or not api_key_policy:
        return True, None
    mode = str(api_key_policy.get("mode") or "strict").lower()
    keys = api_key_policy.get("keys") or []
    token = ""
    if auth_header:
        parts = auth_header.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1].strip()
    if not token:
        return (mode != "strict"), None
    token_hash = f"sha256:{hashlib.sha256(token.encode('utf-8')).hexdigest()}"
    for idx, entry in enumerate(keys):
        if not isinstance(entry, dict):
            continue
        raw_k = entry.get("key")
        exp_k = _expand_env_value(raw_k) if raw_k is not None else None
        khash = entry.get("keyHash")
        if (exp_k is not None and hmac.compare_digest(str(exp_k), token)) or (
            isinstance(khash, str) and hmac.compare_digest(khash.lower(), token_hash.lower())
        ):
            return True, {"id": _file_api_key_id(entry, idx), "entry": entry}
    return False, None


def _model_allowed_by_key(model_name: str, key_entry: dict[str, Any] | None) -> bool:
    if not key_entry:
        return True
    allowed = key_entry["entry"].get("allowedModels")
    if allowed is None:
        return True
    if not isinstance(allowed, list) or not allowed:
        return False
    return any(fnmatch.fnmatchcase(model_name, str(pat)) for pat in allowed)


def _check_budgets_before_llm(key_info: dict[str, Any] | None) -> tuple[bool, str | None]:
    if not key_info:
        return True, None
    key_id = key_info["id"]
    for idx, b in enumerate(key_info["entry"].get("budgets") or []):
        if not isinstance(b, dict):
            continue
        b_name = str(b.get("name") or f"budget-{idx + 1}")
        limit_amt = float(b.get("amount") or 0)
        on_exceeded = str(b.get("onBudgetExceeded") or "Block")
        used = float(_BUDGET_USAGE.get((key_id, b_name), 0.0))
        if limit_amt > 0 and used >= limit_amt and on_exceeded == "Block":
            return False, f"Budget '{b_name}' exceeded ({used}/{limit_amt} {b.get('unit', 'Tokens')})"
    return True, None


def _charge_budgets_after_llm(key_info: dict[str, Any] | None, total_tokens: int, cost: float) -> None:
    if not key_info:
        return
    key_id = key_info["id"]
    for idx, b in enumerate(key_info["entry"].get("budgets") or []):
        if not isinstance(b, dict):
            continue
        b_name = str(b.get("name") or f"budget-{idx + 1}")
        unit = str(b.get("unit") or "Tokens")
        delta = float(cost if unit == "USD" else total_tokens)
        _BUDGET_USAGE[(key_id, b_name)] = _BUDGET_USAGE.get((key_id, b_name), 0.0) + delta


def _resolve_model_candidates(
    requested_model: str,
    cfg: dict[str, Any],
    cel_ctx: dict[str, Any],
) -> list[dict[str, Any]]:
    llm_cfg = cfg.get("llm") or {}
    models = [m for m in (llm_cfg.get("models") or []) if isinstance(m, dict)]
    providers_by_name = {p["name"]: p for p in (llm_cfg.get("providers") or []) if isinstance(p, dict) and p.get("name")}
    vmodels = [v for v in (llm_cfg.get("virtualModels") or []) if isinstance(v, dict)]

    def lookup_concrete(name: str) -> dict[str, Any] | None:
        exact = next((m for m in models if (m.get("id") or m.get("name")) == name or m.get("name") == name), None)
        chosen = exact or next((m for m in models if fnmatch.fnmatchcase(name, str(m.get("name") or ""))), None)
        if not chosen:
            return None
        params = dict(chosen.get("params") or {})
        prov = chosen.get("provider")
        prov_type = prov if isinstance(prov, str) else "custom"
        if isinstance(prov, dict) and "reference" in prov:
            ref = providers_by_name.get(prov["reference"]) or {}
            ref_params = dict(ref.get("params") or {})
            params = {**ref_params, **params}
            raw_p = ref.get("provider")
            prov_type = raw_p if isinstance(raw_p, str) else "custom"
        return {
            "name": chosen.get("name") or name,
            "providerName": prov_type.lower() if prov_type != "openAI" else "openai",
            "upstreamModel": params.get("model") or name,
            "baseUrl": params.get("baseUrl") or params.get("endpoint") or "https://api.openai.com/v1",
            "apiKey": _expand_env_value(params.get("apiKey")),
        }

    vm = next((v for v in vmodels if v.get("name") == requested_model), None)
    if vm and isinstance(vm.get("routing"), dict):
        routing = vm["routing"]
        if isinstance(routing.get("weighted"), dict):
            targets = [t for t in (routing["weighted"].get("targets") or []) if isinstance(t, dict)]
            if targets:
                weights = [max(0.0, float(t.get("weight") or 1)) for t in targets]
                pick = random.choices(targets, weights=weights, k=1)[0]
                resolved = lookup_concrete(str(pick.get("model") or ""))
                return [resolved] if resolved else []
        if isinstance(routing.get("failover"), dict):
            groups = sorted(
                [g for g in (routing["failover"].get("targets") or []) if isinstance(g, dict)],
                key=lambda g: float(g.get("priority") or 0),
            )
            candidates: list[dict[str, Any]] = []
            for grp in groups:
                for mname in grp.get("models") or []:
                    resolved = lookup_concrete(str(mname))
                    if resolved:
                        candidates.append(resolved)
            return candidates
        if isinstance(routing.get("conditional"), dict):
            for cond_t in routing["conditional"].get("targets") or []:
                if not isinstance(cond_t, dict):
                    continue
                when = cond_t.get("when")
                if not when or _safe_cel_bool(str(when), cel_ctx):
                    resolved = lookup_concrete(str(cond_t.get("model") or ""))
                    if resolved:
                        return [resolved]
            return []

    concrete = lookup_concrete(requested_model)
    return [concrete] if concrete else []


def _estimate_llm_cost(provider: str, model: str, in_tok: int, out_tok: int) -> float:
    rates = MODEL_PRICING_PER_1M.get(provider, {}).get(model, (0.50, 1.50))
    return (in_tok * rates[0] + out_tok * rates[1]) / 1_000_000.0


async def _handle_llm_models(_request: Request, cfg: dict[str, Any]) -> JSONResponse:
    llm_cfg = cfg.get("llm") or {}
    items = [
        {"id": m.get("name"), "object": "model", "owned_by": "tunai-gateway"}
        for m in (llm_cfg.get("models") or []) + (llm_cfg.get("virtualModels") or [])
        if isinstance(m, dict) and m.get("name")
    ]
    return JSONResponse({"object": "list", "data": items})


async def _handle_llm_chat(request: Request, cfg: dict[str, Any]) -> Response:
    started_at = iso_now()
    t0 = time.perf_counter()
    llm_cfg = cfg.get("llm") or {}
    policies = llm_cfg.get("policies") or {}
    user_agent = request.headers.get("user-agent") or "unknown"

    def llm_err(status: int, msg: str, provider: str = "openai", req_model: str = "unknown", user: str = "anonymous", payload: Any = None) -> JSONResponse:
        err = {"error": {"message": msg, "type": "gateway_error"}}
        record_gateway_log(
            GatewayLogRecord(
                operation_name="chat",
                provider_name=provider,
                request_model=req_model,
                response_model=req_model,
                started_at=started_at,
                duration_ms=int((time.perf_counter() - t0) * 1000),
                http_status=status,
                error=msg,
                user=user,
                group="default",
                user_agent=user_agent,
                extra_attributes={},
                request_payload=payload,
                response_preview=err,
            )
        )
        return JSONResponse(err, status_code=status)

    try:
        payload = await request.json()
    except Exception:
        return llm_err(400, "Invalid JSON request body")
    if not isinstance(payload, dict):
        return llm_err(400, "Request body must be a JSON object")

    req_model = str(payload.get("model") or "")
    ok_key, key_info = _match_api_key(request.headers.get("authorization"), policies.get("apiKey"))
    key_meta = (key_info["entry"].get("metadata") or {}) if key_info else {}
    user_id = str(key_meta.get("owner") or key_meta.get("name") or (key_info["id"] if key_info else "anonymous"))
    if not ok_key:
        return llm_err(401, "Invalid or missing Virtual API Key", req_model=req_model, user=user_id, payload=payload)
    if not _model_allowed_by_key(req_model, key_info):
        return llm_err(403, f"API key is not allowed to access model '{req_model}'", req_model=req_model, user=user_id, payload=payload)

    ok_budget, budget_msg = _check_budgets_before_llm(key_info)
    if not ok_budget:
        return llm_err(429, budget_msg or "Budget exceeded", req_model=req_model, user=user_id, payload=payload)

    client_key = str(user_id if user_id != "anonymous" else (request.client.host if request.client else "anonymous"))
    if not check_rate_limit(client_key, policies.get("localRateLimit"), scope="llm"):
        return llm_err(429, "Rate limit exceeded", req_model=req_model, user=user_id, payload=payload)

    cel_ctx = {
        **_build_request_cel_ctx(request, {}, key_meta),
        "llmRequest": {"model": req_model},
        "llm": {"requestModel": req_model, "streaming": bool(payload.get("stream"))},
    }
    candidates = _resolve_model_candidates(req_model, cfg, cel_ctx)
    if not candidates:
        return llm_err(404, f"Configured LLM model '{req_model}' not found", req_model=req_model, user=user_id, payload=payload)

    msgs = payload.get("messages")
    if isinstance(msgs, list):
        rejected, r_status, r_body = await _run_llm_guardrails(policies.get("guardrails"), "request", msgs)
        if rejected:
            return llm_err(r_status, r_body, provider=candidates[0]["providerName"], req_model=req_model, user=user_id, payload=payload)

    last_err: str | None = None
    last_status = 502
    chosen_cand = candidates[0]
    upstream_resp: httpx.Response | None = None

    async with httpx.AsyncClient(timeout=60.0) as client:
        for cand in candidates:
            chosen_cand = cand
            out_body = {**payload, "model": cand["upstreamModel"]}
            headers = {"Content-Type": "application/json", "Accept": request.headers.get("accept", "application/json")}
            if cand.get("apiKey"):
                headers["Authorization"] = f"Bearer {cand['apiKey']}"
            _apply_header_transformations(headers, policies.get("transformations"), "request", cel_ctx)
            url = f"{cand['baseUrl'].rstrip('/')}/chat/completions"
            try:
                r = await client.post(url, headers=headers, json=out_body)
                if r.status_code >= 500:
                    last_status = r.status_code
                    last_err = r.text[:200] or f"HTTP {r.status_code}"
                    continue
                upstream_resp = r
                break
            except Exception as exc:
                last_err = str(exc)
                last_status = 502
                continue

    if upstream_resp is None:
        return llm_err(last_status, f"All upstream model targets failed: {last_err}", provider=chosen_cand["providerName"], req_model=req_model, user=user_id, payload=payload)

    ctype = upstream_resp.headers.get("content-type", "application/json")
    resp_headers: dict[str, str] = {}
    _apply_header_transformations(resp_headers, policies.get("transformations"), "response", cel_ctx)

    in_tok = out_tok = tot_tok = 0
    resp_model = chosen_cand["upstreamModel"]
    resp_bytes = upstream_resp.content
    preview: Any = upstream_resp.text[:1000] if upstream_resp.content else ""

    if "application/json" in ctype and upstream_resp.status_code < 400:
        try:
            rj = upstream_resp.json()
            resp_model = str(rj.get("model") or resp_model)
            usage = rj.get("usage") or {}
            in_tok = int(usage.get("prompt_tokens") or 0)
            out_tok = int(usage.get("completion_tokens") or 0)
            tot_tok = int(usage.get("total_tokens") or (in_tok + out_tok))
            choices = rj.get("choices")
            if isinstance(choices, list):
                rejected, r_status, r_body = await _run_llm_guardrails(policies.get("guardrails"), "response", choices)
                if rejected:
                    return llm_err(r_status, r_body, provider=chosen_cand["providerName"], req_model=req_model, user=user_id, payload=payload)
            resp_bytes = json.dumps(rj).encode("utf-8")
            preview = rj
        except Exception:
            pass

    cost = _estimate_llm_cost(chosen_cand["providerName"], resp_model, in_tok, out_tok)
    _charge_budgets_after_llm(key_info, tot_tok, cost)
    record_gateway_log(
        GatewayLogRecord(
            operation_name="chat",
            provider_name=chosen_cand["providerName"],
            request_model=req_model,
            response_model=resp_model,
            started_at=started_at,
            duration_ms=int((time.perf_counter() - t0) * 1000),
            http_status=upstream_resp.status_code,
            error=None if upstream_resp.status_code < 400 else f"HTTP {upstream_resp.status_code}",
            user=user_id,
            group=str(key_meta.get("team") or "default"),
            user_agent=user_agent,
            extra_attributes={},
            request_payload=payload,
            response_preview=preview,
            input_tokens=in_tok,
            output_tokens=out_tok,
            total_tokens=tot_tok,
            cost=cost,
        )
    )
    return Response(content=resp_bytes, status_code=upstream_resp.status_code, media_type=ctype, headers=resp_headers)


# ---------------------------------------------------------------------------
# Generic HTTP Traffic Routing (`routes` / `binds[].listeners[].routes`)
# ---------------------------------------------------------------------------

def _collect_http_routes(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    routes = [r for r in (cfg.get("routes") or []) if isinstance(r, dict)]
    for bind in cfg.get("binds") or []:
        if isinstance(bind, dict):
            for listener in bind.get("listeners") or []:
                if isinstance(listener, dict):
                    routes.extend(r for r in (listener.get("routes") or []) if isinstance(r, dict))
    return routes


def _route_matches(route: dict[str, Any], request: Request) -> bool:
    matches = route.get("matches")
    if not matches:
        return False
    req_path = request.url.path
    for m in matches:
        if not isinstance(m, dict):
            continue
        method = m.get("method")
        if method and request.method.upper() != str(method).upper():
            continue
        path_spec = m.get("path") or {}
        if isinstance(path_spec, dict):
            if "exact" in path_spec and req_path != str(path_spec["exact"]):
                continue
            elif "pathPrefix" in path_spec and not req_path.startswith(str(path_spec["pathPrefix"])):
                continue
            elif "regex" in path_spec and not re.search(str(path_spec["regex"]), req_path):
                continue
        headers_ok = True
        for hm in m.get("headers") or []:
            if isinstance(hm, dict) and hm.get("name"):
                actual = request.headers.get(str(hm["name"]))
                exp = hm.get("value")
                if actual is None or (isinstance(exp, dict) and "exact" in exp and actual != str(exp["exact"])):
                    headers_ok = False
                    break
        if headers_ok:
            return True
    return False


async def _handle_generic_http_route(request: Request, cfg: dict[str, Any]) -> Response:
    started_at = iso_now()
    t0 = time.perf_counter()
    for route in _collect_http_routes(cfg):
        if not _route_matches(route, request):
            continue
        backends = [b for b in (route.get("backends") or []) if isinstance(b, dict) and b.get("host")]
        if not backends:
            return JSONResponse({"error": "No backend configured for matched route"}, status_code=503)
        backend = backends[0]
        host = str(backend["host"]).rstrip("/")
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"http://{host}"
        query_str = f"?{request.url.query}" if request.url.query else ""
        target_url = f"{host}{request.url.path}{query_str}"

        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
        cel_ctx = _build_request_cel_ctx(request, {})
        route_pols = route.get("policies") or {}
        _apply_header_transformations(fwd_headers, route_pols.get("transformations"), "request", cel_ctx)
        body = await request.body()
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream = await client.request(request.method, target_url, headers=fwd_headers, content=body)
        resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in ("content-length", "transfer-encoding")}
        _apply_header_transformations(resp_headers, route_pols.get("transformations"), "response", cel_ctx)
        record_gateway_log(
            GatewayLogRecord(
                operation_name="http_route",
                provider_name=str(route.get("name") or "http-route"),
                request_model=request.url.path,
                response_model=target_url,
                started_at=started_at,
                duration_ms=int((time.perf_counter() - t0) * 1000),
                http_status=upstream.status_code,
                error=None if upstream.status_code < 400 else f"HTTP {upstream.status_code}",
                user="anonymous",
                group="default",
                user_agent=request.headers.get("user-agent") or "unknown",
                extra_attributes={},
                request_payload=request.url.path,
                response_preview=upstream.text[:500] if upstream.content else "",
            )
        )
        return Response(content=upstream.content, status_code=upstream.status_code, headers=resp_headers)
    return JSONResponse({"error": f"No route matched path: {request.url.path}"}, status_code=404)


# ---------------------------------------------------------------------------
# Data-Plane Entrypoint & Dynamic CORS (port 3000)
# ---------------------------------------------------------------------------

def _resolve_cors_policy(cfg: dict[str, Any], path: str) -> dict[str, Any]:
    if path.startswith("/v1"):
        cors = (cfg.get("llm") or {}).get("policies", {}).get("cors")
    else:
        cors = (cfg.get("mcp") or {}).get("policies", {}).get("cors")
    if isinstance(cors, dict):
        return cors
    return {"allowOrigins": ["*"], "allowHeaders": ["*"], "exposeHeaders": ["Mcp-Session-Id", "mcp-session-id"]}


def _apply_dynamic_cors(response: Response, request: Request, cfg: dict[str, Any]) -> Response:
    origin = request.headers.get("origin")
    cors = _resolve_cors_policy(cfg, request.url.path)
    allowed = cors.get("allowOrigins") or []
    expose = cors.get("exposeHeaders") or ["Mcp-Session-Id", "mcp-session-id"]
    allow_origin = "*" if "*" in allowed else (origin if origin and origin in allowed else None)
    if allow_origin:
        response.headers["Access-Control-Allow-Origin"] = allow_origin
        response.headers["Access-Control-Allow-Methods"] = ", ".join(cors.get("allowMethods") or ["GET", "POST", "DELETE", "OPTIONS"])
        response.headers["Access-Control-Allow-Headers"] = ", ".join(cors.get("allowHeaders") or ["*"])
        if expose:
            response.headers["Access-Control-Expose-Headers"] = ", ".join(str(h) for h in expose)
    return response


async def data_plane_dispatch(request: Request) -> Response:
    cfg = load_config_dict()
    if request.method == "OPTIONS":
        return _apply_dynamic_cors(Response(status_code=204), request, cfg)
    path = request.url.path
    if path in ("/mcp", "/mcp/"):
        resp = await _handle_mcp_request(request, cfg)
    elif path == "/v1/models":
        resp = await _handle_llm_models(request, cfg)
    elif path == "/v1/chat/completions":
        resp = await _handle_llm_chat(request, cfg)
    else:
        resp = await _handle_generic_http_route(request, cfg)
    return _apply_dynamic_cors(resp, request, cfg)


def build_proxy_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/healthz/ready", healthz),
            Route("/{path:path}", data_plane_dispatch, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"]),
        ]
    )


async def main() -> None:
    mcp_port = resolve_mcp_port()
    admin_config = uvicorn.Config(build_admin_app(), host="127.0.0.1", port=15000, log_level="info")
    proxy_config = uvicorn.Config(build_proxy_app(), host="127.0.0.1", port=mcp_port, log_level="info")

    admin_server = uvicorn.Server(admin_config)
    proxy_server = uvicorn.Server(proxy_config)

    print("TunAI Personal Gateway UI: http://127.0.0.1:15000/ui/")
    print(f"TunAI MCP Data Plane:      http://127.0.0.1:{mcp_port}/mcp -> {resolve_mcp_target_url()}")
    await asyncio.gather(admin_server.serve(), proxy_server.serve())


if __name__ == "__main__":
    asyncio.run(main())
