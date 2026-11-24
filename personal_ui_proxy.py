"""Personal AI & MCP Gateway container entrypoint and front UI proxy.

Runs the Rust `agentgateway` engine (port 3000 data plane, 127.0.0.1:15000 admin,
15020 metrics, 15021 readiness) and serves the personalized TunAI Gateway UI at /ui/
on 0.0.0.0:15005 while forwarding /api/* calls to Rust admin.
"""

from __future__ import annotations

import asyncio
import hmac
import os
import signal
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from start_local_gateway import render_ui_index_html

UI_DIST_DIR = Path(os.environ.get("PERSONAL_UI_DIST", "/app/ui/dist"))
CONFIG_FILE = os.environ.get("AGENTGATEWAY_CONFIG", "/config/config.yaml")
RUST_ADMIN_BASE = "http://127.0.0.1:15000"
PROXY_PORT = int(os.environ.get("PERSONAL_UI_PORT", os.environ.get("PORT", "15005")))
BRAND_NAME = os.environ.get("GATEWAY_BRAND_NAME", "TunAI Gateway")

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}

UNTRUSTED_IDENTITY_HEADERS = {
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-user",
    "x-real-ip",
    "x-auth-request-user",
    "x-auth-request-email",
}

DANGEROUS_ADMIN_PREFIXES = ("/quitquitquit", "/debug/", "/logging", "/config_dump", "/memory")
ALLOW_DANGEROUS_ADMIN = os.environ.get("PERSONAL_ALLOW_DANGEROUS_ADMIN", "").lower() == "true"
UI_ADMIN_TOKEN = os.environ.get("PERSONAL_UI_ADMIN_TOKEN", "")
UI_REQUIRE_AUTH = os.environ.get("PERSONAL_UI_REQUIRE_AUTH", "").lower() == "true"


def _strip_request_headers(headers) -> dict[str, str]:
    nominated: set[str] = set()
    for conn_val in headers.getlist("connection") if hasattr(headers, "getlist") else [headers.get("connection", "")]:
        for token in conn_val.split(","):
            t = token.strip().lower()
            if t:
                nominated.add(t)
    blocked = HOP_BY_HOP_HEADERS | UNTRUSTED_IDENTITY_HEADERS | nominated
    return {k: v for k, v in headers.items() if k.lower() not in blocked}


def _check_proxy_auth(request: Request) -> JSONResponse | None:
    if UI_REQUIRE_AUTH and not UI_ADMIN_TOKEN:
        return JSONResponse(
            {"error": "UI proxy auth required but PERSONAL_UI_ADMIN_TOKEN is not configured"},
            status_code=503,
        )
    if not UI_ADMIN_TOKEN:
        return None
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-admin-token", "").strip()
    if not token or not hmac.compare_digest(token, UI_ADMIN_TOKEN):
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    return None


async def _watch_rust_process(proc: subprocess.Popen[bytes]) -> None:
    """Exit the container if the underlying Rust agentgateway process terminates."""
    while True:
        await asyncio.sleep(2)
        if proc.poll() is not None:
            code = proc.returncode
            print(f"agentgateway exited unexpectedly with code {code}", file=sys.stderr, flush=True)
            os._exit(code if code != 0 else 1)


@asynccontextmanager
async def lifespan(starlette_app: Starlette):
    os.environ.setdefault("OPENAI_API_KEY", "sk-placeholder")
    proc = subprocess.Popen(["/app/agentgateway", "-f", CONFIG_FILE])
    client = httpx.AsyncClient(base_url=RUST_ADMIN_BASE, timeout=httpx.Timeout(60.0, read=None))
    starlette_app.state.agentgateway_proc = proc
    starlette_app.state.http_client = client
    watcher = asyncio.create_task(_watch_rust_process(proc))
    try:
        for _ in range(30):
            try:
                r = await client.get("/api/runtime")
                if r.status_code < 500:
                    break
            except Exception:
                await asyncio.sleep(0.2)
        yield
    finally:
        watcher.cancel()
        await client.aclose()
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


async def redirect_to_ui(_request: Request) -> Response:
    return RedirectResponse(url="/ui/", status_code=302)


async def serve_ui_spa(request: Request) -> Response:
    subpath = request.path_params.get("path", "").lstrip("/")
    if subpath:
        candidate = (UI_DIST_DIR / subpath).resolve()
        if candidate.is_file() and UI_DIST_DIR.resolve() in candidate.parents:
            return FileResponse(candidate)
    return HTMLResponse(
        render_ui_index_html(),
        headers={
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'",
        },
    )


async def proxy_to_rust_admin(request: Request) -> Response:
    if not ALLOW_DANGEROUS_ADMIN and request.url.path.startswith(DANGEROUS_ADMIN_PREFIXES):
        return JSONResponse({"error": "Endpoint disabled on external UI proxy"}, status_code=403)
    if request.method != "OPTIONS":
        auth_err = _check_proxy_auth(request)
        if auth_err is not None:
            return auth_err

    http_client: httpx.AsyncClient = request.app.state.http_client
    path = request.url.path
    if request.url.query:
        path = f"{path}?{request.url.query}"

    fwd_headers = _strip_request_headers(request.headers)
    body = await request.body()

    if path.startswith("/api/logs/tail"):
        req = http_client.build_request(request.method, path, headers=fwd_headers, content=body)
        upstream = await http_client.send(req, stream=True)
        resp_headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in HOP_BY_HOP_HEADERS
        }

        async def iter_bytes():
            try:
                async for chunk in upstream.aiter_bytes():
                    yield chunk
            finally:
                await upstream.aclose()

        return StreamingResponse(
            iter_bytes(),
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type=upstream.headers.get("content-type", "text/event-stream"),
        )

    upstream = await http_client.request(
        method=request.method,
        url=path,
        headers=fwd_headers,
        content=body,
        follow_redirects=False,
    )

    resp_headers = {
        k: v
        for k, v in upstream.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }

    if request.url.path == "/api/runtime" and upstream.status_code == 200:
        try:
            data = upstream.json()
            if isinstance(data, dict) and isinstance(data.get("build"), dict):
                data["build"]["version"] = f"{BRAND_NAME} v1.0"
                data["build"]["gitRevision"] = "personal"
            return JSONResponse(data, status_code=200)
        except Exception:
            pass

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=resp_headers,
        media_type=upstream.headers.get("content-type"),
    )


def create_app() -> Starlette:
    routes: list = [
        Route("/", redirect_to_ui, methods=["GET"]),
        Route("/ui", redirect_to_ui, methods=["GET"]),
    ]

    assets_dir = UI_DIST_DIR / "assets"
    if assets_dir.is_dir():
        routes.append(Mount("/ui/assets", app=StaticFiles(directory=str(assets_dir)), name="ui-assets"))

    routes.extend(
        [
            Route("/ui/", serve_ui_spa, methods=["GET"]),
            Route("/ui/{path:path}", serve_ui_spa, methods=["GET"]),
            Route("/{path:path}", proxy_to_rust_admin, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]),
        ]
    )
    return Starlette(routes=routes, lifespan=lifespan)


app = create_app()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PROXY_PORT, log_level="info")
