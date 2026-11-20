import asyncio
import csv
import io
import os
import re
import secrets
import time
from collections import deque
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi.responses import JSONResponse

from .common.base_server import BaseSecurityServer
from .common.redaction import redact_headers, redact_text, redact_url
from .config import settings

try:
    from playwright.async_api import async_playwright
except ImportError:
    async_playwright = None

MAX_TEXT_CHARS = 65536
MAX_SCRIPT_CHARS = 32768
MAX_CONSOLE_MESSAGES = 100
MAX_INTERACTIONS = 100
MAX_TOKENS = 256
TOKEN_TTL_SECONDS = 300
MAX_DNS_QUERIES = 200
MAX_SOCKET_BYTES = 65536
MAX_SOCKET_READS = 32
MAX_EXPORT_BYTES = 1000000
MAX_CALLBACK_BODY_BYTES = 65536

_oob_tokens: Dict[str, float] = {}
_oob_memory: Dict[str, List[dict]] = {}
_oob_expiry: Dict[str, float] = {}
_dns_queries: deque = deque(maxlen=MAX_DNS_QUERIES)
_dns_transport = None

FORMULA_PREFIXES = ("=", "+", "@")
_NUMERIC_NEGATIVE = re.compile(r"^-\d+(?:\.\d+)?$")


def _cap(value: str, limit: int = MAX_TEXT_CHARS) -> str:
    text = value if isinstance(value, str) else str(value or "")
    return text[:limit]


def _redact_query(params) -> Dict[str, str]:
    redacted = {}
    for key, value in (params or {}).items():
        rendered = redact_text(f"{key}={_cap(str(value), 1024)}")
        _, _, masked = rendered.partition("=")
        redacted[str(key)] = masked
    return redacted


def _now() -> float:
    return time.time()


def _redis_client():
    url = getattr(settings, "REDIS_URL", "")
    if not url:
        return None
    try:
        import redis
        return redis.Redis.from_url(url, socket_timeout=1, socket_connect_timeout=1)
    except Exception:
        return None


def _clean_oob_state() -> None:
    now = _now()
    for token in [t for t, exp in _oob_tokens.items() if exp <= now]:
        _oob_tokens.pop(token, None)
        _oob_memory.pop(token, None)
        _oob_expiry.pop(token, None)
    while len(_oob_tokens) > MAX_TOKENS:
        token = next(iter(_oob_tokens))
        _oob_tokens.pop(token, None)
        _oob_memory.pop(token, None)
        _oob_expiry.pop(token, None)


def _register_token(token: str) -> None:
    _clean_oob_state()
    expires = _now() + TOKEN_TTL_SECONDS
    _oob_tokens[token] = expires
    _oob_expiry[token] = expires
    _oob_memory.setdefault(token, [])


def _token_known(token: str) -> bool:
    expiry = _oob_tokens.get(token or "")
    return bool(expiry and expiry > _now())


def _store_interaction(token: str, interaction: dict) -> None:
    if not _token_known(token):
        return
    record = dict(interaction)
    record.setdefault("at", _now())
    _oob_memory.setdefault(token, []).append(record)
    if len(_oob_memory[token]) > MAX_INTERACTIONS:
        del _oob_memory[token][:-MAX_INTERACTIONS]
    client = _redis_client()
    if client is None:
        return
    try:
        import json
        key = f"oob:interaction:{token}"
        client.rpush(key, json.dumps(record, default=str))
        client.ltrim(key, -MAX_INTERACTIONS, -1)
        client.expire(key, TOKEN_TTL_SECONDS)
    except Exception:
        pass


def _read_interactions(token: str) -> List[dict]:
    interactions = list(_oob_memory.get(token) or [])
    client = _redis_client()
    if client is None:
        return interactions
    try:
        import json
        values = client.lrange(f"oob:interaction:{token}", 0, MAX_INTERACTIONS - 1) or []
        for raw in values:
            try:
                interactions.append(json.loads(raw))
            except (TypeError, ValueError):
                continue
    except Exception:
        pass
    seen = set()
    unique = []
    for item in interactions:
        key = repr(item)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique[-MAX_INTERACTIONS:]


def callback_url(token: str) -> str:
    host = getattr(settings, "OOB_CALLBACK_HOST", "127.0.0.1")
    port = int(getattr(settings, "OOB_CALLBACK_PORT", 8091) or 8091)
    return f"http://{host}:{port}/oob/{token}"


def dns_callback_hint(token: str) -> str:
    host = getattr(settings, "OOB_CALLBACK_HOST", "127.0.0.1")
    port = int(getattr(settings, "OOB_DNS_PORT", 5353) or 5353)
    return f"udp://{host}:{port}/{token}.oob.invalid"


class _DNSProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        query = _cap(data.decode(errors="replace"), 512)
        for candidate in re.findall(r"[A-Za-z0-9_-]{10,}", query):
            if _token_known(candidate):
                item = {
                    "type": "dns",
                    "query": redact_text(query),
                    "source": addr[0] if addr else "",
                }
                _dns_queries.append(item)
                _store_interaction(candidate, item)
                break

    def error_received(self, exc):
        return


async def _ensure_dns_listener() -> Optional[str]:
    global _dns_transport
    if _dns_transport is not None:
        return None
    host = getattr(settings, "OOB_CALLBACK_HOST", "127.0.0.1")
    port = int(getattr(settings, "OOB_DNS_PORT", 5353) or 5353)
    try:
        loop = asyncio.get_running_loop()
        _dns_transport, _ = await loop.create_datagram_endpoint(
            _DNSProtocol, local_addr=(host, port)
        )
    except Exception as exc:
        return f"DNS listener unavailable: {type(exc).__name__}"
    return None


def csv_formula_cells(contents: str) -> List[dict]:
    cells = []
    try:
        rows = csv.reader(io.StringIO(contents))
        for row_number, row in enumerate(rows, start=1):
            for column, value in enumerate(row, start=1):
                stripped = value.lstrip(" \t\r\n\"'")
                if not stripped:
                    continue
                if stripped[0] in FORMULA_PREFIXES or (
                    stripped[0] == "-" and not _NUMERIC_NEGATIVE.match(stripped)
                ):
                    cells.append({
                        "row": row_number,
                        "column": column,
                        "value": redact_text(_cap(value, 512)),
                    })
    except (csv.Error, ValueError):
        pass
    return cells


def _decode_payload(payload: Any) -> bytes:
    if payload is None:
        return b""
    if isinstance(payload, (bytes, bytearray)):
        return bytes(payload)
    if isinstance(payload, list):
        try:
            return bytes(int(item) & 0xFF for item in payload[:MAX_SOCKET_BYTES])
        except (TypeError, ValueError):
            return b""
    text = str(payload)
    if len(text) > MAX_SOCKET_BYTES:
        text = text[:MAX_SOCKET_BYTES]
    return text.encode("utf-8", errors="replace")


def _download_filename(url: str, content_disposition: str = "") -> str:
    match = re.search(r"filename\*?=(?:UTF-8''|\"?)([^\";]+)", content_disposition or "", re.I)
    if match:
        name = os.path.basename(match.group(1).strip().strip('"'))
        if name:
            return _cap(name, 255)
    path = urlparse(url).path
    name = os.path.basename(path.rstrip("/"))
    return _cap(name or "export", 255)


class InjectionHarnessServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("Injection Harness Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def browser_probe(
            url: str = "",
            marker: str = "",
            script: str = "",
            data_url: str = "",
            timeout: float = 10.0,
            selector: str = "",
            headers: Optional[dict] = None,
        ):
            return await self.browser_probe(
                url=url, marker=marker, script=script, data_url=data_url,
                timeout=timeout, selector=selector, headers=headers,
            )

        @self.mcp.tool()
        async def oob_probe(
            target_url: str = "",
            oob_wait_seconds: float = 0.0,
            marker: str = "",
        ):
            return await self.oob_probe(
                target_url=target_url, oob_wait_seconds=oob_wait_seconds, marker=marker
            )

        @self.mcp.tool()
        async def smtp_capture(
            target_url: str = "",
            recipient: str = "",
            subject: str = "",
            body: str = "",
            headers: Optional[dict] = None,
            message: str = "",
        ):
            return await self.smtp_capture(
                target_url=target_url, recipient=recipient, subject=subject,
                body=body, headers=headers, message=message
            )

        @self.mcp.tool()
        async def file_export_probe(url: str = "", timeout: float = 10.0):
            return await self.file_export_probe(url=url, timeout=timeout)

        @self.mcp.tool()
        async def raw_socket_probe(
            url: str = "",
            host: str = "",
            port: int = 0,
            raw_socket_payload: str = "",
            timeout: float = 5.0,
        ):
            return await self.raw_socket_probe(
                url=url, host=host, port=port,
                raw_socket_payload=raw_socket_payload, timeout=timeout
            )

    async def oob_callback_route(self, request):
        token = (request.path_params or {}).get("token", "")
        if not _token_known(token):
            return JSONResponse({"error": "unknown callback token"}, status_code=404)
        length = request.headers.get("content-length")
        if length:
            try:
                if int(length) > MAX_CALLBACK_BODY_BYTES:
                    return JSONResponse({"error": "callback body too large"}, status_code=413)
            except ValueError:
                return JSONResponse({"error": "invalid content length"}, status_code=400)
        raw = await request.body()
        interaction = {
            "type": "http",
            "method": getattr(request, "method", ""),
            "path": redact_text(_cap(str(request.url.path), 2048)),
            "query": _redact_query(request.query_params),
            "headers": redact_headers({str(k): str(v) for k, v in request.headers.items()}),
            "body": redact_text(_cap(raw.decode(errors="replace"), MAX_CALLBACK_BODY_BYTES)),
        }
        _store_interaction(token, interaction)
        return JSONResponse({"status": "recorded"})

    async def browser_probe(
        self, url="", marker="", script="", data_url="", timeout=10.0, selector="",
        headers=None,
    ):
        result = {
            "body": "",
            "console": [],
            "dom": "",
            "marker_seen": False,
            "selector": str(selector or ""),
            "selector_matched": False,
            "status": "unsupported",
        }
        target = str(data_url or url or "")
        if not target:
            result["error"] = "no browser destination supplied"
            return result
        if async_playwright is None:
            result["error"] = "Playwright/Chromium is unavailable in this sandbox"
            return result
        try:
            timeout_ms = max(100, min(int(float(timeout) * 1000), 30000))
            scripts = _cap(str(script or ""), MAX_SCRIPT_CHARS)
            console = []

            def _on_console(message):
                if len(console) < MAX_CONSOLE_MESSAGES:
                    console.append(_cap(message.text, 2048))

            async with async_playwright() as playwright:
                browser = None
                launch_errors = []
                options = [
                    {"headless": True, "args": ["--no-sandbox", "--disable-dev-shm-usage"]},
                    {"headless": True, "executable_path": "/usr/bin/chromium",
                     "args": ["--no-sandbox", "--disable-dev-shm-usage"]},
                    {"headless": True, "executable_path": "/usr/bin/chromium-browser",
                     "args": ["--no-sandbox", "--disable-dev-shm-usage"]},
                ]
                for option in options:
                    try:
                        browser = await playwright.chromium.launch(**option)
                        break
                    except Exception as exc:
                        launch_errors.append(f"{type(exc).__name__}: {_cap(str(exc), 256)}")
                if browser is None:
                    result["status"] = "unsupported"
                    result["error"] = "Chromium launch failed: " + " | ".join(launch_errors[:2])
                    return result
                try:
                    page = await browser.new_page()
                    page.on("console", _on_console)
                    if headers and hasattr(page, "set_extra_http_headers"):
                        await page.set_extra_http_headers({
                            str(k): str(v) for k, v in headers.items()
                        })
                    await page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
                    if scripts:
                        await page.add_script_tag(content=scripts)
                        await page.wait_for_timeout(100)
                    body = await page.evaluate(
                        "document.body ? document.body.innerText : ''"
                    )
                    dom = await page.content()
                    console_text = "\n".join(console)
                    marker_seen = bool(
                        marker and str(marker).lower() in console_text.lower()
                    )
                    selector_signal = (
                        f"__wraith_selector__{marker}__wraith_selector__"
                        if marker else ""
                    )
                    result = {
                        "body": redact_text(_cap(body or "")),
                        "console": [redact_text(line) for line in console],
                        "dom": redact_text(_cap(dom or "")),
                        "marker_seen": marker_seen,
                        "selector": str(selector or ""),
                        "selector_matched": bool(
                            selector and selector_signal
                            and selector_signal in console_text
                        ),
                        "status": "ok",
                        "url": redact_url(target),
                    }
                finally:
                    await browser.close()
        except Exception as exc:
            result["status"] = "error"
            result["error"] = f"{type(exc).__name__}: {_cap(str(exc), 512)}"
        return result

    async def oob_probe(self, target_url="", oob_wait_seconds=0.0, marker=""):
        token = secrets.token_urlsafe(12)
        _register_token(token)
        dns_error = await _ensure_dns_listener()
        try:
            configured_wait = float(
                getattr(settings, "OOB_MAX_WAIT_SECONDS", 15.0) or 15.0
            )
        except (TypeError, ValueError):
            configured_wait = 15.0
        max_wait = max(0.0, min(configured_wait, 15.0))
        try:
            wait = max(0.0, min(float(oob_wait_seconds or 0.0), max_wait))
        except (TypeError, ValueError):
            wait = 0.0
        deadline = _now() + wait
        while _now() < deadline:
            await asyncio.sleep(min(0.1, max(0.0, deadline - _now())))
        interactions = _read_interactions(token)
        result = {
            "interactions": interactions,
            "callback_url": callback_url(token),
            "dns_callback": dns_callback_hint(token),
            "token": token,
            "target_url": redact_url(str(target_url)) if target_url else "",
            "status": "ok",
        }
        if marker:
            result["marker"] = redact_text(_cap(str(marker), 512))
        if dns_error:
            result["dns_error"] = dns_error
        return result

    async def smtp_capture(
        self, target_url="", recipient="", subject="", body="", headers=None, message=""
    ):
        recipient = str(recipient or "")
        allowed = _allowed_recipient_domains()
        if recipient and not _recipient_allowed(recipient, allowed):
            return {
                "headers": [],
                "body": "",
                "recipients": [],
                "status": "rejected",
                "error": "recipient is not in the SMTP capture allowlist",
            }
        if not recipient:
            return {
                "headers": [],
                "body": "",
                "recipients": [],
                "status": "rejected",
                "error": "no SMTP recipient supplied",
            }
        text = str(message or "")
        if not text:
            extra = ""
            for key, value in (headers or {}).items():
                extra += f"{key}: {value}\r\n"
            text = extra + f"Subject: {subject}\r\n\r\n{body}"
        stored = await _run_smtp_capture(recipient, text)
        stored["target_url"] = redact_url(str(target_url)) if target_url else ""
        stored["recipients"] = [recipient]
        return stored

    async def file_export_probe(self, url="", timeout=10.0):
        target = str(url or "")
        if not target:
            return {
                "contents": "",
                "cells": [],
                "download_filename": "",
                "status": "error",
                "error": "no export destination supplied",
            }
        try:
            limit = max(0.1, min(float(timeout or 10.0), 20.0))
        except (TypeError, ValueError):
            limit = 10.0
        try:
            async with httpx.AsyncClient(
                timeout=limit, follow_redirects=False,
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=0),
            ) as client:
                response = await client.get(target)
            content = bytes(response.content or b"")[:MAX_EXPORT_BYTES]
            contents = content.decode("utf-8", errors="replace")
            cells = csv_formula_cells(contents)
            name = _download_filename(
                target, str(response.headers.get("content-disposition", ""))
            )
            return {
                "contents": redact_text(contents),
                "cells": cells,
                "download_filename": name,
                "status": "ok",
                "content_type": str(response.headers.get("content-type", "")),
                "status_code": response.status_code,
            }
        except Exception as exc:
            return {
                "contents": "",
                "cells": [],
                "download_filename": _download_filename(target),
                "status": "error",
                "error": f"{type(exc).__name__}: {_cap(str(exc), 512)}",
            }

    async def raw_socket_probe(
        self, url="", host="", port=0, raw_socket_payload="", timeout=5.0
    ):
        destination = str(url or "")
        if not destination and host and port:
            destination = f"{host}:{port}"
        if not destination:
            return {
                "header_lines": [],
                "response_count": 0,
                "status": "error",
                "error": "no raw socket destination supplied",
            }
        parsed = urlparse(destination if "://" in destination else "http://" + destination)
        target_host = parsed.hostname or str(host or "")
        try:
            target_port = int(parsed.port or port or 80)
        except (TypeError, ValueError):
            target_port = int(port or 80)
        if not target_host or not 1 <= target_port <= 65535:
            return {
                "header_lines": [],
                "response_count": 0,
                "status": "error",
                "error": "raw socket destination is not host:port",
            }
        try:
            limit = max(0.1, min(float(timeout or 5.0), 10.0))
        except (TypeError, ValueError):
            limit = 5.0
        payload = _decode_payload(raw_socket_payload)
        result = {
            "header_lines": [],
            "response_count": 0,
            "host": target_host,
            "port": target_port,
            "status": "ok",
        }
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_host, target_port), timeout=limit
            )
            try:
                if payload:
                    writer.write(payload)
                    await asyncio.wait_for(writer.drain(), timeout=limit)
                chunks = []
                total = 0
                reads = 0
                while reads < MAX_SOCKET_READS and total < MAX_SOCKET_BYTES:
                    try:
                        chunk = await asyncio.wait_for(reader.read(4096), timeout=min(limit, 1.0))
                    except asyncio.TimeoutError:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    reads += 1
                result["response_count"] = reads
                raw_text = b"".join(chunks).decode("utf-8", errors="replace")
                header_lines = []
                for line in raw_text.splitlines():
                    if not line.strip():
                        break
                    if ":" in line:
                        name, _, value = line.partition(":")
                        header_lines.append(
                            f"{name.strip()}: {redact_text(_cap(value.strip(), 1024))}"
                        )
                    else:
                        header_lines.append(redact_text(_cap(line, 2048)))
                    if len(header_lines) >= MAX_CONSOLE_MESSAGES:
                        break
                result["header_lines"] = header_lines
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception as exc:
            result["status"] = "error"
            result["error"] = f"{type(exc).__name__}: {_cap(str(exc), 512)}"
        return result


def _allowed_recipient_domains() -> List[str]:
    raw = str(getattr(settings, "SMTP_ALLOWED_RECIPIENT_DOMAINS", ".invalid") or ".invalid")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _recipient_allowed(recipient: str, domains: List[str]) -> bool:
    address = str(recipient or "").strip().lower()
    if "@" not in address:
        return False
    domain = address.rpartition("@")[2].rstrip(".")
    if not domain or any(ch in domain for ch in " \t\r\n/\\"):
        return False
    for allowed in domains:
        suffix = allowed.lstrip(".")
        if domain == suffix or domain.endswith("." + suffix):
            return True
    return False


class _SMTPCaptureHandler:
    def __init__(self):
        self.messages: deque = deque(maxlen=MAX_INTERACTIONS)
        self.domains = _allowed_recipient_domains()
        self.recipients: List[str] = []

    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        session.host_name = hostname
        session.extended_smtp = True
        return responses

    async def handle_HELO(self, server, session, envelope, hostname):
        session.host_name = hostname
        return "250 OK"

    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        envelope.mail_from = address
        return "250 OK"

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if not _recipient_allowed(address, self.domains):
            return "550 recipient not allowed"
        envelope.rcpt_tos.append(address)
        self.recipients.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        content = envelope.content or b""
        text = content.decode("utf-8", errors="replace")
        raw_headers, _, raw_body = text.partition("\r\n\r\n")
        if not raw_body and "\n\n" in text:
            raw_headers, _, raw_body = text.partition("\n\n")
        headers = {}
        for line in raw_headers.splitlines():
            if ":" in line:
                name, _, value = line.partition(":")
                headers[str(name).strip()] = str(value).strip()
        self.messages.append({
            "headers": redact_headers(headers),
            "body": redact_text(_cap(raw_body)),
        })
        return "250 Message accepted"

    async def handle_RSET(self, server, session, envelope):
        envelope.rcpt_tos.clear()
        return "250 OK"

    async def handle_QUIT(self, server, session, envelope):
        return "221 Bye"


class _FallbackEnvelope:
    def __init__(self):
        self.mail_from = ""
        self.rcpt_tos = []


class _FallbackSMTPServer(asyncio.Protocol):
    def __init__(self, handler: _SMTPCaptureHandler):
        self.handler = handler
        self.transport = None
        self.buffer = b""
        self.in_data = False
        self.envelope = _FallbackEnvelope()
        self.data_lines: List[bytes] = []

    def connection_made(self, transport):
        self.transport = transport
        self._send("220 wraith-smtp ready")

    def data_received(self, data):
        self.buffer += data
        while b"\n" in self.buffer:
            line, _, self.buffer = self.buffer.partition(b"\n")
            text = line.decode("utf-8", errors="replace").rstrip("\r")
            if self.in_data:
                if text == ".":
                    self.in_data = False
                    self.handler.messages.append(
                        self._parse_message(b"\r\n".join(self.data_lines))
                    )
                    self.data_lines = []
                    self._send("250 Message accepted")
                else:
                    if len(self.data_lines) < MAX_INTERACTIONS * 32:
                        self.data_lines.append(text.encode(errors="replace"))
                continue
            upper = text.upper()
            if upper.startswith("EHLO") or upper.startswith("HELO"):
                self._send("250-wraith-smtp")
                self._send("250 OK")
            elif upper.startswith("MAIL FROM:"):
                self.envelope.mail_from = text[10:]
                self._send("250 OK")
            elif upper.startswith("RCPT TO:"):
                address = text[8:].strip().strip("<>")
                if _recipient_allowed(address, self.handler.domains):
                    self.envelope.rcpt_tos.append(address)
                    self._send("250 OK")
                else:
                    self._send("550 recipient not allowed")
            elif upper == "DATA":
                if not self.envelope.rcpt_tos:
                    self._send("503 no valid recipients")
                else:
                    self.in_data = True
                    self._send("354 end with <CRLF>.<CRLF>")
            elif upper == "RSET":
                self.envelope.rcpt_tos.clear()
                self._send("250 OK")
            elif upper == "QUIT":
                self._send("221 Bye")
                if self.transport:
                    self.transport.close()
            else:
                self._send("500 unknown command")

    def _parse_message(self, content: bytes) -> dict:
        text = content.decode("utf-8", errors="replace")
        raw_headers, _, raw_body = text.partition("\r\n\r\n")
        if not raw_body and "\n\n" in text:
            raw_headers, _, raw_body = text.partition("\n\n")
        headers = {}
        for line in raw_headers.splitlines():
            if ":" in line:
                name, _, value = line.partition(":")
                headers[str(name).strip()] = str(value).strip()
        return {
            "headers": redact_headers(headers),
            "body": redact_text(_cap(raw_body)),
        }

    def _send(self, line: str) -> None:
        if self.transport:
            self.transport.write((line + "\r\n").encode())


def _smtp_port(host: str, port: int) -> int:
    if port:
        return port
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((host, 0))
        return int(probe.getsockname()[1])


async def _run_smtp_capture(recipient: str, text: str) -> dict:
    host = str(getattr(settings, "SMTP_CAPTURE_HOST", "127.0.0.1") or "127.0.0.1")
    port = int(getattr(settings, "SMTP_CAPTURE_PORT", 2525) or 2525)
    port = _smtp_port(host, port)
    handler = _SMTPCaptureHandler()
    server = None
    controller = None
    try:
        from aiosmtpd.controller import Controller
    except ImportError:
        Controller = None
    try:
        if Controller is not None:
            try:
                controller = Controller(handler, hostname=host, port=port)
                controller.start()
            except Exception:
                controller = None
        if controller is None:
            loop = asyncio.get_running_loop()
            server = await loop.create_server(
                lambda: _FallbackSMTPServer(handler), host, port
            )
    except OSError as exc:
        return {
            "headers": [],
            "body": "",
            "status": "error",
            "error": f"{type(exc).__name__}: {_cap(str(exc), 512)}",
        }
    try:
        import smtplib

        def _send():
            with smtplib.SMTP(host, port, timeout=2.0) as client:
                client.sendmail("probe@wraith.invalid", [recipient], text)

        await asyncio.wait_for(asyncio.to_thread(_send), timeout=4.0)
    except Exception as exc:
        return {
            "headers": [],
            "body": "",
            "status": "error",
            "error": f"{type(exc).__name__}: {_cap(str(exc), 512)}",
        }
    finally:
        if controller is not None:
            controller.stop()
        if server is not None:
            server.close()
            await server.wait_closed()
    message = handler.messages[-1] if handler.messages else {"headers": {}, "body": ""}
    return {
        "headers": message.get("headers") or {},
        "body": message.get("body") or "",
        "status": "ok",
        "recipient": recipient,
    }
