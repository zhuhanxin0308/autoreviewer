"""Loopback-only HTTP transport for the local review application.

The browser is a local control surface, not a public multi-user service. Host,
Origin and per-process token checks protect its privileged local operations.
"""

from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
import json
from pathlib import Path
import re
import secrets
from urllib.parse import parse_qs, urlsplit
import webbrowser

from .reports import render_markdown


MAX_BODY_BYTES = 1024 * 1024
MAX_IMPORT_BODY_BYTES = 32 * 1024 * 1024 + 1024
_JOB_PATH = re.compile(r"/api/jobs/([A-Za-z0-9_-]{1,80})(?:/(cancel|retry|report|issues/preview|issues/publish))?\Z")


class _HTTPError(ValueError):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields are not allowed")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Nonfinite JSON values are not allowed")


class LocalWebServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, service):
        if server_address[0] != "127.0.0.1":
            raise ValueError("The local UI must bind to 127.0.0.1")
        self.service = service
        self.csrf_token = secrets.token_urlsafe(32)
        super().__init__(server_address, _Handler)


class _Handler(BaseHTTPRequestHandler):
    server_version = "autoreviewer"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Avoid storing request URLs, model output or credential-bearing bodies.
        pass

    def _send(self, status: int, content: bytes, content_type: str, *, filename=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        if status == 405:
            self.send_header("Allow", "GET, POST, PUT")
        self.end_headers()
        self.wfile.write(content)

    def _json(self, status: int, value):
        self._send(status, json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _check_browser(self):
        hosts = self.headers.get_all("Host", [])
        port = self.server.server_port
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if port == 80:
            allowed.update({"127.0.0.1", "localhost"})
        if len(hosts) != 1 or hosts[0].lower() not in allowed:
            raise _HTTPError(403, "Invalid local Host header")
        origins = self.headers.get_all("Origin", [])
        if len(origins) > 1 or (origins and origins[0] != f"http://{hosts[0].lower()}"):
            raise _HTTPError(403, "Cross-origin requests are not allowed")
        sites = self.headers.get_all("Sec-Fetch-Site", [])
        if len(sites) > 1 or (sites and sites[0] not in {"same-origin", "none"}):
            raise _HTTPError(403, "Cross-site requests are not allowed")

    def _check_token(self):
        tokens = self.headers.get_all("X-Autoreviewer-Token", [])
        if len(tokens) != 1 or not tokens[0].isascii() or not hmac.compare_digest(tokens[0], self.server.csrf_token):
            raise _HTTPError(403, "Invalid session token; reload the page")

    def _body(self, limit):
        if self.headers.get("Transfer-Encoding") is not None:
            raise _HTTPError(400, "Transfer encoding is not supported")
        lengths = self.headers.get_all("Content-Length", [])
        if not lengths:
            raise _HTTPError(411, "Content-Length is required")
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,12}", lengths[0]):
            raise _HTTPError(400, "Invalid Content-Length")
        length = int(lengths[0])
        if length > limit:
            raise _HTTPError(413, "Report import exceeds the size limit" if limit == MAX_IMPORT_BODY_BYTES else "Request exceeds 1 MiB")
        types = self.headers.get_all("Content-Type", [])
        if len(types) != 1 or types[0].split(";", 1)[0].strip().lower() != "application/json":
            raise _HTTPError(415, "Use application/json")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise _HTTPError(400, "Incomplete request body")
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                               parse_constant=_reject_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise _HTTPError(400, "Invalid JSON object (duplicate or nonfinite fields are not allowed)") from None
        if not isinstance(value, dict):
            raise _HTTPError(400, "Request body must be a JSON object")
        return value

    def _dispatch(self):
        self._check_browser()
        if self.command not in {"GET", "PUT", "POST"}:
            raise _HTTPError(405, "Method not allowed")
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise _HTTPError(400, "Use a local request path")
        path = parsed.path
        static = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                  "/styles.css": ("styles.css", "text/css")}
        if path in static:
            if self.command != "GET":
                raise _HTTPError(405, "Method not allowed")
            name, mime = static[path]
            self._send(200, files("autoreviewer").joinpath("static", name).read_bytes(), mime + "; charset=utf-8")
            return
        service = self.server.service
        if path == "/api/bootstrap" and self.command == "GET":
            self._json(200, {**service.bootstrap(), "csrf_token": self.server.csrf_token})
            return
        if not path.startswith("/api/"):
            raise _HTTPError(404, "Not found")
        self._check_token()
        limit = MAX_IMPORT_BODY_BYTES if path == "/api/reports/import" and self.command == "POST" else MAX_BODY_BYTES
        body = self._body(limit) if self.command in {"POST", "PUT"} else None
        if path == "/api/config" and self.command == "PUT":
            if (set(body) != {"config", "revision"} or not isinstance(body["config"], dict)
                    or type(body["revision"]) is not int or body["revision"] < 0):
                raise _HTTPError(400, "Provide a config object and its nonnegative integer revision")
            self._json(200, service.save_config(body["config"], expected_revision=body["revision"]))
        elif path == "/api/credentials" and self.command == "PUT":
            if set(body) != {"name", "value"} or not all(isinstance(body[k], str) for k in body):
                raise _HTTPError(400, "Provide credential name and value strings")
            self._json(200, service.set_credential(body["name"], body["value"]))
        elif path == "/api/jobs" and self.command == "GET":
            self._json(200, {"jobs": service.list_jobs()})
        elif path == "/api/jobs" and self.command == "POST":
            self._json(202, service.start_job(body))
        elif path == "/api/reports/import" and self.command == "POST":
            self._json(201, service.import_report(body))
        elif path == "/api/config/export" and self.command == "GET":
            self._send(200, service.export_config().encode("utf-8"), "text/toml; charset=utf-8",
                       filename="autoreviewer.toml")
        elif match := _JOB_PATH.fullmatch(path):
            job_id, action = match.groups()
            if action is None and self.command == "GET":
                self._json(200, service.get_job(job_id))
            elif action == "cancel" and self.command == "POST":
                if body:
                    raise _HTTPError(400, "Cancel accepts an empty JSON object")
                self._json(200, service.cancel_job(job_id))
            elif action == "retry" and self.command == "POST":
                self._json(202, service.retry_job(job_id, body))
            elif action == "report" and self.command == "GET":
                query = parse_qs(parsed.query, keep_blank_values=True)
                if set(query) - {"format"} or len(query.get("format", ["json"])) != 1:
                    raise _HTTPError(400, "Choose json or markdown report format")
                report_format = query.get("format", ["json"])[0]
                if report_format not in {"json", "markdown"}:
                    raise _HTTPError(400, "Choose json or markdown report format")
                report = service.get_report(job_id)
                if report_format == "json":
                    content = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
                    mime, suffix = "application/json", "json"
                else:
                    content, mime, suffix = render_markdown(report), "text/markdown", "md"
                self._send(200, content.encode("utf-8"), mime + "; charset=utf-8",
                           filename=f"autoreviewer-{job_id}-report.{suffix}")
            elif action == "issues/preview" and self.command == "POST":
                self._json(200, service.preview_issues(job_id, body))
            elif action == "issues/publish" and self.command == "POST":
                self._json(200, service.publish_issues(job_id, body))
            else:
                raise _HTTPError(405, "Method not allowed")
        elif path in {"/api/config", "/api/credentials", "/api/jobs", "/api/bootstrap", "/api/reports/import", "/api/config/export"}:
            raise _HTTPError(405, "Method not allowed")
        else:
            raise _HTTPError(404, "Not found")

    def _handle(self):
        try:
            self._dispatch()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except ValueError as exc:
            status = getattr(exc, "status_code", 400)
            if status not in {400, 403, 404, 405, 409, 411, 413, 415, 503}:
                status = 400
            try:
                self._json(status, {"error": str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass
        except Exception:
            try:
                self._json(500, {"error": "The local service could not complete this operation"})
            except (BrokenPipeError, ConnectionResetError):
                pass

    do_GET = _handle
    do_PUT = _handle
    do_POST = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_OPTIONS = _handle
    do_HEAD = _handle


def serve(config_path: Path, data_dir: Path, port: int = 8765, open_browser: bool = False) -> int:
    from .webservice import WebService

    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("UI port must be between 1 and 65535")
    service = WebService(config_path, data_dir)
    try:
        with LocalWebServer(("127.0.0.1", port), service) as server:
            url = f"http://127.0.0.1:{server.server_port}"
            print(f"autoreviewer UI: {url}\nLocal access only. Press Ctrl+C to stop.", flush=True)
            if open_browser:
                webbrowser.open(url)
            try:
                server.serve_forever(poll_interval=0.25)
            except KeyboardInterrupt:
                print("Stopping the UI and cancelling active review processes.", flush=True)
    finally:
        service.close()
    return 0
