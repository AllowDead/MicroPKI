"""HTTP certificate and CRL repository for MicroPKI."""

from __future__ import annotations

import email.utils
import hashlib
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from cryptography import x509

from .database import get_certificate_by_serial, normalize_serial_hex

_SERIAL_RE = re.compile(r"^[0-9A-Fa-f]+$")


class RepositoryRequestHandler(BaseHTTPRequestHandler):
    server_version = "MicroPKIRepository/0.4"

    def log_message(self, format, *args):  # noqa: A003 - BaseHTTPRequestHandler API
        return

    @property
    def repo_logger(self):
        return getattr(self.server, "repo_logger", None)

    @property
    def db_path(self):
        return getattr(self.server, "db_path")

    @property
    def cert_dir(self):
        return getattr(self.server, "cert_dir")

    @property
    def crl_dir(self):
        return getattr(self.server, "crl_dir")

    def _log_request(self, status: int) -> None:
        logger = self.repo_logger
        if logger:
            logger.info(f"[HTTP] {self.client_address[0]} {self.command} {self.path} {status}")

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/plain; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self._log_request(status)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        self._send_bytes(status, text.encode("utf-8"), content_type)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self._log_request(204)

    def do_HEAD(self):
        return self.do_GET()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") if parsed.path != "/" else parsed.path
        if path.startswith("/certificate/"):
            return self._handle_certificate(path[len("/certificate/"):])
        if path.startswith("/ca/"):
            return self._handle_ca(path[len("/ca/"):])
        if path == "/crl":
            query = parse_qs(parsed.query)
            ca = (query.get("ca") or ["intermediate"])[0]
            return self._handle_crl(ca)
        if path.startswith("/crl/"):
            leaf = path[len("/crl/"):]
            if leaf.endswith(".crl"):
                leaf = leaf[:-4]
            return self._handle_crl(leaf)
        return self._send_text(404, "Not Found")

    def do_POST(self):
        self._send_text(405, "Method Not Allowed")

    def do_PUT(self):
        self._send_text(405, "Method Not Allowed")

    def do_DELETE(self):
        self._send_text(405, "Method Not Allowed")

    def _handle_certificate(self, serial: str):
        serial = serial.strip()
        if not serial or not _SERIAL_RE.fullmatch(serial):
            return self._send_text(400, "Malformed serial number. Use hexadecimal characters only.")
        try:
            record = get_certificate_by_serial(self.db_path, normalize_serial_hex(serial))
        except ValueError as exc:
            return self._send_text(400, str(exc))
        except Exception as exc:
            return self._send_text(500, f"Database error: {exc}")
        if not record:
            return self._send_text(404, "Certificate not found")
        return self._send_bytes(200, record["cert_pem"].encode("ascii"), "application/x-pem-file")

    def _handle_ca(self, level: str):
        level = level.lower().strip()
        if level == "root":
            filename = "ca.cert.pem"
        elif level == "intermediate":
            filename = "intermediate.cert.pem"
        else:
            return self._send_text(400, "Unsupported CA level. Use root or intermediate.")
        path = os.path.join(self.cert_dir, filename)
        if not os.path.isfile(path):
            return self._send_text(404, "CA certificate not found")
        with open(path, "rb") as f:
            data = f.read()
        return self._send_bytes(200, data, "application/x-pem-file")

    def _handle_crl(self, ca: str):
        ca = ca.lower().strip()
        if ca not in {"root", "intermediate"}:
            return self._send_text(400, "Unsupported CRL CA. Use root or intermediate.")
        path = os.path.join(self.crl_dir, f"{ca}.crl.pem")
        if not os.path.isfile(path):
            return self._send_text(404, "CRL not found")
        with open(path, "rb") as f:
            data = f.read()
        return self._send_bytes(200, data, "application/pkix-crl", _crl_headers(path, data))


def _http_date(timestamp: float) -> str:
    return email.utils.formatdate(timestamp, usegmt=True)


def _crl_headers(path: str, data: bytes) -> dict[str, str]:
    headers = {
        "Last-Modified": _http_date(os.path.getmtime(path)),
        "ETag": hashlib.sha256(data).hexdigest(),
    }
    try:
        crl = x509.load_pem_x509_crl(data)
        now = crl.last_update_utc
        next_update = crl.next_update_utc
        max_age = max(0, int((next_update - now).total_seconds()))
        headers["Cache-Control"] = f"max-age={max_age}"
    except Exception:
        headers["Cache-Control"] = "max-age=0"
    return headers


def create_repository_server(host: str, port: int, db_path: str, cert_dir: str, logger=None, crl_dir: str | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, int(port)), RepositoryRequestHandler)
    server.db_path = os.path.abspath(db_path)
    server.cert_dir = os.path.abspath(cert_dir)
    server.crl_dir = os.path.abspath(crl_dir or os.path.join(os.path.dirname(os.path.abspath(cert_dir)), "crl"))
    server.repo_logger = logger
    return server


def serve_repository(host: str, port: int, db_path: str, cert_dir: str, logger=None, crl_dir: str | None = None) -> None:
    from .database import init_database

    init_database(db_path)
    server = create_repository_server(host, port, db_path, cert_dir, logger, crl_dir)
    if logger:
        logger.info(
            f"Repository server listening on {host}:{port}; db={os.path.abspath(db_path)}; "
            f"cert_dir={os.path.abspath(cert_dir)}; crl_dir={server.crl_dir}"
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if logger:
            logger.info("Repository server interrupted by user")
    finally:
        server.server_close()
