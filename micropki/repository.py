"""HTTP certificate repository for MicroPKI."""

from __future__ import annotations

import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse

from .database import get_certificate_by_serial, normalize_serial_hex

_SERIAL_RE = re.compile(r"^[0-9A-Fa-f]+$")


class RepositoryRequestHandler(BaseHTTPRequestHandler):
    server_version = "MicroPKIRepository/0.3"

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

    def _log_request(self, status: int) -> None:
        logger = self.repo_logger
        if logger:
            logger.info(f"[HTTP] {self.client_address[0]} {self.command} {self.path} {status}")

    def _send_bytes(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        self._log_request(status)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        self._send_bytes(status, text.encode("utf-8"), content_type)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self._log_request(204)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") if parsed.path != "/" else parsed.path
        if path.startswith("/certificate/"):
            return self._handle_certificate(path[len("/certificate/"):])
        if path.startswith("/ca/"):
            return self._handle_ca(path[len("/ca/"):])
        if path == "/crl":
            return self._send_text(501, "CRL generation not yet implemented", "application/pkix-crl")
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


def create_repository_server(host: str, port: int, db_path: str, cert_dir: str, logger=None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, int(port)), RepositoryRequestHandler)
    server.db_path = os.path.abspath(db_path)
    server.cert_dir = os.path.abspath(cert_dir)
    server.repo_logger = logger
    return server


def serve_repository(host: str, port: int, db_path: str, cert_dir: str, logger=None) -> None:
    from .database import init_database

    init_database(db_path)
    server = create_repository_server(host, port, db_path, cert_dir, logger)
    if logger:
        logger.info(f"Repository server listening on {host}:{port}; db={os.path.abspath(db_path)}; cert_dir={os.path.abspath(cert_dir)}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if logger:
            logger.info("Repository server interrupted by user")
    finally:
        server.server_close()
