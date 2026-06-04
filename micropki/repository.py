"""HTTP certificate and CRL repository for MicroPKI."""

from __future__ import annotations

import email.utils
import hashlib
import os
import re
import tempfile
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.parse import parse_qs, urlparse

from cryptography import x509

from .database import get_certificate_by_serial, normalize_serial_hex

_SERIAL_RE = re.compile(r"^[0-9A-Fa-f]+$")


class MicroPKIThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def shutdown(self):
        t = threading.Thread(target=super().shutdown, daemon=True)
        t.start()
        t.join(timeout=2)

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
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
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
        parsed = urlparse(self.path)
        if parsed.path == "/request-cert":
            return self._handle_request_cert(parsed)
        self._send_text(405, "Method Not Allowed")

    def do_PUT(self):
        self._send_text(405, "Method Not Allowed")

    def do_DELETE(self):
        self._send_text(405, "Method Not Allowed")

    def _handle_request_cert(self, parsed):
        template = (parse_qs(parsed.query).get("template") or [""])[0]
        if template not in {"server", "client", "code_signing"}:
            return self._send_text(400, "Unsupported or missing template")
        expected_key = getattr(self.server, "api_key", None)
        if expected_key and self.headers.get("X-API-Key") != expected_key:
            return self._send_text(401, "Invalid or missing API key")
        if not getattr(self.server, "ca_cert_path", None) or not getattr(self.server, "ca_key_path", None):
            return self._send_text(503, "Repository is not configured for certificate issuance")
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return self._send_text(400, "Invalid Content-Length")
        if length <= 0:
            return self._send_text(400, "Empty CSR request")
        csr_data = self.rfile.read(length)
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile("wb", delete=False, suffix=".csr.pem") as tmp:
                tmp.write(csr_data)
                tmp_path = tmp.name
            from .ca import issue_cert
            from .cli import load_passphrase
            passphrase = load_passphrase(self.server.ca_pass_file) if getattr(self.server, "ca_pass_file", None) else None
            args = Namespace(
                ca_cert=self.server.ca_cert_path,
                ca_key=self.server.ca_key_path,
                ca_pass_file=getattr(self.server, "ca_pass_file", None),
                ca_passphrase_bytes=passphrase,
                template=template,
                subject=None,
                san=[],
                out_dir=self.cert_dir,
                validity_days=int(getattr(self.server, "default_validity_days", 365)),
                csr=tmp_path,
                db_path=self.db_path,
            )
            result = issue_cert(args, self.repo_logger)
            if self.repo_logger:
                self.repo_logger.info(f"API certificate issuance completed: source_ip={self.client_address[0]}, template={template}, serial={result['serial_hex']}")
            return self._send_bytes(201, result["cert_pem"], "application/x-pem-file")
        except SystemExit:
            return self._send_text(400, "Certificate issuance failed")
        except Exception as exc:
            return self._send_text(400, f"Certificate issuance failed: {exc}")
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

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


def create_repository_server(
    host: str,
    port: int,
    db_path: str,
    cert_dir: str,
    logger=None,
    crl_dir: str | None = None,
    ca_cert_path: str | None = None,
    ca_key_path: str | None = None,
    ca_pass_file: str | None = None,
    api_key: str | None = None,
    default_validity_days: int = 365,
) -> ThreadingHTTPServer:
    server = MicroPKIThreadingHTTPServer((host, int(port)), RepositoryRequestHandler)
    server.db_path = os.path.abspath(db_path)
    server.cert_dir = os.path.abspath(cert_dir)
    server.crl_dir = os.path.abspath(crl_dir or os.path.join(os.path.dirname(os.path.abspath(cert_dir)), "crl"))
    server.repo_logger = logger
    server.ca_cert_path = os.path.abspath(ca_cert_path) if ca_cert_path else None
    server.ca_key_path = os.path.abspath(ca_key_path) if ca_key_path else None
    server.ca_pass_file = os.path.abspath(ca_pass_file) if ca_pass_file else None
    server.api_key = api_key
    server.default_validity_days = default_validity_days
    return server


def serve_repository(
    host: str,
    port: int,
    db_path: str,
    cert_dir: str,
    logger=None,
    crl_dir: str | None = None,
    ca_cert_path: str | None = None,
    ca_key_path: str | None = None,
    ca_pass_file: str | None = None,
    api_key: str | None = None,
    default_validity_days: int = 365,
) -> None:
    from .database import init_database

    init_database(db_path)
    server = create_repository_server(
        host, port, db_path, cert_dir, logger, crl_dir,
        ca_cert_path=ca_cert_path, ca_key_path=ca_key_path, ca_pass_file=ca_pass_file,
        api_key=api_key, default_validity_days=default_validity_days,
    )
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
