"""HTTP OCSP responder for MicroPKI."""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from urllib.parse import urlparse

from .certificates import load_certificate
from .database import init_database
from .ocsp import load_ocsp_private_key, process_ocsp_request, validate_ocsp_signer_certificate
from .ratelimit import TokenBucketRateLimiter


class MicroPKIThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def shutdown(self):
        # BaseServer.shutdown can block forever in rare test races if called
        # while serve_forever is not fully inside its loop. Bound it.
        self._micropki_shutdown_requested = True
        t = threading.Thread(target=super().shutdown, daemon=True)
        t.start()
        t.join(timeout=2)

    def server_close(self):
        # On Windows, closing the listening socket while serve_forever() is still
        # polling it can raise WinError 10038 in the background thread. Make
        # server_close() safe for tests and callers that forgot shutdown().
        if not getattr(self, "_micropki_shutdown_requested", False):
            self.shutdown()
        super().server_close()

class OCSPRequestHandler(BaseHTTPRequestHandler):
    server_version = "MicroPKIOCSP/0.5"

    def log_message(self, format, *args):  # noqa: A003 - BaseHTTPRequestHandler API
        return

    @property
    def ocsp_logger(self):
        return getattr(self.server, "ocsp_logger", None)

    def _rate_limit_exceeded(self) -> bool:
        limiter = getattr(self.server, "rate_limiter", None)
        if not limiter:
            return False
        allowed, retry_after = limiter.allow(self.client_address[0])
        if allowed:
            return False
        body = b"Too Many Requests"
        self.send_response(429)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Retry-After", str(retry_after))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        if self.ocsp_logger:
            self.ocsp_logger.warning(f"Rate limit exceeded: client_ip={self.client_address[0]}, path={self.path}")
        return True

    def _send_bytes(self, status: int, body: bytes, content_type: str = "application/ocsp-response") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_text(self, status: int, text: str) -> None:
        self._send_bytes(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    def do_OPTIONS(self):
        if self._rate_limit_exceeded():
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self._rate_limit_exceeded():
            return
        self._send_text(405, "OCSP responder accepts POST requests only")

    def do_POST(self):
        if self._rate_limit_exceeded():
            return
        parsed = urlparse(self.path)
        if parsed.path not in {"/", "/ocsp"}:
            self._send_text(404, "Not Found")
            return
        content_type = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/ocsp-request":
            if self.ocsp_logger:
                self.ocsp_logger.error(
                    f'{{"event":"ocsp_error","client_ip":"{self.client_address[0]}",'
                    f'"error":"unsupported_content_type:{content_type}"}}'
                )
            self._send_text(400, "Content-Type must be application/ocsp-request")
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            self._send_text(400, "Invalid Content-Length")
            return
        if length <= 0:
            self._send_text(400, "Empty OCSP request")
            return
        data = self.rfile.read(length)
        status, body, response_type, _ = process_ocsp_request(
            data,
            self.server.db_path,
            self.server.ca_cert,
            self.server.responder_cert,
            self.server.responder_key,
            self.server.cache_ttl,
            self.ocsp_logger,
            self.client_address[0],
        )
        self._send_bytes(status, body, response_type)


def create_ocsp_server(
    host: str,
    port: int,
    db_path: str,
    responder_cert_path: str,
    responder_key_path: str,
    ca_cert_path: str,
    cache_ttl: int = 60,
    logger=None,
    rate_limit: float = 0,
    rate_burst: int = 10,
) -> ThreadingHTTPServer:
    init_database(db_path)
    responder_cert = load_certificate(responder_cert_path)
    validate_ocsp_signer_certificate(responder_cert)
    responder_key = load_ocsp_private_key(responder_key_path)
    ca_cert = load_certificate(ca_cert_path)

    server = MicroPKIThreadingHTTPServer((host, int(port)), OCSPRequestHandler)
    server.db_path = os.path.abspath(db_path)
    server.responder_cert = responder_cert
    server.responder_key = responder_key
    server.ca_cert = ca_cert
    server.cache_ttl = int(cache_ttl)
    server.ocsp_logger = logger
    server.rate_limiter = TokenBucketRateLimiter(rate_limit, rate_burst)
    return server


def serve_ocsp(
    host: str,
    port: int,
    db_path: str,
    responder_cert_path: str,
    responder_key_path: str,
    ca_cert_path: str,
    cache_ttl: int = 60,
    logger=None,
    rate_limit: float = 0,
    rate_burst: int = 10,
) -> None:
    server = create_ocsp_server(
        host,
        port,
        db_path,
        responder_cert_path,
        responder_key_path,
        ca_cert_path,
        cache_ttl,
        logger,
        rate_limit=rate_limit,
        rate_burst=rate_burst,
    )
    if logger:
        logger.info(
            f"OCSP responder listening on {host}:{port}; db={os.path.abspath(db_path)}; "
            f"responder_cert={os.path.abspath(responder_cert_path)}; ca_cert={os.path.abspath(ca_cert_path)}; rate_limit={rate_limit}; rate_burst={rate_burst}"
        )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if logger:
            logger.info("OCSP responder interrupted by user")
    finally:
        server.server_close()
