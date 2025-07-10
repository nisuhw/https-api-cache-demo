"""Sequential HTTPS Forward Proxy with SSL Bumping and Caching (Non-async, single-threaded)."""

import socket
import ssl
import urllib.parse
from typing import Optional, Tuple
import tempfile
import os
import threading
import logging

from cert_utils import CertificateAuthority
from cache_utils import RequestCache


# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class HTTPSProxy:
    """HTTPS forward proxy with SSL bumping and request caching (sequential, blocking)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8888, cache=None, cache_ttl: int = 5, cache_max_size: int = 10000):
        self.host = host
        self.port = port
        self.ca = CertificateAuthority()
        self.cache = cache if cache is not None else RequestCache(ttl_seconds=cache_ttl, max_size=cache_max_size)
        # Cache is now internally thread-safe, no need for external lock

    def serve_forever(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(5)
            logging.info(f"Proxy server listening on {self.host}:{self.port}")
            logging.info(f"CA certificate: {self.ca.ca_cert_path}")
            logging.info(f"Cache TTL: {self.cache.ttl_seconds} seconds")
            logging.info(f"Cache max size: {self.cache.max_size} entries")
            print("\nMake sure to add ca.crt to your client's trusted certificates!")
            print("\nConfigure your client to use proxy:")
            print(f"  HTTP Proxy: {self.host}:{self.port}")
            print(f"  HTTPS Proxy: {self.host}:{self.port}")
            while True:
                logging.debug("Waiting for new client connection...")
                client_sock, client_addr = server_sock.accept()
                logging.debug(f"New connection from {client_addr}")
                t = threading.Thread(target=self.handle_client, args=(client_sock,))
                t.daemon = True
                t.start()

    def handle_client(self, client_sock: socket.socket):
        client_file = client_sock.makefile('rb')
        request_line = client_file.readline()
        if not request_line:
            logging.info("Empty request line from client.")
            return
        request_line = request_line.decode('utf-8').strip()
        logging.debug(f"Request line: {request_line}")
        parts = request_line.split(" ")
        if len(parts) < 3:
            logging.warning(f"Malformed request line: {request_line}")
            return
        method, path, version = parts[0], parts[1], parts[2]
        headers = {}
        while True:
            header_line = client_file.readline()
            if header_line in (b"\r\n", b"\n", b"", None):
                break
            header_line = header_line.decode('utf-8').strip()
            if ":" in header_line:
                key, value = header_line.split(":", 1)
                headers[key.strip()] = value.strip()
        logging.debug(f"Method: {method}, Path: {path}, Version: {version}")
        logging.debug(f"Headers: {headers}")
        if method == "CONNECT":
            self.handle_connect(client_sock, client_file, path, headers)
        else:
            logging.warning(f"Non-CONNECT method received: {method}")
            self.handle_http(client_sock)

    def handle_connect(self, client_sock, client_file, target, headers):
        if ":" in target:
            target_host, target_port = target.split(":", 1)
            target_port = int(target_port)
        else:
            target_host = target
            target_port = 443
        logging.debug(f"CONNECT to {target_host}:{target_port}")
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\nProxy-Connection: Keep-Alive\r\n\r\n")
        cert_pem, key_pem = self.ca.get_cert_key_paths(target_host)
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as cert_file:
            cert_file.write(cert_pem)
            cert_path = cert_file.name
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as key_file:
            key_file.write(key_pem)
            key_path = key_file.name
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            ssl_client_sock = context.wrap_socket(client_sock, server_side=True)
            logging.debug(f"Upgraded client connection to SSL for {target_host}")
            self.handle_https_requests(ssl_client_sock, target_host, target_port)
        except ssl.SSLError as e:
            if "EOF occurred in violation of protocol" in str(e):
                logging.warning(f"Client disconnected during SSL handshake for {target_host}")
            else:
                logging.error(f"SSL error in CONNECT handler: {e}")
        except Exception as e:
            logging.error(f"Error in CONNECT handler: {e}")
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    def handle_https_requests(self, ssl_client_sock, target_host, target_port):
        while True:
            request_data = self.read_http_request(ssl_client_sock)
            if not request_data:
                logging.debug(f"No more HTTPS requests from client.")
                break
            method, path, version, headers, body = request_data
            url = f"https://{target_host}:{target_port}{path}"
            logging.debug(f"HTTPS {method} {url}")
            
            # Cache is now internally thread-safe
            cached_response = self.cache.get(method, url, headers, body)
            if cached_response:
                logging.info(f"[CACHE] HIT for {method} {url}")
                ssl_client_sock.sendall(cached_response["status_line"].encode())
                for header in cached_response["headers"]:
                    ssl_client_sock.sendall(header.encode())
                ssl_client_sock.sendall(b"\r\n")
                ssl_client_sock.sendall(cached_response["body"])
                continue
            logging.info(f"[CACHE] MISS for {method} {url}")
            response_data = self.forward_https_request(target_host, target_port, method, path, version, headers, body)
            if response_data:
                logging.debug(f"Forwarded {method} {url} to upstream server.")
                ssl_client_sock.sendall(response_data["status_line"].encode())
                for header in response_data["headers"]:
                    ssl_client_sock.sendall(header.encode())
                ssl_client_sock.sendall(b"\r\n")
                ssl_client_sock.sendall(response_data["body"])
                # Cache is now internally thread-safe
                self.cache.set(method, url, headers, body, response_data)
            else:
                logging.error(f"Failed to get response from upstream for {method} {url}")

    def read_http_request(self, sock) -> Optional[Tuple]:
        file = sock.makefile('rb')
        request_line = file.readline()
        if not request_line:
            logging.debug("Empty HTTPS request line.")
            return None
        request_line = request_line.decode('utf-8').strip()
        if not request_line:
            logging.warning("Blank HTTPS request line.")
            return None
        parts = request_line.split(" ")
        if len(parts) < 3:
            logging.warning(f"Malformed HTTPS request line: {request_line}")
            return None
        method, path, version = parts[0], parts[1], parts[2]
        headers = {}
        content_length = 0
        while True:
            header_line = file.readline()
            if header_line in (b"\r\n", b"\n", b"", None):
                break
            header_line = header_line.decode('utf-8').strip()
            if ":" in header_line:
                key, value = header_line.split(":", 1)
                key = key.strip()
                value = value.strip()
                headers[key] = value
                if key.lower() == "content-length":
                    content_length = int(value)
        body = b""
        if content_length > 0:
            body = file.read(content_length)
        logging.debug(f"HTTPS Request: {method} {path} {version}, Headers: {headers}, Body length: {len(body)}")
        return method, path, version, headers, body

    def forward_https_request(self, host, port, method, path, version, headers, body) -> Optional[dict]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as server_sock:
                with context.wrap_socket(server_sock, server_hostname=host) as ssl_server_sock:
                    logging.debug(f"Connecting to upstream {host}:{port} for {method} {path}")
                    ssl_server_sock.sendall(f"{method} {path} {version}\r\n".encode())
                    for key, value in headers.items():
                        if key.lower() not in ["proxy-connection", "connection"]:
                            ssl_server_sock.sendall(f"{key}: {value}\r\n".encode())
                    ssl_server_sock.sendall(b"Connection: close\r\n\r\n")
                    if body:
                        ssl_server_sock.sendall(body)
                    file = ssl_server_sock.makefile('rb')
                    response_line = file.readline().decode('utf-8').strip()
                    response_headers = []
                    while True:
                        header_line = file.readline()
                        if header_line in (b"\r\n", b"\n", b"", None):
                            break
                        response_headers.append(header_line.decode('utf-8').strip())
                    response_body = file.read()
                    logging.debug(f"Upstream response: {response_line}, Headers: {response_headers}, Body length: {len(response_body)}")
                    return {
                        "status_line": response_line + "\r\n",
                        "headers": [h + "\r\n" for h in response_headers],
                        "body": response_body,
                    }
        except Exception as e:
            logging.error(f"Error forwarding request to {host}:{port} - {e}")
            return None

    def handle_http(self, client_sock):
        logging.warning("HTTP request received, only HTTPS CONNECT is supported.")
        client_sock.sendall(b"HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain\r\n\r\nThis proxy only supports HTTPS connections via CONNECT method.\r\n")


def healthcheck_server(cache):
    """Simple HTTP healthcheck server on port 8889."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", 8889))
        server_sock.listen(5)
        logging.info("Healthcheck server listening on 0.0.0.0:8889 (/healthz)")
        while True:
            client_sock, _ = server_sock.accept()
            try:
                file = client_sock.makefile('rb')
                request_line = file.readline()
                if request_line:
                    line = request_line.decode().strip()
                    if line.startswith("GET /healthz"):
                        stats = cache.stats() if cache else {}
                        logging.info(f"Healthcheck cache stats: {stats}")
                        import json as _json
                        stats_json = _json.dumps(stats)
                        response = (
                            f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(stats_json)}\r\n\r\n{stats_json}"
                        )
                        client_sock.sendall(response.encode())
            except Exception as e:
                logging.error(f"Healthcheck error: {e}")
            finally:
                client_sock.close()

def main():
    shared_cache = RequestCache(ttl_seconds=5, max_size=10000)
    proxy = HTTPSProxy(host="0.0.0.0", port=8888, cache=shared_cache)
    health_thread = threading.Thread(target=healthcheck_server, args=(shared_cache,), daemon=True)
    health_thread.start()
    proxy.serve_forever()

if __name__ == "__main__":
    main()
