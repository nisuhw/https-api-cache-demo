"""HTTPS Forward Proxy with SSL Bumping and Caching."""

import asyncio
import socket
import ssl
import urllib.parse
from typing import Optional, Tuple
import tempfile
import os
import threading

from cert_utils import CertificateAuthority
from cache_utils import RequestCache


class HTTPSProxy:
    """HTTPS forward proxy with SSL bumping and request caching."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8888, cache_ttl: int = 5):
        self.host = host
        self.port = port
        self.ca = CertificateAuthority()
        self.cache = RequestCache(ttl_seconds=cache_ttl)

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle incoming client connection."""
        client_addr = writer.get_extra_info("peername")
        print(f"New connection from {client_addr}")

        try:
            # Read the initial request
            request_line = await reader.readline()
            if not request_line:
                return

            request_line = request_line.decode("utf-8").strip()
            print(f"Request: {request_line}")

            parts = request_line.split(" ")
            if len(parts) < 3:
                return

            method, path, version = parts[0], parts[1], parts[2]

            # Read headers
            headers = {}
            while True:
                header_line = await reader.readline()
                if header_line == b"\r\n" or not header_line:
                    break
                header_line = header_line.decode("utf-8").strip()
                if ":" in header_line:
                    key, value = header_line.split(":", 1)
                    headers[key.strip()] = value.strip()

            if method == "CONNECT":
                # Handle HTTPS CONNECT method
                await self.handle_connect(reader, writer, path, headers)
            else:
                # Handle regular HTTP proxy request
                await self.handle_http(reader, writer, method, path, version, headers)

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
        headers: dict,
    ):
        """Handle CONNECT method for HTTPS tunneling with SSL bumping."""
        try:
            # Parse target host and port
            if ":" in target:
                target_host, target_port = target.split(":", 1)
                target_port = int(target_port)
            else:
                target_host = target
                target_port = 443

            print(f"CONNECT to {target_host}:{target_port}")

            # Send 200 Connection Established to client
            writer.write(b"HTTP/1.1 200 Connection Established\r\n")
            writer.write(b"Proxy-Connection: Keep-Alive\r\n")
            writer.write(b"\r\n")
            await writer.drain()

            # Generate certificate for target host
            cert_pem, key_pem = self.ca.get_cert_key_paths(target_host)

            # Create SSL context for client connection
            client_ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

            # Use temporary files for certificate and key
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name

            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as key_file:
                key_file.write(key_pem)
                key_path = key_file.name

            try:
                client_ssl_context.load_cert_chain(cert_path, key_path)

                # Upgrade client connection to SSL
                transport = writer.transport
                protocol = transport.get_protocol()

                loop = asyncio.get_event_loop()
                ssl_transport = await loop.start_tls(
                    transport, protocol, client_ssl_context, server_side=True
                )

                # Create new StreamReader and StreamWriter for the SSL transport
                ssl_reader = asyncio.StreamReader()
                ssl_protocol = asyncio.StreamReaderProtocol(ssl_reader)
                ssl_transport.set_protocol(ssl_protocol)
                ssl_writer = asyncio.StreamWriter(
                    ssl_transport, ssl_protocol, ssl_reader, loop
                )

                # Now handle HTTPS requests from client using the SSL streams
                await self.handle_https_requests(
                    ssl_reader, ssl_writer, target_host, target_port
                )

            finally:
                # Clean up temporary files
                os.unlink(cert_path)
                os.unlink(key_path)

        except Exception as e:
            print(f"Error in CONNECT handler: {e}")

    async def handle_https_requests(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ):
        """Handle HTTPS requests after SSL handshake."""
        try:
            while True:
                # Read request from client
                request_data = await self.read_http_request(reader)
                if not request_data:
                    break

                method, path, version, headers, body = request_data

                # Construct full URL
                url = f"https://{target_host}:{target_port}{path}"

                # Check cache
                cached_response = self.cache.get(method, url, headers, body)
                if cached_response:
                    # Send cached response
                    writer.write(cached_response["status_line"].encode())
                    for header in cached_response["headers"]:
                        writer.write(header.encode())
                    writer.write(b"\r\n")
                    writer.write(cached_response["body"])
                    await writer.drain()
                    continue

                # Forward request to target server
                response_data = await self.forward_https_request(
                    target_host, target_port, method, path, version, headers, body
                )

                if response_data:
                    # Send response to client
                    writer.write(response_data["status_line"].encode())
                    for header in response_data["headers"]:
                        writer.write(header.encode())
                    writer.write(b"\r\n")
                    writer.write(response_data["body"])
                    await writer.drain()

                    # Cache the response
                    self.cache.set(method, url, headers, body, response_data)

        except Exception as e:
            print(f"Error handling HTTPS requests: {e}")

    async def read_http_request(self, reader: asyncio.StreamReader) -> Optional[Tuple]:
        """Read a complete HTTP request."""
        try:
            # Read request line
            request_line = await reader.readline()
            if not request_line:
                return None

            request_line = request_line.decode("utf-8").strip()
            if not request_line:
                return None

            parts = request_line.split(" ")
            if len(parts) < 3:
                return None

            method, path, version = parts[0], parts[1], parts[2]

            # Read headers
            headers = {}
            content_length = 0
            while True:
                header_line = await reader.readline()
                if header_line == b"\r\n" or not header_line:
                    break
                header_line = header_line.decode("utf-8").strip()
                if ":" in header_line:
                    key, value = header_line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    headers[key] = value
                    if key.lower() == "content-length":
                        content_length = int(value)

            # Read body if present
            body = b""
            if content_length > 0:
                body = await reader.read(content_length)

            return method, path, version, headers, body

        except Exception as e:
            print(f"Error reading request: {e}")
            return None

    async def forward_https_request(
        self,
        host: str,
        port: int,
        method: str,
        path: str,
        version: str,
        headers: dict,
        body: bytes,
    ) -> Optional[dict]:
        """Forward HTTPS request to target server."""
        try:
            # Create SSL context for server connection
            ssl_context = ssl.create_default_context()

            # Connect to target server
            reader, writer = await asyncio.open_connection(host, port, ssl=ssl_context)

            # Send request
            request_line = f"{method} {path} {version}\r\n"
            writer.write(request_line.encode())

            # Forward headers (excluding some proxy-specific ones)
            for key, value in headers.items():
                if key.lower() not in ["proxy-connection", "connection"]:
                    writer.write(f"{key}: {value}\r\n".encode())

            # Ensure connection close for simplicity
            writer.write(b"Connection: close\r\n")
            writer.write(b"\r\n")

            if body:
                writer.write(body)

            await writer.drain()

            # Read response
            response_line = await reader.readline()
            response_line = response_line.decode("utf-8").strip()

            # Read response headers
            response_headers = []
            while True:
                header_line = await reader.readline()
                if header_line == b"\r\n":
                    break
                response_headers.append(header_line.decode("utf-8").strip())

            # Read response body
            response_body = await reader.read()

            writer.close()
            await writer.wait_closed()

            return {
                "status_line": response_line + "\r\n",
                "headers": [h + "\r\n" for h in response_headers],
                "body": response_body,
            }

        except Exception as e:
            print(f"Error forwarding request: {e}")
            return None

    async def handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        url: str,
        version: str,
        headers: dict,
    ):
        """Handle regular HTTP proxy requests."""
        # For this POC, we'll focus on HTTPS
        writer.write(b"HTTP/1.1 501 Not Implemented\r\n")
        writer.write(b"Content-Type: text/plain\r\n")
        writer.write(b"\r\n")
        writer.write(
            b"This proxy only supports HTTPS connections via CONNECT method.\r\n"
        )
        await writer.drain()

    async def start(self):
        """Start the proxy server."""
        server = await asyncio.start_server(self.handle_client, self.host, self.port)

        print(f"Proxy server listening on {self.host}:{self.port}")
        print(f"CA certificate: {self.ca.ca_cert_path}")
        print(f"Cache TTL: {self.cache.ttl_seconds} seconds")
        print("\nMake sure to add ca.crt to your client's trusted certificates!")
        print("\nConfigure your client to use proxy:")
        print(f"  HTTP Proxy: {self.host}:{self.port}")
        print(f"  HTTPS Proxy: {self.host}:{self.port}")

        async with server:
            await server.serve_forever()


async def healthcheck_server():
    """A simple HTTP healthcheck server on port 8889."""

    async def handle_health(reader, writer):
        request_line = await reader.readline()
        if request_line:
            # Only respond to GET /healthz
            line = request_line.decode().strip()
            if line.startswith("GET /healthz"):
                response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK"
                writer.write(response.encode())
                await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_health, "0.0.0.0", 8889)
    async with server:
        await server.serve_forever()


async def main():
    """Main entry point."""
    proxy = HTTPSProxy(host="0.0.0.0", port=8888, cache_ttl=5)
    # Run proxy and healthcheck server concurrently
    await asyncio.gather(
        proxy.start(),
        healthcheck_server(),
    )


if __name__ == "__main__":
    asyncio.run(main())
