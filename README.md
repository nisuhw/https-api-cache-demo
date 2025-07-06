# HTTPS Proxy with SSL Bumping and Caching

A Python proof-of-concept implementation of an HTTPS forward proxy with SSL bumping (MITM) capabilities and request caching.

## Features

- **HTTPS Forward Proxy**: Handles HTTPS CONNECT traffic
- **SSL Bumping**: Decrypts and re-encrypts HTTPS traffic for inspection
- **Self-signed CA**: Uses a self-signed CA certificate for SSL interception
- **Request Caching**: Caches responses for 5 seconds based on request hash
- **Async Implementation**: Built with Python's asyncio for concurrent connections

## Requirements

- Python 3.7+
- Each service (proxy and client) has its own requirements.txt file with only the dependencies it needs.

## Installation

1. Clone the repository:
```bash
cd https-proxy-caching-demo
```

2. Install dependencies for each service:
   - For the proxy server:
     ```bash
     cd proxy
     pip install -r requirements.txt
     ```
   - For the client:
     ```bash
     cd ../client
     pip install -r requirements.txt
     ```

## Dependency Separation

This project uses separate requirements files for the proxy and client services to minimize dependencies and improve maintainability:

- **proxy/requirements.txt** (for the proxy server):
  ```
  cryptography>=41.0.0
  ```
- **client/requirements.txt** (for the test client):
  ```
  requests>=2.31.0
  urllib3>=1.26.0
  ```

## Usage

### 1. Start the Proxy Server

```bash
python proxy_server.py
```

The proxy will:
- Listen on `127.0.0.1:8888` by default
- Generate a CA certificate (`ca.crt` and `ca.key`) if not present
- Cache requests for 5 seconds

### 2. Configure Your Client

#### Option A: Trust the CA Certificate (Recommended for testing)

1. The proxy generates `ca.crt` on first run
2. Add this certificate to your system's trusted certificates:
   - **macOS**: Double-click `ca.crt` and add to Keychain
   - **Linux**: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
   - **Windows**: Import via Certificate Manager

#### Option B: Disable Certificate Verification (Not recommended)

Configure your HTTP client to skip certificate verification (see test_client.py example).

### 3. Configure Proxy Settings

Set your application or system to use:
- HTTP Proxy: `127.0.0.1:8888`
- HTTPS Proxy: `127.0.0.1:8888`

### 4. Test the Proxy

Run the test client:
```bash
python test_client.py
```

This will demonstrate:
- Cache MISS on first request
- Cache HIT on subsequent requests within 5 seconds
- Cache expiration after 5 seconds

## How It Works

### SSL Bumping Process

1. Client sends CONNECT request to proxy
2. Proxy responds with "200 Connection Established"
3. Proxy generates a certificate for the target domain (signed by our CA)
4. Client performs SSL handshake with proxy (using generated certificate)
5. Proxy establishes separate SSL connection to target server
6. Proxy decrypts client requests, forwards to server, and caches responses

### Caching Mechanism

- Cache key is generated using SHA256 hash of:
  - HTTP method
  - URL
  - Relevant headers (excluding auth/cookies)
  - Request body hash
- Responses are cached for 5 seconds
- Cache checks happen before forwarding requests to target server

## Project Structure

```
https-proxy-caching-demo/
├── proxy/
│   ├── proxy_server.py    # Main proxy server implementation
│   ├── cert_utils.py      # Certificate generation utilities
│   ├── cache_utils.py     # Request caching implementation
│   ├── requirements.txt   # Proxy dependencies
├── client/
│   ├── test_client.py     # Test client to demonstrate functionality
│   ├── requirements.txt   # Client dependencies
├── README.md              # This file
```

## Security Considerations

⚠️ **WARNING**: This is a proof-of-concept implementation for educational purposes.

- SSL bumping (MITM) should only be used in controlled environments
- Never use this proxy for production traffic
- The self-signed CA certificate gives the proxy ability to decrypt all HTTPS traffic
- Only trust the CA certificate on test systems

## Customization

You can modify the proxy behavior:

- Change cache TTL: Modify `cache_ttl` parameter in `proxy_server.py`
- Change proxy port: Modify `port` parameter in `proxy_server.py`
- Customize cache key generation: Edit `_generate_cache_key` in `cache_utils.py`

## Limitations

- Only supports HTTPS traffic (HTTP CONNECT method)
- Simple in-memory cache (not persistent)
- Basic HTTP/1.1 support
- No connection pooling for upstream servers
- Single-threaded per connection

## Troubleshooting

1. **"Connection refused" error**: Make sure the proxy server is running
2. **SSL certificate errors**: Either trust the CA certificate or use `verify=False` in your client
3. **Cache not working**: Check proxy server logs for cache HIT/MISS messages
4. **Performance issues**: This is a simple implementation without optimizations

## License

This is a proof-of-concept for educational purposes. 