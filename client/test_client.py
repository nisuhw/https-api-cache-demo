"""Test client for the HTTPS proxy with caching."""

import time
import asyncio
import aiohttp
import urllib3
import sys
import ssl
import os
import socket
import re
import traceback
import argparse
from collections import defaultdict


class CacheIntegrityError(Exception):
    """Exception raised when cache hit response doesn't match the original response."""

    pass


def get_ssl_verify_setting():
    """Get SSL verification setting from environment variable."""
    ssl_verify_env = os.environ.get("SSL_VERIFY", "true").lower()
    return ssl_verify_env not in ("false", "0", "no", "off")


def create_ssl_context():
    """Create SSL context based on SSL_VERIFY environment variable."""
    if get_ssl_verify_setting():
        # Use default SSL context with verification enabled
        return ssl.create_default_context()
    else:
        # Create SSL context with verification disabled
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context


async def test_proxy_with_caching():
    """Test the proxy server with caching functionality using aiohttp."""
    test_url = "https://www.uuidtools.com/api/generate/v4/count/1"

    ssl_verify = get_ssl_verify_setting()
    print("Testing HTTPS Proxy with Caching (aiohttp)")
    print("=" * 50)
    print(f"Test URL: {test_url}")
    print("Cache TTL: 5 seconds")
    print(f"SSL Verification: {'Enabled' if ssl_verify else 'Disabled'}")
    print()

    try:
        # Create connector with SSL settings
        connector = aiohttp.TCPConnector(
            ssl=create_ssl_context() if ssl_verify else False
        )

        async with aiohttp.ClientSession(
            trust_env=True, connector=connector
        ) as session:
            # First request - should be a cache MISS
            print("Request 1 - Should be CACHE MISS:")
            start_time = time.time()
            async with session.get(test_url) as response1:
                text1 = await response1.text()
                elapsed1 = time.time() - start_time
                print(f"  Status: {response1.status}")
                print(f"  Time: {elapsed1:.3f}s")
                print(f"  Response snippet: {text1[:100]}...")
                print()

            # Second request immediately - should be a cache HIT
            print("Request 2 - Should be CACHE HIT (immediate):")
            start_time = time.time()
            async with session.get(test_url) as response2:
                text2 = await response2.text()
                elapsed2 = time.time() - start_time
                print(f"  Status: {response2.status}")
                print(f"  Time: {elapsed2:.3f}s (should be faster)")
                print(f"  Response snippet: {text2[:100]}...")
                print()

            # Verify cache HIT response body matches the MISS
            if text1 == text2:
                print("[CHECK] Cache HIT response body matches the MISS (OK)")
            else:
                error_msg = f"Cache HIT response body does NOT match the MISS!\nOriginal: {text1[:200]}...\nCached: {text2[:200]}..."
                print(f"[ERROR] {error_msg}")
                raise CacheIntegrityError(error_msg)
            print()

            # Wait for 3 seconds
            print("Waiting 3 seconds...")
            await asyncio.sleep(3)

            # Third request - should still be a cache HIT
            print("Request 3 - Should be CACHE HIT (after 3s):")
            start_time = time.time()
            async with session.get(test_url) as response3:
                text3 = await response3.text()
                elapsed3 = time.time() - start_time
                print(f"  Status: {response3.status}")
                print(f"  Time: {elapsed3:.3f}s (should be faster)")
                print()

            # Verify cache HIT response body matches the original
            if text1 == text3:
                print("[CHECK] Cache HIT response body matches the original (OK)")
            else:
                error_msg = f"Cache HIT response body does NOT match the original!\nOriginal: {text1[:200]}...\nCached: {text3[:200]}..."
                print(f"[ERROR] {error_msg}")
                raise CacheIntegrityError(error_msg)
            print()

            # Wait for 3 more seconds (total 6 seconds)
            print("Waiting 3 more seconds (total 6s)...")
            await asyncio.sleep(3)

            # Fourth request - should be a cache MISS (expired)
            print("Request 4 - Should be CACHE MISS (after 6s, cache expired):")
            start_time = time.time()
            async with session.get(test_url) as response4:
                text4 = await response4.text()
                elapsed4 = time.time() - start_time
                print(f"  Status: {response4.status}")
                print(f"  Time: {elapsed4:.3f}s (should be slower)")
                print()

            # Test with POST request (different method)
            print("Request 5 - POST request (different method, should be CACHE MISS):")
            start_time = time.time()
            async with session.post(
                "https://httpbin.org/post",
                json={"test": "data"},
            ) as response5:
                text5 = await response5.text()
                elapsed5 = time.time() - start_time
                print(f"  Status: {response5.status}")
                print(f"  Time: {elapsed5:.3f}s")
                print()

    except CacheIntegrityError:
        # Re-raise cache integrity errors
        raise
    except aiohttp.ClientProxyConnectionError as e:
        print(f"Proxy Error: {e}")
        print("\nMake sure the proxy server is running on port 8888")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    print("Test completed!")
    print("\nSummary:")
    print(f"  Cache MISS time: ~{elapsed1:.3f}s")
    print(f"  Cache HIT time: ~{elapsed2:.3f}s")
    print(f"  Speedup: ~{elapsed1 / elapsed2:.1f}x")


async def load_test_proxy(
    test_url,
    num_clients=10,
    requests_per_client=10,
    method="GET",
    payload=None,
    ssl_verify=True,
):
    """Load test the proxy server with multiple concurrent clients."""
    stats = defaultdict(list)
    errors = []

    async def client_task(client_id):
        connector = aiohttp.TCPConnector(
            ssl=create_ssl_context() if ssl_verify else False
        )
        async with aiohttp.ClientSession(
            trust_env=True, connector=connector
        ) as session:
            for i in range(requests_per_client):
                try:
                    start_time = time.time()
                    if method == "GET":
                        async with session.get(test_url) as resp:
                            text = await resp.text()
                            elapsed = time.time() - start_time
                            stats["elapsed"].append(elapsed)
                            stats["status"].append(resp.status)
                    elif method == "POST":
                        async with session.post(test_url, json=payload) as resp:
                            text = await resp.text()
                            elapsed = time.time() - start_time
                            stats["elapsed"].append(elapsed)
                            stats["status"].append(resp.status)
                    else:
                        raise ValueError(f"Unsupported method: {method}")
                except Exception as e:
                    errors.append((client_id, i, str(e)))

    print(
        f"Starting load test: {num_clients} clients x {requests_per_client} requests each"
    )
    start = time.time()
    await asyncio.gather(*(client_task(cid) for cid in range(num_clients)))
    total_time = time.time() - start
    total_requests = num_clients * requests_per_client
    print("\nLoad Test Summary:")
    print(f"  Total requests: {total_requests}")
    print(f"  Total time: {total_time:.2f}s")
    if stats["elapsed"]:
        print(
            f"  Avg response time: {sum(stats['elapsed']) / len(stats['elapsed']):.3f}s"
        )
        print(f"  Min response time: {min(stats['elapsed']):.3f}s")
        print(f"  Max response time: {max(stats['elapsed']):.3f}s")
    status_counts = defaultdict(int)
    for s in stats["status"]:
        status_counts[s] += 1
    print(f"  Status codes:")
    for code, count in sorted(status_counts.items()):
        print(f"    {code}: {count}")
    print(f"  Errors: {len(errors)}")
    if errors:
        print(f"  First 5 errors:")
        for err in errors[:5]:
            print(f"    Client {err[0]}, Request {err[1]}: {err[2]}")


async def check_ca_trusted():
    """Check if the self-signed CA is trusted by attempting a request with verify=ca.crt using aiohttp."""
    test_url = "https://www.google.com"
    ssl_verify = get_ssl_verify_setting()

    try:
        # Create connector with SSL settings
        connector = aiohttp.TCPConnector(
            ssl=create_ssl_context() if ssl_verify else False
        )

        async with aiohttp.ClientSession(
            trust_env=True, connector=connector
        ) as session:
            async with session.get(test_url, timeout=3) as resp:
                await resp.text()

        if ssl_verify:
            print(
                "[DEBUG] CA certificate appears to be trusted by the system (no SSL error)."
            )
        else:
            print("[DEBUG] SSL verification is disabled - connection successful.")
        return True
    except aiohttp.ClientConnectorCertificateError as e:
        print("[DEBUG] SSL error when using CA certificate. It may not be trusted.")
        print(f"[DEBUG] SSL error details: {e}")
        return False
    except Exception as e:
        print(f"[DEBUG] Unexpected error during CA trust check: {e}")
        traceback.print_exc()
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HTTPS Proxy Test Client (aiohttp)")
    parser.add_argument(
        "--load-test", action="store_true", help="Run load test with multiple clients"
    )
    parser.add_argument(
        "--clients",
        type=int,
        default=10,
        help="Number of concurrent clients (default: 10)",
    )
    parser.add_argument(
        "--requests", type=int, default=10, help="Requests per client (default: 10)"
    )
    parser.add_argument(
        "--url",
        type=str,
        default="https://www.uuidtools.com/api/generate/v4/count/1",
        help="Test URL",
    )
    parser.add_argument(
        "--method", type=str, default="GET", choices=["GET", "POST"], help="HTTP method"
    )
    parser.add_argument(
        "--payload", type=str, default=None, help="POST payload as JSON string"
    )
    args = parser.parse_args()

    print("HTTPS Proxy Test Client (aiohttp)")
    print("=" * 50)
    print("\nIMPORTANT: Make sure to:")
    print("1. Run the proxy server first: python proxy_server.py")
    print("2. Add ca.crt to your system's trusted certificates")
    print("   OR use verify=False (as in this test)")
    print("3. Set SSL_VERIFY=false to disable SSL verification if needed")
    print()

    # Print relevant environment variables for debugging
    print("[DEBUG] Environment variables:")
    print(f"  HTTP_PROXY: {os.environ.get('HTTP_PROXY')}")
    print(f"  HTTPS_PROXY: {os.environ.get('HTTPS_PROXY')}")
    print(
        f"  SSL_VERIFY: {os.environ.get('SSL_VERIFY', 'true')} (SSL verification {'enabled' if get_ssl_verify_setting() else 'disabled'})"
    )
    print(f"  REQUESTS_CA_BUNDLE: {os.environ.get('REQUESTS_CA_BUNDLE')}")
    print(f"  CURL_CA_BUNDLE: {os.environ.get('CURL_CA_BUNDLE')}")
    print(f"  SSL_CERT_FILE: {os.environ.get('SSL_CERT_FILE')}")
    print(f"  SSL_CERT_DIR: {os.environ.get('SSL_CERT_DIR')}")
    print()

    ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE")
    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            print(
                f"[WARNING] REQUESTS_CA_BUNDLE is set to '{ca_bundle}', but the file does not exist!"
            )
        else:
            print(f"[DEBUG] REQUESTS_CA_BUNDLE file exists: {ca_bundle}")
    else:
        print("[WARNING] REQUESTS_CA_BUNDLE is not set!")
    print()

    ca_bundle = os.environ.get("SSL_CERT_FILE")
    if ca_bundle:
        if not os.path.isfile(ca_bundle):
            print(
                f"[WARNING] SSL_CERT_FILE is set to '{ca_bundle}', but the file does not exist!"
            )
        else:
            print(f"[DEBUG] SSL_CERT_FILE file exists: {ca_bundle}")
    else:
        print("[WARNING] SSL_CERT_FILE is not set!")
    print()

    def check_proxy_env_and_connect(var_name):
        proxy_url = os.environ.get(var_name)
        if not proxy_url:
            print(f"[WARNING] {var_name} is not set!")
            return
        print(f"[DEBUG] {var_name} is set to: {proxy_url}")
        try:
            m = re.match(r"http[s]?://([^:/]+)(?::(\d+))?", proxy_url)
            if not m:
                print(f"[WARNING] {var_name} value '{proxy_url}' is not a valid URL!")
                return
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else 8888
            with socket.create_connection((host, port), timeout=3):
                print(f"[DEBUG] {var_name} proxy {host}:{port} is reachable.")
        except Exception as e:
            print(f"[WARNING] {var_name} proxy {proxy_url} is NOT reachable: {e}")

    import asyncio

    if not asyncio.run(check_ca_trusted()):
        if get_ssl_verify_setting():
            print(
                "[INFO] Your CA certificate is NOT trusted by the system. You may see SSL warnings or errors."
            )
            print(
                "[INFO] To avoid this, add 'ca.crt' to your system's trusted certificates."
            )
            print("[INFO] Or set SSL_VERIFY=false to disable SSL verification.")
        else:
            print("[INFO] SSL verification is disabled.")
    else:
        if get_ssl_verify_setting():
            print("[INFO] Your CA certificate is trusted by the system.")
        else:
            print("[INFO] SSL verification is disabled - connection successful.")

    max_retries = 10
    for i in range(max_retries):
        try:
            check_proxy_env_and_connect("HTTP_PROXY")
            check_proxy_env_and_connect("HTTPS_PROXY")
            break
        except Exception:
            print(f"Waiting for proxy to become available... ({i + 1}/{max_retries})")
            time.sleep(1)
    else:
        print("[ERROR] Proxy is not available after waiting. Exiting.")
        sys.exit(1)
    print()

    if args.load_test:
        import json

        payload = json.loads(args.payload) if args.payload else None
        asyncio.run(
            load_test_proxy(
                test_url=args.url,
                num_clients=args.clients,
                requests_per_client=args.requests,
                method=args.method,
                payload=payload,
                ssl_verify=get_ssl_verify_setting(),
            )
        )
        sys.exit(0)

    try:
        asyncio.run(test_proxy_with_caching())
    except CacheIntegrityError as e:
        print(f"\n[FATAL ERROR] Cache integrity check failed: {e}")
        sys.exit(1)
