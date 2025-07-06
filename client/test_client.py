"""Test client for the HTTPS proxy with caching."""

import time
import requests
import urllib3
import sys
import ssl
import os
import socket
import re


def check_ca_trusted():
    """Check if the self-signed CA is trusted by attempting a request with verify=ca.crt."""
    test_url = "https://httpbin.org/get"
    try:
        requests.get(test_url, timeout=3)
        print(
            "[DEBUG] CA certificate appears to be trusted by the system (no SSL error)."
        )
        return True
    except requests.exceptions.SSLError as e:
        print("[DEBUG] SSL error when using CA certificate. It may not be trusted.")
        print(f"[DEBUG] SSL error details: {e}")
        return False
    except Exception as e:
        print(f"[DEBUG] Unexpected error during CA trust check: {e}")
        return False


# Disable SSL warnings for self-signed certificates
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def test_proxy_with_caching():
    """Test the proxy server with caching functionality."""

    # Test URL
    test_url = "https://www.uuidtools.com/api/generate/v4/count/1"

    print("Testing HTTPS Proxy with Caching")
    print("=" * 50)
    print(f"Test URL: {test_url}")
    print("Cache TTL: 5 seconds")
    print()

    # Important: The CA certificate must be trusted by the system
    # or you need to specify verify=False (not recommended for production)

    try:
        # First request - should be a cache MISS
        print("Request 1 - Should be CACHE MISS:")
        start_time = time.time()
        response1 = requests.get(test_url)
        elapsed1 = time.time() - start_time
        print(f"  Status: {response1.status_code}")
        print(f"  Time: {elapsed1:.3f}s")
        print(f"  Response snippet: {response1.text[:100]}...")
        print()

        # Second request immediately - should be a cache HIT
        print("Request 2 - Should be CACHE HIT (immediate):")
        start_time = time.time()
        response2 = requests.get(test_url)
        elapsed2 = time.time() - start_time
        print(f"  Status: {response2.status_code}")
        print(f"  Time: {elapsed2:.3f}s (should be faster)")
        print(f"  Response snippet: {response2.text[:100]}...")
        print()

        # Verify cache HIT response body matches the MISS
        if response1.text == response2.text:
            print("[CHECK] Cache HIT response body matches the MISS (OK)")
        else:
            print("[WARNING] Cache HIT response body does NOT match the MISS!")
        print()

        # Wait for 3 seconds
        print("Waiting 3 seconds...")
        time.sleep(3)

        # Third request - should still be a cache HIT
        print("Request 3 - Should be CACHE HIT (after 3s):")
        start_time = time.time()
        response3 = requests.get(test_url)
        elapsed3 = time.time() - start_time
        print(f"  Status: {response3.status_code}")
        print(f"  Time: {elapsed3:.3f}s (should be faster)")
        print()

        # Wait for 3 more seconds (total 6 seconds)
        print("Waiting 3 more seconds (total 6s)...")
        time.sleep(3)

        # Fourth request - should be a cache MISS (expired)
        print("Request 4 - Should be CACHE MISS (after 6s, cache expired):")
        start_time = time.time()
        response4 = requests.get(test_url)
        elapsed4 = time.time() - start_time
        print(f"  Status: {response4.status_code}")
        print(f"  Time: {elapsed4:.3f}s (should be slower)")
        print()

        # Test with POST request (different method)
        print("Request 5 - POST request (different method, should be CACHE MISS):")
        start_time = time.time()
        response5 = requests.post(
            "https://httpbin.org/post",
            json={"test": "data"},
        )
        elapsed5 = time.time() - start_time
        print(f"  Status: {response5.status_code}")
        print(f"  Time: {elapsed5:.3f}s")
        print()

    except requests.exceptions.ProxyError as e:
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


if __name__ == "__main__":
    print("HTTPS Proxy Test Client")
    print("=" * 50)
    print("\nIMPORTANT: Make sure to:")
    print("1. Run the proxy server first: python proxy_server.py")
    print("2. Add ca.crt to your system's trusted certificates")
    print("   OR use verify=False (as in this test)")
    print()

    # Print relevant environment variables for debugging
    print("[DEBUG] Environment variables:")
    print(f"  HTTP_PROXY: {os.environ.get('HTTP_PROXY')}")
    print(f"  HTTPS_PROXY: {os.environ.get('HTTPS_PROXY')}")
    print(f"  REQUESTS_CA_BUNDLE: {os.environ.get('REQUESTS_CA_BUNDLE')}")
    print()

    # Check if REQUESTS_CA_BUNDLE is set and file exists
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

    # Check if HTTP_PROXY and HTTPS_PROXY are set and live
    def check_proxy_env_and_connect(var_name):
        proxy_url = os.environ.get(var_name)
        if not proxy_url:
            print(f"[WARNING] {var_name} is not set!")
            return
        print(f"[DEBUG] {var_name} is set to: {proxy_url}")
        try:
            # Parse host and port
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

    if not check_ca_trusted():
        print(
            "[INFO] Your CA certificate is NOT trusted by the system. You may see SSL warnings or errors."
        )
        print(
            "[INFO] To avoid this, add 'ca.crt' to your system's trusted certificates."
        )
    else:
        print("[INFO] Your CA certificate is trusted by the system.")

    # Wait for the proxy to become available (retry up to 10 times)
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

    test_proxy_with_caching()
