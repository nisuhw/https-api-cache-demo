#!/bin/sh
set -e

# Copy the shared CA cert to the system trust store if it exists
if [ -f /app/ca/ca.crt ]; then
    echo "[Entrypoint] Installing custom CA certificate..."
    cp /app/ca/ca.crt /usr/local/share/ca-certificates/proxy_ca.crt
    update-ca-certificates
else
    echo "[Entrypoint] No CA certificate found at /app/ca/ca.crt"
fi

# Run the test client
python test_client.py 