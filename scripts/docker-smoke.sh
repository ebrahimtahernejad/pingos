#!/usr/bin/env bash
# End-to-end smoke test on Linux: brings up target+server+client in docker
# compose, sends bytes through the tunnel, verifies they come back.
#
# Usage: ./scripts/docker-smoke.sh

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE_FILE=docker/compose.yml
EXIT_CODE=1

cleanup() {
    echo
    echo "--- container logs (tail) ---"
    docker compose -f "$COMPOSE_FILE" logs --no-color 2>&1 | tail -120 || true
    echo "--- tearing down ---"
    docker compose -f "$COMPOSE_FILE" down --remove-orphans --volumes >/dev/null 2>&1 || true
    exit "$EXIT_CODE"
}
trap cleanup EXIT

echo "--- building images ---"
docker compose -f "$COMPOSE_FILE" build

echo "--- starting stack ---"
docker compose -f "$COMPOSE_FILE" up -d

# Wait for client to listen.
echo -n "waiting for client port 4455 to accept connections "
for i in $(seq 1 30); do
    if (echo > /dev/tcp/127.0.0.1/4455) >/dev/null 2>&1; then
        echo " ok"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo " TIMEOUT"
        exit 1
    fi
done

# Let handshake settle.
sleep 1

# Use Python to do a clean TCP send-payload-then-read-exact-bytes-back round-trip.
# Portable across macOS/Linux.
echo "--- TCP round-trip test ---"
PYTHON=$(command -v python3 || command -v python)
"$PYTHON" - <<'PY'
import os, socket, sys, time

# Three test payloads of increasing size, to exercise SYN/SynAck + segmentation + windowing.
PAYLOADS = [
    b"hello pingos!\n",
    bytes((i % 251 for i in range(8 * 1024))),   # 8 KiB
    bytes(((i * 7) % 251 for i in range(64 * 1024))),  # 64 KiB
]

for n, payload in enumerate(PAYLOADS):
    s = socket.create_connection(("127.0.0.1", 4455), timeout=20)
    s.sendall(payload)
    s.shutdown(socket.SHUT_WR)
    buf = bytearray()
    while len(buf) < len(payload):
        chunk = s.recv(65536)
        if not chunk:
            break
        buf.extend(chunk)
    s.close()
    if bytes(buf) != payload:
        print(f"FAIL on payload {n}: sent={len(payload)}, got={len(buf)}", flush=True)
        # Show first diff position.
        for i, (a, b) in enumerate(zip(payload, buf)):
            if a != b:
                print(f"  first diff at offset {i}: sent={a:02x} got={b:02x}", flush=True)
                break
        sys.exit(1)
    print(f"OK payload {n}: {len(payload)} bytes round-tripped", flush=True)

print("PASS", flush=True)
PY

EXIT_CODE=$?
if [[ "$EXIT_CODE" == 0 ]]; then
    echo "--- PASS ---"
fi
