#!/usr/bin/env bash
# End-to-end v2: boot the Rust reference server with a known identity and run the
# C v2 client against it (authenticated handshake + AAD round-trip). Skips
# cleanly if the server binary isn't available.
#
# The server identity seed 0x11*32 yields the Ed25519 public key pinned below.
set -u
PORT="${PORT:-3197}"
PINNED="d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${ADATP_SERVER_BIN:-}"
for cand in "$BIN" "$HERE/../../../server/target/debug/adatp-server" \
            "/Users/thecoder/adatp/server/target/debug/adatp-server"; do
  [ -n "$cand" ] && [ -x "$cand" ] && BIN="$cand" && break
done
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
  echo "SKIP: adatp-server binary not found (set ADATP_SERVER_BIN)."; exit 0
fi

CLIENT="$HERE/../build/e2e_v2"
if [ ! -x "$CLIENT" ]; then echo "build the SDK first (cmake --build build)"; exit 2; fi

TMP="$(mktemp -d)"
printf '\x11%.0s' $(seq 1 32) > "$TMP/identity.key"   # 32 bytes of 0x11
trap 'kill "$SRV" 2>/dev/null; rm -rf "$TMP"' EXIT

PORT="$PORT" HOST=127.0.0.1 AUTH_DRIVER=none MSG_RATE_LIMIT=0 \
  DATABASE_URL="sqlite:$TMP/e2e.db" ADATP_IDENTITY_PATH="$TMP/identity.key" \
  RUST_LOG=info "$BIN" >"$TMP/server.log" 2>&1 &
SRV=$!

for _ in $(seq 1 60); do grep -q "listening on" "$TMP/server.log" 2>/dev/null && break; sleep 0.25; done
if ! grep -q "listening on" "$TMP/server.log"; then echo "server did not start:"; cat "$TMP/server.log"; exit 1; fi
grep -q "$PINNED" "$TMP/server.log" || { echo "server identity mismatch"; cat "$TMP/server.log"; exit 1; }

echo "server up on :$PORT (min=1, accepts v1 + v2)"
echo "--- v2 (pinned, authenticated) ---"
"$CLIENT" 127.0.0.1 "$PORT" "$PINNED"; rc2=$?
echo "--- v1 (unauthenticated, regression check) ---"
"$CLIENT" 127.0.0.1 "$PORT" v1; rc1=$?
if [ $rc2 -eq 0 ] && [ $rc1 -eq 0 ]; then
  echo "END-TO-END C<->Rust PASSED (v2 authenticated + v1 unchanged)."; exit 0
else
  echo "END-TO-END FAILED (v2 rc=$rc2, v1 rc=$rc1)."; exit 1
fi
