#!/usr/bin/env bash
# Smoke-test the built server locally:
#  - GET /agent (health)
#  - POST /agent with an INVALID signature (expect 403)
#  - POST /agent with a VALID signature + a VALID event-shape task
#    (expect 200 APPROVE; proof is null without circuit artifacts,
#    unless GATEKEEPER_WASM/GATEKEEPER_ZKEY point at real files)
# Usage: AGENT_SECRET=test-secret bash scripts/test-server.sh
# Exits non-zero if any check fails.
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build

export AGENT_SECRET="${AGENT_SECRET:-test-secret-do-not-use-in-production}"
export PORT="${PORT:-3456}"
node dist/index.js &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT

# Wait for the health endpoint (up to 10s); fail loudly if it never comes up.
for _ in $(seq 1 20); do
  if curl -fsS "http://127.0.0.1:$PORT/agent" >/dev/null 2>&1; then break; fi
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/agent" >/dev/null || { echo "FAIL: server did not come up"; exit 1; }

check() { # check <label> <expected-status> <curl-args...>
  local label="$1" expected="$2"; shift 2
  local got
  got=$(curl -sS -o /tmp/gk-resp.json -w "%{http_code}" "$@")
  echo "== $label (expect $expected, got $got) =="
  cat /tmp/gk-resp.json; echo
  [ "$got" = "$expected" ] || { echo "FAIL: $label"; exit 1; }
}

echo "== GET /agent =="
check "GET /agent" 200 "http://127.0.0.1:$PORT/agent"

BODY='{"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_24_9d1","mode":"competition","input":{"registered_vk":"0x7d3a00000000000000000000000000000000000000000000000000000000f291","proof_vk":"0x7d3a00000000000000000000000000000000000000000000000000000000f291","minimum":"1000","public_balance":"1460","expiry_block":19842201,"current_block":19832000,"recipient":"0xDe42f1a2b3c4d5e6f708192a3b4c5d6e7f809f01","condition_recipient":"0xDe42f1a2b3c4d5e6f708192a3b4c5d6e7f809f01","amount":"500","max_transfer":"1000","proof_tx":"0xa4c1000000000000000000000000000000000000000000000000000000008ff1"}}'
SIG_BAD=$(node -e "console.log(require('node:crypto').createHmac('sha256','wrong-secret').update(process.argv[1]).digest('hex'))" "$BODY")
check "POST /agent, invalid signature" 403 -X POST "http://127.0.0.1:$PORT/agent" \
  -H 'content-type: application/json' -H "x-agent-games-signature: $SIG_BAD" -d "$BODY"

SIG_OK=$(node -e "console.log(require('node:crypto').createHmac('sha256',process.env.AGENT_SECRET).update(process.argv[1]).digest('hex'))" "$BODY")
check "POST /agent, valid signature" 200 -X POST "http://127.0.0.1:$PORT/agent" \
  -H 'content-type: application/json' -H "x-agent-games-signature: $SIG_OK" -d "$BODY"
node -e "const r=require('/tmp/gk-resp.json'); if (r.decision!=='APPROVE') { console.error('FAIL: expected APPROVE, got', r.decision); process.exit(1); } console.log('decision APPROVE confirmed')"

echo "== all smoke checks passed =="
