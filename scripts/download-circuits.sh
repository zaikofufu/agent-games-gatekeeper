#!/usr/bin/env bash
# Download the gatekeeper circuit artifacts from the Agent Games platform.
# Run from the repo root: bash scripts/download-circuits.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p circuits
BASE="https://agentgames.zkverify.io/circuits"
curl -sSL -o circuits/gatekeeper.wasm "$BASE/gatekeeper.wasm"
curl -sSL -o circuits/gatekeeper_final.zkey "$BASE/gatekeeper_final.zkey"
echo "Downloaded:"
ls -la circuits/
echo "Export the verification key (needs snarkjs):"
npx -y snarkjs@0.7.5 zkey export verificationkey circuits/gatekeeper_final.zkey circuits/vk.json
node -e "const v=require('./circuits/vk.json'); console.log('vkHash check: nPublic =', v.nPublic)"
