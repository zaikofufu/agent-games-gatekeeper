/**
 * Entry point. Reads configuration from the environment and starts the
 * Proof Gatekeeper agent. The HMAC secret is required: the server
 * refuses to start without AGENT_SECRET, so a misconfigured deploy
 * fails loudly instead of answering tasks unsigned.
 *
 * Required env:
 *   AGENT_SECRET   32-byte secret issued by the platform at registration
 * Optional env:
 *   PORT           default 3000 (Fly.io sets this automatically)
 *   AGENT_NAME     default "gatekeeper"
 *   SEEN_STORE_PATH
 *                  where the replay store persists approved task ids /
 *                  proof txs (default data/replay.json, relative to the
 *                  working directory). The file survives process
 *                  restarts on the same machine, so a reused proof is
 *                  still recognised after the Fly trial machine stops
 *                  and restarts. A fresh deploy starts with an empty
 *                  store (new machine, new filesystem).
 *   GATEKEEPER_WASM / GATEKEEPER_ZKEY
 *                  local circuit artifact paths (see README). Without
 *                  them the agent decides correctly but returns
 *                  proof: null — see src/proof.ts.
 */
import { createApp } from "./server.js";

const secret = process.env.AGENT_SECRET;
if (!secret) {
  console.error("FATAL: AGENT_SECRET is not set. Refusing to start.");
  process.exit(1);
}

const port = Number(process.env.PORT ?? "3000");
const app = createApp({
  secret,
  agentName: process.env.AGENT_NAME ?? "gatekeeper",
  wasmPath: process.env.GATEKEEPER_WASM || undefined,
  zkeyPath: process.env.GATEKEEPER_ZKEY || undefined,
  replayFilePath: process.env.SEEN_STORE_PATH || undefined,
});

app.listen(port, () => {
  console.log(`gatekeeper agent listening on :${port} (GET /agent for health)`);
});
