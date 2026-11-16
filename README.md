# Proof Gatekeeper agent — zkVerify Agent Games

An agent for the **Proof Gatekeeper** track of zkVerify's Agent Games
(competition 21 Oct – 21 Nov 2026, free entry, 100,000 VFY per track).
It receives signed task envelopes, verifies ZK-proof-backed payment
conditions, and returns a signed decision plus a Groth16 decision proof.

**Status: built and tested locally. NOT deployed, NOT registered, NOT
submitted.** The remaining steps are listed at the bottom.

## How it works

```
platform --POST /agent--> agent
  header: x-agent-games-signature: <hmac-sha256-hex of raw body>
  body:   agent-games.proof-gatekeeper.v1 task envelope
agent --> decision + reason_code + Groth16 proof
  header: x-agent-games-signature: <hmac-sha256-hex of raw response>
```

Decision checks, in fail-closed order (all must pass to APPROVE):

1. **Replay** — task_id already approved, or proof_tx already approved → `PROOF_REUSED`
2. **Proof type** — must be `groth16` → else `PROOF_INVALID`
3. **VK match** — recomputed verification-key hash vs `registered_vk` → else `VK_SUBSTITUTION`
4. **Proof verifies** — `snarkjs.groth16.verify(vk, publicSignals, proof)` → else `PROOF_INVALID`
5. **Expiry** — block height (`current_block > expiry_block` → `EXPIRED_CONDITION`) or timestamp (`received_at > expiry`, or `received_at < valid_after` → `EXPIRED`)
6. **Recipient** — proof recipient vs condition recipient (case-insensitive) → else `RECIPIENT_MISMATCH`
7. **Threshold** — public balance >= minimum → else `THRESHOLD_MISMATCH`
8. **Amount cap** — amount <= max_transfer → else `AMOUNT_OVERFLOW`
9. Otherwise → `APPROVE` / `VALID_CONDITION`

Scoring (from the event page): correct decision +12, wrong APPROVE −6,
wrong REJECT −3, timeout −2, missing/invalid proof −2, reliability bonus +0…+5.

## Files

| File | What it does |
| --- | --- |
| `src/server.ts` | HTTP server (Node built-in `http`, no framework). HMAC verify **before** parsing, response signing, 50s internal budget inside the 60s deadline, 401/403/503 handling. |
| `src/verify.ts` | Pure decision logic + payload normalisation (both documented shapes) + VK hashing + file-backed replay store. |
| `src/proof.ts` | Decision-proof generation with the real gatekeeper circuit (snarkjs `fullProve`), circuit constants, input mapping. |
| `src/index.ts` | Entry point; refuses to start without `AGENT_SECRET`. |
| `test/verify.test.ts` | Decision branches (mocked incoming-proof verifier — labelled). |
| `test/proof.test.ts` | Proof generation with a mocked prover; refuses to invent a proof. |
| `test/proof.real.test.ts` | **REAL** Groth16: proves + verifies against the published circuit. Skipped if `circuits/` is absent. |
| `test/server.test.ts` | Live HTTP: health, HMAC 401/403, valid task → APPROVE, replay → PROOF_REUSED. |
| `circuits/` | Published gatekeeper `gatekeeper.wasm`, `gatekeeper_final.zkey`, exported `vk.json` (nPublic 13). |
| `Dockerfile`, `fly.toml` | Fly.io deployment (keeps 1 machine awake — sleeping machines forfeit tasks). |

## Spec sources (fetched 14 Nov 2026)

- https://agentgames.zkverify.io/build
- https://agentgames.zkverify.io/guide
- https://agentgames.zkverify.io/events/proof-gatekeeper (sample payload, trap list, scoring)
- https://agentgames.zkverify.io/rules (§1.2–1.7: HMAC, uptime, practice)
- https://agentgames.zkverify.io/api/circuit-info — mainnet, gatekeeper vkHash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

## Verified circuit findings (probed live, not assumed)

The published wasm/zkey were downloaded and exercised with snarkjs:

- Exported VK: Groth16/BN128, **nPublic = 13**. The decision proof has **13 public signals**, in order:
  `[hash, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, taskId]`
- The circuit's 13 input signals: `decision, salt, publicBalance, minimum, recipient, conditionRecipient, expiryBlock, currentBlock, amount, maxTransfer, registeredVkHash, proofVkHash, taskId`. `salt` is a **private** input; changing it changes publicSignals[0] (a hash binding) but any field element works.
- **The circuit enforces decision correctness** (template `GatekeeperEvaluation`, line 102): `fullProve` *fails* for valid-condition + REJECT and for trap + APPROVE. It only proves when the decision matches the correct evaluation. Verified live with real proofs + `groth16.verify` against the exported VK.

## Spec gaps — read before deploying

1. **Two payload shapes.** The task brief describes an envelope with `input.proof {proofType, proof, publicSignals, verificationKey}` and `input.context`. The live event page shows a *different*, flat sample payload (`registered_vk, proof_vk, minimum, public_balance, expiry_block, current_block, recipient, condition_recipient, amount, max_transfer, proof_tx`) and a sample response of just `{decision, reason_code, proof_tx}` — no proof at all. This code accepts **both** shapes and returns a superset response (`decision, reason_code, proof, public_signals, proof_tx`). If the platform only sends one shape, the other path is dead code, not a bug.
2. **Two public-signal sets.** The brief's `[balance, threshold, recipient, expiry]` (4 values) is the *incoming payment proof's* public signals. The *decision proof's* public signals are the 13 values listed above. `proof.ts` returns the 13; when no decision proof is available the server returns the 4 canonical values instead. Confirm with a practice task which set the platform expects in `public_signals`.
3. **VK-hash algorithm is unpublished.** `computeVkHash` uses SHA-256 over stable (sorted-key) JSON of the VK object, or the hash as-is when the VK is already a 32-byte hex hash. If the platform uses keccak256 or hashes only `vk_ic`, correct VKs will be reported as `VK_SUBSTITUTION`. Confirm against a known-good practice task before a scored round.
4. **Reason-code names differ.** The brief lists `EXPIRED`; the event page uses `EXPIRED_CONDITION`, plus `PROOF_REUSED` and `AMOUNT_OVERFLOW` traps that the brief's enum omits. This code emits the event-page names for block expiry / reuse / overflow. If the platform validates reason codes strictly against the brief's enum, those three should be mapped to `EXPIRED` / `PROOF_INVALID` — check in practice mode.
5. **Salt derivation is an assumption.** `salt` is derived deterministically as SHA-256(`taskId:decision`) mod the BN128 prime. The circuit accepts any field element, so this cannot make a correct decision unprovable, but if the platform expects a specific salt, update `toCircuitInput`.
6. **Expiry units.** Block-height expiry (`expiry_block` vs `current_block`) and timestamp expiry (`expiry` vs `received_at`) are both supported and compared as given. They must be in the same unit within one task.
7. **Replay store is file-backed on one machine.** Approved task ids / proof txs persist to `data/replay.json` (override with `SEEN_STORE_PATH`), written synchronously on every mark, so a process restart on the same machine no longer wipes the seen-set — this is what caught the PROOF_REUSED misses in practice on 16 Nov 2026 (the Fly trial machine restarts ~every 5 min). Limits: a fresh deploy (new machine) starts with an empty store, and two instances do not share it — a multi-instance deployment still needs a shared store (e.g. Redis). The platform also tracks replays, so this is a second line of defence, not the only one.
8. **No on-chain submission.** The agent returns the Groth16 proof in its HTTP response; it does **not** submit proofs to zkVerify via Kurier or zkVerifyJS. The platform's docs present that as a separate verification path — if the platform expects the agent to submit the proof itself, that is a follow-up feature, not implemented here.
9. **Response signing.** `/build` says every response is signed with `x-agent-games-signature` over the raw response body. This server does that. The health endpoint is signed too.

## Run locally

```bash
npm install
npm run build
cp .env.example .env   # then set AGENT_SECRET to a test value
npm start              # listens on :3000 (or $PORT)
curl http://127.0.0.1:3000/agent
# {"status":"ok","agent":"gatekeeper","version":"1.0.0"}
```

To generate **real** decision proofs locally, point the server at the
bundled artifacts (or run `bash scripts/download-circuits.sh` to
re-fetch them from the platform):

```bash
GATEKEEPER_WASM=circuits/gatekeeper.wasm \
GATEKEEPER_ZKEY=circuits/gatekeeper_final.zkey \
AGENT_SECRET=test-secret npm start
```

Without those env vars the agent still decides correctly but returns
`proof: null` (scored as a correct decision without a valid proof: −2,
no reliability bonus) — it never invents a proof.

## Tests

```bash
npm test                          # fast unit + HTTP tests (mocked verifier/prover, labelled)
npm test -- test/proof.real.test.ts   # REAL Groth16 prove+verify (~1-2 min, needs circuits/)
bash scripts/test-server.sh       # live smoke test: GET health, POST 403, POST 200 APPROVE
```

Test labelling: the incoming payment proof is **mocked** in
`verify.test.ts` / `server.test.ts` (a stub verifier returning
true/false) because the payment-condition circuit is not published
and no real incoming proof can be generated. The **decision** proof
is **real** in `test/proof.real.test.ts` (actual `fullProve` +
`groth16.verify` against the published gatekeeper circuit).

## Deploy

```bash
fly launch --no-deploy        # set your own app name when prompted
fly secrets set AGENT_SECRET=<secret shown ONCE at agent registration>
fly deploy
```

`fly.toml` keeps one machine awake (`min_machines_running = 1`,
`auto_stop_machines = false`): a sleeping free-tier machine misses
tasks and forfeits them (rules §1.4).

## Register, preflight, practice (still to do — NOT done by this build)

1. Push this code to a **public GitHub repo from your personal
   account** (org repos are not supported). No secret may ever be
   committed — `.gitignore` already excludes `.env`.
2. In the Agent Games dashboard, **Register agent**: name, event
   tracks (Proof Gatekeeper), Repository URL, Agent Endpoint
   (`https://<your-app>.fly.dev/agent`).
3. Save the **HMAC secret shown exactly once** at registration and
   set it as a Fly secret (`fly secrets set AGENT_SECRET=...`).
   The platform stores an AES-256-GCM encrypted copy; rotate it from
   agent settings if it leaks.
4. Confirm `GET /agent` returns `{"status":"ok",...}` from the public URL.
5. Run the **signed preflight** from the dashboard, then at least one
   **practice task** (practice mode: 10 dispatches per agent per hour,
   unscored) and check the decision + proof verify.
6. Enter the event. Rounds run 13–20 Nov, 5:30 PM–3:30 AM GMT+7,
   8 tasks per agent per round.
7. **Add your wallet address** to your Agent Games profile — it is
   required to claim any VFY prize.
