/**
 * REAL Groth16 integration test — NOT mocked.
 *
 * Runs snarkjs.groth16.fullProve against the actual published
 * gatekeeper circuit (circuits/gatekeeper.wasm + circuits/gatekeeper_final.zkey,
 * vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0)
 * and verifies the resulting proof with the exported verification key
 * (circuits/vk.json, nPublic 13).
 *
 * This is slow (tens of seconds per proof on a small VM) and is
 * skipped automatically when the circuit artifacts are absent:
 * run `bash scripts/download-circuits.sh` to fetch them from the
 * platform first. The fast mocked unit tests in test/proof.test.ts
 * cover the same code paths without proving.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { describe, expect, it } from "vitest";
import { createSnarkjsProver, generateDecisionProof, toCircuitInput } from "../src/proof.js";
import { normaliseTask } from "../src/verify.js";
import { validEventTask } from "./fixtures.js";

const dir = path.dirname(fileURLToPath(import.meta.url));
const WASM = path.join(dir, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(dir, "..", "circuits", "gatekeeper_final.zkey");
const VK_PATH = path.join(dir, "..", "circuits", "vk.json");
const HAS_ARTIFACTS = existsSync(WASM) && existsSync(ZKEY) && existsSync(VK_PATH);

const VK = HAS_ARTIFACTS ? JSON.parse(readFileSync(VK_PATH, "utf8")) : null;

/** Values chosen so the circuit inputs are small, self-consistent numbers
 *  (same values as the live probe runs of 14 Nov 2026). */
function probeTask(overrides: Record<string, unknown> = {}) {
  return normaliseTask(
    validEventTask({
      registered_vk: "0x000000000000000000000000000000000000000000000000000000000000006f",
      proof_vk: "0x000000000000000000000000000000000000000000000000000000000000006f",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: "0x000000000000000000000000000000000000007b",
      condition_recipient: "0x000000000000000000000000000000000000007b",
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
      ...overrides,
    }) as unknown as Record<string, unknown>,
  );
}

describe.skipIf(!HAS_ARTIFACTS)("REAL gatekeeper decision proof", () => {
  it(
    "valid condition + APPROVE proves and verifies, 13 public signals",
    async () => {
      const task = probeTask();
      const { proof, publicSignals } = await generateDecisionProof(task, "APPROVE", {
        wasmPath: WASM,
        zkeyPath: ZKEY,
      });
      expect(publicSignals).toHaveLength(13);
      // Public signals in order: [hash, registeredVkHash, proofVkHash,
      // minimum, publicBalance, expiryBlock, currentBlock, recipient,
      // conditionRecipient, amount, maxTransfer, decision, taskId]
      expect(publicSignals[1]).toBe("111");
      expect(publicSignals[2]).toBe("111");
      expect(publicSignals[3]).toBe("1000");
      expect(publicSignals[4]).toBe("1460");
      expect(publicSignals[11]).toBe("1");
      const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
      expect(ok).toBe(true);
    },
    180_000,
  );

  it(
    "trap + REJECT proves and verifies (decision signal 0)",
    async () => {
      const task = probeTask({ public_balance: "500" });
      const { proof, publicSignals } = await generateDecisionProof(task, "REJECT", {
        wasmPath: WASM,
        zkeyPath: ZKEY,
      });
      expect(publicSignals[11]).toBe("0");
      const ok = await snarkjs.groth16.verify(VK, publicSignals, proof);
      expect(ok).toBe(true);
    },
    180_000,
  );

  it(
    "wrong decision cannot be proven: trap + APPROVE fails the circuit assert",
    async () => {
      const task = probeTask({ public_balance: "500" });
      const prover = createSnarkjsProver(WASM, ZKEY);
      await expect(prover(toCircuitInput(task, "APPROVE"))).rejects.toThrow(/Assert Failed/);
    },
    180_000,
  );

  it(
    "wrong decision cannot be proven: valid condition + REJECT fails the circuit assert",
    async () => {
      const task = probeTask();
      const prover = createSnarkjsProver(WASM, ZKEY);
      await expect(prover(toCircuitInput(task, "REJECT"))).rejects.toThrow(/Assert Failed/);
    },
    180_000,
  );
});

describe.skipIf(HAS_ARTIFACTS)("REAL gatekeeper decision proof (skipped)", () => {
  it("skipped: circuit artifacts missing — run scripts/download-circuits.sh", () => {
    expect(HAS_ARTIFACTS).toBe(false);
  });
});
