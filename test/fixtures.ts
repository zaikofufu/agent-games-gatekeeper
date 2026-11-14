/**
 * Shared fixtures for the gatekeeper tests.
 *
 * MOCKED vs REAL — read this first:
 *  - The incoming payment proof in these fixtures is a DUMMY object and
 *    the snarkjs verifier is MOCKED in verify.test.ts / server.test.ts
 *    (a stub that returns true/false on demand). No real incoming
 *    Groth16 proof exists in the fixtures, because the payment-condition
 *    circuit that produced the task's proof is not published.
 *  - The DECISION proof is REAL in test/proof.real.test.ts: it runs
 *    snarkjs.groth16.fullProve against the actual published gatekeeper
 *    wasm/zkey (circuits/ in this repo) and verifies the result with
 *    the exported verification key. That test is skipped automatically
 *    when the circuit artifacts are absent.
 */
import { computeVkHash } from "../src/verify.js";

export const RECIPIENT = "0xDe42f1a2b3c4d5e6f708192a3b4c5d6e7f809f01";
export const RECIPIENT_BIGINT = BigInt(RECIPIENT).toString();

export const MOCK_VK = {
  protocol: "groth16",
  curve: "bn128",
  nPublic: 4,
  vk_alpha_1: ["1", "2", "1"],
  vk_beta_2: [
    ["3", "4"],
    ["5", "6"],
    ["1", "0"],
  ],
  vk_gamma_2: [
    ["7", "8"],
    ["9", "10"],
    ["1", "0"],
  ],
  vk_delta_2: [
    ["11", "12"],
    ["13", "14"],
    ["1", "0"],
  ],
  vk_ic: [
    ["15", "16", "1"],
    ["17", "18", "1"],
    ["19", "20", "1"],
    ["21", "22", "1"],
    ["23", "24", "1"],
  ],
};

export const MOCK_PROOF = {
  pi_a: ["1", "2", "1"],
  pi_b: [
    ["3", "4"],
    ["5", "6"],
    ["1", "0"],
  ],
  pi_c: ["7", "8", "1"],
  protocol: "groth16",
  curve: "bn128",
};

export function registeredVkFor(vk: unknown): string {
  return computeVkHash(vk as never) ?? "";
}

/** Brief-shape payload (agent-games.proof-gatekeeper.v1) that is VALID. */
export function validBriefTask(overrides: Record<string, unknown> = {}) {
  const publicSignals = ["1460", "1000", RECIPIENT_BIGINT, "19842201"];
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    input: {
      registered_vk: registeredVkFor(MOCK_VK),
      proof: {
        proofType: "groth16",
        proof: MOCK_PROOF,
        publicSignals,
        verificationKey: MOCK_VK,
      },
      context: {
        recipient: RECIPIENT,
        minimum_balance: "1000",
        valid_after: "1000",
        expiry: "19842201",
      },
      received_at: "19832000",
      ...overrides,
    },
  };
}

/** Event-page-shape payload (flat input fields) that is VALID. */
export function validEventTask(overrides: Record<string, unknown> = {}) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: "gk_24_9d1",
    mode: "competition",
    input: {
      registered_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
      proof_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
      ...overrides,
    },
  };
}
