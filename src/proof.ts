/**
 * Decision-proof generation for the Proof Gatekeeper track.
 *
 * Verified facts (from the live platform, 14 Nov 2026):
 *  - Circuit info: https://agentgames.zkverify.io/api/circuit-info
 *    network mainnet, gatekeeper vkHash
 *    0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0,
 *    wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm,
 *    zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
 *  - The gatekeeper verification key exported from that zkey has
 *    nPublic = 13 (Groth16/BN128) — the decision proof therefore has
 *    13 public signals, NOT the 4 public signals of the incoming
 *    payment proof. Do not confuse the two.
 *  - The circuit's 13 input signals were recovered empirically by
 *    probing the published wasm with snarkjs (FNV-hash signal oracle)
 *    and then confirmed by real fullProve + groth16.verify runs:
 *    decision, salt, publicBalance, minimum, recipient,
 *    conditionRecipient, expiryBlock, currentBlock, amount,
 *    maxTransfer, registeredVkHash, proofVkHash, taskId.
 *    `salt` is the 13th, private input: changing it changes
 *    publicSignals[0] (a hash binding) but any field element works.
 *  - The circuit ENFORCES decision correctness (template
 *    GatekeeperEvaluation, line 102): fullProve FAILS for
 *    valid-condition + REJECT, and for trap + APPROVE. It only
 *    proves when decision matches the correct evaluation:
 *    valid -> APPROVE, any trap -> REJECT. Verified live:
 *    valid+approve proved+verified; valid+reject, trap+approve
 *    failed the circuit assert; trap+reject proved+verified.
 *  - Decision-proof public signals, in order (verified live):
 *    [hash, registeredVkHash, proofVkHash, minimum, publicBalance,
 *    expiryBlock, currentBlock, recipient, conditionRecipient,
 *    amount, maxTransfer, decision, taskId] — 13 values. The first
 *    is a hash bound to the (private) salt; the rest echo the inputs.
 *    NOTE: this order differs from the brief's [balance, threshold,
 *    recipient, expiry] — that order is the INCOMING payment
 *    proof's public signals, not the decision proof's.
 *  - Until the platform confirms how `salt` should be derived, this
 *    code derives it deterministically as SHA-256(taskId + decision)
 *    mod the BN128 field prime, so the same task always yields the
 *    same proof. The circuit accepts any field element as salt, so
 *    this choice cannot make a correct decision unprovable — but if
 *    the platform expects a specific salt derivation, update
 *    toCircuitInput accordingly.
 */
import { createHash } from "node:crypto";
import * as snarkjs from "snarkjs";
import type { CanonicalTask } from "./verify.js";

export const GATEKEEPER_CIRCUIT = {
  network: "mainnet",
  vkHash: "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0",
  wasmUrl: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
  zkeyUrl: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
  /** Public signals in the decision proof (from the exported VK). */
  nPublic: 13,
} as const;

/**
 * The circuit's input signals, as confirmed by probing the published
 * wasm and by real fullProve + groth16.verify runs (see README).
 * Values are field elements, given as decimal strings.
 * `taskId` is hashed (SHA-256 -> bigint mod the BN128 field prime)
 * because a task id such as "gk_24_9d1" is not a field element.
 * `salt` is the private 13th input; see the header comment.
 */
export interface DecisionCircuitInput {
  decision: string; // "1" = APPROVE, "0" = REJECT
  salt: string; // decimal bigint string (private input)
  publicBalance: string;
  minimum: string;
  recipient: string; // decimal bigint string
  conditionRecipient: string; // decimal bigint string
  expiryBlock: string;
  currentBlock: string;
  amount: string;
  maxTransfer: string;
  registeredVkHash: string; // decimal bigint string
  proofVkHash: string; // decimal bigint string
  taskId: string; // decimal bigint string (hashed)
}

const BN128_PRIME = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

export function fieldElement(value: string): string {
  return (BigInt(value) % BN128_PRIME).toString();
}

export function hashToField(value: string): string {
  const digest = createHash("sha256").update(value, "utf8").digest("hex");
  return (BigInt(`0x${digest}`) % BN128_PRIME).toString();
}

/**
 * Map a normalised task + decision to the circuit's input signals.
 * Hashes (registered_vk / proof_vk) are converted 0x hex -> decimal
 * bigint string. Throws if a required value is missing.
 */
export function toCircuitInput(task: CanonicalTask, decision: "APPROVE" | "REJECT"): DecisionCircuitInput {
  const registered = task.registeredVk.toLowerCase().replace(/^0x/, "");
  const proofVk =
    typeof task.proofVk === "string" ? task.proofVk.toLowerCase().replace(/^0x/, "") : registered;
  return {
    decision: decision === "APPROVE" ? "1" : "0",
    // Deterministic per task+decision; the circuit accepts any field
    // element as salt (verified live with salt "1" and "999").
    salt: hashToField(`${task.taskId}:${decision}`),
    publicBalance: task.balance,
    minimum: task.threshold,
    recipient: task.recipient,
    conditionRecipient: task.conditionRecipient,
    expiryBlock: task.expiryBlock ?? task.expiryTs ?? "0",
    currentBlock: task.currentBlock ?? task.receivedAt ?? "0",
    amount: task.amount ?? "0",
    maxTransfer: task.maxTransfer ?? "0",
    registeredVkHash: BigInt(`0x${registered || "0"}`).toString(),
    proofVkHash: BigInt(`0x${proofVk || "0"}`).toString(),
    taskId: hashToField(task.taskId),
  };
}

export interface DecisionProof {
  proof: unknown;
  publicSignals: string[];
}

export type Prover = (input: DecisionCircuitInput) => Promise<DecisionProof>;

export class CircuitArtifactsMissingError extends Error {
  constructor() {
    super(
      "Gatekeeper circuit artifacts not configured: set GATEKEEPER_WASM and " +
        "GATEKEEPER_ZKEY (or inject a prover). Decision proof cannot be generated.",
    );
    this.name = "CircuitArtifactsMissingError";
  }
}

/**
 * Build a real snarkjs prover from local wasm/zkey files.
 * The circuit enforces decision correctness: fullProve throws if the
 * decision does not match the correct evaluation (valid -> APPROVE,
 * any trap -> REJECT), so a wrong decision can never produce a proof.
 */
export function createSnarkjsProver(wasmPath: string, zkeyPath: string): Prover {
  return async (input: DecisionCircuitInput): Promise<DecisionProof> => {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input as unknown as Record<string, unknown>,
      wasmPath,
      zkeyPath,
    );
    return { proof, publicSignals: publicSignals.map(String) };
  };
}

/**
 * Generate the decision proof for a task.
 *
 *  - If a `prover` is injected (tests), use it.
 *  - Else if wasm/zkey paths are configured, build a snarkjs prover.
 *  - Else throw CircuitArtifactsMissingError — the caller (server)
 *    then returns the decision with proof: null instead of inventing
 *    a proof.
 *
 * NOTE: a wrong decision cannot be proven — the circuit asserts at
 * GatekeeperEvaluation line 102 when decision != correct evaluation,
 * so fullProve throws and the server answers 500 rather than
 * returning a bogus proof. That is the intended fail-closed behaviour.
 */
export async function generateDecisionProof(
  task: CanonicalTask,
  decision: "APPROVE" | "REJECT",
  opts: { prover?: Prover; wasmPath?: string; zkeyPath?: string } = {},
): Promise<DecisionProof> {
  const input = toCircuitInput(task, decision);
  if (opts.prover) return opts.prover(input);
  if (opts.wasmPath && opts.zkeyPath) {
    return createSnarkjsProver(opts.wasmPath, opts.zkeyPath)(input);
  }
  throw new CircuitArtifactsMissingError();
}
