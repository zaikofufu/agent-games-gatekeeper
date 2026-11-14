/**
 * Unit tests for decision-proof generation (src/proof.ts).
 *
 * The prover is MOCKED here (an injected stub returning a fixture
 * proof). The REAL snarkjs path — fullProve against the published
 * gatekeeper wasm/zkey, then groth16.verify against the exported VK —
 * is covered by test/proof.real.test.ts, which runs only when the
 * circuit artifacts are present under circuits/.
 */
import { describe, expect, it } from "vitest";
import {
  CircuitArtifactsMissingError,
  createSnarkjsProver,
  generateDecisionProof,
  hashToField,
  toCircuitInput,
} from "../src/proof.js";
import { normaliseTask } from "../src/verify.js";
import { validEventTask } from "./fixtures.js";

const task = normaliseTask(validEventTask() as unknown as Record<string, unknown>);

describe("toCircuitInput", () => {
  it("maps a task to the circuit's confirmed input signals", () => {
    const input = toCircuitInput(task, "APPROVE");
    expect(input.decision).toBe("1");
    expect(input.publicBalance).toBe("1460");
    expect(input.minimum).toBe("1000");
    expect(input.recipient).toBe(BigInt("0xDe42f1a2b3c4d5e6f708192a3b4c5d6e7f809f01").toString());
    expect(input.conditionRecipient).toBe(input.recipient);
    expect(input.expiryBlock).toBe("19842201");
    expect(input.currentBlock).toBe("19832000");
    expect(input.amount).toBe("500");
    expect(input.maxTransfer).toBe("1000");
    expect(input.registeredVkHash).toBe(input.proofVkHash);
    expect(input.taskId).toBe(hashToField("gk_24_9d1"));
  });

  it("REJECT maps decision to 0", () => {
    expect(toCircuitInput(task, "REJECT").decision).toBe("0");
  });
});

describe("generateDecisionProof with a MOCKED prover", () => {
  it("returns the stub proof and public signals", async () => {
    const stubProof = { pi_a: ["1", "2", "1"], pi_b: [], pi_c: ["3", "4", "1"] };
    const result = await generateDecisionProof(task, "APPROVE", {
      prover: async (input) => {
        expect(input.decision).toBe("1");
        return { proof: stubProof, publicSignals: ["a", "b"] };
      },
    });
    expect(result.proof).toBe(stubProof);
    expect(result.publicSignals).toEqual(["a", "b"]);
  });
});

describe("generateDecisionProof without artifacts", () => {
  it("throws CircuitArtifactsMissingError instead of inventing a proof", async () => {
    await expect(generateDecisionProof(task, "APPROVE")).rejects.toBeInstanceOf(
      CircuitArtifactsMissingError,
    );
  });
});

describe("createSnarkjsProver", () => {
  it("fails loudly when the artifact files do not exist", async () => {
    const prover = createSnarkjsProver("circuits/nope.wasm", "circuits/nope.zkey");
    await expect(prover(toCircuitInput(task, "APPROVE"))).rejects.toThrow();
  });

  it("toCircuitInput includes the private salt input", () => {
    const input = toCircuitInput(task, "APPROVE");
    expect(input.salt).toBe(hashToField("gk_24_9d1:APPROVE"));
    expect(input.salt).not.toBe(hashToField("gk_24_9d1:REJECT"));
  });
});
