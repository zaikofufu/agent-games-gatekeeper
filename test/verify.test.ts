/**
 * Unit tests for the decision logic (src/verify.ts).
 *
 * The incoming-proof verifier is MOCKED here (a stub returning
 * true/false). That is deliberate and labelled: the payment-condition
 * circuit that produced a task's incoming proof is not published, so
 * no real incoming Groth16 proof can be generated in a fixture.
 * The mocked verifier lets us test every decision branch
 * deterministically. The REAL snarkjs path is covered by
 * test/proof.real.test.ts, which proves and verifies against the
 * actual published gatekeeper circuit.
 */
import { describe, expect, it } from "vitest";
import {
  computeVkHash,
  createReplayStore,
  decide,
  normaliseTask,
  type ProofVerifier,
} from "../src/verify.js";
import { MOCK_PROOF, MOCK_VK, RECIPIENT, RECIPIENT_BIGINT, registeredVkFor, validBriefTask, validEventTask } from "./fixtures.js";

const verifyTrue: ProofVerifier = async () => true;
const verifyFalse: ProofVerifier = async () => false;

function decideBrief(raw: unknown, verifyProof: ProofVerifier = verifyTrue) {
  return decide(normaliseTask(raw as Record<string, unknown>), {
    verifyProof,
    replay: createReplayStore(),
  });
}

describe("VALID -> APPROVE", () => {
  it("brief shape: all checks pass", async () => {
    const r = await decideBrief(validBriefTask());
    expect(r).toEqual({
      decision: "APPROVE",
      reason_code: "VALID_CONDITION",
      public_signals: ["1460", "1000", RECIPIENT_BIGINT, "19842201"],
    });
  });

  it("event-page shape: all checks pass", async () => {
    const r = await decideBrief(validEventTask());
    expect(r.decision).toBe("APPROVE");
    expect(r.reason_code).toBe("VALID_CONDITION");
  });

  it("balance exactly equal to threshold approves", async () => {
    const r = await decideBrief(
      validEventTask({ public_balance: "1000", minimum: "1000" }),
    );
    expect(r.decision).toBe("APPROVE");
  });
});

describe("VK_SUBSTITUTION -> REJECT", () => {
  it("brief shape: verification key hash differs from registered_vk", async () => {
    const task = validBriefTask();
    (task.input as Record<string, unknown>).registered_vk =
      "0x00000000000000000000000000000000000000000000000000000000deadbeef";
    const r = await decideBrief(task);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "VK_SUBSTITUTION" });
  });

  it("event shape: proof_vk hash differs from registered_vk", async () => {
    const r = await decideBrief(
      validEventTask({
        proof_vk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff",
      }),
    );
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "VK_SUBSTITUTION" });
  });

  it("computeVkHash is deterministic and matches the registered value", () => {
    expect(computeVkHash(MOCK_VK)).toBe(registeredVkFor(MOCK_VK));
  });
});

describe("THRESHOLD_MISMATCH -> REJECT", () => {
  it("brief shape: balance below threshold", async () => {
    const task = validBriefTask();
    const proof = (task.input as Record<string, unknown>).proof as Record<string, unknown>;
    proof.publicSignals = ["999", "1000", RECIPIENT_BIGINT, "19842201"];
    const r = await decideBrief(task);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" });
  });

  it("event shape: public_balance below minimum", async () => {
    const r = await decideBrief(validEventTask({ public_balance: "500" }));
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" });
  });
});

describe("RECIPIENT_MISMATCH -> REJECT", () => {
  it("brief shape: proof recipient differs from condition recipient (case-insensitive)", async () => {
    const task = validBriefTask();
    const proof = (task.input as Record<string, unknown>).proof as Record<string, unknown>;
    proof.publicSignals = ["1460", "1000", BigInt("0x1111111111111111111111111111111111111111").toString(), "19842201"];
    const r = await decideBrief(task);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" });
  });

  it("event shape: recipient differs from condition_recipient", async () => {
    const r = await decideBrief(
      validEventTask({ recipient: "0x1111111111111111111111111111111111111111" }),
    );
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" });
  });

  it("recipient comparison is case-insensitive", async () => {
    const r = await decideBrief(validEventTask({ recipient: RECIPIENT.toUpperCase() }));
    expect(r.decision).toBe("APPROVE");
  });
});

describe("EXPIRED -> REJECT", () => {
  it("brief shape: received_at after expiry", async () => {
    const task = validBriefTask();
    (task.input as Record<string, unknown>).received_at = "19850000";
    const r = await decideBrief(task);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "EXPIRED" });
  });

  it("brief shape: received_at before valid_after", async () => {
    const task = validBriefTask();
    (task.input as Record<string, unknown>).received_at = "500";
    const r = await decideBrief(task);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "EXPIRED" });
  });

  it("event shape: current_block past expiry_block", async () => {
    const r = await decideBrief(validEventTask({ current_block: 19850000 }));
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "EXPIRED_CONDITION" });
  });
});

describe("PROOF_INVALID -> REJECT", () => {
  it("mocked verifier returns false", async () => {
    const r = await decideBrief(validBriefTask(), verifyFalse);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "PROOF_INVALID" });
  });

  it("wrong proofType", async () => {
    const task = validBriefTask();
    const proof = (task.input as Record<string, unknown>).proof as Record<string, unknown>;
    proof.proofType = "plonk";
    const r = await decideBrief(task);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "PROOF_INVALID" });
  });

  it("verifier throwing is treated as failed verification (fail closed)", async () => {
    const throwing: ProofVerifier = async () => {
      throw new Error("snarkjs boom");
    };
    const r = await decideBrief(validBriefTask(), throwing);
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "PROOF_INVALID" });
  });
});

describe("PROOF_REUSED -> REJECT", () => {
  it("same task_id approved twice", async () => {
    const replay = createReplayStore();
    const task = normaliseTask(validBriefTask() as unknown as Record<string, unknown>);
    const first = await decide(task, { verifyProof: verifyTrue, replay });
    expect(first.decision).toBe("APPROVE");
    // The server marks approved tasks; simulate that here.
    replay.markApprovedTask(task.taskId);
    const second = await decide(task, { verifyProof: verifyTrue, replay });
    expect(second).toMatchObject({ decision: "REJECT", reason_code: "PROOF_REUSED" });
  });

  it("same proof_tx approved twice (event shape)", async () => {
    const replay = createReplayStore();
    const task = normaliseTask(validEventTask() as unknown as Record<string, unknown>);
    const first = await decide(task, { verifyProof: verifyTrue, replay });
    expect(first.decision).toBe("APPROVE");
    replay.markApprovedProofTx(task.proofTx!);
    const second = await decide(task, { verifyProof: verifyTrue, replay });
    expect(second).toMatchObject({ decision: "REJECT", reason_code: "PROOF_REUSED" });
  });

  it("a REJECTED task is not recorded as reused (only approvals are)", async () => {
    const replay = createReplayStore();
    const task = normaliseTask(
      validEventTask({ public_balance: "1" }) as unknown as Record<string, unknown>,
    );
    const first = await decide(task, { verifyProof: verifyTrue, replay });
    expect(first.decision).toBe("REJECT");
    const second = await decide(task, { verifyProof: verifyTrue, replay });
    // Still a threshold mismatch, not a replay rejection.
    expect(second.reason_code).toBe("THRESHOLD_MISMATCH");
  });
});

describe("AMOUNT_OVERFLOW -> REJECT", () => {
  it("event shape: amount exceeds max_transfer", async () => {
    const r = await decideBrief(validEventTask({ amount: "1500" }));
    expect(r).toMatchObject({ decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" });
  });

  it("amount exactly at the cap approves", async () => {
    const r = await decideBrief(validEventTask({ amount: "1000" }));
    expect(r.decision).toBe("APPROVE");
  });
});

describe("normaliseTask", () => {
  it("throws on a missing input", () => {
    expect(() => normaliseTask({ type: "agent-games.proof-gatekeeper.v1" })).toThrow("missing input");
  });

  it("throws on a missing task_id", () => {
    expect(() =>
      normaliseTask({ type: "agent-games.proof-gatekeeper.v1", input: { minimum: "1" } }),
    ).toThrow("missing task_id");
  });

  it("MOCK_PROOF fixture is present (shape check only — it is not a real proof)", () => {
    expect(MOCK_PROOF.protocol).toBe("groth16");
    expect(MOCK_VK.nPublic).toBe(4);
  });
});
