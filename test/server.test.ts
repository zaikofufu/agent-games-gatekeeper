/**
 * HTTP tests for src/server.ts.
 *
 * The proof verifier and the decision-proof prover are MOCKED here
 * (injected stubs). HMAC handling, JSON parsing, status codes and
 * response signing are REAL — they run against a live HTTP server
 * bound to an ephemeral port.
 */
import { createHmac } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp, type AgentOptions } from "../src/server.js";
import { createReplayStore } from "../src/verify.js";
import { RECIPIENT_BIGINT, validBriefTask, validEventTask } from "./fixtures.js";

const SECRET = "test-secret-do-not-use-in-production";

function sign(secret: string, body: string): string {
  return createHmac("sha256", secret).update(body, "utf8").digest("hex");
}

async function startServer(overrides: Partial<AgentOptions> = {}) {
  const app = createApp({
    secret: SECRET,
    verifyProof: async () => true,
    prover: async () => ({ proof: { pi_a: ["1"] }, publicSignals: ["1", "2"] }),
    // In-memory replay store: HTTP tests must not touch the real file.
    replay: createReplayStore({ filePath: null }),
    ...overrides,
  });
  await new Promise<void>((resolve) => app.listen(0, resolve));
  const port = (app.address() as { port: number }).port;
  return { app, base: `http://127.0.0.1:${port}` };
}

describe("GET /agent", () => {
  let app: ReturnType<typeof createApp>;
  let base: string;
  beforeEach(async () => ({ app, base } = await startServer()));
  afterEach(async () => await new Promise<void>((r) => app.close(() => r())));

  it("returns the health payload and signs the response", async () => {
    const res = await fetch(`${base}/agent`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", agent: "gatekeeper", version: "1.0.0" });
    const sig = res.headers.get("x-agent-games-signature");
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it("unknown paths return 404", async () => {
    const res = await fetch(`${base}/nope`);
    expect(res.status).toBe(404);
  });
});

describe("POST /agent — HMAC", () => {
  let app: ReturnType<typeof createApp>;
  let base: string;
  beforeEach(async () => ({ app, base } = await startServer()));
  afterEach(async () => await new Promise<void>((r) => app.close(() => r())));

  it("missing signature -> 401", async () => {
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(validBriefTask()),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "missing_signature" });
  });

  it("invalid signature -> 403", async () => {
    const body = JSON.stringify(validBriefTask());
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sign("wrong-secret", body),
      },
      body,
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "invalid_signature" });
  });

  it("valid signature + VALID task -> 200 APPROVE with proof and a signed response", async () => {
    const body = JSON.stringify(validBriefTask());
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sign(SECRET, body),
      },
      body,
    });
    expect(res.status).toBe(200);
    const payload = (await res.json()) as Record<string, unknown>;
    expect(payload.decision).toBe("APPROVE");
    expect(payload.reason_code).toBe("VALID_CONDITION");
    expect(payload.proof).toEqual({ pi_a: ["1"] });
    expect(payload.public_signals).toEqual(["1", "2"]);
    // The response signature must verify over the exact response body.
    const rawText = JSON.stringify(payload);
    const sig = res.headers.get("x-agent-games-signature") ?? "";
    // Note: res.json() re-serialises; verify against the raw bytes instead.
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
    expect(sign(SECRET, rawText)).toBe(sig);
  });

  it("valid signature + event-shape task -> 200 APPROVE with proof_tx passthrough", async () => {
    const body = JSON.stringify(validEventTask());
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sign(SECRET, body),
      },
      body,
    });
    expect(res.status).toBe(200);
    const payload = (await res.json()) as Record<string, unknown>;
    expect(payload.decision).toBe("APPROVE");
    expect(payload.proof_tx).toBe(
      "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
    );
  });

  it("valid signature + REJECT task -> 200 REJECT", async () => {
    const body = JSON.stringify(validEventTask({ public_balance: "1" }));
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sign(SECRET, body),
      },
      body,
    });
    expect(res.status).toBe(200);
    const payload = (await res.json()) as Record<string, unknown>;
    expect(payload).toMatchObject({ decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" });
  });

  it("valid signature + malformed JSON -> 400", async () => {
    const body = "{not json";
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sign(SECRET, body),
      },
      body,
    });
    expect(res.status).toBe(400);
  });

  it("valid signature + wrong type -> 400", async () => {
    const body = JSON.stringify({ type: "something.else", task_id: "x", input: {} });
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sign(SECRET, body),
      },
      body,
    });
    expect(res.status).toBe(400);
  });

  it("same task approved twice -> second is PROOF_REUSED", async () => {
    const body = JSON.stringify(validEventTask());
    const headers = {
      "content-type": "application/json",
      "x-agent-games-signature": sign(SECRET, body),
    };
    const first = await fetch(`${base}/agent`, { method: "POST", headers, body });
    expect((await first.json() as Record<string, unknown>).decision).toBe("APPROVE");
    const second = await fetch(`${base}/agent`, { method: "POST", headers, body });
    const payload = (await second.json()) as Record<string, unknown>;
    expect(payload).toMatchObject({ decision: "REJECT", reason_code: "PROOF_REUSED" });
  });
});

describe("POST /agent — prover throws a generic error", () => {
  it("fails soft: 200 with the decision and proof: null, not a 500", async () => {
    // Live case (16 Nov 2026): a VK_SUBSTITUTION practice task made
    // proof generation assert-fail ("Error in template
    // GatekeeperEvaluation_79 line: 102") and the server answered
    // HTTP 500, so no decision was delivered. A 500 is an unanswered
    // task (-2); a decision with proof: null still scores the
    // correct decision.
    const { app, base } = await startServer({
      prover: async () => {
        throw new Error(
          "Assert Failed. Error in template GatekeeperEvaluation_79 line: 102",
        );
      },
    });
    try {
      const body = JSON.stringify(validBriefTask());
      const res = await fetch(`${base}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": sign(SECRET, body),
        },
        body,
      });
      expect(res.status).toBe(200);
      const payload = (await res.json()) as Record<string, unknown>;
      expect(payload).toMatchObject({
        decision: "APPROVE",
        reason_code: "VALID_CONDITION",
        proof: null,
      });
      // The decision's own public signals are kept (same as the
      // missing-artifacts path), so the response shape is unchanged.
      expect(payload.public_signals).toEqual(["1460", "1000", RECIPIENT_BIGINT, "19842201"]);
    } finally {
      await new Promise<void>((r) => app.close(() => r()));
    }
  });
});

describe("POST /agent — no decision-proof artifacts", () => {
  it("returns the decision with proof: null instead of inventing one", async () => {
    const { app, base } = await startServer({ prover: undefined, wasmPath: undefined });
    try {
      const body = JSON.stringify(validBriefTask());
      const res = await fetch(`${base}/agent`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-agent-games-signature": sign(SECRET, body),
        },
        body,
      });
      expect(res.status).toBe(200);
      const payload = (await res.json()) as Record<string, unknown>;
      expect(payload.decision).toBe("APPROVE");
      expect(payload.proof).toBeNull();
    } finally {
      await new Promise<void>((r) => app.close(() => r()));
    }
  });
});
