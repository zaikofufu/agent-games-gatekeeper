/**
 * HTTP server for the Proof Gatekeeper agent.
 *
 * Contract (verified against https://agentgames.zkverify.io/build,
 * /guide, /rules and /events/proof-gatekeeper, 14 Nov 2026):
 *  - POST /agent — JSON task envelope. Header
 *    x-agent-games-signature: <hmac-sha256-hex> over the RAW request
 *    body, using the per-agent secret issued at registration.
 *    Verify the signature BEFORE parsing the body. Missing header
 *    -> 401; failed verification -> 403. The body is never logged.
 *  - GET /agent — health check: {"status":"ok","agent":...,"version":"1.0.0"}
 *  - Every response is signed with x-agent-games-signature over the
 *    raw response body (same secret).
 *  - Hard deadline 60s: the server races decision+proof against a
 *    50s internal budget and answers 503 if it cannot respond in time.
 *
 * No framework is used (Node's built-in http only) so the only runtime
 * dependency is snarkjs. The HMAC secret comes from env (AGENT_SECRET)
 * and is never logged, returned, or written to disk.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import * as snarkjs from "snarkjs";
import {
  CircuitArtifactsMissingError,
  generateDecisionProof,
  type Prover,
} from "./proof.js";
import {
  createReplayStore,
  decide,
  normaliseTask,
  type ProofVerifier,
  type ReplayStore,
} from "./verify.js";

export const AGENT_VERSION = "1.0.0";
export const MAX_BODY_BYTES = 1_000_000;
/** Internal budget, inside the platform's 60s deadline. */
export const RESPONSE_BUDGET_MS = 50_000;

export interface AgentOptions {
  secret: string;
  agentName?: string;
  /** Defaults to snarkjs.groth16.verify. Inject a stub in tests. */
  verifyProof?: ProofVerifier;
  /** Defaults to a snarkjs prover when wasm/zkey paths are set. */
  prover?: Prover;
  wasmPath?: string;
  zkeyPath?: string;
  replay?: ReplayStore;
  responseBudgetMs?: number;
}

function hmacHex(secret: string, body: Buffer): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

function signaturesMatch(secret: string, body: Buffer, header: string | undefined): boolean {
  if (!header) return false;
  const expected = hmacHex(secret, body);
  const given = header.trim().toLowerCase().replace(/^0x/, "");
  if (given.length !== expected.length) return false;
  try {
    return timingSafeEqual(Buffer.from(given, "utf8"), Buffer.from(expected, "utf8"));
  } catch {
    return false;
  }
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY_BYTES) throw new Error("body too large");
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("response budget exceeded")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export function createApp(opts: AgentOptions): Server {
  const secret = opts.secret;
  if (!secret) throw new Error("AGENT_SECRET is required");
  const agentName = opts.agentName ?? "gatekeeper";
  const verifyProof: ProofVerifier =
    opts.verifyProof ??
    ((vk, publicSignals, proof) => snarkjs.groth16.verify(vk, publicSignals, proof));
  const replay = opts.replay ?? createReplayStore();
  const budget = opts.responseBudgetMs ?? RESPONSE_BUDGET_MS;

  function send(res: ServerResponse, status: number, payload: unknown): void {
    const body = Buffer.from(JSON.stringify(payload), "utf8");
    res.writeHead(status, {
      "content-type": "application/json",
      "x-agent-games-signature": hmacHex(secret, body),
    });
    res.end(body);
  }

  return createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (url.pathname === "/agent" && req.method === "GET") {
        send(res, 200, { status: "ok", agent: agentName, version: AGENT_VERSION });
        return;
      }
      if (url.pathname !== "/agent" || req.method !== "POST") {
        send(res, 404, { error: "not_found" });
        return;
      }

      // Read the raw body first — the HMAC is over the raw bytes, and
      // it must be verified BEFORE the body is parsed or logged.
      const rawBody = await readBody(req);
      const sigHeader = req.headers["x-agent-games-signature"];
      const signature = Array.isArray(sigHeader) ? sigHeader[0] : sigHeader;
      if (!signature) {
        send(res, 401, { error: "missing_signature" });
        return;
      }
      if (!signaturesMatch(secret, rawBody, signature)) {
        send(res, 403, { error: "invalid_signature" });
        return;
      }

      let raw: Record<string, unknown>;
      try {
        raw = JSON.parse(rawBody.toString("utf8")) as Record<string, unknown>;
      } catch {
        send(res, 400, { error: "invalid_json" });
        return;
      }
      if (raw.type !== "agent-games.proof-gatekeeper.v1") {
        send(res, 400, { error: "unsupported_type" });
        return;
      }

      let task;
      try {
        task = normaliseTask(raw);
      } catch {
        send(res, 400, { error: "invalid_task" });
        return;
      }

      const result = await withTimeout(
        (async () => {
          const decision = await decide(task, { verifyProof, replay });
          let proof: unknown = null;
          let publicSignals: string[] | null = decision.public_signals;
          try {
            const generated = await generateDecisionProof(task, decision.decision, {
              prover: opts.prover,
              wasmPath: opts.wasmPath,
              zkeyPath: opts.zkeyPath,
            });
            proof = generated.proof;
            publicSignals = generated.publicSignals;
          } catch (err) {
            // No valid decision proof available. The decision itself is
            // still returned (the event page's own sample response is
            // just {decision, reason_code, proof_tx}); the platform
            // scores it as a correct decision without a valid proof
            // (-2, no reliability bonus) rather than a wrong decision.
            // Never invent a proof.
            if (!(err instanceof CircuitArtifactsMissingError)) {
              throw err;
            }
            proof = null;
          }
          // Record approved tasks only after the decision was computed,
          // so a retry after a network failure can still be answered.
          if (decision.decision === "APPROVE") {
            replay.markApprovedTask(task.taskId);
            if (task.proofTx) replay.markApprovedProofTx(task.proofTx);
          }
          return {
            decision: decision.decision,
            reason_code: decision.reason_code,
            proof,
            public_signals: publicSignals,
            // Passthrough for the event page's response shape.
            ...(task.proofTx ? { proof_tx: task.proofTx } : {}),
          };
        })(),
        budget,
      );
      send(res, 200, result);
    } catch (err) {
      if (err instanceof Error && err.message === "response budget exceeded") {
        // 503: cannot respond in time — the platform scores this as a
        // timeout (-2), but a late 200 would be a forfeit anyway.
        try {
          send(res, 503, { error: "response_timeout" });
        } catch {
          /* socket already gone */
        }
        return;
      }
      // Never leak internal details (or the body) in an error response.
      try {
        send(res, 500, { error: "internal_error" });
      } catch {
        /* socket already gone */
      }
    }
  });
}

/** sha256 helper (used by the health endpoint? no — kept for tests). */
export function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}
