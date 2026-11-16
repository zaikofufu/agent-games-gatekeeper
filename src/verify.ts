/**
 * Decision logic for the Proof Gatekeeper track.
 *
 * Two payload shapes are accepted, because the platform documents two:
 *
 *  1. The "brief" envelope (agent-games.proof-gatekeeper.v1) with
 *     input.proof { proofType, proof, publicSignals, verificationKey },
 *     input.registered_vk and input.context { recipient, minimum_balance,
 *     valid_after, expiry }, input.received_at.
 *  2. The sample payload on https://agentgames.zkverify.io/events/proof-gatekeeper
 *     with flat input fields: registered_vk, proof_vk, minimum,
 *     public_balance, expiry_block, current_block, recipient,
 *     condition_recipient, amount, max_transfer, proof_tx.
 *
 * Both are normalised to CanonicalTask and then checked in fail-closed
 * order. See README.md "Spec gaps" for the discrepancies this file
 * papers over (notably: the VK-hash algorithm and the block-vs-time
 * expiry are NOT published by the platform — see computeVkHash).
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export type Decision = "APPROVE" | "REJECT";

/**
 * Reason codes. The brief lists VALID_CONDITION, RECIPIENT_MISMATCH,
 * THRESHOLD_MISMATCH, VK_SUBSTITUTION, EXPIRED, PROOF_INVALID.
 * The live event page additionally uses EXPIRED_CONDITION (block expiry),
 * PROOF_REUSED and AMOUNT_OVERFLOW — all three are real traps on that
 * page, so they are included here. EXPIRED is kept as the timestamp
 * variant; EXPIRED_CONDITION is the block-height variant.
 */
export type ReasonCode =
  | "VALID_CONDITION"
  | "VK_SUBSTITUTION"
  | "THRESHOLD_MISMATCH"
  | "RECIPIENT_MISMATCH"
  | "EXPIRED"
  | "EXPIRED_CONDITION"
  | "PROOF_INVALID"
  | "PROOF_REUSED"
  | "AMOUNT_OVERFLOW";

export interface DecisionResult {
  decision: Decision;
  reason_code: ReasonCode;
  /** Canonical public signals, in order [balance, threshold, recipient, expiry]. */
  public_signals: string[];
}

/** A Groth16 verification key object (snarkjs format). */
export type VerificationKey = Record<string, unknown>;

/**
 * Normalised task. All money/block/time values are kept as strings and
 * compared with BigInt so large balances and block numbers never lose
 * precision in a JS number.
 */
export interface CanonicalTask {
  taskId: string;
  mode: "competition" | "practice";
  balance: string;
  threshold: string;
  /** Recipient committed in the proof, as a decimal bigint string. */
  recipient: string;
  /** Recipient on the payment condition, as a decimal bigint string. */
  conditionRecipient: string;
  /** Block-height expiry (event-page shape). */
  expiryBlock?: string;
  /** Block height at which the task was issued (event-page shape). */
  currentBlock?: string;
  /** Timestamp expiry (brief shape). */
  expiryTs?: string;
  /** Earliest valid timestamp (brief shape). */
  validAfter?: string;
  /** Timestamp at which the platform sent the task (brief shape). */
  receivedAt?: string;
  amount?: string;
  maxTransfer?: string;
  /** On-chain proof reference (event-page shape). */
  proofTx?: string;
  registeredVk: string;
  /** Hash string (event-page shape) or full VK object (brief shape). */
  proofVk: string | VerificationKey | null;
  proofType: string;
  /** The incoming Groth16 proof object, if the payload carried one. */
  proof: unknown;
  /** The incoming proof's public signals, if the payload carried them. */
  publicSignals: string[];
  /** The incoming proof's verification key object, if carried. */
  verificationKey: VerificationKey | null;
}

export interface ProofVerifier {
  /** snarkjs.groth16.verify(vk, publicSignals, proof). */
  (vk: VerificationKey, publicSignals: string[], proof: unknown): Promise<boolean>;
}

export interface ReplayStore {
  hasApprovedTask(taskId: string): boolean;
  markApprovedTask(taskId: string): void;
  hasApprovedProofTx(proofTx: string): boolean;
  markApprovedProofTx(proofTx: string): void;
}

/** Max approved task ids / proof txs kept per set (oldest trimmed first). */
export const DEFAULT_REPLAY_MAX_ENTRIES = 5000;
/** Default store file, relative to the process working directory. */
export const DEFAULT_REPLAY_FILE = "data/replay.json";

export interface ReplayStoreOptions {
  /**
   * Path of the JSON file the store persists to.
   *  - a string: file-backed at that path (relative paths resolve
   *    against the process working directory);
   *  - undefined: the SEEN_STORE_PATH env var, else "data/replay.json";
   *  - null: purely in-memory, nothing is written to disk (tests).
   */
  filePath?: string | null;
  /** Max entries kept per set (oldest trimmed first). Default 5000. */
  maxEntries?: number;
}

/**
 * File-backed replay store. Approved task ids and proof txs live in
 * in-memory Sets (the hot path) and are written to a JSON file
 * synchronously on every mark, so a process restart on the same
 * machine — e.g. the Fly trial machine stopping every ~5 minutes —
 * no longer wipes the seen-set. A fresh store instance loads the file
 * on creation.
 *
 * Limits: the file lives on the machine's own filesystem, so a fresh
 * deploy (a new machine) starts with an empty store, and two
 * instances do not share it — a multi-instance deployment still
 * needs a shared store (e.g. Redis). Writes go to a temp file +
 * rename so a SIGINT mid-write cannot leave a half-written file.
 * A failed load or write never throws: the in-memory sets still hold
 * the entry for this process, so the decision path is unaffected —
 * only cross-restart durability is lost. Only ids are stored, never
 * task bodies, proofs, keys or secrets.
 */
export function createReplayStore(opts: ReplayStoreOptions = {}): ReplayStore {
  const maxEntries = Math.max(1, Math.floor(opts.maxEntries ?? DEFAULT_REPLAY_MAX_ENTRIES));
  const filePath =
    opts.filePath === null
      ? null
      : resolve(process.cwd(), opts.filePath ?? process.env.SEEN_STORE_PATH ?? DEFAULT_REPLAY_FILE);

  const taskQueue: string[] = [];
  const taskSet = new Set<string>();
  const txQueue: string[] = [];
  const txSet = new Set<string>();

  function add(queue: string[], set: Set<string>, value: string): void {
    if (set.has(value)) return;
    queue.push(value);
    set.add(value);
    while (queue.length > maxEntries) {
      const oldest = queue.shift();
      if (oldest !== undefined) set.delete(oldest);
    }
  }

  function load(): void {
    if (filePath === null) return;
    try {
      if (!existsSync(filePath)) return;
      const parsed = JSON.parse(readFileSync(filePath, "utf8")) as {
        tasks?: unknown;
        proofTx?: unknown;
      };
      // Keep only the newest maxEntries of each list, in file order.
      for (const [list, queue, set] of [
        [parsed.tasks, taskQueue, taskSet],
        [parsed.proofTx, txQueue, txSet],
      ] as const) {
        if (!Array.isArray(list)) continue;
        for (const entry of list.slice(-maxEntries)) {
          if (typeof entry === "string") add(queue, set, entry);
        }
      }
    } catch {
      // Corrupt or unreadable file: start empty and let the next mark
      // rewrite a valid file. Same exposure as the old in-memory store.
      console.error(`replay store: could not load ${filePath}; starting empty`);
    }
  }

  function persist(): void {
    if (filePath === null) return;
    try {
      mkdirSync(dirname(filePath), { recursive: true });
      const tmp = `${filePath}.tmp`;
      writeFileSync(tmp, JSON.stringify({ tasks: taskQueue, proofTx: txQueue }), "utf8");
      renameSync(tmp, filePath);
    } catch {
      console.error(`replay store: could not persist ${filePath}`);
    }
  }

  function mark(queue: string[], set: Set<string>, value: string): void {
    if (set.has(value)) return; // No change, no rewrite.
    add(queue, set, value);
    persist();
  }

  load();
  return {
    hasApprovedTask: (t) => taskSet.has(t),
    markApprovedTask: (t) => mark(taskQueue, taskSet, t),
    hasApprovedProofTx: (t) => txSet.has(t),
    markApprovedProofTx: (t) => mark(txQueue, txSet, t),
  };
}

/** Deterministic JSON: sorted keys, no whitespace. Used for VK hashing. */
export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`)
    .join(",")}}`;
}

/**
 * Recompute a verification-key hash.
 *
 * SPEC GAP (see README): the platform does not publish how registered_vk
 * is computed from a verification key. This implementation:
 *  - if the VK is already a 0x hex hash (32 bytes), uses it as-is;
 *  - otherwise SHA-256 over the stable (sorted-key) JSON of the VK object.
 *
 * If the platform instead uses keccak256, or hashes only vk_ic, a VK that
 * is actually correct will be reported as VK_SUBSTITUTION in production.
 * Confirm the algorithm against a known-good practice task before a
 * scored round, and update this function if it differs.
 */
export function computeVkHash(vk: string | VerificationKey | null): string | null {
  if (vk === null || vk === undefined) return null;
  if (typeof vk === "string") {
    const h = vk.toLowerCase();
    if (/^0x[0-9a-f]{64}$/.test(h)) return h;
    // A non-hash string is hashed as-is (defensive; not expected).
    return `0x${createHash("sha256").update(vk, "utf8").digest("hex")}`;
  }
  return `0x${createHash("sha256").update(stableStringify(vk), "utf8").digest("hex")}`;
}

export function normaliseVkHash(value: string | null | undefined): string | null {
  if (!value) return null;
  const v = value.toLowerCase();
  return v.startsWith("0x") ? v : `0x${v}`;
}

/** 0x address (or decimal bigint string) -> decimal bigint string. */
export function addressToBigint(value: string): string {
  const v = value.trim().toLowerCase();
  try {
    return BigInt(v).toString();
  } catch {
    return v;
  }
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  return undefined;
}

/**
 * Normalise either documented payload shape into a CanonicalTask.
 * Throws on a structurally unusable payload (missing task_id / input).
 */
export function normaliseTask(raw: Record<string, unknown>): CanonicalTask {
  const input = raw.input as Record<string, unknown> | undefined;
  if (!input || typeof input !== "object") throw new Error("missing input");
  const taskId = asString(raw.task_id) ?? asString(input.task_id);
  if (!taskId) throw new Error("missing task_id");
  const mode = raw.mode === "practice" ? "practice" : "competition";

  // ---- Brief shape: input.proof { proofType, proof, publicSignals, verificationKey }
  const proofObj = input.proof as Record<string, unknown> | undefined;
  if (proofObj && typeof proofObj === "object") {
    const publicSignals = (proofObj.publicSignals as unknown[])?.map((s) => String(s)) ?? [];
    const context = (input.context as Record<string, unknown>) ?? {};
    const recipient = asString(context.recipient) ?? "";
    return {
      taskId,
      mode,
      balance: publicSignals[0] ?? "0",
      threshold: publicSignals[1] ?? asString(context.minimum_balance) ?? "0",
      recipient: publicSignals[2] ?? addressToBigint(recipient),
      conditionRecipient: addressToBigint(recipient),
      expiryTs: publicSignals[3] ?? asString(context.expiry),
      validAfter: asString(context.valid_after),
      receivedAt: asString(input.received_at),
      registeredVk: asString(input.registered_vk) ?? "",
      proofVk: (proofObj.verificationKey as VerificationKey) ?? null,
      proofType: asString(proofObj.proofType) ?? "",
      proof: proofObj.proof ?? null,
      publicSignals,
      verificationKey: (proofObj.verificationKey as VerificationKey) ?? null,
    };
  }

  // ---- Event-page shape: flat input fields.
  const recipient = asString(input.recipient) ?? "";
  const conditionRecipient = asString(input.condition_recipient) ?? recipient;
  return {
    taskId,
    mode,
    balance: asString(input.public_balance) ?? "0",
    threshold: asString(input.minimum) ?? "0",
    recipient: addressToBigint(recipient),
    conditionRecipient: addressToBigint(conditionRecipient),
    expiryBlock: asString(input.expiry_block),
    currentBlock: asString(input.current_block),
    amount: asString(input.amount),
    maxTransfer: asString(input.max_transfer),
    proofTx: asString(input.proof_tx),
    registeredVk: asString(input.registered_vk) ?? "",
    proofVk: asString(input.proof_vk) ?? null,
    proofType: "groth16", // Platform states both tracks use Groth16/BN128.
    proof: null,
    // Canonical public signals, same order as the brief shape.
    publicSignals: [
      asString(input.public_balance) ?? "0",
      asString(input.minimum) ?? "0",
      addressToBigint(recipient),
      asString(input.expiry_block) ?? "0",
    ],
    verificationKey: null,
  };
}

function reject(code: ReasonCode, task: CanonicalTask): DecisionResult {
  return { decision: "REJECT", reason_code: code, public_signals: task.publicSignals };
}

/**
 * Run every decision check, fail-closed, in the order the platform's
 * own checklist implies (see /build §04 and the event "trap encyclopedia"):
 * replay -> proof type -> VK match -> proof verifies -> expiry ->
 * recipient -> threshold -> amount overflow -> approve.
 *
 * The injected `verifyProof` is only called when the payload actually
 * carried a proof object + verification key (brief shape). For the
 * event-page shape the proof lives on-chain under proof_tx and the
 * platform/zkVerify is the verifier; the agent checks the VK hash and
 * the fields instead. A verifier that throws is treated as a failed
 * verification (fail closed).
 */
export async function decide(
  task: CanonicalTask,
  opts: { verifyProof: ProofVerifier; replay: ReplayStore },
): Promise<DecisionResult> {
  const { verifyProof, replay } = opts;

  // 1. Replay: a task_id already approved, or a proof_tx already approved.
  if (replay.hasApprovedTask(task.taskId)) return reject("PROOF_REUSED", task);
  if (task.proofTx && replay.hasApprovedProofTx(task.proofTx)) return reject("PROOF_REUSED", task);

  // 2. Proof system must be the one the task expects.
  if (task.proofType.toLowerCase() !== "groth16") return reject("PROOF_INVALID", task);

  // 3. The verification key must match the registered condition VK.
  //    A proof can verify perfectly against the WRONG key — validity is
  //    not the same as condition compliance.
  const registered = normaliseVkHash(task.registeredVk);
  const proofVkHash = computeVkHash(task.proofVk);
  if (!registered || !proofVkHash || normaliseVkHash(proofVkHash) !== registered) {
    return reject("VK_SUBSTITUTION", task);
  }

  // 4. The incoming proof must actually verify against that key, and its
  //    public signals must match the condition values in the task.
  if (task.proof !== null && task.verificationKey !== null) {
    let ok = false;
    try {
      ok = await verifyProof(task.verificationKey, task.publicSignals, task.proof);
    } catch {
      ok = false;
    }
    if (!ok) return reject("PROOF_INVALID", task);
    if (task.publicSignals.length !== 4) return reject("PROOF_INVALID", task);
  }

  // 5. Expiry — block height (event shape) or timestamp (brief shape).
  if (task.expiryBlock !== undefined && task.currentBlock !== undefined) {
    if (BigInt(task.currentBlock) > BigInt(task.expiryBlock)) return reject("EXPIRED_CONDITION", task);
  }
  if (task.expiryTs !== undefined && task.receivedAt !== undefined) {
    if (BigInt(task.receivedAt) > BigInt(task.expiryTs)) return reject("EXPIRED", task);
  }
  if (task.validAfter !== undefined && task.receivedAt !== undefined) {
    if (BigInt(task.receivedAt) < BigInt(task.validAfter)) return reject("EXPIRED", task);
  }

  // 6. The recipient committed in the proof must be the condition's recipient.
  if (task.recipient !== task.conditionRecipient) return reject("RECIPIENT_MISMATCH", task);

  // 7. The public balance must meet the minimum threshold.
  if (BigInt(task.balance) < BigInt(task.threshold)) return reject("THRESHOLD_MISMATCH", task);

  // 8. The requested amount must not exceed the single-transfer cap.
  if (task.amount !== undefined && task.maxTransfer !== undefined) {
    if (BigInt(task.amount) > BigInt(task.maxTransfer)) return reject("AMOUNT_OVERFLOW", task);
  }

  return { decision: "APPROVE", reason_code: "VALID_CONDITION", public_signals: task.publicSignals };
}
