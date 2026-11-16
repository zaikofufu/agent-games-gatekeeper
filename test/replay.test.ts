/**
 * Tests for the file-backed replay store (src/verify.ts).
 *
 * This is the regression suite for the 16 Nov 2026 PROOF_REUSED bug:
 * the old in-memory store lost every approved task id / proof tx when
 * the Fly trial machine restarted (~every 5 minutes), so a reused
 * proof approved hours earlier was APPROVEd again instead of being
 * REJECTed as PROOF_REUSED. The store must now survive a process
 * restart on the same machine.
 *
 * All tests use temp files (never the real data/replay.json) except
 * the explicit in-memory cases, which must not touch disk at all.
 */
import { createHmac } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../src/server.js";
import { createReplayStore } from "../src/verify.js";
import { validEventTask } from "./fixtures.js";

const tmpDirs: string[] = [];
let savedSeenStorePath: string | undefined;

function tmpFile(): string {
  const dir = mkdtempSync(join(tmpdir(), "gatekeeper-replay-"));
  tmpDirs.push(dir);
  return join(dir, "replay.json");
}

beforeEach(() => {
  savedSeenStorePath = process.env.SEEN_STORE_PATH;
});

afterEach(() => {
  if (savedSeenStorePath === undefined) delete process.env.SEEN_STORE_PATH;
  else process.env.SEEN_STORE_PATH = savedSeenStorePath;
  for (const dir of tmpDirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function readStored(file: string): { tasks: string[]; proofTx: string[] } {
  return JSON.parse(readFileSync(file, "utf8")) as { tasks: string[]; proofTx: string[] };
}

describe("file-backed replay store", () => {
  it("persists marks to disk synchronously and a fresh instance (simulated restart) sees them", () => {
    const file = tmpFile();
    const first = createReplayStore({ filePath: file });
    first.markApprovedTask("task-1");
    first.markApprovedProofTx("0xabc");

    // Written at decision time, not at shutdown: already on disk.
    expect(existsSync(file)).toBe(true);
    expect(readStored(file)).toEqual({ tasks: ["task-1"], proofTx: ["0xabc"] });

    // Simulated restart: a brand-new store over the same file.
    const restarted = createReplayStore({ filePath: file });
    expect(restarted.hasApprovedTask("task-1")).toBe(true);
    expect(restarted.hasApprovedProofTx("0xabc")).toBe(true);
    expect(restarted.hasApprovedTask("task-2")).toBe(false);
  });

  it("marks made by the restarted instance persist too", () => {
    const file = tmpFile();
    const first = createReplayStore({ filePath: file });
    first.markApprovedTask("task-1");
    const restarted = createReplayStore({ filePath: file });
    restarted.markApprovedTask("task-2");
    const third = createReplayStore({ filePath: file });
    expect(third.hasApprovedTask("task-1")).toBe(true);
    expect(third.hasApprovedTask("task-2")).toBe(true);
  });

  it("trims the oldest entries first (FIFO) once the cap is reached", () => {
    const file = tmpFile();
    const store = createReplayStore({ filePath: file, maxEntries: 3 });
    for (const t of ["t1", "t2", "t3", "t4", "t5"]) store.markApprovedTask(t);
    expect(store.hasApprovedTask("t1")).toBe(false);
    expect(store.hasApprovedTask("t2")).toBe(false);
    expect(store.hasApprovedTask("t3")).toBe(true);
    expect(store.hasApprovedTask("t4")).toBe(true);
    expect(store.hasApprovedTask("t5")).toBe(true);
    // The file on disk holds the trimmed set, and a fresh instance agrees.
    expect(readStored(file).tasks).toEqual(["t3", "t4", "t5"]);
    const restarted = createReplayStore({ filePath: file, maxEntries: 3 });
    expect(restarted.hasApprovedTask("t1")).toBe(false);
    expect(restarted.hasApprovedTask("t5")).toBe(true);
  });

  it("marking an already-seen value does not duplicate it on disk", () => {
    const file = tmpFile();
    const store = createReplayStore({ filePath: file });
    store.markApprovedTask("task-1");
    store.markApprovedTask("task-1");
    expect(readStored(file).tasks).toEqual(["task-1"]);
  });

  it("a corrupt file starts empty and recovers on the next mark", () => {
    const file = tmpFile();
    writeFileSync(file, "this is not json{{", "utf8");
    const store = createReplayStore({ filePath: file });
    expect(store.hasApprovedTask("task-1")).toBe(false);
    store.markApprovedTask("task-1");
    expect(store.hasApprovedTask("task-1")).toBe(true);
    expect(readStored(file).tasks).toEqual(["task-1"]);
  });

  it("SEEN_STORE_PATH is honoured when no filePath is given", () => {
    const file = tmpFile();
    process.env.SEEN_STORE_PATH = file;
    const store = createReplayStore();
    store.markApprovedTask("task-env");
    expect(readStored(file).tasks).toEqual(["task-env"]);
    const restarted = createReplayStore();
    expect(restarted.hasApprovedTask("task-env")).toBe(true);
  });

  it("filePath: null is purely in-memory and never touches disk", () => {
    const file = tmpFile();
    process.env.SEEN_STORE_PATH = file;
    const store = createReplayStore({ filePath: null });
    store.markApprovedTask("task-1");
    store.markApprovedProofTx("0xabc");
    expect(store.hasApprovedTask("task-1")).toBe(true);
    expect(existsSync(file)).toBe(false);
  });
});

describe("server restart keeps replay state", () => {
  const SECRET = "test-secret-do-not-use-in-production";

  async function startServer(file: string) {
    const app = createApp({
      secret: SECRET,
      verifyProof: async () => true,
      prover: async () => ({ proof: { pi_a: ["1"] }, publicSignals: ["1", "2"] }),
      replayFilePath: file,
    });
    await new Promise<void>((resolve) => app.listen(0, resolve));
    const port = (app.address() as { port: number }).port;
    return { app, base: `http://127.0.0.1:${port}` };
  }

  function sign(body: string): string {
    return createHmac("sha256", SECRET).update(body, "utf8").digest("hex");
  }

  async function postTask(base: string, body: string) {
    const res = await fetch(`${base}/agent`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-agent-games-signature": sign(body),
      },
      body,
    });
    return (await res.json()) as Record<string, unknown>;
  }

  it("a task approved before a restart is PROOF_REUSED after it", async () => {
    const file = tmpFile();
    const body = JSON.stringify(validEventTask());

    const first = await startServer(file);
    try {
      const approved = await postTask(first.base, body);
      expect(approved.decision).toBe("APPROVE");
    } finally {
      await new Promise<void>((r) => first.app.close(() => r()));
    }

    // Simulated Fly trial restart: new process, same file.
    const restarted = await startServer(file);
    try {
      const replayed = await postTask(restarted.base, body);
      expect(replayed).toMatchObject({ decision: "REJECT", reason_code: "PROOF_REUSED" });
    } finally {
      await new Promise<void>((r) => restarted.app.close(() => r()));
    }
  });
});
