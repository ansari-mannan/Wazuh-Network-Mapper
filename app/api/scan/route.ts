import { NextRequest, NextResponse } from "next/server";
import fs from "fs";
import path from "path";
import { spawn } from "child_process";
import { getScan, setScan } from "@/lib/scanState";

// Ported from server.js `POST /api/scan`. Spawns the Python pipeline and writes
// its stdout to graph.json. The actual work runs async; we respond 202 and the
// frontend polls /api/scan/status.
const GRAPH_PATH = process.env.GRAPH_PATH || path.join(process.cwd(), "graph.json");
const DEFAULT_COMMUNITY = process.env.DEFAULT_COMMUNITY || "cyfor123";
// `python3` is the documented binary, but Windows ships it as `python`; pick a
// sensible per-platform default and let PYTHON_BIN override it.
const PYTHON_BIN =
  process.env.PYTHON_BIN || (process.platform === "win32" ? "python" : "python3");

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  if (getScan().status === "running") {
    return NextResponse.json(
      { status: "running", error: "a scan is already running" },
      { status: 409 },
    );
  }

  // Body is optional; default the community if not provided.
  let community = DEFAULT_COMMUNITY;
  try {
    const body = await req.json();
    if (body && typeof body.community === "string" && body.community) {
      community = body.community;
    }
  } catch {
    // No/invalid JSON body — fall back to the default community.
  }

  setScan({
    status: "running",
    error: null,
    startedAt: new Date().toISOString(),
    finishedAt: null,
  });

  // No shell: args are passed as an array, so the community string can't break
  // out into a second command (basic safety even though hardening is out of scope).
  const args = ["-m", "vulnmapper", "--community", community];
  let child;
  try {
    child = spawn(PYTHON_BIN, args, { cwd: process.cwd() });
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    setScan({
      ...getScan(),
      status: "error",
      error: `failed to start ${PYTHON_BIN}: ${msg}`,
      finishedAt: new Date().toISOString(),
    });
    return NextResponse.json({ status: "error", error: getScan().error }, { status: 202 });
  }

  const chunks: Buffer[] = [];
  let stderr = "";
  child.stdout.on("data", (d: Buffer) => chunks.push(d));
  child.stderr.on("data", (d: Buffer) => (stderr += d.toString()));

  child.on("error", (e: Error) => {
    // Fires when the binary itself can't be launched (e.g. python not installed).
    setScan({
      ...getScan(),
      status: "error",
      error: `failed to start ${PYTHON_BIN}: ${e.message}`,
      finishedAt: new Date().toISOString(),
    });
  });

  child.on("close", (code: number) => {
    if (getScan().status === "error") return; // spawn error already recorded
    const out = Buffer.concat(chunks);
    if (code === 0 && out.length) {
      try {
        JSON.parse(out.toString()); // validate before overwriting the good file
        fs.writeFileSync(GRAPH_PATH, out);
        setScan({
          ...getScan(),
          status: "done",
          error: null,
          finishedAt: new Date().toISOString(),
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setScan({
          ...getScan(),
          status: "error",
          error: `scanner output was not valid JSON: ${msg}`,
          finishedAt: new Date().toISOString(),
        });
      }
    } else {
      setScan({
        ...getScan(),
        status: "error",
        error: stderr.trim() || `scanner exited with code ${code}`,
        finishedAt: new Date().toISOString(),
      });
    }
  });

  // Started response — the UI polls /api/scan/status from here.
  return NextResponse.json({ status: "running" }, { status: 202 });
}
