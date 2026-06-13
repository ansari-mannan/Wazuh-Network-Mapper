/**
 * vulnmapper GUI backend (POC dev tool).
 *
 * Three responsibilities:
 *   GET  /api/graph        -> read graph.json fresh from disk and return it.
 *   POST /api/scan         -> spawn the Python pipeline, write stdout to graph.json.
 *   GET  /api/scan/status  -> poll the async scan (idle|running|done|error).
 *   GET  /api/config       -> default community string to pre-fill the UI.
 *
 * The graph is NEVER bundled into the frontend — it is always read live from
 * GRAPH_PATH so the same static file the scanner writes is the single source.
 */
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import { spawn } from "child_process";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// gui/backend -> repo root (two levels up) holds the scanner + graph.json.
const REPO_ROOT = path.resolve(__dirname, "..", "..");

const PORT = process.env.PORT || 3001;
const GRAPH_PATH = process.env.GRAPH_PATH || path.join(REPO_ROOT, "graph.json");
const DEFAULT_COMMUNITY = process.env.DEFAULT_COMMUNITY || "cyfor123";
// `python3` is the documented binary, but Windows ships it as `python`; pick a
// sensible per-platform default and let PYTHON_BIN override it.
const PYTHON_BIN =
  process.env.PYTHON_BIN || (process.platform === "win32" ? "python" : "python3");

const app = express();
app.use(cors());
app.use(express.json());

// In-memory scan state. A POC runs one scan at a time, so a single object is
// enough; a real deployment would key this by job id.
let scan = { status: "idle", error: null, startedAt: null, finishedAt: null };

app.get("/api/config", (_req, res) => {
  res.json({ community: DEFAULT_COMMUNITY });
});

app.get("/api/graph", (_req, res) => {
  fs.readFile(GRAPH_PATH, "utf-8", (err, data) => {
    if (err) {
      return res
        .status(404)
        .json({ error: `Could not read graph at ${GRAPH_PATH}: ${err.message}` });
    }
    try {
      res.json(JSON.parse(data));
    } catch (e) {
      res.status(500).json({ error: `graph.json is not valid JSON: ${e.message}` });
    }
  });
});

app.get("/api/scan/status", (_req, res) => res.json(scan));

app.post("/api/scan", (req, res) => {
  if (scan.status === "running") {
    return res.status(409).json({ status: "running", error: "a scan is already running" });
  }
  const community = (req.body && req.body.community) || DEFAULT_COMMUNITY;
  scan = { status: "running", error: null, startedAt: new Date().toISOString(), finishedAt: null };

  // No shell: args are passed as an array, so the community string can't break
  // out into a second command (basic safety even though hardening is out of scope).
  const args = ["-m", "vulnmapper", "--community", community];
  let child;
  try {
    child = spawn(PYTHON_BIN, args, { cwd: REPO_ROOT });
  } catch (e) {
    scan = { ...scan, status: "error", error: `failed to start ${PYTHON_BIN}: ${e.message}`, finishedAt: new Date().toISOString() };
    return res.status(202).json({ status: "error", error: scan.error });
  }

  const chunks = [];
  let stderr = "";
  child.stdout.on("data", (d) => chunks.push(d));
  child.stderr.on("data", (d) => (stderr += d.toString()));

  child.on("error", (e) => {
    // Fires when the binary itself can't be launched (e.g. python not installed).
    scan = { ...scan, status: "error", error: `failed to start ${PYTHON_BIN}: ${e.message}`, finishedAt: new Date().toISOString() };
  });

  child.on("close", (code) => {
    if (scan.status === "error") return; // spawn error already recorded
    const out = Buffer.concat(chunks);
    if (code === 0 && out.length) {
      try {
        JSON.parse(out.toString()); // validate before overwriting the good file
        fs.writeFileSync(GRAPH_PATH, out);
        scan = { ...scan, status: "done", error: null, finishedAt: new Date().toISOString() };
      } catch (e) {
        scan = { ...scan, status: "error", error: `scanner output was not valid JSON: ${e.message}`, finishedAt: new Date().toISOString() };
      }
    } else {
      scan = {
        ...scan,
        status: "error",
        error: stderr.trim() || `scanner exited with code ${code}`,
        finishedAt: new Date().toISOString(),
      };
    }
  });

  // Started response — the UI polls /api/scan/status from here.
  res.status(202).json({ status: "running" });
});

app.listen(PORT, () => {
  console.log(`vulnmapper GUI backend -> http://localhost:${PORT}`);
  console.log(`  graph path : ${GRAPH_PATH}`);
  console.log(`  python bin : ${PYTHON_BIN}  (cwd ${REPO_ROOT})`);
});
