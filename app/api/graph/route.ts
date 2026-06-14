import { NextResponse } from "next/server";
import fs from "fs";
import path from "path";

// Ported from server.js `GET /api/graph`. The graph is NEVER bundled — it is
// read fresh from disk on every request so the same static file the scanner
// writes is the single source of truth. process.cwd() is the Next.js project
// (repo) root, which holds graph.json.
const GRAPH_PATH = process.env.GRAPH_PATH || path.join(process.cwd(), "graph.json");

export const dynamic = "force-dynamic";

export function GET() {
  let data: string;
  try {
    data = fs.readFileSync(GRAPH_PATH, "utf-8");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { error: `Could not read graph at ${GRAPH_PATH}: ${msg}` },
      { status: 404 },
    );
  }
  try {
    return NextResponse.json(JSON.parse(data));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return NextResponse.json(
      { error: `graph.json is not valid JSON: ${msg}` },
      { status: 500 },
    );
  }
}
