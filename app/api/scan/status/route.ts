import { NextResponse } from "next/server";
import { getScan } from "@/lib/scanState";

// Ported from server.js `GET /api/scan/status`. Returns the module-level scan
// state object: { status, error, startedAt, finishedAt }.
export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json(getScan());
}
