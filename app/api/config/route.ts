import { NextResponse } from "next/server";

// Ported from server.js `GET /api/config`. Default community string used to
// pre-fill the Scan Configuration UI. Overridable via DEFAULT_COMMUNITY.
const DEFAULT_COMMUNITY = process.env.DEFAULT_COMMUNITY || "cyfor123";

export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json({ community: DEFAULT_COMMUNITY });
}
