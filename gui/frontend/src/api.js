// Thin /api/* client. The browser never reads files or holds a bundled graph —
// everything comes through the Express backend (proxied by Vite in dev).

async function asJson(res) {
  const body = await res.json().catch(() => ({}));
  if (!res.ok && res.status !== 202) {
    throw new Error(body.error || `${res.status} ${res.statusText}`);
  }
  return body;
}

export function getConfig() {
  return fetch("/api/config").then(asJson);
}

export function getGraph() {
  return fetch("/api/graph").then(asJson);
}

export function startScan(community) {
  return fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ community }),
  }).then(asJson);
}

export function getScanStatus() {
  return fetch("/api/scan/status").then(asJson);
}
