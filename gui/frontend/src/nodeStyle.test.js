// Frontend unit test for the two independent visual channels (Issue 5):
// dot = liveness (statusDot), border = risk (riskBorder). Runs with no test
// framework:  node --test src/nodeStyle.test.js  (from gui/frontend).
import { test } from "node:test";
import assert from "node:assert/strict";
import { statusDot, riskBorder } from "./nodeStyle.js";

test("statusDot maps liveness, never risk", () => {
  assert.equal(statusDot("active"), "#22c55e"); // up -> green
  assert.equal(statusDot("online"), "#22c55e");
  assert.equal(statusDot("discovered"), "#9ca3af"); // unconfirmed -> grey
  assert.equal(statusDot("disconnected"), "#ef4444"); // down -> red
  assert.equal(statusDot("down"), "#ef4444");
  assert.equal(statusDot(undefined), "#9ca3af"); // unknown -> grey
});

test("riskBorder maps risk to color + width, independent of liveness", () => {
  assert.deepEqual(riskBorder(9.8), { color: "#dc2626", width: 3 }); // critical
  assert.deepEqual(riskBorder(7.5), { color: "#f97316", width: 2 }); // high
  assert.deepEqual(riskBorder(5.0), { color: "#eab308", width: 2 }); // medium
  assert.deepEqual(riskBorder(0), { color: "#22c55e", width: 1 }); // clean
  assert.deepEqual(riskBorder(null), { color: "#d1d5db", width: 1 }); // unscored
});

test("a healthy-but-vulnerable host reads green dot + red border", () => {
  // CYFOR-1/2/3 etc: status active, risk 9.x -> NOT a dead-looking red dot.
  assert.equal(statusDot("active"), "#22c55e");
  assert.equal(riskBorder(9.8).color, "#dc2626");
});
