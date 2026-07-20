// k6 latency-budget suite (spec §4.1).
//
// Assertions:
//   - Deterministic tier (secrets in-process + PII HTTP): p95 < 30 ms on 4K
//     payloads. Because the M1 build runs the PII detector over HTTP, this
//     really measures gateway-overhead + secrets-scan + one HTTP hop.
//
// Fails the k6 run — and therefore any CI job that shells out to it — when
// the threshold is breached. Wire from `deploy/k6/latency_gate.sh` for the
// GA hardening CI gate.
//
// Run:
//   k6 run deploy/k6/latency_budgets.js
//
// Env:
//   GUARDX_GATEWAY_URL       default http://localhost:8081
//   GUARDX_APP               default claims-bot
//   GUARDX_LATENCY_P95_MS    default 30 (spec §4.1 deterministic-tier target)
import http from "k6/http";
import { check } from "k6";

const BASE   = __ENV.GUARDX_GATEWAY_URL || "http://localhost:8081";
const APP    = __ENV.GUARDX_APP || "claims-bot";
const TARGET = Number(__ENV.GUARDX_LATENCY_P95_MS || 30);

// 4 KB filler payload — clean prose (no matches), matching the spec assumption.
const filler = "The claims system continues normal operation across the region. ".repeat(64);

export const options = {
  scenarios: {
    deterministic: {
      executor: "constant-vus",
      vus: 10,
      duration: "20s",
    },
  },
  thresholds: {
    // abortOnFail turns any breach into a non-zero k6 exit code — the CI
    // gate script relies on this to fail the build.
    "http_req_duration{scenario:deterministic}": [
      { threshold: `p(95)<${TARGET}`, abortOnFail: true },
    ],
    "checks{scenario:deterministic}": [
      { threshold: "rate>0.99", abortOnFail: true },
    ],
  },
};

export default function () {
  const body = JSON.stringify({
    app: APP,
    direction: "output",
    text: filler,
  });
  const res = http.post(`${BASE}/v1/guard/check`, body, {
    headers: { "content-type": "application/json" },
    tags: { scenario: "deterministic" },
  });
  check(res, { "guard/check 200": (r) => r.status === 200 });
}
