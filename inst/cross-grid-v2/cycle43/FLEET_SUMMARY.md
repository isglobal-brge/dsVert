# HEAVY release results

Collected 2/12 ready job results: 1 PASS, 1 FAIL.

Server `502b0058cd4b804b0e7adbba0e4c71485c755989`; client `4c6c5622fbdc2ae97de315f18c18901d452f3c09`. Exact committed archives; packaged binary and harness hashes verified. One real release per pod; 86400s maximum / 900s idle leases; private state `/var/lib/dsvert-heavy-state/<job>`.

| Family | ε | K | Mode | Pod | Oracle | Recovery | Cold | Tamper | Native bytes | RPC bytes | Release s | Wall s | Result |
|---|---:|---:|---|---|---|---|---|---|---|---:|---:|---:|---|
| binomial_glmm | 8 | 2 | recovery | pod16 | not verified | not verified | not verified | not verified | unavailable | unavailable | unavailable | 795.7 | FAIL |
| lmm | 8 | 5 | baseline | pod22 | PASS | not requested | PASS | PASS | {"exact_gc_unique_payload_bytes": 8838064187, "exact_gc_offered_payload_bytes": 8838064187, "source_ciphertext_delivered_bytes": 4573950} | 24036925468 | 22774.59 | 23070.63 | PASS |

Failures before the final oracle/lifecycle checks leave those checks unverified; they do not establish an oracle mismatch. Missing native/RPC measurements are unavailable, not zero. Wall seconds measure the whole harness invocation. The uniform capacity ceilings are 256,000,000,000 serialized-RPC bytes and 28,800 release seconds (2026-09-20 decision; retained measurements re-scored without rerunning).

- `binomial_glmm-e8-k2-i01-recovery`: Discrete-Gaussian plan unavailable: fixed-work Gaussian table is outside certified support. [Log](logs/binomial_glmm-e8-k2-i01-recovery/remote-logs/binomial_glmm-e8-k2-i01-recovery.log)

Nine new CPU-only pods, each 32 vCPU / 64 GB at $0.96/hour ($8.64/hour total, storage additional), plus reused idle pod12/14/15. Pod11/13 were occupied by prior work at dispatch. Pods and private state remain allocated for review. See [fleet inventory](FLEET.md) and [audit](artifacts/fleet-audit.json).

Pod4 was read-only. No project code, manifest, integrator status, thesis, GEE worktree, or frozen LMM changes. No pushes or tags. The state-path override is recorded alongside each exact manifest CLI in RESULTS.jsonl.

The manifest changed after dispatch. 12 currently ready entries name a replacement commit pair; this batch provides evidence only for the original pair above. See [manifest provenance check](artifacts/manifest-provenance-check.json).
