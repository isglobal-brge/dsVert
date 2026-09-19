# Revised Cox family envelope

Final admitted family-kernel rectangle: **N <= 4000, J <= 50**. The measured
4000x50 run completed in **52,962,304,383 bytes and 5663.674 seconds**
(52.962 GB, 94.395 minutes), with every coordinate equal to the integer oracle.

**Matrix complete: 9/9 recorded.** Six complete runs pass both resource limits
and oracle equality; all three 10000-row probes stop at the traffic budget.
The deterministic summary selects 4000x50 (maximum passing N*J, then N).
See `inst/cross-cox-v1/envelope_v2/summary.json` for report hashes and selection.

This replaces the superseded blocked-gate report. Production remains disabled
pending the authenticated step-2 wiring in [INTEGRATION_COX.md](INTEGRATION_COX.md).

| Public N | Grid J | Padded rows | Measured bytes | Total seconds | Result |
| ---: | ---: | ---: | ---: | ---: | --- |
| 2000 | 16 | 2048 | 8,472,921,669 | 1298.420 | Complete; oracle equal |
| 2000 | 32 | 2048 | 16,943,647,939 | 2355.695 | Complete; oracle equal |
| 2000 | 50 | 2048 | 26,473,265,394 | 2940.744 | Complete; oracle equal |
| 4000 | 16 | 4096 | 16,951,184,064 | 1846.358 | Complete; oracle equal |
| 4000 | 32 | 4096 | 33,897,588,865 | 4061.319 | Complete; oracle equal |
| 4000 | 50 | 4096 | 52,962,304,383 | 5663.674 | Complete; oracle equal |
| 10000 | 16 | 16384 | 59,999,957,516 | 5279.340 | 60 GB cutoff; incomplete |
| 10000 | 32 | 16384 | 59,999,969,168 | 5412.021 | 60 GB cutoff; incomplete |
| 10000 | 50 | 16384 | 59,999,962,098 | 4737.815 | 60 GB cutoff; incomplete |

The cutoff rows record successfully transmitted bytes before the next record
would exceed 60,000,000,000 bytes. They are resource-censored observations, not
completed releases or full-vector oracle-equality results. No extrapolated total
is substituted for a measurement.

## Scope and reproduction

The entire family kernel is measured: one packed permutation, all padded exp/log
batches, share additions, private Breslow tie selection, finalizers and receipts.
Both encrypted directions and cold circuit compilation are included. The two
peers run via net.Pipe on the pod; source/PSI authentication, Ring64-to-Ring128
conversion inside authenticated fusion, joint-DP sampling, sticky publication
and two-host RTT are excluded. Step 2 must fit those costs into the remaining
**7,037,695,617 bytes and 1536.326 seconds** before production promotion.

Raw reports, source hashes, binary hashes, host details and test logs are under
`inst/cross-cox-v1/envelope_v2/`. The pod exposes 96 CPUs but has a 7.65-core
cgroup quota shared with other lanes. At most two GOMAXPROCS=2 probes run at once.
For example, from the pod family directory after compiling the test binary:

```sh
DSVERT_COX_ENVELOPE=1 DSVERT_COX_N=4000 DSVERT_COX_J=50 \
DSVERT_COX_REPORT=report.json GOMAXPROCS=2 \
./cox-shared.test -test.run='^TestCoxGridCrossSharedEnvelope$'
```

The full launcher and deterministic admission summary are in
`inst/cross-cox-v1/run_shared_envelope_v2.sh` and
`inst/cross-cox-v1/summarize_shared_envelope_v2.py`.

## Enforcement and validation

Both R packages rebuild signed `resource_admission` metadata and reject excess
rows/candidates even with both valid signatures. Registered Go SharedPlan,
SharedCompile and RunShares enforce the same limit before protected use.
Original runner limits remain; exp/log batches additionally stay below 5000
non-XOR gates per row, and finalizers below 4096 gates (99-case observed max 877).
Numeric error, sensitivity, epsilon/delta and loss caps are unchanged.

Final Cox tests: **24 Go tests + 7 subtests; 641 server and 77 client R expectations**.
The client count includes 23 tagged two-peer DSLite expectations at epsilon 1,4,8
against the pure-R integer oracle and pooled survival::coxph. Reference-noise
utility results are also retained in `inst/cross-cox-v1/utility_dslite_mac.json`;
they are not a production joint-DP protocol claim.

Both full R CMD checks ran. Client: 25,425 passes and three pre-existing WARNING
categories. Server: 13,279 passes, 17 failures, 2 WARNINGs and 1 NOTE; every
failure was reproduced against independently installed primitive baseline 38146c0.
No Cox test failed. The signed-admission/layout additions were checked afterward
with the final targeted counts above. [STATUS_COX.md](STATUS_COX.md) records commands,
commits and the paired baseline evidence.
