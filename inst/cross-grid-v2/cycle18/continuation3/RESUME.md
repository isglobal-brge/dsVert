# Cycle18 third continuation — release sequences active; Cox input adapter

Production code 82a0ff0c7fe982f590be2b966b7af2ac4604176e / 4c6c5622fbdc2ae97de315f18c18901d452f3c09; native runtimes unchanged b59d34c.

## Promotion state

Source-verifying07:00:55 UTC harvest: cycle16-r2 LMM n2000/K2 still active,
2553 hashes match; cycle17 GLMM binomial queued,2556 match. Existing sequential
24h total/15min inactivity drivers and isolated transports remain untouched.
The reviewer n2000 milestone is not corroborated by these logs: the completed
oracle marker remains n4 only. At07:00:13 UTC both LMM authorities had213 COMMIT
stages and product000020 running. This is progress only. No completed release
metrics exist to evaluate256,000,000,000 serialized aggregate-RPC bytes/21,600s.
K3/K5/recovery/cold/tamper/full paired gates remain pending; **LMM Promoted=No**.

Cap-source paired e4df243/4c6c562 remains active;2563 hashes match. It excludes
subsequent Cox patches and does not establish current-source or n2000 capacity.
Existing local collectors49135/69790/78671 retain matching command/start
identities; collectors.txt records them. No frozen source/controller modified,
no duplicate release launched and no current evidence attributed to old runs.

## Cox implementation and validation

R/dpCoxGridCrossMaterializer.R adds an internal authenticated snapshot adapter.
It validates the existing signed Cox source context, resolved snapshots/PSI,
dataset identity/version and patient-key ownership. The existing admission
ordering is retained; repeated patients reject. Predictors use exact binary64
rational normalization and the existing rational f50 ties-to-even quantizer,
without intermediate rounded subtraction/division or decimal reconstruction.
Nonbinary events are invalid before clipping. Times remain clipped binary64
owner-local values for the existing private route sidecar; transport blocks
contain only their validity. Padded lanes remain zero, in signed block order.

The final focused run passes18 tests/1020 assertions with no failures, errors,
warnings or skips. Covers K2/K3/K5 owners, actual snapshot/PSI tampering,
dataset substitution, duplicate rejection, missing/invalid values, padding,
exact f50 ties, subnormal numbers, overflow-prone bounds and an independent
Python Fraction binary64 normalization case that differs from naive floating
arithmetic. The first run failed while constructing an intentionally duplicate
PSI fixture; the second expected a Cox error class where the existing PSI
validator rejected earlier. Both retained; corrected tests pass on the final
code. No arithmetic or protocol defect was found.

This adapter produces private source inputs only. Next Cox steps: integrate
producer commitments/sharing/persistence and the time sidecar, then the private
complete-case stage from additive validity lanes, durable R/DP lifecycle and
public signed reader. No Cox release/promotion or capacity is claimed.

GEE estimator/privacy/global-sensitivity scope remains the question in
cycle17/GEE_ALPHA_SCOPE.md. Asked asynchronously again; no answer received at
checkpoint. Do not substitute fixed public rho for estimated alpha.

## Resume commands

```sh
python3 integrator-evidence/cycle16-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle17-20260920/harvest.py --verify-source
python3 integrator-evidence/cycle18-20260920/paired/harvest.py --allow-partial
```

After paired termination, harvest without --allow-partial and review all
RDS/CSV nonpasses. Continue the existing release sequence; do not relaunch.
LMM signed admission/public reader/provenance/garbler fixture and256-candidate
sampler cap fixes remain retained from earlier cycles. These code changes do
not replace measured release gates. No BLOCKED file or tier escalation,
no tags/pushes/thesis edits/simple-family releases.
