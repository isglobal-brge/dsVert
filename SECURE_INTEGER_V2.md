# Layer 2 — fused arithmetic; authenticated lifecycle remains open

Status: internal fused kernel and joint-noise composition tested; signed
producer, authenticated R lifecycle and production release NOT COMPLETE.

## Initial component probe (historical)

`cross_grid_profile_v2_test.go` builds test-only quadratic circuits. Exact
comparisons cover interval endpoints, both sides of every internal breakpoint,
random additive share splits, random output masks, random valid inputs,
maximum uint32 and one-past-domain inputs. Invalid-domain inputs produce zero
and a false validity flag in this TEST interface. Production needs private
validity handling and cannot expose this interface to an analyst.

`cross_grid_profile_protocol_v2_test.go` runs the actual Yao/KOS garbling and
OT code, over authenticated encrypted record framing on net.Pipe. Four K=64
family/domain combinations, each with four boundary/interior/invalid values,
match the big.Int profile oracle. Only synthetic public fixture inputs are used.
The test protocol context is explicitly test-only, not server-minted admission.
Random protocol framing produces small byte-count variations; transcript
invariance for the eventual protected kernel has not been established.

The local test-only constant-folding pass preserves XOR/AND/OR/INV truth tables,
shares identical expressions, and removes dead gates. All 65,536 uint8 input
pairs agree with the unoptimized test circuit. Profile comparisons additionally
exercise the resulting circuits. Existing production compiler settings and
circuits are unchanged.

Not covered: complete f100 multi-owner dot product, private complete-case and
alignment masks, bounded outcome/log-factorial lookup, loss clamp/sums,
joint-DP noise inside MPC, source/result signatures, admission/materialization,
sticky release identity, exactly-once injection, replay/tamper or crash/resume
through two direct callr server processes. Therefore this is not completion of
Layer 2 or permission to promote materialized state.

## Range-reduced and batched component update

`cross_grid_exp_reduced_v2_test.go` adds exact comparisons against the independent
big.Int oracle for all 1611 public vectors and out-of-domain signed32 inputs.
`cross_grid_exp_reduced_protocol_v2_test.go` runs both peers in-process with
batch sizes 1/32, both legacy and opt-in compact framing, and valid/invalid
synthetic batches. `cross_grid_binomial_batch_v2_test.go` applies the same
32-evaluation transport to the unchanged certified binomial polynomial.
These TEST interfaces reveal a validity bit; they remain unsuitable as the
production protected kernel, which needs private masking and release evidence.

The compact framing implementation binds every public gate operation/wire,
input bit geometry and output width into the authenticated context. A real
mismatched-topology exchange fails at context negotiation before input OT.
Tests establish that legacy mode retains exactly its prior context digest;
existing protocol and encrypted-record replay/tamper tests remain green.
No production caller selects compact framing. The shared-core change only
factors the two old entry functions through an opt-in mode, retaining old
row-length framing in every existing route.

Mac targeted command:

```
go test -run '^(TestCrossGridExpReducedV2|TestCrossGridBinomialV2BatchProtocol$|TestExactGCProtocolEndToEnd$|TestExactGCProtocolFreshArithmeticShares$|TestExactGCSecureRecords)' -json -count=1
```

Passes 14 top-level / 32 including-subtest tests, zero failed/skipped. Evidence:
`inst/cross-grid-v2/exp-reduced-targeted.jsonl`. This does not cover the direct
callr lifecycle, signed grid admission, joint noise, source injection or crash
recovery listed as outstanding above.

Final pod verification reproduces the Mac's 14 top-level / 32 including-subtest
passes, zero failed/skipped. Raw log:
`inst/cross-grid-v2/pod-exp-reduced/exp-reduced-targeted.jsonl`.
All 464 source/fixture hashes were checked against the Mac manifest before
accepting this run. This does not change the outstanding Layer-2 lifecycle gate.

## Fused producer and actual joint-noise composition

The new typed internal producer derives exact f100 partial predictor shares
locally, then privately validates source/alignment, rounds the shared predictor
once, evaluates both pinned profiles, assembles bounded-outcome losses and
reduces clamped coordinates. Only Ring128 additive output masks and one private
XOR alignment-validity bit leave the circuit. It has no R/DSI RPC, and the
ordinary exact-GC compiler explicitly rejects its operation.

The final focused Mac and pod selection passes 18 top-level tests / 36 including subtests,
zero failures/skips. It includes shared R/Go fixtures, randomized source cases,
malformed source/plan rejection, private alignment failure, purpose binding,
caller-mutation isolation, generic-admission exclusion, real encrypted net.Pipe
comparisons and existing encrypted-record replay/tamper tests. Two tests pass
actual kernel shares to the existing joint-vector Laplace MPC sampler at
(epsilon=4, delta=2^-100), matching its seeded oracle and final clamp exactly.
Raw evidence: `inst/cross-grid-v2/fused-targeted-{mac,pod}.jsonl`.
All 467 final source/module/fixture hashes match the pod export. The final
selection includes signed half-tie/adjacent-point and full endpoint/slack
regressions; the earlier 17/35 selection preceded that final addition.

These tests do NOT supply signed new-profile admission, source-claim binding,
recipient-specific durable output evidence, sticky release keys, exactly-once
injection or crash/resume. None of the required two-process callr lifecycle or
12 DSLite API releases has been executed. Record-level replay protection does
not replace those lifecycle tests. The cost gate also remains a separate gate;
passing integer equality does not authorize a production materialized state.
