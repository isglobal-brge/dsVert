# Layer 2 — nonlinear component only

Status: tested Boolean probe; fused secure grid and R lifecycle NOT COMPLETE.

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
