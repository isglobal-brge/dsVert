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
