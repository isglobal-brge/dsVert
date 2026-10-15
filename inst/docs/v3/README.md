# dsVert v3: fixed-path DP Newton/IRLS (prototype)

Implementation records for the design in [isglobal-brge/dsVert#26](https://github.com/isglobal-brge/dsVert/issues/26).

- **Status:** experimental prototype on branch `feature/v3-dp-irls`, development version 1.5.0.9000. It is not
  promoted and not on `main`.
- **Release status:** existing grids, Synopsis artifacts and the 1.4.2 surface are unchanged.

| Document | Contents |
|---|---|
| `DESIGN_V3_DP_IRLS.md` | Phase A implementation design: backend, path integrity, release identity, contract, sensitivity, inference, validation, milestones |
| `claude-session-review-phaseA.md` | The maintainer session's review and five binding additions |
| `CONSENSUS_V3_DP_IRLS.md`, `claude-review-v3impl01-r1.md`, `-r2.md` | Records of the earlier review rounds |
| `B1_REPORT.md`, `B1_QUESTIONS.md`, `B1_CONTRACT_SCHEMA.md`, `B1_ARITHMETIC_ABI.md` | B1: signed contract, stage identities, exact accounting, exact rational update (Go) with an independent R/gmp verifier |
| `claude-session-review-B1.md` | B1 review |
| `B2_REPORT.md`, `B2_QUESTIONS.md` | B2: fused public-point score/curvature exact-GC producer, numeric certificate, exactness and sensitivity witnesses |
| `claude-session-review-B2.md` | B2 review |
| `B3_QUESTIONS.md`, `B3_STATUS.md` | B3: selector-only R/DSI lifecycle, mandatory two-lane noise, dual-signed publication, the cost gate and the end-to-end proof of concept |

**Proof-of-concept result.** It is in dsVertClient, `inst/validation/v1.5.0-poc/` on the same branch:
- binomial, two custodians, n = 64, ε = 8;
- three signed releases in 1,219 s;
- inference correctly refused at this n.
