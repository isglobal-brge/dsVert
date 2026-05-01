---
name: Feature request
about: Propose a new method, primitive, or capability for dsVert
labels: enhancement
---

## Motivation

<!-- What use-case is currently unsupported? What centralised R
function would you replace with a federated equivalent? Cite the
biomedical / epidemiological setting that needs it. -->

## Proposal

<!-- What method, primitive, or extension do you propose adding?
Sketch the API and the MPC orchestration if known. -->

## Centralised reference

- R function: <e.g. `survival::coxph`, `lme4::glmer`, `MASS::polr`>
- Centralised bound to match: <e.g. max|Δβ| < 1e-3>

## Disclosure profile

- Client view: <list scalar / p-vector aggregates the analyst would see>
- Inter-server leakage: <new tier? if yes, justify; if no, which
  existing tier (Cox sort permutation, LMM cluster ID, etc.)?>
- K=2 path: <yes / no — must be yes for shippable methods>

## Acceptance band target

- [ ] STRICT (max|Δβ| < 1e-3 vs centralised reference)
- [ ] SUB-NOISE (σ-probe ratio ≥ 100× per-fit Wald SE)
- [ ] PRACTICAL (inside a peer-reviewed theoretical floor; cite the bound)

## References

<!-- Papers / textbooks supporting the formal bound, or prior MPC
literature for the primitive. -->
