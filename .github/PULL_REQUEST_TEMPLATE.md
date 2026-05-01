## Summary

<!-- One paragraph: what does this PR do? -->

## Scope check

- [ ] R CMD check passes (`Status: 0 ERRORs / 0 NOTEs`; the single
      `inst/bin` Go binary WARNING is intentional and acceptable).
- [ ] `testthat` passes — full suite green, new tests added for any
      new method.
- [ ] `go test ./inst/dsvert-mpc/...` passes (if Go sources changed).
- [ ] `bash scripts/quick_impl_check.sh` passes (8/8 L1 + go).
- [ ] If the change touches federated estimators,
      `bash scripts/continuous_validation.sh medium` passes.
- [ ] Roxygen docs cover every new exported argument; markdown
      bracket-link traps avoided (`\code{}` for inline code, no bare
      `[token]`); `call(name = "fn", ...)` style preserved.
- [ ] Hand-maintained `NAMESPACE` updated explicitly (do not regenerate).

## Disclosure check

- [ ] No new observation-level reveal at the client.
- [ ] No new inter-server leakage tier beyond the disclosure ledger
      (paper §VI Table 3); if a new tier IS added, this PR includes
      the ledger row + the rationale.
- [ ] K=2 path works (the change doesn't require ≥ 3 servers).

## Validation evidence

| Method | max\|Δβ\| | Reference | Acceptance band |
|---|---|---|---|
| <method> | <e.g. 8.09e-05> | <`survival::coxph`> | STRICT / SUB-NOISE / PRACTICAL |

## Related

Closes #<issue>.
