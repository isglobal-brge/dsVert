# Contributing to dsVert

Thank you for considering a contribution. dsVert is the server-side
half of a tightly-paired R + Go codebase that implements federated
MPC primitives for vertically partitioned DataSHIELD analyses.
Contributions need to clear three quality bars: **correctness**
(matches centralised R within documented bounds), **non-disclosure**
(no observation-level data ever leaves a server), and
**reviewer-grade hygiene** (`R CMD check` clean, `testthat` green,
`go test` green).

## Repository layout

- `R/` — exported `dsvert*DS` / `k2*DS` / `glmRing63*DS` / `psi*DS`
  aggregate methods and `assign` methods. Hand-maintained `NAMESPACE`
  (do **not** regenerate); add new exports manually.
- `inst/dsvert-mpc/` — Go MPC kernel sources. Compiled per platform
  into `inst/bin/{darwin-amd64,darwin-arm64,linux-amd64,windows-amd64}/`.
- `inst/mhe-tool/` — legacy MHE tool (CKKS); kept for backward-compat.
- `tests/testthat/` — server-side unit tests (K-arity guards,
  contingency, histogram, LMM K=2 enforcement, etc.).

## Workflow

1. **Fork** and create a feature branch off `main`.
2. **Match existing style**: don't reformat adjacent code. New `R/`
   files use `roxygen2` markdown mode (set in `DESCRIPTION`); wrap
   math in `\eqn{}` / `\preformatted{}`, never bare LaTeX macros.
3. **Document every exported argument** — `R CMD check --as-cran`
   gates on this. Use `\code{}` (not bracket-link prose) inside
   markdown roxygen, and use `call(name = "fn", ...)` (the explicit
   `name = ...` form) in client-side `DSI::datashield.aggregate`
   call expressions to avoid the partial-arg-match NOTE.
4. **Run the local validation gate** before pushing:
   ```sh
   bash scripts/quick_impl_check.sh        # ~3 min  (8 L1 probes + go test)
   bash scripts/continuous_validation.sh medium   # ~33 min  (L1 + L2 local-distributed)
   ```
   For a method that ships a new MPC orchestration, add a probe under
   `scripts/probe_<method>.R` and wire it into `continuous_validation.sh`.
5. **R CMD check**:
   ```sh
   R CMD build --no-build-vignettes dsVert
   R CMD check dsVert_*.tar.gz --no-manual --as-cran
   ```
   Acceptance: `Status: 0 ERRORs / 1 WARNING / 0 NOTEs` — the single
   warning is the intentional `inst/bin/{platform}/dsvert-mpc` Go
   runtime binaries, which are unavoidable for the dual-package R + Go
   architecture. **Any new warnings or notes must be addressed**.
6. **`testthat`**: `Rscript -e 'devtools::test()'` — full suite must
   PASS. Add tests for any new method.
7. **Go tests**: `cd inst/dsvert-mpc && go test ./...` — must PASS in
   ~2 s.
8. **Submit a pull request** referencing any related issue. The CI
   workflow (`.github/workflows/R-CMD-check.yaml`) will reproduce the
   above check on a clean Linux runner.

## Disclosure invariants (do not violate)

1. The client must only see p-dimensional aggregate sums, scalar
   deviances / log-likelihoods, coefficient vectors, scalar test
   statistics, or already-agreed-aggregate correlation / histogram
   tables. **No `n`-dimensional vectors ever reconstructed at the
   client.**
2. Beyond the existing Ring63 / Ring127 shares + transport-encrypted
   blobs, permissible new inter-server leakage is restricted to the
   patterns already listed in the disclosure ledger (paper §VI Table
   3): event-time ordering in Cox (sort permutation, not the times),
   cluster-ID membership in LMM / GEE, ascending-time event indicator
   in the Cox K=2 OT-Beaver path. Any new leakage tier requires a
   ledger row + reviewer sign-off.
3. K=2 must work with exactly two servers, both acting as DCF parties.
   No method may require a third party for correctness; dealer
   rotation gracefully degenerates to fixed dealer.
4. No direct server-to-server channels. All inter-server bytes flow
   through `datashield.aggregate` / `datashield.assign` calls via the
   client.

## Acceptance bands

A method is reviewer-shippable in one of three bands:

| Band | Bound | Where it belongs |
|---|---|---|
| STRICT | max\|Δβ\| < 1e-3 vs centralised reference | Paper §V.A row, no caveat |
| SUB-NOISE | σ-probe ratio ≥ 100× the per-fit Wald SE | Paper §V.B row + (H10) sub-noise margin |
| PRACTICAL | Empirical max\|Δβ\| inside a peer-reviewed theoretical floor (Catrina-Saxena fp50, McCullagh-Agresti L1, Bohning, etc.) | Paper §V.A row with formal-bound citation |

Anything below PRACTICAL needs further work before merge.

## Reporting issues

Use the GitHub issue tracker:
<https://github.com/isglobal-brge/dsVert/issues>

For the client-side companion package, see
<https://github.com/isglobal-brge/dsVertClient>.
