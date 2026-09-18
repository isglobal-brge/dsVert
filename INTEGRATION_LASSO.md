# LASSO cross-owner integration

The isolated family entry is `.dsvert_dp_lasso_cross_register()` in both packages.
It returns `spec`, `validate_contract`, `base_descriptor`, `postprocess`, and the
required state markers and `nonlinear_arithmetic_required`. `production_release_enabled=FALSE` is intentional: a
signed descriptor does not establish that MPC or joint DP noise ran. The new
client `dp_lasso_grid()` accepts owner-qualified covariates and authenticates the
two-custodian GLM contract, then fails closed before release. No existing route
or same-owner LASSO implementation was changed.

Exact wiring remaining:

1. Register this descriptor in the Step 2 fused producer/client registry. Build
   binomial/Poisson base contracts from the **unique**, canonical beta rows;
   require its certified piecewise-polynomial producer (Day 1 decision), with
   signed profile tables, rounding, certificate and approximation-aware caps;
   multiple public lambdas can reuse one already released base coordinate.
2. Authenticate the ABI-preserving certified-profile base contract, signed schema, two compute/noise
   custodians and private PSI alignment using Step 2. Pass its validated
   descriptor through `.dsvert_dp_lasso_cross_base(base_contract, policy)`.
   Supply Step 2's authoritative profile validator as the internal
   `.base_validator` argument. The default validator only knows the frozen
   Step-1 staging contract; its old q64 profile is not a production fallback.
3. For Gaussian, run the **existing** cross-owner Gaussian manifest/artifact and
   certificate validators. Pass the authenticated artifact to
   `.dsvert_dp_lasso_cross_base(artifact, policy, "gaussian")`. Supply this adapter
   as the internal `.base_validator` argument to LASSO contract validation. The
   default base validator intentionally rejects Gaussian: no self-asserted
   Gaussian artifact, signature-only object or fake moment vector is accepted
   by a production public entry point.
4. Validate the LASSO extension using `validate_contract(value, policy,
   schema_manifest, base_contract)`. It reconstructs every public penalty,
   candidate association and copied sensitivity and checks signatures from
   exactly the two custodians. Bind the extension hash to the signed sticky
   semantic query, receipt and public result provenance. It must not cause the
   same base semantic release to be noised again when only its public penalty
   postprocessing changes.
5. Complete the existing authenticated source/result, two-authority noise and
   sticky release gates. Only then invoke `postprocess(coordinates, spec)` with
   the authenticated common-lattice DP vector. A state marker or
   `result_evidence_required=TRUE` is not execution evidence.
6. Add `export(dp_lasso_grid)` together with the authoritative public method
   inventory/status registration after producer promotion. The staging entry
   currently remains namespace-internal. Replace the final fail-closed call in `dp_lasso_grid()` with that authenticated
   orchestration. Do not add a caller-provided plaintext/noisy-vector argument,
   environment-variable bypass or test-reference fallback. Translate normalized
   coefficients using the signed predictor/outcome ranges when returning
   original-scale coefficients; the current internal result deliberately labels
   them `normalized_paths`.

The Gaussian coordinate order is the existing count, upper-triangular XTX in
column-major order, XTy in design order, yty. Its first count coordinate is never
a denominator: all objectives use public capacity N. Gaussian candidates use
normalized y/x and the glmnet convention `RSS/(2N) + lambda * slope_L1`.
Binomial/Poisson candidates use `NLL/N + lambda * slope_L1`. Selection is per
signed lambda, with first-in-canonical-order tie breaking. No optimizer, standard
errors or new protected-data access is introduced.

Synthetic fixtures are in `tests/testthat/helper-lasso-cross.R` in both packages.
`.lasso_cross_fixture(family, capacity, bits, beta_grid)` supplies real Ed25519
GLM signatures and the public Gaussian artifact shape. The Gaussian fixture is
checked against the existing client artifact validator. These helpers are test
code and carry no production execution evidence. The family DSLite harness and
tagged plaintext-reference audit are tracked by the parent family session.

The Family A tagged DSLite campaign distinguishes arithmetic from runtime
integration coverage. Binomial/Poisson reference cases still use the frozen
Step 1 oracle while their piecewise producer is developed in parallel. Gaussian
cases exercise the existing moment arithmetic and client artifact validation;
their two-peer synthetic staging uses the common NB signed schema/contract
fixture. It does not establish authenticated Gaussian server-manifest/session
coverage. Completing that existing manifest/session adapter remains item 3
above and is explicitly marked in each Gaussian result record.
