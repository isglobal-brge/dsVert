# dsVert (development version)

### Beaver preprocessing

* Added `dsvertBeaverPolicyDS()` so DataSHIELD administrators can expose an
  explicit Beaver preprocessing policy: efficient dealer mode, IKNP
  OT-extension mode, or both.
* Added relayable semi-honest IKNP OT-extension commands as the strengthened
  Beaver preprocessing backend, with rebuilt `dsvert-mpc` binaries for all
  packaged platforms.
* Domain-separated IKNP extension seeds so client-side orchestrators can reuse
  a base-OT transcript safely across multiple multiplication batches without
  reusing PRG pads.
* Kept dealer preprocessing as a product backend for governed institutional
  peer deployments and removed the historical direct-OT helpers from the
  registered `AggregateMethods` surface.

### Cleanup

* Removed archived `inst/k2-mpc-tool` research sources and generated package
  tarballs from version control. The maintained Go runtime is
  `inst/dsvert-mpc`; shipped binaries remain under `inst/bin/`.
* Documented the production DataSHIELD surface as the `AggregateMethods` /
  `AssignMethods` list in `DESCRIPTION`. Disclosive or suboptimal historical
  helpers are removed from the invocable server surface.
* Strengthened the product-surface disclosure test so debug reveal helpers,
  patient-level ordinal/NB legacy helpers, plaintext weight helpers, and Cox
  rank primitives remain out of `AggregateMethods`, out of `NAMESPACE`
  exports, and absent from the package namespace.
* Removed archived server code for debug share reveal, Cox rank/Newton/Path-B,
  plaintext DCF weights, disclosive NB eta transport, and ordinal
  patient-level reconstruction.

## dsVert 1.1.0

Server-side primitives for the v2.0 federated method stack. Companion
release to dsVertClient 1.1.0.

### New aggregate methods

* **Cox K=2** discrete-time non-disclosive primitives — `dsvertCoxDiscreteShareMaskDS`,
  `dsvertCoxDiscreteReceiveSharesDS`, and assign-time
  `dsvertCoxDiscreteExpandXDS` for the Allison 1982 / Andreux 2020
  pooled-logistic equivalence with K=2-safe share-mask gating
  (Aliasgari-Blanton 2013 NDSS).
* **NB regression** — full profile-MLE digamma chain
  (`dsvertNBProfileSumsDS`, `dsvertNBMomentSumsDS`,
  `dsvertNBEtaShareDS`, `dsvertNBEtaTotalReceiveDS`,
  `dsvertNBSumShareDS`, `dsvertNBPsiAggregateDS`) supporting iid-mu,
  Method-of-Moments, and non-disclosive full-regression theta estimators with
  the Ring127 NR-LOG
  share-domain primitive (Goldschmidt 1964 + Pugh 2004).
* **Multinomial joint Newton** — `dsvertPrepareMultinomGradDS`,
  `dsvertSoftmaxDenominatorDS`, `dsvertOneHotDS`,
  `dsvertComputeResidualShareDS` for the K-1 stacked Bohning-bounded
  Newton path (paper §V.A row).
* **Ordinal joint PO Newton** — `dsvertOrdinalShareClassMasksDS`,
  `dsvertOrdinalReceiveClassMaskDS`, and `dsvertOrdinalExtractXColumnDS`
  for strict class-mask/share-domain orchestration without the historical
  patient-level reconstruction path.
* **LMM (random intercept + slopes)** —
  `dsvertCluster{Sizes,Residuals}DS`, `dsvertExpandClusterWeightsDS`,
  `dsvertClusterZtZDS`, `dsvertLMMPeerFittedShareDS`,
  `dsvertLMMCoordResidualShareDS`, `dsvertLMMPeerResidualFinaliseDS`,
  `dsvertLMMExactClusterR2DS`, `dsvertLMM{Broadcast,Receive}ClusterIDsDS`,
  `dsvertLMM{Per,Global}SumDS`, `dsvertLMMGLS{Transform,Aggregates}DS`,
  `dsvertLMMLocalGramDS`, `dsvertLMMReceiveGramSharesDS`,
  `dsvertLMM{R1,R2}DS` for the Laird-Ware GLS closed form with
  Pinheiro-Bates §2.4.2 within-between ANOVA variance components.
* **LMM K=3** — `dsvertLMMVarianceComponentsDS` +
  `dsvertLMMXCovarianceWithinDS` for the K=3 sigma^2 / sigma_b^2
  recovery with Var_within(X β) correction.
* **Beaver vecmul Ring63 / Ring127 stack** —
  `k2BeaverVecmul{GenTriples,ConsumeTriple,R1,R2}DS`,
  `k2Beaver{ShareVector,ReceiveVector,ExtractColumn,SumShare}DS`,
  `k2Ring127{AffineCombine,LocalScale}DS`. Underpins the joint Newton,
  Cox Path B, LMM Gram, and chi-square primitives.
* **Histogram + descriptive aggregates** — `dsvertHistogramDS`,
  `dsvertLocalMomentsDS`, `dsvertContingencyDS` for the v2 descriptive /
  contingency table API.
* **PSI / IPW / chi-sq** — `psi*DS` family extended;
  `dsvertOneHotDS`, `dsvertImputeColumnDS`, `dsvertPearsonR2ColDS`,
  `k2CrossOneHotCountsDS` for two-way contingency Beaver dot products.

### Changes

* Cox now defaults to `ring = 127L` (5/5 STRICT on Pima synthetic at
  ~2× speedup vs Ring63).
* `glmStandardizeDS` gains a `mode = "x_only" | "full"` switch.
* `glmRing63ReorderXFullDS` reorders the fusion party's X to the
  canonical `(coord | fusion | extras)` ordering.
* `mpcStoreTransportKeysDS` and `psiStoreTransportKeysDS` gain
  base64url JSON variants for chunked-blob relay through DataSHIELD.

### Documentation / quality

* Rd warnings cleared: bracket-link traps, loose LaTeX-macro escapes,
  `Lost braces`, `Missing link` cross-refs all eliminated.
* Auto-generated @param entries replaced with descriptive prose
  for 102+ previously-undocumented arguments.
* Non-ASCII characters in R sources replaced with ASCII equivalents
  (R CMD check `code files for non-ASCII characters` clean).
* LICENSE switched to DCF stub; full MIT text retained in `LICENSE.md`.
* `.Rbuildignore` excludes Go-source dirs and vignette caches; the
  per-platform compiled binaries under `inst/bin/{darwin,linux,windows}-*`
  ship intentionally.

### Testing

* 88 server-side `testthat` checks (K-arity guards, contingency,
  histogram, LMM K=2 enforce). All PASS.
* Go tests (`dsvert-mpc`) — full suite passes in ~2 s.

## dsVert 1.0.0

Initial public release: K=2 GLM (Gaussian / Binomial / Poisson),
correlation, and PCA via Ring63 Beaver MPC + DCF wide-spline link
functions, with ECDH-PSI record alignment.
