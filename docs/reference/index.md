# Package index

## All functions

- [`base64_to_base64url()`](https://isglobal-brge.github.io/dsVert/reference/base64_to_base64url.md)
  : Convert standard base64 to base64url

- [`cox-newton`](https://isglobal-brge.github.io/dsVert/reference/cox-newton.md)
  : Cox one-step Newton at beta = 0 (bias-free)

- [`cox-path-b`](https://isglobal-brge.github.io/dsVert/reference/cox-path-b.md)
  : Cox Path B: iterative Newton with Fisher(beta_k) via Beaver

- [`dsvertAddClusterColumnDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertAddClusterColumnDS.md)
  : Append a deterministic cluster column (aggregate, test helper)

- [`dsvertAddQuartileColumnDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertAddQuartileColumnDS.md)
  : Append an age-quartile factor column (test helper)

- [`dsvertAddSyntheticSurvivalDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertAddSyntheticSurvivalDS.md)
  : Append synthetic exponential time + binary event columns (test
  helper)

- [`dsvertClusterResidualsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertClusterResidualsDS.md)
  : Per-cluster residual sums for LMM REML updates

- [`dsvertClusterSizesDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertClusterSizesDS.md)
  : Cluster-size aggregate (for LMM / GEE)

- [`dsvertClusterZtZDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertClusterZtZDS.md)
  : Per-cluster Z^T Z matrices for LMM random slopes

- [`dsvertColNamesDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertColNamesDS.md)
  : List column names of a server-side data frame

- [`dsvertComputeResidualShareDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertComputeResidualShareDS.md)
  : Compute residual share r = y_ind - p on outcome server

- [`dsvertContingencyDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertContingencyDS.md)
  : Server-side 2-way contingency table (aggregate)

- [`dsvertCopyDfDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCopyDfDS.md)
  : Copy a data frame to a new name (test helper)

- [`dsvertCoxDiscreteExpandXDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxDiscreteExpandXDS.md)
  : Expand local covariates to uniform Jxn person-period frame

- [`dsvertCoxDiscreteReceiveSharesDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxDiscreteReceiveSharesDS.md)
  : Cox K=2 discrete-time receive shared mask + y at NL

- [`dsvertCoxDiscreteShareMaskDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxDiscreteShareMaskDS.md)
  : Cox K=2 discrete-time non-disclosive share-mask primitives (#D')

- [`dsvertCoxNewtonFisherScalarDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxNewtonFisherScalarDS.md)
  : Compute scalar share of Fisher term (after Beaver round 2)

- [`dsvertCoxNewtonGradDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxNewtonGradDS.md)
  : Return the p_total-vector grad(0) scalar share

- [`dsvertCoxNewtonLoadPairDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxNewtonLoadPairDS.md)
  : Seed and prepare for the per-pair Beaver vecmul round

- [`dsvertCoxNewtonPrepDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxNewtonPrepDS.md)
  : Cox-Newton prep: extract+cumsum all columns and build plaintext
  weights

- [`dsvertCoxPathBCopyDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxPathBCopyDS.md)
  : Copy a session slot to another slot (alias helper for the Beaver
  plumbing)

- [`dsvertCoxPathBCumsumDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxPathBCumsumDS.md)
  : Generic strata-aware cumulative sum on an FP share vector

- [`dsvertCoxPathBScalarDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxPathBScalarDS.md)
  : Compute scalar share of Sum_i w_i \* share(i) where w is plaintext
  at both parties

- [`dsvertCoxTVStrataDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertCoxTVStrataDS.md)
  : Build a combined stratum column from tstart + optional base strata

- [`dsvertExpandClusterWeightsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertExpandClusterWeightsDS.md)
  : Expand a per-cluster weights vector into a per-patient column

- [`dsvertHistogramDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertHistogramDS.md)
  : Server-side histogram bucket counts (aggregate)

- [`dsvertIdentityPkDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertIdentityPkDS.md)
  : Query this server's identity public key

- [`dsvertImputeColumnDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertImputeColumnDS.md)
  : Server-side Bayesian-ridge imputation of a single column

- [`dsvertInjectNADS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertInjectNADS.md)
  : Inject missing values into a column (aggregate, test helper)

- [`dsvertLMMBroadcastClusterIDsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMBroadcastClusterIDsDS.md)
  : Broadcast per-patient cluster IDs to the peer (LMM exact)

- [`dsvertLMMCoordResidualShareDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMCoordResidualShareDS.md)
  : LMM cross-server exact residual pipeline – coordinator side

- [`dsvertLMMExactClusterR2DS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMExactClusterR2DS.md)
  : LMM cross-server exact: per-cluster r^2 aggregate

- [`dsvertLMMGLSAggregatesDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMGLSAggregatesDS.md)
  : Aggregate sums weighted by (1 - lambda_i) for LMM GLS intercept

- [`dsvertLMMGLSTransformDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMGLSTransformDS.md)
  : Cluster-mean-center columns for random-intercept GLS (LMM)

- [`dsvertLMMGlobalSumDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMGlobalSumDS.md)
  : Global FP sum of a session share vector (LMM exact)

- [`dsvertLMMGramR1DS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMGramR1DS.md)
  : LMM closed-form GLS: Beaver dot product of two shared columns

- [`dsvertLMMLocalGramDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMLocalGramDS.md)
  : LMM closed-form GLS: local Gram blocks + share transformed columns

- [`dsvertLMMPeerFittedShareDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMPeerFittedShareDS.md)
  : LMM cross-server exact residual pipeline – peer side

- [`dsvertLMMPeerResidualFinaliseDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMPeerResidualFinaliseDS.md)
  : LMM cross-server exact: peer-side residual slot finaliser

- [`dsvertLMMPerClusterSumDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMPerClusterSumDS.md)
  : Per-cluster FP sum of a session share vector (LMM exact)

- [`dsvertLMMReceiveClusterIDsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMReceiveClusterIDsDS.md)
  : Receive + store peer's cluster IDs (LMM exact)

- [`dsvertLMMReceiveGramSharesDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMReceiveGramSharesDS.md)
  : LMM closed-form GLS: receive peer's column shares

- [`dsvertLMMVarianceComponentsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMVarianceComponentsDS.md)
  : Cluster ANOVA moments for LMM K=3 variance-component recovery

- [`dsvertLMMXCovarianceWithinDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMXCovarianceWithinDS.md)
  : Within-cluster X covariance for LMM K=3 sigma^2 X-correction

- [`dsvertLocalMomentsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertLocalMomentsDS.md)
  : Server-side local descriptive moments (aggregate)

- [`dsvertNBEtaSealDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBEtaSealDS.md)
  : Per-patient mu seal on non-label server for NB full-reg theta MLE

- [`dsvertNBEtaShareConfirmDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBEtaShareConfirmDS.md)
  : NL-side mirror: pin NL's eta_total share + cache n

- [`dsvertNBEtaShareDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBEtaShareDS.md)
  : NL-side: split eta^nl into Ring127 additive shares

- [`dsvertNBEtaTotalReceiveDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBEtaTotalReceiveDS.md)
  : Label-side: receive NL's eta^nl share + assemble eta_total share

- [`dsvertNBFullScoreDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBFullScoreDS.md)
  : Full-regression theta-MLE score on label server (per-patient mu)

- [`dsvertNBMomentSumsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBMomentSumsDS.md)
  : NB Method-of-Moments aggregate sufficient statistics

- [`dsvertNBProfileSumsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBProfileSumsDS.md)
  : NB profile-MLE score sums for dispersion theta (aggregate)

- [`dsvertNBPsiAggregateDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBPsiAggregateDS.md)
  : Label-side: plaintext Sumpsi(y+theta) and Sumpsi_1(y+theta)

- [`dsvertNBSumShareDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBSumShareDS.md)
  : Both-side: scalar share sum reveal helper

- [`dsvertNBYThetaShareDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBYThetaShareDS.md)
  : Label-side: re-share (y + theta) into Ring127 additive shares

- [`dsvertNBYThetaShareReceiveDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNBYThetaShareReceiveDS.md)
  : NL-side: receive (y + theta) share blob + store under canonical key

- [`dsvertNaOmitDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertNaOmitDS.md)
  : Remove rows with NAs in specified columns (per-server,
  non-disclosive)

- [`dsvertOneHotDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertOneHotDS.md)
  : One-hot encode a categorical variable (server-side aggregate)

- [`dsvertOrdinalExtractXColumnDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertOrdinalExtractXColumnDS.md)
  : Extract column j of an nxp Ring127 share matrix into n-vector slot

- [`dsvertOrdinalReceiveBetaWeightsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertOrdinalReceiveBetaWeightsDS.md)
  : Receive transport-encrypted W (beta-Hessian weight) share

- [`dsvertOrdinalSealEtaDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertOrdinalSealEtaDS.md)
  : Seal non-label eta^nl vector for outcome-server reveal

- [`dsvertOrdinalSealFkSharesDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertOrdinalSealFkSharesDS.md)
  : Seal F_k shares for inter-server reveal to outcome server

- [`dsvertOutcomeLevelsDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertOutcomeLevelsDS.md)
  : List ordered factor levels of an outcome column

- [`dsvertPearsonR2ColDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertPearsonR2ColDS.md)
  : Materialise r^2 as a column on the outcome server (GEE sandwich
  prep)

- [`dsvertPrepareMultinomGradDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertPrepareMultinomGradDS.md)
  :

  Prepare softmax-gradient inputs by copying shares into the canonical
  `secure_mu_share` / `k2_y_share_fp` slots

- [`dsvertResetDataFrameDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertResetDataFrameDS.md)
  : Remove dsVert-internal columns from the aligned data frame

- [`dsvertSoftmaxDenominatorDS()`](https://isglobal-brge.github.io/dsVert/reference/dsvertSoftmaxDenominatorDS.md)
  : Sum K-1 exp(eta_k) shares + party-0 constant 1 -\> denominator share

- [`getObsCountDS()`](https://isglobal-brge.github.io/dsVert/reference/getObsCountDS.md)
  : Get Observation Count (Server-Side)

- [`glm-ring63-protocol`](https://isglobal-brge.github.io/dsVert/reference/glm-ring63-protocol.md)
  : Ring63 DCF + Beaver Gradient Server Functions for K\>=3

- [`glmRing63CorSetColDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63CorSetColDS.md)
  : Set column j of X_full as "mu" for Beaver correlation Extracts
  column col_idx from k2_x_full_fp, stores as secure_mu_share. Combined
  with zero y, the "residual" = col_j, and Beaver computes X^T x col_j.

- [`glmRing63CorSetZeroYDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63CorSetZeroYDS.md)
  : Set y_share to zeros (for correlation: no response variable)

- [`glmRing63DevianceSumsDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63DevianceSumsDS.md)
  : Compute scalar sums for canonical deviance

- [`glmRing63ExportOwnShareDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63ExportOwnShareDS.md)
  : Export own share (complement) to second DCF party

- [`glmRing63GenDcfKeysDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63GenDcfKeysDS.md)
  : Generate DCF keys on server and distribute to DCF parties

- [`glmRing63GenGradTriplesDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63GenGradTriplesDS.md)
  : Generate gradient matvec Beaver triples on server and distribute

- [`glmRing63GenSplineTriplesDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63GenSplineTriplesDS.md)
  : Generate spline Beaver triples on server and distribute to DCF
  parties

- [`glmRing63PrepDevianceDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63PrepDevianceDS.md)
  : Prepare deviance: store residual as 1-column X matrix for Beaver
  Sumr^2

- [`glmRing63ReceiveExtraShareDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63ReceiveExtraShareDS.md)
  : Receive and assemble extra feature shares from non-DCF servers

- [`glmRing63ReorderXFullDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63ReorderXFullDS.md)
  : Reorder X_full columns to canonical order on fusion party

- [`glmRing63TransportInitDS()`](https://isglobal-brge.github.io/dsVert/reference/glmRing63TransportInitDS.md)
  : Initialize transport keys with Ed25519 identity

- [`glmStandardizeDS()`](https://isglobal-brge.github.io/dsVert/reference/glmStandardizeDS.md)
  : Standardize Features for GLM (Server-Side)

- [`k2-input-sharing`](https://isglobal-brge.github.io/dsVert/reference/k2-input-sharing.md)
  : K=2 Input-Sharing + Gradient (ALL in FixedPoint Ring63)

- [`k2-wide-spline`](https://isglobal-brge.github.io/dsVert/reference/k2-wide-spline.md)
  : K=2 DCF Wide Spline (4-Phase Sigmoid/Exp)

- [`k2ApplyCoxPermutationDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ApplyCoxPermutationDS.md)
  : Apply the Cox sort permutation to this server's X share

- [`k2ApplyWeightsDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ApplyWeightsDS.md)
  : Apply registered weights to the current mu and y shares

- [`k2BeaverExtractColumnDS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverExtractColumnDS.md)
  : Extract a single column from a row-major n-by-K FP vector

- [`k2BeaverReceiveVectorDS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverReceiveVectorDS.md)
  : Receive a shared FP vector and store under a session key

- [`k2BeaverShareVectorDS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverShareVectorDS.md)
  : Share a session FP vector with the peer (additive 2-party split)

- [`k2BeaverSumShareDS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverSumShareDS.md)
  : Sum an FP share vector to a scalar share

- [`k2BeaverVecmulConsumeTripleDS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulConsumeTripleDS.md)
  : Consume a relayed Beaver vecmul triple

- [`k2BeaverVecmulGenTriplesDS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulGenTriplesDS.md)
  : Generate n-length Beaver triples for element-wise Ring63 product

- [`k2BeaverVecmulR1DS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulR1DS.md)
  : Beaver vecmul round 1

- [`k2BeaverVecmulR2DS()`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulR2DS.md)
  : Beaver vecmul round 2

- [`k2ClearOffsetDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ClearOffsetDS.md)
  : Clear a registered offset for a session (server-side)

- [`k2ClearWeightsDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ClearWeightsDS.md)
  : Clear registered weights from a session

- [`k2ComputeEtaShareDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ComputeEtaShareDS.md)
  : Compute eta share in FixedPoint from full data shares and public
  beta

- [`k2CoxFinaliseResidualDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CoxFinaliseResidualDS.md)
  :

  Cox residual finalisation: r = delta - mu*G (party 0) / -mu*G (party
  1)

- [`k2CoxForwardCumsumGDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CoxForwardCumsumGDS.md)
  :

  Compute the forward cumsum
  `G_j = sum over i<=j with delta=1 of recip(i)`

- [`k2CoxPartialLogLikAggregateDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CoxPartialLogLikAggregateDS.md)
  : Cox partial-log-likelihood aggregate

- [`k2CoxPrepareLogSPhaseDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CoxPrepareLogSPhaseDS.md)
  : Prepare the DCF log phase for the Cox S -\> logS step

- [`k2CoxPrepareRecipPhaseDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CoxPrepareRecipPhaseDS.md)
  : Prepare the DCF reciprocal phase for the Cox 1/S step

- [`k2CoxReverseCumsumSDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CoxReverseCumsumSDS.md)
  : Cox-gradient second-term computation using reverse/forward cumsums

- [`k2CoxSaveMuDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CoxSaveMuDS.md)
  : Cox save-mu helper (copy mu share before DCF reciprocal overwrites
  it)

- [`k2CrossOneHotCountsDS()`](https://isglobal-brge.github.io/dsVert/reference/k2CrossOneHotCountsDS.md)
  : Beaver K x L contingency counts across DCF parties

- [`k2GradientR1DS()`](https://isglobal-brge.github.io/dsVert/reference/k2GradientR1DS.md)
  : Gradient round 1: compute (X-A, r-B) in selected ring (Ring63 /
  Ring127)

- [`k2GradientR2DS()`](https://isglobal-brge.github.io/dsVert/reference/k2GradientR2DS.md)
  : Gradient round 2: compute gradient share from Beaver formula

- [`k2IdentityLinkDS()`](https://isglobal-brge.github.io/dsVert/reference/k2IdentityLinkDS.md)
  : Identity link: set mu = eta (for Gaussian GLM)

- [`k2ReceiveCoxMetaDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ReceiveCoxMetaDS.md)
  : Receive Cox permutation and event indicator on the peer server

- [`k2ReceiveShareDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ReceiveShareDS.md)
  : Receive peer's shared data (FixedPoint)

- [`k2ReceiveWeightsDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ReceiveWeightsDS.md)
  : Receive observation weights from the DCF peer (non-outcome side)

- [`k2Ring127AffineCombineDS()`](https://isglobal-brge.github.io/dsVert/reference/k2Ring127AffineCombineDS.md)
  : Ring127 affine combine – server-side local op for Horner/NR
  orchestration.

- [`k2SetCoxTimesDS()`](https://isglobal-brge.github.io/dsVert/reference/k2SetCoxTimesDS.md)
  : Register Cox survival times and sort the cohort (outcome server,
  stratified)

- [`k2SetOffsetDS()`](https://isglobal-brge.github.io/dsVert/reference/k2SetOffsetDS.md)
  : Register an offset column for an open GLM session (server-side)

- [`k2SetWeightsDS()`](https://isglobal-brge.github.io/dsVert/reference/k2SetWeightsDS.md)
  : Register observation weights for an open GLM session (outcome-side)

- [`k2ShareInputDS()`](https://isglobal-brge.github.io/dsVert/reference/k2ShareInputDS.md)
  : Share local data with peer (FixedPoint shares)

- [`k2StoreCoxRecipDS()`](https://isglobal-brge.github.io/dsVert/reference/k2StoreCoxRecipDS.md)
  : Cache the reciprocal-of-S share returned by the DCF-reciprocal pass

- [`k2StoreDcfKeysPersistentDS()`](https://isglobal-brge.github.io/dsVert/reference/k2StoreDcfKeysPersistentDS.md)
  : Store DCF keys persistently (reused across iterations)

- [`k2StoreGradTripleDS()`](https://isglobal-brge.github.io/dsVert/reference/k2StoreGradTripleDS.md)
  : Store gradient Beaver triple (Ring63 FP format)

- [`k2WideSplinePhase1DS()`](https://isglobal-brge.github.io/dsVert/reference/k2WideSplinePhase1DS.md)
  : Wide spline Phase 1: DCF masked values

- [`k2WideSplinePhase2DS()`](https://isglobal-brge.github.io/dsVert/reference/k2WideSplinePhase2DS.md)
  : Wide spline Phase 2: DCF close + Beaver R1 for AND and Hadamard-1

- [`k2WideSplinePhase3DS()`](https://isglobal-brge.github.io/dsVert/reference/k2WideSplinePhase3DS.md)
  : Wide spline Phase 3: Close AND+Had1, generate Had2 R1

- [`k2WideSplinePhase4DS()`](https://isglobal-brge.github.io/dsVert/reference/k2WideSplinePhase4DS.md)
  : Wide spline Phase 4: Close Had2 + assemble mu shares

- [`localCorDS()`](https://isglobal-brge.github.io/dsVert/reference/localCorDS.md)
  : Local Correlation (Server-Side)

- [`mpcAvailable()`](https://isglobal-brge.github.io/dsVert/reference/mpcAvailable.md)
  : Check if MPC binary is available

- [`mpcCleanupDS()`](https://isglobal-brge.github.io/dsVert/reference/mpcCleanupDS.md)
  : Clean up session state

- [`mpcGcDS()`](https://isglobal-brge.github.io/dsVert/reference/mpcGcDS.md)
  : Force garbage collection on the server

- [`mpcStoreBlobDS()`](https://isglobal-brge.github.io/dsVert/reference/mpcStoreBlobDS.md)
  : Store a blob on server (adaptive chunking support)

- [`mpcStoreTransportKeysDS()`](https://isglobal-brge.github.io/dsVert/reference/mpcStoreTransportKeysDS.md)
  : Store peer transport public keys (with identity verification)

- [`mpcVersion()`](https://isglobal-brge.github.io/dsVert/reference/mpcVersion.md)
  : Get MPC tool version

- [`nb-full-reg-share`](https://isglobal-brge.github.io/dsVert/reference/nb-full-reg-share.md)
  : Non-disclosive K=2 share-domain primitives for NB full-reg theta MLE

- [`psi-protocol`](https://isglobal-brge.github.io/dsVert/reference/psi-protocol.md)
  : ECDH-PSI Record Alignment - Server-Side Functions (Blind Relay)

- [`psiDoubleMaskDS()`](https://isglobal-brge.github.io/dsVert/reference/psiDoubleMaskDS.md)
  : Double-mask target points using stored scalar (aggregate function)

- [`psiExportMaskedDS()`](https://isglobal-brge.github.io/dsVert/reference/psiExportMaskedDS.md)
  : Export encrypted masked points for a target server (aggregate
  function)

- [`psiFilterCommonDS()`](https://isglobal-brge.github.io/dsVert/reference/psiFilterCommonDS.md)
  : Filter aligned data to common intersection (assign function)

- [`psiGetMatchedIndicesDS()`](https://isglobal-brge.github.io/dsVert/reference/psiGetMatchedIndicesDS.md)
  : Get matched reference indices (aggregate function)

- [`psiInitDS()`](https://isglobal-brge.github.io/dsVert/reference/psiInitDS.md)
  : Initialize PSI transport keys (aggregate function)

- [`psiMaskIdsDS()`](https://isglobal-brge.github.io/dsVert/reference/psiMaskIdsDS.md)
  : Mask identifiers using ECDH (aggregate function)

- [`psiMatchAndAlignDS()`](https://isglobal-brge.github.io/dsVert/reference/psiMatchAndAlignDS.md)
  : Match and align data using PSI result (assign function)

- [`psiProcessTargetDS()`](https://isglobal-brge.github.io/dsVert/reference/psiProcessTargetDS.md)
  : Process reference points on target server (aggregate function)

- [`psiSelfAlignDS()`](https://isglobal-brge.github.io/dsVert/reference/psiSelfAlignDS.md)
  : Self-align reference server data (assign function)

- [`psiStoreTransportKeysDS()`](https://isglobal-brge.github.io/dsVert/reference/psiStoreTransportKeysDS.md)
  : Store peer transport public keys (aggregate function)

- [`session-management`](https://isglobal-brge.github.io/dsVert/reference/session-management.md)
  : Session Management
