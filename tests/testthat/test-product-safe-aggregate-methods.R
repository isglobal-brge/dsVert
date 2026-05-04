aggregate_methods_from_description <- function() {
  candidates <- c("DESCRIPTION", "../../DESCRIPTION",
                  system.file("DESCRIPTION", package = "dsVert"))
  desc_path <- candidates[file.exists(candidates)][1L]
  if (is.na(desc_path) || !nzchar(desc_path)) {
    stop("Could not locate dsVert DESCRIPTION", call. = FALSE)
  }
  desc <- read.dcf(desc_path)
  trimws(strsplit(desc[1, "AggregateMethods"], ",")[[1]])
}

test_that("DataSHIELD AggregateMethods expose safe ordinal helpers only", {
  methods <- aggregate_methods_from_description()

  expect_true("dsvertOrdinalShareClassMasksDS" %in% methods)
  expect_true("dsvertOrdinalReceiveClassMaskDS" %in% methods)

  blocked <- c(
    "dsvertOrdinalPatientDiffsDS",
    "dsvertOrdinalSealFkSharesDS",
    "dsvertOrdinalSealEtaDS",
    "dsvertOrdinalReceiveBetaWeightsDS")
  expect_false(any(blocked %in% methods))
})

test_that("debug and patient-level legacy helpers are not product-exposed", {
  methods <- aggregate_methods_from_description()

  blocked <- c(
    "dsvertDebugRevealDS",
    "dsvertDebugSnapshotDS",
    "dsvertNBEtaSealDS",
    "dsvertNBFullScoreDS",
    "k2SetWeightsDS",
    "k2ReceiveWeightsDS",
    "k2ApplyWeightsDS",
    "k2ApplySqrtWeightsDS")
  expect_false(any(blocked %in% methods))
})

test_that("debug and patient-level helpers are not namespace-exported", {
  exports <- getNamespaceExports("dsVert")

  blocked <- c(
    "dsvertDebugRevealDS",
    "dsvertDebugSnapshotDS",
    "dsvertOrdinalPatientDiffsDS",
    "dsvertOrdinalSealFkSharesDS",
    "dsvertOrdinalSealEtaDS",
    "dsvertOrdinalReceiveBetaWeightsDS",
    "dsvertNBEtaSealDS",
    "dsvertNBFullScoreDS",
    "k2SetWeightsDS",
    "k2ReceiveWeightsDS",
    "k2ApplyWeightsDS",
    "k2ApplySqrtWeightsDS",
    "k2SetCoxTimesDS",
    "k2ReceiveCoxMetaDS",
    "k2ApplyCoxPermutationDS",
    "k2CoxReverseCumsumSDS",
    "k2CoxForwardCumsumGDS",
    "k2StoreCoxRecipDS",
    "k2CoxPrepareRecipPhaseDS",
    "k2CoxResidualDS",
    "k2CoxSaveMuDS",
    "k2CoxFinaliseResidualDS",
    "k2CoxPrepareLogSPhaseDS",
    "k2CoxPartialLogLikAggregateDS",
    "dsvertCoxNewtonPrepDS",
    "dsvertCoxNewtonGradDS",
    "dsvertCoxNewtonLoadPairDS",
    "dsvertCoxNewtonFisherScalarDS",
    "dsvertCoxPathBCumsumDS",
    "dsvertCoxPathBScalarDS",
    "dsvertCoxPathBCopyDS",
    "dsvertCoxTVStrataDS")
  expect_false(any(blocked %in% exports))
})

test_that("discarded unsafe helpers are removed from the namespace", {
  ns <- asNamespace("dsVert")
  removed <- c(
    "dsvertDebugRevealDS",
    "dsvertDebugSnapshotDS",
    "dsvertOrdinalPatientDiffsDS",
    "dsvertOrdinalSealFkSharesDS",
    "dsvertOrdinalSealEtaDS",
    "dsvertOrdinalReceiveBetaWeightsDS",
    "dsvertNBEtaSealDS",
    "dsvertNBFullScoreDS",
    "k2SetWeightsDS",
    "k2ReceiveWeightsDS",
    "k2ApplyWeightsDS",
    "k2ApplySqrtWeightsDS",
    "k2SetCoxTimesDS",
    "k2ReceiveCoxMetaDS",
    "k2ApplyCoxPermutationDS",
    "k2CoxReverseCumsumSDS",
    "k2CoxForwardCumsumGDS",
    "k2StoreCoxRecipDS",
    "k2CoxPrepareRecipPhaseDS",
    "k2CoxResidualDS",
    "k2CoxSaveMuDS",
    "k2CoxFinaliseResidualDS",
    "k2CoxPrepareLogSPhaseDS",
    "k2CoxPartialLogLikAggregateDS",
    "dsvertCoxNewtonPrepDS",
    "dsvertCoxNewtonGradDS",
    "dsvertCoxNewtonLoadPairDS",
    "dsvertCoxNewtonFisherScalarDS",
    "dsvertCoxPathBCumsumDS",
    "dsvertCoxPathBScalarDS",
    "dsvertCoxPathBCopyDS",
    "dsvertCoxTVStrataDS")
  present <- vapply(removed, exists, logical(1), envir = ns, inherits = FALSE)
  expect_false(any(present), info = paste(names(present)[present], collapse = ", "))
})

test_that("legacy Cox rank AggregateMethods are not product-exposed", {
  methods <- aggregate_methods_from_description()

  blocked <- c(
    "k2SetCoxTimesDS",
    "k2ReceiveCoxMetaDS",
    "k2ApplyCoxPermutationDS",
    "k2CoxReverseCumsumSDS",
    "k2CoxForwardCumsumGDS",
    "k2StoreCoxRecipDS",
    "k2CoxPrepareRecipPhaseDS",
    "k2CoxResidualDS",
    "k2CoxSaveMuDS",
    "k2CoxFinaliseResidualDS",
    "k2CoxPrepareLogSPhaseDS",
    "k2CoxPartialLogLikAggregateDS",
    "dsvertCoxNewtonPrepDS",
    "dsvertCoxNewtonGradDS",
    "dsvertCoxNewtonLoadPairDS",
    "dsvertCoxNewtonFisherScalarDS",
    "dsvertCoxPathBCumsumDS",
    "dsvertCoxPathBScalarDS",
    "dsvertCoxPathBCopyDS",
    "dsvertCoxTVStrataDS")
  expect_false(any(blocked %in% methods))
})

test_that("Gaussian GEE AR1 exposes only guarded order-share helpers", {
  methods <- aggregate_methods_from_description()

  expected <- c(
    "dsvertGEEAR1OrderBroadcastDS",
    "dsvertGEEAR1OrderReceiveDS",
    "dsvertGEEAR1TransformShareDS")
  expect_true(all(expected %in% methods))
})
