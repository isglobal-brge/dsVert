aggregate_methods_from_description <- function() {
  desc_path <- .dsvert_test_package_file("DESCRIPTION")
  desc <- read.dcf(desc_path)
  trimws(strsplit(desc[1, "AggregateMethods"], ",")[[1]])
}

test_that("legacy ordinal helpers are internal and not remotely exposed", {
  methods <- aggregate_methods_from_description()
  retired <- c(
    "dsvertOrdinalShareClassMasksDS",
    "dsvertOrdinalReceiveClassMaskDS",
    "dsvertOrdinalExtractXColumnDS")
  removed <- c(
    "dsvertOrdinalPatientDiffsDS",
    "dsvertOrdinalSealFkSharesDS",
    "dsvertOrdinalSealEtaDS",
    "dsvertOrdinalReceiveBetaWeightsDS")
  expect_false(any(c(retired, removed) %in% methods))
  expect_false(any(retired %in% getNamespaceExports("dsVert")))
  expect_true(all(vapply(
    retired, exists, logical(1L), envir = asNamespace("dsVert"),
    mode = "function", inherits = FALSE)))
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
    "k2ApplySqrtWeightsDS",
    "k2OtMulSenderSetupDS",
    "k2OtMulReceiverChoicesDS",
    "k2OtMulSenderEncryptDS",
    "k2OtMulReceiverDecryptDS")
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
    "k2OtMulSenderSetupDS",
    "k2OtMulReceiverChoicesDS",
    "k2OtMulSenderEncryptDS",
    "k2OtMulReceiverDecryptDS",
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

test_that("legacy GEE AR1 helpers are internal and not remotely exposed", {
  methods <- aggregate_methods_from_description()

  retired <- c(
    "dsvertGEEAR1OrderBroadcastDS",
    "dsvertGEEAR1OrderReceiveDS",
    "dsvertGEEAR1TransformShareDS")
  expect_false(any(retired %in% methods))
  expect_false(any(retired %in% getNamespaceExports("dsVert")))
  expect_true(all(vapply(
    retired, exists, logical(1L), envir = asNamespace("dsVert"),
    mode = "function", inherits = FALSE)))
})
