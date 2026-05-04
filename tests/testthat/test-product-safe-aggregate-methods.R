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
    "dsvertOrdinalReceiveBetaWeightsDS")
  expect_false(any(blocked %in% methods))
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
