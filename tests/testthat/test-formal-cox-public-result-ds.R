.formal_cox_public_result_hash <- function(label) {
  digest::digest(label, algo = "sha256", serialize = FALSE)
}

.formal_cox_public_result_specs <- function() {
  list(primary_cox = list(
    version = "dsvert-formal-cox-public-result-spec-v1",
    analysis_id = "primary_cox", data_name = "study",
    formula_sha256 = .formal_cox_public_result_hash("Surv(time,status) ~ x"),
    coefficient_names = c("x", "z"), certificate_json = "{}",
    pins = list(site_a = strrep("A", 43L), site_b = strrep("B", 43L))))
}

.formal_cox_public_result_reply <- function(specs =
                                               .formal_cox_public_result_specs()) {
  spec <- specs$primary_cox
  list(
    version = "dsvert-formal-cox-public-result-v1",
    artifact_id = .formal_cox_public_result_hash("artifact"),
    certificate_sha256 = .formal_cox_public_result_hash("certificate"),
    valid = TRUE,
    coefficients = list(
      list(index = 0L, beta_steps = "64", fraction_bits = 8L,
           beta = 0.25, hazard_ratio_lower = 1.28,
           hazard_ratio_upper = 1.29, hazard_ratio_midpoint = 1.285),
      list(index = 1L, beta_steps = "-32", fraction_bits = 8L,
           beta = -0.125, hazard_ratio_lower = 0.88,
           hazard_ratio_upper = 0.89, hazard_ratio_midpoint = 0.885)),
    production_ready = FALSE)
}

test_that("formal public Cox results are read-only, bounded and redacted", {
  specs <- .formal_cox_public_result_specs()
  withr::local_options(list(dsvert.dp.formal_cox_public_results = specs))
  calls <- 0L
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      calls <<- calls + 1L
      expect_identical(command, "formal-cox-public-result")
      expect_identical(input_data$certificate_json, "{}")
      expect_identical(input_data$pins, specs$primary_cox$pins)
      expect_false(simplify_output)
      .formal_cox_public_result_reply(specs)
    },
    .package = "dsVert")
  output <- dsvertFormalCoxPublicResultDS(
    "primary_cox", "study", specs$primary_cox$formula_sha256)
  expect_identical(calls, 1L)
  expect_setequal(names(output), c(
    "version", "analysis_id", "artifact_id", "certificate_sha256",
    "formula_sha256", "coefficients", "production_ready"))
  expect_identical(output$coefficients[[2L]]$coefficient, "z")
  expect_identical(output$coefficients[[2L]]$beta_steps, "-32")
  expect_false(output$production_ready)
  forbidden <- c("certificate_json", "pins", "path", "key", "seed")
  expect_false(any(forbidden %in% names(output)))
})

test_that("formal public Cox selectors and malformed releases fail closed", {
  specs <- .formal_cox_public_result_specs()
  withr::local_options(list(dsvert.dp.formal_cox_public_results = specs))
  calls <- 0L
  testthat::local_mocked_bindings(
    .callMpcTool = function(...) {
      calls <<- calls + 1L
      .formal_cox_public_result_reply(specs)
    },
    .package = "dsVert")
  expect_error(dsvertFormalCoxPublicResultDS(
    "primary_cox", "other", specs$primary_cox$formula_sha256),
    class = "dsvert_formal_cox_public_error")
  expect_identical(calls, 0L)

  testthat::local_mocked_bindings(
    .callMpcTool = function(...) {
      result <- .formal_cox_public_result_reply(specs)
      result$coefficients[[1L]]$hazard_ratio_midpoint <- 2
      result
    },
    .package = "dsVert")
  expect_error(dsvertFormalCoxPublicResultDS(
    "primary_cox", "study", specs$primary_cox$formula_sha256),
    class = "dsvert_formal_cox_public_error")
})
