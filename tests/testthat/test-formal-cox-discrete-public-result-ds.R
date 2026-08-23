.formal_cox_discrete_public_result_hash <- function(label) {
  digest::digest(label, algo = "sha256", serialize = FALSE)
}

.formal_cox_discrete_public_result_specs <- function() {
  list(primary_discrete = list(
    version = "dsvert-formal-cox-discrete-public-result-spec-v1",
    analysis_id = "primary_discrete", data_name = "study",
    target = "discrete_logit",
    source_formula_sha256 = .formal_cox_discrete_public_result_hash(
      "Surv(time,status) ~ x"),
    model_formula_sha256 = .formal_cox_discrete_public_result_hash(
      "event ~ time_bin + x"),
    time_grid_sha256 = .formal_cox_discrete_public_result_hash(
      "fixed time grid"),
    coefficient_names = c("(Intercept)", "time_bin2", "x"),
    certificate_json = "{}",
    pins = list(site_a = strrep("A", 43L), site_b = strrep("B", 43L))))
}

.formal_cox_discrete_public_result_reply <- function(
    specs = .formal_cox_discrete_public_result_specs()) {
  spec <- specs$primary_discrete
  list(
    version = "dsvert-formal-glm-public-result-v1",
    artifact_id = .formal_cox_discrete_public_result_hash("artifact"),
    certificate_sha256 = .formal_cox_discrete_public_result_hash("certificate"),
    family = "binomial", formula_sha256 = spec$model_formula_sha256,
    coefficients = list(
      list(coefficient = "(Intercept)", signed_steps = "0",
           output_lattice_bits = 20, value = 0),
      list(coefficient = "time_bin2", signed_steps = "262144",
           output_lattice_bits = 20, value = 0.25),
      list(coefficient = "x", signed_steps = "-131072",
           output_lattice_bits = 20, value = -0.125)),
    production_ready = FALSE)
}

test_that("formal discrete-time results are read-only, grid-bound and redacted", {
  specs <- .formal_cox_discrete_public_result_specs()
  withr::local_options(list(
    dsvert.dp.formal_cox_discrete_public_results = specs))
  calls <- 0L
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      calls <<- calls + 1L
      expect_identical(command, "formal-glm-public-result")
      expect_identical(input_data$certificate_json, "{}")
      expect_identical(input_data$pins, specs$primary_discrete$pins)
      expect_false(simplify_output)
      .formal_cox_discrete_public_result_reply(specs)
    },
    .package = "dsVert")
  output <- dsvertFormalCoxDiscretePublicResultDS(
    "primary_discrete", "study",
    specs$primary_discrete$source_formula_sha256)
  expect_identical(calls, 1L)
  expect_setequal(names(output), c(
    "version", "analysis_id", "artifact_id", "certificate_sha256",
    "target", "source_formula_sha256", "model_formula_sha256",
    "time_grid_sha256", "coefficients", "production_ready"))
  expect_identical(output$target, "discrete_logit")
  expect_identical(output$coefficients[[3L]]$signed_steps, "-131072")
  expect_false(output$production_ready)
  forbidden <- c("certificate_json", "pins", "path", "key", "seed")
  expect_false(any(forbidden %in% names(output)))
})

test_that("formal discrete-time selectors, grids and releases fail closed", {
  specs <- .formal_cox_discrete_public_result_specs()
  withr::local_options(list(
    dsvert.dp.formal_cox_discrete_public_results = specs))
  calls <- 0L
  testthat::local_mocked_bindings(
    .callMpcTool = function(...) {
      calls <<- calls + 1L
      .formal_cox_discrete_public_result_reply(specs)
    },
    .package = "dsVert")
  expect_error(dsvertFormalCoxDiscretePublicResultDS(
    "primary_discrete", "other",
    specs$primary_discrete$source_formula_sha256),
    class = "dsvert_formal_cox_discrete_public_error")
  expect_identical(calls, 0L)

  bad_grid <- specs
  bad_grid$primary_discrete$time_grid_sha256 <- "not-a-sha"
  withr::local_options(list(
    dsvert.dp.formal_cox_discrete_public_results = bad_grid))
  expect_error(dsvertFormalCoxDiscretePublicResultDS(
    "primary_discrete", "study",
    specs$primary_discrete$source_formula_sha256),
    class = "dsvert_formal_cox_discrete_public_error")

  withr::local_options(list(
    dsvert.dp.formal_cox_discrete_public_results = specs))
  testthat::local_mocked_bindings(
    .callMpcTool = function(...) {
      result <- .formal_cox_discrete_public_result_reply(specs)
      result$coefficients[[2L]]$coefficient <- "x"
      result
    },
    .package = "dsVert")
  expect_error(dsvertFormalCoxDiscretePublicResultDS(
    "primary_discrete", "study",
    specs$primary_discrete$source_formula_sha256),
    class = "dsvert_formal_cox_discrete_public_error")
})
