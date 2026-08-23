.formal_glm_public_result_hash <- function(label) {
  digest::digest(label, algo = "sha256", serialize = FALSE)
}

.formal_glm_public_result_specs <- function() {
  formula <- .dsvert_formal_glm_frontdoor_formula("y ~ x")
  list(primary_logit = list(
    version = "dsvert-formal-glm-public-result-spec-v1",
    analysis_id = "primary_logit", data_name = "study", family = "binomial",
    formula_sha256 = formula$sha256, certificate_json = "{}",
    pins = list(site_a = strrep("A", 43L), site_b = strrep("B", 43L))))
}

.formal_glm_public_result_reply <- function(specs =
                                               .formal_glm_public_result_specs()) {
  spec <- specs$primary_logit
  list(
    version = "dsvert-formal-glm-public-result-v1",
    artifact_id = .formal_glm_public_result_hash("artifact"),
    certificate_sha256 = .formal_glm_public_result_hash("certificate"),
    family = spec$family, formula_sha256 = spec$formula_sha256,
    coefficients = list(
      list(coefficient = "(Intercept)", signed_steps = "524288",
           output_lattice_bits = 20, value = 0.5),
      list(coefficient = "x", signed_steps = "-262144",
           output_lattice_bits = 20, value = -0.25)),
    production_ready = FALSE)
}

test_that("completed formal-model result readers are remotely exported", {
  exports <- getNamespaceExports("dsVert")
  expect_true(all(c(
    "dsvertFormalGLMPublicResultDS",
    "dsvertFormalCoxPublicResultDS",
    "dsvertFormalCoxDiscretePublicResultDS") %in% exports))
})

test_that("formal public GLM results are read-only, bounded and redacted", {
  specs <- .formal_glm_public_result_specs()
  withr::local_options(list(dsvert.dp.formal_glm_public_results = specs))
  calls <- 0L
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      calls <<- calls + 1L
      expect_identical(command, "formal-glm-public-result")
      expect_identical(input_data$certificate_json, "{}")
      expect_identical(input_data$pins, specs$primary_logit$pins)
      expect_false(simplify_output)
      .formal_glm_public_result_reply(specs)
    },
    .package = "dsVert")
  output <- dsvertFormalGLMPublicResultDS(
    "primary_logit", "study", "binomial",
    specs$primary_logit$formula_sha256)
  expect_identical(calls, 1L)
  expect_setequal(names(output), c(
    "version", "analysis_id", "artifact_id", "certificate_sha256",
    "family", "formula_sha256", "coefficients", "production_ready"))
  expect_identical(output$analysis_id, "primary_logit")
  expect_identical(output$coefficients[[2L]]$signed_steps, "-262144")
  expect_false(output$production_ready)
  forbidden <- c("certificate_json", "pins", "path", "key", "seed")
  expect_false(any(forbidden %in% names(output)))
})

test_that("formal public GLM selectors and malformed releases fail closed", {
  specs <- .formal_glm_public_result_specs()
  withr::local_options(list(dsvert.dp.formal_glm_public_results = specs))
  calls <- 0L
  testthat::local_mocked_bindings(
    .callMpcTool = function(...) {
      calls <<- calls + 1L
      .formal_glm_public_result_reply(specs)
    },
    .package = "dsVert")
  expect_error(dsvertFormalGLMPublicResultDS(
    "primary_logit", "other", "binomial",
    specs$primary_logit$formula_sha256),
    class = "dsvert_formal_glm_frontdoor_error")
  expect_identical(calls, 0L)

  testthat::local_mocked_bindings(
    .callMpcTool = function(...) {
      result <- .formal_glm_public_result_reply(specs)
      result$coefficients[[1L]]$signed_steps <- "-0"
      result
    },
    .package = "dsVert")
  expect_error(dsvertFormalGLMPublicResultDS(
    "primary_logit", "study", "binomial",
    specs$primary_logit$formula_sha256),
    class = "dsvert_formal_glm_frontdoor_error")
})
