test_that("registered fresh GLM source is sealed before source selection", {
  selector <- list(
    analysis_id = "fresh_binomial", data_name = "D", family = "binomial",
    formula_sha256 = paste(rep("a", 64L), collapse = ""))
  opened <- FALSE
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(...) {
      opened <<- TRUE
      stop("must not open", call. = FALSE)
    },
    .package = "dsVert")

  expect_error(dsvertFormalGLMRegisteredFreshSourceDS(
    selector$analysis_id, selector$data_name, selector$family,
    selector$formula_sha256, "ticket", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_false(opened)
})

test_that("registered fresh GLM source rejects widened and mismatched selectors before opening", {
  opened <- FALSE
  withr::local_options(
    dsvert.formal_glm.registered_analysis_specs = list(
      fresh_binomial = list(
        version = "dsvert-formal-glm-registered-analysis-spec-v1",
        analysis_id = "fresh_binomial", data_name = "D", family = "binomial",
        formula_sha256 = paste(rep("a", 64L), collapse = ""),
        source_contract_json = "{\"contract\":\"configured\"}",
        publication_context_json = "{\"publication\":\"configured\"}",
        phase16_policy_json = "{\"policy\":\"configured\"}",
        sampler_authority_root = "not-canonical-base64")))
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(...) {
      opened <<- TRUE
      new.env(parent = emptyenv())
    },
    .package = "dsVert")

  expect_error(dsvertFormalGLMRegisteredFreshSourceDS(
    "fresh_binomial", "D", "poisson", paste(rep("a", 64L), collapse = ""),
    "ticket", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_error(dsvertFormalGLMRegisteredFreshSourceDS(
    "fresh_binomial", "D", "binomial", paste(rep("a", 64L), collapse = ""),
    "ticket", list(extra = TRUE)),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_error(dsvertFormalGLMRegisteredFreshSourceDS(
    "fresh_binomial", "D", "binomial", paste(rep("a", 64L), collapse = ""),
    "ticket", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_false(opened)
})

test_that("registered fresh GLM source seals even fixed public shapes", {
  selector <- list(
    analysis_id = "fresh_binomial", data_name = "D", family = "binomial",
    formula_sha256 = paste(rep("a", 64L), collapse = ""))
  opened <- FALSE
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(...) {
      opened <<- TRUE
      stop("must not open", call. = FALSE)
    },
    .package = "dsVert")

  expect_error(dsvertFormalGLMRegisteredFreshSourceDS(
    selector$analysis_id, selector$data_name, selector$family,
    selector$formula_sha256, "shape", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_false(opened)
})
