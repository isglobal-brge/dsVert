test_that("registered fresh GLM source keeps its contract in custodian configuration", {
  contract <- "{\"contract\":\"configured\"}"
  selector <- list(
    analysis_id = "fresh_binomial", data_name = "D", family = "binomial",
    formula_sha256 = paste(rep("a", 64L), collapse = ""))
  spec <- c(list(
    version = "dsvert-formal-glm-registered-analysis-spec-v1"), selector,
    list(source_contract_json = contract))
  context <- new.env(parent = emptyenv())
  opened <- NULL
  withr::local_options(
    dsvert.formal_glm.registered_analysis_specs = list(fresh_binomial = spec))
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(value, environment) {
      opened <<- list(value, environment)
      context
    },
    .dsvert_formal_glm_registered_source_issue_ticket = function(actual_context) {
      expect_identical(actual_context, context)
      list(ticket = list(version = "ticket"), replayed = FALSE)
    },
    .package = "dsVert")

  result <- dsvertFormalGLMRegisteredFreshSourceDS(
    selector$analysis_id, selector$data_name, selector$family,
    selector$formula_sha256, "ticket", structure(list(), names = character()))

  expect_identical(opened[[1L]], contract)
  expect_true(is.environment(opened[[2L]]))
  expect_identical(result, list(
    version = "dsvert-formal-glm-registered-fresh-source-response-v1",
    action = "ticket", payload = list(ticket = list(version = "ticket"),
                                        replayed = FALSE),
    production_ready = FALSE))
  expect_false(grepl("configured", jsonlite::toJSON(result, auto_unbox = TRUE),
                     fixed = TRUE))
})

test_that("registered fresh GLM source rejects widened and mismatched selectors before opening", {
  opened <- FALSE
  withr::local_options(
    dsvert.formal_glm.registered_analysis_specs = list(
      fresh_binomial = list(
        version = "dsvert-formal-glm-registered-analysis-spec-v1",
        analysis_id = "fresh_binomial", data_name = "D", family = "binomial",
        formula_sha256 = paste(rep("a", 64L), collapse = ""),
        source_contract_json = "{\"contract\":\"configured\"}")))
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
  expect_false(opened)
})
