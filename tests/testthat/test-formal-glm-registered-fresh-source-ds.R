test_that("registered fresh GLM source keeps its contract in custodian configuration", {
  contract <- "{\"contract\":\"configured\"}"
  selector <- list(
    analysis_id = "fresh_binomial", data_name = "D", family = "binomial",
    formula_sha256 = paste(rep("a", 64L), collapse = ""))
  spec <- c(list(
    version = "dsvert-formal-glm-registered-analysis-spec-v1"), selector,
    list(source_contract_json = contract,
         publication_context_json = "{\"publication\":\"configured\"}",
         sampler_authority_root = ""))
  context <- new.env(parent = emptyenv())
  opened <- NULL
  withr::local_options(
    dsvert.formal_glm.registered_analysis_specs = list(fresh_binomial = spec))
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(
        value, environment, publication_context_json, sampler_authority_root) {
      opened <<- list(value, environment, publication_context_json,
                       sampler_authority_root)
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
  expect_identical(opened[[3L]], "{\"publication\":\"configured\"}")
  expect_identical(opened[[4L]], "")
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
        source_contract_json = "{\"contract\":\"configured\"}",
        publication_context_json = "{\"publication\":\"configured\"}",
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

test_that("registered fresh GLM source exposes only its fixed public shape", {
  selector <- list(
    analysis_id = "fresh_binomial", data_name = "D", family = "binomial",
    formula_sha256 = paste(rep("a", 64L), collapse = ""))
  spec <- c(list(
    version = "dsvert-formal-glm-registered-analysis-spec-v1"), selector,
    list(source_contract_json = "{\"contract\":\"configured\"}",
         publication_context_json = "{\"publication\":\"configured\"}",
         sampler_authority_root = ""))
  context <- new.env(parent = emptyenv())
  context$alignment_consensus <- as.raw(rep(0L, 32L))
  context$authorization <- list(
    artifact_id = paste(rep("b", 64L), collapse = ""),
    source_contract_sha256 = paste(rep("c", 64L), collapse = ""),
    custodian_peers = c("site_a", "site_b", "site_c"),
    designated_compute_peers = c("site_a", "site_b"),
    geometry = list(total_blocks = 3L), production_ready = FALSE)
  context$authorization_json <- "{}"
  context$contract_json <- "{\"contract\":\"configured\"}"
  context$publication_context_json <- "{\"publication\":\"configured\"}"
  context$sampler_authority_root <- ""
  context$pins <- list()
  context$rows <- data.frame()
  context$source_name <- "site_a"
  class(context) <- "dsvert_formal_glm_registered_source_context"
  withr::local_options(
    dsvert.formal_glm.registered_analysis_specs = list(fresh_binomial = spec))
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(...) context,
    .package = "dsVert")

  value <- dsvertFormalGLMRegisteredFreshSourceDS(
    selector$analysis_id, selector$data_name, selector$family,
    selector$formula_sha256, "shape", structure(list(), names = character()))
  expect_identical(value$payload, list(
    version = "dsvert-formal-glm-registered-fresh-source-shape-v1",
    artifact_id = paste(rep("b", 64L), collapse = ""),
    source_contract_sha256 = paste(rep("c", 64L), collapse = ""),
    source = "site_a", custodian_peers = c("site_a", "site_b", "site_c"),
    designated_compute_peers = c("site_a", "site_b"), total_blocks = 3L,
    production_ready = FALSE))
})
