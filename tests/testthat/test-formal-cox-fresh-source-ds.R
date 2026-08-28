.formal_cox_fresh_source_test_plan <- function() {
  list(
    version = "dsvert-formal-cox-run-plan-v1",
    analysis_id = "primary", data_name = "study",
    formula_sha256 = strrep("a", 64L), schema_sha256 = strrep("b", 64L),
    run_id = strrep("c", 64L), compute_peers = c("site1", "site2"),
    production_ready = FALSE)
}

.formal_cox_fresh_source_test_schema <- function() {
  list(
    schema_sha256 = strrep("b", 64L),
    unsigned = list(peer_pinset = list(site1 = "pin1", site2 = "pin2")))
}

test_that("formal Cox fresh source relay is sealed before source access", {
  opened <- FALSE
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_run_plan = function(...) .formal_cox_fresh_source_test_plan(),
    .dsvert_formal_cox_server_source_open = function(...) {
      opened <<- TRUE
      stop("must not open")
    },
    .package = "dsVert")

  expect_error(dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "shape", list()),
    class = "dsvert_formal_cox_fresh_source_ds_error")
  expect_false(opened)
})

test_that("formal Cox fresh source relay fails closed before local source access", {
  opened <- FALSE
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_run_plan = function(...) stop("selector rejected"),
    .dsvert_formal_cox_server_source_open = function(...) {
      opened <<- TRUE
      stop("must not open")
    },
    .package = "dsVert")

  expect_error(dsvertFormalCoxFreshSourceDS(
    "bad id", "study", strrep("a", 64L), "shape", list()),
    class = "dsvert_formal_cox_fresh_source_ds_error")
  expect_false(opened)
})

test_that("formal Cox fresh source relay rejects malformed actions before source access", {
  opened <- FALSE
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_run_plan = function(...) .formal_cox_fresh_source_test_plan(),
    .dsvert_formal_cox_run_spec = function(...) list(schema = .formal_cox_fresh_source_test_schema()),
    .dsvert_require_configured_local_peer_name = function() "site1",
    .dsvert_formal_cox_server_source_spec = function(...) list(
      source_name = "site1", data_name = "study", block_capacity = 4L),
    .dsvert_formal_cox_server_source_open = function(...) {
      opened <<- TRUE
      stop("must not open")
    },
    .package = "dsVert")

  expect_error(dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "unknown", list()),
    class = "dsvert_formal_cox_fresh_source_ds_error")
  expect_error(dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "shape", list(extra = TRUE)),
    class = "dsvert_formal_cox_fresh_source_ds_error")
  expect_error(dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "produce",
    list(recipient_tickets = list(), block_index = 0L)),
    class = "dsvert_formal_cox_fresh_source_ds_error")
  expect_false(opened)
})
