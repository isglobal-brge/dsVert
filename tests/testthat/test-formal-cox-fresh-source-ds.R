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

test_that("formal Cox fresh source relay moves only configured opaque records", {
  plan <- .formal_cox_fresh_source_test_plan()
  schema <- .formal_cox_fresh_source_test_schema()
  calls <- new.env(parent = emptyenv())
  calls$actions <- character()
  calls$opened <- 0L
  source_context <- new.env(parent = emptyenv())
  source_context$source_name <- "site1"
  source_context$block_capacity <- 4L

  testthat::local_mocked_bindings(
    .dsvert_formal_cox_run_plan = function(...) plan,
    .dsvert_formal_cox_run_spec = function(...) list(schema = schema),
    .dsvert_formal_cox_run_id = function(...) plan$run_id,
    .dsvert_require_configured_local_peer_name = function() "site1",
    .dsvert_formal_cox_compute_peers = function(...) plan$compute_peers,
    .dsvert_formal_cox_schema_numeric = function(...) list(capacity = 8L),
    .dsvert_formal_cox_server_source_spec = function(...) list(
      source_name = "site1", data_name = "study", block_capacity = 4L),
    .dsvert_formal_cox_server_source_open = function(...) {
      calls$opened <- calls$opened + 1L
      source_context
    },
    .dsvert_formal_cox_server_source_produce_block = function(
        context, run_id, recipient_tickets, block_index) {
      expect_identical(context, source_context)
      expect_identical(run_id, plan$run_id)
      expect_identical(recipient_tickets, list(list(ticket = "g"), list(ticket = "e")))
      expect_identical(block_index, 0L)
      calls$actions <- c(calls$actions, "produce")
      list(receipt = list(version = "receipt"), receipt_sha256 = strrep("d", 64L),
           replayed = FALSE)
    },
    .dsvert_formal_cox_server_source_deliver_block = function(
        context, run_id, recipient_tickets, block_index, recipient_peer_name) {
      expect_identical(context, source_context)
      expect_identical(recipient_peer_name, "site2")
      calls$actions <- c(calls$actions, "delivery")
      list(version = "dsvert-formal-cox-blockwise-source-delivery-v1",
           purpose = "formal-cox-recipient-encrypted-source-delivery-v1",
           receipt = list(version = "receipt"), receipt_sha256 = strrep("d", 64L),
           recipient_peer_name = "site2", envelope = list(ciphertext = "opaque"),
           binding = list(receipt = "opaque"))
    },
    .dsvert_formal_cox_server_source_recipient_ticket = function(...) {
      calls$actions <- c(calls$actions, "ticket")
      list(version = "ticket", transport_public_key = "public")
    },
    .dsvert_formal_cox_server_source_import_block = function(...) {
      calls$actions <- c(calls$actions, "import")
      list(version = "dsvert-formal-cox-blockwise-source-import-receipt-v1",
           purpose = "formal-cox-recipient-encrypted-source-delivery-v1",
           receipt_sha256 = strrep("d", 64L), recipient_peer_name = "site1",
           replayed = FALSE)
    },
    .dsvert_formal_cox_worker_provision = function(...) {
      calls$actions <- c(calls$actions, "provision")
      list(version = "worker", peer_name = "site1", plan_sha256 = strrep("b", 64L),
           attempt_id = strrep("e", 64L), replayed = FALSE,
           production_ready = FALSE)
    },
    .package = "dsVert")

  shape <- dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "shape", list())
  expect_identical(names(shape), c("version", "action", "payload", "production_ready"))
  expect_identical(shape$action, "shape")
  expect_identical(shape$payload, list(
    version = "dsvert-formal-cox-fresh-source-shape-v1", analysis_id = "primary",
    schema_sha256 = strrep("b", 64L), source = "site1",
    custodian_peers = c("site1", "site2"), designated_compute_peers = c("site1", "site2"),
    total_blocks = 2L, production_ready = FALSE))
  expect_identical(calls$opened, 1L)

  tickets <- list(list(ticket = "g"), list(ticket = "e"))
  ticket <- dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "ticket", list())
  expect_identical(ticket$payload$ticket$transport_public_key, "public")
  expect_identical(calls$opened, 1L)

  produced <- dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "produce",
    list(recipient_tickets = tickets, block_index = 0L))
  expect_identical(produced$payload$receipt_sha256, strrep("d", 64L))

  delivered <- dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "delivery",
    list(recipient_tickets = tickets, block_index = 0L, recipient_peer_name = "site2"))
  expect_identical(delivered$payload$recipient_peer_name, "site2")

  delivery <- delivered$payload
  imported <- dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "import",
    list(recipient_tickets = tickets, delivery = delivery))
  expect_identical(imported$payload$receipt_sha256, strrep("d", 64L))
  provisioned <- dsvertFormalCoxFreshSourceDS(
    "primary", "study", strrep("a", 64L), "provision",
    list(recipient_tickets = tickets, delivery = delivery))
  expect_identical(provisioned$payload$peer_name, "site1")
  expect_identical(calls$actions, c("ticket", "produce", "delivery", "import", "provision"))

  encoded <- jsonlite::toJSON(provisioned, auto_unbox = TRUE, null = "null")
  expect_false(grepl("recipient_signing_key|source_signing_key|canonical_input|rows|path|secret",
                     encoded, ignore.case = TRUE))
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

test_that("formal Cox fresh source relay rejects a run-plan/spec split before source access", {
  opened <- FALSE
  plan <- .formal_cox_fresh_source_test_plan()
  split_schema <- .formal_cox_fresh_source_test_schema()
  split_schema$schema_sha256 <- strrep("f", 64L)
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_run_plan = function(...) plan,
    .dsvert_formal_cox_run_spec = function(...) list(schema = split_schema),
    .dsvert_require_configured_local_peer_name = function() "site1",
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
