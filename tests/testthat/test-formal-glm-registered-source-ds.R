.formal_glm_registered_source_ds_receipt <- function() {
  list(
    version = "dsvert-formal-glm-registered-phase18-source-outbox-chunk-v3",
    purpose = "formal_glm_registered_source_outbox_chunk_v3",
    handle = strrep("a", 64L), artifact_id = strrep("b", 64L),
    source_contract_sha256 = strrep("c", 64L),
    authorization_sha256 = strrep("d", 64L), source = "site_a",
    block_index = 0L, pair_sha256 = strrep("e", 64L), pair_bytes = 6L,
    offset = 0L, chunk_sha256 = strrep("f", 64L), chunk_bytes = 6L,
    complete = TRUE, production_ready = FALSE)
}

test_that("registered formal GLM source DS relays a bounded opaque chunk", {
  context <- new.env(parent = emptyenv())
  seen <- NULL
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(
        source_contract_json, source_environment) {
      expect_identical(source_contract_json, "{\"contract\":\"registered\"}")
      expect_true(is.environment(source_environment))
      context
    },
    .dsvert_formal_glm_registered_source_read_block_chunk = function(
        actual_context, recipient_tickets, block_index, offset) {
      seen <<- list(actual_context, recipient_tickets, block_index, offset)
      list(
        chunk_receipt = .formal_glm_registered_source_ds_receipt(),
        pair_chunk = charToRaw("opaque"), replayed = TRUE)
    },
    .package = "dsVert")

  output <- dsvertFormalGLMRegisteredSourceDS(
    "{\"contract\":\"registered\"}", "chunk", list(
      recipient_tickets = unname(list(list(ticket = "a"), list(ticket = "b"))),
      block_index = 0L, offset = 0L))

  expect_identical(seen, list(
    context, unname(list(list(ticket = "a"), list(ticket = "b"))), 0L, 0L))
  expect_identical(output, list(
    version = "dsvert-formal-glm-registered-phase18-source-response-v1",
    action = "chunk", payload = list(
      chunk_receipt = .formal_glm_registered_source_ds_receipt(),
      pair_chunk_base64 = "b3BhcXVl", replayed = TRUE),
    production_ready = FALSE))
  expect_false(any(c("rows", "values", "private_consensus", "pair_json") %in%
                   names(output$payload)))
})

test_that("registered formal GLM source DS rejects widened or unsafe envelopes", {
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_formal_glm_registered_source_open = function(...) {
      calls <<- calls + 1L
      new.env(parent = emptyenv())
    },
    .dsvert_formal_glm_registered_source_issue_ticket = function(...) list(
      ticket = list(storage_key = "must-not-leak"), replayed = FALSE),
    .package = "dsVert")

  expect_error(dsvertFormalGLMRegisteredSourceDS(
    "{\"contract\":\"registered\"}", "unknown", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_error(dsvertFormalGLMRegisteredSourceDS(
    strrep("x", 1024L * 1024L + 1L), "ticket", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_error(dsvertFormalGLMRegisteredSourceDS(
    "{\"contract\":\"registered\"}", "ticket", list(extra = TRUE)),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_identical(calls, 0L)

  expect_error(dsvertFormalGLMRegisteredSourceDS(
    "{\"contract\":\"registered\"}", "ticket", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_source_ds_error")
  expect_identical(calls, 1L)
})
