.synopsis_wrapper_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-source-gate.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})
.synopsis_wrapper_symbols <- c(
  ".dsvert_dp_synopsis_source_transport_ticket_v1",
  ".dsvert_dp_synopsis_source_transport_prepare_v1",
  ".dsvert_dp_synopsis_source_transport_chunk_v1")
.synopsis_wrapper_available <- function() all(vapply(
  .synopsis_wrapper_symbols, exists, logical(1L), mode = "function",
  inherits = TRUE))

.synopsis_wrapper_authority_mock <- function(
    fixture, peer, output, state, label) {
  force(output)
  function(manifest_sha256, artifact, claim_set, receipts,
           .policy, .secret, .cache_get, .verifier) {
    state$events <- c(state$events, label)
    if (isTRUE(state$reject)) stop("authority rejected", call. = FALSE)
    expect_identical(manifest_sha256, fixture$input$manifest_sha256)
    expect_identical(artifact, fixture$artifact)
    expect_identical(claim_set, fixture$input$claim_set)
    expect_identical(receipts, fixture$receipts)
    expect_identical(.policy, fixture$input$policies[[peer]])
    expect_identical(.secret, fixture$input$secrets[[peer]])
    expect_identical(.cache_get, fixture$input$cache_get)
    expect_identical(.verifier, fixture$input$verifier)
    output
  }
}

test_that("synopsis source wrappers expose only the closed internal ABI", {
  available <- vapply(
    .synopsis_wrapper_symbols, exists, logical(1L), mode = "function",
    inherits = TRUE)
  for (index in seq_along(available)) {
    expect_true(available[[index]], info = paste(
      "missing", .synopsis_wrapper_symbols[[index]]))
  }
  if (all(available)) {
    evidence <- c(
      "manifest_sha256", "artifact", "claim_set", "receipts")
    expect_identical(names(formals(
      .dsvert_dp_synopsis_source_transport_ticket_v1)), c(
        evidence, ".policy", ".secret", ".cache_get", ".verifier"))
    expect_identical(names(formals(
      .dsvert_dp_synopsis_source_transport_prepare_v1)), c(
        evidence, "first_ticket_json", "second_ticket_json", ".policy",
        ".secret", ".envir", ".cache_get", ".verifier"))
    expect_identical(names(formals(
      .dsvert_dp_synopsis_source_transport_chunk_v1)), c(
        evidence, "source_transfer_id", "chunk_index", ".policy", ".secret",
        ".envir", ".cache_get", ".verifier"))
    expect_false(any(.synopsis_wrapper_symbols %in%
                     getNamespaceExports("dsVert")))
  }
})

test_that("ticket derives its namespace from context before durable work", {
  skip_if_not(.synopsis_wrapper_available(), "RED: wrappers missing")
  fixture <- .synopsis_wrapper_helpers$.synopsis_gate_fixture(3L)
  peer <- "peer_b"
  context <- .synopsis_wrapper_helpers$.synopsis_gate_call(
    fixture, peer, context = TRUE)
  expect_null(context$local_claim)
  state <- new.env(parent = emptyenv())
  state$events <- character(); state$reject <- FALSE
  authority <- .synopsis_wrapper_authority_mock(
    fixture, peer, context, state, "context")
  ticket_impl <- function(
      manifest_json, .policy, .secret, .verifier, .allocation_require,
      source_contract, ...) {
    state$events <- c(state$events, "ticket")
    expect_identical(manifest_json, context$manifest_json)
    expect_identical(.policy, fixture$input$policies[[peer]])
    expect_identical(.secret, fixture$input$secrets[[peer]])
    expect_identical(.verifier, fixture$input$verifier)
    expect_identical(source_contract, context$source_contract)
    expect_true(is.function(.allocation_require))
    expect_true(isTRUE(.allocation_require(
      .policy, manifest_json, .secret, .verifier)))
    expect_length(list(...), 0L)
    "ticket-json"
  }
  invoke <- function() .dsvert_dp_synopsis_source_transport_ticket_v1(
    fixture$input$manifest_sha256, fixture$artifact,
    fixture$input$claim_set, fixture$receipts,
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]],
    .cache_get = fixture$input$cache_get,
    .verifier = fixture$input$verifier)
  testthat::with_mocked_bindings({
    expect_identical(invoke(), "ticket-json")
    expect_identical(state$events, c("context", "ticket"))
    state$events <- character(); state$reject <- TRUE
    expect_error(invoke(), "authority rejected")
    expect_identical(state$events, "context")
  }, .dsvert_dp_synopsis_source_transport_context_v1 = authority,
  .dsvert_dp_synopsis_source_transport_gate_v1 = function(...) {
    stop("ticket used source gate")
  }, .dsvert_dp_capsule_source_ticket_impl = ticket_impl,
  .package = "dsVert")
})

test_that("prepare installs only gate-owned producer callbacks", {
  skip_if_not(.synopsis_wrapper_available(), "RED: wrappers missing")
  fixture <- .synopsis_wrapper_helpers$.synopsis_gate_fixture(2L)
  peer <- "peer_a"
  gate <- .synopsis_wrapper_helpers$.synopsis_gate_call(fixture)
  state <- new.env(parent = emptyenv())
  state$events <- character(); state$reject <- FALSE
  authority <- .synopsis_wrapper_authority_mock(
    fixture, peer, gate, state, "gate")
  source_envir <- new.env()
  prepare_impl <- function(
      manifest_json, first_ticket_json, second_ticket_json,
      first_opening_json, second_opening_json, .policy, .secret, .envir,
      .materializer, .verifier, .allocation_observer,
      .producer_validator, source_contract, ...) {
    state$events <- c(state$events, "prepare")
    expect_identical(manifest_json, gate$manifest_json)
    expect_identical(c(first_ticket_json, second_ticket_json), c("t1", "t2"))
    expect_null(first_opening_json); expect_null(second_opening_json)
    expect_identical(.policy, fixture$input$policies[[peer]])
    expect_identical(.secret, fixture$input$secrets[[peer]])
    expect_identical(.envir, source_envir)
    expect_identical(.materializer, gate$materializer)
    expect_identical(.producer_validator, gate$producer_validator)
    expect_true(is.function(.allocation_observer))
    expect_true(isTRUE(.allocation_observer(
      .policy, manifest_json, NULL, NULL, .secret, .verifier)))
    expect_identical(source_contract, gate$source_contract)
    expect_identical(.verifier, fixture$input$verifier)
    expect_length(list(...), 0L)
    "summary-json"
  }
  invoke <- function() .dsvert_dp_synopsis_source_transport_prepare_v1(
    fixture$input$manifest_sha256, fixture$artifact,
    fixture$input$claim_set, fixture$receipts, "t1", "t2",
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]], .envir = source_envir,
    .cache_get = fixture$input$cache_get,
    .verifier = fixture$input$verifier)
  testthat::with_mocked_bindings({
    expect_identical(invoke(), "summary-json")
    expect_identical(state$events, c("gate", "prepare"))
    state$events <- character(); state$reject <- TRUE
    expect_error(invoke(), "authority rejected")
    expect_identical(state$events, "gate")
  }, .dsvert_dp_synopsis_source_transport_gate_v1 = authority,
  .dsvert_dp_capsule_source_prepare_negotiated_impl = prepare_impl,
  .dsvert_dp_capsule_source_prepare_impl = function(...) {
    stop("prepare bypassed negotiation")
  }, .package = "dsVert")
})

test_that("chunk rejects a foreign transfer id before opening its store", {
  skip_if_not(.synopsis_wrapper_available(), "RED: wrappers missing")
  fixture <- .synopsis_wrapper_helpers$.synopsis_gate_fixture(2L)
  peer <- "peer_a"
  gate <- .synopsis_wrapper_helpers$.synopsis_gate_call(fixture)
  expected <- .dsvert_dp_capsule_source_transfer_id(
    gate$source_contract, peer)
  state <- new.env(parent = emptyenv())
  state$events <- character(); state$reject <- FALSE
  authority <- .synopsis_wrapper_authority_mock(
    fixture, peer, gate, state, "gate")
  source_envir <- new.env()
  chunk_impl <- function(
      source_transfer_id, chunk_index, .policy, .secret, .envir,
      .materializer, .verifier, ...) {
    state$events <- c(state$events, "chunk")
    expect_identical(source_transfer_id, expected); expect_identical(chunk_index, 7L)
    expect_identical(.policy, fixture$input$policies[[peer]])
    expect_identical(.secret, fixture$input$secrets[[peer]])
    expect_identical(.envir, source_envir)
    expect_identical(.materializer, gate$materializer)
    expect_identical(.verifier, fixture$input$verifier)
    expect_length(list(...), 0L)
    "bundle-json"
  }
  invoke <- function(transfer_id) .dsvert_dp_synopsis_source_transport_chunk_v1(
    fixture$input$manifest_sha256, fixture$artifact,
    fixture$input$claim_set, fixture$receipts, transfer_id, 7L,
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]], .envir = source_envir,
    .cache_get = fixture$input$cache_get,
    .verifier = fixture$input$verifier)
  testthat::with_mocked_bindings({
    expect_error(invoke(paste0("csrc_", strrep("f", 64L))), "transfer")
    expect_identical(state$events, "gate")
    state$events <- character()
    expect_identical(invoke(expected), "bundle-json")
    expect_identical(state$events, c("gate", "chunk"))
  }, .dsvert_dp_synopsis_source_transport_gate_v1 = authority,
  .dsvert_dp_capsule_source_chunk_impl = chunk_impl,
  .dsvert_dp_capsule_source_with_store = function(...) {
    state$events <- c(state$events, "store")
    stop("store reached before transfer validation")
  }, .package = "dsVert")
})

test_that("wrappers resolve one policy and secret for authority and core", {
  fixture <- .synopsis_wrapper_helpers$.synopsis_gate_fixture(2L)
  peer <- "peer_a"
  context <- .synopsis_wrapper_helpers$.synopsis_gate_call(
    fixture, peer, context = TRUE)
  gate <- .synopsis_wrapper_helpers$.synopsis_gate_call(fixture, peer)
  policy_calls <- 0L; secret_calls <- 0L
  authority <- function(value) {
    force(value)
    function(
        manifest_sha256, artifact, claim_set, receipts,
        .policy, .secret, .cache_get, .verifier) {
      expect_identical(.policy, fixture$input$policies[[peer]])
      expect_identical(.secret, fixture$input$secrets[[peer]])
      value
    }
  }
  invoke <- function(name, ...) get(name)(
    fixture$input$manifest_sha256, fixture$artifact,
    fixture$input$claim_set, fixture$receipts, ...,
    .cache_get = fixture$input$cache_get,
    .verifier = fixture$input$verifier)
  transfer_id <- .dsvert_dp_capsule_source_transfer_id(
    gate$source_contract, peer)
  testthat::with_mocked_bindings({
    expect_identical(invoke(
      ".dsvert_dp_synopsis_source_transport_ticket_v1"), "ticket")
    expect_identical(invoke(
      ".dsvert_dp_synopsis_source_transport_prepare_v1",
      "t1", "t2"), "prepare")
    expect_identical(invoke(
      ".dsvert_dp_synopsis_source_transport_chunk_v1",
      transfer_id, 0L), "chunk")
  }, .dsvert_dp_policy = function() {
    policy_calls <<- policy_calls + 1L
    fixture$input$policies[[peer]]
  }, .dsvert_dp_secret = function() {
    secret_calls <<- secret_calls + 1L
    fixture$input$secrets[[peer]]
  }, .dsvert_dp_synopsis_source_transport_context_v1 = authority(context),
  .dsvert_dp_synopsis_source_transport_gate_v1 = authority(gate),
  .dsvert_dp_capsule_source_ticket_impl = function(...) "ticket",
  .dsvert_dp_capsule_source_prepare_negotiated_impl = function(...) "prepare",
  .dsvert_dp_capsule_source_chunk_impl = function(...) "chunk",
  .package = "dsVert")
  expect_identical(policy_calls, 3L)
  expect_identical(secret_calls, 3L)
})
