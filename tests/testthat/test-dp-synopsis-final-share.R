.synopsis_final_share_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-result.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_final_share_require <- function() skip_if_not(exists(
  ".dsvert_dp_synopsis_execution_final_share_v1", mode = "function",
  inherits = TRUE), "RED: synopsis FINAL_SHARE is absent")

.synopsis_final_share_setup <- function(k = 2L) {
  fixture <- .synopsis_final_share_helpers$.synopsis_result_helpers$
    .synopsis_start_convolution_fixture(k)
  .synopsis_final_share_helpers$.synopsis_result_helpers$
    .synopsis_start_cleanup(fixture, envir = parent.frame())
  setup <- .synopsis_final_share_helpers$.synopsis_result_helpers$
    .synopsis_start_setup(fixture)
  results <- lapply(setup$authorities, function(peer) {
    .synopsis_final_share_helpers$.synopsis_result_start_local(
      fixture, setup, peer)
    .synopsis_final_share_helpers$.synopsis_result_call(
      fixture, setup, peer)
  })
  names(results) <- setup$authorities
  list(fixture = fixture, setup = setup, results = results)
}

.synopsis_final_share_session <- function(built, peer) {
  ss <- built$setup$authorized[[peer]]$state
  peers <- setdiff(built$fixture$peers, peer)
  transport <- lapply(seq_along(peers), function(index) {
    gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(
      rep((index + 10L) %% 255L, 32L))))
  })
  names(transport) <- peers
  ss$.session_id <- built$setup$session_id
  ss$peer_transport_pks <- transport
  ss$.typed_blob_self_name <- peer
  ss$.typed_blob_peer_identity_pks <- as.list(
    built$fixture$input$fixture$pins[peers])
  ss$.typed_blob_peer_binding_digest <- strrep("a", 64L)
  ss
}

test_that("synopsis FINAL_SHARE exposes only the closed authorization ABI", {
  present <- exists(
    ".dsvert_dp_synopsis_execution_final_share_v1", mode = "function",
    inherits = TRUE)
  expect_true(present, info = "missing dedicated synopsis FINAL_SHARE")
  if (!present) skip("RED: synopsis FINAL_SHARE is absent")
  expect_identical(names(formals(
    .dsvert_dp_synopsis_execution_final_share_v1)), c(
      "ss", "session_id", "first_result", "second_result",
      "public_chunk_index", ".policy", ".secret", ".identity",
      ".cache_get", ".verifier", ".encryptor"))
})

test_that("FINAL_SHARE transports the exact durable Ring128 bytes", {
  .synopsis_final_share_require()
  built <- .synopsis_final_share_setup()
  peer <- built$setup$authorities[[1L]]
  recipient <- built$setup$authorities[[2L]]
  ss <- .synopsis_final_share_session(built, peer)
  observed <- new.env(parent = emptyenv())
  local <- .dsvert_dp_synopsis_execution_with_store_v1(
    built$fixture$input$policies[[peer]],
    built$fixture$input$secrets[[peer]], function(connection) {
      context <- .synopsis_final_share_helpers$.synopsis_result_helpers$
        .synopsis_start_context(built$fixture, built$setup, peer)
      chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, 0L)
      .dsvert_dp_synopsis_execution_local_load_v1(
        connection, built$fixture$input$secrets[[peer]], context, NULL,
        chunk, built$fixture$input$policies[[peer]],
        built$fixture$input$verifier)
    })
  expect_false(is.null(local))
  transfer <- list(
    ticket = "ticket", transfer_id = paste0("tb_", strrep("1", 32L)),
    capability_id = "blob.analysis-dp.synopsis-final-share.v1",
    sender_name = peer, recipient_name = recipient,
    payload_chars = 1, payload_sha256 = strrep("2", 64L))
  result <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_final_share_v1(
      ss, built$setup$session_id, built$results[[1L]],
      built$results[[2L]], 0L,
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(identity_pk = unname(
        built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .encryptor = function(plaintext, recipient_pk) {
        observed$plaintext <- plaintext
        observed$recipient_pk <- recipient_pk
        gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(9L, 32L))))
      }),
    .S = function(...) ss,
    .dsvert_typed_blob_operation_replay = function(...) list(
      hit = FALSE, key = "key"),
    .dsvert_typed_blob_mint = function(
        ss, session_id, capability_id, recipient_pk, payload, context,
        producer = NULL) {
      observed$capability_id <- capability_id
      observed$context <- context
      observed$payload <- payload
      observed$producer <- producer
      transfer
    },
    .dsvert_typed_blob_operation_commit = function(
        ss, producer, request, result) {
      observed$request <- request
      result
    }, .package = "dsVert")
  expect_named(result, c(
    "ciphertext", "transfer", "artifact_key", "contract_sha256",
    "attempt_sha256", "result_set_sha256", "public_chunk_index",
    "intermediate_payload_exposed", "capability_available"),
  ignore.order = FALSE)
  expect_identical(observed$capability_id,
    "blob.analysis-dp.synopsis-final-share.v1")
  expect_identical(observed$producer,
    ".dsvert_dp_synopsis_execution_final_share_v1")
  payload <- jsonlite::fromJSON(
    rawToChar(observed$plaintext), simplifyVector = FALSE)
  expect_identical(payload$version,
    "dsvert-stateless-catalog-synopsis-final-share-payload-v1")
  expect_identical(as.numeric(payload$context$ring_bits), 128)
  expect_identical(as.numeric(payload$context$frac_bits), 0)
  expect_length(payload$segments, 1L)
  expect_identical(payload$segments[[1L]]$noised_share_b64,
                   local$noised_share_b64)
  resolved <- .dsvert_typed_blob_destination(
    observed$capability_id, peer, observed$context)
  expect_silent(.dsvert_typed_blob_validate_synopsis_route(
    observed$capability_id, resolved, peer, recipient))
  expect_error(.dsvert_typed_blob_validate_synopsis_route(
    observed$capability_id, resolved, peer, setdiff(
      built$fixture$peers, recipient)[[1L]]), "synopsis route")

  forbidden <- function(...) stop("private dependency reran", call. = FALSE)
  replay <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_final_share_v1(
      ss, built$setup$session_id, built$results[[2L]],
      built$results[[1L]], 0L,
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(identity_pk = unname(
        built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .encryptor = forbidden),
    .S = function(...) ss,
    .dsvert_typed_blob_operation_replay = function(...) list(
      hit = TRUE, result = result),
    .dsvert_dp_synopsis_execution_with_store_v1 = forbidden,
    .dsvert_typed_blob_mint = forbidden,
    .dsvert_typed_blob_operation_commit = forbidden,
    .callMpcTool = forbidden, .package = "dsVert")
  expect_identical(replay, result)
})

test_that("FINAL_SHARE routes K=3/5 only between the two authorities", {
  .synopsis_final_share_require()
  for (k in c(3L, 5L)) {
    built <- .synopsis_final_share_setup(k)
    peer <- built$setup$authorities[[1L]]
    recipient <- built$setup$authorities[[2L]]
    witnesses <- setdiff(built$fixture$peers, built$setup$authorities)
    ss <- .synopsis_final_share_session(built, peer)
    observed <- list()
    sentinel <- list(done = TRUE)
    run <- function(first, second) testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_execution_final_share_v1(
        ss, built$setup$session_id, first, second, 0L,
        .policy = built$fixture$input$policies[[peer]],
        .secret = built$fixture$input$secrets[[peer]],
        .identity = list(identity_pk = unname(
          built$fixture$input$fixture$pins[[peer]])),
        .cache_get = built$fixture$input$cache_get,
        .verifier = built$fixture$input$verifier,
        .encryptor = function(...) stop("encrypt reached")),
      .S = function(...) ss,
      .dsvert_typed_blob_operation_replay = function(ss, producer, request) {
        observed[[length(observed) + 1L]] <<- request
        list(hit = TRUE, result = sentinel)
      }, .package = "dsVert")
    expect_identical(run(built$results[[1L]], built$results[[2L]]),
                     sentinel)
    expect_identical(run(built$results[[2L]], built$results[[1L]]),
                     sentinel)
    expect_identical(vapply(observed, `[[`, character(1L),
                              "recipient_name"), rep(recipient, 2L))
    expect_false(any(vapply(observed, function(value)
      value$recipient_name %in% witnesses, logical(1L))))
    expect_identical(observed[[1L]]$result_set_sha256,
                     observed[[2L]]$result_set_sha256)
    changed <- ss$.typed_blob_peer_identity_pks[[witnesses[[1L]]]]
    ss$.typed_blob_peer_identity_pks[[witnesses[[1L]]]] <-
      ss$.typed_blob_peer_identity_pks[[recipient]]
    expect_error(run(built$results[[1L]], built$results[[2L]]),
                 "recipient is not pinned")
    ss$.typed_blob_peer_identity_pks[[witnesses[[1L]]]] <- changed
  }
})

test_that("FINAL_SHARE public geometry is stable at 8192 coordinates", {
  .synopsis_final_share_require()
  geometry <- function(dimension, index) {
    context <- list(
      contract = list(value = list(geometry = list(
        coordinate_count = dimension,
        public_chunk_coordinates = min(8192L, dimension),
        public_chunk_count = ceiling(dimension / min(8192L, dimension))))),
      attempt = list(value = list(execution_geometry = list(
        chunk_coordinates = min(8192L, dimension),
        chunk_count = ceiling(dimension / min(8192L, dimension))))))
    .dsvert_dp_synopsis_execution_public_chunk_v1(context, index)
  }
  expect_identical(geometry(1L, 0L)[c("offset", "count")],
                   list(offset = 0L, count = 1L))
  expect_identical(geometry(8192L, 0L)[c("offset", "count")],
                   list(offset = 0L, count = 8192L))
  expect_identical(geometry(8193L, 1L)[c("offset", "count")],
                   list(offset = 8192L, count = 1L))
  expect_error(geometry(8193L, 2L), "chunk index|geometry")
})

test_that("FINAL_SHARE rejects duplicate RESULT and exact-GC", {
  .synopsis_final_share_require()
  built <- .synopsis_final_share_setup()
  peer <- built$setup$authorities[[1L]]
  ss <- .synopsis_final_share_session(built, peer)
  forbidden <- function(...) stop("private dependency reached", call. = FALSE)
  expect_error(.dsvert_dp_synopsis_execution_final_share_v1(
    ss, built$setup$session_id, built$results[[1L]], built$results[[1L]],
    0L, .policy = built$fixture$input$policies[[peer]],
    .secret = built$fixture$input$secrets[[peer]],
    .identity = list(identity_pk = unname(
      built$fixture$input$fixture$pins[[peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier,
    .encryptor = forbidden), "RESULT|authority|coverage|duplicate")
  mixed <- built$results[[2L]]
  mixed$prepare_set_sha256 <- strrep("f", 64L)
  mixed$signature <- built$fixture$input$signer(
    .dsvert_dp_synopsis_execution_result_message_v1(mixed),
    unname(built$fixture$input$fixture$pins[[
      built$setup$authorities[[2L]]]]))
  expect_error(.dsvert_dp_synopsis_execution_final_share_v1(
    ss, built$setup$session_id, built$results[[1L]], mixed, 0L,
    .policy = built$fixture$input$policies[[peer]],
    .secret = built$fixture$input$secrets[[peer]],
    .identity = list(identity_pk = unname(
      built$fixture$input$fixture$pins[[peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier,
    .encryptor = forbidden), "RESULT records do not agree")

  exact <- .synopsis_final_share_helpers$.synopsis_result_helpers$
    .synopsis_start_helpers$.synopsis_execution_helpers$
    .synopsis_authorization_fixture(2L)
  .synopsis_final_share_helpers$.synopsis_result_helpers$
    .synopsis_start_cleanup(exact)
  exact_setup <- .synopsis_final_share_helpers$.synopsis_result_helpers$
    .synopsis_start_setup(exact)
  exact_peer <- exact_setup$authorities[[1L]]
  expect_error(.dsvert_dp_synopsis_execution_final_share_v1(
    exact_setup$authorized[[exact_peer]]$state, exact_setup$session_id,
    list(), list(), 0L, .policy = exact$input$policies[[exact_peer]],
    .secret = exact$input$secrets[[exact_peer]],
    .identity = list(identity_pk = unname(
      exact$input$fixture$pins[[exact_peer]])),
    .cache_get = exact$input$cache_get,
    .verifier = exact$input$verifier,
    .encryptor = forbidden), "exact-GC|exact GC")
})
