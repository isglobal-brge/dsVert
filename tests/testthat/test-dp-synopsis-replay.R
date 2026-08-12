.synopsis_replay_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-release.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_replay_require <- function() skip_if_not(exists(
  ".dsvert_dp_synopsis_execution_replay_v1", mode = "function",
  inherits = TRUE), "RED: synopsis REPLAY is absent")

.synopsis_replay_setup <- function(k = 2L, envir = parent.frame()) {
  result <- .synopsis_replay_helpers$.synopsis_release_helpers$
    .synopsis_result_helpers
  start <- result$.synopsis_result_helpers
  fixture <- start$.synopsis_start_convolution_fixture(
    k, planner = function(input) .callMpcTool(
      "joint-dp-vector-convolution-plan-v3", input))
  start$.synopsis_start_cleanup(fixture, envir = envir)
  setup <- start$.synopsis_start_setup(fixture)
  results <- lapply(setup$authorities, function(peer) {
    start$.synopsis_start_call(
      fixture, setup, peer, start$.synopsis_start_zero_source,
      function(command, input) .callMpcTool(command, input))
    result$.synopsis_result_call(fixture, setup, peer)
  })
  names(results) <- setup$authorities
  built <- list(fixture = fixture, setup = setup, results = results)
  releases <- lapply(setup$authorities, function(peer)
    .synopsis_replay_helpers$.synopsis_release_call(built, peer))
  names(releases) <- setup$authorities
  c(built, list(releases = releases))
}

.synopsis_replay_call <- function(
    built, peer, first = built$releases[[1L]],
    second = built$releases[[2L]], index = 0L) {
  .dsvert_dp_synopsis_execution_replay_v1(
    built$setup$authorized[[peer]]$state, built$setup$session_id,
    first, second, index,
    .policy = built$fixture$input$policies[[peer]],
    .secret = built$fixture$input$secrets[[peer]],
    .identity = list(identity_pk = unname(
      built$fixture$input$fixture$pins[[peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier)
}

.synopsis_replay_resign <- function(built, receipt) {
  peer <- receipt$local_authority$peer_name
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  c(unsigned, list(signature = built$fixture$input$signer(
    .dsvert_dp_synopsis_execution_release_message_v1(unsigned),
    unname(built$fixture$input$fixture$pins[[peer]]))))
}

.synopsis_replay_verify_proof <- function(chunk_sha256, proof) {
  node <- .dsvert_joint_dp_vector_merkle_leaf(chunk_sha256)
  for (sibling in proof) {
    node <- if (identical(sibling$side, "left")) {
      .dsvert_joint_dp_vector_merkle_parent(sibling$sha256, node)
    } else {
      .dsvert_joint_dp_vector_merkle_parent(node, sibling$sha256)
    }
  }
  node
}

test_that("synopsis REPLAY exposes only the closed authorization ABI", {
  present <- exists(
    ".dsvert_dp_synopsis_execution_replay_v1", mode = "function",
    inherits = TRUE)
  expect_true(present, info = "missing dedicated synopsis REPLAY")
  if (!present) skip("RED: synopsis REPLAY is absent")
  expect_identical(names(formals(
    .dsvert_dp_synopsis_execution_replay_v1)), c(
      "ss", "session_id", "first_release", "second_release",
      "public_chunk_index", ".policy", ".secret", ".identity",
      ".cache_get", ".verifier"))
  defaults <- formals(.dsvert_dp_synopsis_execution_replay_v1)
  expect_true(all(vapply(defaults[c(
    ".policy", ".secret", ".identity")], is.null, logical(1L))))
  expect_identical(defaults$.cache_get,
    quote(.dsvert_dp_capsule_manifest_cache_get))
  expect_identical(defaults$.verifier,
    quote(.dsvert_relay_verify_message))
})

test_that("REPLAY returns the exact durable PUBLIC chunk and Merkle proof", {
  .synopsis_replay_require()
  built <- .synopsis_replay_setup()
  expect_identical(
    built$releases[[1L]]$final_chunk_hashes,
    built$releases[[2L]]$final_chunk_hashes)
  expect_identical(
    built$releases[[1L]]$final_vector_root,
    built$releases[[2L]]$final_vector_root)
  peer <- built$setup$authorities[[1L]]
  forbidden <- function(...) stop("private replay dependency reached",
                                  call. = FALSE)
  replay <- testthat::with_mocked_bindings(
    .synopsis_replay_call(
      built, peer, first = built$releases[[2L]],
      second = built$releases[[1L]]),
    .S = forbidden, .dsvert_typed_blob_consume = forbidden,
    .dsvert_dp_capsule_source_aggregate_release_range_internal = forbidden,
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .get_identity_seed = forbidden, .callMpcTool = forbidden,
    .dsvert_dp_synopsis_execution_release_v1 = forbidden,
    .package = "dsVert")
  forward <- .synopsis_replay_call(built, peer)
  expect_identical(replay, forward)
  expect_identical(
    .dsvert_dp_canonical_json(replay),
    .dsvert_dp_canonical_json(forward))
  fields <- c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "result_set_sha256", "final_vector_root", "public_chunk_index",
    "public_chunk_count", "chunk_sha256", "chunk", "merkle_proof",
    "durable_replay", "source_store_read", "sampler_invoked",
    "finalizer_invoked", "transport_read")
  expect_named(replay, fields, ignore.order = FALSE)
  expect_identical(replay$version,
    "dsvert-stateless-catalog-synopsis-replay-v1")
  expect_identical(replay$phase, "synopsis_public_chunk_replayed")
  expect_identical(replay$chunk_sha256,
    .dsvert_dp_synopsis_execution_hash_v1(
      .DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_DOMAIN, replay$chunk))
  hashes <- unlist(
    built$releases[[1L]]$final_chunk_hashes, use.names = FALSE)
  expect_identical(replay$chunk_sha256, hashes[[1L]])
  expect_identical(replay$merkle_proof,
    .dsvert_joint_dp_vector_merkle_proof(hashes, 0L))
  expect_identical(.synopsis_replay_verify_proof(
    replay$chunk_sha256, replay$merkle_proof),
    replay$final_vector_root)
  expect_identical(unlist(replay[c(
    "durable_replay", "source_store_read", "sampler_invoked",
    "finalizer_invoked", "transport_read")], use.names = FALSE),
    c(TRUE, FALSE, FALSE, FALSE, FALSE))
})

test_that("REPLAY is authority-only for K=2/3/5", {
  .synopsis_replay_require()
  for (k in c(2L, 3L, 5L)) {
    built <- .synopsis_replay_setup(k)
    authority_replays <- list()
    for (peer in built$setup$authorities) {
      authority_replays[[peer]] <- .synopsis_replay_call(built, peer)
      expect_identical(authority_replays[[peer]]$final_vector_root,
                       built$releases[[peer]]$final_vector_root)
    }
    expect_identical(
      authority_replays[[built$setup$authorities[[1L]]]],
      authority_replays[[built$setup$authorities[[2L]]]])
    for (witness in setdiff(
        built$fixture$peers, built$setup$authorities)) {
      expect_error(.dsvert_dp_synopsis_execution_replay_v1(
        built$setup$authorized[[built$setup$authorities[[1L]]]]$state,
        built$setup$session_id, built$releases[[1L]],
        built$releases[[2L]], 0L,
        .policy = built$fixture$input$policies[[witness]],
        .secret = built$fixture$input$secrets[[witness]],
        .identity = list(identity_pk = unname(
          built$fixture$input$fixture$pins[[witness]])),
        .cache_get = built$fixture$input$cache_get,
        .verifier = built$fixture$input$verifier),
        "authorization|noise authority")
    }
  }
})

test_that("REPLAY rejects duplicate, mixed and tampered RELEASE", {
  .synopsis_replay_require()
  built <- .synopsis_replay_setup()
  peer <- built$setup$authorities[[1L]]
  expect_error(.synopsis_replay_call(
    built, peer, second = built$releases[[1L]]),
    "RELEASE|authority|coverage|duplicate")

  bad_signature <- built$releases[[2L]]
  bad_signature$signature <- built$releases[[1L]]$signature
  expect_error(.synopsis_replay_call(
    built, peer, second = bad_signature), "RELEASE|signature")

  tampered <- built$releases[[2L]]
  tampered$final_vector_root <- strrep("f", 64L)
  expect_error(.synopsis_replay_call(
    built, peer, second = tampered), "RELEASE|root|signature")

  mixed <- built$releases[[2L]]
  mixed$final_chunk_hashes[[1L]] <- strrep("e", 64L)
  mixed$final_vector_root <- .dsvert_joint_dp_vector_merkle_root(
    unlist(mixed$final_chunk_hashes, use.names = FALSE))
  mixed <- .synopsis_replay_resign(built, mixed)
  expect_error(.synopsis_replay_call(
    built, peer, second = mixed), "RELEASE|same|agree|root|hash")

  forged <- lapply(built$releases, function(value) {
    value$final_chunk_hashes[[1L]] <- strrep("d", 64L)
    value$final_vector_root <- .dsvert_joint_dp_vector_merkle_root(
      unlist(value$final_chunk_hashes, use.names = FALSE))
    .synopsis_replay_resign(built, value)
  })
  expect_error(.synopsis_replay_call(
    built, peer, first = forged[[1L]], second = forged[[2L]]),
    "durable local|durable RELEASE|include")
})

test_that("REPLAY fails closed after durable RELEASE HMAC tampering", {
  .synopsis_replay_require()
  built <- .synopsis_replay_setup()
  peer <- built$setup$authorities[[1L]]
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    built$fixture$input$policies[[peer]])
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  expect_identical(DBI::dbExecute(connection, paste(
    "UPDATE synopsis_releases SET row_mac=? WHERE artifact_key=?"),
    params = list(strrep("0", 64L),
      built$releases[[peer]]$artifact_key)), 1L)
  DBI::dbDisconnect(connection)
  forbidden <- function(...) stop("private replay dependency reached",
                                  call. = FALSE)
  expect_error(testthat::with_mocked_bindings(
    .synopsis_replay_call(built, peer),
    .S = forbidden, .dsvert_typed_blob_consume = forbidden,
    .dsvert_dp_capsule_source_aggregate_release_range_internal = forbidden,
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .get_identity_seed = forbidden, .callMpcTool = forbidden,
    .package = "dsVert"), "authentication|HMAC|store")
})

test_that("REPLAY fails closed after durable PUBLIC HMAC tampering", {
  .synopsis_replay_require()
  built <- .synopsis_replay_setup()
  peer <- built$setup$authorities[[1L]]
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    built$fixture$input$policies[[peer]])
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  expect_identical(DBI::dbExecute(connection, paste(
    "UPDATE synopsis_public_chunks SET row_mac=? WHERE artifact_key=?",
    "AND public_chunk_index=0"), params = list(
      strrep("0", 64L), built$releases[[peer]]$artifact_key)), 1L)
  DBI::dbDisconnect(connection)
  forbidden <- function(...) stop("private replay dependency reached",
                                  call. = FALSE)
  expect_error(testthat::with_mocked_bindings(
    .synopsis_replay_call(built, peer),
    .S = forbidden, .dsvert_typed_blob_consume = forbidden,
    .dsvert_dp_capsule_source_aggregate_release_range_internal = forbidden,
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .get_identity_seed = forbidden, .callMpcTool = forbidden,
    .package = "dsVert"), "authentication|HMAC|store")
})

test_that("REPLAY never recreates a missing durable store", {
  .synopsis_replay_require()
  built <- .synopsis_replay_setup()
  peer <- built$setup$authorities[[1L]]
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    built$fixture$input$policies[[peer]])
  unlink(c(path, paste0(path, "-wal"), paste0(path, "-shm")),
         force = TRUE)
  expect_false(file.exists(path))
  forbidden <- function(...) stop("private replay dependency reached",
                                  call. = FALSE)
  expect_error(testthat::with_mocked_bindings(
    .synopsis_replay_call(built, peer),
    .S = forbidden, .dsvert_typed_blob_consume = forbidden,
    .dsvert_dp_capsule_source_aggregate_release_range_internal = forbidden,
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .get_identity_seed = forbidden, .callMpcTool = forbidden,
    .package = "dsVert"), class = "dsvert_phase_not_ready")
  expect_false(file.exists(path))
})
