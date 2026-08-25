.synopsis_remote_abi <- list(
  dsvertDPSynopsisClaimDS = "manifest_sha256",
  dsvertDPSynopsisCompileDS = c("manifest_sha256", "claims_json"),
  dsvertDPSynopsisPrepareDS = c(
    "session_id", "manifest_sha256", "claim_set_json", "compilation_json"),
  dsvertDPSynopsisStartDS = c(
    "session_id", "first_prepare_json", "second_prepare_json", "chunk_index"),
  dsvertDPSynopsisResultDS = c(
    "session_id", "first_prepare_json", "second_prepare_json"),
  dsvertDPSynopsisFinalShareDS = c(
    "session_id", "first_result_json", "second_result_json",
    "public_chunk_index"),
  dsvertDPSynopsisReleaseDS = c(
    "session_id", "first_result_json", "second_result_json"),
  dsvertDPSynopsisSourceTicketDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json"),
  dsvertDPSynopsisSourcePrepareDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json",
    "first_ticket_json", "second_ticket_json"),
  dsvertDPSynopsisSourceChunkDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json",
    "source_transfer_id", "chunk_index"),
  dsvertDPSynopsisSourceAcceptDS = c(
    "manifest_sha256", "envelope_json"),
  dsvertDPSynopsisCategoricalCrossBindDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json",
    "analysis_id", "session_id"),
  dsvertDPSynopsisCategoricalCrossFinalizeDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json",
    "analysis_id", "session_id"),
  dsvertDPSynopsisAlignmentMaskStartDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json",
    "batch_operation_id", "operation_id", "chunk_index", "chunk_count",
    "session_id"),
  dsvertDPSynopsisAlignmentMaskStoreDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json",
    "batch_operation_id", "operation_id", "chunk_index", "chunk_count",
    "session_id"),
  dsvertDPSynopsisAlignmentMaskSealDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json",
    "batch_operation_id", "session_id"),
  dsvertDPSynopsisAlignmentMaskReceiveDS = c(
    "manifest_sha256", "claim_set_json", "compilation_json", "peer_blob",
    "batch_operation_id", "session_id"))

.synopsis_remote_available <- function() {
  namespace <- asNamespace("dsVert")
  all(vapply(names(.synopsis_remote_abi), exists, logical(1L),
             envir = namespace, mode = "function", inherits = FALSE))
}

.synopsis_remote_json <- function(value) {
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value))
}

.synopsis_remote_frame <- function(value) {
  .dsvert_dsi_text_encode(.synopsis_remote_json(value))
}

test_that("the closed synopsis remote closures exist", {
  namespace <- asNamespace("dsVert")
  missing <- names(.synopsis_remote_abi)[!vapply(
    names(.synopsis_remote_abi), exists, logical(1L), envir = namespace,
    mode = "function", inherits = FALSE)]
  expect_identical(missing, character())
})

test_that("session-bound Synopsis Replay is retired", {
  expect_false(exists(
    "dsvertDPSynopsisReplayDS", asNamespace("dsVert"),
    mode = "function", inherits = FALSE))
})

test_that("the synopsis remote ABI has no raw dependency overrides", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  namespace <- asNamespace("dsVert")
  forbidden <- c(
    "...", ".policy", ".secret", ".identity", ".cache_get", ".resolver",
    ".planner", ".signer", ".verifier", ".source_reader", ".sampler",
    ".exact_compiler", ".exact_start", ".exact_consume", ".encryptor",
    ".peer_share_reader", ".finalizer", ".session", ".envir")
  for (name in names(.synopsis_remote_abi)) {
    observed <- names(formals(get(name, namespace, inherits = FALSE)))
    expect_identical(observed, .synopsis_remote_abi[[name]], info = name)
    expect_length(intersect(observed, forbidden), 0L)
  }
})

test_that("session endpoints reject non-canonical UUIDs before protected work", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  endpoint <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
  invalid <- "not-a-uuid"
  touched <- FALSE
  protected <- function(...) {
    touched <<- TRUE
    stop("protected work reached")
  }
  calls <- list(
    function() endpoint("dsvertDPSynopsisPrepareDS")(
      invalid, strrep("a", 64L), "claim-set", "compilation"),
    function() endpoint("dsvertDPSynopsisStartDS")(
      invalid, "first", "second", 0L),
    function() endpoint("dsvertDPSynopsisResultDS")(
      invalid, "first", "second"),
    function() endpoint("dsvertDPSynopsisFinalShareDS")(
      invalid, "first", "second", 0L),
    function() endpoint("dsvertDPSynopsisReleaseDS")(
      invalid, "first", "second"))
  testthat::with_mocked_bindings(
    for (call in calls) {
      expect_error(call(), class = "dsvert_dp_public_failure")
    },
    .dsvert_dp_synopsis_remote_manifest_v1 = protected,
    .dsvert_dp_synopsis_remote_text_v1 = protected,
    .dsvert_dp_synopsis_remote_decode_v1 = protected,
    .session_storage = protected,
    .S = protected,
    .package = "dsVert")
  expect_false(touched)
})

test_that("post-PREPARE endpoints never allocate missing sessions", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  endpoint <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
  storage <- new.env(parent = emptyenv())
  allocated <- character()
  execution_reached <- FALSE
  allocator <- function(session_id) {
    allocated <<- c(allocated, session_id)
    storage[[session_id]] <- new.env(parent = emptyenv())
    storage[[session_id]]
  }
  execute <- function(...) {
    execution_reached <<- TRUE
    list(version = "unexpected")
  }
  frame <- .synopsis_remote_frame(list(version = "evidence-v1"))
  ids <- sprintf(
    "00000000-0000-4000-8000-%012d", seq_len(4L) + 100L)
  calls <- list(
    function() endpoint("dsvertDPSynopsisStartDS")(
      ids[[1L]], frame, frame, 0L),
    function() endpoint("dsvertDPSynopsisResultDS")(
      ids[[2L]], frame, frame),
    function() endpoint("dsvertDPSynopsisFinalShareDS")(
      ids[[3L]], frame, frame, 0L),
    function() endpoint("dsvertDPSynopsisReleaseDS")(
      ids[[4L]], frame, frame))
  testthat::with_mocked_bindings(
    for (call in calls) {
      expect_error(call(), class = "dsvert_dp_public_failure")
    },
    .session_storage = function() storage,
    .S = allocator,
    .dsvert_dp_synopsis_execution_start_v1 = execute,
    .dsvert_dp_synopsis_execution_result_v1 = execute,
    .dsvert_dp_synopsis_execution_final_share_v1 = execute,
    .dsvert_dp_synopsis_execution_release_v1 = execute,
    .package = "dsVert")
  expect_identical(allocated, character())
  expect_identical(ls(storage, all.names = TRUE), character())
  expect_false(execution_reached)
})

test_that("PREPARE never imposes a call, session, or lifetime quota", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  endpoint <- get(
    "dsvertDPSynopsisPrepareDS", asNamespace("dsVert"), inherits = FALSE)
  storage <- new.env(parent = emptyenv())
  active_ids <- sprintf(
    "00000000-0000-4000-8000-%012d",
    seq_len(32L))
  for (id in active_ids) {
    state <- new.env(parent = emptyenv())
    state$.dp_synopsis_authorization <- list(session_id = id)
    storage[[id]] <- state
  }
  new_id <- "00000000-0000-4000-8000-000000000999"
  calls <- character()
  output <- list(version = "prepare-v1")
  invoke <- function(id) endpoint(
    id, strrep("a", 64L), "claim-set", "compilation")

  testthat::with_mocked_bindings({
    expect_identical(invoke(new_id), .synopsis_remote_json(output))
    expect_identical(
      calls, c("preflight", "S", "authorize", "prepare"))
  },
  .dsvert_dp_synopsis_remote_manifest_v1 = function(...) list(
    policy = list(peer_name = "peer_a"), secret = raw(32L),
    manifest = list()),
  .dsvert_dp_synopsis_remote_reject_cross_v1 = function(...) invisible(TRUE),
  .dsvert_dp_synopsis_remote_decode_v1 = function(...) list(
    version = "claim-set-v1"),
  .dsvert_dp_synopsis_remote_compilation_v1 = function(...) list(
    artifact = list(), receipts = list()),
  .dsvert_dp_synopsis_compile_v1 = function(...) {
    calls <<- c(calls, "preflight")
    list(artifact = list(), receipts = list())
  },
  .dsvert_dp_synopsis_compilation_register_v1 = function(...) invisible(NULL),
  .session_storage = function() storage,
  .S = function(id) {
    calls <<- c(calls, "S")
    if (!exists(id, envir = storage, inherits = FALSE)) {
      storage[[id]] <- new.env(parent = emptyenv())
    }
    storage[[id]]
  },
  .dsvert_dp_synopsis_authorize_session_v1 = function(...) {
    calls <<- c(calls, "authorize")
    list(authorized = TRUE)
  },
  .dsvert_dp_synopsis_execution_prepare_v1 = function(...) {
    calls <<- c(calls, "prepare")
    output
  }, .package = "dsVert")
})

test_that("post-PREPARE lookup rejects a session without authorization", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  endpoint <- get(
    "dsvertDPSynopsisStartDS", asNamespace("dsVert"), inherits = FALSE)
  session_id <- "00000000-0000-4000-8000-000000000106"
  storage <- new.env(parent = emptyenv())
  storage[[session_id]] <- new.env(parent = emptyenv())
  execution_reached <- FALSE
  frame <- .synopsis_remote_frame(list(version = "evidence-v1"))
  testthat::with_mocked_bindings(
    expect_error(endpoint(session_id, frame, frame, 0L),
                 class = "dsvert_dp_public_failure"),
    .session_storage = function() storage,
    .dsvert_enforce_release_mode = function(...) invisible(TRUE),
    .dsvert_dp_synopsis_execution_start_v1 = function(...) {
      execution_reached <<- TRUE
      list(version = "unexpected")
    },
    .package = "dsVert")
  expect_false(execution_reached)
  expect_identical(ls(storage, all.names = TRUE), session_id)
})

test_that("the synopsis surface forwards canonical evidence and JSON outputs", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  endpoint <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
  manifest_sha256 <- strrep("a", 64L)
  session_id <- "00000000-0000-4000-8000-000000000001"
  ss <- new.env(parent = emptyenv())
  ss$.dp_synopsis_authorization <- list(
    version = .DSVERT_DP_SYNOPSIS_AUTHORIZATION_VERSION,
    session_id = session_id, manifest_sha256 = manifest_sha256,
    artifact = list(), artifact_key = strrep("c", 64L),
    source_claim_set_sha256 = strrep("b", 64L),
    receipt_peers = list("peer_a", "peer_b"),
    receipt_set_sha256 = strrep("d", 64L), local_authority = list(),
    authorization_sha256 = strrep("e", 64L))
  storage <- new.env(parent = emptyenv())
  storage[[session_id]] <- ss
  policy <- list(peer_name = "peer_a")
  secret <- charToRaw("secret")
  manifest <- list(workload = list(families = list(
    categorical_pairs = list(cross_artifacts = list()),
    gaussian_models = list(artifacts = list()))))
  claim <- list(version = "claim-v1", source_peer_name = "peer_a")
  claims <- list(claim)
  claim_set <- list(version = "claim-set-v1", sha256 = strrep("b", 64L))
  artifact <- list(
    semantic = list(source_claim_set_sha256 = claim_set$sha256),
    artifact_key = strrep("c", 64L), physical_plan = list())
  receipt <- list(
    version = "dsvert-stateless-catalog-synopsis-compile-receipt-v1",
    peer_name = "peer_a", peer_identity_pk =
      "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    manifest_sha256 = manifest_sha256, artifact_key = strrep("c", 64L),
    source_claim_set_sha256 = claim_set$sha256,
    full_plan_sha256 = strrep("e", 64L), signature = strrep("A", 86L))
  compilation <- list(
    version = "dsvert-stateless-catalog-synopsis-compile-receipt-set-v1",
    artifact = artifact, receipts = list(receipt),
    receipt_set_sha256 =
      .dsvert_dp_synopsis_compile_receipt_set_hash_v1(list(receipt)))
  prepare <- list(version = "prepare-v1", peer = "peer_a")
  prepare_peer <- list(version = "prepare-v1", peer = "peer_b")
  result <- list(version = "result-v1", peer = "peer_a")
  result_peer <- list(version = "result-v1", peer = "peer_b")
  release <- list(version = "release-v1", peer = "peer_a")
  outputs <- list(
    claim = list(version = "local-claim-v1", claim = claim),
    prepare = prepare, start = list(version = "start-v1"), result = result,
    final_share = list(version = "final-share-v1"), release = release,
    ticket = list(version = "ticket-v1"),
    ticket_peer = list(version = "ticket-v1", peer = "peer_b"),
    source_prepare = list(version = "source-prepare-v1"),
    source_chunk = list(version = "source-chunk-v1"),
    source_accept = list(version = "source-accept-v1"))
  seen <- new.env(parent = emptyenv())
  capture <- function(name, value, output) {
    seen[[name]] <- value
    output
  }
  compilation_frame <- .synopsis_remote_frame(compilation)
  claim_set_frame <- .synopsis_remote_frame(claim_set)
  decode_wire <- function(value) jsonlite::fromJSON(
    .synopsis_remote_json(value), simplifyVector = FALSE)
  claims_wire <- decode_wire(claims)
  claim_set_wire <- decode_wire(claim_set)
  compilation_wire <- decode_wire(compilation)
  prepare_json <- .synopsis_remote_json(prepare)
  prepare_peer_json <- .synopsis_remote_json(prepare_peer)
  result_json <- .synopsis_remote_json(result)
  result_peer_json <- .synopsis_remote_json(result_peer)
  ticket_json <- .synopsis_remote_json(outputs$ticket)
  ticket_peer_json <- .synopsis_remote_json(outputs$ticket_peer)
  envelope_json <- .synopsis_remote_json(list(
    version = "source-envelope-v1", capsule_id = strrep("f", 64L)))
  testthat::with_mocked_bindings({
    observed <- list(
      claim = endpoint("dsvertDPSynopsisClaimDS")(manifest_sha256),
      compile = endpoint("dsvertDPSynopsisCompileDS")(
        manifest_sha256, .synopsis_remote_frame(claims)),
      prepare = endpoint("dsvertDPSynopsisPrepareDS")(
        session_id, manifest_sha256, claim_set_frame, compilation_frame),
      start = endpoint("dsvertDPSynopsisStartDS")(
        session_id, .dsvert_dsi_text_encode(prepare_json),
        .dsvert_dsi_text_encode(prepare_peer_json), 3L),
      result = endpoint("dsvertDPSynopsisResultDS")(
        session_id, .dsvert_dsi_text_encode(prepare_json),
        .dsvert_dsi_text_encode(prepare_peer_json)),
      final_share = endpoint("dsvertDPSynopsisFinalShareDS")(
        session_id, .dsvert_dsi_text_encode(result_json),
        .dsvert_dsi_text_encode(result_peer_json), 4L),
      release = endpoint("dsvertDPSynopsisReleaseDS")(
        session_id, .dsvert_dsi_text_encode(result_json),
        .dsvert_dsi_text_encode(result_peer_json)),
      ticket = endpoint("dsvertDPSynopsisSourceTicketDS")(
        manifest_sha256, claim_set_frame, compilation_frame),
      source_prepare = endpoint("dsvertDPSynopsisSourcePrepareDS")(
        manifest_sha256, claim_set_frame, compilation_frame,
        .dsvert_dsi_text_encode(ticket_json),
        .dsvert_dsi_text_encode(ticket_peer_json)),
      source_chunk = endpoint("dsvertDPSynopsisSourceChunkDS")(
        manifest_sha256, claim_set_frame, compilation_frame,
        paste0("csrc_", strrep("e", 64L)), 6L),
      source_accept = endpoint("dsvertDPSynopsisSourceAcceptDS")(
        manifest_sha256, .dsvert_dsi_text_encode(envelope_json)))
    expected_compile <- list(
      version = "dsvert-stateless-catalog-synopsis-local-compile-envelope-v1",
      claim_set = claim_set, artifact = artifact, receipt = receipt)
    expected <- c(outputs[setdiff(names(outputs), "ticket_peer")],
                  list(compile = expected_compile))
    expected <- expected[names(observed)]
    expect_identical(observed, lapply(expected, .synopsis_remote_json))
  },
  .dsvert_dp_synopsis_policy_for_manifest_v1 = function(...) {
    arguments <- list(...)
    if (isTRUE(arguments$.with_manifest)) {
      return(list(policy = policy, manifest_json = "manifest-json"))
    }
    policy
  },
  .dsvert_dp_policy = function(...) stop("legacy policy reached"),
  .dsvert_dp_synopsis_policy_v1 = function(...) stop(
    "mutable synopsis policy reached"),
  .dsvert_dp_secret = function() secret,
  .dsvert_dp_synopsis_cached_manifest_v1 = function(...) "manifest-json",
  .dsvert_dp_capsule_source_manifest = function(...) manifest,
  .dsvert_dp_synopsis_local_claim_v1 = function(...) capture(
    "claim", list(...), outputs$claim),
  .dsvert_dp_synopsis_source_claim_set_v1 = function(...) capture(
    "claim_set", list(...), claim_set),
  .dsvert_dp_synopsis_local_compile_v1 = function(...) capture(
    "compile", list(...), list(artifact = artifact, receipt = receipt)),
  .dsvert_dp_synopsis_compilation_register_v1 = function(...) invisible(NULL),
  .dsvert_dp_synopsis_compile_v1 = function(...) compilation_wire,
  .S = function(id) {
    seen$session_id <- id
    seen$session_allocations <- (seen$session_allocations %||% 0L) + 1L
    ss
  },
  .session_storage = function() storage,
  .dsvert_dp_synopsis_session_authorization_validate_v1 = function(
      state, id, ...) {
    seen$session_lookups <- c(seen$session_lookups %||% character(), id)
    list(authorized = TRUE)
  },
  .dsvert_dp_synopsis_authorize_session_v1 = function(...) capture(
    "authorize", list(...), list(authorized = TRUE)),
  .dsvert_dp_synopsis_execution_prepare_v1 = function(...) capture(
    "prepare", list(...), outputs$prepare),
  .dsvert_dp_synopsis_execution_start_v1 = function(...) capture(
    "start", list(...), outputs$start),
  .dsvert_dp_synopsis_execution_result_v1 = function(...) capture(
    "result", list(...), outputs$result),
  .dsvert_dp_synopsis_execution_final_share_v1 = function(...) capture(
    "final_share", list(...), outputs$final_share),
  .dsvert_dp_synopsis_execution_release_v1 = function(...) capture(
    "release", list(...), outputs$release),
  .dsvert_dp_synopsis_source_transport_ticket_v1 = function(...) {
    capture("ticket", list(...), .synopsis_remote_json(outputs$ticket))
  },
  .dsvert_dp_synopsis_source_transport_prepare_v1 = function(...) {
    capture("source_prepare", list(...),
            .synopsis_remote_json(outputs$source_prepare))
  },
  .dsvert_dp_synopsis_source_transport_chunk_v1 = function(...) {
    capture("source_chunk", list(...),
            .synopsis_remote_json(outputs$source_chunk))
  },
  .dsvert_dp_capsule_source_accept_impl = function(...) {
    capture("source_accept", list(...),
            .synopsis_remote_json(outputs$source_accept))
  }, .package = "dsVert")

  expect_identical(seen$session_id, session_id)
  expect_identical(seen$session_allocations, 1L)
  expect_identical(seen$session_lookups, rep(session_id, 4L))
  expect_identical(unname(seen$claim_set[1:3]),
                   list(policy, manifest, claims_wire))
  expect_identical(unname(seen$compile[1:2]),
                   list(manifest_sha256, claim_set))
  expect_identical(unname(seen$authorize[1:6]), list(
    ss, session_id, manifest_sha256, compilation_wire$artifact,
    claim_set_wire, compilation_wire$receipts))
  expect_identical(unname(seen$start[1:5]),
                   list(ss, session_id, prepare_json, prepare_peer_json, 3L))
  expect_identical(unname(seen$result[1:4]),
                   list(ss, session_id, prepare_json, prepare_peer_json))
  expect_identical(unname(seen$final_share[1:5]),
                   list(ss, session_id, decode_wire(result),
                        decode_wire(result_peer), 4L))
  expect_identical(unname(seen$release[1:4]),
                   list(ss, session_id, decode_wire(result),
                        decode_wire(result_peer)))
  expect_identical(unname(seen$source_prepare[5:6]),
                   list(ticket_json, ticket_peer_json))
  for (name in c("start", "result", "final_share", "release")) {
    expect_identical(seen[[name]]$.policy, policy, info = name)
    expect_identical(seen[[name]]$.secret, secret, info = name)
    expect_identical(
      seen[[name]]$.cache_get,
      .dsvert_dp_synopsis_manifest_cache_get_readonly_v1, info = name)
  }
  expect_identical(seen$source_accept[[1L]], envelope_json)
  expect_identical(seen$source_accept$.policy, policy)
  expect_identical(seen$source_accept$.secret, secret)
})

test_that("Compile rejects cross-owner catalogs before signing", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  endpoint <- get("dsvertDPSynopsisCompileDS", asNamespace("dsVert"))
  cross <- list(workload = list(families = list(
    categorical_pairs = list(cross_artifacts = list(cross = list(
      version = .DSVERT_DP_CATEGORICAL_CROSS_ARTIFACT_VERSION))),
    gaussian_models = list(artifacts = list()))))
  signed <- FALSE
  claimed <- FALSE
  testthat::with_mocked_bindings(
    {
      expect_error(endpoint(strrep("a", 64L),
                            .synopsis_remote_frame(list(list(claim = TRUE)))),
                   class = "dsvert_dp_public_failure")
      expect_error(get("dsvertDPSynopsisClaimDS", asNamespace("dsVert"))(
        strrep("a", 64L)), class = "dsvert_dp_public_failure")
    },
    .dsvert_dp_synopsis_policy_for_manifest_v1 = function(...) list(
      peer_name = "peer_a"),
    .dsvert_dp_secret = function() charToRaw("secret"),
    .dsvert_dp_synopsis_cached_manifest_v1 = function(...) "manifest-json",
    .dsvert_dp_capsule_source_manifest = function(...) cross,
    .dsvert_dp_synopsis_source_claim_set_v1 = function(...) list(
      version = "claim-set-v1", sha256 = strrep("b", 64L)),
    .dsvert_dp_synopsis_local_compile_v1 = function(...) {
      signed <<- TRUE
      stop("compile signer reached")
    },
    .dsvert_dp_synopsis_local_claim_v1 = function(...) {
      claimed <<- TRUE
      stop("Claim materializer reached")
    }, .package = "dsVert")
  expect_false(signed)
  expect_false(claimed)
})

test_that("framed evidence is mandatory and raw dependencies are unusable", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  compile <- get("dsvertDPSynopsisCompileDS", asNamespace("dsVert"))
  claim <- get("dsvertDPSynopsisClaimDS", asNamespace("dsVert"))
  expect_error(compile(strrep("a", 64L), .synopsis_remote_json(list())))
  expect_error(do.call(claim, list(
    manifest_sha256 = strrep("a", 64L), .policy = list())))
})

test_that("compilation envelopes and cross detection are fail closed", {
  skip_if_not(.synopsis_remote_available(), "RED: remote closures missing")
  compilation <- list(
    version = "wrong", artifact = list(), receipts = list(list()),
    receipt_set_sha256 = strrep("a", 64L))
  expect_error(.dsvert_dp_synopsis_remote_compilation_v1(
    .synopsis_remote_frame(compilation)), "compilation")
  receipt <- list(
    version = "dsvert-stateless-catalog-synopsis-compile-receipt-v1",
    peer_name = "peer_a", peer_identity_pk =
      "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
    manifest_sha256 = strrep("1", 64L), artifact_key = strrep("2", 64L),
    source_claim_set_sha256 = strrep("3", 64L),
    full_plan_sha256 = strrep("4", 64L), signature = strrep("A", 86L))
  compilation <- list(
    version = "dsvert-stateless-catalog-synopsis-compile-receipt-set-v1",
    artifact = list(), receipts = list(receipt),
    receipt_set_sha256 = strrep("f", 64L))
  expect_error(.dsvert_dp_synopsis_remote_compilation_v1(
    .synopsis_remote_frame(compilation)), "receipt-set hash")
  compilation$receipt_set_sha256 <-
    .dsvert_dp_synopsis_compile_receipt_set_hash_v1(compilation$receipts)
  malformed <- compilation
  malformed$receipts[[1L]]$signature <- "signed"
  expect_error(.dsvert_dp_synopsis_remote_compilation_v1(
    .synopsis_remote_frame(malformed)), "signature")
  mixed <- receipt
  mixed$peer_name <- "peer_b"
  mixed$peer_identity_pk <- .dsvert_relay_b64url_encode(raw(32L))
  mixed$full_plan_sha256 <- strrep("5", 64L)
  expect_error(.dsvert_dp_synopsis_compile_receipt_set_hash_v1(
    list(receipt, mixed)), "receipt set")
  session_reached <- FALSE
  manifest <- list(workload = list(
    vertical_crosses = list(
      categorical_pair_sets = list(), configured_crosses = list(),
      cross_owner_sets = list()),
    families = list(
      categorical_pairs = list(cross_artifacts = list()),
      gaussian_models = list(artifacts = list()))))
  testthat::with_mocked_bindings(
    expect_error(get("dsvertDPSynopsisPrepareDS", asNamespace("dsVert"))(
      "00000000-0000-4000-8000-000000000001", strrep("1", 64L),
      .synopsis_remote_frame(list(version = "claim-set-v1")),
      .synopsis_remote_frame(compilation)),
      class = "dsvert_dp_public_failure"),
    .dsvert_dp_synopsis_policy_for_manifest_v1 = function(...) list(
      peer_name = "peer_a"),
    .dsvert_dp_secret = function() charToRaw("secret"),
    .dsvert_dp_synopsis_cached_manifest_v1 = function(...) "manifest-json",
    .dsvert_dp_capsule_source_manifest = function(...) manifest,
    .S = function(...) { session_reached <<- TRUE; new.env() },
    .package = "dsVert")
  expect_false(session_reached)
  compilation$artifact <- list(preflight = TRUE)
  preflight_reached <- FALSE
  testthat::with_mocked_bindings(
    expect_error(get("dsvertDPSynopsisPrepareDS", asNamespace("dsVert"))(
      "00000000-0000-4000-8000-000000000001", strrep("1", 64L),
      .synopsis_remote_frame(list(version = "claim-set-v1")),
      .synopsis_remote_frame(compilation)),
      class = "dsvert_dp_public_failure"),
    .dsvert_dp_synopsis_policy_for_manifest_v1 = function(...) list(
      peer_name = "peer_a"),
    .dsvert_dp_secret = function() charToRaw("secret"),
    .dsvert_dp_synopsis_cached_manifest_v1 = function(...) "manifest-json",
    .dsvert_dp_capsule_source_manifest = function(...) manifest,
    .dsvert_dp_synopsis_compile_v1 = function(...) {
      preflight_reached <<- TRUE
      stop("compile signature verification failed")
    },
    .S = function(...) { session_reached <<- TRUE; new.env() },
    .package = "dsVert")
  expect_true(preflight_reached)
  expect_false(session_reached)
  future_cross <- list(workload = list(
    vertical_crosses = list(
      categorical_pair_sets = list(), configured_crosses = list(),
      cross_owner_sets = list()),
    families = list(
      categorical_pairs = list(cross_artifacts = list(future = list(
        version = "future-cross-v9"))),
      gaussian_models = list(artifacts = list()))))
  expect_error(.dsvert_dp_synopsis_remote_reject_cross_v1(future_cross),
               "Cross-owner")
  future_cross$workload$families$categorical_pairs$cross_artifacts <- list()
  future_cross$workload$families$gaussian_models$artifacts <- list(
    future = list(version = "future-gaussian-cross-v9"))
  expect_error(.dsvert_dp_synopsis_remote_reject_cross_v1(future_cross),
               "Cross-owner")
})

test_that("all-schema cross reservations are not materialized crosses", {
  reserved <- list(workload = list(
    vertical_crosses = list(
      implementation_state = "reserved_not_materialized",
      cross_owner_sets = list(alignment = list(
        implementation_state = "reserved_not_materialized")),
      categorical_pair_sets = list(alignment = list(
        included_coordinate_count = 0L,
        implementation_state = "reserved_not_materialized")),
      configured_crosses = list(), included_coordinate_count = 0L),
    families = list(
      categorical_pairs = list(cross_artifacts = list()),
      gaussian_models = list(artifacts = list(
        local = list(version =
          "bounded-normalized-gaussian-sufficient-statistics-v1"),
        lmm_fixed = list(version =
          "bounded-normalized-random-intercept-fixed-sufficient-statistics-v2"))))))
  expect_invisible(.dsvert_dp_synopsis_remote_reject_cross_v1(reserved))

  configured <- reserved
  configured$workload$vertical_crosses$configured_crosses <- list(
    requested = list(implementation_state = "reserved_not_materialized"))
  materialized <- reserved
  materialized$workload$vertical_crosses$implementation_state <-
    "categorical_pair_exact_gc_materialized"
  materialized$workload$vertical_crosses$included_coordinate_count <- 4L
  future <- reserved
  future$workload$vertical_crosses$implementation_state <-
    "future_cross_state_v9"
  future_set <- reserved
  future_set$workload$vertical_crosses$cross_owner_sets[[1L]]$
    implementation_state <- "future_cross_state_v9"

  for (manifest in list(configured, materialized, future, future_set)) {
    expect_error(.dsvert_dp_synopsis_remote_reject_cross_v1(manifest),
                 "Cross-owner")
  }
})
