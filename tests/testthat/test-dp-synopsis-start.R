.synopsis_start_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path("test-dp-synopsis-execution.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_start_require <- function() skip_if_not(exists(
    ".dsvert_dp_synopsis_execution_start_v1", mode = "function",
    inherits = TRUE), "RED: synopsis convolution START is absent")

.synopsis_start_convolution_fixture <- local({
  receipts <- .synopsis_start_helpers$.synopsis_execution_helpers$
    .synopsis_authorization_helpers$.synopsis_receipt_fixture
  artifacts <- .synopsis_start_helpers$.synopsis_execution_helpers$
    .synopsis_authorization_helpers$.synopsis_receipt_helpers
  function(k = 2L, planner = NULL, gaussian = FALSE) {
    input <- receipts(k)
    if (isTRUE(gaussian)) {
      source <- artifacts$.synopsis_artifact_helpers$.vector_capsule_fixture(
        gaussian = TRUE, k = k, count_only = TRUE)
      base <- list(policy = source$policies[[1L]],
        manifest = source$manifests[[1L]],
        pins = source$policies[[1L]]$peer_pinset)
    } else {
      base <- artifacts$.synopsis_artifact_fixture(k = k)
    }
    peers <- names(base$pins)
    input$policies <- stats::setNames(lapply(peers, function(peer) {
      value <- base$policy; value$peer_name <- peer
      value$own_identity_pk <- unname(base$pins[[peer]])
      value$ledger_path <- tempfile(paste0("synopsis-start-", peer, "-"))
      value$ledger_private <- FALSE; value
    }), peers)
    input$fixture <- list(policy = input$policies[[1L]],
      manifest = base$manifest, pins = base$pins)
    input$claim_set <- artifacts$.synopsis_artifact_claim_set(input$fixture)
    input$manifest_json <- .dsvert_dp_canonical_json(base$manifest)
    input$manifest_sha256 <- digest::digest(input$manifest_json,
      algo = "sha256", serialize = FALSE)
    input$cache_get <- function(policy, secret, cache_key = NULL,
                                manifest_sha256 = NULL) {
      .dsvert_dp_capsule_manifest_cache_record(strrep("1", 64L),
        strrep("2", 64L),
        .dsvert_dp_capsule_manifest_local_authority(policy, secret),
        strrep("3", 64L), strrep("4", 64L), input$manifest_json)
    }
    input$planner <- if (isTRUE(gaussian)) source$planner else
      artifacts$.synopsis_artifact_planner()
    input$mint <- function(peer, planner = input$planner)
      .dsvert_dp_synopsis_local_compile_v1(
        input$manifest_sha256, input$claim_set, input$policies[[peer]],
        input$secrets[[peer]], list(identity_pk = unname(base$pins[[peer]]),
          identity_sk = unname(base$pins[[peer]])), input$cache_get,
        planner, input$signer, input$verifier)
    if (is.null(planner)) planner <- input$planner
    local <- lapply(peers, input$mint, planner = planner)
    list(input = input, peers = peers, artifact = local[[1L]]$artifact,
         receipts = lapply(local, `[[`, "receipt"))
  }
})

.synopsis_start_cleanup <- function(fixture, envir = parent.frame()) {
  paths <- vapply(fixture$input$policies, function(policy)
    paste0(policy$ledger_path, ".synopsis-execution-v1.sqlite"), character(1L))
  withr::defer(unlink(unique(c(
    paths, paste0(paths, ".lock"), paste0(paths, "-wal"),
    paste0(paths, "-shm"))), force = TRUE), envir = envir)
}

.synopsis_start_setup <- function(
    fixture, session_id = "00000000-0000-4000-8000-000000000001") {
  authorities <- .synopsis_start_helpers$.synopsis_execution_authorities(fixture)
  authorized <- stats::setNames(lapply(authorities, function(peer)
    .synopsis_start_helpers$.synopsis_execution_authorize(
      fixture, peer, session_id)), authorities)
  prepared <- stats::setNames(lapply(authorities, function(peer)
    .synopsis_start_helpers$.synopsis_execution_prepare(
      fixture, authorized[[peer]], peer, session_id)), authorities)
  encoded <- lapply(prepared, function(value)
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value)))
  list(authorities = authorities, authorized = authorized,
       prepared = prepared, encoded = encoded, session_id = session_id)
}

.synopsis_start_context <- function(fixture, setup, peer) {
  .dsvert_dp_synopsis_execution_context_v1(
    setup$authorized[[peer]]$state, setup$session_id,
    fixture$input$policies[[peer]], fixture$input$secrets[[peer]],
    list(identity_pk = unname(fixture$input$fixture$pins[[peer]])),
    fixture$input$cache_get)
}

.synopsis_start_zero_source <- function(
    policy, manifest_json, offset, count, secret, source_contract)
  raw(count * 16L)

.synopsis_start_identity_seed <- function() gsub(
  "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(61L, 32L))))

.synopsis_start_sampler <- function(context, observe = NULL) {
  function(command, input) {
    if (is.function(observe)) observe(command, input)
    output <- .callMpcTool(command, input)
    # The fixture plan is a deterministic certificate stub; keep the real
    # sampler output but restore the plan to the contract under test.
    output$plan <- context$vector$plan
    output$sampler_contract_hash <- context$vector$plan_sha256
    chunk <- list(index = 0L, offset = input$chunk_start,
      count = input$coordinate_count)
    expect_silent(.dsvert_joint_dp_vector_sampler_validate(
      output, context$vector, list(
        peer_name = input$peer_name,
        seed_commitment = input$seed_commitment), chunk))
    output
  }
}

.synopsis_start_call <- function(
    fixture, setup, peer, source_reader, sampler,
    first = setup$encoded[[1L]], second = setup$encoded[[2L]],
    session = NULL, exact_compiler = NULL,
    identity_seed = .synopsis_start_identity_seed) {
  testthat::with_mocked_bindings(.dsvert_dp_synopsis_execution_start_v1(
    setup$authorized[[peer]]$state, setup$session_id, first, second, 0L,
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]],
    .identity = list(
      identity_pk = unname(fixture$input$fixture$pins[[peer]]),
      identity_sk = unname(fixture$input$fixture$pins[[peer]])),
    .cache_get = fixture$input$cache_get, .verifier = fixture$input$verifier,
    .signer = fixture$input$signer,
    .source_reader = source_reader, .sampler = sampler,
    .exact_compiler = exact_compiler, .session = session),
    .get_identity_seed = identity_seed, .package = "dsVert")
}

test_that("synopsis START exposes only the closed authorization ABI", {
  present <- exists(
    ".dsvert_dp_synopsis_execution_start_v1", mode = "function",
    inherits = TRUE)
  expect_true(present, info = "missing dedicated synopsis convolution START")
  if (!present) skip("RED: synopsis convolution START is absent")
  expect_identical(names(formals(.dsvert_dp_synopsis_execution_start_v1)), c(
    "ss", "session_id", "first_prepare", "second_prepare", "chunk_index",
    ".policy", ".secret", ".identity", ".cache_get", ".verifier",
    ".signer", ".source_reader", ".sampler", ".exact_compiler",
    ".exact_start", ".session"))
  defaults <- formals(.dsvert_dp_synopsis_execution_start_v1)
  nulls <- c(".policy", ".secret", ".identity", ".signer",
    ".source_reader", ".sampler", ".exact_compiler", ".session")
  expect_true(all(vapply(defaults[nulls], is.null, logical(1L))))
  expect_identical(defaults$.cache_get, quote(.dsvert_dp_capsule_manifest_cache_get))
  expect_identical(defaults$.verifier, quote(.dsvert_relay_verify_message))
  expect_identical(defaults$.exact_start, quote(.dsvert_joint_dp_vector_exact_gc_start))
})

test_that("convolution START is authority-only for K=2/3/5", {
  .synopsis_start_require()
  fields <- c("version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "local_authority", "chunk_index", "coordinate_offset",
    "coordinate_count", "backend", "sampler", "seed_commitment",
    "local_chunk_sha256", "sampler_contract_sha256",
    "local_chunk_durable", "intermediate_payload_exposed", "signature")
  for (k in c(2L, 3L, 5L)) {
    fixture <- .synopsis_start_convolution_fixture(k); .synopsis_start_cleanup(fixture)
    setup <- .synopsis_start_setup(fixture)
    expect_length(setup$authorities, 2L)
    for (index in seq_along(setup$authorities)) {
      peer <- setup$authorities[[index]]
      context <- .synopsis_start_context(fixture, setup, peer)
      expect_false(context$vector$profile$exact_gc)
      receipt <- .synopsis_start_call(
        fixture, setup, peer, .synopsis_start_zero_source,
        .synopsis_start_sampler(context),
        first = setup$encoded[[2L]], second = setup$encoded[[1L]])
      expect_named(receipt, fields, ignore.order = FALSE)
      expect_identical(receipt$phase, "synopsis_local_chunk_committed")
      expect_identical(receipt$local_authority$peer_name, peer)
      expect_true(receipt$local_chunk_durable); expect_false(receipt$intermediate_payload_exposed)
    }
    for (peer in setdiff(fixture$peers, setup$authorities)) {
      path <- .dsvert_dp_synopsis_execution_store_path_v1(
        fixture$input$policies[[peer]])
      expect_error(.dsvert_dp_synopsis_execution_start_v1(
        new.env(parent = emptyenv()), setup$session_id,
        setup$encoded[[1L]], setup$encoded[[2L]], 0L,
        .policy = fixture$input$policies[[peer]],
        .secret = fixture$input$secrets[[peer]],
        .identity = list(identity_pk = fixture$input$fixture$pins[[peer]]),
        .cache_get = fixture$input$cache_get,
        .verifier = fixture$input$verifier, .signer = fixture$input$signer,
        .source_reader = function(...) stop("source reached"),
        .sampler = function(...) stop("sampler reached")),
        "authorization|noise authority")
      expect_false(file.exists(path))
    }
  }
})

test_that("START validates PREPARE then orders CAS before private material", {
  .synopsis_start_require()
  fixture <- .synopsis_start_convolution_fixture(); .synopsis_start_cleanup(fixture)
  setup <- .synopsis_start_setup(fixture); peer <- setup$authorities[[1L]]
  context <- .synopsis_start_context(fixture, setup, peer)
  bad <- setup$prepared[[2L]]; bad$attempt_sha256 <- strrep("f", 64L)
  bad <- .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(bad))
  expect_error(.synopsis_start_call(
    fixture, setup, peer, function(...) stop("source reached"),
    function(...) stop("sampler reached"), second = bad),
    "PREPARE|signature|agree")

  events <- character(); observed <- new.env(parent = emptyenv())
  source <- function(policy, manifest_json, offset, count, secret,
                     source_contract) {
    events <<- c(events, "source")
    observed$range <- c(offset, count); observed$contract <- source_contract
    raw(count * 16L)
  }
  sampler <- .synopsis_start_sampler(context, function(command, input) {
    events <<- c(events, "sampler")
    observed$command <- command; observed$input <- input
  })
  claim <- .dsvert_dp_synopsis_execution_start_claim_v1
  seed <- .dsvert_dp_sticky_subseed_material_v1
  receipt <- testthat::with_mocked_bindings(
    .synopsis_start_call(fixture, setup, peer, source, sampler),
    .dsvert_dp_synopsis_execution_start_claim_v1 = function(...) {
      events <<- c(events, "cas"); claim(...) },
    .dsvert_dp_sticky_subseed_material_v1 = function(...) {
      events <<- c(events, "seed"); seed(...) },
    .package = "dsVert")
  expect_identical(events, c("cas", "seed", "source", "sampler"))
  expect_identical(observed$range,
    c(receipt$coordinate_offset, receipt$coordinate_count))
  expect_identical(observed$contract, context$source_contract)
  expect_identical(observed$input$chunk_start, receipt$coordinate_offset)
  expect_identical(observed$input$release_contract_hash, context$contract$sha256)
  expect_identical(observed$input$transcript_hash, context$contract$sha256)
  expect_identical(observed$command, context$vector$profile$share_command)
})

test_that("START retries one attempt deterministically then replays durable", {
  .synopsis_start_require()
  fixture <- .synopsis_start_convolution_fixture(); .synopsis_start_cleanup(fixture)
  setup <- .synopsis_start_setup(fixture); peer <- setup$authorities[[1L]]
  context <- .synopsis_start_context(fixture, setup, peer)
  inputs <- list(); sources <- list()
  source <- function(policy, manifest_json, offset, count, secret,
                     source_contract) {
    value <- as.raw(rep(7L, count * 16L))
    sources[[length(sources) + 1L]] <<- value
    value
  }
  sampler <- .synopsis_start_sampler(context, function(command, input) {
    inputs[[length(inputs) + 1L]] <<- input
    if (length(inputs) == 1L) stop("injected sampler failure", call. = FALSE)
  })
  run <- function() .synopsis_start_call(fixture, setup, peer, source, sampler)
  expect_error(run(), "injected sampler failure")
  receipt <- run()
  expect_identical(inputs[[1L]]$private_seed, inputs[[2L]]$private_seed)
  expect_identical(inputs[[1L]]$source_share, inputs[[2L]]$source_share)
  expect_identical(sources[[1L]], sources[[2L]])
  forbidden <- function(...) stop("private material reran", call. = FALSE)
  replay <- testthat::with_mocked_bindings(
    .synopsis_start_call(fixture, setup, peer, forbidden, forbidden,
      identity_seed = forbidden),
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .package = "dsVert")
  expect_identical(replay, receipt)

  other <- .synopsis_start_setup(fixture,
    "00000000-0000-4000-8000-000000000002")
  expect_identical(testthat::with_mocked_bindings(
    .synopsis_start_call(fixture, other, peer, forbidden, forbidden,
      identity_seed = forbidden),
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .package = "dsVert"), receipt)
})

test_that("productive convolution plan and sampler agree without rewriting", {
  .synopsis_start_require()
  planner <- function(input) .callMpcTool(
    "joint-dp-vector-convolution-plan-v3", input)
  fixture <- .synopsis_start_convolution_fixture(2L, planner)
  .synopsis_start_cleanup(fixture)
  setup <- .synopsis_start_setup(fixture)
  receipts <- lapply(setup$authorities, function(peer) {
    .synopsis_start_call(
      fixture, setup, peer, .synopsis_start_zero_source,
      function(command, input) .callMpcTool(command, input))
  })
  expect_true(all(vapply(receipts, function(receipt) {
    grepl("^[0-9a-f]{64}$", receipt$sampler_contract_sha256)
  }, logical(1L))))
  expect_false(identical(
    receipts[[1L]]$sampler_contract_sha256,
    receipts[[2L]]$sampler_contract_sha256))
})

test_that("manifest-certified Gaussian START uses its productive worker", {
  .synopsis_start_require()
  fixture <- .synopsis_start_convolution_fixture(2L, gaussian = TRUE)
  .synopsis_start_cleanup(fixture)
  setup <- .synopsis_start_setup(fixture)
  receipts <- lapply(setup$authorities, function(peer) {
    context <- .synopsis_start_context(fixture, setup, peer)
    expect_true(context$vector$profile$gaussian)
    .synopsis_start_call(
      fixture, setup, peer, .synopsis_start_zero_source,
      function(command, input) .callMpcTool(command, input))
  })
  expect_true(all(vapply(receipts, function(receipt) {
    identical(receipt$backend, .DSVERT_JOINT_DP_GAUSSIAN_BACKEND) &&
      grepl("^[0-9a-f]{64}$", receipt$sampler_contract_sha256)
  }, logical(1L))))
})

test_that("the first START attempt wins before any private material", {
  .synopsis_start_require()
  fixture <- .synopsis_start_convolution_fixture(); .synopsis_start_cleanup(fixture)
  first <- .synopsis_start_setup(fixture); peer <- first$authorities[[1L]]
  context <- .synopsis_start_context(fixture, first, peer)
  .synopsis_start_call(fixture, first, peer, .synopsis_start_zero_source,
    .synopsis_start_sampler(context))

  planner <- .synopsis_start_helpers$.synopsis_execution_helpers$
    .synopsis_authorization_helpers$.synopsis_receipt_helpers$
    .synopsis_artifact_planner(operational = "b")
  alternate <- .synopsis_start_convolution_fixture(2L, planner)
  .synopsis_start_cleanup(alternate)
  for (name in names(alternate$input$policies)) {
    alternate$input$policies[[name]]$ledger_path <-
      fixture$input$policies[[name]]$ledger_path
  }
  second <- .synopsis_start_setup(alternate)
  expect_identical(first$prepared[[1L]]$artifact_key,
                   second$prepared[[1L]]$artifact_key)
  expect_identical(first$prepared[[1L]]$contract_sha256,
                   second$prepared[[1L]]$contract_sha256)
  expect_false(identical(first$prepared[[1L]]$attempt_sha256,
                         second$prepared[[1L]]$attempt_sha256))
  forbidden <- function(...) stop("private material reached", call. = FALSE)
  expect_error(testthat::with_mocked_bindings(
    .synopsis_start_call(alternate, second, peer, forbidden, forbidden,
      identity_seed = forbidden),
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .package = "dsVert"),
    "conflict|attempt|first|claimed")
})

test_that("durable LOCAL records fail closed after HMAC tampering", {
  .synopsis_start_require()
  fixture <- .synopsis_start_convolution_fixture(); .synopsis_start_cleanup(fixture)
  setup <- .synopsis_start_setup(fixture); peer <- setup$authorities[[1L]]
  context <- .synopsis_start_context(fixture, setup, peer)
  .synopsis_start_call(fixture, setup, peer, .synopsis_start_zero_source,
    .synopsis_start_sampler(context))
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(if (!is.null(connection)) DBI::dbDisconnect(connection), add = TRUE)
  expect_identical(DBI::dbExecute(connection, paste(
    "UPDATE synopsis_chunks SET row_mac=?",
    "WHERE kind='LOCAL' AND chunk_index=0"),
    params = list(strrep("0", 64L))), 1L)
  DBI::dbDisconnect(connection); connection <- NULL
  forbidden <- function(...) stop("private material reached", call. = FALSE)
  expect_error(.synopsis_start_call(
    fixture, setup, peer, forbidden, forbidden, identity_seed = forbidden),
    "authentication|HMAC|store")
})

test_that("exact-GC cannot masquerade as a durable convolution START", {
  .synopsis_start_require()
  fixture <- .synopsis_start_helpers$.synopsis_execution_helpers$
    .synopsis_authorization_fixture(2L)
  .synopsis_start_cleanup(fixture); setup <- .synopsis_start_setup(fixture)
  peer <- setup$authorities[[1L]]
  context <- .synopsis_start_context(fixture, setup, peer)
  expect_true(context$vector$profile$exact_gc)
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])
  forbidden <- function(...) stop("convolution material reached", call. = FALSE)
  expect_error(.synopsis_start_call(
    fixture, setup, peer, forbidden, forbidden,
    session = NULL, exact_compiler = NULL, identity_seed = forbidden),
    "exact-GC|exact GC|session")
  expect_false(file.exists(path))
})
