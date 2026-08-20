.synopsis_threading_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-capsule-source-transport.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_threading_fixture <- function() {
  retained_before <- .dsvert_resource_retained_bytes()
  fixture <- .synopsis_threading_helpers$.capsule_source_test_fixture(2L)
  store_paths <- vapply(fixture$policies, function(policy) {
    paste0(policy$ledger_path, ".capsule-source-v3.sqlite")
  }, character(1L))
  owners <- vapply(
    fixture$policies, .dsvert_dp_capsule_source_resource_owner,
    character(1L))
  withr::defer({
    for (owner in owners) {
      .dsvert_resource_external_unregister(owner)
    }
    unlink(c(
      store_paths, paste0(store_paths, ".lock"),
      paste0(store_paths, "-wal"), paste0(store_paths, "-shm")),
      force = TRUE)
    expect_length(intersect(
      owners, names(.dsvert_resource_registry$external)), 0L)
    expect_identical(
      .dsvert_resource_retained_bytes(), retained_before)
  }, envir = parent.frame())
  base <- .dsvert_dp_capsule_source_contract(
    fixture$policies$peer_a, fixture$manifests$peer_a)
  binding <- list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION,
    manifest_capsule_id = base$capsule_id,
    artifact_key = strrep("a", 64L),
    source_claim_set_sha256 = strrep("b", 64L))
  contract <- base
  contract$capsule_id <-
    .dsvert_dp_synopsis_source_namespace_id_v1(binding)
  contract$synopsis_binding <- binding
  fixture$source_contract <- .dsvert_dp_capsule_source_contract_validate(
    .dsvert_dp_canonical_query_value(contract))
  fixture
}

.synopsis_threading_tickets <- function(fixture) {
  lapply(fixture$peers[1:2], function(peer) {
    .dsvert_dp_capsule_source_ticket_impl(
      fixture$manifest_json,
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .signer = .synopsis_threading_helpers$.capsule_source_test_signer,
      .allocation_require =
        .synopsis_threading_helpers$.capsule_source_test_allocation_require,
      source_contract = fixture$source_contract)
  })
}

.synopsis_threading_callbacks <- function() {
  state <- new.env(parent = emptyenv())
  state$materializers <- list()
  state$validators <- list()
  state$named_flags <- logical()
  materializer <- function(policy, manifest, snapshots,
                           compute_commitment, include_release) {
    call <- as.list(sys.call())[-1L]
    state$named_flags <- c(state$named_flags, all(c(
      "compute_commitment", "include_release") %in% names(call)))
    expect_identical(compute_commitment, TRUE)
    expect_identical(include_release, TRUE)
    producer <- .dsvert_dp_gaussian_cross_source_producer(
      policy, manifest, snapshots,
      compute_commitment = compute_commitment,
      include_release = include_release)
    state$materializers[[length(state$materializers) + 1L]] <- producer
    producer
  }
  validator <- function(producer, policy, manifest, contract) {
    current <- state$materializers[[length(state$materializers)]]
    expect_identical(producer, current)
    expect_identical(contract$synopsis_binding$manifest_capsule_id,
                     producer$capsule_id)
    expect_identical(policy$peer_name, producer$peer_name)
    expect_identical(manifest$capsule_identity$capsule_id,
                     contract$synopsis_binding$manifest_capsule_id)
    state$validators[[length(state$validators) + 1L]] <- producer
    TRUE
  }
  list(state = state, materializer = materializer, validator = validator)
}

.synopsis_threading_prepare <- function(fixture, tickets, callbacks,
                                        producer_validator =
                                          callbacks$validator) {
  .dsvert_dp_capsule_source_prepare_impl(
    fixture$manifest_json, tickets[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .materializer = callbacks$materializer,
    .random_bytes = function(...) stop("prepare consumed RNG"),
    .signer = .synopsis_threading_helpers$.capsule_source_test_signer,
    .verifier = .synopsis_threading_helpers$.capsule_source_test_verifier,
    .allocation_observer =
      .synopsis_threading_helpers$.capsule_source_test_allocation_observer,
    .producer_validator = producer_validator,
    source_contract = fixture$source_contract)
}

test_that("source-contract threading extends only the internal ABI", {
  expect_identical(names(formals(
    .dsvert_dp_capsule_source_contract_json)),
    c("policy", "manifest_json", "source_contract"))
  expect_identical(names(formals(.dsvert_dp_capsule_source_ticket_impl)), c(
    "manifest_json", ".policy", ".secret", ".keygen", ".signer",
    ".verifier", ".allocation_require", "source_contract"))
  prepare_prefix <- c(
    "manifest_json", "first_ticket_json", "second_ticket_json",
    "first_opening_json", "second_opening_json", ".policy", ".secret",
    ".envir", ".resolved_snapshots", ".materializer", ".random_bytes",
    ".encryptor", ".signer", ".verifier", ".allocation_observer")
  expect_identical(names(formals(.dsvert_dp_capsule_source_prepare_impl)),
                   c(prepare_prefix, ".producer_validator", "source_contract"))
  expect_identical(names(formals(
    .dsvert_dp_capsule_source_prepare_negotiated_impl)),
    c(prepare_prefix, ".producer_validator", "source_contract"))
  expect_identical(names(formals(
    .dsvert_dp_capsule_source_aggregate_range_internal)),
    c("policy", "manifest_json", "start", "count", "secret",
      "source_contract"))
  expect_identical(names(formals(
    .dsvert_dp_capsule_source_aggregate_chunk_internal)),
    c("policy", "manifest_json", "chunk_index", "secret",
      "source_contract"))
  expect_identical(names(formals(.dsvert_dp_capsule_source_chunk_impl)), c(
    "source_transfer_id", "chunk_index", ".policy", ".secret", ".envir",
    ".resolved_snapshots", ".materializer", ".random_bytes", ".encryptor",
    ".signer", ".verifier"))
  expect_null(formals(.dsvert_dp_capsule_source_contract_json)$source_contract)
  expect_null(formals(.dsvert_dp_capsule_source_prepare_impl)$.producer_validator)
  expect_null(formals(.dsvert_dp_capsule_source_prepare_impl)$source_contract)
})

test_that("contextual normalization rejects detached synopsis contracts", {
  fixture <- .synopsis_threading_fixture()
  policy <- fixture$policies$peer_a
  parsed <- .dsvert_dp_capsule_source_contract_json(
    policy, fixture$manifest_json,
    source_contract = fixture$source_contract)
  expect_identical(parsed$contract, fixture$source_contract)
  expect_identical(parsed$contract_json,
                   .dsvert_dp_canonical_json(fixture$source_contract))
  expect_identical(parsed$contract_hash,
                   .dsvert_joint_dp_hash(fixture$source_contract))

  legacy <- .dsvert_dp_capsule_source_contract_json(
    policy, fixture$manifest_json)
  expect_identical(
    legacy,
    .dsvert_dp_capsule_source_contract_json(
      policy, fixture$manifest_json, source_contract = NULL))

  omitted <- fixture$source_contract
  omitted$synopsis_binding <- NULL
  rehashed <- fixture$source_contract
  rehashed$synopsis_binding$manifest_capsule_id <- strrep("c", 64L)
  rehashed$capsule_id <- .dsvert_dp_synopsis_source_namespace_id_v1(
    rehashed$synopsis_binding)
  base_mismatch <- fixture$source_contract
  base_mismatch$workload_sha256 <- strrep("d", 64L)
  for (detached in list(omitted, rehashed, base_mismatch)) {
    expect_silent(.dsvert_dp_capsule_source_contract_validate(detached))
    expect_error(.dsvert_dp_capsule_source_contract_json(
      policy, fixture$manifest_json, source_contract = detached))
  }
})

test_that("recipient tickets persist the synopsis artifact namespace", {
  fixture <- .synopsis_threading_fixture()
  ticket_json <- .synopsis_threading_tickets(fixture)[[1L]]
  ticket <- .dsvert_dp_capsule_source_decode_json(
    ticket_json, "synopsis test ticket", 64L * 1024L)
  parsed <- .dsvert_dp_capsule_source_contract_json(
    fixture$policies$peer_a, fixture$manifest_json,
    source_contract = fixture$source_contract)
  expect_identical(ticket$capsule_id, fixture$source_contract$capsule_id)
  expect_identical(ticket$contract_hash, parsed$contract_hash)
  row <- .dsvert_dp_capsule_source_with_store(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    function(connection) DBI::dbGetQuery(
      connection,
      "SELECT capsule_id FROM source_recipient_keys"))
  expect_identical(row$capsule_id,
                   fixture$source_contract$capsule_id)
})

test_that("synopsis prepare validates the same fresh producer on replay", {
  fixture <- .synopsis_threading_fixture()
  tickets <- .synopsis_threading_tickets(fixture)
  absent <- .synopsis_threading_callbacks()
  expect_error(
    .synopsis_threading_prepare(
      fixture, tickets, absent, producer_validator = NULL),
    "validator", ignore.case = TRUE)
  expect_length(absent$state$materializers, 0L)

  callbacks <- .synopsis_threading_callbacks()
  first <- .synopsis_threading_prepare(fixture, tickets, callbacks)
  summary <- .dsvert_dp_capsule_source_decode_json(
    first, "synopsis test summary", 64L * 1024L)
  load_outbound <- function() {
    .dsvert_dp_capsule_source_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) .dsvert_dp_capsule_source_outbound_load(
        connection, summary$source_transfer_id,
        fixture$secrets$peer_a))
  }
  before <- load_outbound()
  expect_identical(before$contract_json,
                   .dsvert_dp_canonical_json(fixture$source_contract))

  replay <- testthat::with_mocked_bindings(
    .synopsis_threading_prepare(fixture, tickets, callbacks),
    .dsvert_dp_capsule_source_record_insert = function(...) {
      stop("replay inserted durable state")
    },
    .dsvert_dp_capsule_source_record_update = function(...) {
      stop("replay updated durable state")
    },
    .package = "dsVert")
  after <- load_outbound()
  expect_identical(replay, first)
  expect_identical(after, before)
  expect_length(callbacks$state$materializers, 2L)
  expect_length(callbacks$state$validators, 2L)
  expect_true(all(callbacks$state$named_flags))

  negotiated <- lapply(seq_along(tickets), function(index) {
    peer <- fixture$peers[[index]]
    .dsvert_dp_capsule_source_ticket_negotiation_wrap(
      tickets[[index]], fixture$policies[[peer]],
      .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT,
      .synopsis_threading_helpers$.capsule_source_test_signer)
  })
  negotiated_replay_json <-
    .dsvert_dp_capsule_source_prepare_negotiated_impl(
    fixture$manifest_json, negotiated[[1L]], negotiated[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .materializer = callbacks$materializer,
    .signer = .synopsis_threading_helpers$.capsule_source_test_signer,
    .verifier = .synopsis_threading_helpers$.capsule_source_test_verifier,
    .allocation_observer =
      .synopsis_threading_helpers$.capsule_source_test_allocation_observer,
    .producer_validator = callbacks$validator,
    source_contract = fixture$source_contract)
  negotiated_replay <- .dsvert_dp_capsule_source_decode_json(
    negotiated_replay_json, "synopsis negotiated replay", 64L * 1024L)
  expect_identical(negotiated_replay$summary_json, first)
  expect_length(callbacks$state$validators, 3L)
})

test_that("a durable synopsis chunk without its binding fails before resolve", {
  fixture <- .synopsis_threading_fixture()
  tickets <- .synopsis_threading_tickets(fixture)
  callbacks <- .synopsis_threading_callbacks()
  summary_json <- .synopsis_threading_prepare(
    fixture, tickets, callbacks)
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "synopsis test summary", 64L * 1024L)
  .dsvert_dp_capsule_source_with_store(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    function(connection) {
      source <- .dsvert_dp_capsule_source_outbound_load(
        connection, summary$source_transfer_id,
        fixture$secrets$peer_a)
      source$contract_json <- .dsvert_dp_canonical_json(
        .dsvert_dp_capsule_source_contract(
          fixture$policies$peer_a, fixture$manifests$peer_a))
      .dsvert_dp_capsule_source_record_update(
        connection, "source_outbound", source,
        fixture$secrets$peer_a, "transfer_id = ?",
        list(summary$source_transfer_id))
    })
  resolves <- 0L
  testthat::with_mocked_bindings(
    expect_error(.dsvert_dp_capsule_source_chunk_impl(
      summary$source_transfer_id, 0L,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .materializer = function(...) stop("materialized detached chunk"),
      .signer = .synopsis_threading_helpers$.capsule_source_test_signer,
      .verifier = .synopsis_threading_helpers$.capsule_source_test_verifier),
      "contract|binding", ignore.case = TRUE),
    .dsvert_dp_resolve_snapshot = function(...) {
      resolves <<- resolves + 1L
      stop("resolved detached chunk")
    },
    .package = "dsVert")
  expect_identical(resolves, 0L)
})

test_that("a synopsis chunk reconstructs its durable contract", {
  fixture <- .synopsis_threading_fixture()
  tickets <- .synopsis_threading_tickets(fixture)
  callbacks <- .synopsis_threading_callbacks()
  summary_json <- .synopsis_threading_prepare(
    fixture, tickets, callbacks)
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "synopsis test summary", 64L * 1024L)
  flags <- NULL
  materializer <- function(policy, manifest, snapshots,
                           compute_commitment, include_release) {
    flags <<- list(compute_commitment, include_release)
    .dsvert_dp_gaussian_cross_source_producer(
      policy, manifest, snapshots,
      compute_commitment = compute_commitment,
      include_release = include_release)
  }
  bundle_json <- .dsvert_dp_capsule_source_chunk_impl(
    summary$source_transfer_id, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .materializer = materializer,
    .signer = .synopsis_threading_helpers$.capsule_source_test_signer,
    .verifier = .synopsis_threading_helpers$.capsule_source_test_verifier)
  bundle <- .dsvert_dp_capsule_source_decode_json(
    bundle_json, "synopsis test bundle",
    .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES)
  expect_identical(flags, list(FALSE, TRUE))
  expect_identical(bundle$capsule_id,
                   fixture$source_contract$capsule_id)
  expect_identical(bundle$contract_hash,
                   .dsvert_joint_dp_hash(fixture$source_contract))
})

test_that("a durable synopsis chunk replay revalidates its binding", {
  fixture <- .synopsis_threading_fixture()
  tickets <- .synopsis_threading_tickets(fixture)
  callbacks <- .synopsis_threading_callbacks()
  summary_json <- .synopsis_threading_prepare(
    fixture, tickets, callbacks)
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "synopsis test summary", 64L * 1024L)
  bundle_json <- .dsvert_dp_capsule_source_chunk_impl(
    summary$source_transfer_id, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .synopsis_threading_helpers$.capsule_source_test_signer,
    .verifier = .synopsis_threading_helpers$.capsule_source_test_verifier)
  .dsvert_dp_capsule_source_with_store(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    function(connection) {
      source <- .dsvert_dp_capsule_source_outbound_load(
        connection, summary$source_transfer_id,
        fixture$secrets$peer_a)
      source$contract_json <- .dsvert_dp_canonical_json(
        .dsvert_dp_capsule_source_contract(
          fixture$policies$peer_a, fixture$manifests$peer_a))
      .dsvert_dp_capsule_source_record_update(
        connection, "source_outbound", source,
        fixture$secrets$peer_a, "transfer_id = ?",
        list(summary$source_transfer_id))
    })
  resolves <- 0L
  testthat::with_mocked_bindings(
    expect_error(.dsvert_dp_capsule_source_chunk_impl(
      summary$source_transfer_id, 0L,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .materializer = function(...) stop("materialized replay chunk"),
      .signer = .synopsis_threading_helpers$.capsule_source_test_signer,
      .verifier = .synopsis_threading_helpers$.capsule_source_test_verifier),
      "contract|binding", ignore.case = TRUE),
    .dsvert_dp_resolve_snapshot = function(...) {
      resolves <<- resolves + 1L
      stop("resolved replay chunk")
    },
    .package = "dsVert")
  expect_identical(resolves, 0L)
  expect_type(bundle_json, "character")
})
