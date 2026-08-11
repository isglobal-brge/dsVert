.synopsis_gate_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-receipts.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})
.synopsis_gate_fixture <- function(k = 2L) {
  input <- .synopsis_gate_helpers$.synopsis_receipt_fixture(k)
  peers <- names(input$fixture$pins)
  local <- lapply(peers, input$mint)
  list(
    input = input, peers = peers, artifact = local[[1L]]$artifact,
    receipts = lapply(local, `[[`, "receipt"))
}
.synopsis_gate_call <- function(
    fixture, peer = "peer_a", claim_set = fixture$input$claim_set,
    receipts = fixture$receipts, artifact = fixture$artifact,
    cache_get = fixture$input$cache_get, context = FALSE) {
  implementation <- if (isTRUE(context)) {
    .dsvert_dp_synopsis_source_transport_context_v1
  } else {
    .dsvert_dp_synopsis_source_transport_gate_v1
  }
  implementation(
    fixture$input$manifest_sha256, artifact, claim_set, receipts,
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]],
    .cache_get = cache_get, .verifier = fixture$input$verifier)
}
.synopsis_gate_resign_claims <- function(fixture) {
  value <- fixture$input$claim_set
  value$claims <- lapply(value$claims, function(claim) {
    unsigned <- claim[setdiff(names(claim), "signature")]
    c(unsigned, list(signature = fixture$input$alternate_signer(
      .dsvert_dp_synopsis_source_vector_claim_message_v1(unsigned),
      unsigned$source_identity_pk)))
  })
  value
}
.synopsis_gate_defer_store_cleanup <- function(input, envir) {
  paths <- vapply(input$policies, function(policy) {
    paste0(policy$ledger_path, ".capsule-source-v3.sqlite")
  }, character(1L))
  owners <- vapply(
    input$policies, .dsvert_dp_capsule_source_resource_owner, character(1L))
  withr::defer({
    for (owner in owners) .dsvert_resource_external_unregister(owner)
    unlink(c(
      paths, paste0(paths, ".lock"), paste0(paths, "-wal"),
      paste0(paths, "-shm")), force = TRUE)
  }, envir = envir)
}
.synopsis_gate_available <- function() {
  all(vapply(c(
    ".dsvert_dp_synopsis_source_transport_context_v1",
    ".dsvert_dp_synopsis_source_transport_gate_v1"), exists, logical(1L),
    mode = "function", inherits = TRUE))
}
test_that("synopsis source context and gate have a closed internal ABI", {
  symbols <- c(
    ".dsvert_dp_synopsis_source_transport_context_v1",
    ".dsvert_dp_synopsis_source_transport_gate_v1")
  available <- vapply(
    symbols, exists, logical(1L), mode = "function", inherits = TRUE)
  expect_true(available[[1L]], info = paste("missing", symbols[[1L]]))
  expect_true(available[[2L]], info = paste("missing", symbols[[2L]]))
  if (all(available)) {
    expected <- c(
      "manifest_sha256", "artifact", "claim_set", "receipts",
      ".policy", ".secret", ".cache_get", ".verifier")
    expect_identical(
      names(formals(.dsvert_dp_synopsis_source_transport_context_v1)),
      expected)
    expect_identical(
      names(formals(.dsvert_dp_synopsis_source_transport_gate_v1)), expected)
  }
})
test_that("data-free context validates cache and exact K before source work", {
  skip_if_not(.synopsis_gate_available(), "RED: source context/gate missing")
  fixture <- .synopsis_gate_fixture(3L)
  events <- character()
  no_producer <- function(...) {
    events <<- c(events, "producer")
    stop("source materialized")
  }
  testthat::with_mocked_bindings({
    expect_error(.synopsis_gate_call(
      fixture, context = TRUE, cache_get = function(...) {
        events <<- c(events, "cache_rejected")
        NULL
      }), "not emitted|authorized")
    expect_identical(events, "cache_rejected")
    events <- character()
    expect_error(.synopsis_gate_call(
      fixture, context = TRUE, receipts = fixture$receipts[-1L],
      cache_get = function(...) {
        events <<- c(events, "cache_authorized")
        fixture$input$cache_get(...)
      }), "exactly one|coverage")
    expect_identical(events, "cache_authorized")
  }, .dsvert_dp_gaussian_cross_source_producer = no_producer,
  .package = "dsVert")
})
test_that("all peers validate context but only sources receive callbacks", {
  skip_if_not(.synopsis_gate_available(), "RED: source context/gate missing")
  for (k in c(2L, 3L, 5L)) {
    fixture <- .synopsis_gate_fixture(k)
    sources <- names(fixture$input$claim_set$claims)
    expect_identical(sources, "peer_a")
    for (peer in fixture$peers) {
      context <- .synopsis_gate_call(fixture, peer, context = TRUE)
      expect_named(context, c(
        "manifest_json", "source_contract", "local_claim"),
        ignore.order = FALSE)
      expect_identical(context$manifest_json, fixture$input$manifest_json)
      if (peer %in% sources) {
        expect_identical(
          context$local_claim, fixture$input$claim_set$claims[[peer]])
        gate <- .synopsis_gate_call(fixture, peer)
        expect_named(gate, c(
          "manifest_json", "source_contract", "materializer",
          "producer_validator"), ignore.order = FALSE)
        expect_true(is.function(gate$materializer))
        expect_true(is.function(gate$producer_validator))
      } else {
        expect_null(context$local_claim)
        expect_error(.synopsis_gate_call(fixture, peer), "source")
      }
    }
  }

  fixture <- .synopsis_gate_fixture(3L)
  testthat::with_mocked_bindings(
    expect_error(.synopsis_gate_call(fixture), "context sentinel"),
    .dsvert_dp_synopsis_source_transport_context_v1 = function(...) {
      stop("context sentinel", call. = FALSE)
    }, .package = "dsVert")
})
test_that("gate validates unsigned evidence from the same fresh producer", {
  skip_if_not(.synopsis_gate_available(), "RED: source context/gate missing")
  fixture <- .synopsis_gate_fixture(2L)
  resigned <- .synopsis_gate_resign_claims(fixture)
  expect_identical(resigned$sha256, fixture$input$claim_set$sha256)
  expect_false(identical(resigned$claims, fixture$input$claim_set$claims))
  gate <- .synopsis_gate_call(fixture, claim_set = resigned)
  expected <- resigned$claims$peer_a[
    setdiff(names(resigned$claims$peer_a), "signature")]
  fresh <- list(marker = new.env(parent = emptyenv()),
                reset = function() invisible(NULL))
  observed <- new.env(parent = emptyenv())
  observed$unsigned <- expected
  observed$ct <- list()
  testthat::with_mocked_bindings({
    materialized <- gate$materializer(
      fixture$input$policies$peer_a, fixture$input$fixture$manifest,
      list(), compute_commitment = TRUE, include_release = TRUE)
    expect_identical(materialized, fresh)
    expect_true(gate$producer_validator(
      producer = materialized,
      policy = fixture$input$policies$peer_a,
      manifest = fixture$input$fixture$manifest,
      contract = gate$source_contract))
    expect_identical(observed$ct, list(
      expected$source_vector_commitment,
      expected$source_vector_commitment))

    observed$unsigned <- expected
    observed$unsigned$catalog_sha256 <- strrep("e", 64L)
    expect_false(gate$producer_validator(
      producer = materialized,
      policy = fixture$input$policies$peer_a,
      manifest = fixture$input$fixture$manifest,
      contract = gate$source_contract))
  }, .dsvert_dp_gaussian_cross_source_producer = function(
      policy, manifest, resolved_snapshots, compute_commitment,
      include_release) {
    call <- as.list(sys.call())[-1L]
    expect_true(all(c(
      "compute_commitment", "include_release") %in% names(call)))
    expect_identical(compute_commitment, TRUE)
    expect_identical(include_release, TRUE)
    fresh
  }, .dsvert_dp_synopsis_source_vector_unsigned_from_producer_v1 = function(
      policy, manifest, producer, identity_pk) {
    expect_identical(producer, fresh)
    expect_identical(identity_pk, expected$source_identity_pk)
    observed$unsigned
  }, .dsvert_joint_dp_dsi_hex_equal = function(left, right) {
    observed$ct <- list(left, right)
    identical(left, right)
  }, .package = "dsVert")
})

test_that("A to B source mismatch fails before durable state or RNG", {
  skip_if_not(.synopsis_gate_available(), "RED: source context/gate missing")
  fixture <- .synopsis_gate_fixture(2L)
  .synopsis_gate_defer_store_cleanup(fixture$input, parent.frame())
  gate <- .synopsis_gate_call(fixture)
  transport <- .synopsis_gate_helpers$.synopsis_receipt_helpers$
    .synopsis_artifact_helpers
  tickets <- lapply(fixture$peers[1:2], function(peer) {
    .dsvert_dp_capsule_source_ticket_impl(
      fixture$input$manifest_json,
      .policy = fixture$input$policies[[peer]],
      .secret = fixture$input$secrets[[peer]],
      .signer = transport$.capsule_source_test_signer,
      .allocation_require = transport$.capsule_source_test_allocation_require,
      source_contract = gate$source_contract)
  })
  expected <- fixture$input$claim_set$claims$peer_a[
    setdiff(names(fixture$input$claim_set$claims$peer_a), "signature")]
  observed <- expected
  observed$source_vector_commitment <- strrep("2", 64L)
  real_hex_equal <- .dsvert_joint_dp_dsi_hex_equal
  events <- character()
  fresh <- list(reset = function() events <<- c(events, "reset"))
  opening <- .dsvert_dp_canonical_json(list(phase = "test_opening"))

  testthat::with_mocked_bindings(
    expect_error(.dsvert_dp_capsule_source_prepare_impl(
      fixture$input$manifest_json, tickets[[1L]], tickets[[2L]],
      opening, opening,
      .policy = fixture$input$policies$peer_a,
      .secret = fixture$input$secrets$peer_a,
      .resolved_snapshots = list(), .materializer = gate$materializer,
      .random_bytes = function(...) events <<- c(events, "rng"),
      .signer = transport$.capsule_source_test_signer,
      .verifier = transport$.capsule_source_test_verifier,
      .allocation_observer = transport$.capsule_source_test_allocation_observer,
      .producer_validator = gate$producer_validator,
      source_contract = gate$source_contract), "producer.*validation"),
    .dsvert_dp_gaussian_cross_source_producer = function(...) {
      events <<- c(events, "producer")
      fresh
    },
    .dsvert_dp_synopsis_source_vector_unsigned_from_producer_v1 = function(
        policy, manifest, producer, identity_pk) {
      expect_identical(producer, fresh)
      events <<- c(events, "unsigned")
      observed
    },
    .dsvert_joint_dp_dsi_hex_equal = function(left, right) {
      if (identical(left, observed$source_vector_commitment) &&
          identical(right, expected$source_vector_commitment)) {
        events <<- c(events, "ct")
        return(FALSE)
      }
      real_hex_equal(left, right)
    },
    .dsvert_dp_capsule_source_record_insert = function(...) {
      events <<- c(events, "durable")
      stop("durable state reached")
    }, .package = "dsVert")
  expect_false(any(c("durable", "rng") %in% events))
  expect_identical(events, c("producer", "unsigned", "ct", "reset"))
  rows <- .dsvert_dp_capsule_source_with_store(
    fixture$input$policies$peer_a, fixture$input$secrets$peer_a,
    function(connection) DBI::dbGetQuery(
      connection, "SELECT COUNT(*) AS n FROM source_outbound")$n[[1L]])
  expect_identical(as.integer(rows), 0L)
})
