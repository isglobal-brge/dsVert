.vector_allocator_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  expressions <- parse(testthat::test_path(
    "test-joint-dp-vector-capsule.R"))
  for (expression in expressions) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.vector_allocator_manifest_gate <- function(policy, manifest_json,
                                               secret = NULL) {
  list(
    cache_key = .dsvert_joint_dp_hash(list(
      protocol = "test-vector-manifest-cache-v1",
      manifest_json = manifest_json)),
    local_authority_sha256 = .dsvert_joint_dp_hash(list(
      protocol = "test-vector-local-authority-v1",
      peer_name = policy$peer_name,
      secret_sha256 = digest::digest(
        secret, algo = "sha256", serialize = FALSE))),
    manifest_sha256 = digest::digest(
      manifest_json, algo = "sha256", serialize = FALSE),
    manifest_json = manifest_json)
}

.vector_allocator_k3_fixture <- function() {
  fixture <- .vector_allocator_helpers$.vector_capsule_helpers$
    .capsule_source_test_fixture(3L)
  for (peer in fixture$peers) {
    key <- fixture$secrets[[peer]]
    fixture$policies[[peer]]$noise_root <- list(
      protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
      provider_id = "joint_dp_vector_k3_test_provider", epoch = 1,
      key_id = paste0("test_", substr(digest::digest(
        key, "sha256", serialize = FALSE), 1L, 32L)),
      hmac = local({
        private_key <- key
        function(message) digest::hmac(
          key = private_key, object = message,
          algo = "sha256", serialize = FALSE)
      }))
  }
  fixture$signer <-
    .vector_allocator_helpers$.vector_capsule_helpers$
      .capsule_source_test_signer
  fixture$verifier <- function(message, pin, signature, ...) {
    .vector_allocator_helpers$.vector_capsule_helpers$
      .capsule_source_test_verifier(message, pin, signature)
  }
  fixture
}

.vector_allocator_lifecycle <- function(fixture) {
  peers <- sort(fixture$peers[1:2], method = "radix")
  prepare <- list()
  prepare[[peers[[1L]]]] <-
    .dsvert_joint_dp_vector_allocation_prepare_impl(
      fixture$manifest_json, .policy = fixture$policies[[peers[[1L]]]],
      .secret = fixture$secrets[[peers[[1L]]]],
      .signer = fixture$signer, .verifier = fixture$verifier,
      .manifest_gate = .vector_allocator_manifest_gate)
  prepare[[peers[[2L]]]] <-
    .dsvert_joint_dp_vector_allocation_prepare_impl(
      fixture$manifest_json, prepare[[peers[[1L]]]],
      .policy = fixture$policies[[peers[[2L]]]],
      .secret = fixture$secrets[[peers[[2L]]]],
      .signer = fixture$signer, .verifier = fixture$verifier,
      .manifest_gate = .vector_allocator_manifest_gate)
  commit <- stats::setNames(lapply(peers, function(peer) {
    .dsvert_joint_dp_vector_allocation_commit_impl(
      prepare[[peers[[1L]]]], prepare[[peers[[2L]]]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier)
  }), peers)
  authorization <- stats::setNames(lapply(peers, function(peer) {
    .dsvert_joint_dp_vector_allocation_authorize_impl(
      commit[[peers[[1L]]]], commit[[peers[[2L]]]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier)
  }), peers)
  opening <- stats::setNames(lapply(peers, function(peer) {
    .dsvert_joint_dp_vector_allocation_open_impl(
      authorization[[peers[[1L]]]], authorization[[peers[[2L]]]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier)
  }), peers)
  list(
    peers = peers, prepare = prepare, commit = commit,
    authorization = authorization, opening = opening)
}

test_that("biomedical allocation proposals are entirely server-derived", {
  fixture <- .vector_allocator_helpers$.vector_capsule_fixture(FALSE)
  proposals <- lapply(fixture$peers[1:2], function(peer) {
    .dsvert_joint_dp_vector_allocator_proposal(
      fixture$policies[[peer]], fixture$manifest_json,
      fixture$secrets[[peer]], .vector_allocator_manifest_gate)
  })

  expect_identical(proposals[[1L]]$capsule_id,
                   fixture$manifests[[1L]]$capsule_identity$capsule_id)
  expect_identical(proposals[[1L]]$query_id, proposals[[1L]]$capsule_id)
  expect_identical(proposals[[1L]]$common_query,
                   proposals[[2L]]$common_query)
  expect_identical(proposals[[1L]]$mechanism_hash,
                   proposals[[2L]]$mechanism_hash)
  expect_false(identical(proposals[[1L]]$snapshot_binding,
                         proposals[[2L]]$snapshot_binding))
  expect_setequal(names(proposals[[1L]]), c(
    "capsule_id", "query_id", "common_query", "mechanism_hash",
    "sensitivity", "uses_delta", "snapshot_binding"))

  modified <- jsonlite::fromJSON(
    fixture$manifest_json, simplifyVector = FALSE)
  modified$workload$capsule_mechanism$sensitivity <- 1
  modified_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(modified))
  expect_error(.dsvert_joint_dp_vector_allocator_proposal(
    fixture$policies$peer_a, modified_json, fixture$secrets$peer_a,
    .vector_allocator_manifest_gate))
})

test_that("cross-signed allocation is mandatory, sticky and non-quota", {
  fixture <- .vector_allocator_helpers$.vector_capsule_fixture(FALSE)
  expect_error(.dsvert_joint_dp_vector_allocation_require(
    fixture$policies$peer_a, fixture$manifest_json,
    fixture$secrets$peer_a, fixture$verifier,
    .vector_allocator_manifest_gate),
    "not cross-signed|no matching cross-signed")
  absent <- tryCatch(.dsvert_joint_dp_vector_allocation_proof_impl(
    fixture$manifest_json, .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a, .verifier = fixture$verifier,
    .manifest_gate = .vector_allocator_manifest_gate), error = identity)
  expect_s3_class(absent, "dsvert_phase_not_ready")

  prepared <- .dsvert_joint_dp_vector_allocation_prepare_impl(
    fixture$manifest_json, .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .signer = fixture$signer, .verifier = fixture$verifier,
    .manifest_gate = .vector_allocator_manifest_gate)
  expect_true(nzchar(prepared))
  incomplete <- tryCatch(.dsvert_joint_dp_vector_allocation_proof_impl(
    fixture$manifest_json, .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a, .verifier = fixture$verifier,
    .manifest_gate = .vector_allocator_manifest_gate), error = identity)
  expect_s3_class(incomplete, "dsvert_phase_not_ready")

  lifecycle <- .vector_allocator_lifecycle(fixture)
  audits <- 0L
  original_audit <- .dsvert_joint_dp_allocator_forensic_audit
  certificates <- testthat::with_mocked_bindings(
    stats::setNames(lapply(lifecycle$peers, function(peer) {
      .dsvert_joint_dp_vector_allocation_require(
        fixture$policies[[peer]], fixture$manifest_json,
        fixture$secrets[[peer]], fixture$verifier,
        .vector_allocator_manifest_gate)
    }), lifecycle$peers),
    .dsvert_joint_dp_allocator_forensic_audit = function(...) {
      audits <<- audits + 1L
      original_audit(...)
    },
    .package = "dsVert")
  expect_identical(audits, length(lifecycle$peers))
  expect_true(all(vapply(certificates, `[[`, logical(1L), "authorized")))
  expect_true(all(vapply(certificates, function(value) {
    identical(value$history_gate, TRUE) &&
      identical(value$request_limit, FALSE) &&
      identical(value$operation_limit, TRUE) &&
      identical(value$data_access, FALSE)
  }, logical(1L))))
  proofs <- stats::setNames(lapply(lifecycle$peers, function(peer) {
    .dsvert_joint_dp_vector_allocation_proof_impl(
      fixture$manifest_json, .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]], .verifier = fixture$verifier,
      .manifest_gate = .vector_allocator_manifest_gate)
  }), lifecycle$peers)
  expect_identical(proofs, lifecycle$opening)

  replay <- .dsvert_joint_dp_vector_allocation_prepare_impl(
    fixture$manifest_json,
    .policy = fixture$policies[[lifecycle$peers[[1L]]]],
    .secret = fixture$secrets[[lifecycle$peers[[1L]]]],
    .signer = fixture$signer, .verifier = fixture$verifier,
    .manifest_gate = .vector_allocator_manifest_gate)
  expect_identical(replay, lifecycle$prepare[[lifecycle$peers[[1L]]]])
  status <- .dsvert_joint_dp_capsule_status(
    .policy = fixture$policies[[lifecycle$peers[[1L]]]],
    .secret = fixture$secrets[[lifecycle$peers[[1L]]]])
  expect_identical(status$composition_telemetry$capsules_created, 1)
  expect_identical(status$privacy_contract$operation_limit, TRUE)
  expect_identical(
    status$privacy_contract$history_can_deny_operation, TRUE)

  policy <- fixture$policies[[lifecycle$peers[[1L]]]]
  secret <- fixture$secrets[[lifecycle$peers[[1L]]]]
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(if (!is.null(handle)) {
    .dsvert_joint_dp_close_ledger(handle)
  }, add = TRUE)
  record <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, secret, fixture$verifier)
    .dsvert_joint_dp_load(
      handle$connection,
      fixture$manifests[[1L]]$capsule_identity$capsule_id, secret)
  })
  expect_identical(record$state, "open_authorized")
  record$opening_token <- NULL
  record_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(record))
  row_mac <- .dsvert_joint_dp_row_mac(secret, record_json)
  allocator_state <- .dsvert_joint_dp_allocator_state_read(
    handle$connection, secret)
  allocator_state$tail_row_mac <- row_mac
  changed <- DBI::dbExecute(handle$connection, paste(
    "UPDATE joint_records SET record_json = ?, row_mac = ?",
    "WHERE query_id = ?"), params = list(
      record_json, row_mac, record$query_id))
  expect_identical(as.integer(changed), 1L)
  .dsvert_joint_dp_allocator_state_write(
    handle$connection, secret, allocator_state)
  .dsvert_joint_dp_close_ledger(handle)
  handle <- NULL
  malformed <- tryCatch(.dsvert_joint_dp_vector_allocation_proof_impl(
    fixture$manifest_json, .policy = policy, .secret = secret,
    .verifier = fixture$verifier,
    .manifest_gate = .vector_allocator_manifest_gate), error = identity)
  expect_false(inherits(malformed, "dsvert_phase_not_ready"))
  expect_s3_class(malformed, "error")
})

test_that("allocation rejects relay tamper and non-designated peers", {
  fixture <- .vector_allocator_helpers$.vector_capsule_fixture(FALSE)
  lifecycle <- .vector_allocator_lifecycle(fixture)
  changed <- jsonlite::fromJSON(
    lifecycle$commit[[lifecycle$peers[[1L]]]], simplifyVector = FALSE)
  changed$new_chain <- strrep("f", 64L)
  changed_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(changed))
  expect_error(.dsvert_joint_dp_vector_allocation_authorize_impl(
    changed_json, lifecycle$commit[[lifecycle$peers[[2L]]]],
    .policy = fixture$policies[[lifecycle$peers[[1L]]]],
    .secret = fixture$secrets[[lifecycle$peers[[1L]]]],
    .signer = fixture$signer, .verifier = fixture$verifier))

  source_fixture <- .vector_allocator_k3_fixture()
  expect_error(.dsvert_joint_dp_vector_allocator_proposal(
    source_fixture$policies$peer_c, source_fixture$manifest_json,
    source_fixture$secrets$peer_c, .vector_allocator_manifest_gate),
    "designated noise peer")

  k3_lifecycle <- .vector_allocator_lifecycle(source_fixture)
  observer <- .dsvert_joint_dp_vector_allocation_observer_require(
    source_fixture$policies$peer_c, source_fixture$manifest_json,
    k3_lifecycle$opening[[k3_lifecycle$peers[[1L]]]],
    k3_lifecycle$opening[[k3_lifecycle$peers[[2L]]]],
    source_fixture$secrets$peer_c, source_fixture$verifier,
    .vector_allocator_manifest_gate)
  expect_true(observer$authorized)
  expect_false(observer$relay_is_authority)
  expect_identical(observer$designated_noise_peers,
                   k3_lifecycle$peers)

  tampered_opening <- jsonlite::fromJSON(
    k3_lifecycle$opening[[k3_lifecycle$peers[[1L]]]],
    simplifyVector = FALSE)
  tampered_opening$allocation_index <- "999"
  tampered_opening_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(tampered_opening))
  expect_error(.dsvert_joint_dp_vector_allocation_observer_require(
    source_fixture$policies$peer_c, source_fixture$manifest_json,
    tampered_opening_json,
    k3_lifecycle$opening[[k3_lifecycle$peers[[2L]]]],
    source_fixture$secrets$peer_c, source_fixture$verifier,
    .vector_allocator_manifest_gate))
  expect_error(.dsvert_joint_dp_vector_allocation_observer_require(
    source_fixture$policies$peer_c, source_fixture$manifest_json,
    k3_lifecycle$opening[[k3_lifecycle$peers[[1L]]]],
    k3_lifecycle$opening[[k3_lifecycle$peers[[1L]]]],
    source_fixture$secrets$peer_c, source_fixture$verifier,
    .vector_allocator_manifest_gate))

  wrong_manifest <- source_fixture$manifest_json
  substr(wrong_manifest, nchar(wrong_manifest), nchar(wrong_manifest)) <- " "
  expect_error(.dsvert_joint_dp_vector_allocation_observer_require(
    source_fixture$policies$peer_c, wrong_manifest,
    k3_lifecycle$opening[[k3_lifecycle$peers[[1L]]]],
    k3_lifecycle$opening[[k3_lifecycle$peers[[2L]]]],
    source_fixture$secrets$peer_c, source_fixture$verifier,
    .vector_allocator_manifest_gate))
})
