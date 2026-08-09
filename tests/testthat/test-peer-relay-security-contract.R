.peer_relay_matrix_path <- function() {
  candidates <- c(
    .dsvert_test_package_file(
      "inst", "docs", "peer_relay_security_matrix.json"),
    system.file(
      "docs", "peer_relay_security_matrix.json", package = "dsVert"))
  candidates <- candidates[file.exists(candidates)]
  if (!length(candidates)) stop("Peer-relay security matrix is missing.")
  candidates[[1L]]
}

.peer_relay_test_b64 <- function(seed) {
  raw <- as.raw((seq_len(32L) + as.integer(seed)) %% 256L)
  base64_to_base64url(gsub("[\r\n]", "", jsonlite::base64_enc(raw)))
}

test_that("the peer-relay security matrix covers the complete active surface", {
  matrix <- jsonlite::fromJSON(
    .peer_relay_matrix_path(), simplifyVector = FALSE)
  expect_identical(
    matrix$schema_version, "dsvert-peer-relay-security-matrix-v1")
  expect_identical(matrix$threat_model$relay, "fully_malicious")
  expect_identical(
    matrix$threat_model$covered_outcome,
    "authentic_delivery_exact_duplicate_or_abort")
  expect_false(matrix$threat_model$malicious_peer_security_claimed)
  expect_false(matrix$threat_model$collusion_security_claimed)
  expect_true(all(c(
    "physical_timing", "availability", "poll_count", "retransmission_count",
    "scheduler_behavior", "backpressure_incidence", "denial_of_service") %in%
    unlist(matrix$threat_model$excluded_observables, use.names = FALSE)))

  channels <- matrix$channels
  ids <- vapply(channels, `[[`, character(1L), "id")
  expect_identical(anyDuplicated(ids), 0L)
  expect_setequal(ids, c(
    "generic_dsi_relay_substrate",
    "typed_blob_capability_transport",
    "padded_psi_peer_frames",
    "exact_gc_peer_frames",
    "dp_capsule_source_shares",
    "dp_cross_owner_share_frames",
    "joint_dp_vector_final_shares",
    "dp_manifest_allocation_control",
    "dp_release_control",
    "legacy_generic_blob_routes",
    "legacy_transport_key_routes",
    "legacy_unpadded_psi_routes"))

  required_properties <- c(
    "sender_pinned", "recipient_scope_bound", "cryptographic_integrity",
    "session_bound", "application_scope_bound", "ordering_bound",
    "replay_safe", "idempotent_retry")
  active <- Filter(function(channel) {
    channel$status %in% c("production_active", "internal_substrate")
  }, channels)
  for (channel in active) {
    for (property in required_properties) {
      expect_true(
        isTRUE(channel[[property]]),
        info = paste(channel$id, "must satisfy", property))
    }
    expect_identical(
      channel$relay_tamper_outcome,
      "authentic_delivery_exact_duplicate_or_abort",
      info = channel$id)
    expect_identical(channel$malicious_peer_security, "not_claimed")
    if (isTRUE(channel$private_payload)) {
      expect_false(channel$relay_plaintext_private_data, info = channel$id)
      expect_true(channel$confidentiality %in% c(
        "recipient_aead", "authenticated_encrypted_protocol",
        "capability_specific_recipient_aead_or_opaque_cryptographic"),
        info = channel$id)
    }
  }

  production <- Filter(function(channel) {
    identical(channel$status, "production_active")
  }, channels)
  exposed <- unique(unlist(lapply(
    production, `[[`, "remote_endpoints"), use.names = FALSE))
  local_only <- c(
    "dsvertSecurityProfileDS", "dsvertTransportProbeDS",
    "dsvertIdentityPkDS", "dsvertNumericPolicyDS", "dsvertColNamesDS",
    "dsvertJointDPCapsuleStatusDS", "dsvertPublicFixedCohortCountDS")
  expect_setequal(
    exposed,
    setdiff(.dsvert_disclosure_safe_remote_methods, local_only))

  blocked <- Filter(function(channel) {
    identical(channel$status, "blocked_by_single_profile")
  }, channels)
  blocked_endpoints <- unique(unlist(lapply(
    blocked, `[[`, "remote_endpoints"), use.names = FALSE))
  expect_length(intersect(
    blocked_endpoints, .dsvert_disclosure_safe_remote_methods), 0L)
  expect_true(all(vapply(blocked, function(channel) {
    identical(channel$relay_security_claim, "not_covered")
  }, logical(1L))))
})

test_that("typed peer manifests bind every peer for K=2, K=3 and K=5", {
  for (k in c(2L, 3L, 5L)) {
    peer_names <- paste0("site_", seq_len(k))
    identities <- stats::setNames(lapply(seq_len(k), function(index) {
      list(identity_pk = .peer_relay_test_b64(index))
    }), peer_names)
    transports <- stats::setNames(lapply(seq_len(k), function(index) {
      .peer_relay_test_b64(40L + index)
    }), peer_names)

    binding <- .dsvert_typed_blob_peer_binding(identities, transports)
    expect_identical(
      binding,
      .dsvert_typed_blob_peer_binding(
        identities[rev(peer_names)], transports[rev(peer_names)]),
      info = paste("canonical K", k))

    for (peer in peer_names) {
      substituted <- identities
      substituted[[peer]]$identity_pk <- .peer_relay_test_b64(90L + k)
      expect_false(identical(
        binding,
        .dsvert_typed_blob_peer_binding(substituted, transports)),
        info = paste("identity substitution K", k, peer))

      rotated <- transports
      rotated[[peer]] <- .peer_relay_test_b64(120L + k)
      expect_false(identical(
        binding,
        .dsvert_typed_blob_peer_binding(identities, rotated)),
        info = paste("transport substitution K", k, peer))
    }

    ss <- new.env(parent = emptyenv())
    ss$.typed_blob_self_name <- peer_names[[1L]]
    ss$.typed_blob_peer_identity_pks <- lapply(
      identities[-1L], `[[`, "identity_pk")
    ss$.typed_blob_peer_binding_digest <- binding
    ss$peer_transport_pks <- lapply(
      transports[-1L], .base64url_to_base64)
    for (peer in peer_names[-1L]) {
      expect_identical(
        .dsvert_typed_blob_recipient_name(ss, transports[[peer]]), peer,
        info = paste("unique recipient K", k, peer))
    }
    if (k >= 3L) {
      ambiguous <- ss
      ambiguous$peer_transport_pks[[2L]] <-
        ambiguous$peer_transport_pks[[1L]]
      expect_error(
        .dsvert_typed_blob_recipient_name(
          ambiguous, transports[[peer_names[[2L]]]]),
        "not uniquely bound")
    }
  }
})

test_that("exact-GC pair bindings commit the full K=2, K=3 and K=5 pinset", {
  pinset_digest <- function(identities) {
    identities <- identities[order(names(identities), method = "radix")]
    digest::digest(
      .dsvert_dp_canonical_json(as.list(identities)),
      algo = "sha256", serialize = FALSE)
  }
  contract <- function(k, identities, transports) {
    peers <- names(identities)
    designated <- sort(c(peers[[1L]], peers[[k]]), method = "radix")
    list(
      version = "dsvert-exact-gc-designated-binding-v2",
      capability_id = .DSVERT_EXACT_GC_CAPABILITY,
      session_id = "12345678-1234-4234-9234-123456789abc",
      consortium_id = paste0("consortium-k", k),
      full_peer_pinset_sha256 = pinset_digest(identities),
      designated_peers = as.list(designated),
      designated_peer_pinset = as.list(identities[designated]),
      identity_pks = as.list(identities[designated]),
      transport_pks = as.list(transports[designated]))
  }

  for (k in c(2L, 3L, 5L)) {
    peers <- paste0("site_", seq_len(k))
    identities <- stats::setNames(vapply(
      seq_len(k), .peer_relay_test_b64, character(1L)), peers)
    transports <- stats::setNames(vapply(
      40L + seq_len(k), .peer_relay_test_b64, character(1L)), peers)
    original <- contract(k, identities, transports)
    original_digest <- .exact_gc_peer_binding_contract_digest(original)
    expect_match(original_digest, "^[0-9a-f]{64}$")

    changed <- identities
    changed_peer <- if (k > 2L) peers[[2L]] else peers[[1L]]
    changed[[changed_peer]] <- .peer_relay_test_b64(200L + k)
    changed_contract <- contract(k, changed, transports)
    expect_false(identical(
      original$full_peer_pinset_sha256,
      changed_contract$full_peer_pinset_sha256),
      info = paste("full pinset K", k))
    expect_false(identical(
      original_digest,
      .exact_gc_peer_binding_contract_digest(changed_contract)),
      info = paste("binding digest K", k))
  }
})
