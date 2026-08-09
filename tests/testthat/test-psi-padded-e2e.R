.psi_padded_test_seed <- function(byte) {
  gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(byte, 32L))))
}

.psi_padded_test_with_identity <- function(seed, trusted, code,
                                           peer_name = NULL,
                                           source_data = NULL,
                                           source_data_name = "D",
                                           source_id_col = "id",
                                           source_id = "test-logical-cohort",
                                           source_version = "v1",
                                           source_purpose =
                                             "patient-record-alignment-v1") {
  settings <- list(
    dsvert.identity_seed = seed,
    dsvert.trusted_peers = trusted,
    dsvert.peer_name = peer_name)
  if (!is.null(source_data)) {
    settings <- c(settings, .psi_padded_test_source_options(
      source_data, source_data_name, source_id_col, source_id,
      source_version, source_purpose))
  }
  old <- options(settings)
  on.exit(options(old), add = TRUE)
  force(code)
}

.psi_padded_test_exact_binary <- local({
  cached <- NULL
  function() {
    if (exists(".exact_gc_test_binary", inherits = TRUE)) {
      return(get(".exact_gc_test_binary", inherits = TRUE)())
    }
    if (!is.null(cached) && file.exists(cached)) return(cached)
    source_candidates <- file.path(
      .dsvert_test_source_roots(), "inst", "dsvert-mpc")
    source_candidates <- source_candidates[
      file.exists(file.path(source_candidates, "main.go"))]
    if (!length(source_candidates)) {
      cached <<- .findMpcBinary()
      return(cached)
    }
    go <- Sys.which("go")
    skip_if(!nzchar(go), "Go toolchain is required for padded PSI exact AND")
    source <- source_candidates[[1L]]
    binary <- tempfile("dsvert-mpc-psi-padded-test-")
    status <- withr::with_dir(source, system2(
      go, c("build", "-o", binary, "."), stdout = TRUE, stderr = TRUE))
    skip_if(!identical(attr(status, "status"), NULL) &&
              !identical(attr(status, "status"), 0L),
            paste(status, collapse = "\n"))
    Sys.chmod(binary, mode = "0700")
    cached <<- binary
    binary
  }
})

.psi_padded_test_exact_pump <- function(
    ss_left, ss_right, session_id, operation_id, seeds) {
  if (exists(".exact_gc_test_pump", inherits = TRUE)) {
    return(get(".exact_gc_test_pump", inherits = TRUE)(
      ss_left, ss_right, session_id, operation_id,
      seeds[[1L]], seeds[[2L]]))
  }
  sessions <- list(ss_left, ss_right)
  operation_states <- lapply(
    sessions, .exact_gc_operation_state, operation_id = operation_id)
  ids <- vapply(operation_states, `[[`, character(1L), "self_peer_id")
  names(sessions) <- names(operation_states) <- ids
  seed_by_id <- stats::setNames(as.list(seeds), ids)
  offsets <- stats::setNames(c(0, 0), ids)
  pending <- stats::setNames(vector("list", 2L), ids)
  for (iteration in seq_len(10000L)) {
    responses <- list()
    for (target in ids) {
      source <- setdiff(ids, target)
      delivery <- pending[[source]]
      fields <- if (is.null(delivery)) list(
        delivery_offset = 0,
        delivery_chunk_bytes = 0,
        delivery_payload_hash = "",
        delivery_payload = "",
        delivery_signature = "") else list(
          delivery_offset = delivery$offset,
          delivery_chunk_bytes = delivery$chunk_bytes,
          delivery_payload_hash = delivery$payload_hash,
          delivery_payload = delivery$payload,
          delivery_signature = delivery$signature)
      responses[[target]] <- .psi_padded_test_with_identity(
        seed_by_id[[target]], NULL,
        do.call(.exact_gc_exchange_impl, c(list(
          ss = sessions[[target]], session_id = session_id,
          operation_id = operation_id, peer_id = target,
          read_offset = offsets[[target]]), fields,
          list(long_poll = FALSE))))
    }
    for (target in ids) {
      source <- setdiff(ids, target)
      delivery <- pending[[source]]
      if (!is.null(delivery)) {
        expected <- delivery$offset + delivery$chunk_bytes
        if (responses[[target]]$inbound_size != expected) {
          stop("Padded PSI exact AND returned a conflicting acknowledgment.")
        }
        offsets[[source]] <- expected
        pending[[source]] <- NULL
      }
    }
    for (source in ids) {
      envelope <- responses[[source]]$outbound
      if (is.null(envelope) || envelope$offset < offsets[[source]]) next
      if (envelope$offset != offsets[[source]]) {
        stop("Padded PSI exact AND returned a byte gap.")
      }
      if (is.null(pending[[source]])) {
        pending[[source]] <- envelope
      } else if (!identical(pending[[source]], envelope)) {
        stop("Padded PSI exact AND changed an unacknowledged envelope.")
      }
    }
    complete <- vapply(responses, function(value) {
      identical(value$state, "complete") && isTRUE(value$stored)
    }, logical(1L))
    if (all(complete) && all(vapply(pending, is.null, logical(1L)))) {
      return(invisible(iteration))
    }
    Sys.sleep(0.002)
  }
  stop("Padded PSI exact AND integration pump did not converge.")
}

.psi_padded_test_run_k2 <- function(
    ids_a, ids_b, suffix, source_version = "v1",
    seed_bytes = c(alpha = 31L, beta = 47L)) {
  stopifnot(is.numeric(seed_bytes), length(seed_bytes) == 2L,
            !is.null(names(seed_bytes)),
            identical(sort(names(seed_bytes)), c("alpha", "beta")))
  seeds <- vapply(seed_bytes, .psi_padded_test_seed, character(1L))
  identities <- lapply(seeds, function(seed) .callMpcTool(
    "derive-identity", list(seed = seed)))
  data <- list(
    alpha = data.frame(id = ids_a, a = seq_along(ids_a),
                       stringsAsFactors = FALSE),
    beta = data.frame(id = rev(ids_b), b = seq_along(ids_b),
                      stringsAsFactors = FALSE))
  states <- list(alpha = new.env(parent = emptyenv()),
                 beta = new.env(parent = emptyenv()))
  session_id <- paste0("12345678-1234-4234-9234-123456789ab", suffix)
  operation_id <- paste0("op_", strrep(suffix, 32L))
  offers <- lapply(names(states), function(peer) {
      .psi_padded_test_with_identity(
      seeds[[peer]], c(),
      .psi_padded_init_impl(
        states[[peer]], data[[peer]], "D", "id", session_id, operation_id),
      source_data = data[[peer]], source_version = source_version)
  })
  names(offers) <- names(states)
  bound <- lapply(names(states), function(peer) {
    other <- setdiff(names(states), peer)
    trusted <- stats::setNames(
      identities[[other]]$identity_pk, other)
    .psi_padded_test_with_identity(
      seeds[[peer]], trusted,
      .psi_padded_bind_impl(states[[peer]], offers, names(states)),
      peer_name = peer)
  })
  names(bound) <- names(states)
  receipts <- lapply(bound, `[[`, "receipt")
  for (peer in names(states)) {
    .psi_padded_confirm_impl(states[[peer]], receipts)
    .psi_padded_prepare_impl(states[[peer]], data[[peer]])
  }
  contract <- states$alpha$.psi_padded_state$contract
  reference <- contract$reference_peer
  target <- setdiff(names(states), reference)

  reference_export <- .psi_padded_test_with_identity(
    seeds[[reference]], NULL,
    .psi_padded_reference_export_impl(states[[reference]], target))
  target_export <- .psi_padded_test_with_identity(
    seeds[[target]], NULL,
    .psi_padded_target_process_impl(
      states[[target]], reference_export$envelope))
  double_export <- .psi_padded_test_with_identity(
    seeds[[reference]], NULL,
    .psi_padded_reference_double_impl(
      states[[reference]], target, target_export$envelope))
  membership <- .psi_padded_test_with_identity(
    seeds[[target]], NULL,
    .psi_padded_target_match_impl(
      states[[target]], double_export$envelope))
  for (compute in contract$compute_peers) {
    transport <- .psi_padded_publish_envelope(
      states[[target]], membership$envelopes[[compute]],
      .psi_padded_membership_context(
        states[[target]]$.psi_padded_state, target, compute),
      force_relay = FALSE)
    incoming <- .psi_padded_resolve_envelope(
      states[[compute]],
      if (identical(transport$transport, "inline")) {
        transport$envelope
      } else "",
      if (identical(transport$transport, "local")) {
        # DSI carries this descriptor through JSON. Whole-valued doubles are
        # decoded as integers, which is semantically equivalent and must not
        # invalidate an otherwise exact authenticated transport binding.
        jsonlite::fromJSON(
          .psi_padded_canonical_json(transport$relay),
          simplifyVector = FALSE)
      } else NULL,
      .psi_padded_membership_context(
        states[[compute]]$.psi_padded_state, target, compute))
    .psi_padded_membership_accept_impl(
      states[[compute]], target, incoming)
  }
  sums <- lapply(contract$compute_peers, function(peer) {
    states[[peer]]$.psi_padded_state$membership_sum_share
  })
  global <- .psi_padded_and_reference(sums[[1L]], sums[[2L]], 1L)
  ref_state <- states[[reference]]$.psi_padded_state
  ref_state$global_membership_chunks <- list(`1` = global)
  states[[reference]]$.psi_padded_state <- ref_state

  final <- .psi_padded_test_with_identity(
    seeds[[reference]], NULL,
    .psi_padded_final_prepare_impl(states[[reference]]))
  aligned <- list()
  aligned[[reference]] <- .psi_padded_filter_impl(
    states[[reference]], data[[reference]])
  aligned[[target]] <- .psi_padded_filter_impl(
    states[[target]], data[[target]], final$envelopes[[target]])
  attestations <- lapply(names(states), function(peer) {
    .psi_padded_attestation_impl(states[[peer]], aligned[[peer]])
  })
  names(attestations) <- names(states)
  list(
    contract = contract, states = states, data = data, seeds = seeds,
    identities = identities, aligned = aligned, attestations = attestations,
    visible_lengths = c(
      reference = nchar(reference_export$envelope, type = "bytes"),
      target = nchar(target_export$envelope, type = "bytes"),
      doubled = nchar(double_export$envelope, type = "bytes"),
      membership_1 = nchar(membership$envelopes[[1L]], type = "bytes"),
      membership_2 = nchar(membership$envelopes[[2L]], type = "bytes"),
      final = nchar(final$envelopes[[target]], type = "bytes")))
}

.psi_padded_test_run_multi <- function(
    ids_by_peer, suffix, source_version = "v1") {
  stopifnot(is.list(ids_by_peer), length(ids_by_peer) >= 2L,
            length(ids_by_peer) <= 5L, !is.null(names(ids_by_peer)))
  peers <- names(ids_by_peer)
  seed_bytes <- c(23L, 59L, 97L, 131L, 173L)[seq_along(peers)]
  seeds <- stats::setNames(lapply(seed_bytes, .psi_padded_test_seed), peers)
  identities <- lapply(seeds, function(seed) .callMpcTool(
    "derive-identity", list(seed = seed)))
  data <- stats::setNames(lapply(peers, function(peer) {
    value <- data.frame(
      id = ids_by_peer[[peer]], value = seq_along(ids_by_peer[[peer]]),
      stringsAsFactors = FALSE)
    names(value)[[2L]] <- paste0("value_", peer)
    value
  }), peers)
  states <- stats::setNames(lapply(peers, function(peer) {
    new.env(parent = emptyenv())
  }), peers)
  session_id <- paste0("22345678-1234-4234-9234-123456789ab", suffix)
  operation_id <- paste0("op_", strrep(suffix, 32L))
  offers <- stats::setNames(lapply(peers, function(peer) {
    .psi_padded_test_with_identity(
      seeds[[peer]], c(), .psi_padded_init_impl(
        states[[peer]], data[[peer]], "D", "id", session_id, operation_id),
      source_data = data[[peer]], source_version = source_version)
  }), peers)
  bound <- stats::setNames(lapply(peers, function(peer) {
    others <- setdiff(peers, peer)
    trusted <- stats::setNames(vapply(
      identities[others], `[[`, character(1L), "identity_pk"), others)
    .psi_padded_test_with_identity(
      seeds[[peer]], trusted,
      .psi_padded_bind_impl(states[[peer]], offers, peers),
      peer_name = peer)
  }), peers)
  receipts <- lapply(bound, `[[`, "receipt")
  for (peer in peers) {
    .psi_padded_confirm_impl(states[[peer]], receipts)
    .psi_padded_prepare_impl(states[[peer]], data[[peer]])
  }
  contract <- states[[1L]]$.psi_padded_state$contract
  reference <- contract$reference_peer
  memberships <- list()
  pair_lengths <- list()
  for (target in .psi_padded_targets(contract)) {
    reference_export <- .psi_padded_test_with_identity(
      seeds[[reference]], NULL,
      .psi_padded_reference_export_impl(states[[reference]], target))
    target_export <- .psi_padded_test_with_identity(
      seeds[[target]], NULL,
      .psi_padded_target_process_impl(
        states[[target]], reference_export$envelope))
    double_export <- .psi_padded_test_with_identity(
      seeds[[reference]], NULL,
      .psi_padded_reference_double_impl(
        states[[reference]], target, target_export$envelope))
    membership <- .psi_padded_test_with_identity(
      seeds[[target]], NULL,
      .psi_padded_target_match_impl(
        states[[target]], double_export$envelope))
    memberships[[target]] <- membership$envelopes
    pair_lengths[[target]] <- c(
      reference = nchar(reference_export$envelope, type = "bytes"),
      target = nchar(target_export$envelope, type = "bytes"),
      doubled = nchar(double_export$envelope, type = "bytes"),
      membership = vapply(
        membership$envelopes, nchar, integer(1L), type = "bytes"))
    for (compute in contract$compute_peers) {
      .psi_padded_membership_accept_impl(
        states[[compute]], target, membership$envelopes[[compute]])
    }
  }
  sums <- lapply(contract$compute_peers, function(peer) {
    states[[peer]]$.psi_padded_state$membership_sum_share
  })
  global <- .psi_padded_and_reference(
    sums[[1L]], sums[[2L]], length(contract$peer_names) - 1L)
  ref_state <- states[[reference]]$.psi_padded_state
  ref_state$global_membership_chunks <- list(`1` = global)
  states[[reference]]$.psi_padded_state <- ref_state
  final <- .psi_padded_test_with_identity(
    seeds[[reference]], NULL,
    .psi_padded_final_prepare_impl(states[[reference]]))
  aligned <- list()
  for (peer in peers) {
    aligned[[peer]] <- .psi_padded_filter_impl(
      states[[peer]], data[[peer]],
      if (identical(peer, reference)) NULL else final$envelopes[[peer]])
  }
  list(
    contract = contract, states = states, data = data, seeds = seeds,
    identities = identities, memberships = memberships,
    pair_lengths = pair_lengths, final = final, aligned = aligned)
}

test_that("padded PSI bind requires a server-authoritative local name", {
  peers <- c("alpha", "beta")
  seeds <- c(
    alpha = .psi_padded_test_seed(181L),
    beta = .psi_padded_test_seed(197L))
  identities <- lapply(seeds, function(seed) .callMpcTool(
    "derive-identity", list(seed = seed)))
  states <- stats::setNames(lapply(peers, function(peer) {
    new.env(parent = emptyenv())
  }), peers)
  data <- stats::setNames(lapply(peers, function(peer) {
    data.frame(id = c("shared", peer), stringsAsFactors = FALSE)
  }), peers)
  session_id <- "32345678-1234-4234-9234-123456789abc"
  operation_id <- paste0("op_", strrep("9", 32L))
  offers <- stats::setNames(lapply(peers, function(peer) {
    .psi_padded_test_with_identity(
      seeds[[peer]], c(), .psi_padded_init_impl(
        states[[peer]], data[[peer]], "D", "id",
        session_id, operation_id), source_data = data[[peer]])
  }), peers)
  trusted <- c(beta = identities$beta$identity_pk)
  expect_error(.psi_padded_test_with_identity(
    seeds[["alpha"]], trusted,
    .psi_padded_bind_impl(states$alpha, offers, peers),
    peer_name = NULL),
    "server-authoritative logical site name")
  expect_null(states$alpha$.psi_padded_state$contract)
})

test_that("padded PSI production bootstraps reject a different authorized purpose", {
  peers <- c("alpha", "beta")
  seeds <- c(
    alpha = .psi_padded_test_seed(211L),
    beta = .psi_padded_test_seed(223L))
  identities <- lapply(seeds, function(seed) .callMpcTool(
    "derive-identity", list(seed = seed)))
  states <- stats::setNames(lapply(peers, function(peer) {
    new.env(parent = emptyenv())
  }), peers)
  data <- stats::setNames(lapply(peers, function(peer) {
    data.frame(id = c("shared", peer), stringsAsFactors = FALSE)
  }), peers)
  session_id <- "72345678-1234-4234-9234-123456789abc"
  operation_id <- paste0("op_", strrep("7", 32L))
  offers <- stats::setNames(lapply(peers, function(peer) {
    .psi_padded_test_with_identity(
      seeds[[peer]], c(), .psi_padded_init_impl(
        states[[peer]], data[[peer]], "D", "id", session_id, operation_id),
      source_data = data[[peer]],
      source_purpose = if (identical(peer, "alpha")) {
        "patient-record-alignment-v1"
      } else {
        "different-analysis-purpose-v1"
      })
  }), peers)
  trusted <- c(beta = identities$beta$identity_pk)

  expect_error(
    .psi_padded_test_with_identity(
      seeds[["alpha"]], trusted,
      .psi_padded_bind_impl(states$alpha, offers, peers),
      peer_name = "alpha"),
    "server-owned policy")
  expect_null(states$alpha$.psi_padded_state$contract)
})

test_that("fixed-capacity pinned PSI completes K=2 with exact canonical order", {
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only")
  on.exit(options(old), add = TRUE)
  result <- .psi_padded_test_run_k2(
    sprintf("id-%02d", 1:12), sprintf("id-%02d", 4:15), "a")
  reference <- result$contract$reference_peer
  target <- setdiff(names(result$aligned), reference)
  expected <- if (identical(reference, "alpha")) {
    sprintf("id-%02d", 4:12)
  } else {
    rev(sprintf("id-%02d", 4:12))
  }
  expect_identical(result$aligned[[reference]]$id, expected)
  expect_identical(result$aligned[[target]]$id,
                   result$aligned[[reference]]$id)
  expect_identical(result$attestations[[1L]], result$attestations[[2L]])
  visible <- result$attestations[[1L]]
  expect_named(visible, c(
    "attestation_version", "alignment_attested", "alignment_protocol",
    "attestation_id", "contract_hash", "policy_id", "alignment_purpose",
    "dataset_id", "dataset_version", "id_column", "source_binding_id",
    "pinset_id", "capacity_bucket",
    "relay_frame_bytes", "inline_max_bytes", "peer_count",
    "reference_peer", "compute_peers"))
  expect_false(any(c(
    "n", "n_common", "hash", "snapshot", "token", "indices",
    "permutation") %in% names(visible)))

  target_state <- result$states[[target]]$.psi_padded_state
  relay_context <- .psi_padded_membership_context(
    target_state, target, target)
  relay_operation <- .psi_padded_relay_operation(relay_context)
  relay_descriptor <- .psi_padded_relay_descriptor(
    target_state, relay_context, charToRaw("sealed"), relay_operation)
  relay_descriptor <- jsonlite::fromJSON(
    .psi_padded_canonical_json(relay_descriptor), simplifyVector = FALSE)
  expect_type(relay_descriptor$frame_bytes, "integer")
  expect_silent(.psi_padded_validate_relay_descriptor(
    relay_descriptor, target_state, relay_context))
  for (invalid_frame_bytes in list(
      relay_descriptor$frame_bytes + 0.5, -1L, 2^53, "491520")) {
    invalid_descriptor <- relay_descriptor
    invalid_descriptor$frame_bytes <- invalid_frame_bytes
    expect_error(.psi_padded_validate_relay_descriptor(
      invalid_descriptor, target_state, relay_context),
      "Invalid padded PSI relay descriptor")
  }

  descriptors <- lapply(result$aligned, dsvertDPDatasetDescriptor,
                        id = "test-logical-cohort", version = "v1")
  expect_length(unique(vapply(
    descriptors, `[[`, character(1L), "alignment_manifest_hash")), 1L)
  expect_length(unique(vapply(
    descriptors, `[[`, character(1L), "snapshot_sha256")), 2L)
  expect_true(all(vapply(descriptors, function(value) {
    identical(value$alignment_manifest_version, 3L)
  }, logical(1L))))

  for (peer in names(result$aligned)) {
    aligned_peer <- result$aligned[[peer]]
    descriptor <- descriptors[[peer]]
    policy <- list(
      datasets = list(DA = descriptor), patient_column = "id",
      require_alignment_manifest = TRUE, domain = "cohort-release-v1")
    expect_silent(.dsvert_dp_dataset_binding(
      policy, "DA", aligned_peer, as.raw(seq_len(32L))))
    frozen <- .dsvert_dp_freeze_snapshot_frame(aligned_peer)
    expect_false(is.null(attr(
      frozen, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)))
    expect_false(is.null(attr(
      frozen, .PSI_PADDED_ATTESTATION_ATTRIBUTE, exact = TRUE)))
    expect_silent(.dsvert_dp_dataset_binding(
      policy, "DA", frozen, as.raw(seq_len(32L))))

    changed <- aligned_peer
    value_column <- setdiff(names(changed), "id")[[1L]]
    changed[[value_column]][[1L]] <- changed[[value_column]][[1L]] + 1
    expect_error(.dsvert_dp_dataset_binding(
      policy, "DA", changed, as.raw(seq_len(32L))),
      "custodian-approved DP snapshot")
    reordered <- aligned_peer[rev(seq_len(nrow(aligned_peer))), , drop = FALSE]
    expect_error(.dsvert_dp_dataset_binding(
      policy, "DA", reordered, as.raw(seq_len(32L))),
      "custodian-approved DP snapshot|authentication failed")
  }
})

.psi_padded_test_registry_context <- function(
    result, peer, state_dir, version, code) {
  others <- setdiff(names(result$identities), peer)
  trusted <- stats::setNames(vapply(
    result$identities[others], `[[`, character(1L), "identity_pk"), others)
  old <- options(
    dsvert.state_dir = state_dir,
    dsvert.identity_seed = result$seeds[[peer]],
    dsvert.trusted_peers = trusted,
    dsvert.peer_name = peer,
    dsvert.dp.patient_column = "id",
    dsvert.dp.datasets = list(DA = list(
      id = "test-logical-cohort", version = version)))
  on.exit(options(old), add = TRUE)
  force(code)
}

.psi_padded_test_attestation_ds <- function(
    result, peer, session_id = result$contract$session_id,
    data = result$aligned[[peer]]) {
  evaluation <- list2env(
    list(DA = data, session_id = session_id),
    parent = asNamespace("dsVert"))
  testthat::with_mocked_bindings(
    evalq(psiPaddedAttestationDS("DA", session_id), evaluation),
    .S = function(value) {
      if (!identical(value, result$contract$session_id)) {
        stop("Unexpected padded PSI test session", call. = FALSE)
      }
      result$states[[peer]]
    },
    .package = "dsVert")
}

test_that("the live padded-PSI attestation hook alone provisions DP state", {
  skip_on_cran()
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only")
  on.exit(options(old), add = TRUE)

  result <- .psi_padded_test_run_k2(
    sprintf("id-%02d", 1:12), sprintf("id-%02d", 4:15), "0")
  root <- withr::local_tempdir(pattern = "dsvert-attestation-hook-")

  # An authenticated PSI remains usable without a DP template, but it cannot
  # invent a protected-dataset registry entry.
  no_template <- file.path(root, "no-template")
  dir.create(no_template, mode = "0700")
  .psi_padded_test_registry_context(
    result, "alpha", no_template, "v1", {
      options(dsvert.dp.datasets = NULL)
      expect_identical(
        .psi_padded_test_attestation_ds(result, "alpha"),
        result$attestations$alpha)
      expect_length(list.files(
        file.path(no_template, "privacy", "aligned-datasets"),
        pattern = "^dataset_.*\\.json$", full.names = TRUE), 0L)
    })

  # The empty-session status route validates the object only. It must neither
  # create nor repair derived registry state.
  read_only <- file.path(root, "read-only")
  dir.create(read_only, mode = "0700")
  .psi_padded_test_registry_context(
    result, "alpha", read_only, "v1", {
      expect_identical(
        .psi_padded_test_attestation_ds(result, "alpha", session_id = ""),
        result$attestations$alpha)
      expect_length(list.files(
        file.path(read_only, "privacy", "aligned-datasets"),
        pattern = "^dataset_.*\\.json$", full.names = TRUE), 0L)
    })

  # A non-empty, real PSI session plus the minimal custodian template is the
  # only automatic provisioning boundary.
  live <- file.path(root, "live")
  dir.create(live, mode = "0700")
  path <- .psi_padded_test_registry_context(
    result, "alpha", live, "v1", {
      expect_identical(
        .psi_padded_test_attestation_ds(result, "alpha"),
        result$attestations$alpha)
      pinset_id <- .psi_padded_validate_persistent_attestation(
        result$aligned$alpha)$pinset_id
      .dsvert_dp_alignment_registry_path(
        "DA", "test-logical-cohort", "v1", pinset_id)
    })
  expect_true(file_test("-f", path))
  expect_false(.dsvert_dp_path_is_link(path))
  expect_identical(as.integer(file.info(path)$mode), strtoi("600", base = 8L))
  expect_identical(.dsvert_dp_noise_link_count(path), 1)

  connection <- file(path, open = "wb")
  writeBin(charToRaw("corrupt"), connection)
  close(connection)
  Sys.chmod(path, mode = "0600")
  .psi_padded_test_registry_context(
    result, "alpha", live, "v1", {
      expect_identical(
        .psi_padded_test_attestation_ds(result, "alpha", session_id = ""),
        result$attestations$alpha)
      pinset <- .dsvert_dp_peer_pinset()$pinset
      expect_error(.dsvert_dp_alignment_registry_resolve_templates(
        getOption("dsvert.dp.datasets"), "id", pinset),
        "authentication failed|invalid size")
    })

  # Failure to commit the custodian binding invalidates the live attestation
  # call as a whole; no apparent success can escape this boundary.
  contradictory <- file.path(root, "contradictory")
  dir.create(contradictory, mode = "0700")
  .psi_padded_test_registry_context(
    result, "alpha", contradictory, "v1", {
      options(dsvert.dp.datasets = list(
        DA = list(id = "different-cohort", version = "v1")))
      expect_error(
        .psi_padded_test_attestation_ds(result, "alpha"),
        "Padded PSI alignment attestation unavailable")
      expect_length(list.files(
        file.path(contradictory, "privacy", "aligned-datasets"),
        pattern = "^dataset_.*\\.json$", full.names = TRUE), 0L)
    })
})

test_that("authenticated padded PSI provisions a durable stable DP registry", {
  skip_on_cran()
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only")
  on.exit(options(old), add = TRUE)

  ids_a <- sprintf("id-%02d", 1:12)
  ids_b <- sprintf("id-%02d", 4:15)
  first <- .psi_padded_test_run_k2(ids_a, ids_b, "1")
  retry <- .psi_padded_test_run_k2(ids_a, ids_b, "2")
  expect_false(identical(
    attr(first$aligned$alpha, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)$token,
    attr(retry$aligned$alpha, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)$token))

  root <- withr::local_tempdir(pattern = "dsvert-aligned-registry-")
  state_dir <- file.path(root, "alpha")
  dir.create(state_dir, mode = "0700")
  Sys.chmod(state_dir, mode = "0700")

  committed <- .psi_padded_test_registry_context(
    first, "alpha", state_dir, "v1", {
      path <- .dsvert_dp_alignment_registry_commit(
        "DA", first$aligned$alpha)
      pinset <- .dsvert_dp_peer_pinset()$pinset
      descriptor <- .dsvert_dp_alignment_registry_resolve_templates(
        getOption("dsvert.dp.datasets"), "id", pinset)$DA
      list(path = path, descriptor = descriptor,
           bytes = readBin(path, "raw", n = file.info(path)$size + 1L))
    })
  expect_true(file.exists(committed$path))
  expect_true(file_test("-f", committed$path))
  expect_false(.dsvert_dp_path_is_link(committed$path))
  expect_identical(as.integer(file.info(committed$path)$mode),
                   strtoi("600", base = 8L))
  expect_identical(.dsvert_dp_noise_link_count(committed$path), 1)

  # Even an otherwise correctly-sized pinset cannot rename or omit the
  # authenticated reference/compute peers from the registry contract.
  .psi_padded_test_registry_context(
    first, "alpha", state_dir, "v1", {
      pinset <- .dsvert_dp_peer_pinset()$pinset
      pinset_id <- .psi_padded_pinset_id(as.list(pinset))
      names(pinset)[[2L]] <- "unrecognized-peer"
      expect_error(testthat::with_mocked_bindings(
        .dsvert_dp_alignment_registry_resolve_templates(
          getOption("dsvert.dp.datasets"), "id", pinset),
        .psi_padded_pinset_id = function(value) pinset_id,
        .package = "dsVert"),
        "contradicts the active custodian policy or pinned peer set")
    })

  replayed <- .psi_padded_test_registry_context(
    retry, "alpha", state_dir, "v1", {
      path <- .dsvert_dp_alignment_registry_commit(
        "DA", retry$aligned$alpha)
      pinset <- .dsvert_dp_peer_pinset()$pinset
      list(
        path = path,
        descriptor = .dsvert_dp_alignment_registry_resolve_templates(
          getOption("dsvert.dp.datasets"), "id", pinset)$DA,
        bytes = readBin(path, "raw", n = file.info(path)$size + 1L))
    })
  expect_identical(replayed$path, committed$path)
  expect_identical(replayed$descriptor, committed$descriptor)
  expect_identical(replayed$bytes, committed$bytes)

  # A local mutation retains the valid padded alignment attestation but has a
  # different protected snapshot. The same pinset/id/version must not rebind.
  changed <- retry$aligned$alpha
  changed$a[[1L]] <- changed$a[[1L]] + 1L
  .psi_padded_test_registry_context(
    retry, "alpha", state_dir, "v1",
    expect_error(
      .dsvert_dp_alignment_registry_commit("DA", changed),
      "different authenticated aligned snapshot"))

  # Resolve is read-only and never repairs damage; a subsequent live PSI
  # attestation may reconstruct this derived record exactly.
  connection <- file(committed$path, open = "wb")
  writeBin(charToRaw("corrupt"), connection)
  close(connection)
  Sys.chmod(committed$path, mode = "0600")
  .psi_padded_test_registry_context(
    retry, "alpha", state_dir, "v1", {
      pinset <- .dsvert_dp_peer_pinset()$pinset
      expect_error(.dsvert_dp_alignment_registry_resolve_templates(
        getOption("dsvert.dp.datasets"), "id", pinset),
        "authentication failed|invalid size")
      expect_silent(.dsvert_dp_alignment_registry_commit(
        "DA", retry$aligned$alpha))
      expect_identical(
        .dsvert_dp_alignment_registry_resolve_templates(
          getOption("dsvert.dp.datasets"), "id", pinset)$DA,
        committed$descriptor)
    })

  # Loss is also recoverable only from another live, authenticated result.
  expect_true(unlink(committed$path, force = TRUE) == 0L)
  .psi_padded_test_registry_context(
    retry, "alpha", state_dir, "v1", {
      expect_silent(.dsvert_dp_alignment_registry_commit(
        "DA", retry$aligned$alpha))
      expect_true(file.exists(committed$path))
    })

  version_two <- .psi_padded_test_run_k2(
    ids_a, ids_b, "3", source_version = "v2")
  version_two_path <- .psi_padded_test_registry_context(
    version_two, "alpha", state_dir, "v2",
    .dsvert_dp_alignment_registry_commit("DA", version_two$aligned$alpha))
  expect_false(identical(version_two_path, committed$path))

  rotated <- .psi_padded_test_run_k2(
    ids_a, ids_b, "4",
    seed_bytes = c(alpha = 71L, beta = 83L))
  rotated_path <- .psi_padded_test_registry_context(
    rotated, "alpha", state_dir, "v1",
    .dsvert_dp_alignment_registry_commit("DA", rotated$aligned$alpha))
  expect_false(identical(rotated_path, committed$path))
  expect_false(identical(
    dsvertDPDatasetDescriptor(
      rotated$aligned$alpha, "test-logical-cohort", "v1")$
        alignment_manifest_hash,
    committed$descriptor$alignment_manifest_hash))

  if (.Platform$OS.type != "windows") {
    hostile_root <- file.path(root, "hostile")
    dir.create(hostile_root, mode = "0700")
    Sys.chmod(hostile_root, mode = "0700")
    .psi_padded_test_registry_context(
      retry, "alpha", hostile_root, "v1", {
        pinset_id <- .psi_padded_validate_persistent_attestation(
          retry$aligned$alpha)$pinset_id
        path <- .dsvert_dp_alignment_registry_path(
          "DA", "test-logical-cohort", "v1", pinset_id)
        target <- file.path(dirname(path), "hostile-target")
        writeLines("hostile", target, useBytes = TRUE)
        Sys.chmod(target, mode = "0600")
        expect_true(file.symlink(target, path))
        expect_error(.dsvert_dp_alignment_registry_commit(
          "DA", retry$aligned$alpha), "owner-only|symbolic link")
        unlink(path, force = TRUE)
        expect_true(file.link(target, path))
        expect_error(.dsvert_dp_alignment_registry_commit(
          "DA", retry$aligned$alpha), "owner-only")
      })
  }

  if (.Platform$OS.type != "windows") {
    concurrent_root <- file.path(root, "concurrent")
    dir.create(concurrent_root, mode = "0700")
    Sys.chmod(concurrent_root, mode = "0700")
    concurrent <- .psi_padded_test_registry_context(
      retry, "alpha", concurrent_root, "v1",
      parallel::mclapply(seq_len(4L), function(index) {
        .dsvert_dp_alignment_registry_commit("DA", retry$aligned$alpha)
      }, mc.cores = 2L, mc.preschedule = FALSE))
    expect_false(any(vapply(concurrent, inherits, logical(1L), "try-error")))
    expect_length(unique(unlist(concurrent, use.names = FALSE)), 1L)
    expect_length(list.files(
      file.path(concurrent_root, "privacy", "aligned-datasets"),
      pattern = "^dataset_.*\\.json$", full.names = TRUE), 1L)
  }
})

test_that("zero, one and full matches have the same public transcript shape", {
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only")
  on.exit(options(old), add = TRUE)
  scenarios <- list(
    zero = list(sprintf("a-%02d", 1:64), sprintf("b-%02d", 1:64), "b"),
    one = list(sprintf("a-%02d", 1:64),
               c("a-01", sprintf("b-%02d", 2:64)), "c"),
    full = list(sprintf("a-%02d", 1:64), sprintf("a-%02d", 1:64), "d"))
  results <- lapply(scenarios, function(args) {
    do.call(.psi_padded_test_run_k2, args)
  })
  shapes <- lapply(results, `[[`, "visible_lengths")
  expect_identical(shapes$zero, shapes$one)
  expect_identical(shapes$one, shapes$full)
  sizes <- vapply(results, function(result) {
    nrow(result$aligned[[result$contract$reference_peer]])
  }, integer(1L))
  expect_identical(unname(sizes), c(0L, 1L, 64L))
})

test_that("fixed-capacity PSI produces the same canonical intersection for K=3, K=4 and K=5", {
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only")
  on.exit(options(old), add = TRUE)
  suffixes <- c(`3` = "e", `4` = "d", `5` = "f")
  for (k in 3:5) {
    peer_names <- letters[seq_len(k)]
    ids <- stats::setNames(lapply(seq_len(k), function(index) {
      # Every peer contains 20:32, while its non-common prefix/suffix differ.
      values <- c(sprintf("peer-%d-%02d", index, 1:7),
                  sprintf("common-%02d", 20:32),
                  sprintf("tail-%d-%02d", index, 1:3))
      if (index %% 2L) values else rev(values)
    }), peer_names)
    result <- .psi_padded_test_run_multi(ids, suffixes[[as.character(k)]])
    reference <- result$contract$reference_peer
    expected <- ids[[reference]][ids[[reference]] %in%
                                   sprintf("common-%02d", 20:32)]
    for (peer in peer_names) {
      expect_identical(result$aligned[[peer]]$id, expected,
                       info = paste("K", k, "peer", peer))
    }
    if (k == 3L) {
      descriptors <- lapply(
        result$aligned, dsvertDPDatasetDescriptor,
        id = "test-logical-cohort", version = "v1")
      expect_length(unique(vapply(
        descriptors, `[[`, character(1L), "alignment_manifest_hash")), 1L)
      expect_length(unique(vapply(
        descriptors, `[[`, character(1L), "snapshot_sha256")), k)
    }
    expect_identical(result$contract$compute_peers,
                     result$contract$peer_names[1:2])
    expect_identical(result$contract$capacity, 64L)
  }
})

test_that("K>=3 membership relay attacks fail without changing the result", {
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only")
  on.exit(options(old), add = TRUE)
  ids <- list(
    alpha = sprintf("id-%02d", 1:20),
    beta = sprintf("id-%02d", 5:24),
    gamma = sprintf("id-%02d", 8:27))
  result <- .psi_padded_test_run_multi(ids, "7")
  contract <- result$contract
  compute <- contract$compute_peers[[1L]]
  targets <- .psi_padded_targets(contract)
  state <- result$states[[compute]]$.psi_padded_state
  expect_true(all(vapply(state$membership_received, function(receipt) {
    identical(names(receipt), c("payload_sha256", "envelope_sha256")) &&
      all(grepl("^[0-9a-f]{64}$", unlist(receipt, use.names = FALSE)))
  }, logical(1L))))
  expect_false(any(vapply(state$membership_received, function(receipt) {
    any(c("share", "envelope") %in% names(receipt))
  }, logical(1L))))
  state$membership_received <- list()
  state$membership_sum_share <- NULL
  state$phase <- "prepared"
  result$states[[compute]]$.psi_padded_state <- state

  expect_error(.psi_padded_membership_accept_impl(
    result$states[[compute]], targets[[2L]],
    result$memberships[[targets[[2L]]]][[compute]]),
    "reordered membership")
  first <- result$memberships[[targets[[1L]]]][[compute]]
  expect_silent(.psi_padded_membership_accept_impl(
    result$states[[compute]], targets[[1L]], first))
  expect_silent(.psi_padded_membership_accept_impl(
    result$states[[compute]], targets[[1L]], first))
  expect_error(.psi_padded_membership_accept_impl(
    result$states[[compute]], targets[[2L]], first),
    "context mismatch|authentication failed")
  expect_silent(.psi_padded_membership_accept_impl(
    result$states[[compute]], targets[[2L]],
    result$memberships[[targets[[2L]]]][[compute]]))
  expect_false(is.null(
    result$states[[compute]]$.psi_padded_state$membership_sum_share))
})

test_that("purpose-bound padded PSI AND completes through exact GC/OT", {
  skip_on_cran()
  binary <- .psi_padded_test_exact_binary()
  old <- options(
    dsvert.mpc_binary = binary,
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only",
    dsvert.exact_gc.ttl_seconds = 300,
    dsvert.exact_gc.chunk_bytes = 65536,
    dsvert.exact_gc.spool_max_bytes = 8 * 1024^2)
  on.exit(options(old), add = TRUE)
  ids <- list(
    alpha = sprintf("id-%02d", 1:20),
    beta = sprintf("id-%02d", 5:24),
    gamma = sprintf("id-%02d", 8:27))
  result <- .psi_padded_test_run_multi(ids, "8")
  contract <- result$contract
  compute <- contract$compute_peers
  reference <- contract$reference_peer
  for (peer in compute) {
    other <- setdiff(compute, peer)
    ss <- result$states[[peer]]
    ss$.session_id <- paste0(contract$session_id, "_psi_", peer)
    state <- ss$.psi_padded_state
    state$phase <- "prepared"
    ss$.psi_padded_state <- state
    trusted <- stats::setNames(
      result$identities[[other]]$identity_pk, other)
    bound <- .psi_padded_test_with_identity(
      result$seeds[[peer]], trusted,
      .psi_padded_exact_transport_impl(ss))
    expect_true(isTRUE(bound$bound))
    expect_identical(bound$peer, other)
    expect_identical(
      .psi_padded_test_with_identity(
        result$seeds[[peer]], trusted,
        .psi_padded_exact_transport_impl(ss)),
      bound)
  }
  chunk <- .psi_padded_and_chunk_contract(contract, 1L)
  initialized <- list()
  for (peer in compute) {
    other <- setdiff(compute, peer)
    trusted <- stats::setNames(
      result$identities[[other]]$identity_pk, other)
    initialized[[peer]] <- .psi_padded_test_with_identity(
      result$seeds[[peer]], trusted,
      testthat::with_mocked_bindings(
        .psi_padded_and_start_impl(
          result$states[[peer]], 1L, binary = binary),
        .exact_gc_record_private_error = function(state, message) {
          log <- file.path(state$spool, "worker-private.log")
          detail <- if (file.exists(log)) {
            paste(readLines(log, warn = FALSE), collapse = " | ")
          } else "worker log absent"
          stop(message, ": ", detail, call. = FALSE)
        },
        .package = "dsVert"))
  }
  expect_identical(
    initialized[[compute[[1L]]]]$context_hash,
    initialized[[compute[[2L]]]]$context_hash)
  expect_setequal(vapply(initialized, `[[`, character(1L), "role"),
                  c("garbler", "evaluator"))
  expect_true(all(vapply(initialized, `[[`, character(1L), "operation") ==
                    "compare-signed"))
  expect_true(all(vapply(initialized, `[[`, character(1L), "threshold") ==
                    as.character(length(contract$peer_names) - 1L)))
  expect_true(all(vapply(initialized, function(value) {
    is.numeric(value$worker_heartbeat) &&
      length(value$worker_heartbeat) == 1L &&
      !is.na(value$worker_heartbeat) && value$worker_heartbeat >= 1
  }, logical(1L))))
  expect_true(all(vapply(initialized, function(value) {
    is.numeric(value$max_runtime_seconds) &&
      length(value$max_runtime_seconds) == 1L &&
      !is.na(value$max_runtime_seconds) &&
      value$max_runtime_seconds >= value$ttl_seconds
  }, logical(1L))))
  roundtripped <- lapply(initialized, function(value) {
    jsonlite::fromJSON(
      .psi_padded_canonical_json(value), simplifyVector = FALSE)
  })
  expect_true(all(vapply(roundtripped, function(value) {
    all(c("worker_heartbeat", "max_runtime_seconds") %in% names(value)) &&
      !any(c(
        "master_key", "source_share", "private_seed", "spool", "process",
        "transport_sk") %in% names(value))
  }, logical(1L))))
  .psi_padded_test_exact_pump(
    result$states[[compute[[1L]]]], result$states[[compute[[2L]]]],
    contract$session_id, chunk$operation_id, result$seeds[compute])
  outputs <- list()
  for (peer in compute) {
    outputs[[peer]] <- .psi_padded_test_with_identity(
      result$seeds[[peer]], NULL,
      .psi_padded_and_finalize_impl(result$states[[peer]], 1L))
  }
  reference_state <- result$states[[reference]]$.psi_padded_state
  expected <- reference_state$global_membership_chunks[["1"]]
  reference_state$and_received <- list()
  reference_state$global_membership_chunks <- list()
  result$states[[reference]]$.psi_padded_state <- reference_state
  for (peer in compute) {
    .psi_padded_and_accept_impl(
      result$states[[reference]], 1L, peer, outputs[[peer]]$envelope)
  }
  actual <- result$states[[reference]]$.psi_padded_state$
    global_membership_chunks[["1"]]
  expect_identical(actual, expected)
  expect_identical(sum(actual), 13L)
  capability <- .exact_gc_capability_probe()
  expect_false(is.null(capability))
  expect_true(isTRUE(capability$canonical_input_encoding))
  expect_false(any(grepl("dcf", c(
    initialized[[1L]]$purpose, initialized[[2L]]$purpose),
    ignore.case = TRUE)))
  for (ss in result$states[compute]) .exact_gc_abort_all(ss)
})
