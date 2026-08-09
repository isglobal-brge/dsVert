test_that("padded PSI selects a server-owned capacity bucket without exact counts", {
  expect_identical(.psi_padded_capacity_bucket(0L), 64L)
  expect_identical(.psi_padded_capacity_bucket(1L), 64L)
  expect_identical(.psi_padded_capacity_bucket(64L), 64L)
  expect_identical(.psi_padded_capacity_bucket(65L), 128L)
  expect_identical(.psi_padded_capacity_bucket(1000000L), 1048576L)
  expect_error(.psi_padded_capacity_bucket(1048577L), "capacity policy")
})

test_that("padded PSI dummies are domain separated and slots are shuffled", {
  deterministic <- local({
    counter <- 0L
    function(n) {
      counter <<- counter + 1L
      as.raw((seq_len(n) + counter) %% 256L)
    }
  })
  first <- .psi_padded_prepare_slots(
    ids = c("alpha", "beta"), rows = c(4L, 9L), capacity = 8L,
    peer_id = paste0("peer_", paste(rep("a", 64L), collapse = "")),
    snapshot_id = paste0("snap_", paste(rep("b", 64L), collapse = "")),
    random_bytes = deterministic)
  second <- .psi_padded_prepare_slots(
    ids = c("alpha", "beta"), rows = c(4L, 9L), capacity = 8L,
    peer_id = paste0("peer_", paste(rep("c", 64L), collapse = "")),
    snapshot_id = paste0("snap_", paste(rep("d", 64L), collapse = "")),
    random_bytes = deterministic)

  expect_length(first$mask_ids, 8L)
  expect_identical(sum(first$slot_valid), 2L)
  expect_identical(sort(first$slot_rows[first$slot_valid]), c(4L, 9L))
  expect_identical(anyDuplicated(first$mask_ids), 0L)
  expect_false(any(first$mask_ids[!first$slot_valid] %in%
                     second$mask_ids[!second$slot_valid]))
  expect_false(any(grepl("alpha|beta", first$mask_ids[!first$slot_valid])))
})

test_that("padded PSI rejects a forced dummy collision before masking", {
  peer <- paste0("peer_", paste(rep("a", 64L), collapse = ""))
  snapshot <- paste0("snap_", paste(rep("b", 64L), collapse = ""))
  expect_error(
    .psi_padded_prepare_slots(
      ids = "alpha", rows = 1L, capacity = 2L,
      peer_id = peer, snapshot_id = snapshot,
      dummy_factory = function(...) .psi_padded_real_label("alpha")),
    "dummy domain collision"
  )
})

test_that("reported dummy matches are structurally inert", {
  capacity <- 64L
  # The backend reports (a) an own dummy matching a valid reference slot and
  # (b) an own real slot matching a reference dummy. The former is removed by
  # the target validity mask; the latter cannot survive the reference's final
  # validity mask.
  mapping <- .psi_padded_match_map(
    matched_own_rows = c(0L, 1L), matched_ref_indices = c(0L, 2L),
    own_slot_valid = c(FALSE, TRUE, rep(FALSE, capacity - 2L)),
    ref_slot_valid = rep(TRUE, capacity), capacity = capacity)
  expected <- integer(capacity)
  expected[[3L]] <- 1L
  expect_identical(mapping$bits, expected)
  final <- .psi_padded_selection_plan(
    mapping$bits, c(TRUE, TRUE, rep(FALSE, capacity - 2L)))
  expect_identical(final$bits, integer(capacity))
})

test_that("padded PSI resolves invalid and duplicate identifiers locally", {
  D <- data.frame(
    id = c("a", NA, "", "a", "b"),
    x = c(1, 2, 3, 4, NA), stringsAsFactors = FALSE)
  selected <- .psi_padded_select_rows(D, "id", "id_only", "first")
  expect_identical(selected$rows, c(1L, 5L))
  expect_identical(selected$ids, c("a", "b"))
  complete <- .psi_padded_select_rows(D, "id", "complete_cases", "first")
  expect_identical(complete$rows, 1L)
  expect_error(.psi_padded_select_rows(D, "id", "id_only", "reject"),
               "duplicate identifier policy")
})

test_that("multi-party padded AND is exact for K=2 through K=5", {
  for (k in 2:5) {
    target_count <- k - 1L
    patterns <- as.matrix(expand.grid(rep(list(0:1), target_count)))
    for (row in seq_len(nrow(patterns))) {
      bits <- as.integer(patterns[row, ])
      split <- lapply(bits, function(bit) {
        .psi_padded_ring63_share_bits(bit)
      })
      left <- .psi_padded_ring63_sum(lapply(split, `[[`, "left"))
      right <- .psi_padded_ring63_sum(lapply(split, `[[`, "right"))
      got <- .psi_padded_and_reference(left, right, target_count)
      expect_identical(got, as.integer(all(bits == 1L)),
                       info = paste("K", k, "pattern", paste(bits, collapse = "")))
    }
  }
})

test_that("fixed membership and selection payloads do not reveal cardinality", {
  capacity <- 129L
  lengths <- vapply(c(0L, 1L, capacity), function(n) {
    bits <- integer(capacity)
    if (n) bits[seq_len(n)] <- 1L
    plan <- .psi_padded_selection_plan(bits, rep(TRUE, capacity))
    length(.psi_padded_pack_selection(plan, capacity,
      token = base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))))
  }, integer(1L))
  expect_identical(length(unique(lengths)), 1L)

  bit_lengths <- vapply(c(0L, 1L, capacity), function(n) {
    bits <- integer(capacity)
    if (n) bits[seq_len(n)] <- 1L
    length(.psi_padded_pack_bits(bits))
  }, integer(1L))
  expect_identical(length(unique(bit_lengths)), 1L)
})

test_that("target materialization follows the reference permutation", {
  capacity <- 8L
  data <- data.frame(id = letters[1:5], value = 1:5)
  # Shuffled target slots: reference slot 0 maps to local row c, slot 3 to a,
  # and slot 5 to e. All other slots are dummies/unmatched.
  slot_rows <- c(3L, 0L, 1L, 0L, 0L, 5L, 0L, 0L)
  slot_valid <- slot_rows > 0L
  target_slot_by_ref <- rep(capacity, capacity)
  target_slot_by_ref[c(1L, 4L, 6L)] <- c(0L, 2L, 5L)
  global <- integer(capacity)
  global[c(1L, 4L, 6L)] <- 1L
  plan <- .psi_padded_selection_plan(global, rep(TRUE, capacity))
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))

  result <- .psi_padded_materialize_target(
    data, "id", slot_rows, slot_valid, target_slot_by_ref, plan, token)
  expect_identical(result$id, c("c", "a", "e"))
  expect_silent(.psi_validate_alignment_manifest(result))

  substituted <- target_slot_by_ref
  substituted[[4L]] <- capacity
  expect_error(.psi_padded_materialize_target(
    data, "id", slot_rows, slot_valid, substituted, plan, token),
    "authenticated padded PSI result is inconsistent")
})

test_that("padded PSI contracts reject permutation, omission and substitution", {
  identities <- lapply(1:3, function(i) .callMpcTool(
    "derive-identity", list(seed = jsonlite::base64_enc(
      as.raw((seq_len(32L) + 37L * i) %% 256L)))))
  transports <- lapply(seq_along(identities), function(i) .callMpcTool(
    "transport-keygen", list()))
  names(identities) <- names(transports) <- c("alpha", "beta", "gamma")
  pinset <- lapply(identities, `[[`, "identity_pk")
  session_id <- "12345678-1234-1234-1234-123456789abc"
  operation_id <- paste0("op_", paste(rep("1", 32L), collapse = ""))
  pinset_id <- .psi_padded_pinset_id(pinset)
  offers <- lapply(names(identities), function(peer) {
    .psi_padded_sign_offer(
      peer, identities[[peer]], transports[[peer]]$public_key,
      capacity = 64L, session_id = session_id, operation_id = operation_id,
      policy_id = paste0("policy_", paste(rep("2", 64L), collapse = "")),
      source_authorization = .psi_padded_test_source_public(),
      pinset_id = pinset_id,
      snapshot_id = paste0("snap_", digest::digest(
        paste0("snapshot/", peer), algo = "sha256", serialize = FALSE)),
      attestation_nonce = base64_to_base64url(jsonlite::base64_enc(
        as.raw((seq_len(32L) + nchar(peer)) %% 256L))))
  })
  names(offers) <- names(identities)

  contract <- .psi_padded_contract_from_offers(offers, pinset)
  expect_identical(contract$capacity, 64L)
  expect_length(contract$compute_peers, 2L)
  expect_identical(sort(contract$peer_names), sort(names(identities)))

  expect_error(.psi_padded_contract_from_offers(offers[-1L], pinset),
               "complete pinned peer set")
  permuted <- offers
  permuted[[1L]]$unsigned$peer_name <- "gamma"
  expect_error(.psi_padded_contract_from_offers(permuted, pinset),
               "offer authentication")
  substituted <- offers
  substituted[[1L]]$unsigned$identity_pk <- identities$beta$identity_pk
  expect_error(.psi_padded_contract_from_offers(substituted, pinset),
               "offer authentication")
})

test_that("padded PSI envelopes bind every routing and snapshot field", {
  sender_identity <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(as.raw(0:31))))
  recipient_identity <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(as.raw(32:63))))
  recipient_transport <- .callMpcTool("transport-keygen", list())
  context <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = "12345678-1234-1234-1234-123456789abc",
    operation_id = paste0("op_", paste(rep("3", 32L), collapse = "")),
    message_kind = "membership-share",
    sequence = 7L,
    sender = "alpha", recipient = "beta",
    sender_snapshot_id = paste0("snap_", paste(rep("4", 64L), collapse = "")),
    recipient_snapshot_id = paste0("snap_", paste(rep("5", 64L), collapse = "")),
    contract_hash = paste(rep("6", 64L), collapse = ""),
    pinset_id = paste0("pinset_", paste(rep("7", 64L), collapse = "")))
  payload <- as.raw(rep(19L, 128L))
  sealed <- .psi_padded_seal_envelope(
    payload, context, sender_identity$identity_sk,
    recipient_transport$public_key)
  opened <- .psi_padded_open_envelope(
    sealed, context, sender_identity$identity_pk,
    recipient_transport$secret_key, expected_payload_bytes = 128L)
  expect_identical(opened, payload)

  for (field in c("protocol", "session_id", "operation_id", "message_kind",
                  "sequence", "sender", "recipient", "sender_snapshot_id",
                  "recipient_snapshot_id", "contract_hash", "pinset_id")) {
    tampered <- context
    if (is.numeric(tampered[[field]])) {
      tampered[[field]] <- tampered[[field]] + 1L
    } else {
      tampered[[field]] <- paste0(tampered[[field]], "x")
    }
    expect_error(.psi_padded_open_envelope(
      sealed, tampered, sender_identity$identity_pk,
      recipient_transport$secret_key, expected_payload_bytes = 128L),
      "envelope context")
  }
  expect_error(.psi_padded_open_envelope(
    sealed, context, recipient_identity$identity_pk,
    recipient_transport$secret_key, expected_payload_bytes = 128L),
    "sender authentication")
})

test_that("padded PSI replay cache is idempotent and rejects conflicting duplicates", {
  cache <- new.env(parent = emptyenv())
  first <- .psi_padded_accept_once(cache, "round-1", "opaque-value")
  replay <- .psi_padded_accept_once(cache, "round-1", "opaque-value")
  expect_true(first$accepted)
  expect_false(replay$accepted)
  expect_true(replay$replay)
  expect_error(.psi_padded_accept_once(cache, "round-1", "substitution"),
               "conflicting duplicate")
})
