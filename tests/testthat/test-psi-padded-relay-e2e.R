.psi_padded_relay_test_seed <- function(byte) {
  gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(byte, 32L))))
}

.psi_padded_relay_with_identity <- function(seed, code) {
  old <- options(dsvert.identity_seed = seed)
  on.exit(options(old), add = TRUE)
  force(code)
}

.psi_padded_relay_fixture <- function(k = 2L, capacity = 16384L) {
  peers <- letters[seq_len(k)]
  seeds <- stats::setNames(lapply(
    c(17L, 43L, 79L, 113L, 151L)[seq_len(k)],
    .psi_padded_relay_test_seed), peers)
  identities <- lapply(seeds, function(seed) {
    .psi_padded_relay_with_identity(seed, .get_identity_keypair())
  })
  peer_ids <- vapply(identities, function(value) {
    .dsvert_relay_peer_id(value$identity_pk)
  }, character(1L))
  ordered <- peers[order(peer_ids, method = "radix")]
  session_id <- paste0("42345678-1234-4234-9234-123456789ab", k)
  operation_id <- paste0("op_", strrep(as.character(k), 32L))
  contract <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = session_id, operation_id = operation_id,
    policy_id = paste0("policy_", strrep("1", 64L)),
    alignment_purpose = "patient-record-alignment-v1",
    dataset_id = "test-logical-cohort",
    dataset_version = "v1",
    id_column = "id",
    source_binding_id = .psi_padded_test_source_public()$source_binding_id,
    pinset_id = paste0("pinset_", strrep("2", 64L)),
    capacity = capacity,
    relay_frame_bytes = 16L * 1024L,
    inline_max_bytes = 16L * 1024L,
    peer_names = ordered, peer_ids = unname(peer_ids[ordered]),
    reference_peer = ordered[[1L]], compute_peers = ordered[1:2],
    snapshot_ids = paste0("snap_", vapply(seq_len(k), function(index) {
      paste(rep(letters[[index]], 64L), collapse = "")
    }, character(1L))),
    attestation_id = paste0("attest_", strrep("3", 64L)),
    contract_hash = strrep(as.character(k), 64L))
  identity_pks <- lapply(identities, `[[`, "identity_pk")
  states <- stats::setNames(lapply(peers, function(peer) {
    ss <- new.env(parent = emptyenv())
    ss$.session_id <- session_id
    ss$.psi_padded_state <- list(
      protocol = .DSVERT_PSI_PADDED_PROTOCOL,
      session_id = session_id, operation_id = operation_id,
      self_peer = peer, self_peer_id = peer_ids[[peer]],
      identity_pk = identities[[peer]]$identity_pk,
      identity_pks = identity_pks, contract = contract,
      phase = "confirmed", replay_cache = new.env(parent = emptyenv()))
    ss
  }), peers)
  withr::defer({
    for (ss in states) {
      if (is.environment(ss$.dsvert_dsi_relay)) {
        .dsvert_relay_close(ss)
      }
      .dsvert_resource_unregister(ss)
    }
  }, envir = parent.frame())
  list(
    peers = peers, seeds = seeds, identities = identities,
    peer_ids = peer_ids, states = states, contract = contract)
}

.psi_padded_relay_test_exchange <- function(
    fixture, peer, request, outbound_operation_id = NULL,
    terminal_receipt = NULL) {
  .psi_padded_relay_with_identity(
    fixture$seeds[[peer]], {
      .psi_padded_relay_ensure(fixture$states[[peer]])
      if (!is.null(terminal_receipt)) {
        .dsvert_relay_verify_receipt(
          fixture$states[[peer]], terminal_receipt)
      }
      .dsvert_relay_exchange(
        fixture$states[[peer]], request,
        outbound_operation_id = outbound_operation_id)
    })
}

test_that("B=16384 padded PSI framing survives reorder, duplicate, lost ACK and restart", {
  old <- options(
    dsvert.relay.frame_bytes = 16L * 1024L,
    dsvert.relay.exchange_max_bytes = 32L * 1024L,
    dsvert.relay.spool_max_bytes = 8L * 1024L^2,
    dsvert.relay.max_envelope_bytes = 8L * 1024L^2,
    dsvert.psi.padded.inline_max_bytes = 16L * 1024L)
  on.exit(options(old), add = TRUE)
  f <- .psi_padded_relay_fixture(k = 2L, capacity = 16384L)
  sender <- f$contract$reference_peer
  recipient <- setdiff(f$peers, sender)
  state <- f$states[[sender]]$.psi_padded_state
  context <- .psi_padded_pair_context(
    state, "reference-masked-points", sender, recipient, 1001L)
  # Fixed-size opaque envelope representative of B=16384 point transport.
  payload <- .psi_padded_b64url_encode(as.raw(
    (seq_len(900L * 1024L) - 1L) %% 251L))
  transport <- .psi_padded_relay_with_identity(
    f$seeds[[sender]], .psi_padded_publish_envelope(
      f$states[[sender]], payload, context, force_relay = TRUE))
  expect_identical(transport$transport, "relay")
  descriptor <- transport$relay
  expect_identical(descriptor$total_bytes,
                   as.numeric(nchar(payload, type = "bytes")))
  expect_identical(f$contract$capacity, 16384L)

  source_cursor <- 0
  restarted <- FALSE
  frame_shape <- numeric()
  repeat {
    poll <- stats::setNames(list(list(
      outbox_cursor = source_cursor, deliveries = list())),
      descriptor$sender_peer_id)
    source <- .psi_padded_relay_test_exchange(f, sender, poll)
    retry <- .psi_padded_relay_test_exchange(f, sender, poll)
    expect_identical(retry, source) # lost response/ACK is byte-frozen
    if (!length(source$outbound)) {
      expect_identical(source$outbox_cursor, source$outbox_eof)
      break
    }
    frame_shape <- c(frame_shape, vapply(
      source$outbound, `[[`, numeric(1L), "chunk_bytes"))
    route <- function(frames) stats::setNames(list(list(
      outbox_cursor = 0, deliveries = frames)),
      descriptor$recipient_peer_id)
    if (!restarted && length(source$outbound) > 1L) {
      expect_error(.psi_padded_relay_test_exchange(
        f, recipient, route(rev(source$outbound))),
        "offset gap|sequence")
      first <- .psi_padded_relay_test_exchange(
        f, recipient, route(source$outbound))
      duplicate <- .psi_padded_relay_test_exchange(
        f, recipient, route(source$outbound))
      first_acks <- vapply(
        first$accepted, `[[`, numeric(1L), "ack_offset")
      duplicate_acks <- vapply(
        duplicate$accepted, `[[`, numeric(1L), "ack_offset")
      expect_true(all(duplicate_acks >= first_acks))
      expect_true(all(duplicate_acks == max(first_acks)))
      expect_identical(
        vapply(duplicate$accepted, `[[`, logical(1L), "terminal"),
        vapply(first$accepted, `[[`, logical(1L), "terminal"))
      .dsvert_relay_close(f$states[[recipient]])
      .psi_padded_relay_with_identity(
        f$seeds[[recipient]],
        .psi_padded_relay_ensure(f$states[[recipient]]))
      # The source never saw an ACK, so the restarted recipient can recover
      # from the same absolute frames without a rerolled envelope.
      expect_silent(.psi_padded_relay_test_exchange(
        f, recipient, route(source$outbound)))
      restarted <- TRUE
    } else {
      expect_silent(.psi_padded_relay_test_exchange(
        f, recipient, route(source$outbound)))
    }
    source_cursor <- source$outbox_cursor
  }
  expect_true(restarted)
  expect_true(all(frame_shape[-length(frame_shape)] == 16L * 1024L))
  rebuilt <- .psi_padded_relay_with_identity(
    f$seeds[[recipient]], .psi_padded_resolve_envelope(
      f$states[[recipient]], "", descriptor, context))
  expect_identical(rebuilt, payload)
  expect_identical(
    .dsvert_relay_state(f$states[[sender]])$retained_bytes, 0)
})

test_that("padded PSI relay manifests and fixed framing work for K=2,3,5", {
  old <- options(
    dsvert.relay.frame_bytes = 16L * 1024L,
    dsvert.relay.exchange_max_bytes = 16L * 1024L,
    dsvert.relay.spool_max_bytes = 4L * 1024L^2,
    dsvert.relay.max_envelope_bytes = 4L * 1024L^2,
    dsvert.psi.padded.inline_max_bytes = 16L * 1024L)
  on.exit(options(old), add = TRUE)
  shapes <- list()
  for (k in c(2L, 3L, 5L)) {
    f <- .psi_padded_relay_fixture(k = k, capacity = 16384L)
    sender <- f$contract$reference_peer
    recipient <- setdiff(f$peers, sender)[[1L]]
    context <- .psi_padded_pair_context(
      f$states[[sender]]$.psi_padded_state,
      "reference-masked-points", sender, recipient, 1001L)
    payload <- .psi_padded_b64url_encode(as.raw(
      (seq_len(96L * 1024L) + k) %% 251L))
    published <- .psi_padded_relay_with_identity(
      f$seeds[[sender]], .psi_padded_publish_envelope(
        f$states[[sender]], payload, context, force_relay = TRUE))
    cursor <- 0
    shape <- numeric()
    repeat {
      source <- .psi_padded_relay_test_exchange(
        f, sender, stats::setNames(list(list(
          outbox_cursor = cursor, deliveries = list())),
          published$relay$sender_peer_id))
      if (!length(source$outbound)) break
      shape <- c(shape, vapply(
        source$outbound, `[[`, numeric(1L), "chunk_bytes"))
      .psi_padded_relay_test_exchange(
        f, recipient, stats::setNames(list(list(
          outbox_cursor = 0, deliveries = source$outbound)),
          published$relay$recipient_peer_id))
      cursor <- source$outbox_cursor
    }
    rebuilt <- .psi_padded_relay_with_identity(
      f$seeds[[recipient]], .psi_padded_resolve_envelope(
        f$states[[recipient]], "", published$relay, context))
    expect_identical(rebuilt, payload, info = paste("K", k))
    shapes[[as.character(k)]] <- shape
  }
  expect_identical(shapes[["2"]], shapes[["3"]])
  expect_identical(shapes[["3"]], shapes[["5"]])
})

test_that("one source can queue multiple PSI envelopes without cross-operation frames", {
  old <- options(
    dsvert.relay.frame_bytes = 16L * 1024L,
    dsvert.relay.exchange_max_bytes = 32L * 1024L,
    dsvert.relay.spool_max_bytes = 4L * 1024L^2,
    dsvert.relay.max_envelope_bytes = 4L * 1024L^2,
    dsvert.psi.padded.inline_max_bytes = 16L * 1024L)
  on.exit(options(old), add = TRUE)
  f <- .psi_padded_relay_fixture(k = 3L, capacity = 16384L)
  sender <- f$contract$reference_peer
  recipients <- setdiff(f$peers, sender)[1:2]
  published <- lapply(seq_along(recipients), function(index) {
    context <- .psi_padded_pair_context(
      f$states[[sender]]$.psi_padded_state,
      "final-selection", sender, recipients[[index]], 9000L + index)
    # 25,500 raw bytes encode to 34,000 bytes: after a 32 KiB exchange,
    # the short terminal frame would share a generic response with the next
    # queued operation unless the source selector is enforced.
    payload <- .psi_padded_b64url_encode(as.raw(
      (seq_len(25500L) + index) %% 251L))
    transport <- .psi_padded_relay_with_identity(
      f$seeds[[sender]], .psi_padded_publish_envelope(
        f$states[[sender]], payload, context, force_relay = TRUE))
    list(context = context, payload = payload, transport = transport)
  })
  expect_false(identical(
    published[[1L]]$transport$relay$operation_id,
    published[[2L]]$transport$relay$operation_id))

  cursor <- 0
  for (index in seq_along(published)) {
    item <- published[[index]]
    descriptor <- item$transport$relay
    recipient <- recipients[[index]]
    terminal_receipt <- NULL
    repeat {
      source_route <- stats::setNames(list(list(
        outbox_cursor = cursor, deliveries = list())),
        descriptor$sender_peer_id)
      source <- .psi_padded_relay_test_exchange(
        f, sender, source_route,
        outbound_operation_id = descriptor$operation_id)
      expect_true(length(source$outbound) > 0L)
      expect_true(all(vapply(source$outbound, function(frame) {
        identical(frame$operation_id, descriptor$operation_id)
      }, logical(1L))))
      recipient_route <- stats::setNames(list(list(
        outbox_cursor = 0, deliveries = source$outbound)),
        descriptor$recipient_peer_id)
      accepted <- .psi_padded_relay_test_exchange(
        f, recipient, recipient_route,
        outbound_operation_id = descriptor$operation_id)
      cursor <- source$outbox_cursor
      finals <- which(vapply(
        source$outbound, `[[`, logical(1L), "final"))
      if (length(finals)) {
        expect_identical(length(finals), 1L)
        terminal_receipt <- accepted$accepted[[finals]]$receipt
        terminal_receipt <- .psi_padded_decode_relay_receipt(
          .psi_padded_json_b64url(terminal_receipt))
        break
      }
    }
    finalized_route <- stats::setNames(list(list(
      outbox_cursor = cursor, deliveries = list())),
      descriptor$sender_peer_id)
    finalized <- .psi_padded_relay_test_exchange(
      f, sender, finalized_route,
      outbound_operation_id = descriptor$operation_id,
      terminal_receipt = terminal_receipt)
    expect_length(finalized$outbound, 0L)
    expect_identical(finalized$outbox_cursor, as.numeric(cursor))
    rebuilt <- .psi_padded_relay_with_identity(
      f$seeds[[recipient]], .psi_padded_resolve_envelope(
        f$states[[recipient]], "", descriptor, item$context))
    expect_identical(rebuilt, item$payload)
  }
  expect_identical(
    .dsvert_relay_state(f$states[[sender]])$retained_bytes, 0)
})
