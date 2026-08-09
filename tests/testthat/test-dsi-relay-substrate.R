fake_relay_signature <- function(message) {
  h <- digest::digest(message, algo = "sha256", serialize = FALSE, raw = TRUE)
  .dsvert_relay_b64url_encode(c(h, h))
}

fake_relay_verify <- function(message, identity_pk, signature) {
  identical(signature, fake_relay_signature(message))
}

queue_relay_test_stream <- function(ss, operation_id, recipient_peer_id,
                                    capability_id, payload, frame_bytes) {
  payload_hash <- digest::digest(payload, algo = "sha256", serialize = FALSE)
  .dsvert_relay_queue_begin(
    ss, operation_id, recipient_peer_id, capability_id,
    total_bytes = length(payload), payload_hash = payload_hash,
    frame_bytes = frame_bytes)
  state <- .dsvert_relay_state(ss)
  key <- paste(recipient_peer_id, operation_id, capability_id, sep = "|")
  stream <- state$outgoing[[key]]
  for (index in seq_along(stream$frame_offsets)) {
    first <- stream$frame_offsets[[index]] + 1
    last <- first + stream$frame_lengths[[index]] - 1
    .dsvert_relay_queue_append(
      ss, operation_id, recipient_peer_id, capability_id,
      stream$frame_offsets[[index]], payload[first:last])
  }
  .dsvert_relay_queue_seal(
    ss, operation_id, recipient_peer_id, capability_id, payload_hash,
    signer = fake_relay_signature)
  state <- .dsvert_relay_state(ss)
  descriptors <- state$outbox[vapply(
    state$outbox, function(value) identical(value$stream_key, key), logical(1L))]
  lapply(descriptors, function(value)
    .dsvert_relay_materialize_frame(state, key, value$frame_index))
}

relay_fixture <- function(frame_bytes = 3L, queue = TRUE) {
  id_a <- jsonlite::base64_enc(as.raw(seq_len(32L)))
  id_b <- jsonlite::base64_enc(as.raw(seq.int(33L, 64L)))
  session_id <- "01234567-89ab-cdef-0123-456789abcdef"
  capabilities <- c("mpc.share.v1", "psi.envelope.v1")
  a <- new.env(parent = emptyenv())
  b <- new.env(parent = emptyenv())
  .dsvert_relay_init(a, session_id, id_a, c(id_a, id_b), capabilities)
  .dsvert_relay_init(b, session_id, id_b, c(id_a, id_b), capabilities)
  withr::defer(if (is.environment(a$.dsvert_dsi_relay))
    .dsvert_relay_close(a), envir = parent.frame())
  withr::defer(if (is.environment(b$.dsvert_dsi_relay))
    .dsvert_relay_close(b), envir = parent.frame())
  withr::defer(.dsvert_resource_unregister(a), envir = parent.frame())
  withr::defer(.dsvert_resource_unregister(b), envir = parent.frame())
  frames <- if (isTRUE(queue)) queue_relay_test_stream(
      a,
      operation_id = "op_0123456789abcdef0123456789abcdef",
      recipient_peer_id = .dsvert_relay_peer_id(id_b),
      capability_id = "mpc.share.v1",
      payload = charToRaw("opaque-ciphertext"),
      frame_bytes = frame_bytes
    ) else list()
  list(a = a, b = b, id_a = id_a, id_b = id_b, frames = frames,
       sender = .dsvert_relay_peer_id(id_a),
       recipient = .dsvert_relay_peer_id(id_b),
       operation_id = "op_0123456789abcdef0123456789abcdef")
}

test_that("relay peer IDs are deterministic identity capabilities", {
  pk <- jsonlite::base64_enc(as.raw(seq_len(32L)))
  peer_id <- .dsvert_relay_peer_id(pk)

  expect_match(peer_id, "^dsv1_[0-9a-f]{64}$")
  expect_identical(peer_id, .dsvert_relay_peer_id(base64_to_base64url(pk)))
  expect_error(.dsvert_relay_peer_id("not-base64"), "identity public key")
  expect_error(.dsvert_relay_validate_peer_id("server-a"), "peer capability")
})

test_that("one authenticated envelope is framed without changing its bytes", {
  f <- relay_fixture(frame_bytes = 3L)

  expect_length(f$frames, ceiling(length(charToRaw("opaque-ciphertext")) / 3))
  expect_identical(vapply(f$frames, `[[`, character(1L), "signature"),
                   rep(f$frames[[1L]]$signature, length(f$frames)))
  expect_identical(vapply(f$frames, `[[`, numeric(1L), "offset"),
                   c(0, 3, 6, 9, 12, 15))
  expect_identical(vapply(f$frames, `[[`, logical(1L), "final"),
                   c(rep(FALSE, 5L), TRUE))

  rebuilt <- do.call(c, lapply(f$frames, function(x) .dsvert_relay_decode_payload(x$payload)))
  expect_identical(rebuilt, charToRaw("opaque-ciphertext"))
})

test_that("the in-memory convenience queue cannot create multi-frame streams", {
  f <- relay_fixture(queue = FALSE)
  expect_error(.dsvert_relay_queue(
    f$a, "op_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", f$recipient,
    "mpc.share.v1", charToRaw("two-frames"), frame_bytes = 4L,
    signer = fake_relay_signature), "begin/append/seal streaming")
  expect_length(.dsvert_relay_state(f$a)$outgoing, 0L)
  expect_identical(.dsvert_relay_state(f$a)$retained_bytes, 0)
})

test_that("delivery is complete, authenticated, and exactly idempotent", {
  f <- relay_fixture()
  statuses <- vapply(f$frames, function(frame) {
    .dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify)$status
  }, character(1L))

  expect_identical(tail(statuses, 1L), "complete")
  expect_identical(
    .dsvert_relay_payload(f$b, f$sender, f$operation_id, "mpc.share.v1"),
    charToRaw("opaque-ciphertext")
  )

  replay <- vapply(f$frames, function(frame) {
    .dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify)$status
  }, character(1L))
  expect_true(all(replay == "duplicate"))
  expect_identical(
    .dsvert_relay_payload(f$b, f$sender, f$operation_id, "mpc.share.v1"),
    charToRaw("opaque-ciphertext")
  )
})

test_that("completed payloads support bounded absolute-offset consumption", {
  f <- relay_fixture(frame_bytes = 3L)
  invisible(lapply(f$frames, function(frame)
    .dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify)))
  expected <- charToRaw("opaque-ciphertext")
  offset <- 0
  pieces <- list()
  first <- NULL
  repeat {
    part <- .dsvert_relay_payload_read(
      f$b, f$sender, f$operation_id, "mpc.share.v1",
      offset = offset, max_bytes = 4L)
    if (is.null(first)) {
      first <- part
      expect_identical(.dsvert_relay_payload_read(
        f$b, f$sender, f$operation_id, "mpc.share.v1",
        offset = offset, max_bytes = 4L), first)
    }
    expect_lte(length(part$payload), 4L)
    pieces[[length(pieces) + 1L]] <- part$payload
    offset <- part$next_offset
    if (isTRUE(part$final)) break
  }
  expect_identical(do.call(c, pieces), expected)
  expect_identical(offset, as.numeric(length(expected)))
  eof <- .dsvert_relay_payload_read(
    f$b, f$sender, f$operation_id, "mpc.share.v1",
    offset = offset, max_bytes = 4L)
  expect_true(eof$final)
  expect_identical(eof$payload, raw(0))
  expect_error(.dsvert_relay_payload_read(
    f$b, f$sender, f$operation_id, "mpc.share.v1",
    offset = offset + 1, max_bytes = 4L), "offset exceeds")
  oversized <- tryCatch(.dsvert_relay_payload_read(
    f$b, f$sender, f$operation_id, "mpc.share.v1",
    max_bytes = .dsvert_relay_state(f$b)$exchange_max_bytes + 1),
    error = identity)
  expect_s3_class(oversized, "dsvert_resource_oversize")
  expect_false(oversized$retryable)
})

test_that("replayed payload reads do not refresh relay retention", {
  f <- relay_fixture(frame_bytes = 3L)
  invisible(lapply(f$frames, function(frame)
    .dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify)))
  clock <- 300
  state <- .dsvert_relay_state(f$b)
  state$last_activity <- clock

  testthat::with_mocked_bindings({
    clock <- 301
    first <- .dsvert_relay_payload_read(
      f$b, f$sender, f$operation_id, "mpc.share.v1",
      offset = 0, max_bytes = 4L)
    expect_identical(.dsvert_relay_state(f$b)$last_activity, 301)

    clock <- 302
    expect_identical(.dsvert_relay_payload_read(
      f$b, f$sender, f$operation_id, "mpc.share.v1",
      offset = 0, max_bytes = 4L), first)
    expect_identical(.dsvert_relay_state(f$b)$last_activity, 301)

    clock <- 303
    .dsvert_relay_payload(
      f$b, f$sender, f$operation_id, "mpc.share.v1")
    expect_identical(.dsvert_relay_state(f$b)$last_activity, 303)

    clock <- 304
    .dsvert_relay_payload(
      f$b, f$sender, f$operation_id, "mpc.share.v1")
    expect_identical(.dsvert_relay_state(f$b)$last_activity, 303)
  }, .dsvert_relay_now = function() clock, .package = "dsVert")
})

test_that("duplicate frames return a monotonic committed-byte ACK", {
  f <- relay_fixture(frame_bytes = 3L)
  .dsvert_relay_accept(f$b, f$frames[[1L]], verifier = fake_relay_verify)
  second <- .dsvert_relay_accept(
    f$b, f$frames[[2L]], verifier = fake_relay_verify)
  replay_first <- .dsvert_relay_accept(
    f$b, f$frames[[1L]], verifier = fake_relay_verify)

  expect_identical(second$ack_offset, 6)
  expect_identical(replay_first$status, "duplicate")
  expect_identical(replay_first$ack_offset, second$ack_offset)

  for (frame in f$frames[-c(1L, 2L)]) {
    .dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify)
  }
  terminal_replay <- .dsvert_relay_accept(
    f$b, f$frames[[1L]], verifier = fake_relay_verify)
  expect_identical(terminal_replay$ack_offset,
                   as.numeric(length(charToRaw("opaque-ciphertext"))))
})

test_that("gaps, conflicting retries, and cross-session frames fail closed", {
  f <- relay_fixture()

  expect_error(
    .dsvert_relay_accept(f$b, f$frames[[2L]], verifier = fake_relay_verify),
    "offset gap"
  )
  expect_identical(
    .dsvert_relay_accept(f$b, f$frames[[1L]], verifier = fake_relay_verify)$status,
    "accepted"
  )

  conflict <- f$frames[[1L]]
  conflict$payload <- base64_to_base64url(jsonlite::base64_enc(charToRaw("bad")))
  conflict$chunk_hash <- digest::digest(charToRaw("bad"), algo = "sha256",
                                        serialize = FALSE)
  expect_error(
    .dsvert_relay_accept(f$b, conflict, verifier = fake_relay_verify),
    "conflicting retry"
  )

  wrong_session <- f$frames[[2L]]
  wrong_session$session_id <- "ffffffff-ffff-ffff-ffff-ffffffffffff"
  expect_error(
    .dsvert_relay_accept(f$b, wrong_session, verifier = fake_relay_verify),
    "session"
  )
})

test_that("recipient, sender, capability, length, and hashes are enforced", {
  f <- relay_fixture(frame_bytes = 64L)
  frame <- f$frames[[1L]]

  bad <- frame
  bad$recipient_peer_id <- f$sender
  expect_error(.dsvert_relay_accept(f$b, bad, verifier = fake_relay_verify),
               "recipient")

  bad <- frame
  bad$sender_peer_id <- paste0("dsv1_", strrep("f", 64L))
  expect_error(.dsvert_relay_accept(f$b, bad, verifier = fake_relay_verify),
               "pinned sender")

  bad <- frame
  bad$capability_id <- "raw.rows.v1"
  expect_error(.dsvert_relay_accept(f$b, bad, verifier = fake_relay_verify),
               "capability")

  bad <- frame
  bad$chunk_bytes <- bad$chunk_bytes + 1
  expect_error(.dsvert_relay_accept(f$b, bad, verifier = fake_relay_verify),
               "chunk length")

  bad <- frame
  bad$payload <- .dsvert_relay_b64url_encode(
    charToRaw(strrep("x", frame$chunk_bytes)))
  expect_error(.dsvert_relay_accept(f$b, bad, verifier = fake_relay_verify),
               "chunk hash")
})

test_that("tampering with signed metadata cannot produce a ready envelope", {
  f <- relay_fixture(frame_bytes = 64L)
  frame <- f$frames[[1L]]
  frame$total_bytes <- frame$total_bytes + 1

  expect_error(.dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify),
               "final frame")
  expect_null(.dsvert_relay_payload(
    f$b, f$sender, f$operation_id, "mpc.share.v1"
  ))

  f <- relay_fixture(frame_bytes = 64L)
  frame <- f$frames[[1L]]
  frame$signature <- base64_to_base64url(jsonlite::base64_enc(as.raw(rep(0, 64))))
  expect_error(.dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify),
               "signature")
  expect_null(.dsvert_relay_payload(
    f$b, f$sender, f$operation_id, "mpc.share.v1"
  ))
})

test_that("a malicious relay cannot alter K=2, K=3 or K=5 peer traffic", {
  for (k in c(2L, 3L, 5L)) {
    identities <- vapply(seq_len(k), function(index) {
      jsonlite::base64_enc(as.raw(
        (seq_len(32L) + 41L * index) %% 256L))
    }, character(1L))
    session_id <- sprintf(
      "%08d-89ab-4def-8123-456789abcdef", k)
    operation_id <- sprintf("op_%032x", 1000L + k)
    sender_id <- .dsvert_relay_peer_id(identities[[1L]])
    recipient_id <- .dsvert_relay_peer_id(identities[[2L]])
    sender <- new.env(parent = emptyenv())
    .dsvert_relay_init(
      sender, session_id, identities[[1L]], identities, "mpc.share.v1")
    frames <- queue_relay_test_stream(
      sender, operation_id, recipient_id, "mpc.share.v1",
      charToRaw(paste0("opaque-k", k)), frame_bytes = 3L)

    receiver <- function() {
      value <- new.env(parent = emptyenv())
      .dsvert_relay_init(
        value, session_id, identities[[2L]], identities, "mpc.share.v1")
      value
    }
    cleanup <- function(value) {
      if (is.environment(value$.dsvert_dsi_relay)) {
        .dsvert_relay_close(value)
      }
      .dsvert_resource_unregister(value)
    }

    target <- receiver()
    expect_error(
      .dsvert_relay_accept(
        target, frames[[2L]], verifier = fake_relay_verify),
      "offset gap", info = paste("reorder K", k))
    expect_null(.dsvert_relay_payload(
      target, sender_id, operation_id, "mpc.share.v1"))
    cleanup(target)

    mutations <- list(
      recipient_peer_id = if (k > 2L) {
        .dsvert_relay_peer_id(identities[[3L]])
      } else {
        sender_id
      },
      sender_peer_id = if (k > 2L) {
        .dsvert_relay_peer_id(identities[[3L]])
      } else {
        recipient_id
      },
      session_id = "ffffffff-ffff-4fff-8fff-ffffffffffff",
      operation_id = "op_ffffffffffffffffffffffffffffffff",
      capability_id = "psi.envelope.v1")
    for (field in names(mutations)) {
      target <- receiver()
      changed <- frames[[1L]]
      changed[[field]] <- mutations[[field]]
      expect_error(
        .dsvert_relay_accept(
          target, changed, verifier = fake_relay_verify),
        info = paste("mutated", field, "K", k))
      expect_null(.dsvert_relay_payload(
        target, sender_id, operation_id, "mpc.share.v1"))
      cleanup(target)
    }

    target <- receiver()
    changed <- frames[[1L]]
    changed$payload <- .dsvert_relay_b64url_encode(charToRaw("bad"))
    expect_error(
      .dsvert_relay_accept(
        target, changed, verifier = fake_relay_verify),
      "chunk length|chunk hash", info = paste("payload mutation K", k))
    expect_null(.dsvert_relay_payload(
      target, sender_id, operation_id, "mpc.share.v1"))
    cleanup(target)

    target <- receiver()
    accepted <- lapply(frames, function(frame) {
      .dsvert_relay_accept(
        target, frame, verifier = fake_relay_verify)
    })
    terminal_ack <- tail(accepted, 1L)[[1L]]$ack_offset
    expect_identical(
      .dsvert_relay_payload(
        target, sender_id, operation_id, "mpc.share.v1"),
      charToRaw(paste0("opaque-k", k)))
    replay <- .dsvert_relay_accept(
      target, tail(frames, 1L)[[1L]], verifier = fake_relay_verify)
    expect_identical(replay$status, "duplicate")
    expect_identical(replay$ack_offset, terminal_ack)
    cleanup(target)
    cleanup(sender)
  }
})

test_that("an unauthenticated first frame allocates no inbox state", {
  f <- relay_fixture(frame_bytes = 3L)
  frame <- f$frames[[1L]]
  frame$signature <- .dsvert_relay_b64url_encode(as.raw(rep(0, 64L)))

  expect_error(.dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify),
               "signature")
  expect_length(.dsvert_relay_state(f$b)$inbox, 0L)
})

test_that("fan-out exchange is atomic and keeps a replayable outbox log", {
  f <- relay_fixture(frame_bytes = 64L)
  request <- setNames(list(list(
    outbox_cursor = 0,
    deliveries = f$frames
  )), f$recipient)

  result <- .dsvert_relay_exchange(
    f$b, request, verifier = fake_relay_verify,
    receipt_signer = fake_relay_signature)
  expect_identical(result$peer_id, f$recipient)
  expect_identical(result$accepted[[1L]]$status, "complete")
  expect_identical(
    .dsvert_relay_payload(f$b, f$sender, f$operation_id, "mpc.share.v1"),
    charToRaw("opaque-ciphertext")
  )

  # B has no queued outbound data yet. Queue one and prove cursors are read-only:
  out <- .dsvert_relay_queue(
    f$b, "op_ffffffffffffffffffffffffffffffff", f$sender, "psi.envelope.v1",
    charToRaw("reply"), frame_bytes = 64L, signer = fake_relay_signature
  )
  empty_request <- setNames(list(list(outbox_cursor = 0, deliveries = list())),
                            f$recipient)
  first <- .dsvert_relay_exchange(f$b, empty_request,
                                  verifier = fake_relay_verify)
  retry <- .dsvert_relay_exchange(f$b, empty_request,
                                  verifier = fake_relay_verify)
  expect_identical(first$outbound, out)
  expect_identical(retry$outbound, out)

  advanced_request <- setNames(
    list(list(outbox_cursor = first$outbox_cursor, deliveries = list())),
    f$recipient
  )
  advanced <- .dsvert_relay_exchange(f$b, advanced_request,
                                     verifier = fake_relay_verify)
  expect_length(advanced$outbound, 0L)
})

test_that("fan-out rejects the whole delivery set atomically on a bad frame", {
  f <- relay_fixture(frame_bytes = 3L)
  bad <- f$frames[[2L]]
  bad$offset <- bad$offset + 1
  request <- setNames(list(list(
    outbox_cursor = 0,
    deliveries = list(f$frames[[1L]], bad)
  )), f$recipient)

  expect_error(.dsvert_relay_exchange(f$b, request,
                                      verifier = fake_relay_verify),
               "offset gap")
  expect_null(.dsvert_relay_payload(
    f$b, f$sender, f$operation_id, "mpc.share.v1"
  ))

  # The valid frame was rolled back and can be accepted as new, not duplicate.
  expect_identical(
    .dsvert_relay_accept(f$b, f$frames[[1L]], verifier = fake_relay_verify)$status,
    "accepted"
  )
})

test_that("exchange preserves retryable backpressure class and exact rollback", {
  old <- options(
    dsvert.relay.exchange_max_bytes = 2 * 1024^2,
    dsvert.relay.spool_max_bytes = 4 * 1024^2,
    dsvert.transport.global_spool_max_bytes = 8 * 1024^3)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(frame_bytes = 512 * 1024L, queue = FALSE)
  receiver <- .dsvert_relay_state(f$b)
  receiver$spool_max_bytes <- 1024^2
  payload <- as.raw((seq_len(400 * 1024L) - 1L) %% 251L)
  operations <- paste0("op_", sprintf("%032x", 301:303))
  frames <- lapply(operations, function(operation) {
    queue_relay_test_stream(
      f$a, operation, f$recipient, "mpc.share.v1", payload,
      frame_bytes = 512 * 1024L)[[1L]]
  })
  before_files <- list.files(receiver$spool, all.files = TRUE, no.. = TRUE)
  before_activity <- receiver$last_activity
  before_session_activity <- f$b$.last_activity
  condition <- tryCatch({
    .dsvert_relay_exchange(
      f$b, setNames(list(list(
        outbox_cursor = receiver$outbox_base, deliveries = frames)),
        f$recipient),
      verifier = fake_relay_verify, receipt_signer = fake_relay_signature)
    NULL
  }, error = identity)

  expect_s3_class(condition, "dsvert_resource_backpressure")
  expect_identical(condition$code, "resource_backpressure")
  expect_true(condition$retryable)
  expect_length(receiver$inbox, 0L)
  expect_identical(receiver$retained_bytes, 0)
  expect_identical(receiver$last_activity, before_activity)
  expect_identical(f$b$.last_activity, before_session_activity)
  expect_identical(
    list.files(receiver$spool, all.files = TRUE, no.. = TRUE), before_files)

  accepted <- .dsvert_relay_exchange(
    f$b, setNames(list(list(
      outbox_cursor = receiver$outbox_base, deliveries = frames[1:2])),
      f$recipient),
    verifier = fake_relay_verify, receipt_signer = fake_relay_signature)
  expect_true(all(vapply(
    accepted$accepted, function(value) identical(value$status, "complete"),
    logical(1L))))
  for (operation in operations[1:2]) {
    expect_identical(.dsvert_relay_payload(
      f$b, f$sender, operation, "mpc.share.v1"), payload)
    .dsvert_relay_mark_payload_consumed(
      f$b, f$sender, operation, "mpc.share.v1")
  }
  expect_length(receiver$inbox, 1L)
  expect_silent(.dsvert_relay_exchange(
    f$b, setNames(list(list(
      outbox_cursor = receiver$outbox_base, deliveries = frames[3])),
      f$recipient),
    verifier = fake_relay_verify, receipt_signer = fake_relay_signature))
})

test_that("frame byte limits do not impose request-count limits", {
  f <- relay_fixture(frame_bytes = 64L)
  old <- options(dsvert.relay.max_envelope_bytes = 4L)
  on.exit(options(old), add = TRUE)
  oversized <- tryCatch(.dsvert_relay_queue(
    f$a, "op_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", f$recipient,
    "mpc.share.v1", charToRaw("12345"), signer = fake_relay_signature),
    error = identity)
  expect_s3_class(oversized, "dsvert_resource_oversize")
  expect_identical(oversized$code, "resource_oversize")
  expect_false(oversized$retryable)

  options(dsvert.relay.max_envelope_bytes = 1024L)
  for (i in seq_len(25L)) {
    op <- sprintf("op_%032x", i)
    expect_silent(.dsvert_relay_queue(
      f$a, op, f$recipient, "mpc.share.v1", charToRaw("x"),
      signer = fake_relay_signature
    ))
  }
})

test_that("relay guards encoded shape before Base64 decoding", {
  f <- relay_fixture(frame_bytes = 64L)
  frame <- f$frames[[1L]]
  frame$payload <- strrep("A", 100000L)

  expect_error(
    .dsvert_relay_accept(f$b, frame, verifier = fake_relay_verify),
    "payload shape")
  expect_length(.dsvert_relay_state(f$b)$inbox, 0L)
})

test_that("outbound data is disk-backed and one exchange has a byte bound", {
  old <- options(
    dsvert.relay.exchange_max_bytes = 16 * 1024L,
    dsvert.relay.spool_max_bytes = 1024^2L)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(frame_bytes = 8 * 1024L, queue = FALSE)
  payload <- as.raw((seq_len(40 * 1024L) - 1L) %% 256L)
  operation <- "op_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  frames <- queue_relay_test_stream(
    f$a, operation, f$recipient, "mpc.share.v1", payload,
    frame_bytes = 8 * 1024L)
  state <- .dsvert_relay_state(f$a)

  expect_length(frames, 5L)
  expect_true(file.exists(state$outgoing[[paste(
    f$recipient, operation, "mpc.share.v1", sep = "|")]]$path))
  expect_false(any(vapply(state$outbox, function(value)
    "payload" %in% names(value), logical(1L))))

  request <- setNames(list(list(outbox_cursor = 0, deliveries = list())),
                      f$sender)
  first <- .dsvert_relay_exchange(f$a, request, verifier = fake_relay_verify)
  replay <- .dsvert_relay_exchange(f$a, request, verifier = fake_relay_verify)
  expect_identical(first, replay)
  expect_length(first$outbound, 2L)
  expect_identical(first$outbox_cursor, 16 * 1024)
  expect_identical(first$outbox_eof, 40 * 1024)
  expect_lte(sum(vapply(first$outbound, `[[`, numeric(1L), "chunk_bytes")),
             16 * 1024)
})

test_that("absolute byte acknowledgements compact and release spool capacity", {
  old <- options(
    dsvert.relay.exchange_max_bytes = 1024^2L,
    dsvert.relay.spool_max_bytes = 1024^2L)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(frame_bytes = 64L, queue = FALSE)
  first_payload <- as.raw(rep(0x11, 700 * 1024L))
  second_payload <- as.raw(rep(0x22, 400 * 1024L))
  first_operation <- "op_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  second_operation <- "op_cccccccccccccccccccccccccccccccc"
  .dsvert_relay_queue(
    f$a, first_operation, f$recipient, "mpc.share.v1", first_payload,
    frame_bytes = 1024^2L, signer = fake_relay_signature)
  expect_error(.dsvert_relay_queue(
    f$a, second_operation, f$recipient, "mpc.share.v1", second_payload,
    frame_bytes = 1024^2L, signer = fake_relay_signature),
    "spool capacity")

  poll <- setNames(list(list(outbox_cursor = 0, deliveries = list())), f$sender)
  sent <- .dsvert_relay_exchange(f$a, poll, verifier = fake_relay_verify)
  ack <- setNames(list(list(
    outbox_cursor = sent$outbox_cursor, deliveries = list())), f$sender)
  .dsvert_relay_exchange(f$a, ack, verifier = fake_relay_verify)
  expect_identical(.dsvert_relay_state(f$a)$retained_bytes, 0)
  expect_silent(.dsvert_relay_queue(
    f$a, second_operation, f$recipient, "mpc.share.v1", second_payload,
    frame_bytes = 1024^2L, signer = fake_relay_signature))
})

test_that("global byte backpressure spans sessions and leaves no penalty", {
  old <- options(
    dsvert.transport.global_spool_max_bytes = 1024^2,
    dsvert.relay.spool_max_bytes = 2 * 1024^2,
    dsvert.relay.exchange_max_bytes = 1024^2)
  on.exit(options(old), add = TRUE)
  first <- relay_fixture(queue = FALSE)
  second <- relay_fixture(queue = FALSE)
  op_first <- "op_10101010101010101010101010101010"
  op_second <- "op_20202020202020202020202020202020"
  .dsvert_relay_queue_begin(
    first$a, op_first, first$recipient, "mpc.share.v1",
    total_bytes = 700 * 1024, frame_bytes = 1024^2)

  condition <- tryCatch({
    .dsvert_relay_queue_begin(
      second$a, op_second, second$recipient, "mpc.share.v1",
      total_bytes = 400 * 1024, frame_bytes = 1024^2)
    NULL
  }, error = identity)
  expect_s3_class(condition, "dsvert_resource_backpressure")
  expect_identical(condition$code, "resource_backpressure")
  expect_true(condition$retryable)
  expect_identical(.dsvert_relay_state(second$a)$retained_bytes, 0)
  expect_length(.dsvert_relay_state(second$a)$outgoing, 0L)
  expect_true(all(grepl(
    "^resource-[0-9]+$", names(.dsvert_resource_registry$sessions))))

  .dsvert_relay_queue_abort(
    first$a, op_first, first$recipient, "mpc.share.v1")
  expect_silent(.dsvert_relay_queue_begin(
    second$a, op_second, second$recipient, "mpc.share.v1",
    total_bytes = 400 * 1024, frame_bytes = 1024^2))
})

test_that("terminal receipts are sticky, peer-signed, and payload-bound", {
  f <- relay_fixture(frame_bytes = 64L)
  request <- setNames(list(list(
    outbox_cursor = 0, deliveries = f$frames)), f$recipient)
  first <- .dsvert_relay_exchange(
    f$b, request, verifier = fake_relay_verify,
    receipt_signer = fake_relay_signature)
  replay <- .dsvert_relay_exchange(
    f$b, request, verifier = fake_relay_verify,
    receipt_signer = fake_relay_signature)
  receipt <- first$accepted[[1L]]$receipt

  expect_identical(replay$accepted[[1L]]$receipt, receipt)
  expect_true(.dsvert_relay_verify_receipt(
    f$a, receipt, verifier = fake_relay_verify))
  mutations <- list(
    version = "dsvert-relay-receipt-v0",
    session_id = "ffffffff-ffff-ffff-ffff-ffffffffffff",
    operation_id = "op_ffffffffffffffffffffffffffffffff",
    sender_peer_id = f$recipient,
    recipient_peer_id = f$sender,
    capability_id = "psi.envelope.v1",
    total_bytes = as.numeric(receipt$total_bytes) + 1,
    payload_hash = strrep("f", 64L),
    ack_offset = as.numeric(receipt$ack_offset) - 1,
    terminal = FALSE,
    signature = paste0(
      if (substr(receipt$signature, 1L, 1L) == "A") "B" else "A",
      substr(receipt$signature, 2L, nchar(receipt$signature))))
  for (field in names(mutations)) {
    changed <- receipt
    changed[[field]] <- mutations[[field]]
    expect_error(.dsvert_relay_verify_receipt(
      f$a, changed, verifier = fake_relay_verify),
      info = paste("mutated terminal receipt field", field))
  }
})

test_that("many sequential relay transfers retain only one replay window", {
  f <- relay_fixture(frame_bytes = 16L, queue = FALSE)
  payload <- as.raw((seq_len(64L) - 1L) %% 251L)
  compact_size <- NULL
  final_frames <- NULL
  final_receipt <- NULL

  for (index in seq_len(50L)) {
    operation <- paste0("op_", sprintf("%032x", index))
    frames <- queue_relay_test_stream(
      f$a, operation, f$recipient, "mpc.share.v1", payload, 16L)
    received <- .dsvert_relay_exchange(
      f$b, setNames(list(list(
        outbox_cursor = .dsvert_relay_state(f$b)$outbox_base,
        deliveries = frames)), f$recipient),
      verifier = fake_relay_verify, receipt_signer = fake_relay_signature)
    receipts <- Filter(Negate(is.null), lapply(
      received$accepted, `[[`, "receipt"))
    expect_length(receipts, 1L)
    receipt <- receipts[[1L]]
    expect_identical(.dsvert_relay_payload(
      f$b, f$sender, operation, "mpc.share.v1"), payload)
    .dsvert_relay_mark_payload_consumed(
      f$b, f$sender, operation, "mpc.share.v1")

    sender_state <- .dsvert_relay_state(f$a)
    eof <- tail(sender_state$outbox, 1L)[[1L]]$end
    .dsvert_relay_exchange(
      f$a, setNames(list(list(
        outbox_cursor = eof, deliveries = list())), f$sender),
      verifier = fake_relay_verify)
    expect_true(.dsvert_relay_verify_receipt(
      f$a, receipt, verifier = fake_relay_verify))
    .dsvert_relay_record_verified_receipt(f$a, receipt)

    if (index == 5L) {
      compact_size <- as.numeric(object.size(list(
        inbox = .dsvert_relay_state(f$b)$inbox,
        outgoing = .dsvert_relay_state(f$a)$outgoing,
        inbox_latest = .dsvert_relay_state(f$b)$inbox_latest_consumed,
        outgoing_latest =
          .dsvert_relay_state(f$a)$outgoing_latest_receipt)))
    }
    final_frames <- frames
    final_receipt <- receipt
  }

  sender <- .dsvert_relay_state(f$a)
  recipient <- .dsvert_relay_state(f$b)
  final_size <- as.numeric(object.size(list(
    inbox = recipient$inbox, outgoing = sender$outgoing,
    inbox_latest = recipient$inbox_latest_consumed,
    outgoing_latest = sender$outgoing_latest_receipt)))
  expect_length(sender$outgoing, 1L)
  expect_length(recipient$inbox, 1L)
  expect_length(sender$outgoing_latest_receipt, 1L)
  expect_length(recipient$inbox_latest_consumed, 1L)
  expect_identical(sender$retained_bytes, 0)
  expect_identical(recipient$retained_bytes,
                   as.numeric(length(payload) + 4L * 1024L))
  expect_lte(final_size, compact_size + 2048)

  replay <- .dsvert_relay_exchange(
    f$b, setNames(list(list(
      outbox_cursor = recipient$outbox_base,
      deliveries = final_frames)), f$recipient),
    verifier = fake_relay_verify, receipt_signer = fake_relay_signature)
  expect_true(all(vapply(
    replay$accepted, function(value) identical(value$status, "duplicate"),
    logical(1L))))
  replay_receipts <- Filter(
    Negate(is.null), lapply(replay$accepted, `[[`, "receipt"))
  expect_length(replay_receipts, length(final_frames))
  expect_true(all(vapply(
    replay_receipts, identical, logical(1L), final_receipt)))
})

test_that("large replay, reconnect cycle, and compaction preserve every byte", {
  old <- options(
    dsvert.relay.exchange_max_bytes = 128 * 1024L,
    dsvert.relay.spool_max_bytes = 1024^2L)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(frame_bytes = 64 * 1024L, queue = FALSE)
  payload <- as.raw((seq_len(512 * 1024L) - 1L) %% 251L)
  operation <- "op_dddddddddddddddddddddddddddddddd"
  queue_relay_test_stream(
    f$a, operation, f$recipient, "mpc.share.v1", payload,
    frame_bytes = 64 * 1024L)

  source_cursor <- 0
  lost_response <- NULL
  terminal <- NULL
  cycles <- 0L
  repeat {
    poll <- setNames(list(list(
      outbox_cursor = source_cursor, deliveries = list())), f$sender)
    source <- .dsvert_relay_exchange(
      f$a, poll, verifier = fake_relay_verify)
    cycles <- cycles + 1L
    if (is.null(lost_response)) {
      lost_response <- source
      source <- .dsvert_relay_exchange(
        f$a, poll, verifier = fake_relay_verify)
      expect_identical(source, lost_response)
    }
    if (!length(source$outbound)) break
    deliver <- setNames(list(list(
      outbox_cursor = 0, deliveries = source$outbound)), f$recipient)
    received <- .dsvert_relay_exchange(
      f$b, deliver, verifier = fake_relay_verify,
      receipt_signer = fake_relay_signature)
    receipts <- lapply(received$accepted, `[[`, "receipt")
    receipts <- Filter(Negate(is.null), receipts)
    if (length(receipts)) terminal <- receipts[[length(receipts)]]
    source_cursor <- source$outbox_cursor
  }

  rebuilt <- .dsvert_relay_payload(
    f$b, f$sender, operation, "mpc.share.v1")
  expect_identical(digest::digest(rebuilt, "sha256", serialize = FALSE),
                   digest::digest(payload, "sha256", serialize = FALSE))
  expect_true(.dsvert_relay_verify_receipt(
    f$a, terminal, verifier = fake_relay_verify))
  expect_identical(.dsvert_relay_state(f$a)$outbox_base,
                   as.numeric(length(payload)))
  expect_identical(.dsvert_relay_state(f$a)$retained_bytes, 0)
  expect_lte(cycles, 5L)
})

test_that("stream producers are bounded, idempotent, and backpressured", {
  old <- options(
    dsvert.relay.max_envelope_bytes = 32 * 1024^2,
    dsvert.relay.exchange_max_bytes = 480 * 1024,
    dsvert.relay.spool_max_bytes = 8 * 1024^2)
  on.exit(options(old), add = TRUE)
  small <- relay_fixture(queue = FALSE)
  operation <- "op_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  before_files <- list.files(.dsvert_relay_state(small$a)$spool)

  oversize <- tryCatch(.dsvert_relay_queue_begin(
    small$a, operation, small$recipient, "mpc.share.v1",
    total_bytes = 16 * 1024^2, frame_bytes = 480 * 1024),
    error = identity)
  expect_s3_class(oversize, "dsvert_resource_oversize")
  expect_identical(oversize$code, "resource_oversize")
  expect_false(oversize$retryable)
  expect_false(inherits(oversize, "dsvert_resource_backpressure"))
  expect_match(conditionMessage(oversize), "dsvert_resource_oversize", fixed = TRUE)
  expect_length(.dsvert_relay_state(small$a)$outgoing, 0L)
  expect_identical(.dsvert_relay_state(small$a)$retained_bytes, 0)
  expect_identical(list.files(.dsvert_relay_state(small$a)$spool), before_files)

  options(dsvert.relay.spool_max_bytes = 32 * 1024^2)
  f <- relay_fixture(queue = FALSE)
  total <- 16 * 1024^2
  opened <- .dsvert_relay_queue_begin(
    f$a, operation, f$recipient, "mpc.share.v1", total_bytes = total,
    frame_bytes = 480 * 1024)
  key <- paste(f$recipient, operation, "mpc.share.v1", sep = "|")
  stream <- .dsvert_relay_state(f$a)$outgoing[[key]]
  expect_identical(opened$committed_bytes, 0)

  peak_chunk <- 0
  for (index in seq_along(stream$frame_offsets)) {
    offset <- stream$frame_offsets[[index]]
    n <- stream$frame_lengths[[index]]
    chunk <- as.raw(((offset + seq_len(n) - 1) %% 251))
    peak_chunk <- max(peak_chunk, as.numeric(object.size(chunk)))
    committed <- .dsvert_relay_queue_append(
      f$a, operation, f$recipient, "mpc.share.v1", offset, chunk)
    expect_identical(committed, offset + n)
    if (index == 1L) {
      before_hash <- digest::digest(
        file = stream$path, algo = "sha256", serialize = FALSE)
      expect_identical(.dsvert_relay_queue_append(
        f$a, operation, f$recipient, "mpc.share.v1", offset, chunk),
        committed)
      conflict <- chunk
      conflict[[1L]] <- as.raw((as.integer(conflict[[1L]]) + 1L) %% 256L)
      expect_error(.dsvert_relay_queue_append(
        f$a, operation, f$recipient, "mpc.share.v1", offset, conflict),
        "Conflicting retry")
      expect_identical(digest::digest(
        file = stream$path, algo = "sha256", serialize = FALSE), before_hash)
    }
  }
  expect_lte(peak_chunk, 481 * 1024)
  expect_identical(as.numeric(file.size(stream$path)), as.numeric(total))
  payload_hash <- digest::digest(
    file = stream$path, algo = "sha256", serialize = FALSE)
  sealed <- .dsvert_relay_queue_seal(
    f$a, operation, f$recipient, "mpc.share.v1", payload_hash,
    signer = fake_relay_signature)
  expect_identical(sealed$status, "queued")
  expect_identical(.dsvert_relay_queue_begin(
    f$a, operation, f$recipient, "mpc.share.v1", total_bytes = total,
    payload_hash = payload_hash, frame_bytes = 480 * 1024)$status, "queued")
  expect_error(.dsvert_relay_queue_begin(
    f$a, operation, f$recipient, "mpc.share.v1", total_bytes = total,
    payload_hash = strrep("f", 64L), frame_bytes = 480 * 1024),
    "Conflicting retry")
  expect_error(.dsvert_relay_queue_seal(
    f$a, operation, f$recipient, "mpc.share.v1", strrep("f", 64L),
    signer = fake_relay_signature), "Conflicting retry")

  sender_state <- .dsvert_relay_state(f$a)
  expect_lte(as.numeric(object.size(list(
    outgoing = sender_state$outgoing, outbox = sender_state$outbox))),
    256 * 1024)
  first_frame <- .dsvert_relay_materialize_frame(sender_state, key, 1L)
  expect_lte(first_frame$chunk_bytes, 480 * 1024)

  source_cursor <- 0
  repeat {
    source <- .dsvert_relay_exchange(
      f$a, setNames(list(list(
        outbox_cursor = source_cursor, deliveries = list())), f$sender),
      verifier = fake_relay_verify)
    if (!length(source$outbound)) break
    .dsvert_relay_exchange(
      f$b, setNames(list(list(
        outbox_cursor = 0, deliveries = source$outbound)), f$recipient),
      verifier = fake_relay_verify, receipt_signer = fake_relay_signature)
    source_cursor <- source$outbox_cursor
  }
  receiver_state <- .dsvert_relay_state(f$b)
  incoming_key <- paste(f$sender, operation, "mpc.share.v1", sep = "|")
  incoming <- receiver_state$inbox[[incoming_key]]
  expect_true(incoming$complete)
  expect_identical(digest::digest(
    file = incoming$path, algo = "sha256", serialize = FALSE), payload_hash)
  expect_lte(as.numeric(object.size(receiver_state$inbox)), 256 * 1024)
  expect_identical(.dsvert_relay_state(f$a)$retained_bytes, 0)
  expect_error(.dsvert_relay_queue_begin(
    f$a, operation, f$recipient, "mpc.share.v1", total_bytes = total,
    payload_hash = strrep("f", 64L), frame_bytes = 480 * 1024),
    "Conflicting retry")
  expect_error(.dsvert_relay_queue_seal(
    f$a, operation, f$recipient, "mpc.share.v1", strrep("f", 64L),
    signer = fake_relay_signature), "acknowledged relay stream")
})

test_that("tiny-frame metadata amplification fails before allocation or verification", {
  old <- options(
    dsvert.relay.metadata_max_bytes = 64 * 1024,
    dsvert.relay.spool_max_bytes = 1024^2)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(queue = FALSE)
  state <- .dsvert_relay_state(f$a)
  before_files <- list.files(state$spool)
  operation <- "op_fefefefefefefefefefefefefefefefe"

  oversized <- tryCatch(.dsvert_relay_queue_begin(
    f$a, operation, f$recipient, "mpc.share.v1",
    total_bytes = 65L, frame_bytes = 1L),
    error = identity)
  expect_s3_class(oversized, "dsvert_resource_oversize")
  expect_false(oversized$retryable)
  expect_length(state$outgoing, 0L)
  expect_identical(state$retained_bytes, 0)
  expect_identical(list.files(state$spool), before_files)

  one_byte <- as.raw(0x42)
  incoming <- list(
    version = .DSVERT_RELAY_VERSION,
    session_id = state$session_id,
    operation_id = operation,
    sender_peer_id = f$recipient,
    recipient_peer_id = f$sender,
    capability_id = "mpc.share.v1",
    sequence = 0, offset = 0, chunk_bytes = 1, total_bytes = 65,
    final = FALSE,
    payload_hash = digest::digest(raw(65L), "sha256", serialize = FALSE),
    chunk_hash = digest::digest(one_byte, "sha256", serialize = FALSE),
    payload = .dsvert_relay_b64url_encode(one_byte),
    signature = strrep("A", 86L))
  verifier_calls <- 0L
  oversized <- tryCatch(.dsvert_relay_accept(
    f$a, incoming, verifier = function(...) {
      verifier_calls <<- verifier_calls + 1L
      TRUE
    }), error = identity)
  expect_s3_class(oversized, "dsvert_resource_oversize")
  expect_false(oversized$retryable)
  expect_identical(verifier_calls, 0L)
  expect_length(state$inbox, 0L)
  expect_identical(list.files(state$spool), before_files)
})

test_that("failed signing cannot publish a descriptor-less outbound stream", {
  f <- relay_fixture(queue = FALSE)
  operation <- "op_fdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfd"
  payload <- as.raw((seq_len(128L) - 1L) %% 251L)
  payload_hash <- digest::digest(payload, "sha256", serialize = FALSE)
  .dsvert_relay_queue_begin(
    f$a, operation, f$recipient, "mpc.share.v1",
    total_bytes = length(payload), payload_hash = payload_hash,
    frame_bytes = 64L)
  for (offset in c(0, 64)) {
    .dsvert_relay_queue_append(
      f$a, operation, f$recipient, "mpc.share.v1", offset,
      payload[(offset + 1L):(offset + 64L)])
  }

  expect_error(.dsvert_relay_queue_seal(
    f$a, operation, f$recipient, "mpc.share.v1", payload_hash,
    signer = function(message) stop("signer unavailable")),
    "signer unavailable")
  state <- .dsvert_relay_state(f$a)
  key <- paste(f$recipient, operation, "mpc.share.v1", sep = "|")
  expect_identical(state$outgoing[[key]]$status, "building")
  expect_null(state$outgoing[[key]]$payload_hash)
  expect_null(state$outgoing[[key]]$signature)
  expect_length(state$outbox, 0L)

  expect_identical(.dsvert_relay_queue_seal(
    f$a, operation, f$recipient, "mpc.share.v1", payload_hash,
    signer = fake_relay_signature)$status, "queued")
  expect_length(.dsvert_relay_state(f$a)$outbox, 2L)
})

test_that("an unpublished stream can be rolled back without residue", {
  old <- options(
    dsvert.relay.exchange_max_bytes = 480 * 1024,
    dsvert.relay.spool_max_bytes = 4 * 1024^2)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(queue = FALSE)
  operation <- "op_fffffffffffffffffffffffffffffffe"
  .dsvert_relay_queue_begin(
    f$a, operation, f$recipient, "mpc.share.v1", total_bytes = 1024^2,
    frame_bytes = 480 * 1024)
  key <- paste(f$recipient, operation, "mpc.share.v1", sep = "|")
  state <- .dsvert_relay_state(f$a)
  path <- state$outgoing[[key]]$path
  .dsvert_relay_queue_append(
    f$a, operation, f$recipient, "mpc.share.v1", 0,
    as.raw(rep(0x33, 480 * 1024)))

  expect_true(.dsvert_relay_queue_abort(
    f$a, operation, f$recipient, "mpc.share.v1"))
  expect_false(file.exists(path))
  expect_null(state$outgoing[[key]])
  expect_identical(state$retained_bytes, 0)
  expect_false(.dsvert_relay_queue_abort(
    f$a, operation, f$recipient, "mpc.share.v1"))
})

test_that("inactive relay sessions expire and remove their bounded spool", {
  f <- relay_fixture(frame_bytes = 64L)
  state <- .dsvert_relay_state(f$a)
  spool <- state$spool
  state$last_activity <- .dsvert_relay_now() - state$ttl_seconds - 1

  expect_error(.dsvert_relay_gc(f$a), "session expired")
  expect_false(dir.exists(spool))
  expect_null(f$a$.dsvert_dsi_relay)
})

test_that("progressing relay transfers refresh the inactivity lease", {
  old <- options(dsvert.relay.ttl_seconds = 10)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(queue = FALSE)
  operation <- "op_fffffffffffffffffffffffffffffffd"
  clock <- 100
  state <- .dsvert_relay_state(f$a)
  state$last_activity <- clock

  testthat::with_mocked_bindings({
    .dsvert_relay_queue_begin(
      f$a, operation, f$recipient, "mpc.share.v1",
      total_bytes = 128, frame_bytes = 64)
    clock <- clock + 9
    .dsvert_relay_queue_append(
      f$a, operation, f$recipient, "mpc.share.v1", 0,
      as.raw(rep(0x11, 64)))
    expect_identical(.dsvert_relay_state(f$a)$last_activity, clock)
    clock <- clock + 9
    .dsvert_relay_queue_append(
      f$a, operation, f$recipient, "mpc.share.v1", 64,
      as.raw(rep(0x22, 64)))
    expect_identical(.dsvert_relay_state(f$a)$last_activity, clock)
    expect_invisible(.dsvert_relay_gc(f$a, now = clock + 10))
  }, .dsvert_relay_now = function() clock, .package = "dsVert")

  expect_error(.dsvert_relay_gc(f$a, now = clock + 11), "session expired")
})

test_that("replays, invalid frames, and empty polls cannot extend the lease", {
  old <- options(dsvert.relay.ttl_seconds = 10)
  on.exit(options(old), add = TRUE)
  f <- relay_fixture(frame_bytes = 3L)
  clock <- 200
  state <- .dsvert_relay_state(f$b)
  state$last_activity <- clock
  f$b$.last_activity <- clock

  testthat::with_mocked_bindings({
    clock <- 205
    first <- .dsvert_relay_accept(
      f$b, f$frames[[1L]], verifier = fake_relay_verify)
    expect_identical(first$status, "accepted")
    expect_identical(.dsvert_relay_state(f$b)$last_activity, clock)
    expect_identical(f$b$.last_activity, clock)

    clock <- 209
    duplicate <- .dsvert_relay_accept(
      f$b, f$frames[[1L]], verifier = fake_relay_verify)
    expect_identical(duplicate$status, "duplicate")
    expect_identical(.dsvert_relay_state(f$b)$last_activity, 205)
    expect_identical(f$b$.last_activity, 205)

    forged <- f$frames[[1L]]
    forged$operation_id <- "op_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    expect_error(
      .dsvert_relay_accept(f$b, forged, verifier = fake_relay_verify),
      "signature verification failed")
    expect_identical(.dsvert_relay_state(f$b)$last_activity, 205)
    expect_identical(f$b$.last_activity, 205)

    peer <- .dsvert_relay_state(f$b)$self_peer_id
    request <- stats::setNames(list(list(
      outbox_cursor = .dsvert_relay_state(f$b)$outbox_base,
      deliveries = list())), peer)
    .dsvert_relay_exchange(f$b, request)
    expect_identical(.dsvert_relay_state(f$b)$last_activity, 205)
    expect_identical(f$b$.last_activity, 205)
  }, .dsvert_relay_now = function() clock, .package = "dsVert")

  expect_error(.dsvert_relay_gc(f$b, now = 216), "session expired")
})

test_that("real pinned Ed25519 signatures authenticate relay envelopes", {
  identity <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(charToRaw("relay-test-seed"))
  ))
  message <- charToRaw("canonical relay envelope")
  signature <- .dsvert_relay_sign_message(message, identity$identity_sk)

  expect_true(.dsvert_relay_verify_message(
    message, identity$identity_pk, signature
  ))
  expect_false(.dsvert_relay_verify_message(
    charToRaw("changed relay envelope"), identity$identity_pk, signature
  ))
})

test_that("only the purpose-bound padded PSI relay is remotely exposed", {
  candidates <- c(
    .dsvert_test_package_file("DESCRIPTION"),
    system.file("DESCRIPTION", package = "dsVert")
  )
  desc_path <- candidates[file.exists(candidates)][1L]
  expect_true(length(desc_path) == 1L && nzchar(desc_path))
  desc <- read.dcf(desc_path)
  aggregate_methods <- trimws(strsplit(desc[1L, "AggregateMethods"], ",")[[1L]])
  expect_identical(
    grep("RelayExchange", aggregate_methods, value = TRUE, fixed = TRUE),
    "psiPaddedRelayExchangeDS")
  expect_identical(
    grep("relay", getNamespaceExports("dsVert"), value = TRUE,
         ignore.case = TRUE),
    "psiPaddedRelayExchangeDS")
})
