.typed_blob_test_b64 <- function(byte, n) {
  gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(byte, n))))
}

.typed_blob_test_fixture <- function(
    self_name = "self", peer_name = "peer", own_byte = 1L,
    peer_byte = 2L, peer_transport_byte = 3L) {
  ss <- new.env(parent = emptyenv())
  session_id <- "12345678-1234-4234-8234-123456789abc"
  own_identity <- .typed_blob_test_b64(own_byte, 32L)
  peer_identity <- .typed_blob_test_b64(peer_byte, 32L)
  peer_transport <- .typed_blob_test_b64(peer_transport_byte, 32L)
  ss$.session_id <- session_id
  ss$keys <- list(identity_pk = own_identity, transport_sk = "test-secret")
  ss$peer_transport_pks <- stats::setNames(list(peer_transport), peer_name)
  ss$.typed_blob_self_name <- self_name
  ss$.typed_blob_peer_identity_pks <- stats::setNames(
    list(peer_identity), peer_name)
  ss$.typed_blob_peer_binding_digest <- strrep("a", 64L)
  list(
    ss = ss, session_id = session_id, own_identity = own_identity,
    peer_identity = peer_identity,
    peer_transport = base64_to_base64url(peer_transport))
}

.typed_blob_test_pair <- function() {
  list(
    sender = .typed_blob_test_fixture(
      self_name = "self", peer_name = "peer", own_byte = 1L,
      peer_byte = 2L, peer_transport_byte = 3L),
    recipient = .typed_blob_test_fixture(
      self_name = "peer", peer_name = "self", own_byte = 2L,
      peer_byte = 1L, peer_transport_byte = 4L))
}

.typed_blob_test_sign <- function(message, identity_sk) {
  gsub("[\r\n]", "", jsonlite::base64_enc(
    openssl::sha512(charToRaw(message))))
}

.typed_blob_test_verify <- function(message, identity_pk, signature) {
  identical(signature, .typed_blob_test_sign(message, "ignored"))
}

.typed_blob_mutate_envelope <- function(token, mutate,
                                        receipt = FALSE) {
  envelope <- jsonlite::fromJSON(rawToChar(.dsvert_relay_b64url_decode(
    token, "test typed-blob envelope")), simplifyVector = FALSE)
  body <- jsonlite::fromJSON(rawToChar(.dsvert_relay_b64url_decode(
    envelope$body, "test typed-blob body")), simplifyVector = FALSE)
  body <- mutate(body)
  envelope$body <- .dsvert_typed_blob_body_token(body)
  message <- if (isTRUE(receipt)) {
    .dsvert_typed_blob_receipt_signature_message(envelope$body)
  } else {
    .dsvert_typed_blob_signature_message(envelope$body)
  }
  envelope$signature <- base64_to_base64url(
    .typed_blob_test_sign(message, "ignored"))
  .dsvert_relay_b64url_encode(charToRaw(as.character(jsonlite::toJSON(
    envelope, auto_unbox = TRUE, null = "null", digits = NA))))
}

.typed_blob_with_crypto <- function(
    fixture, code, verify = .typed_blob_test_verify) {
  testthat::with_mocked_bindings(
    code,
    .S = function(session_id) fixture$ss,
    .dsvert_secure_random_bytes = function(n) {
      counter <- fixture$ss$.test_random_counter %||% 0L
      fixture$ss$.test_random_counter <- counter + 1L
      as.raw((seq_len(n) + counter) %% 256L)
    },
    .get_identity_keypair = function() list(
      identity_pk = fixture$own_identity, identity_sk = "test-secret"),
    .sign_transport_pk = .typed_blob_test_sign,
    .verify_peer_identity = verify,
    mpcTypedBlobStoreDS = .mpcTypedBlobStoreDS_impl,
    mpcTypedBlobReceiptDS = .mpcTypedBlobReceiptDS_impl)
}

test_that("remote typed endpoints reject safely without exposing error text", {
  store <- mpcTypedBlobStoreDS("not-a-ticket", "A", 0, "not-a-session")
  read <- mpcTypedBlobReadDS("not-a-ticket", 0, 1, "not-a-session")
  receipt <- mpcTypedBlobReceiptDS("not-a-receipt", "not-a-session")
  source <- mpcTypedSourceProbeDS("not-a-peer", 1, "not-a-session")
  expected_store <- list(
    version = "dsvert-typed-blob-rejection-v1",
    operation = "store", rejected = TRUE)
  expected_receipt <- list(
    version = "dsvert-typed-blob-rejection-v1",
    operation = "receipt", rejected = TRUE)
  expected_read <- list(
    version = "dsvert-typed-blob-rejection-v1",
    operation = "read", rejected = TRUE)
  expected_source <- list(
    version = "dsvert-typed-blob-rejection-v1",
    operation = "source-probe", rejected = TRUE)
  expect_identical(store, expected_store)
  expect_identical(read, expected_read)
  expect_identical(receipt, expected_receipt)
  expect_identical(source, expected_source)
  expect_false(any(grepl(
    "ticket|signature|session|conflict",
    unlist(store, use.names = FALSE), ignore.case = TRUE)))
})

test_that("optional formal routing does not block Synopsis tickets", {
  expected <- c(
    .DSVERT_FORMAL_FINALIZER_HANDOFF_CAPABILITY =
      "blob.formal-finalizer-handoff.v1",
    .DSVERT_FORMAL_GLM_CONTROL_CAPABILITY =
      "blob.formal-glm-one-draw-control.v1",
    .DSVERT_FORMAL_COX_CONTROL_CAPABILITY =
      "blob.formal-cox-blockwise-control.v1")
  expect_identical(unname(vapply(names(expected), get,
                                  character(1L), inherits = TRUE)),
                   unname(expected))
  for (validator in list(
      .dsvert_typed_blob_validate_formal_finalizer_route,
      .dsvert_typed_blob_validate_formal_glm_control_route,
      .dsvert_typed_blob_validate_formal_cox_control_route)) {
    expect_silent(validator(.DSVERT_TYPED_BLOB_SYNOPSIS_FINAL_CAPABILITY,
                            list(context = list()), "peer_a", "peer_b"))
  }
})

test_that("typed source spool reads fixed idempotent frames and releases on receipt", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- paste(rep(c("A", "b", "1", "_"), 31L), collapse = "")
  stage <- .dsvert_typed_blob_source_stage_path(pair$sender$ss)
  con <- file(stage, "wb")
  writeBin(charToRaw(payload), con, useBytes = TRUE)
  close(con)
  Sys.chmod(stage, mode = "0600")
  request <- list(kind = "source-test")
  minted <- .typed_blob_with_crypto(pair$sender, {
    transfer <- .dsvert_typed_blob_mint_file(
      pair$sender$ss, pair$sender$session_id,
      "blob.transport.source-probe.v1", pair$sender$peer_transport,
      stage, list(raw_bytes = "93", ring = "63"),
      producer = "mpcTypedSourceProbeDS")
    .dsvert_typed_blob_operation_commit(
      pair$sender$ss, "mpcTypedSourceProbeDS", request,
      list(source_transfer = transfer))$source_transfer
  })
  source_path <- pair$sender$ss$.typed_blob_outbound[[
    minted$transfer_id]]$source_path
  expect_true(file.exists(source_path))
  expect_identical(
    digest::digest(file = source_path, algo = "sha256", serialize = FALSE),
    minted$payload_sha256)

  first <- .typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReadDS_impl(
      minted$ticket, 0, 17, pair$sender$session_id))
  expect_identical(first$chunk, substr(payload, 1L, 17L))
  expect_false(first$final)
  high_water <- pair$sender$ss$.typed_blob_outbound[[
    minted$transfer_id]]$source_high_water
  duplicate <- .typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReadDS_impl(
      minted$ticket, 0, 17, pair$sender$session_id))
  expect_identical(duplicate, first)
  expect_identical(pair$sender$ss$.typed_blob_outbound[[
    minted$transfer_id]]$source_high_water, high_water)
  expect_error(.typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReadDS_impl(
      minted$ticket, 17, 18, pair$sender$session_id)), "geometry")
  expect_error(.typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReadDS_impl(
      minted$ticket, 34, 17, pair$sender$session_id)), "out of order")

  offset <- 0
  receipt <- NULL
  while (offset < minted$payload_chars) {
    frame <- .typed_blob_with_crypto(pair$sender,
      .mpcTypedBlobReadDS_impl(
        minted$ticket, offset, 17, pair$sender$session_id))
    ack <- .typed_blob_with_crypto(pair$recipient,
      .mpcTypedBlobStoreDS_impl(
        minted$ticket, frame$chunk, offset,
        pair$recipient$session_id))
    offset <- offset + frame$chunk_chars
    if (isTRUE(ack$sealed)) receipt <- ack$receipt
  }
  expect_identical(offset, minted$payload_chars)
  expect_match(receipt, "^[A-Za-z0-9_-]+$")
  confirmed <- .typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReceiptDS_impl(receipt, pair$sender$session_id))
  expect_true(confirmed$confirmed)
  expect_false(file.exists(source_path))
  expect_null(pair$sender$ss$.typed_blob_outbound_ticket_index[[
    digest::digest(minted$ticket, algo = "sha256", serialize = FALSE)]])
})

test_that("inline typed sources stream by ticket without entering producer results", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- paste(rep(c("A", "b", "1", "_"), 31L), collapse = "")
  request <- list(kind = "inline-source-test")
  result <- .typed_blob_with_crypto(pair$sender, {
    transfer <- .dsvert_typed_blob_mint_inline_source(
      pair$sender$ss, pair$sender$session_id,
      "blob.transport.source-probe.v1", pair$sender$peer_transport,
      payload, list(raw_bytes = "93", ring = "63"),
      producer = "mpcTypedSourceProbeDS")
    .dsvert_typed_blob_operation_commit(
      pair$sender$ss, "mpcTypedSourceProbeDS", request,
      list(source_transfer = transfer))
  })
  expect_identical(sort(names(result)), "source_transfer")
  transfer <- result$source_transfer
  outbound <- pair$sender$ss$.typed_blob_outbound[[transfer$transfer_id]]
  expect_null(outbound$source_path)
  expect_identical(outbound$source_payload, payload)
  expect_identical(
    .dsvert_typed_blob_retained_bytes(pair$sender$ss),
    as.numeric(nchar(payload, type = "bytes")))

  offset <- 0
  receipt <- NULL
  observed <- character()
  while (offset < transfer$payload_chars) {
    frame <- .typed_blob_with_crypto(pair$sender,
      .mpcTypedBlobReadDS_impl(
        transfer$ticket, offset, 17, pair$sender$session_id))
    observed <- c(observed, frame$chunk)
    ack <- .typed_blob_with_crypto(pair$recipient,
      .mpcTypedBlobStoreDS_impl(
        transfer$ticket, frame$chunk, offset,
        pair$recipient$session_id))
    offset <- offset + frame$chunk_chars
    if (isTRUE(ack$sealed)) receipt <- ack$receipt
  }
  expect_identical(paste0(observed, collapse = ""), payload)
  expect_match(receipt, "^[A-Za-z0-9_-]+$")
  confirmed <- .typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReceiptDS_impl(receipt, pair$sender$session_id))
  expect_true(confirmed$confirmed)
  expect_null(pair$sender$ss$.typed_blob_outbound[[transfer$transfer_id]])
  expect_identical(.dsvert_typed_blob_retained_bytes(pair$sender$ss), 0)
})

test_that("inline typed sources fail closed on tamper and expire cleanly", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  clock <- 1000
  payload <- strrep("A", 64L)
  request <- list(kind = "inline-source-expiry")
  result <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, {
      transfer <- .dsvert_typed_blob_mint_inline_source(
        pair$sender$ss, pair$sender$session_id,
        "blob.transport.source-probe.v1", pair$sender$peer_transport,
        payload, list(raw_bytes = "48", ring = "63"),
        producer = "mpcTypedSourceProbeDS")
      .dsvert_typed_blob_operation_commit(
        pair$sender$ss, "mpcTypedSourceProbeDS", request,
        list(source_transfer = transfer))
    }),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  transfer <- result$source_transfer
  pair$sender$ss$.typed_blob_outbound[[
    transfer$transfer_id]]$source_payload <- strrep("B", 64L)
  expect_error(testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender,
      .mpcTypedBlobReadDS_impl(
        transfer$ticket, 0, 16, pair$sender$session_id)),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert"),
    "integrity changed")

  pair$sender$ss$.typed_blob_outbound[[
    transfer$transfer_id]]$source_payload <- payload
  clock <- clock + .DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS + 1
  expect_true(.dsvert_typed_blob_sweep_expired(
    pair$sender$ss, now = clock, maximum = 1L))
  expect_null(pair$sender$ss$.typed_blob_outbound[[transfer$transfer_id]])
  expect_length(pair$sender$ss$.typed_blob_pending_operations, 0L)
  expect_identical(
    .dsvert_typed_blob_retained_bytes(pair$sender$ss, now = clock), 0)
})

test_that("inline typed sources reject empty payloads and enforce backpressure", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  mint <- function(payload) .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint_inline_source(
      pair$sender$ss, pair$sender$session_id,
      "blob.transport.source-probe.v1", pair$sender$peer_transport,
      payload, list(raw_bytes = "48", ring = "63"),
      producer = "mpcTypedSourceProbeDS"))
  expect_error(mint(""), "non-canonical opaque payload")

  pressure <- tryCatch(testthat::with_mocked_bindings(
    mint(strrep("A", 64L)),
    .dsvert_typed_blob_spool_max_bytes = function() 100,
    .dsvert_typed_blob_retained_bytes = function(ss) 50,
    .package = "dsVert"), error = identity)
  expect_s3_class(pressure, "dsvert_resource_backpressure")
  expect_identical(pressure$requested_bytes, 64)

  oversize <- tryCatch(testthat::with_mocked_bindings(
    mint(strrep("A", 64L)),
    .dsvert_typed_blob_spool_max_bytes = function() 32,
    .package = "dsVert"), error = identity)
  expect_s3_class(oversize, "dsvert_resource_oversize")
  expect_identical(oversize$requested_bytes, 64)
  expect_length(pair$sender$ss$.typed_blob_outbound, 0L)
})

test_that("legacy multi-transfer results stay reserved until every receipt", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload_x <- strrep("A", 60L)
  payload_y <- strrep("B", 80L)
  produced <- .typed_blob_with_crypto(pair$sender, {
    transfer_x <- .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id,
      "blob.input.peer-x.v1", pair$sender$peer_transport, payload_x,
      list(n = "1", p = "1", ring = "63"), producer = "k2ShareInputDS")
    transfer_y <- .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id,
      "blob.input.peer-y.v1", pair$sender$peer_transport, payload_y,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS")
    .dsvert_typed_blob_operation_commit(
      pair$sender$ss, "k2ShareInputDS", list(round = 1L),
      list(payload_x = payload_x, transfer_x = transfer_x,
           payload_y = payload_y, transfer_y = transfer_y))
  })
  expect_identical(.dsvert_typed_blob_retained_bytes(pair$sender$ss), 140)

  receipt_x <- .typed_blob_with_crypto(pair$recipient,
    .mpcTypedBlobStoreDS_impl(
      produced$transfer_x$ticket, payload_x, 0,
      pair$recipient$session_id)$receipt)
  .typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReceiptDS_impl(receipt_x, pair$sender$session_id))
  expect_identical(.dsvert_typed_blob_retained_bytes(pair$sender$ss), 140)

  receipt_y <- .typed_blob_with_crypto(pair$recipient,
    .mpcTypedBlobStoreDS_impl(
      produced$transfer_y$ticket, payload_y, 0,
      pair$recipient$session_id)$receipt)
  .typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReceiptDS_impl(receipt_y, pair$sender$session_id))
  expect_identical(.dsvert_typed_blob_retained_bytes(pair$sender$ss), 0)
})

test_that("typed source lease follows progress, not absolute elapsed time", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  clock <- 1000
  payload <- strrep("A", 90L)
  stage <- .dsvert_typed_blob_source_stage_path(pair$sender$ss)
  con <- file(stage, "wb")
  writeBin(charToRaw(payload), con, useBytes = TRUE)
  close(con)
  Sys.chmod(stage, mode = "0600")
  request <- list(kind = "source-lease-test")
  minted <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, {
      transfer <- .dsvert_typed_blob_mint_file(
        pair$sender$ss, pair$sender$session_id,
        "blob.transport.source-probe.v1", pair$sender$peer_transport,
        stage, list(raw_bytes = "67", ring = "63"),
        producer = "mpcTypedSourceProbeDS")
      .dsvert_typed_blob_operation_commit(
        pair$sender$ss, "mpcTypedSourceProbeDS", request,
        list(source_transfer = transfer))$source_transfer
    }),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  source_path <- pair$sender$ss$.typed_blob_outbound[[
    minted$transfer_id]]$source_path

  first <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, .mpcTypedBlobReadDS_impl(
      minted$ticket, 0, 30, pair$sender$session_id)),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  expect_identical(first$offset, 0)
  clock <- clock + .SESSION_TTL_SECONDS - 1
  second <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, .mpcTypedBlobReadDS_impl(
      minted$ticket, 30, 30, pair$sender$session_id)),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  expect_identical(second$offset, 30)
  clock <- clock + .SESSION_TTL_SECONDS - 1
  final <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, .mpcTypedBlobReadDS_impl(
      minted$ticket, 60, 30, pair$sender$session_id)),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  expect_true(final$final)
  expect_gt(clock - 1000, .SESSION_TTL_SECONDS)
  expect_identical(pair$sender$ss$.typed_blob_outbound[[
    minted$transfer_id]]$source_last_activity, clock)

  clock <- clock + .SESSION_TTL_SECONDS + 1
  expect_error(testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, .mpcTypedBlobReadDS_impl(
      minted$ticket, 60, 30, pair$sender$session_id)),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert"),
    "inactivity lease")
  expect_false(file.exists(source_path))
  expect_null(pair$sender$ss$.typed_blob_outbound[[minted$transfer_id]])
  expect_length(pair$sender$ss$.typed_blob_pending_operations, 0L)
})

test_that("source probe runtime path is server-minted and producer replay is sticky", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  calls <- 0L
  generate <- function(command, input_data) {
    calls <<- calls + 1L
    expect_identical(command, "typed-source-stream-probe")
    root <- .dsvert_typed_blob_source_root(pair$sender$ss, create = FALSE)
    expect_identical(
      normalizePath(dirname(input_data$output_path), mustWork = TRUE), root)
    expect_match(basename(input_data$output_path),
                 "^stage_[0-9a-f]{32}\\.b64$")
    expect_false(file.exists(input_data$output_path))
    payload <- strrep("A", ceiling(4 * input_data$raw_bytes / 3))
    con <- file(input_data$output_path, "wb")
    writeBin(charToRaw(payload), con, useBytes = TRUE)
    close(con)
    Sys.chmod(input_data$output_path, mode = "0600")
    list(
      version = "dsvert-typed-source-stream-v1",
      payload_chars = as.numeric(nchar(payload, type = "bytes")),
      payload_sha256 = digest::digest(
        payload, algo = "sha256", serialize = FALSE))
  }
  run <- function() .typed_blob_with_crypto(pair$sender,
    .mpcTypedSourceProbeDS_impl(
      pair$sender$peer_transport, 96, pair$sender$session_id))
  first <- testthat::with_mocked_bindings(
    run(), .callMpcTool = generate,
    .dsvert_mpc_require_capabilities = function(...) TRUE,
    .package = "dsVert")
  replay <- testthat::with_mocked_bindings(
    run(), .callMpcTool = generate,
    .dsvert_mpc_require_capabilities = function(...) TRUE,
    .package = "dsVert")
  expect_identical(replay, first)
  expect_identical(calls, 1L)
  expect_identical(sort(names(first)), "source_transfer")

  read_body <- paste(deparse(body(.mpcTypedBlobReadDS_impl)), collapse = "\n")
  expect_false(grepl("filename", read_body, fixed = TRUE))
  expect_false(grepl("source_path =", read_body, fixed = TRUE))
})

test_that("source probe applies byte backpressure before runtime or spool creation", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  runtime_calls <- 0L
  capability_checks <- 0L
  condition <- tryCatch(testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender,
      .mpcTypedSourceProbeDS_impl(
        pair$sender$peer_transport, 96, pair$sender$session_id)),
    .dsvert_typed_blob_spool_max_bytes = function() 200,
    .dsvert_typed_blob_retained_bytes = function(ss) 100,
    .dsvert_mpc_require_capabilities = function(...) {
      capability_checks <<- capability_checks + 1L
      TRUE
    },
    .callMpcTool = function(...) {
      runtime_calls <<- runtime_calls + 1L
      stop("runtime must not run")
    },
    .package = "dsVert"), error = identity)
  expect_s3_class(condition, "dsvert_resource_backpressure")
  expect_identical(condition$code, "resource_backpressure")
  expect_true(condition$retryable)
  expect_identical(capability_checks, 0L)
  expect_identical(runtime_calls, 0L)
  expect_false(dir.exists(file.path(
    .ensure_session_dir(pair$sender$ss), "typed_source")))

  oversize <- tryCatch(testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender,
      .mpcTypedSourceProbeDS_impl(
        pair$sender$peer_transport, 96, pair$sender$session_id)),
    .dsvert_typed_blob_spool_max_bytes = function() 100,
    .dsvert_typed_blob_retained_bytes = function(ss) 0,
    .package = "dsVert"), error = identity)
  expect_s3_class(oversize, "dsvert_resource_oversize")
  expect_identical(oversize$code, "resource_oversize")
  expect_false(oversize$retryable)
  expect_false(inherits(oversize, "dsvert_resource_backpressure"))
  expect_match(conditionMessage(oversize), "dsvert_resource_oversize", fixed = TRUE)
})

test_that("typed blob tickets derive a fixed destination and stream exactly", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw(
      paste(rep("purpose-bound-payload", 50L), collapse = "|")))))

  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-x.v1",
      pair$sender$peer_transport, payload,
      list(n = "50", p = "3", ring = "127")))
  .typed_blob_with_crypto(pair$recipient, {
    expect_identical(minted$capability_id, "blob.input.peer-x.v1")
    expect_match(minted$transfer_id, "^tb_[0-9a-f]{32}$")

    cut <- 317L
    first <- mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 1L, cut), 0,
      pair$recipient$session_id)
    expect_identical(first$committed_chars, as.numeric(cut))
    expect_false(first$sealed)

    duplicate <- mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 1L, cut), 0,
      pair$recipient$session_id)
    expect_identical(duplicate, first)

    final <- mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, cut + 1L, nchar(payload)), cut,
      pair$recipient$session_id)
    expect_true(final$sealed)
    expect_identical(final$committed_chars, as.numeric(nchar(payload)))
    completed_replay <- mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 1L, cut), 0,
      pair$recipient$session_id)
    expect_true(completed_replay$sealed)
    expect_identical(completed_replay$receipt, final$receipt)
    expect_identical(.dsvert_typed_blob_consume(
      pair$recipient$ss, "blob.input.peer-x.v1",
      list(n = "50", p = "3", ring = "127"),
      sender_name = "self"), payload)

    # A lost terminal response can replay only the exact final frame.  The
    # consumed payload is not recreated, so downstream work remains one-shot.
    replay <- mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, cut + 1L, nchar(payload)), cut,
      pair$recipient$session_id)
    expect_true(replay$sealed)
    expect_null(.blob_consume("k2_peer_x_share", pair$recipient$ss))
  })
})

test_that("consumed many-frame receipts retain only terminal replay metadata", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw(
      paste(rep("bounded-terminal-replay", 30L), collapse = "|")))))
  context <- list(n = "30", p = "2", ring = "127")
  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-x.v1",
      pair$sender$peer_transport, payload, context))

  .typed_blob_with_crypto(pair$recipient, {
    frame_chars <- 37L
    offsets <- seq.int(0L, nchar(payload) - 1L, by = frame_chars)
    final <- NULL
    for (offset in offsets) {
      chunk <- substr(
        payload, offset + 1L, min(offset + frame_chars, nchar(payload)))
      final <- mpcTypedBlobStoreDS(
        minted$ticket, chunk, offset, pair$recipient$session_id)
    }
    expect_true(final$sealed)
    receipt <- pair$recipient$ss$.typed_blob_receipts[[minted$transfer_id]]
    expect_gt(length(receipt$frame_offsets), 1L)

    expect_identical(.dsvert_typed_blob_consume(
      pair$recipient$ss, "blob.input.peer-x.v1", context,
      sender_name = "self"), payload)
    compact <- pair$recipient$ss$.typed_blob_receipts[[minted$transfer_id]]
    expect_identical(compact$frame_offsets, compact$final_offset)
    expect_identical(compact$frame_chars, compact$final_chars)

    first_chunk <- substr(payload, 1L, frame_chars)
    expect_error(mpcTypedBlobStoreDS(
      minted$ticket, first_chunk, 0, pair$recipient$session_id),
      "Conflicting replay")
    terminal_offset <- tail(offsets, 1L)
    terminal_chunk <- substr(payload, terminal_offset + 1L, nchar(payload))
    replay <- mpcTypedBlobStoreDS(
      minted$ticket, terminal_chunk, terminal_offset,
      pair$recipient$session_id)
    expect_true(replay$sealed)
    expect_identical(replay$receipt, final$receipt)
  })
})

test_that("active model families mint and receive on canonical UUID sessions", {
  families <- list(
    multinomial = list(
      capability = "blob.input.peer-x.v1",
      producer = "k2ShareInputDS",
      context = list(n = "4", p = "2", ring = "127")),
    ordinal = list(
      capability = "blob.gradient.peer-r1.v1",
      producer = "k2GradientR1DS",
      context = list(n = "4", p = "2", ring = "127")),
    cox = list(
      capability = "blob.beaver.vecmul-masked.v1",
      producer = "k2BeaverVecmulR1DS",
      context = list(n = "4", ring = "127")),
    negative_binomial = list(
      capability = "blob.glm.weight-share.v1",
      producer = "k2ShareWeightsDS",
      context = list(n = "4", ring = "127", numeric_family = "poisson")))

  for (family in names(families)) {
    spec <- families[[family]]
    pair <- .typed_blob_test_pair()
    on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
    on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
    expect_match(
      pair$sender$session_id,
      "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
      info = family)
    payload <- base64_to_base64url(gsub(
      "[\r\n]", "", jsonlite::base64_enc(charToRaw(
        paste0(family, "-purpose-bound-payload")))))
    minted <- .typed_blob_with_crypto(pair$sender,
      .dsvert_typed_blob_mint(
        pair$sender$ss, pair$sender$session_id, spec$capability,
        pair$sender$peer_transport, payload, spec$context,
        producer = spec$producer))
    received <- .typed_blob_with_crypto(pair$recipient, {
      ack <- mpcTypedBlobStoreDS(
        minted$ticket, payload, 0, pair$recipient$session_id)
      expect_true(ack$sealed, info = family)
      .dsvert_typed_blob_consume(
        pair$recipient$ss, spec$capability, spec$context,
        sender_name = "self")
    })
    expect_identical(received, payload, info = family)
  }
})

test_that("an admitted ticket is signature-verified once across all frames", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw(
      paste(rep("signature-cache", 20L), collapse = "|")))))
  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, payload,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS"))
  verify_calls <- 0L
  verify <- function(message, identity_pk, signature) {
    verify_calls <<- verify_calls + 1L
    .typed_blob_test_verify(message, identity_pk, signature)
  }
  .typed_blob_with_crypto(pair$recipient, {
    cuts <- c(0L, 7L, 19L, nchar(payload))
    final <- NULL
    for (index in seq_len(length(cuts) - 1L)) {
      final <- mpcTypedBlobStoreDS(
        minted$ticket,
        substr(payload, cuts[[index]] + 1L, cuts[[index + 1L]]),
        cuts[[index]], pair$recipient$session_id)
    }
    expect_true(final$sealed)
    replay <- mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 20L, nchar(payload)), 19L,
      pair$recipient$session_id)
    expect_true(replay$sealed)
  }, verify = verify)
  expect_identical(verify_calls, 1L)
})

test_that("lost producer responses replay one byte-identical pending result", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw(
      "producer response may disappear after commit"))))
  request <- list(peer_pk = pair$sender$peer_transport, logical_round = 1L)

  produced <- .typed_blob_with_crypto(pair$sender, {
    replay <- .dsvert_typed_blob_operation_replay(
      pair$sender$ss, "k2GradientR1DS", request)
    expect_false(replay$hit)
    transfer <- .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id,
      "blob.gradient.peer-r1.v1", pair$sender$peer_transport, payload,
      list(n = "1", p = "1", ring = "127"),
      producer = "k2GradientR1DS")
    .dsvert_typed_blob_operation_commit(
      pair$sender$ss, "k2GradientR1DS", request,
      list(encrypted_r1 = payload, encrypted_r1_transfer = transfer))
  })

  # Simulate an ambiguous/lost DSI response: the exact aggregate function is
  # executed again before the analyst has relayed a single byte.
  retry <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_operation_replay(
      pair$sender$ss, "k2GradientR1DS", request))
  expect_true(retry$hit)
  expect_identical(retry$result, produced)
  expect_identical(
    retry$result$encrypted_r1_transfer$ticket,
    produced$encrypted_r1_transfer$ticket)
  expect_identical(
    pair$sender$ss$.typed_blob_send_sequence[[
      .dsvert_typed_blob_stream_key(
        "blob.gradient.peer-r1.v1", "peer")]], 1)

  receipt <- .typed_blob_with_crypto(pair$recipient, {
    ack <- mpcTypedBlobStoreDS(
      produced$encrypted_r1_transfer$ticket, payload, 0,
      pair$recipient$session_id)
    expect_true(ack$sealed)
    expect_match(ack$receipt, "^[A-Za-z0-9_-]+$")
    ack$receipt
  })
  wrong_peer_receipt <- .typed_blob_mutate_envelope(
    receipt, function(body) {
      body$recipient_name <- "attacker"
      body
    }, receipt = TRUE)
  wrong_hash_receipt <- .typed_blob_mutate_envelope(
    receipt, function(body) {
      body$payload_sha256 <- strrep("0", 64L)
      body
    }, receipt = TRUE)
  expect_error(.typed_blob_with_crypto(pair$sender,
    mpcTypedBlobReceiptDS(
      wrong_peer_receipt, pair$sender$session_id)), "pinned-peer")
  expect_error(.typed_blob_with_crypto(pair$sender,
    mpcTypedBlobReceiptDS(
      wrong_hash_receipt, pair$sender$session_id)), "conflicts")
  confirmation <- .typed_blob_with_crypto(pair$sender,
    mpcTypedBlobReceiptDS(receipt, pair$sender$session_id))
  expect_true(confirmation$confirmed)

  # A lost confirmation response is itself idempotent, while the completed
  # producer invocation no longer blocks the next logical phase.
  expect_identical(.typed_blob_with_crypto(pair$sender,
    mpcTypedBlobReceiptDS(receipt, pair$sender$session_id)), confirmation)
  expect_false(.typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_operation_replay(
      pair$sender$ss, "k2GradientR1DS", request))$hit)
})

test_that("an admitted transfer survives ticket expiry but a new one does not", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  clock <- 1000000
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw(
      paste(rep("slow-dsi", 40L), collapse = "|")))))
  mint_at_clock <- function() .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, payload,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS"))
  minted <- testthat::with_mocked_bindings(
    mint_at_clock(), .dsvert_typed_blob_now = function() clock)

  cut <- 19L
  clock <- clock + .DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS - 10
  testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$recipient,
      mpcTypedBlobStoreDS(
        minted$ticket, substr(payload, 1L, cut), 0,
        pair$recipient$session_id)),
    .dsvert_typed_blob_now = function() clock)
  clock <- clock + 20
  resumed <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$recipient,
      mpcTypedBlobStoreDS(
        minted$ticket, substr(payload, cut + 1L, nchar(payload)), cut,
        pair$recipient$session_id)),
    .dsvert_typed_blob_now = function() clock)
  expect_true(resumed$sealed)

  fresh_pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(fresh_pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(fresh_pair$recipient$ss), add = TRUE)
  clock <- 2000000
  fresh <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(fresh_pair$sender,
      .dsvert_typed_blob_mint(
        fresh_pair$sender$ss, fresh_pair$sender$session_id,
        "blob.input.peer-y.v1", fresh_pair$sender$peer_transport, payload,
        list(n = "1", ring = "63"), producer = "k2ShareInputDS")),
    .dsvert_typed_blob_now = function() clock)
  clock <- clock + .DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS + 1
  expect_error(testthat::with_mocked_bindings(
    .typed_blob_with_crypto(fresh_pair$recipient,
      mpcTypedBlobStoreDS(
        fresh$ticket, payload, 0, fresh_pair$recipient$session_id)),
    .dsvert_typed_blob_now = function() clock), "expired")
})

test_that("typed recipient lease follows byte progress beyond one TTL", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  clock <- 3000000
  payload <- strrep("A", 90L)
  minted <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, payload,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS")),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")

  .typed_blob_with_crypto(pair$recipient, {
    testthat::with_mocked_bindings({
      expect_false(.mpcTypedBlobStoreDS_impl(
        minted$ticket, substr(payload, 1L, 30L), 0,
        pair$recipient$session_id)$sealed)
      clock <- clock + .SESSION_TTL_SECONDS - 1
      expect_false(.mpcTypedBlobStoreDS_impl(
        minted$ticket, substr(payload, 31L, 60L), 30,
        pair$recipient$session_id)$sealed)
      clock <- clock + .SESSION_TTL_SECONDS - 1
      final <- .mpcTypedBlobStoreDS_impl(
        minted$ticket, substr(payload, 61L, 90L), 60,
        pair$recipient$session_id)
      expect_true(final$sealed)
      expect_gt(clock - 3000000, .SESSION_TTL_SECONDS)
    }, .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  })
})

test_that("typed spool reserves final bytes and applies aggregate backpressure", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  first_payload <- strrep("A", 60L)
  second_payload <- strrep("B", 60L)
  first <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, first_payload,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS"))
  second <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-x.v1",
      pair$sender$peer_transport, second_payload,
      list(n = "1", p = "1", ring = "63"),
      producer = "k2ShareInputDS"))

  .typed_blob_with_crypto(pair$recipient, {
    testthat::with_mocked_bindings({
      partial <- mpcTypedBlobStoreDS(
        first$ticket, substr(first_payload, 1L, 10L), 0,
        pair$recipient$session_id)
      expect_false(partial$sealed)
      expect_identical(
        .dsvert_typed_blob_retained_bytes(pair$recipient$ss), 60)
      pressure <- tryCatch(.mpcTypedBlobStoreDS_impl(
        second$ticket, substr(second_payload, 1L, 10L), 0,
        pair$recipient$session_id), error = identity)
      expect_s3_class(pressure, "dsvert_resource_backpressure")
      expect_identical(pressure$code, "resource_backpressure")
      expect_true(pressure$retryable)

      final <- mpcTypedBlobStoreDS(
        first$ticket, substr(first_payload, 11L, 60L), 10,
        pair$recipient$session_id)
      expect_true(final$sealed)
      expect_identical(
        .dsvert_typed_blob_retained_bytes(pair$recipient$ss), 60)
      expect_identical(.dsvert_typed_blob_consume(
        pair$recipient$ss, "blob.input.peer-y.v1",
        list(n = "1", ring = "63"), sender_name = "self"), first_payload)
      expect_identical(
        .dsvert_typed_blob_retained_bytes(pair$recipient$ss), 0)
      expect_false(mpcTypedBlobStoreDS(
        second$ticket, substr(second_payload, 1L, 10L), 0,
        pair$recipient$session_id)$sealed)
    }, .dsvert_typed_blob_spool_max_bytes = function() 100,
       .package = "dsVert")
  })
})

test_that("duplicate typed frames cannot prolong the inactivity lease", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  clock <- 1000
  payload <- strrep("A", 80L)
  minted <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender,
      .dsvert_typed_blob_mint(
        pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
        pair$sender$peer_transport, payload,
        list(n = "1", ring = "63"), producer = "k2ShareInputDS")),
    .dsvert_typed_blob_now = function() clock)

  .typed_blob_with_crypto(pair$recipient, {
    testthat::with_mocked_bindings({
      first <- mpcTypedBlobStoreDS(
        minted$ticket, substr(payload, 1L, 20L), 0,
        pair$recipient$session_id)
      expect_false(first$sealed)
      state <- pair$recipient$ss$.typed_blob_transfers[[minted$transfer_id]]
      expect_identical(state$last_activity, clock)
      expect_identical(pair$recipient$ss$.last_activity, clock)
      spool <- state$path

      clock <- clock + 100
      expect_identical(mpcTypedBlobStoreDS(
        minted$ticket, substr(payload, 1L, 20L), 0,
        pair$recipient$session_id), first)
      state <- pair$recipient$ss$.typed_blob_transfers[[minted$transfer_id]]
      expect_identical(state$last_activity, 1000)
      expect_identical(pair$recipient$ss$.last_activity, 1000)

      clock <- 1000 + .SESSION_TTL_SECONDS + 1
      expect_error(.mpcTypedBlobStoreDS_impl(
        minted$ticket, substr(payload, 21L, 40L), 20,
        pair$recipient$session_id), "inactivity lease")
      expect_null(pair$recipient$ss$.typed_blob_transfers[[
        minted$transfer_id]])
      expect_false(file.exists(spool))
    }, .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  })
})

test_that("typed blob tickets reject arbitrary purpose, routing and replay", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw("opaque payload"))))

  minted <- .typed_blob_with_crypto(pair$sender, {
    expect_error(.dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.arbitrary-key.v1",
      pair$sender$peer_transport, payload, list()), "not present")
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, payload, list(n = "1", ring = "63"))
  })

  .typed_blob_with_crypto(pair$recipient, {
    expect_error(mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 1L, 5L), 1,
      pair$recipient$session_id), "offset zero")
    expect_error(mpcTypedBlobStoreDS(
      minted$ticket, paste0(payload, "A"), 0, pair$recipient$session_id),
      "signed payload length")

    raw_ticket <- .dsvert_relay_b64url_decode(
      minted$ticket, "test typed-blob ticket")
    envelope <- jsonlite::fromJSON(rawToChar(raw_ticket), simplifyVector = FALSE)
    body <- jsonlite::fromJSON(rawToChar(.dsvert_relay_b64url_decode(
      envelope$body, "test typed-blob body")), simplifyVector = FALSE)
    body$recipient_name <- "attacker"
    envelope$body <- .dsvert_typed_blob_body_token(body)
    forged <- .dsvert_relay_b64url_encode(charToRaw(as.character(
      jsonlite::toJSON(envelope, auto_unbox = TRUE))))
    expect_error(mpcTypedBlobStoreDS(
      forged, payload, 0, pair$recipient$session_id), "pinned-peer session")

    first <- substr(payload, 1L, 5L)
    mpcTypedBlobStoreDS(
      minted$ticket, first, 0, pair$recipient$session_id)
    expect_error(mpcTypedBlobStoreDS(
      minted$ticket, paste0(substr(first, 1L, 4L), "A"), 0,
      pair$recipient$session_id), "Conflicting typed-blob frame replay")
    expect_error(mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 7L, nchar(payload)), 6,
      pair$recipient$session_id), "offset does not match")
  })
})

test_that("typed consumers reject partial, legacy and wrong-context payloads", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw("context-bound"))))
  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-x.v1",
      pair$sender$peer_transport, payload,
      list(n = "1", p = "2", ring = "127"),
      producer = "k2ShareInputDS"))

  .typed_blob_with_crypto(pair$recipient, {
    mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 1L, 3L), 0,
      pair$recipient$session_id)
    expect_error(.dsvert_typed_blob_consume(
      pair$recipient$ss, "blob.input.peer-x.v1",
      list(n = "1", p = "2", ring = "127"), sender_name = "self"),
      "not committed")
    mpcTypedBlobStoreDS(
      minted$ticket, substr(payload, 4L, nchar(payload)), 3,
      pair$recipient$session_id)
    expect_error(.dsvert_typed_blob_consume(
      pair$recipient$ss, "blob.input.peer-x.v1",
      list(n = "1", p = "3", ring = "127"), sender_name = "self"),
      "provenance/shape")
    expect_identical(.dsvert_typed_blob_consume(
      pair$recipient$ss, "blob.input.peer-x.v1",
      list(n = "1", p = "2", ring = "127"), sender_name = "self"),
      payload)

    .blob_put("k2_peer_y_share", payload, pair$recipient$ss)
    expect_error(.dsvert_typed_blob_consume(
      pair$recipient$ss, "blob.input.peer-y.v1",
      list(n = "1", ring = "127"), sender_name = "self"),
      "legacy or unprovenanced")
  })
})

test_that("signed ticket type, phase, shape, session and hash are immutable", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw("immutable metadata"))))
  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, payload,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS"))
  mutate <- function(field, value) .typed_blob_mutate_envelope(
    minted$ticket, function(body) {
      body[[field]] <- value
      body
    })

  .typed_blob_with_crypto(pair$recipient, {
    expect_error(mpcTypedBlobStoreDS(
      mutate("session_id", "other-session"), payload, 0,
      pair$recipient$session_id), "ticket body")
    expect_error(mpcTypedBlobStoreDS(
      mutate("sender_name", "untrusted"), payload, 0,
      pair$recipient$session_id), "pinned-peer")
    expect_error(mpcTypedBlobStoreDS(
      mutate("phase", "input.wrong-phase"), payload, 0,
      pair$recipient$session_id), "metadata conflicts")
    expect_error(mpcTypedBlobStoreDS(
      mutate("shape", "wrong-shape"), payload, 0,
      pair$recipient$session_id), "metadata conflicts")
    expect_error(mpcTypedBlobStoreDS(
      mutate("capability_id", "blob.input.peer-x.v1"), payload, 0,
      pair$recipient$session_id), "producer context")
    expect_error(mpcTypedBlobStoreDS(
      mutate("sequence", "2"), payload, 0,
      pair$recipient$session_id), "reordered or skips")
    expect_error(mpcTypedBlobStoreDS(
      mutate("payload_sha256", strrep("0", 64L)), payload, 0,
      pair$recipient$session_id), "payload hash")
  })
})

test_that("extra feature destinations are derived from the signed producer", {
  resolved <- .dsvert_typed_blob_destination(
    "blob.input.extra-x.v1", "site.two",
    list(n = "20", p = "4", ring = "127"))
  expect_identical(resolved$slot, "k2_extra_x_share_site.two")
  expect_error(.dsvert_typed_blob_destination(
    "blob.input.extra-x.v1", "../../escape",
    list(n = "20", p = "4", ring = "127")), "logical peer")
})

test_that("typed peer binding is deterministic and name-bound", {
  identities_a <- list(
    beta = list(identity_pk = .typed_blob_test_b64(2L, 32L)),
    alpha = list(identity_pk = .typed_blob_test_b64(1L, 32L)))
  identities_b <- identities_a[c("alpha", "beta")]
  transports_a <- list(
    beta = .typed_blob_test_b64(4L, 32L),
    alpha = .typed_blob_test_b64(3L, 32L))
  transports_b <- transports_a[c("alpha", "beta")]
  expect_identical(
    .dsvert_typed_blob_peer_binding(identities_a, transports_a),
    .dsvert_typed_blob_peer_binding(identities_b, transports_b))
  swapped <- identities_b
  swapped$alpha$identity_pk <- identities_b$beta$identity_pk
  swapped$beta$identity_pk <- identities_b$alpha$identity_pk
  expect_false(identical(
    .dsvert_typed_blob_peer_binding(identities_a, transports_a),
    .dsvert_typed_blob_peer_binding(swapped, transports_a)))
  rotated <- transports_a
  rotated$alpha <- .typed_blob_test_b64(9L, 32L)
  expect_false(identical(
    .dsvert_typed_blob_peer_binding(identities_a, transports_a),
    .dsvert_typed_blob_peer_binding(identities_a, rotated)))
})

test_that("typed source verification performs one validation and one hash pass", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  validations <- 0L
  hashes <- 0L
  original_validate <- .dsvert_typed_blob_source_validate_stream
  original_hash <- .dsvert_typed_blob_source_hash_file
  generate <- function(command, input_data) {
    payload <- strrep("A", ceiling(4 * input_data$raw_bytes / 3))
    con <- file(input_data$output_path, "wb")
    writeBin(charToRaw(payload), con, useBytes = TRUE)
    close(con)
    Sys.chmod(input_data$output_path, mode = "0600")
    list(
      version = "dsvert-typed-source-stream-v1",
      payload_chars = as.numeric(nchar(payload, type = "bytes")),
      payload_sha256 = digest::digest(
        payload, algo = "sha256", serialize = FALSE))
  }

  testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender,
      .mpcTypedSourceProbeDS_impl(
        pair$sender$peer_transport, 96, pair$sender$session_id)),
    .callMpcTool = generate,
    .dsvert_mpc_require_capabilities = function(...) TRUE,
    .dsvert_typed_blob_source_validate_stream = function(path) {
      validations <<- validations + 1L
      original_validate(path)
    },
    .dsvert_typed_blob_source_hash_file = function(path) {
      hashes <<- hashes + 1L
      original_hash(path)
    },
    .package = "dsVert")
  expect_identical(validations, 1L)
  expect_identical(hashes, 1L)
})

test_that("authenticated source descriptors reject TOCTOU and rename replacement", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  stage <- .dsvert_typed_blob_source_stage_path(pair$sender$ss)
  write_stage <- function(path, value) {
    con <- file(path, "wb")
    writeBin(charToRaw(strrep(value, 64L)), con, useBytes = TRUE)
    close(con)
    Sys.chmod(path, mode = "0600")
  }
  write_stage(stage, "A")
  hash_file <- .dsvert_typed_blob_source_hash_file
  expect_error(testthat::with_mocked_bindings(
    .dsvert_typed_blob_source_file_metadata(pair$sender$ss, stage),
    .dsvert_typed_blob_source_hash_file = function(path) {
      hash <- hash_file(path)
      write_stage(path, "B")
      hash
    },
    .package = "dsVert"), "changed while")
  descriptor <- .dsvert_typed_blob_source_file_metadata(
    pair$sender$ss, stage)
  write_stage(stage, "C")
  expect_error(.typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint_file(
      pair$sender$ss, pair$sender$session_id,
      "blob.transport.source-probe.v1", pair$sender$peer_transport,
      stage, list(raw_bytes = "48", ring = "63"),
      producer = "mpcTypedSourceProbeDS",
      source_descriptor = descriptor)), "no longer matches")

  descriptor <- .dsvert_typed_blob_source_file_metadata(
    pair$sender$ss, stage)
  tampered <- descriptor
  tampered$payload_sha256 <- strrep("0", 64L)
  expect_error(.typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint_file(
      pair$sender$ss, pair$sender$session_id,
      "blob.transport.source-probe.v1", pair$sender$peer_transport,
      stage, list(raw_bytes = "48", ring = "63"),
      producer = "mpcTypedSourceProbeDS",
      source_descriptor = tampered)), "no longer matches")

  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint_file(
      pair$sender$ss, pair$sender$session_id,
      "blob.transport.source-probe.v1", pair$sender$peer_transport,
      stage, list(raw_bytes = "48", ring = "63"),
      producer = "mpcTypedSourceProbeDS",
      source_descriptor = descriptor))
  outbound <- pair$sender$ss$.typed_blob_outbound[[minted$transfer_id]]
  expect_false(identical(outbound$source_path, descriptor$source_path))
  expect_identical(outbound$source_identity$inode,
                   descriptor$identity$inode)

  replacement <- .dsvert_typed_blob_source_stage_path(pair$sender$ss)
  write_stage(replacement, "C")
  unlink(outbound$source_path)
  expect_true(file.rename(replacement, outbound$source_path))
  expect_error(.typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReadDS_impl(
      minted$ticket, 0, 16, pair$sender$session_id)), "integrity changed")
})

test_that("failed atomic source commit removes the renamed spool", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  stage <- .dsvert_typed_blob_source_stage_path(pair$sender$ss)
  con <- file(stage, "wb")
  writeBin(charToRaw(strrep("A", 64L)), con, useBytes = TRUE)
  close(con)
  Sys.chmod(stage, mode = "0600")
  descriptor <- .dsvert_typed_blob_source_file_metadata(
    pair$sender$ss, stage)
  source_identity <- .dsvert_typed_blob_source_identity
  identity_reads <- 0L

  expect_error(testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender,
      .dsvert_typed_blob_mint_file(
        pair$sender$ss, pair$sender$session_id,
        "blob.transport.source-probe.v1", pair$sender$peer_transport,
        stage, list(raw_bytes = "48", ring = "63"),
        producer = "mpcTypedSourceProbeDS",
        source_descriptor = descriptor)),
    .dsvert_typed_blob_source_identity = function(path) {
      identity_reads <<- identity_reads + 1L
      identity <- source_identity(path)
      if (identity_reads > 1L) identity$inode <- identity$inode + 1
      identity
    },
    .package = "dsVert"), "identity changed during atomic commit")
  expect_identical(identity_reads, 2L)
  expect_false(file.exists(stage))
  expect_length(list.files(
    .dsvert_typed_blob_source_root(pair$sender$ss, create = FALSE),
    all.files = TRUE, no.. = TRUE), 0L)
  expect_length(pair$sender$ss$.typed_blob_outbound, 0L)
})

test_that("retained-byte accounting uses an authenticated O(1) fast head", {
  fixture <- .typed_blob_test_fixture()
  on.exit(.session_dir_cleanup(fixture$ss), add = TRUE)
  blob_path <- file.path(.ensure_session_dir(fixture$ss), "blobs", "legacy")
  writeBin(charToRaw(strrep("A", 37L)), blob_path)
  Sys.chmod(blob_path, mode = "0600")
  scans <- 0L
  inventory <- .dsvert_typed_blob_file_inventory

  testthat::with_mocked_bindings({
    expect_identical(.dsvert_typed_blob_retained_bytes(fixture$ss), 37)
    expect_identical(scans, 3L)
    expect_identical(.dsvert_typed_blob_retained_bytes(fixture$ss), 37)
    expect_identical(scans, 3L)

    fixture$ss$.typed_blob_retained_head$total <- 1
    expect_identical(.dsvert_typed_blob_retained_bytes(fixture$ss), 37)
    expect_identical(scans, 6L)
  }, .dsvert_typed_blob_file_inventory = function(...) {
    scans <<- scans + 1L
    inventory(...)
  }, .package = "dsVert")
})

test_that("interleaved admissions do not rescan existing spool files", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  first_payload <- strrep("A", 40L)
  second_payload <- strrep("B", 40L)
  first <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, first_payload,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS"))
  second <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-x.v1",
      pair$sender$peer_transport, second_payload,
      list(n = "1", p = "1", ring = "63"),
      producer = "k2ShareInputDS"))
  .ensure_session_dir(pair$recipient$ss)
  scans <- 0L
  inventory <- .dsvert_typed_blob_file_inventory

  testthat::with_mocked_bindings({
      expect_identical(
        .dsvert_typed_blob_retained_bytes(pair$recipient$ss), 0)
      expect_identical(scans, 3L)
      expect_false(.mpcTypedBlobStoreDS_impl(
        first$ticket, substr(first_payload, 1L, 10L), 0,
        pair$recipient$session_id)$sealed)
      expect_identical(scans, 3L)
      expect_false(.mpcTypedBlobStoreDS_impl(
        second$ticket, substr(second_payload, 1L, 10L), 0,
        pair$recipient$session_id)$sealed)
      expect_identical(scans, 3L)
      expect_identical(
        .dsvert_typed_blob_retained_bytes(pair$recipient$ss), 80)
      expect_identical(scans, 3L)
    },
    .S = function(session_id) pair$recipient$ss,
    .get_identity_keypair = function() list(
      identity_pk = pair$recipient$own_identity,
      identity_sk = "test-secret"),
    .sign_transport_pk = .typed_blob_test_sign,
    .verify_peer_identity = .typed_blob_test_verify,
    .dsvert_typed_blob_file_inventory = function(...) {
      scans <<- scans + 1L
      inventory(...)
    },
    .package = "dsVert")
})

test_that("bounded fair sweep releases expired partial and crashed spools", {
  fixture <- .typed_blob_test_fixture()
  on.exit(.session_dir_cleanup(fixture$ss), add = TRUE)
  typed_root <- file.path(.ensure_session_dir(fixture$ss), "typed")
  dir.create(typed_root, mode = "0700")
  ids <- paste0("tb_", sprintf("%032x", 1:3))
  fixture$ss$.typed_blob_transfers <- setNames(lapply(ids, function(id) {
    path <- file.path(typed_root, id)
    writeBin(charToRaw("A"), path)
    Sys.chmod(path, mode = "0600")
    list(path = path, payload_chars = 10, last_activity = 0,
         ticket_digest = digest::digest(id, algo = "sha256",
                                        serialize = FALSE))
  }), ids)

  now <- .SESSION_TTL_SECONDS + 1
  expect_true(.dsvert_typed_blob_sweep_expired(
    fixture$ss, now = now, maximum = 1L))
  expect_length(fixture$ss$.typed_blob_transfers, 2L)
  expect_true(.dsvert_typed_blob_sweep_expired(
    fixture$ss, now = now, maximum = 1L))
  expect_length(fixture$ss$.typed_blob_transfers, 1L)
  expect_true(.dsvert_typed_blob_sweep_expired(
    fixture$ss, now = now, maximum = 1L))
  expect_length(fixture$ss$.typed_blob_transfers, 0L)

  orphan <- file.path(typed_root, paste0("tb_", strrep("f", 32L)))
  writeBin(charToRaw(strrep("B", 23L)), orphan)
  Sys.chmod(orphan, mode = "0600")
  Sys.setFileTime(orphan, as.POSIXct(0, origin = "1970-01-01"))
  expect_identical(
    .dsvert_typed_blob_retained_bytes(fixture$ss, now = now), 0)
  expect_false(file.exists(orphan))
})

test_that("capacity sweep reclaims an unstarted expired source transfer", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  clock <- 1000
  stage <- .dsvert_typed_blob_source_stage_path(pair$sender$ss)
  con <- file(stage, "wb")
  writeBin(charToRaw(strrep("A", 64L)), con, useBytes = TRUE)
  close(con)
  Sys.chmod(stage, mode = "0600")
  request <- list(kind = "expiry-sweep")
  minted <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, {
      transfer <- .dsvert_typed_blob_mint_file(
        pair$sender$ss, pair$sender$session_id,
        "blob.transport.source-probe.v1", pair$sender$peer_transport,
        stage, list(raw_bytes = "48", ring = "63"),
        producer = "mpcTypedSourceProbeDS")
      .dsvert_typed_blob_operation_commit(
        pair$sender$ss, "mpcTypedSourceProbeDS", request,
        list(source_transfer = transfer))$source_transfer
    }),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  source_path <- pair$sender$ss$.typed_blob_outbound[[
    minted$transfer_id]]$source_path
  expect_identical(
    .dsvert_typed_blob_retained_bytes(pair$sender$ss, now = clock), 64)

  clock <- clock + .DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS + 1
  expect_true(.dsvert_typed_blob_sweep_expired(
    pair$sender$ss, now = clock, maximum = 1L))
  expect_false(file.exists(source_path))
  expect_null(pair$sender$ss$.typed_blob_outbound[[minted$transfer_id]])
  expect_length(pair$sender$ss$.typed_blob_pending_operations, 0L)
  expect_identical(
    .dsvert_typed_blob_retained_bytes(pair$sender$ss, now = clock), 0)
})

test_that("failed first-frame admission rolls back file and accounting", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  payload <- strrep("A", 64L)
  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id, "blob.input.peer-y.v1",
      pair$sender$peer_transport, payload,
      list(n = "1", ring = "63"), producer = "k2ShareInputDS"))

  expect_error(testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$recipient,
      .mpcTypedBlobStoreDS_impl(
        minted$ticket, substr(payload, 1L, 16L), 0,
        pair$recipient$session_id)),
    .dsvert_relay_append = function(...) stop("simulated write crash"),
    .package = "dsVert"), "simulated write crash")
  expect_length(pair$recipient$ss$.typed_blob_transfers, 0L)
  expect_identical(.dsvert_typed_blob_retained_bytes(pair$recipient$ss), 0)
  typed_root <- file.path(pair$recipient$ss$.session_dir, "typed")
  expect_length(list.files(typed_root, all.files = TRUE, no.. = TRUE), 0L)
})

.typed_blob_count_analysis_context <- function() {
  list(
    artifact_key = strrep("1", 64L),
    contract_hash = strrep("2", 64L),
    circuit = paste0("joint-dp-laplace-v2/", strrep("3", 64L)),
    roles = list(source = "self", finalizer = "peer"),
    sender = "self",
    recipient = "peer")
}

.typed_blob_frequency_context <- function() {
  list(
    version = "dsvert-dp-frequency-typed-context-v1",
    purpose = "analysis-dp.frequency-source-to-finalizer.v1",
    artifact_key = strrep("1", 64L),
    contract_sha256 = strrep("2", 64L),
    analysis_binding_sha256 = strrep("3", 64L),
    worker_static_sha256 = strrep("4", 64L),
    authorization_set_sha256 = strrep("5", 64L),
    release_contract_hash = strrep("6", 64L),
    operation_id = paste0("op_", strrep("7", 32L)),
    window_index = "0", window_count = "1",
    first_chunk_index = "0", chunks_in_window = "1",
    coordinate_offset = "0", coordinate_count = "3",
    padded_coordinate_count = "65536",
    ring_bits = "128", frac_bits = "0",
    roles = list(
      source_owner = "self", secondary_noise_authority = "peer"),
    sender = "self", recipient = "peer")
}

test_that("analysis Count capabilities reject context and route tampering", {
  context <- .typed_blob_count_analysis_context()
  capabilities <- "blob.analysis-dp.count-final-share.v1"

  resolved <- lapply(capabilities, function(capability) {
    .dsvert_typed_blob_destination(capability, "self", context)
  })
  expect_identical(vapply(resolved, `[[`, character(1L), "ring"),
                   "127")
  expect_identical(vapply(resolved, `[[`, character(1L), "count"),
                   "1")
  expect_identical(vapply(resolved, `[[`, character(1L), "producer"),
                   "dsvertDPCountFinalShareDS")
  expect_identical(vapply(resolved, `[[`, character(1L), "consumer"),
                   "dsvertDPCountReleaseDS")
  expect_error(.dsvert_typed_blob_destination(
    "blob.analysis-dp.count-source.v1", "self", context),
    "not present in the server registry")

  mutate <- function(field, value) {
    changed <- context
    changed[[field]] <- value
    changed
  }
  for (capability in capabilities) {
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", context[c(
        "artifact_key", "contract_hash", "circuit", "roles", "sender")]),
      "producer context")
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", c(context, list(query_id = strrep("4", 64L)))),
      "producer context")
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", mutate("artifact_key", strrep("A", 64L))),
      "analysis Count context")
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", mutate("contract_hash", strrep("2", 63L))),
      "analysis Count context")
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", mutate(
        "circuit", paste0("joint-dp-vector-laplace-v3/", strrep("3", 64L)))),
      "analysis Count circuit")
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", mutate(
        "roles", list(source = "peer", finalizer = "self"))),
      "analysis Count route")
    expect_error(.dsvert_typed_blob_destination(
      capability, "peer", context), "analysis Count route")
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", mutate("recipient", "self")),
      "analysis Count route")
    expect_error(.dsvert_typed_blob_destination(
      capability, "self", c(context, list(ring = "127"))),
      "producer context")
  }
})

test_that("analysis Count transfers are typed, replay-safe and ephemeral", {
  specs <- list(list(
    capability = "blob.analysis-dp.count-final-share.v1",
    producer = "dsvertDPCountFinalShareDS"))

  for (spec in specs) {
    pair <- .typed_blob_test_pair()
    on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
    on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
    context <- .typed_blob_count_analysis_context()
    payload <- base64_to_base64url(gsub(
      "[\r\n]", "", jsonlite::base64_enc(charToRaw(spec$capability))))
    request <- list(
      artifact_key = context$artifact_key,
      contract_hash = context$contract_hash,
      capability = spec$capability)

    produced <- .typed_blob_with_crypto(pair$sender, {
      transfer <- .dsvert_typed_blob_mint(
        pair$sender$ss, pair$sender$session_id, spec$capability,
        pair$sender$peer_transport, payload, context,
        producer = spec$producer)
      .dsvert_typed_blob_operation_commit(
        pair$sender$ss, spec$producer, request,
        list(ciphertext = payload, transfer = transfer))
    })
    replay <- .typed_blob_with_crypto(pair$sender,
      .dsvert_typed_blob_operation_replay(
        pair$sender$ss, spec$producer, request))
    expect_true(replay$hit)
    expect_identical(replay$result, produced)

    wrong_recipient <- context
    wrong_recipient$recipient <- "another-peer"
    expect_error(.typed_blob_with_crypto(pair$sender,
      .dsvert_typed_blob_mint(
        pair$sender$ss, pair$sender$session_id, spec$capability,
        pair$sender$peer_transport, payload, wrong_recipient,
        producer = spec$producer)), "analysis Count route")
    expect_error(.typed_blob_with_crypto(pair$sender,
      .dsvert_typed_blob_mint(
        pair$sender$ss, pair$sender$session_id, spec$capability,
        pair$sender$peer_transport, payload, context,
        producer = "otherCountProducerDS")), "does not own")

    wrong_type_ticket <- .typed_blob_mutate_envelope(
      produced$transfer$ticket, function(body) {
        body$capability_id <- "blob.analysis-dp.count-source.v1"
        body
      })
    tampered_context_ticket <- .typed_blob_mutate_envelope(
      produced$transfer$ticket, function(body) {
        decoded <- jsonlite::fromJSON(rawToChar(
          .dsvert_relay_b64url_decode(
            body$context, "test Count context")), simplifyVector = FALSE)
        decoded$artifact_key <- strrep("4", 64L)
        body$context <- .dsvert_typed_blob_context_token(decoded)
        body
      })
    receipt <- .typed_blob_with_crypto(pair$recipient, {
      expect_error(.mpcTypedBlobStoreDS_impl(
        wrong_type_ticket, payload, 0, pair$recipient$session_id),
        "not present in the server registry")
      expect_error(.mpcTypedBlobStoreDS_impl(
        tampered_context_ticket, payload, 0, pair$recipient$session_id),
        "metadata conflicts")
      sealed <- .mpcTypedBlobStoreDS_impl(
        produced$transfer$ticket, payload, 0,
        pair$recipient$session_id)
      expect_true(sealed$sealed)
      terminal_replay <- .mpcTypedBlobStoreDS_impl(
        produced$transfer$ticket, payload, 0,
        pair$recipient$session_id)
      expect_identical(terminal_replay, sealed)

      wrong_context <- context
      wrong_context$contract_hash <- strrep("5", 64L)
      expect_error(.dsvert_typed_blob_consume(
        pair$recipient$ss, spec$capability, wrong_context,
        sender_name = "self"),
        "could not resolve|not committed|provenance/shape")
      expect_identical(.dsvert_typed_blob_consume(
        pair$recipient$ss, spec$capability, context,
        sender_name = "self"), payload)
      destination <- .dsvert_typed_blob_destination(
        spec$capability, "self", context)$slot
      expect_null(pair$recipient$ss$.typed_blob_destinations[[destination]])
      expect_false(.dsvert_typed_blob_destination_present(
        pair$recipient$ss, destination))
      receipt_state <- pair$recipient$ss$.typed_blob_receipts[[
        produced$transfer$transfer_id]]
      expect_length(receipt_state$frame_offsets, 1L)
      expect_length(receipt_state$frame_chars, 1L)
      sealed$receipt
    })

    confirmation <- .typed_blob_with_crypto(pair$sender,
      .mpcTypedBlobReceiptDS_impl(receipt, pair$sender$session_id))
    expect_true(confirmation$confirmed)
    expect_null(pair$sender$ss$.typed_blob_outbound[[
      produced$transfer$transfer_id]])
    expect_false(.typed_blob_with_crypto(pair$sender,
      .dsvert_typed_blob_operation_replay(
        pair$sender$ss, spec$producer, request))$hit)
  }
})

test_that("Frequency typed context and fixed header are closed and public", {
  context <- .typed_blob_frequency_context()
  resolved <- .dsvert_typed_blob_destination(
    "blob.analysis-dp.frequency-source-to-finalizer.v1", "self", context)
  expect_identical(resolved$ring, "128")
  expect_identical(resolved$count, "65536")
  expect_identical(resolved$producer, "dsvertDPFrequencySourceWindowDS")
  expect_identical(resolved$consumer, "dsvertDPFrequencyFinalizeWindowDS")

  header <- .dsvert_typed_blob_frequency_header_v1(
    context, strrep("a", 64L))
  expect_identical(header$header_bytes, 8192L)
  expect_identical(header$capability_id,
                   "blob.analysis-dp.frequency-source-to-finalizer.v1")
  expect_identical(header$peer_binding_digest, strrep("a", 64L))
  expect_lte(nchar(.dsvert_dp_canonical_json(header), type = "bytes"),
             header$header_bytes)
  expect_identical(.DSVERT_TYPED_BLOB_FREQUENCY_CIPHERTEXT_CHARS,
                   as.integer(4 * (8192 + 65536 * 16 + 60) / 3))
  for (field in setdiff(names(context), "version")) {
    expect_identical(header[[field]], context[[field]], info = field)
  }
  wire <- .dsvert_dp_canonical_json(list(context = context, header = header))
  expect_false(any(vapply(c(
    "histogram", "noised_share", "source_window_sha256", "chunk_hash",
    "preclamp", "plaintext_sha256", "plaintext_bytes"), grepl,
    logical(1L), x = wire, fixed = TRUE)))

  legacy <- c(context, list(noised_share_sha256 = strrep("b", 64L)))
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY, "self", legacy),
    "producer context")
  expect_error(.dsvert_typed_blob_destination(
    "blob.joint-dp.vector-final-share.v3", "self", context),
    "producer context")
  changed <- context
  changed$roles$secondary_noise_authority <- "other-peer"
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY, "self", changed),
    "Frequency route")
  changed <- context
  changed$first_chunk_index <- "1"
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY, "self", changed),
    "Frequency geometry")
})

test_that("Frequency inline transfer is fixed, replay-safe and released", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  context <- .typed_blob_frequency_context()
  payload <- strrep("A", .DSVERT_TYPED_BLOB_FREQUENCY_CIPHERTEXT_CHARS)
  producer <- "dsvertDPFrequencySourceWindowDS"
  request <- list(
    operation_id = context$operation_id, window_index = context$window_index)

  produced <- .typed_blob_with_crypto(pair$sender, {
    transfer <- .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id,
      .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
      pair$sender$peer_transport, payload, context, producer = producer)
    .dsvert_typed_blob_operation_commit(
      pair$sender$ss, producer, request,
      list(ciphertext_chars = payload, transfer = transfer))
  })
  expect_null(pair$sender$ss$.typed_blob_outbound[[
    produced$transfer$transfer_id]]$source_path)
  expect_identical(.dsvert_typed_blob_retained_bytes(pair$sender$ss),
                   as.numeric(.DSVERT_TYPED_BLOB_FREQUENCY_CIPHERTEXT_CHARS))
  replay <- .dsvert_typed_blob_operation_replay(
    pair$sender$ss, producer, request)
  expect_true(replay$hit)
  expect_identical(replay$result, produced)
  expect_identical(replay$result$ciphertext_chars, payload)

  expect_error(.typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id,
      .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
      pair$sender$peer_transport, substr(payload, 1L, nchar(payload) - 1L),
      context, producer = producer)), "fixed ciphertext")

  receipt <- .typed_blob_with_crypto(pair$recipient, {
    sealed <- .mpcTypedBlobStoreDS_impl(
      produced$transfer$ticket, payload, 0, pair$recipient$session_id)
    expect_true(sealed$sealed)
    expect_identical(.dsvert_typed_blob_consume(
      pair$recipient$ss, .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
      context, sender_name = "self", consume = FALSE), payload)
    expect_identical(.dsvert_typed_blob_consume(
      pair$recipient$ss, .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
      context, sender_name = "self", consume = TRUE), payload)
    expect_false(.dsvert_typed_blob_destination_present(
      pair$recipient$ss, .dsvert_typed_blob_destination(
        .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
        "self", context)$slot))
    sealed$receipt
  })
  confirmation <- .typed_blob_with_crypto(pair$sender,
    .mpcTypedBlobReceiptDS_impl(receipt, pair$sender$session_id))
  expect_true(confirmation$confirmed)
  expect_null(pair$sender$ss$.typed_blob_outbound[[
    produced$transfer$transfer_id]])
  expect_identical(.dsvert_typed_blob_retained_bytes(pair$sender$ss), 0)
  expect_false(.dsvert_typed_blob_operation_replay(
    pair$sender$ss, producer, request)$hit)
})

test_that("Frequency tickets reject TTL, recipient, binding and purpose tamper", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  on.exit(.session_dir_cleanup(pair$recipient$ss), add = TRUE)
  context <- .typed_blob_frequency_context()
  payload <- strrep("A", .DSVERT_TYPED_BLOB_FREQUENCY_CIPHERTEXT_CHARS)
  minted <- .typed_blob_with_crypto(pair$sender,
    .dsvert_typed_blob_mint(
      pair$sender$ss, pair$sender$session_id,
      .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
      pair$sender$peer_transport, payload, context,
      producer = "dsvertDPFrequencySourceWindowDS"))

  mutations <- list(
    ttl = function(body) {
      body$expires_at <- as.character(as.numeric(body$expires_at) + 1)
      body
    },
    recipient = function(body) {
      body$recipient_name <- "other-peer"
      body
    },
    binding = function(body) {
      body$peer_binding_digest <- strrep("b", 64L)
      body
    },
    purpose = function(body) {
      decoded <- jsonlite::fromJSON(rawToChar(.dsvert_relay_b64url_decode(
        body$context, "test Frequency context")), simplifyVector = FALSE)
      decoded$purpose <- "analysis-dp.count-final-share.v1"
      body$context <- .dsvert_typed_blob_context_token(decoded)
      body
    })
  for (name in names(mutations)) {
    tampered <- .typed_blob_mutate_envelope(minted$ticket, mutations[[name]])
    expect_error(.typed_blob_with_crypto(pair$recipient,
      .mpcTypedBlobStoreDS_impl(
        tampered, payload, 0, pair$recipient$session_id)),
      "lifetime|pinned-peer|Frequency purpose", info = name)
  }

  expect_true(.typed_blob_with_crypto(pair$recipient,
    .mpcTypedBlobStoreDS_impl(
      minted$ticket, payload, 0, pair$recipient$session_id))$sealed)
})

test_that("expiry sweep releases an unstarted inline Frequency operation", {
  pair <- .typed_blob_test_pair()
  on.exit(.session_dir_cleanup(pair$sender$ss), add = TRUE)
  clock <- 1000
  context <- .typed_blob_frequency_context()
  payload <- strrep("A", .DSVERT_TYPED_BLOB_FREQUENCY_CIPHERTEXT_CHARS)
  producer <- "dsvertDPFrequencySourceWindowDS"
  request <- list(kind = "inline-expiry")
  produced <- testthat::with_mocked_bindings(
    .typed_blob_with_crypto(pair$sender, {
      transfer <- .dsvert_typed_blob_mint(
        pair$sender$ss, pair$sender$session_id,
        .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
        pair$sender$peer_transport, payload, context, producer = producer)
      .dsvert_typed_blob_operation_commit(
        pair$sender$ss, producer, request,
        list(ciphertext_chars = payload, transfer = transfer))
    }),
    .dsvert_typed_blob_now = function() clock, .package = "dsVert")
  expect_null(pair$sender$ss$.typed_blob_outbound[[
    produced$transfer$transfer_id]]$source_path)

  clock <- clock + .DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS + 1
  expect_true(.dsvert_typed_blob_sweep_expired(
    pair$sender$ss, now = clock, maximum = 1L))
  expect_null(pair$sender$ss$.typed_blob_outbound[[
    produced$transfer$transfer_id]])
  expect_length(pair$sender$ss$.typed_blob_pending_operations, 0L)
})
