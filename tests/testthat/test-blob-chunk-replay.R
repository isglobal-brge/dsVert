test_that("terminal multipart replay is acknowledged without reopening state", {
  ss <- new.env(parent = emptyenv())

  expect_true(.dsvert_store_blob_chunks(
    ss, "relay_blob", "abcd", 1L, 3L))
  expect_true(.dsvert_store_blob_chunks(
    ss, "relay_blob", "efgh", 2L, 3L))
  expect_true(.dsvert_store_blob_chunks(
    ss, "relay_blob", "ij", 3L, 3L))
  expect_identical(.blob_snapshot(ss)$relay_blob, "abcdefghij")
  expect_null(ss$blob_chunks$relay_blob)
  expect_false(is.null(ss$blob_chunk_receipts$relay_blob))

  # Simulate loss of the terminal response: the client replays exactly the
  # same final frame. The completed object remains terminal and no second
  # partial buffer is opened.
  expect_true(.dsvert_store_blob_chunks(
    ss, "relay_blob", "ij", 3L, 3L))
  expect_identical(.blob_snapshot(ss)$relay_blob, "abcdefghij")
  expect_null(ss$blob_chunks$relay_blob)

  expect_error(.dsvert_store_blob_chunks(
    ss, "relay_blob", "different", 3L, 3L),
    "Conflicting retry for a completed blob")
  expect_error(.dsvert_store_blob_chunks(
    ss, "relay_blob", "ij", 3L, 4L),
    "Conflicting retry for a completed blob")
  expect_null(ss$blob_chunks$relay_blob)
})

test_that("consuming a completed blob releases its replay receipt", {
  ss <- new.env(parent = emptyenv())
  expect_true(.dsvert_store_blob_chunks(
    ss, "reusable_blob", "first", 1L, 1L))
  expect_false(is.null(ss$blob_chunk_receipts$reusable_blob))
  expect_identical(.blob_consume("reusable_blob", ss), "first")
  expect_null(ss$blob_chunk_receipts$reusable_blob)

  # Protocol-owned keys may be reused after their previous value is consumed.
  expect_true(.dsvert_store_blob_chunks(
    ss, "reusable_blob", "second", 1L, 1L))
  expect_identical(.blob_snapshot(ss)$reusable_blob, "second")
})

test_that("multipart legacy state is O(1)-updated and purpose-bound", {
  ss <- new.env(parent = emptyenv())
  expect_true(.dsvert_store_blob_chunks(
    ss, "ref_encrypted_blob", "abcd", 2L, 3L, purpose = "psi"))
  state <- ss$blob_chunks$ref_encrypted_blob
  expect_true(is.environment(state))
  expect_identical(state$received_count, 1L)
  expect_identical(state$received_bytes, 4)
  expect_identical(state$chunks[["2"]], "abcd")
  expect_error(.dsvert_store_blob_chunks(
    ss, "ref_encrypted_blob", "efgh", 1L, 3L, purpose = "generic"),
    "Conflicting or malformed")
  expect_true(.dsvert_store_blob_chunks(
    ss, "ref_encrypted_blob", "efgh", 1L, 3L, purpose = "psi"))
  expect_true(.dsvert_store_blob_chunks(
    ss, "ref_encrypted_blob", "ij", 3L, 3L, purpose = "psi"))
  expect_identical(.blob_snapshot(ss)$ref_encrypted_blob, "efghabcdij")
  expect_null(ss$blob_chunks$ref_encrypted_blob)
})

test_that("legacy oversize is terminal and preserves accepted multipart state", {
  ss <- new.env(parent = emptyenv())
  condition <- testthat::with_mocked_bindings(
    tryCatch(.dsvert_store_blob_chunks(
      ss, "bounded_blob", "abcd", 1L, 1L), error = identity),
    .DSVERT_LEGACY_BLOB_MAX_FRAME_BYTES = 3L,
    .package = "dsVert")
  expect_s3_class(condition, "dsvert_resource_oversize")
  expect_identical(condition$code, "resource_oversize")
  expect_false(condition$retryable)
  expect_null(ss$blobs$bounded_blob)

  testthat::with_mocked_bindings(
    expect_true(.dsvert_store_blob_chunks(
      ss, "multipart_blob", "abcd", 1L, 2L)),
    .DSVERT_LEGACY_BLOB_MAX_OBJECT_BYTES = 6,
    .package = "dsVert")
  before <- ss$blob_chunks$multipart_blob
  condition <- testthat::with_mocked_bindings(
    tryCatch(.dsvert_store_blob_chunks(
      ss, "multipart_blob", "efgh", 2L, 2L), error = identity),
    .DSVERT_LEGACY_BLOB_MAX_OBJECT_BYTES = 6,
    .package = "dsVert")
  expect_s3_class(condition, "dsvert_resource_oversize")
  expect_false(condition$retryable)
  expect_identical(ss$blob_chunks$multipart_blob, before)
  expect_identical(before$received_bytes, 4)
  expect_identical(before$chunks[["1"]], "abcd")
})

test_that("legacy byte capacity spans distinct keys and sessions and reclaims", {
  withr::local_options(list(
    dsvert.transport.global_spool_max_bytes = 1024^2))
  first <- new.env(parent = emptyenv())
  second <- new.env(parent = emptyenv())
  first$.session_id <- "legacy-resource-first"
  second$.session_id <- "legacy-resource-second"
  on.exit({
    .session_dir_cleanup(first)
    .session_dir_cleanup(second)
  }, add = TRUE)
  first_payload <- strrep("A", 700L * 1024L)
  second_payload <- strrep("B", 400L * 1024L)
  expect_true(.dsvert_store_blob_chunks(
    first, "distinct_key_one", first_payload, 1L, 1L))

  same_session <- tryCatch(.dsvert_store_blob_chunks(
    first, "distinct_key_two", second_payload, 1L, 1L), error = identity)
  expect_s3_class(same_session, "dsvert_resource_backpressure")
  expect_true(same_session$retryable)
  expect_null(first$blob_chunk_receipts$distinct_key_two)
  expect_null(.blob_snapshot(first)$distinct_key_two)

  other_session <- tryCatch(.dsvert_store_blob_chunks(
    second, "independent_key", second_payload, 1L, 1L), error = identity)
  expect_s3_class(other_session, "dsvert_resource_backpressure")
  expect_null(second$blob_chunk_receipts$independent_key)
  expect_null(.blob_snapshot(second)$independent_key)

  .session_dir_cleanup(first)
  expect_true(.dsvert_store_blob_chunks(
    second, "independent_key", second_payload, 1L, 1L))
  expect_identical(.blob_consume("independent_key", second), second_payload)
  expect_identical(.dsvert_resource_session_bytes(second), 0)
})
