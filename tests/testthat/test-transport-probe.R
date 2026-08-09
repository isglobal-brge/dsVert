test_that("transport probe validates public bytes without protocol state", {
  padding <- strrep("A", 64L * 1024L)
  hash <- digest::digest(padding, algo = "sha256", serialize = FALSE)
  nonce <- paste0("tp_", strrep("a", 32L))
  before_sessions <- ls(.mpc_sessions, all.names = TRUE)

  result <- testthat::with_mocked_bindings(
    dsvertTransportProbeDS(nonce, padding, hash),
    .S = function(...) stop("probe accessed an MPC session"))
  expect_identical(result$version, "dsvert-transport-probe-v1")
  expect_identical(result$nonce, nonce)
  expect_identical(result$padding_chars, as.numeric(nchar(padding)))
  expect_identical(result$padding_sha256, hash)
  expect_identical(result$server_max_padding_chars, 8 * 1024^2)
  expect_identical(ls(.mpc_sessions, all.names = TRUE), before_sessions)
})

test_that("response probe is data-free, bounded and leaves v1 byte-identical", {
  nonce <- paste0("tp_", strrep("a", 32L))
  padding <- "public"
  hash <- digest::digest(padding, algo = "sha256", serialize = FALSE)
  legacy <- dsvertTransportProbeDS(nonce, padding, hash)
  expect_identical(names(legacy), c(
    "version", "nonce", "padding_chars", "padding_sha256",
    "server_max_padding_chars"))

  response <- dsvertTransportProbeDS(
    nonce, padding, hash, response_padding_chars = 16L * 1024L)
  expect_identical(
    response$version, "dsvert-transport-response-probe-v1")
  expect_identical(response$nonce, nonce)
  expect_identical(response$response_padding_chars, 16 * 1024)
  expect_identical(
    nchar(response$response_padding, type = "bytes"), 16L * 1024L)
  expect_identical(
    response$response_padding_sha256,
    digest::digest(
      response$response_padding, algo = "sha256", serialize = FALSE))
  expect_identical(
    response$server_max_response_padding_chars, 8 * 1024^2)
})

test_that("response probe enforces its independent fixed server cap", {
  nonce <- paste0("tp_", strrep("b", 32L))
  padding <- "public"
  hash <- digest::digest(padding, algo = "sha256", serialize = FALSE)
  withr::local_options(list(
    dsvert.transport_probe_max_response_bytes = 32L * 1024L))
  expect_error(dsvertTransportProbeDS(
    nonce, padding, hash, response_padding_chars = 64L * 1024L),
    "response-probe padding exceeds")
  expect_error(dsvertTransportProbeDS(
    nonce, padding, hash, response_padding_chars = 1),
    "response-probe padding exceeds")
})

test_that("transport probe rejects malformed, non-ASCII and oversized input", {
  nonce <- paste0("tp_", strrep("b", 32L))
  padding <- strrep("A", 16L * 1024L)
  hash <- digest::digest(padding, algo = "sha256", serialize = FALSE)
  expect_error(
    dsvertTransportProbeDS("chosen", padding, hash), "nonce")
  expect_error(
    dsvertTransportProbeDS(nonce, paste0(padding, "é"), hash), "ASCII")
  newline <- paste0(padding, "\n")
  expect_error(dsvertTransportProbeDS(
    nonce, newline,
    digest::digest(newline, algo = "sha256", serialize = FALSE)), "ASCII")
  expect_error(
    dsvertTransportProbeDS(nonce, padding, strrep("0", 64L)), "hash")

  withr::local_options(list(
    dsvert.transport_probe_max_padding_bytes = 16L * 1024L))
  expect_error(
    dsvertTransportProbeDS(
      nonce, paste0(padding, "A"),
      digest::digest(paste0(padding, "A"),
                     algo = "sha256", serialize = FALSE)),
    "server byte bound")
})

test_that("transport probe server cap cannot exceed eight MiB", {
  expect_identical(
    .DSVERT_TYPED_BLOB_MAX_FRAME_BYTES,
    .DSVERT_TRANSPORT_PROBE_ABSOLUTE_MAX)
  expect_identical(
    .DSVERT_LEGACY_BLOB_MAX_FRAME_BYTES,
    .DSVERT_TRANSPORT_PROBE_ABSOLUTE_MAX)
  withr::local_options(list(
    dsvert.transport_probe_max_padding_bytes = 8 * 1024^2 + 1))
  expect_error(.dsvert_transport_probe_max_padding(),
               "Invalid server transport-probe byte bound")
})
