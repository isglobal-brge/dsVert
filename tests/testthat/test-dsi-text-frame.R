test_that("canonical DSI text framing has stable R, L, and B goldens", {
  values <- c(
    "",
    "abc_DEF-09",
    paste0(strrep("A", 20), "\"", strrep("B", 20)),
    "{\"a\":\"b\\\\c\",\"n\":1}",
    "é")
  expected <- c(
    "DSV1R_",
    "DSV1R_abc_DEF-09",
    paste0("DSV1L_20-", strrep("A", 20), "2220-", strrep("B", 20)),
    "DSV1B_eyJhIjoiYlxcYyIsIm4iOjF9",
    "DSV1B_w6k")

  encoded <- vapply(
    values, .dsvert_dsi_text_encode, character(1L), USE.NAMES = FALSE)
  expect_identical(encoded, expected)
  expect_true(all(grepl("^[A-Za-z0-9_-]*$", encoded)))
  expect_identical(
    vapply(encoded, .dsvert_dsi_text_decode, character(1L),
           USE.NAMES = FALSE),
    values)
})

test_that("DSI text decoding rejects malformed and non-canonical aliases", {
  malformed <- c(
    "", "raw", "DSV0R_raw", "DSV1R_a%",
    "DSV1L_", "DSV1L_01-A", "DSV1L_2-A", "DSV1L_0-7",
    "DSV1L_0-7b", "DSV1L_0-41", "DSV1L_3-abc",
    "DSV1L_999999999999999999999999-A", "DSV1L_0-220-",
    "DSV1B_", "DSV1B_YWJj", "DSV1B_a")
  for (value in malformed) {
    expect_error(.dsvert_dsi_text_decode(value), "Invalid framed DSI text")
  }
  expect_error(
    .dsvert_dsi_text_decode(
      .dsvert_dsi_text_encode("abcd"), maximum_bytes = 3L),
    "Invalid framed DSI text")
  expect_error(
    .dsvert_dsi_text_decode("DSV1B__w"),
    "Invalid framed DSI text")

  valid_l <- .dsvert_dsi_text_encode(paste0(
    strrep("A", 20L), "\"", strrep("B", 20L)))
  truncated_l <- substr(valid_l, 1L, nchar(valid_l) - 1L)
  expect_error(
    .dsvert_dsi_text_decode(truncated_l),
    "Invalid framed DSI text")
})

test_that("the wire alphabet gate precedes the L parser", {
  entered_l_parser <- FALSE
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dsi_text_decode("DSV1L_1-!22"),
    .dsvert_dsi_text_decode_l = function(...) {
      entered_l_parser <<- TRUE
      raw()
    }), "Invalid framed DSI text")
  expect_false(entered_l_parser)
})

test_that("an old raw client fails before the new server manifest body", {
  entered_manifest_body <- FALSE
  response <- testthat::with_mocked_bindings(
    dsvertDPCapsuleManifestSignDS(
      "{\"version\":\"old-raw-client\"}",
      "{\"version\":\"old-raw-client\"}"),
    .dsvert_dp_capsule_manifest_sign_impl = function(...) {
      entered_manifest_body <<- TRUE
      stop("manifest body must not run", call. = FALSE)
    })

  expect_false(entered_manifest_body)
  expect_identical(response$rejected, TRUE)
  expect_identical(response$reason_code, "boundary_validation_failed")
})

test_that("DSI text framing builds only its selected representation", {
  long_json <- paste0(
    "{\"payload\":\"", strrep("A_", 4096L), "\"}")
  expect_true(startsWith(.dsvert_dsi_text_encode(long_json), "DSV1L_"))
  expect_true(startsWith(.dsvert_dsi_text_encode("{}[],:!"), "DSV1B_"))

  expect_no_error(testthat::with_mocked_bindings(
    .dsvert_dsi_text_encode(long_json),
    .dsvert_dsi_text_encode_b = function(...) {
      stop("the losing B builder ran", call. = FALSE)
    }))
})

test_that("DSI text framing round-trips deterministic byte samples", {
  set.seed(20260808)
  alphabet <- c(letters, LETTERS, 0:9, "_", "-", "{", "}", "\"",
                "\\", ":", ",", "[", "]", "é")
  values <- c("", replicate(256L, paste0(sample(
    alphabet, sample.int(256L, 1L) - 1L, replace = TRUE), collapse = "")))
  for (value in values) {
    encoded <- .dsvert_dsi_text_encode(value)
    expect_match(encoded, "^[A-Za-z0-9_-]*$")
    expect_identical(.dsvert_dsi_text_decode(encoded), enc2utf8(value))
  }
})
