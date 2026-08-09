test_that("DSI text framing keeps byte scans chunk-bounded", {
  value <- paste0(
    "{\"payload\":\"", strrep("A_", 512L * 1024L), "\"}")
  original_safe <- .dsvert_dsi_text_safe_raw
  largest_scan <- 0L
  encoded <- testthat::with_mocked_bindings(
    .dsvert_dsi_text_encode(value),
    .dsvert_dsi_text_safe_raw = function(bytes) {
      largest_scan <<- max(largest_scan, length(bytes))
      original_safe(bytes)
    })

  expect_true(startsWith(encoded, "DSV1L_"))
  expect_lte(largest_scan, .DSVERT_DSI_TEXT_CHUNK_BYTES)
  largest_scan <- 0L
  decoded <- testthat::with_mocked_bindings(
    .dsvert_dsi_text_decode(
      encoded, maximum_bytes = nchar(value, type = "bytes")),
    .dsvert_dsi_text_safe_raw = function(bytes) {
      largest_scan <<- max(largest_scan, length(bytes))
      original_safe(bytes)
    },
    .dsvert_dsi_text_encode = function(...) {
      stop("canonical decode rebuilt the complete frame", call. = FALSE)
    })
  expect_identical(decoded, value)
  expect_lte(largest_scan, .DSVERT_DSI_TEXT_CHUNK_BYTES)
})

test_that("DSI text framing has no payload-multiple auxiliary allocation", {
  skip_if_not(capabilities("profmem"))
  value <- paste0(
    "{\"payload\":\"", strrep("A_", 512L * 1024L), "\"}")
  profile <- tempfile("dsvert-dsi-frame-memory-", fileext = ".out")
  on.exit(unlink(profile), add = TRUE)
  active <- TRUE
  Rprofmem(profile)
  on.exit(if (active) Rprofmem(NULL), add = TRUE)
  encoded <- .dsvert_dsi_text_encode(value)
  decoded <- .dsvert_dsi_text_decode(
    encoded, maximum_bytes = nchar(value, type = "bytes"))
  Rprofmem(NULL)
  active <- FALSE

  records <- readLines(profile, warn = FALSE)
  sizes <- suppressWarnings(as.numeric(sub(
    "^([0-9]+).*$", "\\1", grep("^[0-9]+", records, value = TRUE))))
  sizes <- sizes[is.finite(sizes)]
  expect_true(length(sizes) > 0L)
  expect_lt(max(sizes), 2 * nchar(encoded, type = "bytes"))
  expect_identical(decoded, value)
})

test_that("canonical DSI modes remain stable across scan boundaries", {
  values <- c(
    paste0(strrep("A", .DSVERT_DSI_TEXT_CHUNK_BYTES - 1L), "\"B"),
    paste0(strrep("A", .DSVERT_DSI_TEXT_CHUNK_BYTES), "\"B"),
    paste0(strrep("A", .DSVERT_DSI_TEXT_CHUNK_BYTES + 1L), "\"B"),
    paste0(strrep("A", .DSVERT_DSI_TEXT_CHUNK_BYTES - 1L), "éB"))
  for (value in values) {
    encoded <- .dsvert_dsi_text_encode(value)
    expect_identical(
      .dsvert_dsi_text_decode(
        encoded, maximum_bytes = nchar(value, type = "bytes")),
      enc2utf8(value))
  }
})

test_that("dense canonical L batches remain bounded", {
  batch_copy_bytes <- .DSVERT_DSI_TEXT_CHUNK_BYTES %/% 4L
  small_run <- batch_copy_bytes %/% .DSVERT_DSI_TEXT_L_BATCH_RUNS
  expect_lte(
    .DSVERT_DSI_TEXT_L_BATCH_RUNS * small_run,
    batch_copy_bytes)

  value <- strrep("AAAAAAAA\"", .DSVERT_DSI_TEXT_L_BATCH_RUNS + 1L)
  encoded <- .dsvert_dsi_text_encode(value)
  expect_true(startsWith(encoded, "DSV1L_"))
  expect_identical(
    .dsvert_dsi_text_decode(
      encoded, maximum_bytes = nchar(value, type = "bytes")),
    value)
})

test_that("allocation leader omission uses the canonical empty wire default", {
  expect_identical(
    formals(dsvertJointDPVectorAllocationPrepareDS)$leader_prepare_json,
    "DSV1R_")
  result <- testthat::with_mocked_bindings(
    dsvertJointDPVectorAllocationPrepareDS(
      .dsvert_dsi_text_encode("{}")),
    .dsvert_joint_dp_vector_allocation_prepare_impl =
      function(manifest_json, leader_prepare_json) {
        list(manifest = manifest_json, leader = leader_prepare_json)
      })
  expect_identical(result, list(manifest = "{}", leader = ""))
})
