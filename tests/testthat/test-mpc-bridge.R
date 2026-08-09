test_that("the R-to-Go bridge preserves every binary64 input bit", {
  values <- c(
    1 / 3, .Machine$double.eps, 0.03125, 1e-12,
    pi, .Machine$double.xmin, 2^52 - 1)

  encoded <- .dsvert_mpc_encode_json(list(values = values))
  decoded <- jsonlite::fromJSON(encoded)$values

  expect_identical(decoded, values)
  default_encoded <- as.character(jsonlite::toJSON(
    list(values = values), auto_unbox = TRUE, null = "null"))
  expect_false(identical(jsonlite::fromJSON(default_encoded)$values, values))
})

test_that("the MPC bridge validates command/input before process execution", {
  expect_error(
    .callMpcTool("version;echo injected", list()),
    "Invalid dsvert-mpc command")
  expect_error(
    .callMpcTool("version", "not-a-list"),
    "input_data must be a list")
})

test_that("private per-call bridge directories are removed", {
  skip_on_os("windows")
  fake <- tempfile("dsvert-mpc-fake-")
  writeLines(c("#!/bin/sh", "printf '{\"ok\":true}\\n'"), fake)
  Sys.chmod(fake, mode = "0700")
  on.exit(unlink(fake, force = TRUE), add = TRUE)
  old <- options(dsvert.mpc_binary = fake)
  on.exit(options(old), add = TRUE)

  before <- list.dirs(tempdir(), recursive = FALSE, full.names = TRUE)
  # runtime-capabilities is the sole bootstrap command; all operational
  # commands require a validated manifest before execution.
  result <- .callMpcTool("runtime-capabilities", list(value = pi))
  after <- list.dirs(tempdir(), recursive = FALSE, full.names = TRUE)

  expect_true(isTRUE(result$ok))
  expect_setequal(after, before)
})
