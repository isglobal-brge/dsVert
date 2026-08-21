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

test_that("private per-call bridge files use Rock and are removed", {
  skip_on_os("windows")
  root <- withr::local_tempdir(pattern = "dsvert-mpc-rock-")
  withr::local_options(list(dsvert.state_dir = root))
  fake <- file.path(root, "fake-mpc")
  writeLines(c("#!/bin/sh", "printf '{\"ok\":true}\\n'"), fake)
  Sys.chmod(fake, mode = "0700")
  on.exit(unlink(fake, force = TRUE), add = TRUE)
  old <- options(dsvert.mpc_binary = fake)
  on.exit(options(old), add = TRUE)
  capture_name <- ".dsvert_mpc_bridge_trace_capture"
  assign(capture_name, NULL, envir = .GlobalEnv)
  on.exit(rm(list = capture_name, envir = .GlobalEnv), add = TRUE)
  trace("system2", where = baseenv(), print = FALSE,
        tracer = quote({
          paths <- as.character(c(stdin, stdout, stderr))
          private_file <- get(".dsvert_dp_private_mode",
                              envir = asNamespace("dsVert"), inherits = FALSE)
          assign(".dsvert_mpc_bridge_trace_capture", list(
            command = as.character(command), args = as.character(args),
            stdin = paths[[1L]], stdout = paths[[2L]], stderr = paths[[3L]],
            files_private = vapply(paths, private_file, logical(1L),
                                    directory = FALSE),
            directory_private = private_file(dirname(paths[[1L]]),
                                               directory = TRUE)),
                 envir = .GlobalEnv)
        }))
  on.exit(untrace("system2", where = baseenv()), add = TRUE)

  invocation_root <- .dsvert_mpc_invocation_root()
  before <- list.dirs(invocation_root, recursive = FALSE, full.names = TRUE)
  # runtime-capabilities is the sole bootstrap command; all operational
  # commands require a validated manifest before execution.
  result <- .callMpcTool("runtime-capabilities", list(value = pi))
  after <- list.dirs(invocation_root, recursive = FALSE, full.names = TRUE)
  captured <- get(capture_name, envir = .GlobalEnv, inherits = FALSE)

  expect_true(isTRUE(result$ok))
  expect_setequal(after, before)
  expect_true(all(grepl(
    "/transient-sessions-v1/mpc-invocations-v1/call-[^/]+/(input\\.json|output\\.json|stderr\\.txt)$",
    unlist(captured[c("stdin", "stdout", "stderr")]))) )
  expect_true(all(captured$files_private))
  expect_true(captured$directory_private)
})

test_that("the MPC bridge rejects a temporary invocation root in production", {
  skip_on_os("windows")
  root <- withr::local_tempdir(pattern = "dsvert-mpc-temporary-")
  withr::local_options(list(dsvert.state_dir = root))
  fake <- file.path(root, "fake-mpc")
  writeLines(c("#!/bin/sh", "printf '{\"ok\":true}\\n'"), fake)
  Sys.chmod(fake, mode = "0700")
  on.exit(unlink(fake, force = TRUE), add = TRUE)
  old <- options(dsvert.mpc_binary = fake)
  on.exit(options(old), add = TRUE)
  testthat::local_mocked_bindings(
    .dsvert_identity_test_mode = function() FALSE,
    .package = "dsVert")

  expect_error(
    .callMpcTool("runtime-capabilities", list()),
    "outside temporary")
})

test_that("the MPC bridge preserves singleton arrays only when requested", {
  skip_on_os("windows")
  fake <- tempfile("dsvert-mpc-array-fake-")
  writeLines(c("#!/bin/sh", "printf '{\"values\":[\"only\"]}\\n'"), fake)
  Sys.chmod(fake, mode = "0700")
  on.exit(unlink(fake, force = TRUE), add = TRUE)
  old <- options(dsvert.mpc_binary = fake)
  on.exit(options(old), add = TRUE)

  legacy <- .callMpcTool("runtime-capabilities", list())
  expect_identical(legacy$values, "only")
  preserved <- .callMpcTool(
    "runtime-capabilities", list(), simplify_output = FALSE)
  expect_identical(preserved$values, list("only"))
  expect_error(.callMpcTool(
    "runtime-capabilities", list(), simplify_output = NA),
    "simplify_output")
})
