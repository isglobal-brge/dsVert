test_that("custodians can extend release leases without changing defaults", {
  old <- options(dsvert.exact_gc.ttl_seconds = NULL,
    default.dsvert.exact_gc.ttl_seconds = NULL,
    dsvert.exact_gc.max_runtime_seconds = NULL,
    default.dsvert.exact_gc.max_runtime_seconds = NULL)
  on.exit(options(old), add = TRUE)
  expect_equal(.exact_gc_ttl_seconds(), 180)
  expect_equal(.exact_gc_max_runtime_seconds(), 21600)
  options(dsvert.exact_gc.ttl_seconds = 900,
    dsvert.exact_gc.max_runtime_seconds = 86400)
  expect_equal(.exact_gc_ttl_seconds(), 900)
  expect_equal(.exact_gc_max_runtime_seconds(), 86400)
  options(dsvert.exact_gc.max_runtime_seconds = 899)
  expect_error(.exact_gc_max_runtime_seconds(), "policy")
  options(dsvert.exact_gc.max_runtime_seconds = 7 * 86400 + 1)
  expect_error(.exact_gc_max_runtime_seconds(), "policy")
})

test_that("extended operation lease survives six hours but still expires", {
  state <- new.env(parent = emptyenv())
  state$status <- "running"
  state$ttl_seconds <- 900
  state$max_runtime_seconds <- 86400
  state$started_at <- 100
  state$last_activity <- 21701
  state$worker_heartbeat_seen_at <- 21701
  state$process <- list(is_alive = function() TRUE)
  aborted <- FALSE
  ss <- new.env(parent = emptyenv())
  testthat::with_mocked_bindings({
    expect_false(.exact_gc_expire_if_idle(ss, state, now = 21701))
    # Changing administrator options cannot mutate a lease already negotiated
    # by both peers; the operation's captured policy remains authoritative.
    withr::with_options(list(dsvert.exact_gc.max_runtime_seconds = 21600),
      expect_false(.exact_gc_expire_if_idle(ss, state, now = 21702)))
    expect_false(aborted)
    state$last_activity <- state$worker_heartbeat_seen_at <- 86501
    expect_error(.exact_gc_expire_if_idle(ss, state, now = 86501),
      "total runtime lease")
    expect_true(aborted)
  }, .exact_gc_observe_worker_heartbeat = function(...) FALSE,
  .exact_gc_abort_state = function(...) { aborted <<- TRUE },
  .package = "dsVert")
})

test_that("terminal worker failure survives lease checks until explicit abort", {
  spool <- tempfile("exact-gc-failed-lease-")
  dir.create(spool, mode = "0700")
  on.exit(unlink(spool, recursive = TRUE), add = TRUE)
  diagnostic <- file.path(spool, "worker-private.log")
  writeLines("synthetic worker failure", diagnostic)
  ss <- new.env(parent = emptyenv())
  state <- new.env(parent = emptyenv())
  state$status <- "running"
  state$spool <- spool
  state$operation_id <- "op_45454545454545454545454545454545"
  state$source_key <- "exact_gc_in_45454545454545454545454545454545"
  state$output_key <- "exact_gc_out_45454545454545454545454545454545"
  state$ttl_seconds <- 900
  state$max_runtime_seconds <- 86400
  state$started_at <- state$last_activity <- state$worker_heartbeat_seen_at <- 100
  state$worker_heartbeat_key <- as.raw(rep(1L, 32L))
  ss$.exact_gc_inputs <- list()
  ss$.exact_gc_outputs <- list()
  .exact_gc_mark_failed(ss, state, "numeric_backend_unavailable")

  # Failed workers can still be exiting, or already dead. Neither may renew a
  # lease or erase the diagnostic by replacing failure with an abort.
  for (alive in c(TRUE, FALSE)) {
    state$process <- list(is_alive = function() alive)
    expect_false(.exact_gc_expire_if_idle(ss, state, now = 101))
    expect_identical(state$status, "failed")
    expect_identical(state$failure_code, "numeric_backend_unavailable")
    expect_identical(readLines(diagnostic), "synthetic worker failure")
  }
  expect_false(.exact_gc_expire_if_idle(ss, state, now = 86501))
  expect_length(state$worker_heartbeat_key, 0L)
  .exact_gc_abort_state(ss, state)
  expect_identical(state$status, "aborted")
  expect_false(dir.exists(spool))
})
