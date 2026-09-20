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
