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
