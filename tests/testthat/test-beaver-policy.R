test_that("Beaver policy is IKNP-only by default (dealer mode removed)", {
  old <- options(dsvert.beaver_preprocessing.allowed = NULL,
                 dsvert.beaver_preprocessing.preferred = NULL,
                 dsvert.beaver_preprocessing.minimum = NULL)
  on.exit(options(old), add = TRUE)

  p <- dsvertBeaverPolicyDS()
  expect_setequal(p$supported, "iknp")
  expect_setequal(p$allowed, "iknp")
  expect_identical(p$preferred, "iknp")
  expect_true(p$requires_iknp)
})

test_that("Beaver policy can require IKNP", {
  old <- options(dsvert.beaver_preprocessing.allowed = "iknp",
                 dsvert.beaver_preprocessing.preferred = "iknp",
                 dsvert.beaver_preprocessing.minimum = "iknp")
  on.exit(options(old), add = TRUE)

  p <- dsvertBeaverPolicyDS()
  expect_identical(p$allowed, "iknp")
  expect_identical(p$preferred, "iknp")
  expect_true(p$requires_iknp)
  expect_error(.dsvert_require_beaver_mode("dealer"), "REQUIRES_IKNP")
  expect_silent(.dsvert_require_beaver_mode("iknp"))
})
