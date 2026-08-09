test_that("GLM standardisation fails closed on missing and non-finite values", {
  sid <- "11111111-1111-4111-8111-111111111111"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  D <- data.frame(
    x = c(1, 2, NA, 4, 5, 6),
    y = c(1, 2, 3, 4, 5, 6))

  expect_error(
    glmStandardizeDS("D", "D_std", "x", "y", session_id = sid),
    "DSVERT_INCOMPLETE_ANALYSIS_DATA",
    fixed = TRUE)

  D$x[3] <- Inf
  expect_error(
    glmStandardizeDS("D", "D_std", "x", "y", session_id = sid),
    "DSVERT_NONFINITE_ANALYSIS_DATA",
    fixed = TRUE)
})

test_that("mean imputation is explicit and correct on every scaling mode", {
  sid <- "22222222-2222-4222-8222-222222222222"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  for (mode in c("full", "scale_only", "none")) {
    D <- data.frame(
      x = c(1, 2, NA, 4, 5, 6),
      y = c(2, 4, 6, NA, 10, 12))

    res <- glmStandardizeDS(
      "D", "D_std", "x", "y",
      session_id = sid, missing = "mean_impute", mode = mode)
    stored <- getFromNamespace(".S", "dsVert")(sid)$std_data

    expect_false(anyNA(stored[c("x", "y")]))
    expect_true(all(is.finite(unlist(stored[c("x", "y")]))))
    expect_identical(res$missing_policy, "mean_impute")

    if (identical(mode, "full")) {
      expect_equal(stored$x[3], 0, tolerance = 1e-12)
      expect_equal(stored$y[4], 0, tolerance = 1e-12)
    } else if (identical(mode, "scale_only")) {
      expect_equal(stored$x[3], mean(D$x, na.rm = TRUE) / sd(D$x, na.rm = TRUE))
      expect_equal(stored$y[4], mean(D$y, na.rm = TRUE) / sd(D$y, na.rm = TRUE))
    } else {
      expect_equal(stored$x[3], mean(D$x, na.rm = TRUE))
      expect_equal(stored$y[4], mean(D$y, na.rm = TRUE))
    }
  }
})

test_that("GLM standardisation rejects invalid design contracts", {
  sid <- "33333333-3333-4333-8333-333333333333"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  D <- data.frame(x = 1:6, y = 2:7, group = letters[1:6])

  expect_error(
    glmStandardizeDS("D", "D_std", "missing", "y", session_id = sid),
    "not found")
  expect_error(
    glmStandardizeDS("D", "D_std", "group", "y", session_id = sid),
    "must be numeric")
  expect_error(
    glmStandardizeDS("D", "D_std", "x", "y", session_id = sid,
                     mode = "mystery"),
    "mode must be")
  expect_error(
    glmStandardizeDS("D", "D_std", "x", "y", session_id = sid,
                     missing = "silent"),
    "missing must be")
})
