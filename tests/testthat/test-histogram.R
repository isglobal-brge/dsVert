# Tests for dsvertHistogramDS and dsvertLocalMomentsDS

library(testthat)

# Deterministic fixture visible to server-side callers via parent.frame()
make_df <- function(seed = 42) {
  set.seed(seed)
  data.frame(
    x = c(rnorm(50, mean = 0, sd = 1), NA, NA),
    y = c(rpois(52, lambda = 3)),
    g = factor(rep(c("a", "b"), length.out = 52))
  )
}

# =============================================================================
# dsvertHistogramDS
# =============================================================================

test_that("histogram counts sum to n_total and match tabulate()", {
  D <- make_df()
  edges <- c(-3, -1, 0, 1, 3)
  res <- dsvertHistogramDS("D", "x", edges, suppress_small_cells = FALSE)

  expect_type(res, "list")
  expect_equal(length(res$counts), length(edges) - 1L)
  expect_equal(sum(res$counts) + res$below + res$above, res$n_total)

  # Manual reference: findInterval with right-closed last bucket
  x_nomiss <- D$x[!is.na(D$x)]
  idx <- findInterval(x_nomiss, edges, rightmost.closed = TRUE)
  expected <- as.integer(tabulate(idx, nbins = length(edges) - 1L))
  expect_equal(res$counts, expected)
  expect_equal(res$n_na, sum(is.na(D$x)))
})

test_that("histogram suppresses small cells when enabled", {
  D <- make_df()
  # Very tight edges so some buckets have 1 observation
  edges <- c(-5, -2, -1, 0, 1, 2, 5)

  raw <- dsvertHistogramDS("D", "x", edges, suppress_small_cells = FALSE)
  # privacyLevel default is 5 in dsVert DESCRIPTION; some buckets should
  # have <5 observations on a 50-sample Gaussian.
  has_small <- any(raw$counts > 0L & raw$counts < 5L)
  if (!has_small) skip("no small cells on this fixture; adjust seed or edges")

  suppressed <- dsvertHistogramDS("D", "x", edges, suppress_small_cells = TRUE)
  # Every cell that was in (0, privacy_min) must now be 0
  for (k in seq_along(raw$counts)) {
    if (raw$counts[k] > 0L && raw$counts[k] < 5L) {
      expect_equal(suppressed$counts[k], 0L)
    } else {
      expect_equal(suppressed$counts[k], raw$counts[k])
    }
  }
  expect_equal(suppressed$n_total, raw$n_total)
})

test_that("histogram errors on bad input", {
  D <- make_df()
  expect_error(dsvertHistogramDS("D", "x", c(1)),
               "edges must be a numeric vector of length >= 2")
  expect_error(dsvertHistogramDS("D", "x", c(3, 1, 2)),
               "edges must be strictly increasing")
  expect_error(dsvertHistogramDS("D", "missing", c(0, 1)),
               "Variable 'missing' not found")
  expect_error(dsvertHistogramDS("D", "g", c(0, 1)),
               "must be numeric")
})

# =============================================================================
# dsvertLocalMomentsDS
# =============================================================================

test_that("local moments match base R mean/sd/min/max", {
  D <- make_df()
  res <- dsvertLocalMomentsDS("D", "x")

  x_nomiss <- D$x[!is.na(D$x)]
  expect_equal(res$mean, mean(x_nomiss))
  expect_equal(res$sd, sd(x_nomiss))
  expect_equal(res$min, min(x_nomiss))
  expect_equal(res$max, max(x_nomiss))
  expect_equal(res$n_total, length(x_nomiss))
  expect_equal(res$n_na, sum(is.na(D$x)))
})

test_that("local moments suppressed when cohort below privacyLevel", {
  D <- data.frame(tiny = c(1, 2))  # only 2 observations
  old_opt <- getOption("datashield.privacyLevel", 5L)
  options(datashield.privacyLevel = 5L)
  on.exit(options(datashield.privacyLevel = old_opt), add = TRUE)

  res <- dsvertLocalMomentsDS("D", "tiny")
  expect_true(is.na(res$mean))
  expect_true(is.na(res$sd))
  expect_true(is.na(res$min))
  expect_true(is.na(res$max))
  expect_equal(res$n_total, 2L)
})

test_that("local moments errors on non-numeric variable", {
  D <- make_df()
  expect_error(dsvertLocalMomentsDS("D", "g"), "must be numeric")
})
