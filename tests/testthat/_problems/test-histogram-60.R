# Extracted from test-histogram.R:60

# prequel ----------------------------------------------------------------------
library(testthat)
make_df <- function(seed = 42) {
  set.seed(seed)
  data.frame(
    x = c(rnorm(50, mean = 0, sd = 1), NA, NA),
    y = c(rpois(52, lambda = 3)),
    g = factor(rep(c("a", "b"), length.out = 52))
  )
}

# test -------------------------------------------------------------------------
D <- make_df()
edges <- c(-5, -2, -1, 0, 1, 2, 5)
cl <- as.integer(table(cut(D$x[!is.na(D$x)], breaks = edges,
                             include.lowest = TRUE)))
if (!any(cl > 0L & cl < 5L)) {
    skip("no small cells on this fixture; adjust seed or edges")
  }
expect_error(
    dsvertHistogramDS("D", "x", edges, suppress_small_cells = FALSE),
    "refusing to release counts")
expect_error(
    dsvertHistogramDS("D", "x", edges, suppress_small_cells = TRUE),
    "refusing to release counts")
suppressed <- dsvertHistogramDS("D", "x", edges,
                                  suppress_small_cells = TRUE,
                                  fail_on_small_cells = FALSE)
