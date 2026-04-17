# Tests for dsvertContingencyDS.

library(testthat)

make_cat_df <- function(seed = 42, n = 100) {
  set.seed(seed)
  data.frame(
    sex = sample(c("F", "M"), n, replace = TRUE),
    smoke = sample(c("yes", "no"), n, replace = TRUE, prob = c(0.3, 0.7)),
    stage = sample(c("I", "II", "III", "IV"), n, replace = TRUE),
    age = rnorm(n, 60, 10),
    stringsAsFactors = FALSE)
}

test_that("contingency counts match base R table()", {
  D <- make_cat_df()
  res <- dsvertContingencyDS("D", "sex", "smoke",
                              suppress_small_cells = FALSE)

  ref <- table(factor(D$sex), factor(D$smoke))
  ref_mat <- unname(as.matrix(ref))
  mode(ref_mat) <- "integer"

  expect_equal(res$counts, ref_mat)
  expect_equal(res$row_levels, levels(factor(D$sex)))
  expect_equal(res$col_levels, levels(factor(D$smoke)))
  expect_equal(res$row_margins, as.integer(rowSums(ref_mat)))
  expect_equal(res$col_margins, as.integer(colSums(ref_mat)))
  expect_equal(res$n, sum(ref_mat))
  expect_equal(res$n_na, 0L)
})

test_that("contingency handles 2x4 tables correctly", {
  D <- make_cat_df(n = 200)
  res <- dsvertContingencyDS("D", "sex", "stage",
                              suppress_small_cells = FALSE)
  expect_equal(dim(res$counts), c(2L, 4L))
  expect_equal(sum(res$counts), 200L)
})

test_that("contingency drops rows with missingness in either variable", {
  D <- make_cat_df(n = 50)
  D$sex[c(1, 5, 10)] <- NA
  D$smoke[c(5, 20, 30)] <- NA  # row 5 is NA in both
  res <- dsvertContingencyDS("D", "sex", "smoke",
                              suppress_small_cells = FALSE)
  expect_equal(res$n, 50L - 5L)  # 5 distinct rows have NA
  expect_equal(res$n_na, 5L)
})

test_that("contingency suppresses small cells when privacyLevel active", {
  D <- make_cat_df(n = 50, seed = 1)
  # Make a sparse 2x4 table so some cells drop below 5
  res_raw <- dsvertContingencyDS("D", "sex", "stage",
                                 suppress_small_cells = FALSE)
  if (!any(res_raw$counts > 0L & res_raw$counts < 5L)) {
    skip("no small cells on this fixture")
  }
  res_sup <- dsvertContingencyDS("D", "sex", "stage",
                                 suppress_small_cells = TRUE)
  for (i in seq_len(nrow(res_raw$counts))) {
    for (j in seq_len(ncol(res_raw$counts))) {
      if (res_raw$counts[i, j] > 0L && res_raw$counts[i, j] < 5L) {
        expect_equal(res_sup$counts[i, j], 0L)
      } else {
        expect_equal(res_sup$counts[i, j], res_raw$counts[i, j])
      }
    }
  }
})

test_that("contingency errors on invalid input", {
  D <- make_cat_df()
  expect_error(dsvertContingencyDS("D", "sex", "sex"), "must differ")
  expect_error(dsvertContingencyDS("D", "nope", "sex"),
               "'nope' not found")
})
