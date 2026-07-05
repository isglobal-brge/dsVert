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
  # n / n_na are release-safe totals (not per-cell), so suppression does not
  # affect them; suppress + server-enabled silent suppression avoids the
  # small-cell release refusal.
  old <- options(dsvert.allow_silent_small_cells = TRUE)
  on.exit(options(old), add = TRUE)
  res <- dsvertContingencyDS("D", "sex", "smoke",
                              suppress_small_cells = TRUE,
                              fail_on_small_cells = FALSE)
  expect_equal(res$n, 50L - 5L)  # 5 distinct rows have NA
  expect_equal(res$n_na, 5L)
})

test_that("contingency refuses and suppresses small cells when privacyLevel active", {
  D <- make_cat_df(n = 50, seed = 1)
  # Expected raw table computed client-side (the server refuses to release raw
  # small cells, so we cannot fetch them; a sparse 2x4 table has cells below 5).
  tab_raw <- unclass(table(D$sex, D$stage))
  if (!any(tab_raw > 0L & tab_raw < 5L)) {
    skip("no small cells on this fixture")
  }
  old <- options(dsvert.allow_silent_small_cells = TRUE)
  on.exit(options(old), add = TRUE)
  # Server-authoritative refusal: raw release of a small-cell table is denied.
  expect_error(
    dsvertContingencyDS("D", "sex", "stage",
                        suppress_small_cells = FALSE),
    "refusing to release counts")
  expect_error(
    dsvertContingencyDS("D", "sex", "stage",
                        suppress_small_cells = TRUE),
    "refusing to release counts")

  # With suppression AND fail-open, small cells are zeroed and no positive
  # released cell is below the privacy floor.
  res_sup <- dsvertContingencyDS("D", "sex", "stage",
                                 suppress_small_cells = TRUE,
                                 fail_on_small_cells = FALSE)
  pl <- getOption("datashield.privacyLevel", 5L)
  expect_false(any(res_sup$counts > 0L & res_sup$counts < pl))
})

test_that("contingency errors on invalid input", {
  D <- make_cat_df()
  expect_error(dsvertContingencyDS("D", "sex", "sex"), "must differ")
  expect_error(dsvertContingencyDS("D", "nope", "sex"),
               "'nope' not found")
})
