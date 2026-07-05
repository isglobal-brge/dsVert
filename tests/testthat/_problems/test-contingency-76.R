# Extracted from test-contingency.R:76

# prequel ----------------------------------------------------------------------
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

# test -------------------------------------------------------------------------
D <- make_cat_df(n = 50, seed = 1)
tab_raw <- unclass(table(D$sex, D$stage))
if (!any(tab_raw > 0L & tab_raw < 5L)) {
    skip("no small cells on this fixture")
  }
expect_error(
    dsvertContingencyDS("D", "sex", "stage",
                        suppress_small_cells = FALSE),
    "refusing to release counts")
expect_error(
    dsvertContingencyDS("D", "sex", "stage",
                        suppress_small_cells = TRUE),
    "refusing to release counts")
res_sup <- dsvertContingencyDS("D", "sex", "stage",
                                 suppress_small_cells = TRUE,
                                 fail_on_small_cells = FALSE)
