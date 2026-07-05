# Extracted from test-contingency.R:49

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
D <- make_cat_df(n = 50)
D$sex[c(1, 5, 10)] <- NA
D$smoke[c(5, 20, 30)] <- NA
res <- dsvertContingencyDS("D", "sex", "smoke",
                              suppress_small_cells = TRUE,
                              fail_on_small_cells = FALSE)
