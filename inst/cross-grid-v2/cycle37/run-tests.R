args <- commandArgs(TRUE)
root <- normalizePath(args[[1]])
out <- normalizePath(args[[2]])
pkgload::load_all(file.path(root, "dsVert"), quiet = TRUE)
Sys.setenv(NOT_CRAN = "true", DSVERT_COX_STAGED_TEST_BINARY = file.path(root, "dsVert/inst/bin/darwin-arm64/dsvert-mpc"))
options(dsvert.mpc_binary = Sys.getenv("DSVERT_COX_STAGED_TEST_BINARY"))
env <- new.env(parent = asNamespace("dsVert"))
for (path in list.files(file.path(root, "dsVert/tests/testthat"), pattern = "^helper.*\\.R$", full.names = TRUE)) sys.source(path, env)
files <- c("test-crossgrid-cox.R", "test-crossgrid-lmm-schema-cache.R", "test-crossgrid-lmm-sampler-admission.R", "test-crossgrid-lmm-staged-lifecycle.R", "test-crossgrid-glmm-staged-lifecycle.R", "test-crossgrid-poisson-glmm-staged-lifecycle.R", "test-dp-synopsis-execution-safety.R", "test-dp-synopsis-exact-gc.R", "test-crossgrid-glmm-gaussian-preflight.R")
if (length(args) > 2L) files <- args[-c(1L, 2L)]
if (nzchar(Sys.getenv("DSVERT_TEST_DESCRIPTION"))) {
  selected <- Sys.getenv("DSVERT_TEST_DESCRIPTION")
  env$test_that <- function(desc, code) {
    if (identical(desc, selected)) testthat::test_that(desc, code)
  }
}
for (name in files) {
 result <- testthat::test_file(file.path(root, "dsVert/tests/testthat", name), env = env, reporter = "summary")
 frame <- as.data.frame(result)
 write.csv(frame[setdiff(names(frame), "result")], file.path(out, paste0(name, ".csv")), row.names = FALSE)
 stopifnot(all(frame$failed == 0), all(!frame$error), all(frame$warning == 0), all(frame$skipped == 0))
}
