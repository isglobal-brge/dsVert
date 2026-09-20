root <- normalizePath(commandArgs(TRUE)[[1L]])
pkgload::load_all(file.path(root, "dsVert"), quiet = TRUE)
Sys.setenv(DSVERT_COX_STAGED_TEST_BINARY = dsVert:::.findMpcBinary())
env <- new.env(parent = asNamespace("dsVert"))
for (path in list.files(file.path(root, "dsVert/tests/testthat"),
    "^helper.*[.]R$", full.names = TRUE)) sys.source(path, env)
env$test_that <- function(desc, code) {
  if (identical(desc, "Cox worker preparation authenticates the owner route and cold source before native handoff")) {
    testthat::test_that(desc, code)
  }
}
for (expression in parse(file.path(root, "dsVert/tests/testthat/test-crossgrid-cox.R"))) {
  eval(expression, env)
}
