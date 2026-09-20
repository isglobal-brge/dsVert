args <- commandArgs(TRUE)
root <- normalizePath(args[[1L]])
setwd(root)
Sys.setenv(DSVERT_SERVER_SOURCE = file.path(root, "dsVert"),
  DSVERT_GROUPED_REFERENCE_BINARY = file.path(root, "logs/structured-oracle.test"),
  DSVERT_COX_TEST_BINARY = file.path(root, "logs/structured-oracle.test"),
  DSVERT_GEE_TEST_BINARY = file.path(root, "dsVert/inst/bin/linux-amd64/dsvert-mpc"),
  NOT_CRAN = "true")
options(dsvert.mpc_binary = file.path(root, "dsVert/inst/bin/linux-amd64/dsvert-mpc"))
pkgload::load_all("dsVert", quiet = TRUE)
pkgload::load_all("dsVertClient", quiet = TRUE)
for (package in c("dsVert", "dsVertClient")) {
  Sys.setenv(DSVERT_STATE_DIR = tempfile(paste0(package, "-gee-focused-")))
  dir.create(Sys.getenv("DSVERT_STATE_DIR"), mode = "0700")
  filter <- if (package == "dsVert") "^crossgrid-gee" else "^dp-gee-staged"
  result <- testthat::test_local(package, filter = filter, reporter = "summary", stop_on_failure = FALSE)
  summary <- as.data.frame(result)
  write.csv(summary[setdiff(names(summary), "result")],
    file.path(root, "logs", paste0(package, "-gee-focused.csv")), row.names = FALSE)
  stopifnot(nrow(summary) > 0L, !anyNA(summary[c("failed", "error")]),
    !any(summary$failed > 0 | summary$error))
  cat("GEE_FOCUSED_PACKAGE_PASS", package, sum(summary$passed), "assertions;",
    sum(summary$skipped), "skips;", sum(summary$warning), "warnings\n")
}
