args <- commandArgs(TRUE)
root <- normalizePath(args[[1L]])
package <- args[[2L]]
state_parent <- file.path("/var/lib", paste0(basename(root), "-paired"))
dir.create(state_parent, recursive = TRUE, mode = "0700", showWarnings = FALSE)
Sys.setenv(NOT_CRAN = "true", PROCESSX_NOTIFY_OLD_SIGCHLD = "true",
  DSVERT_SERVER_SOURCE = file.path(root, "dsVert"),
  DSVERT_STATE_DIR = tempfile(paste0(package, "-"), tmpdir = state_parent))
dir.create(Sys.getenv("DSVERT_STATE_DIR"), mode = "0700")
setwd(root)
logs <- Sys.getenv("DSVERT_PAIRED_LOG_DIR", file.path(root, "logs"))
pkgload::load_all(if (package == "dsVert") "dsVertClient" else "dsVert", quiet = TRUE)
Sys.setenv(DSVERT_GROUPED_REFERENCE_BINARY = file.path(root, "logs/structured-oracle.test"),
  DSVERT_COX_TEST_BINARY = file.path(root, "logs/structured-oracle.test"))
testthat::set_max_fails(Inf)
result <- testthat::test_local(package, reporter = "summary", stop_on_failure = FALSE)
saveRDS(result, file.path(logs, paste0(package, "-paired.rds")))
summary <- as.data.frame(result)
write.csv(summary[setdiff(names(summary), "result")], file.path(logs, paste0(package, "-paired.csv")), row.names = FALSE)
stopifnot(nrow(summary) > 0L, !anyNA(summary[c("failed", "error")]), !any(summary$failed > 0 | summary$error))
cat("CYCLE16_PAIRED_PACKAGE_PASS", package, sum(summary$passed), "assertions;",
  sum(summary$skipped), "skips;", sum(summary$warning), "warnings; exclusions require review\n")
