args <- commandArgs(TRUE)
root <- normalizePath(args[[1L]])
out <- normalizePath(args[[2L]])
pkgload::load_all(file.path(root, "dsVert"), quiet = TRUE)
Sys.setenv(DSVERT_COX_STAGED_TEST_BINARY = dsVert:::.findMpcBinary())
env <- new.env(parent = asNamespace("dsVert"))
for (path in list.files(file.path(root, "dsVert/tests/testthat"),
    "^helper.*[.]R$", full.names = TRUE)) sys.source(path, env)
all_green <- TRUE
for (name in c("test-crossgrid-cox.R", "test-dp-cox-synopsis-schema.R",
    "test-dp-glm-grid-cross-contract.R")) {
  result <- testthat::test_file(file.path(root, "dsVert/tests/testthat", name),
    env = env, reporter = "summary")
  frame <- as.data.frame(result)
  write.csv(frame[, !vapply(frame, is.list, logical(1L))],
    file.path(out, paste0(name, ".csv")), row.names = FALSE)
  print(colSums(frame[, c("nb", "failed", "skipped", "error", "warning", "passed")]))
  all_green <- all_green && !any(frame$failed > 0 | frame$error | frame$skipped)
}
stopifnot(all_green)
