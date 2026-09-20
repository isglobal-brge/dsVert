args <- commandArgs(TRUE)
root <- normalizePath(args[[1]])
out <- normalizePath(args[[2]])
pkgload::load_all(file.path(root, "dsVert"), quiet = TRUE)
pkgload::load_all(file.path(root, "dsVertClient"), quiet = TRUE)
env <- new.env(parent = asNamespace("dsVertClient"))
for (path in list.files(file.path(root, "dsVertClient/tests/testthat"), pattern = "^helper.*\\.R$", full.names = TRUE)) sys.source(path, env)
files <- c("test-dp-cox-cross-public-evidence.R", "test-dp-cox-grid-cross.R", "test-dp-lmm-cross-public-release.R")
for (file in files) {
  result <- testthat::test_file(file.path(root, "dsVertClient/tests/testthat", file), env = env, reporter = "summary")
  frame <- as.data.frame(result)
  write.csv(frame[setdiff(names(frame), "result")], file.path(out, paste0(file, ".csv")), row.names = FALSE)
  stopifnot(all(frame$failed == 0), all(!frame$error), all(frame$warning == 0), all(frame$skipped == 0))
}
