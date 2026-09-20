root <- "/Users/david/Documents/GitHub/dsvert-crossowner"
setwd(root)
pkgload::load_all("dsVertClient", quiet = TRUE)
env <- new.env(parent = asNamespace("dsVertClient"))
for (path in list.files("dsVertClient/tests/testthat", "^helper.*[.]R$", full.names = TRUE)) {
  sys.source(path, env)
}
summary <- list()
for (name in c("test-capsule-method-inventory.R", "test-method-status.R",
    "test-dp-grouped-grid-cross-registry.R")) {
  result <- testthat::test_file(file.path("dsVertClient/tests/testthat", name),
    env = env, reporter = "summary")
  frame <- as.data.frame(result)
  write.csv(frame[, !vapply(frame, is.list, logical(1L))],
    file.path("integrator-evidence/cox-ultra/client-registry", paste0(name, ".csv")),
    row.names = FALSE)
  summary[[name]] <- colSums(frame[, c("nb", "failed", "skipped", "error", "warning", "passed")])
}
print(summary)
writeLines(jsonlite::toJSON(summary, auto_unbox = TRUE, pretty = TRUE),
  "integrator-evidence/cox-ultra/client-registry/summary.json")
stopifnot(all(vapply(summary, function(counts)
  counts[["failed"]] == 0 && counts[["error"]] == 0, logical(1L))))
