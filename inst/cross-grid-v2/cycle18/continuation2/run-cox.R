r <- testthat::test_local("dsVert", filter = "^crossgrid-cox$", stop_on_failure = FALSE)
saveRDS(r, "integrator-evidence/cycle18-20260920/continuation2/cox-sidecar-r3.rds")
d <- as.data.frame(r)
d <- d[!vapply(d, is.list, logical(1L))]
write.csv(d, "integrator-evidence/cycle18-20260920/continuation2/cox-sidecar-r3.csv", row.names = FALSE)
if (any(d$failed > 0 | d$error | d$warning > 0 | d$skipped)) quit(status = 1)
