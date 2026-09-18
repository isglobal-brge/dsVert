# Development benchmark of certified-cap source/loss batches, not full releases.
# From dsVert: Rscript inst/cross-grid-v2/benchmark_fused_batch.R .
run <- function(root) {
  old <- setwd(file.path(normalizePath(root, mustWork = TRUE), "inst", "dsvert-mpc"))
  on.exit(setwd(old), add = TRUE)
  status <- system2("go", c("test", "-run", shQuote("^$"), "-bench",
    shQuote("^BenchmarkCrossGridFusedBatch$"), "-benchtime=1x", "-count=1", "-timeout=0"))
  if (!identical(status, 0L)) stop("Fused batch benchmark failed.", call. = FALSE)
  invisible(status)
}
args <- commandArgs(trailingOnly = TRUE)
if (length(args) > 1L) stop("Expected at most one package-root argument.", call. = FALSE)
run(if (length(args)) args[[1L]] else ".")
