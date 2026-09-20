# Whole synthetic Go kernel + joint-noise measurement, both families.
# From dsVert: Rscript inst/cross-grid-v2/benchmark_full.R 1000 5 16
args <- commandArgs(trailingOnly = TRUE)
if (!length(args) %in% 3:4) stop("Expected n, p, grid and optional package root.", call. = FALSE)
dimensions <- suppressWarnings(as.numeric(args[1:3]))
if (anyNA(dimensions) || !dimensions[1] %in% c(1000, 10000) ||
    !dimensions[2] %in% c(5, 10) || !dimensions[3] %in% c(16, 50)) {
  stop("Dimensions are outside the public benchmark matrix.", call. = FALSE)
}
root <- normalizePath(if (length(args) == 4L) args[4] else ".", mustWork = TRUE)
setwd(file.path(root, "inst", "dsvert-mpc"))
Sys.setenv(DSVERT_CROSS_FULL_MEASURE = "1", DSVERT_CROSS_N = dimensions[1],
  DSVERT_CROSS_P = dimensions[2], DSVERT_CROSS_GRID = dimensions[3],
  DSVERT_CROSS_WORKERS = Sys.getenv("DSVERT_CROSS_WORKERS", "4"),
  GOMAXPROCS = Sys.getenv("GOMAXPROCS", "8"))
status <- system2("go", c("test", "-run", shQuote("^TestCrossGridFullMeasurement$"),
  "-v", "-count=1", "-timeout=0"))
if (status != 0L) stop("Whole-workload benchmark failed.", call. = FALSE)
