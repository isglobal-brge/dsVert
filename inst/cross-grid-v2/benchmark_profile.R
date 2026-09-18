# Small driver for the NONLINEAR PROFILE PROBE, not the fused grid benchmark.
args <- commandArgs(trailingOnly = TRUE)
root <- if (length(args)) normalizePath(args[[1]]) else normalizePath(".")
stopifnot(file.exists(file.path(root, "DESCRIPTION")))
setwd(file.path(root, "inst", "dsvert-mpc"))
status <- system2("go", c("test", "-run", shQuote("^$"), "-bench",
                         shQuote("^BenchmarkCrossGridPWV2Protocol$"),
                         "-benchtime=3x", "-count=1"))
quit(status = status)
