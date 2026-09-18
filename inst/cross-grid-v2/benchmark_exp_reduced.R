# Binomial and range-reduced Poisson nonlinear components, NOT the complete n,p,grid release matrix.
args <- commandArgs(trailingOnly = TRUE)
root <- if (length(args)) normalizePath(args[[1]]) else normalizePath(".")
stopifnot(file.exists(file.path(root, "DESCRIPTION")))
setwd(file.path(root, "inst", "dsvert-mpc"))
status <- system2("go", c("test", "-run", shQuote("^$"), "-bench",
                         shQuote("^BenchmarkCrossGrid(ExpReducedV2Protocol|BinomialV2BatchProtocol)$"),
                         "-benchtime=3x", "-count=1"))
quit(status = status)
