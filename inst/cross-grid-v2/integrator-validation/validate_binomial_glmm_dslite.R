#!/usr/bin/env Rscript
# Signed staged GH5 variance grid: two beta vectors x variances {0, 1/4}.
Sys.setenv(DSVERT_GRID_VALIDATION_FAMILY = "binomial_glmm")
args <- commandArgs(trailingOnly = TRUE)
root <- normalizePath(if (length(args)) args[[1]] else "..")
source(file.path(root, "integrator-validation/validate_structured_dslite.R"))
