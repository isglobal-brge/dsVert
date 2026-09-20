#!/usr/bin/env Rscript
Sys.setenv(DSVERT_GRID_VALIDATION_FAMILY = "poisson_glmm")
args <- commandArgs(trailingOnly = TRUE)
root <- normalizePath(if (length(args)) args[[1]] else "..")
source(file.path(root, "integrator-validation/validate_structured_dslite.R"))
