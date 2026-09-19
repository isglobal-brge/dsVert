args <- commandArgs(TRUE)
root <- normalizePath(if (length(args)) args[[1]] else ".")
server_dir <- file.path(root, "dsVert"); client_dir <- file.path(root, "dsVertClient")
pkgload::load_all(server_dir, quiet = TRUE)
pkgload::load_all(client_dir, quiet = TRUE)
source(file.path(root, "integrator-validation/structured_integer_oracle.R"))
e <- new.env(parent = asNamespace("dsVert"))
for (file in c("helper-cross-grid-integer.R", "helper-grouped-integer.R", "helper-grouped-contract.R"))
  sys.source(file.path(server_dir, "tests/testthat", file), e)
f50 <- function(v) sprintf("%.0f", round(v*2^50))
q64 <- function(v) e$.cross_format(e$.cross_shift_left(e$.cross_small(round(v*65536)), 48))
x <- matrix(c(0, .25, .5, 1, .75, 0, 1, .5), ncol = 1)
cluster <- rep(c("a", "b"), each = 4)
for (family in c("lmm", "binomial_glmm", "poisson_glmm", "binomial_gee", "poisson_gee")) {
 f <- e$.grouped_contract_fixture(family, "exchangeable")
 spec <- f$contract$spec
 y <- if (family == "lmm") c(.25, .5, 1, .75, 0, 1, .5, .25) else
   if (startsWith(family, "poisson")) c(0, 1, 3, 4, 2, 1, 0, 3) else c(0, 1, 1, 0, 1, 0, 1, 0)
 observed <- as.numeric(structured_integer_oracle(server_dir, client_dir, spec, x, y, cluster, NULL, NULL))
 expected <- unlist(lapply(seq_along(spec$beta_grid), function(j) {
  beta <- unlist(spec$beta_grid[[j]])
  cap <- unlist(spec$sensitivity$candidate_bounds[[j]]$per_cluster_caps)
  shift <- unlist(spec$sensitivity$candidate_bounds[[j]]$coordinate_shifts)
  values <- lapply(c("a", "b"), function(c) {
   idx <- which(cluster == c)
   request <- list(Eta = as.list(vapply(beta[1]+beta[2]*x[idx,1], q64, character(1))),
     Live = as.list(rep(1, 4)), Outcome = as.list(y[idx]))
   if (family == "lmm") {
    request$Family <- "lmm_stats"; request$Outcome <- NULL
    request$Beta <- as.list(f50(beta))
    request$Features <- lapply(idx, function(i) as.list(f50(c(1, x[i,1], y[i]))))
    request$Sigma <- q64(1); request$Tau <- q64(.25)
    request$LMM <- list(Slots = 4, GridBits = 16, ResidualCap = 2, OutputCap = cap[1])
   } else if (grepl("_glmm$", family)) {
    request$Family <- "glmm"
    request$GLMM <- list(Family = sub("_glmm$", "", family), Rows = 4, OutputBits = 16, VarianceQ16 = 16384)
   } else {
    request$Family <- "gee_whitening"; request$ClusterCap <- cap[1]
    request$Features <- lapply(idx, function(i) list(f50(x[i,1])))
    request$GEE <- list(Slots = 4, Predictors = 1, GridBits = 16, Family = sub("_gee$", "", family),
      Correlation = "exchangeable", RhoQ16 = 16384, ScoreClipQ16 = 65536,
      RowLossCap = cap[1], BreadCap = cap[2]-shift[2], MaxOutcome = spec$max_outcome)
   }
   answer <- e$.grouped_go_reference(request)
   stopifnot(answer$Valid)
   value <- answer$Values
   if (family == "poisson_glmm") value <- pmax(0, pmin(cap[1],
     value - sum(c(0, 0, 45426, 117425, 208277)[y[idx]+1L]) + 8*65536))
   value
  })
  Reduce(`+`, values)
 }), use.names = FALSE)
 stopifnot(identical(observed, as.numeric(expected)))
 cat("STRUCTURED_INDEPENDENT_INTEGER_EQUAL", family, length(observed), "\n")
}
# Independent Cox bridge uses its own Go profile evaluator and direct risk sets.
cenv <- new.env(parent = asNamespace("dsVertClient"))
sys.source(file.path(client_dir, "tests/testthat/helper-cox-grid-cross.R"), cenv)
f <- cenv$.cox_cross_client_fixture(capacity = 8)
spec <- f$contract$spec
x <- cbind(x[,1], rev(x[,1])); time <- c(1, 2, 2, 3, 4, 4, 5, 6); event <- c(1, 1, 0, 1, 1, 0, 1, 0)
observed <- as.numeric(structured_integer_oracle(server_dir, client_dir, spec, x, NULL, NULL, time, event))
beta <- do.call(rbind, lapply(spec$beta_grid, unlist))
request <- list(eta_q16 = unname(x %*% t(beta) * 65536), time = time, event = event,
 valid = rep(TRUE, 8), capacity = 8, numeric_grid_bits = 8, coefficient_grid = unname(beta))
input <- tempfile(); writeLines(jsonlite::toJSON(request, auto_unbox = TRUE, digits = NA), input)
result <- processx::run(Sys.getenv("DSVERT_COX_TEST_BINARY"), "-test.run=^TestCoxGridCrossPlaintextCommand$",
 stdin = input, env = c(DSVERT_COX_PLAINTEXT_TEST = "1"))
answer <- jsonlite::fromJSON(result$stdout)
stopifnot(identical(observed, as.numeric(answer$loss_coordinates)))
cat("STRUCTURED_INDEPENDENT_INTEGER_EQUAL cox", length(observed), "\n")
