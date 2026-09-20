#!/usr/bin/env Rscript
# Independent exact integers for the public synthetic release fixture only.
# No custodians, identity keys, transport, protected source or DP draw is used.
args <- commandArgs(TRUE)
stopifnot(length(args) %in% c(3L, 4L))
root <- normalizePath(args[[1L]])
family <- args[[2L]]
output <- args[[3L]]
n <- if (length(args) == 4L) as.integer(args[[4L]]) else 2000L
stopifnot(family %in% c("binomial_gee", "poisson_gee"), n %in% c(4L, 2000L),
  !file.exists(output))
server <- file.path(root, "dsVert")
client <- file.path(root, "dsVertClient")
pkgload::load_all(server, quiet = TRUE)
pkgload::load_all(client, quiet = TRUE)
sf <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
cf <- function(name) get(name, asNamespace("dsVertClient"), inherits = FALSE)
p <- 3L; instance <- 1L; B <- 4L; C <- n / B
set.seed(20260918 + instance)
x <- matrix(sample(0:16, n * p, replace = TRUE) / 16, n, p)
truth <- c(0, rep(1 / 32, p))
eta <- drop(cbind(1, x) %*% truth)
maximum <- if (family == "poisson_gee") 4 else 1
y <- if (family == "poisson_gee") pmin(maximum, rpois(n, exp(eta))) else
  rbinom(n, 1, plogis(eta))
cluster <- sprintf("cluster-%05d", ceiling(seq_len(n) / B))
# Consume the same fixture RNG sequence as the real harness, although neither
# time nor event contributes to a GEE coordinate.
time <- sample(seq(.25, 20, by = .25), n, replace = TRUE)
event <- rbinom(n, 1, .7)
beta <- lapply(c(0, .25), function(offset)
  truth + c(offset / 2 + (instance - 1) / 1024, rep(0, p)))
beta <- beta[order(vapply(beta, function(value)
  cf(".dsvert_joint_dp_client_json")(as.list(value)), character(1L)), method = "radix")]
grouping <- list(max_patients_per_cluster = B, cluster_capacity = C)
parameters <- list(correlation = "independence", rho = 0, score_clip = 1,
  composition = "staged_fixed_rho_v1")
numeric <- sf(".dsvert_dp_grouped_cross_numeric")(family, grouping, parameters)
stopifnot(identical(numeric,
  cf(".dsvert_dp_grouped_grid_cross_numeric")(family, grouping, parameters)))
sensitivity <- sf(".dsvert_dp_grouped_cross_sensitivity")(beta, family, maximum,
  16L, grouping, parameters, "add_remove_patient", numeric)
stopifnot(identical(sensitivity,
  cf(".dsvert_dp_grouped_grid_cross_sensitivity")(beta, family, maximum,
    16L, grouping, parameters, "add_remove_patient", numeric)))
spec <- list(family = family, beta_grid = beta, numeric_grid_bits = 16L,
  grouping = grouping, parameters = parameters, numeric_contract = numeric,
  sensitivity = sensitivity)
source(file.path(server, "inst/cross-grid-v2/integrator-validation/structured_integer_oracle.R"))
started <- proc.time()[["elapsed"]]
exact <- structured_integer_oracle(server, client, spec, x, y, cluster, time, event)
stopifnot(length(exact) == 42L, all(grepl("^[0-9]+$", exact)))
bytes <- charToRaw(paste0(paste(c(as.character(n), exact), collapse = "\n"), "\n"))
topologies <- lapply(c(2L, 3L, 5L), function(K) {
  peers <- paste0("site_", letters[seq_len(K)])
  covariate_owners <- if (K == 2L) 1L else seq.int(3L, K)
  allocation <- covariate_owners[1L + floor((seq_len(p)-1L) * length(covariate_owners) / p)]
  predictors <- paste0(peers[allocation], "$x", seq_len(p))
  stopifnot(identical(predictors, sort(predictors, method = "radix")))
  list(K = K, predictor_order = as.list(predictors), computation_peers = list("site_a", "site_b"))
})
source_paths <- c("inst/cross-grid-v2/integrator-validation/structured_integer_oracle.R",
  "tests/testthat/helper-cross-grid-integer.R", "tests/testthat/helper-grouped-integer.R",
  "tests/testthat/helper-grouped-lmm-stats-integer.R",
  "tests/testthat/helper-grouped-gee-whitening-integer.R", "R/crossgrid_grouped.R",
  "inst/certificates/grouped_pwlinear_q16_v1.json",
  "inst/certificates/grouped_gee_fixed_rho_staged_v1.json")
hashes <- setNames(lapply(source_paths, function(path)
  digest::digest(file = file.path(server, path), algo = "sha256")), paste0("dsVert/", source_paths))
hashes[["dsVertClient/R/dp_grouped_grid_cross_contract.R"]] <- digest::digest(
  file = file.path(client, "R/dp_grouped_grid_cross_contract.R"), algo = "sha256")
hashes[["dsVertClient/tests/testthat/helper-cox-grid-integer.R"]] <- digest::digest(
  file = file.path(client, "tests/testthat/helper-cox-grid-integer.R"), algo = "sha256")
record <- list(family = family, n = n, p = p, grid = 2L, candidates = 2L,
  clusters = C, slots = B, numeric_grid_bits = 16L, coordinate_count = 42L,
  instance = instance, fixture_seed = 20260918 + instance,
  oracle_only = TRUE, real_authenticated_release = FALSE,
  scope = "public synthetic exact-statistic commitment; no DP draw or protected source",
  working_correlation = parameters, beta_grid = beta, topologies = topologies,
  topology_hash_invariance = "K changes only authenticated owner labels; ordered x,y,beta and statistic are identical",
  source_file_sha256 = hashes,
  oracle_program_sha256 = digest::digest(file = sub("^--file=", "",
    grep("^--file=", commandArgs(FALSE), value = TRUE)[[1L]]), algo = "sha256"),
  exact = as.list(exact),
  elapsed_seconds = proc.time()[["elapsed"]] - started,
  oracle_hash_scope = "UTF-8 count then exact integer coordinates, LF terminated; excludes sticky noise",
  expected_oracle_sha256 = digest::digest(bytes, algo = "sha256", serialize = FALSE))
writeLines(jsonlite::toJSON(record, auto_unbox = TRUE, digits = NA), output)
cat("GEE_PUBLIC_SYNTHETIC_ORACLE_COMMITMENT", family, n,
  record$expected_oracle_sha256, record$elapsed_seconds, "seconds\n")
