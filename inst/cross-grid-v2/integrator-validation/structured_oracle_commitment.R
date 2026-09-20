#!/usr/bin/env Rscript
# Public synthetic deterministic integers only: no source/release RPC or DP draw.
args <- commandArgs(TRUE)
root <- normalizePath(args[[1L]])
family <- args[[2L]]
owners <- as.integer(args[[3L]])
output <- args[[4L]]
stopifnot(family %in% c("lmm", "binomial_glmm", "poisson_glmm"), owners %in% c(2, 3, 5))
n <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_N", "2000"))
stopifnot(n %in% c(4L, 2000L))
predictors <- 3L; instance <- 1L
server <- file.path(root, "dsVert"); client <- file.path(root, "dsVertClient")
pkgload::load_all(server, quiet = TRUE)
e <- new.env(parent = asNamespace("dsVert"))
sys.source(file.path(server, "tests/testthat/helper-grouped-contract.R"), e)
f <- e$.grouped_contract_fixture(family, owners = owners)
sf <- function(name) get(name, asNamespace("dsVert"))
peers <- names(f$policy$peer_pinset)
keys <- setNames(lapply(seq_len(owners), function(i)
  sf(".callMpcTool")("derive-identity", list(seed = jsonlite::base64_enc(
    as.raw((seq_len(32) + 61L*i) %% 256L))))), peers)
sign_schema <- function(schema) {
  schema$signatures <- NULL
  schema$signatures <- lapply(keys, function(key) sf(".dsvert_relay_sign_message")(
    sf(".dsvert_dp_capsule_schema_message")(schema), key$identity_sk))
  schema
}
f$policy$unit_capacity <- n
covariate_owners <- if (owners == 2L) 1L else seq.int(3L, owners)
allocation <- covariate_owners[1L + floor((seq_len(predictors)-1L) * length(covariate_owners) / predictors)]
variables <- paste0("x", seq_len(predictors))
schema <- f$schema
schema$datasets$cohort$columns <- c(setNames(lapply(seq_len(predictors), function(j)
  list(kind = "numeric", owner_peer = peers[allocation[j]], lower = 0, upper = 1)), variables),
  schema$datasets$cohort$columns[c("y", "cluster")])
labels <- sprintf("cluster-%05d", seq_len(n / 4L))
schema$datasets$cohort$columns$cluster$levels <- labels
schema <- sign_schema(schema)
authenticated <- sf(".dsvert_dp_capsule_schema")(f$policy, schema$logical_snapshot,
  schema, sf(".dsvert_relay_verify_message"))
set.seed(20260918 + instance)
x <- matrix(sample(0:16, n * predictors, replace = TRUE) / 16, n, predictors)
truth <- c(0, rep(1 / 32, predictors))
eta <- drop(cbind(1, x) %*% truth)
y <- if (family == "lmm") sample(0:16, n, replace = TRUE) / 16 else
  if (family == "poisson_glmm") pmin(4, rpois(n, exp(eta))) else rbinom(n, 1, plogis(eta))
cluster <- labels[ceiling(seq_len(n) / 4L)]
time <- sample(seq(.25, 20, by = .25), n, replace = TRUE)
event <- rbinom(n, 1, .7)
raw <- f$raw
raw$predictor_order <- paste0(peers[allocation], "$", variables)
raw$beta_grid <- lapply(c(0, .25), function(offset)
  truth + c(offset / 2 + (instance - 1) / 1024, rep(0, predictors)))
raw$beta_grid <- raw$beta_grid[order(vapply(raw$beta_grid, function(b)
  sf(".dsvert_dp_canonical_json")(as.list(b)), character(1)), method = "radix")]
raw$grouping$cluster_capacity <- n / 4L
raw$parameters <- if (family == "lmm") list(objective = "ml", variance_grid = list(
  list(residual_variance = .5, random_intercept_variance = .25),
  list(residual_variance = 1, random_intercept_variance = .25))) else
  list(variance_grid = list(0, .25), quadrature = "gh5_fixed_v1")
spec <- sf(".dsvert_dp_grouped_cross_spec")(raw, f$policy, authenticated)
artifact <- sf(".dsvert_dp_grouped_cross_artifact")(spec)
contract <- f$sign(list(version = sf(".DSVERT_DP_GROUPED_CROSS_VERSION"), spec = spec,
  artifact = artifact, source_contract = sf(".dsvert_dp_grouped_cross_source_contract")(spec, artifact)))
sf(".dsvert_dp_grouped_cross_contract_validate")(contract, f$policy, schema) |> invisible()
source(file.path(server, "inst/cross-grid-v2/integrator-validation/structured_integer_oracle.R"))
exact <- structured_integer_oracle(server, client, spec, x, y, cluster, time, event)
bytes <- charToRaw(paste0(paste(c(as.character(n), exact), collapse = "\n"), "\n"))
heads <- if (file.exists(file.path(root, "frozen-source-manifest.json")))
  jsonlite::fromJSON(file.path(root, "frozen-source-manifest.json"))$repositories else
  setNames(lapply(c(server, client), function(repo)
    trimws(processx::run("git", c("-C", repo, "rev-parse", "HEAD"))$stdout)), c("dsVert", "dsVertClient"))
record <- list(source_commits = heads, family = family, owners = owners, n = n,
  p = predictors, grid = 2L, instance = instance, oracle_only = TRUE,
  scope = "signed synthetic exact-statistic commitment only; no DP selection or real release",
  exact = as.list(exact), expected_oracle_sha256 = digest::digest(bytes, algo = "sha256", serialize = FALSE))
writeLines(jsonlite::toJSON(record, auto_unbox = TRUE, digits = NA), output)
