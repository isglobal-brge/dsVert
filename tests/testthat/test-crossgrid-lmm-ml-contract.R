test_that("LMM ML contracts sign covariance-major candidates and patient caps", {
  f <- .grouped_contract_fixture("lmm")
  raw <- f$raw
  raw$parameters <- list(objective = "ml", variance_grid = list(
    list(residual_variance = .25, random_intercept_variance = 0),
    list(residual_variance = 1, random_intercept_variance = .25)))
  spec <- .dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated)
  count <- length(spec$beta_grid)
  expect_length(spec$candidate_grid, 2 * count)
  expect_equal(vapply(spec$candidate_grid, `[[`, numeric(1), "variance_index"),
    rep(1:2, each = count))
  expect_equal(vapply(spec$candidate_grid, `[[`, numeric(1), "beta_index"), rep(seq_len(count), 2))
  caps <- unlist(spec$sensitivity$per_cluster_caps)
  expect_length(caps, 2 * count)
  expect_equal(spec$sensitivity$raw_l1_sensitivity, sum(caps))
  expect_equal(unlist(spec$sensitivity$maximum_coordinates), spec$grouping$cluster_capacity * caps)
  expect_match(spec$numeric_contract$certificate_sha256, "^[0-9a-f]{64}$")
  expect_identical(spec$numeric_contract$profile, "grouped-lmm-ml-variance-f264-q64-log-up-v1")
  expect_false(spec$numeric_contract$full_likelihood_value)
  artifact <- .dsvert_dp_grouped_cross_artifact(spec)
  expect_equal(artifact$coordinate_count, 2 * count)
  unsigned <- list(version = f$unsigned$version, spec = spec, artifact = artifact,
    source_contract = .dsvert_dp_grouped_cross_source_contract(spec, artifact))
  validate <- function(x) .dsvert_dp_grouped_cross_contract_validate(f$sign(x), f$policy, f$schema)
  expect_identical(validate(unsigned)$spec$parameters$objective, "ml")
  for (mutate in list(
    function(x) { x$spec$candidate_order <- rev(x$spec$candidate_order); x },
    function(x) { x$spec$candidate_grid[[1]]$variance_index <- 2; x },
    function(x) { x$spec$numeric_contract$certificate_sha256 <- strrep("0", 64); x },
    function(x) { x$spec$numeric_contract$logdet_addition <- "after_clamp"; x },
    function(x) { x$spec$sensitivity$per_cluster_caps[[1]] <- 1; x })) {
    expect_error(validate(mutate(unsigned)), class = "dsvert_dp_public_failure")
  }
  source <- .dsvert_dp_lmm_cross_source_plan(unsigned, strrep("1", 64))
  expect_identical(source$Objective, "ml")
  expect_length(source$VarianceGrid, 2)
  expect_length(source$Beta, count)
  expect_length(source$Caps, 2 * count)
  expect_identical(source$Numeric$Sigma2Q64, "4611686018427387904")
  expect_identical(source$VarianceGrid[[2]]$Tau2Q64, "4611686018427387904")
  rows <- spec$grouping$padded_slots
  encode <- function(value) gsub("[\r\n]", "", jsonlite::base64_enc(value))
  block <- function(columns) list(Share = encode(raw(16 * rows * columns)),
    Validity = encode(as.raw(rep(1, rows * columns))))
  directory <- tempfile("lmm-ml-wire-")
  dir.create(directory, mode = "0700")
  on.exit(unlink(directory, recursive = TRUE), add = TRUE)
  wire <- .callMpcTool("grouped-lmm-staged-prepare-v1", list(
    handoff = list(plan = source, numeric = block(length(spec$predictor_order)+1),
      metadata = block(length(spec$predictor_order)+3)),
    role = "garbler", session = "lmm-ml-signed-wire-test",
    authorities = as.list(c("authority-a", "authority-b")), semantic_key = strrep("2", 64),
    store_directory = normalizePath(directory), store_key = encode(as.raw(seq_len(32))),
    routing = list(labels = as.list(rep(0L, rows)), present = as.list(rep(FALSE, rows)))),
    simplify_output = FALSE)
  expect_equal(wire$vector_len, length(caps))
  expect_match(wire$stage_plan_digest, "^[0-9a-f]{64}$")
  native <- rawToChar(jsonlite::base64_dec(wire$worker_input))
  expect_match(native, '"Objective":"ml"', fixed = TRUE)
})

test_that("LMM ML rejects ambiguous covariance order and uncertified objectives", {
  f <- .grouped_contract_fixture("lmm")
  pair <- list(residual_variance = 1, random_intercept_variance = .25)
  other <- list(residual_variance = .25, random_intercept_variance = 0)
  for (parameters in list(
    list(objective = "reml", variance_grid = list(pair)),
    list(objective = "ml", variance_grid = list(pair, pair)),
    list(objective = "ml", variance_grid = list(pair, other)),
    list(objective = "ml", variance_grid = list(list(objective = "ml", variance_grid = list(pair)))),
    list(objective = "ml", variance_grid = list(list(residual_variance = .3, random_intercept_variance = 0))))) {
    raw <- f$raw; raw$parameters <- parameters
    expect_error(.dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated),
      class = "dsvert_dp_public_failure")
  }
})
