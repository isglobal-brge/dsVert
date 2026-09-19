.lmm_signed_admission_fixture <- function(owners = 2L, large = FALSE) {
  f <- .grouped_contract_fixture("lmm", owners = owners)
  f$raw$beta_grid <- f$raw$beta_grid[1:2]
  f$raw$parameters <- list(objective = "ml", variance_grid = list(
    list(residual_variance = .25, random_intercept_variance = 0),
    list(residual_variance = 1, random_intercept_variance = .25)))
  if (large) {
    f$policy$unit_capacity <- 2000
    f$raw$grouping$cluster_capacity <- 500
  }
  spec <- .dsvert_dp_grouped_cross_spec(f$raw, f$policy, f$authenticated)
  artifact <- .dsvert_dp_grouped_cross_artifact(spec)
  f$contract <- f$sign(list(version = .DSVERT_DP_GROUPED_CROSS_VERSION,
    spec = spec, artifact = artifact,
    source_contract = .dsvert_dp_grouped_cross_source_contract(spec, artifact)))
  f
}

test_that("production admission rebuilds only the signed LMM ML profile", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .lmm_signed_admission_fixture(owners)
    value <- .dsvert_dp_glm_grid_profile_admit(f$contract, f$policy, f$schema)
    expect_identical(value$spec$family, "lmm")
    expect_identical(value$spec$numeric_contract$profile,
      "grouped-lmm-ml-variance-f264-q64-log-up-v1")
    expect_equal(value$artifact$coordinate_count, 4)
    expect_equal(unlist(value$artifact$candidate_order),
                 unlist(value$spec$candidate_order))
    expect_equal(vapply(value$spec$candidate_grid, `[[`, numeric(1), "variance_index"),
                 c(1, 1, 2, 2))
    for (mutate in list(
      function(x) { x$spec$numeric_contract$certificate_sha256 <- strrep("0", 64); x },
      function(x) { x$spec$candidate_order <- rev(x$spec$candidate_order); x },
      function(x) { x$spec$sensitivity$per_cluster_caps[[1]] <- 1; x })) {
      expect_error(.dsvert_dp_glm_grid_profile_admit(
        f$sign(mutate(f$contract)), f$policy, f$schema),
        class = "dsvert_dp_public_failure")
    }
  }
  for (family in .DSVERT_DP_GROUPED_CROSS_FAMILIES) {
    f <- .grouped_contract_fixture(family)
    expect_error(.dsvert_dp_glm_grid_profile_admit(f$contract, f$policy, f$schema),
                 class = "dsvert_dp_public_failure")
  }
})

test_that("LMM discovery and workload admission retain private grouping", {
  f <- .lmm_signed_admission_fixture()
  raw <- list(version = "lmm_grid_cross_v1", dataset = "cohort", contract = f$contract)
  descriptor <- .dsvert_dp_capsule_gaussian_spec(f$policy, "grouped", list(grouped = raw))
  expect_identical(descriptor$kind, "lmm_grid_cross")
  owner_policy <- f$policy
  owner_policy$peer_name <- "peer_b"
  owner_policy$capsule_workload_specs <- list(describe = list(), survival = list(),
    gaussian = list(grouped = raw), vertical_cross = list())
  fragment <- .dsvert_dp_capsule_manifest_local_specs(owner_policy,
    mapping = list(datasets = list(cohort = "y")))$gaussian$grouped
  expect_named(fragment, c("contract", "dataset", "version"))
  expect_identical(fragment$contract,
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(f$contract)))
  workload <- list(version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION,
    describe = list(), survival = list(), gaussian = list(grouped = list(
      owner_peer = "peer_b", spec = fragment)), vertical_cross = list())
  decoded <- .dsvert_dp_capsule_manifest_workload_contract(
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(workload)),
    f$policy, .local_exact = FALSE)
  expect_named(decoded$specs$gaussian$grouped, c("contract", "dataset", "version"))
  expect_identical(.dsvert_dp_canonical_query_value(decoded$specs$gaussian$grouped),
                   .dsvert_dp_canonical_query_value(fragment))
  policy <- f$policy
  policy$domain <- "lmm-admission-test"
  policy$cohort_id <- "grouped-cohort"
  policy$peer_name <- "peer_a"
  policy$peer_count <- 2L
  policy$global_total_epsilon <- 4
  policy$global_total_delta <- 2^-100
  policy$lifetime_max_distinct_capsules <- 2L
  policy$patient_column <- "id"
  policy$max_records_per_unit <- 1L
  policy$overflow_policy <- "reject_snapshot"
  policy$contingency_unit_aggregation_policy <- "consistent_cell_else_exclude_v1"
  policy$numeric_bounds <- list(x = c(0, 1))
  policy$categorical_levels <- list(cluster = c("c1", "c2"))
  policy$capsule_workload_scope <- list(mode = "catalog_v1",
    numeric_moments = character(), categorical_marginals = character(),
    categorical_pairs = list(), correlations = list())
  policy$datasets <- list(cohort = list(id = "cohort", version = "v1",
    snapshot_sha256 = NULL, alignment_manifest_hash = NULL,
    alignment_manifest_version = 1L))
  policy$noise_root <- list(epoch = 1, key_id = "test-root")
  policy$ledger_path <- tempfile("lmm-admission-")
  manifest <- .dsvert_dp_capsule_workload_manifest(policy,
    f$schema$logical_snapshot, f$schema, describe_specs = list(),
    survival_specs = list(), vertical_cross_specs = list(),
    gaussian_specs = list(grouped = raw))
  manifest_json <- .dsvert_dp_canonical_json(manifest)
  expect_identical(.dsvert_dp_canonical_json(.dsvert_dp_capsule_source_manifest(manifest_json)),
                   manifest_json)
  artifact <- .dsvert_dp_glm_grid_cross_artifacts(manifest)$grouped
  expect_identical(.dsvert_dp_canonical_query_value(artifact),
    .dsvert_dp_canonical_query_value(.dsvert_dp_grouped_cross_workload_artifact(f$contract)))
  expect_identical(artifact$transcript$producer, "dp.lmm-grid-cross.v1")
  expect_identical(artifact$outcome_encoding, list(kind = "fixed_point", q = 50))
  expect_length(manifest$workload$families$categorical_marginals$artifacts, 0)
  expect_equal(artifact$source_raw_l1_sensitivity, f$contract$spec$sensitivity$raw_l1_sensitivity)
  expect_equal(unlist(artifact$statistic_maximum),
               unlist(f$contract$spec$sensitivity$maximum_coordinates))
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(manifest = manifest,
    layout = .dsvert_dp_capsule_coordinate_layout(manifest)))
  expect_identical(lattice$scale_shifts, c(16L, rep(0L, 4L)))
  expect_identical(lattice$raw_upper_bounds, c(as.character(policy$unit_capacity),
    sprintf("%.0f", unlist(f$contract$spec$sensitivity$maximum_coordinates))))
  expect_equal(as.numeric(lattice$raw_upper_bounds) * 2^lattice$scale_shifts,
    c(policy$unit_capacity * 2^16,
      unlist(f$contract$spec$sensitivity$maximum_coordinates)))
  versions <- paste0("bounded-", gsub("_", "-", .DSVERT_DP_GROUPED_CROSS_FAMILIES),
                     "-cross-grid-v1")
  catalog <- list(workload = list(families = list(gaussian_models = list(
    artifacts = setNames(lapply(versions, function(v) list(version = v)),
                         .DSVERT_DP_GROUPED_CROSS_FAMILIES)))))
  expect_named(.dsvert_dp_glm_grid_cross_artifacts(catalog), c("lmm", "binomial_glmm"))
})

test_that("n2000 admission binds only the exact LMM C500 B4 p3 J4 domain", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .lmm_signed_admission_fixture(owners, large = TRUE)
    value <- .dsvert_dp_glm_grid_profile_admit(f$contract, f$policy, f$schema)
    expect_identical(value$spec$grouping$capacity_profile,
                     "lmm-ml-n2000-c500-b4-p3-j4-v1")
    expect_equal(value$source_contract$private_layout$padded_units, 2000)
    expect_equal(value$artifact$coordinate_count, 4)
    expect_equal(unlist(value$spec$sensitivity$maximum_coordinates),
                 500 * unlist(value$spec$sensitivity$per_cluster_caps))
    changed <- f$contract
    changed$spec$grouping$capacity_profile <- "capacity-proven"
    expect_error(.dsvert_dp_glm_grid_profile_admit(f$sign(changed), f$policy, f$schema),
                 class = "dsvert_dp_public_failure")
  }
  f <- .lmm_signed_admission_fixture(large = TRUE)
  for (mutate in list(
    function(x) { x$raw$grouping$cluster_capacity <- 65; x },
    function(x) { x$raw$grouping$cluster_capacity <- 499; x },
    function(x) { x$raw$grouping$cluster_capacity <- 501; x },
    function(x) { x$raw$grouping$max_patients_per_cluster <- 5; x },
    function(x) { x$policy$unit_capacity <- 1999; x },
    function(x) { x$raw$parameters <- x$raw$parameters$variance_grid[[1]]; x },
    function(x) { x$raw$parameters$variance_grid[[3]] <-
      list(residual_variance = 2, random_intercept_variance = .25); x })) {
    changed <- mutate(f)
    expect_error(.dsvert_dp_grouped_cross_spec(
      changed$raw, changed$policy, changed$authenticated), class = "dsvert_dp_public_failure")
  }
  small <- .lmm_signed_admission_fixture()
  expect_null(small$contract$spec$grouping$capacity_profile)
  other <- .grouped_contract_fixture("binomial_glmm")
  other$raw$grouping$cluster_capacity <- 500
  expect_error(.dsvert_dp_grouped_cross_spec(other$raw, other$policy, other$authenticated),
               class = "dsvert_dp_public_failure")
})

test_that("single-candidate LMM workload projection survives manifest JSON decoding", {
  f <- .lmm_signed_admission_fixture()
  f$raw$beta_grid <- f$raw$beta_grid[1L]
  f$raw$parameters$variance_grid <- f$raw$parameters$variance_grid[1L]
  spec <- .dsvert_dp_grouped_cross_spec(f$raw, f$policy, f$authenticated)
  artifact <- .dsvert_dp_grouped_cross_artifact(spec)
  contract <- f$sign(list(version = .DSVERT_DP_GROUPED_CROSS_VERSION,
    spec = spec, artifact = artifact,
    source_contract = .dsvert_dp_grouped_cross_source_contract(spec, artifact)))
  projected <- .dsvert_dp_grouped_cross_workload_artifact(contract)
  expect_type(projected$participating_peers, "list")
  expect_type(projected$computation_peers, "list")
  encoded <- .dsvert_dp_canonical_json(projected)
  decoded <- jsonlite::fromJSON(encoded, simplifyVector = TRUE,
    simplifyDataFrame = FALSE, simplifyMatrix = FALSE)
  expect_identical(.dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(decoded)), encoded)
  expect_identical(projected$signed_contract,
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(contract)))
  expect_equal(unlist(projected$candidate_loss_bounds),
    unlist(spec$sensitivity$per_cluster_caps))
})

test_that("LMM source-only peers emit zero public losses without reading outcomes", {
  f <- .lmm_signed_admission_fixture(owners = 5L)
  artifact <- .dsvert_dp_grouped_cross_workload_artifact(f$contract)
  block <- list(family = "gaussian_models", dataset = "cohort", owner_peer = "peer_b",
    start = 1L, end = 4L, length = 4L, descriptor = artifact)
  contract <- list(identity = list(capsule_id = strrep("a", 64)),
    layout = list(coordinate_count = 4L, sha256 = strrep("b", 64), blocks = list(grouped = block)))
  manifest <- list(logical_snapshot = f$schema$logical_snapshot,
    workload = list(capsule_mechanism = list(source_context_hash = strrep("c", 64)),
      families = list(gaussian_models = list(artifacts = list(grouped = artifact)))))
  snapshots <- list(cohort = list(data = data.frame(id = "u1"),
    dataset = list(public = list(data_name = "cohort"), fingerprint = strrep("d", 64))))
  local_mocked_bindings(
    .dsvert_dp_capsule_materializer_manifest = function(...) contract,
    .dsvert_dp_capsule_resolved_snapshots = function(...) snapshots,
    .dsvert_dp_capsule_assert_signed_coordinate_bounds = function(...) invisible(TRUE),
    .dsvert_dp_bounded_numeric = function(...) stop("Unexpected plaintext numeric read"))
  for (peer in names(f$policy$peer_pinset)) {
    policy <- f$policy
    policy$peer_name <- peer
    value <- .dsvert_dp_capsule_materialize_local(policy, manifest, snapshots)
    expect_equal(value$values, rep(0, 4))
  }
})
