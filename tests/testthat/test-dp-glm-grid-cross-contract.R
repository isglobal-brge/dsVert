.cross_grid_contract_identities <- local({
  cached <- NULL
  function() {
    if (is.null(cached)) cached <<- stats::setNames(lapply(1:3, function(i) {
      .callMpcTool("derive-identity", list(seed = jsonlite::base64_enc(
        as.raw((seq_len(32) + 47L * i) %% 256L))))
    }), c("peer_a", "peer_b", "peer_c"))
    cached
  }
})

.cross_grid_contract_fixture <- function(family = "binomial", bits = 18,
                                         capacity = 2) {
  identities <- .cross_grid_contract_identities()
  pins <- vapply(identities, function(identity) {
    .dsvert_relay_normalize_identity_pk(identity$identity_pk)
  }, character(1L))
  policy <- list(
    peer_pinset = pins, peer_pinset_sha256 = .dsvert_joint_dp_hash(as.list(pins)),
    designated_noise_peers = c("peer_a", "peer_b"),
    unit_capacity = capacity, numeric_grid_bits = bits,
    adjacency = "add_remove_patient")
  maximum <- if (family == "binomial") 1 else 3
  snapshot <- list(logical_snapshot_id = "grid-cohort", version = "v1",
                   alignment_protocol_version = 1)
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = snapshot, peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = list(cohort = list(
      dataset_id = "cohort", dataset_version = "v1", schema_version = "v1",
      alignment_group = "aligned", patient_keys = list(
        peer_a = "id", peer_b = "id"),
      columns = list(
        x = list(kind = "numeric", owner_peer = "peer_a", lower = -2, upper = 4),
        z = list(kind = "numeric", owner_peer = "peer_b", lower = 0, upper = 10),
        y = list(kind = "numeric", owner_peer = "peer_a", lower = 0,
                 upper = maximum)))))
  schema$signatures <- lapply(identities, function(identity) {
    .dsvert_relay_sign_message(.dsvert_dp_capsule_schema_message(schema),
                               identity$identity_sk)
  })
  authenticated <- .dsvert_dp_capsule_schema(
    policy, snapshot, schema, .dsvert_relay_verify_message)
  raw <- list(
    version = paste0(family, "_grid_cross_v1"), analysis_id = "grid",
    dataset = "cohort", outcome = "peer_a$y",
    predictor_order = c("peer_a$x", "peer_b$z"),
    beta_grid = list(c(-1, 0.5, 1), c(0, 0, 0), c(1, -0.5, 0)),
    max_outcome = maximum,
    alignment = list(
      version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "aligned",
      public_alignment_contract_sha256 = .dsvert_joint_dp_hash(list(
        logical_snapshot = snapshot, alignment_group = "aligned",
        method = "pinned_psi_ordered_manifest_v1")),
      public_patient_dependent_hash = FALSE))
  spec <- .dsvert_dp_glm_grid_cross_spec(raw, policy, authenticated)
  artifact <- .dsvert_dp_glm_grid_cross_artifact(spec)
  unsigned <- list(version = .DSVERT_DP_GLM_GRID_CROSS_CONTRACT_VERSION,
    spec = spec, artifact = artifact,
    source_contract = .dsvert_dp_glm_grid_cross_source_contract(spec, artifact))
  sign <- function(value) {
    value$signatures <- NULL
    message <- .dsvert_dp_glm_grid_cross_message(value)
    value$signatures <- lapply(identities, function(identity) {
      .dsvert_relay_sign_message(message, identity$identity_sk)
    })
    value
  }
  list(policy = policy, schema = schema, authenticated = authenticated,
       raw = raw, unsigned = unsigned, contract = sign(unsigned), sign = sign)
}

.cross_grid_contract_validate <- function(fixture, contract = fixture$contract,
                                          schema = fixture$schema) {
  .dsvert_dp_glm_grid_cross_contract_validate(contract, fixture$policy, schema)
}

test_that("cross-grid signed contracts authenticate both families with real Ed25519", {
  for (family in c("binomial", "poisson")) {
    fixture <- .cross_grid_contract_fixture(family)
    result <- .cross_grid_contract_validate(fixture)
    expect_identical(result$spec$family, family)
    expect_identical(result$artifact$implementation_state,
                     "cross_owner_exact_gc_materialized")
    expect_identical(result$artifact$cross_owner_state,
                     "exact_gc_to_joint_dp_vector_v1")
    expect_identical(result$source_contract$version,
      "dsvert-biomedical-capsule-source-contract-v6-cross-grid-xor-alignment")
    encoded <- jsonlite::fromJSON(.dsvert_dp_canonical_json(result),
                                  simplifyVector = FALSE)
    expect_identical(.cross_grid_contract_validate(fixture, encoded), result)
    expect_identical(result$spec$design_terms,
                     as.list(c("(Intercept)", "peer_a$x", "peer_b$z")))
    expect_identical(result$spec$numeric_contract$input_fraction_bits, 50)
    expect_identical(result$spec$numeric_contract$arithmetic_width_bits, 192)
  }
})

test_that("cross-grid signatures bind bounds, every owner and the compute pair", {
  fixture <- .cross_grid_contract_fixture()
  missing <- fixture$contract
  missing$signatures$peer_b <- NULL
  changed <- fixture$contract
  changed$spec$predictors[[1]]$upper <- 5
  permuted <- fixture$contract
  permuted$spec$design_terms <- rev(permuted$spec$design_terms)
  pair <- fixture$contract
  pair$spec$computation_peers <- as.list(c("peer_a", "peer_c"))
  profile <- fixture$contract
  profile$spec$numeric_contract$profile_sha256 <- strrep("0", 64)
  unaligned <- fixture$contract
  unaligned$spec$alignment$version <- "unjoined_sources_v1"
  public_ids <- fixture$contract
  public_ids$spec$alignment$public_patient_dependent_hash <- TRUE
  for (bad in list(missing, changed, permuted, pair, profile, unaligned,
                   public_ids)) {
    expect_error(.cross_grid_contract_validate(fixture, bad),
      class = "dsvert_dp_public_failure")
  }
  unsigned_bounds <- fixture$schema
  unsigned_bounds$signatures <- NULL
  expect_error(.cross_grid_contract_validate(fixture, schema = unsigned_bounds),
    class = "dsvert_dp_public_failure")
  changed_bounds <- fixture$schema
  changed_bounds$datasets$cohort$columns$x$upper <- 5
  expect_error(.cross_grid_contract_validate(fixture, schema = changed_bounds),
    class = "dsvert_dp_public_failure")
  missing_owner <- fixture$schema
  missing_owner$signatures$peer_b <- NULL
  expect_error(.cross_grid_contract_validate(fixture, schema = missing_owner),
    class = "dsvert_dp_public_failure")
  forged <- fixture$contract
  forged$signatures$peer_a <- forged$signatures$peer_b
  expect_error(.cross_grid_contract_validate(fixture, forged),
    class = "dsvert_dp_public_failure")
})

test_that("cross-grid structural validators reject signed malformed public plans", {
  fixture <- .cross_grid_contract_fixture()
  mutations <- list(
    function(x) { x$unknown <- TRUE; x },
    function(x) { x$version <- "binomial_grid_v1"; x },
    function(x) { x$spec$unknown <- TRUE; x },
    function(x) { x$spec$beta_encoded[[1]][[2]] <- "1"; x },
    function(x) { x$spec$beta_grid <- rev(x$spec$beta_grid); x },
    function(x) { x$spec$predictor_order <- rev(x$spec$predictor_order); x },
    function(x) { x$spec$schema_sha256 <- strrep("1", 64); x },
    function(x) { x$spec$numeric_contract$rounding_rule <- "floor"; x },
    function(x) { x$spec$numeric_contract$input_fraction_bits <- 48; x },
    function(x) { x$spec$numeric_contract$certified_uniform_error <- "0"; x },
    function(x) { x$spec$numeric_contract$per_operation_bounds$dot_raw_abs_lt_pow2 <- 104; x },
    function(x) { x$spec$max_outcome <- 2; x },
    function(x) { x$spec$observation_capacity <- 3; x },
    function(x) { x$artifact$sensitivity$maximum_coordinates[[1]] <- 0; x },
    function(x) { x$artifact$transcript$row_batch_size <- 1; x },
    function(x) { x$artifact$result_evidence_required <- FALSE; x },
    function(x) { x$source_contract$purpose <- "other"; x },
    function(x) { x$source_contract$recipients <- as.list(c("peer_a", "peer_c")); x },
    function(x) { x$source_contract$alignment_sharing <- "public"; x },
    function(x) { x$source_contract$private_layout$blocks[[1]]$value_fraction_bits <- 18; x },
    function(x) { x$source_contract$private_layout$blocks[[3]]$value_fraction_bits <- 50; x },
    function(x) { x$source_contract$private_layout$padding_validity <- 1; x },
    function(x) { x$source_contract$private_layout$blocks[[1]]$unknown <- TRUE; x })
  for (mutate in mutations) {
    bad <- fixture$sign(mutate(fixture$unsigned))
    error <- tryCatch(.cross_grid_contract_validate(fixture, bad),
                      error = identity)
    expect_s3_class(error, "dsvert_dp_public_failure")
    expect_identical(conditionMessage(error), .DSVERT_DP_PUBLIC_FAILURE_MESSAGE)
  }
})

test_that("cross-grid private layout separates f50 inputs, integer outcome and bits", {
  fixture <- .cross_grid_contract_fixture("poisson")
  layout <- fixture$contract$source_contract$private_layout
  expect_identical(layout$release_coordinate_count, 3L)
  expect_equal(layout$private_start, 8193)
  expect_equal(layout$padding_coordinates, 8189)
  expect_equal(layout$transport_coordinate_count, 8204)
  expect_equal(vapply(layout$blocks, `[[`, numeric(1), "value_fraction_bits"),
               c(50, 50, 0))
  expect_equal(vapply(layout$blocks, `[[`, numeric(1), "validity_maximum"),
               c(1, 1, 1))
  expect_identical(layout$release_prefix_source_rule,
                   "all_zero_until_authenticated_result_injection_v1")
  expect_false(fixture$contract$spec$alignment$public_patient_dependent_hash)
})

test_that("cross-grid bounds reject unrepresentable capacities and unsupported dimensions", {
  fixture <- .cross_grid_contract_fixture("poisson")
  raw <- fixture$raw
  raw$beta_grid <- list(c(8, 8, 0))
  policy <- fixture$policy
  policy$unit_capacity <- 10000
  expect_error(.dsvert_dp_glm_grid_cross_spec_validate(
    fixture$contract$spec, policy, fixture$authenticated),
    class = "dsvert_dp_public_failure")
  expect_error(.dsvert_dp_glm_grid_cross_spec(raw, policy, fixture$authenticated),
    class = "dsvert_dp_public_failure")
  for (bits in c(7, 19, NA_real_, 8.5)) {
    policy$numeric_grid_bits <- bits
    expect_error(.dsvert_dp_glm_grid_cross_spec_validate(
      fixture$contract$spec, policy, fixture$authenticated),
      class = "dsvert_dp_public_failure")
  }
  for (field in names(fixture$contract$spec$numeric_contract)) {
    bad <- fixture$contract$spec$numeric_contract
    bad[[field]] <- NULL
    expect_error(.dsvert_dp_glm_grid_cross_numeric_validate(bad, "poisson"),
      class = "dsvert_dp_public_failure")
  }
})

test_that("cross-grid loss caps and adjacency use the existing public formulas", {
  for (family in c("binomial", "poisson")) {
    fixture <- .cross_grid_contract_fixture(family)
    spec <- fixture$contract$spec
    for (g in c(8, 16, 18)) {
      value <- .dsvert_dp_glm_grid_cross_sensitivity(
        spec$beta_grid, family, spec$max_outcome, g, 2, "add_remove_patient")
      caps <- vapply(spec$beta_grid, function(beta) {
        A <- sum(abs(unlist(beta)))
        loss <- if (family == "binomial") {
          outer(0:1, c(-A, A), function(y, eta) {
            pmax(eta, 0) + log1p(exp(-abs(eta))) - y * eta
          })
        } else outer(0:spec$max_outcome, c(-A, A), function(y, eta) {
          exp(eta) - y * eta + lgamma(y + 1)
        })
        ceiling(2^g * max(0, loss))
      }, numeric(1))
      expect_equal(vapply(value$candidate_bounds, `[[`, numeric(1),
                          "per_patient_cap"), caps)
      expect_equal(unlist(value$maximum_coordinates), 2 * caps)
      expect_equal(value$raw_l1_sensitivity, sum(caps))
      expect_equal(value$raw_l2_sensitivity, sqrt(sum(caps^2)))
      expect_equal(value$natural_l1_sensitivity, sum(caps) / 2^g)
      expect_equal(value$natural_l2_sensitivity, sqrt(sum(caps^2)) / 2^g)
      replace <- .dsvert_dp_glm_grid_cross_sensitivity(
        spec$beta_grid, family, spec$max_outcome, g, 2, "replace_one_fixed_cohort")
      expect_equal(replace$raw_l1_sensitivity, 2 * value$raw_l1_sensitivity)
      expect_equal(replace$raw_l2_sensitivity, 2 * value$raw_l2_sensitivity)
    }
  }
})

test_that("cross-grid profile coefficients, proof and numeric template are immutable", {
  fixture <- jsonlite::fromJSON(system.file(
    "cross-grid-v1", "numeric_profile_v1.json", package = "dsVert"),
    simplifyVector = FALSE)
  mutations <- list(
    function(x) { x$profile$softplus_coefficients_q64[[1]] <- "0"; x },
    function(x) { x$certificate$eta_error_bound <- "0"; x },
    function(x) { x$numeric_contract$binomial$input_fraction_bits <- 48; x })
  for (mutate in mutations) {
    changed <- mutate(fixture)
    testthat::with_mocked_bindings({
      expect_error(.dsvert_dp_glm_grid_cross_numeric("binomial"),
                   class = "dsvert_dp_public_failure")
    }, fromJSON = function(...) changed, .package = "jsonlite")
  }
})

test_that("cross-grid signed zero encoding survives canonical round trips", {
  fixture <- .cross_grid_contract_fixture()
  for (zero in c(-0, -2^-52)) {
    raw <- fixture$raw
    raw$beta_grid <- list(c(zero, 0, 0))
    spec <- .dsvert_dp_glm_grid_cross_spec(raw, fixture$policy,
                                         fixture$authenticated)
    expect_identical(spec$beta_encoded[[1]], as.list(c("0", "0", "0")))
    artifact <- .dsvert_dp_glm_grid_cross_artifact(spec)
    contract <- fixture$sign(list(
      version = .DSVERT_DP_GLM_GRID_CROSS_CONTRACT_VERSION,
      spec = spec, artifact = artifact,
      source_contract = .dsvert_dp_glm_grid_cross_source_contract(spec, artifact)))
    validated <- .cross_grid_contract_validate(fixture, contract)
    encoded <- jsonlite::fromJSON(.dsvert_dp_canonical_json(validated),
                                  simplifyVector = FALSE)
    expect_identical(.cross_grid_contract_validate(fixture, encoded), validated)
  }
})

test_that("cross-grid beta L1 comparison is exact at the public boundary", {
  expect_true(.dsvert_dp_glm_grid_cross_beta_l1_valid(c(8, 8)))
  expect_true(.dsvert_dp_glm_grid_cross_beta_l1_valid(rep(0.5, 32)))
  expect_true(.dsvert_dp_glm_grid_cross_beta_l1_valid(
    c(8 - 6 * 2^-50, rep(2 + 3 * 2^-51, 4))))
  expect_false(.dsvert_dp_glm_grid_cross_beta_l1_valid(rep(3.2, 5)))
  expect_false(.dsvert_dp_glm_grid_cross_beta_l1_valid(c(8, 8, 2^-60)))
  expect_false(.dsvert_dp_glm_grid_cross_beta_l1_valid(c(8, 8, 2^-1074)))
  fixture <- .cross_grid_contract_fixture()
  raw <- fixture$raw
  for (beta in list(c(8, 8, 0), c(7.5, 7.5, 1))) {
    raw$beta_grid <- list(beta)
    expect_no_error(.dsvert_dp_glm_grid_cross_spec(
      raw, fixture$policy, fixture$authenticated))
  }
  raw$beta_grid <- list(c(8, 8, 2^-60))
  expect_error(.dsvert_dp_glm_grid_cross_spec(
    raw, fixture$policy, fixture$authenticated), class = "dsvert_dp_public_failure")
})

test_that("cross-grid scalar identifiers reject JSON array representations", {
  fixture <- .cross_grid_contract_fixture()
  for (field in c("analysis_id", "dataset", "outcome")) {
    raw <- fixture$raw
    raw[[field]] <- as.list(raw[[field]])
    expect_error(.dsvert_dp_glm_grid_cross_spec(
      raw, fixture$policy, fixture$authenticated), class = "dsvert_dp_public_failure")
  }
  forged <- fixture$unsigned
  forged$spec$analysis_id <- list("grid")
  forged$artifact <- .dsvert_dp_glm_grid_cross_artifact(forged$spec)
  forged$source_contract <- .dsvert_dp_glm_grid_cross_source_contract(
    forged$spec, forged$artifact)
  expect_error(.cross_grid_contract_validate(fixture, fixture$sign(forged)),
               class = "dsvert_dp_public_failure")
})
