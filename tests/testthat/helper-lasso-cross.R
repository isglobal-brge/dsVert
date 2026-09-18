.lasso_cross_fixture <- function(family = "binomial", capacity = 8, bits = 8,
                                 beta_grid = list(c(0, 0, 0), c(0, 1, 0))) {
  client <- exists(".dsvert_dp_glm_grid_cross_schema_validate", mode = "function")
  hash <- if (client) .dsvert_dp_capsule_source_hash else .dsvert_joint_dp_hash
  json <- if (client) .dsvert_joint_dp_client_json else .dsvert_dp_canonical_json
  keys <- stats::setNames(lapply(1:2, function(i) openssl::ed25519_keygen()),
                          c("peer_a", "peer_b"))
  b64 <- function(value) sub("=+$", "", chartr("+/", "-_",
    gsub("[\r\n]", "", jsonlite::base64_enc(value))))
  pins <- vapply(keys, function(key) b64(tail(as.raw(as.list(key)$pubkey), 32)),
                 character(1L))
  policy <- list(peer_pinset = pins, peer_pinset_sha256 = hash(as.list(pins)),
    designated_noise_peers = names(pins), unit_capacity = capacity,
    numeric_grid_bits = bits, adjacency = "add_remove_patient")
  snapshot <- list(logical_snapshot_id = "lasso-cohort", version = "v1",
                   alignment_protocol_version = 1)
  maximum <- if (family == "poisson") 4 else 1
  schema <- list(version = "dsvert-biomedical-capsule-schema-v1",
    logical_snapshot = snapshot, peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = list(cohort = list(dataset_id = "cohort", dataset_version = "v1",
      schema_version = "v1", alignment_group = "aligned",
      patient_keys = list(peer_a = "id", peer_b = "id"),
      columns = list(x = list(kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 1),
        z = list(kind = "numeric", owner_peer = "peer_b", lower = 0, upper = 1),
        y = list(kind = "numeric", owner_peer = "peer_a", lower = 0, upper = maximum)))))
  schema$version <- if (client) .DSVERT_CLIENT_DP_CAPSULE_SCHEMA_VERSION else
    .DSVERT_DP_CAPSULE_SCHEMA_VERSION
  schema_message <- if (client) charToRaw(paste0(
    .DSVERT_CLIENT_DP_CAPSULE_SCHEMA_SIGNATURE_DOMAIN, json(schema))) else
    .dsvert_dp_capsule_schema_message(schema)
  schema$signatures <- lapply(keys, function(key) b64(openssl::ed25519_sign(schema_message, key)))
  authenticated <- if (client) .dsvert_dp_glm_grid_cross_schema_validate(
    policy, snapshot, schema, .dsvert_dp_glm_grid_cross_verify) else
    .dsvert_dp_capsule_schema(policy, snapshot, schema, .dsvert_relay_verify_message)
  beta_grid <- beta_grid[order(vapply(beta_grid, function(beta) json(as.list(beta)), character(1L)), method = "radix")]
  raw <- list(version = paste0(if (family == "gaussian") "binomial" else family, "_grid_cross_v1"),
    analysis_id = "loss", dataset = "cohort", outcome = "peer_a$y",
    predictor_order = c("peer_a$x", "peer_b$z"), beta_grid = beta_grid,
    max_outcome = maximum, alignment = list(version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "aligned",
      public_alignment_contract_sha256 = hash(list(logical_snapshot = snapshot,
        alignment_group = "aligned", method = "pinned_psi_ordered_manifest_v1")),
      public_patient_dependent_hash = FALSE))
  spec <- .dsvert_dp_glm_grid_cross_spec(raw, policy, authenticated)
  artifact <- .dsvert_dp_glm_grid_cross_artifact(spec)
  base_contract <- list(version = "dsvert-cross-owner-grid-signed-contract-v1",
    spec = spec, artifact = artifact,
    source_contract = .dsvert_dp_glm_grid_cross_source_contract(spec, artifact))
  base_contract$signatures <- lapply(keys, function(key) b64(openssl::ed25519_sign(
    .dsvert_dp_glm_grid_cross_message(base_contract[c("version", "spec", "artifact", "source_contract")]), key)))
  if (family == "gaussian") {
    base_contract <- .lasso_cross_gaussian_artifact(capacity, bits)
  }
  base <- .dsvert_dp_lasso_cross_base(base_contract, policy, family)
  candidates <- unlist(lapply(c(0.5, 0), function(lambda) lapply(beta_grid,
    function(beta) list(lambda = lambda, beta = beta))), recursive = FALSE)
  raw_lasso <- list(version = "lasso_grid_cross_v1", analysis_id = "lasso",
                     candidate_grid = candidates)
  lasso_spec <- .dsvert_dp_lasso_cross_spec(raw_lasso, base)
  sign <- function(unsigned) {
    unsigned$signatures <- NULL
    message <- .dsvert_dp_lasso_cross_message(unsigned)
    unsigned$signatures <- lapply(keys, function(key) b64(openssl::ed25519_sign(message, key)))
    unsigned
  }
  contract <- sign(list(version = "dsvert-cross-owner-lasso-signed-contract-v1", spec = lasso_spec))
  list(policy = policy, schema = schema, base_contract = base_contract,
       base = base, raw = raw_lasso, spec = lasso_spec, contract = contract, sign = sign)
}

# A complete public descriptor matching the existing Gaussian moment route;
# signatures and result evidence still come from that route at integration.
.lasso_cross_gaussian_artifact <- function(capacity = 8, bits = 8) {
  scale <- 2^bits
  count <- 11
  product_error <- 2 + 1 / (4 * scale)
  bound <- function(column, owner) list(column = column, dataset = "cohort",
                                        owner_peer = owner, lower = 0, upper = 1)
  list(version = "bounded-normalized-gaussian-cross-sufficient-statistics-v1",
    spec_version = "v2", analysis_id = "loss", dataset = "cohort", owner_peer = "peer_a",
    outcome = bound("y", "peer_a"), predictors = list(x = bound("x", "peer_a"), z = bound("z", "peer_b")),
    predictor_order = c("x", "z"), input_variable_order = c("x", "z", "y"),
    participating_peers = as.list(c("peer_a", "peer_b")), computation_peers = as.list(c("peer_a", "peer_b")),
    intercept = TRUE, design_terms = c("(Intercept)", "x", "z"), numeric_grid_bits = bits,
    coordinate_count = count, coordinate_order = "n_then_xtx_upper_column_major_then_xty_design_order_then_yty_v2",
    source_coordinate_scaling = "all_coordinates_already_on_common_numeric_lattice_v1",
    private_input_layout = "capacity_padded_value_then_validity_per_signed_variable_manifest_order_v1",
    repeated_record_policy = "clip_finite_rows_then_mean_each_variable_once_per_admitted_unit_v1",
    missingness_policy = "complete_case_mask_remains_secret_shared_through_joint_noise_v1",
    contribution_domain = "round_normalized_inputs_then_exact_floor_ring128_products_on_closed_unit_interval_v1",
    count_gram_intercept_policy = "n_and_all_moments_share_one_secret_complete_case_mask_and_are_released_only_after_joint_dp_v1",
    statistic_maximum = rep(capacity * scale, count), source_raw_l1_sensitivity = count * scale,
    source_raw_l2_sensitivity = sqrt(count) * scale, natural_l1_sensitivity = count,
    natural_l2_sensitivity = sqrt(count), adjacency = "add_remove_patient",
    adjacency_sensitivity_basis = "zero_missing_complete_case_vs_all_one_complete_unit_is_worst_case_for_add_remove_and_replace_one",
    quantization_contract = list(input_rounding = "nearest_integer_ties_to_even_r_v1",
      product_rounding = "exact_signed_floor_after_division_by_scale_v1",
      per_product_max_abs_error_lattice_steps = product_error,
      per_product_max_abs_error_normalized = product_error / scale,
      per_sum_max_abs_error_lattice_steps = capacity * product_error,
      same_owner_v1_numerically_identical = FALSE),
    numeric_certificate = list(version = "dsvert-cross-gaussian-numeric-certificate-v1", ring_bits = 128,
      frac_bits = bits, required_signed_bits = ceiling(log2(capacity + 1)) + 2 * bits + 3,
      operand_maximum = scale, raw_product_maximum = scale^2,
      accumulated_coordinate_maximum = capacity * scale,
      truncation = "exact_signed_floor_gc_ot_or_direct_wide_v1",
      comparison = "not_used_after_custodian_bound_clipping", modular_wrap_proved_absent = TRUE,
      overflow_behavior = "typed_abort_before_commit"),
    transcript = list(version = "dsvert-cross-gaussian-fixed-transcript-v1", padded_units = capacity,
      variable_count = 3, validity_product_rounds = 2, masked_value_rounds = 1,
      moment_product_rounds = 1, data_dependent_branches = 0, exact_intermediate_release_count = 0),
    alignment_contract = list(version = "private-psi-ordered-manifest-consensus-v1",
      public_patient_dependent_hash = FALSE, mismatch_behavior = "typed_non_prealigned_cohort_failure"),
    regularization_policy = "none_in_release_explicit_client_postprocessing_only_v1",
    implementation_state = "cross_owner_exact_gc_materialized",
    cross_owner_state = "exact_gc_to_joint_dp_vector_v1")
}
