# Synthetic fixture only. No protected input, production oracle, or release seam.
.family_b_identities <- local({
  cached <- NULL
  function() {
    if (is.null(cached)) cached <<- stats::setNames(lapply(1:2, function(i) {
      .callMpcTool("derive-identity", list(seed = jsonlite::base64_enc(
        as.raw((seq_len(32) + 61L * i) %% 256L))))
    }), c("peer_a", "peer_b"))
    cached
  }
})

.family_b_contract_fixture <- function(family = "multinomial", beta_grid = NULL,
    candidate_grid = NULL, capacity = 2, bits = 18,
    levels = c("a", "b", "c"), adjacency = "add_remove_patient") {
  identities <- .family_b_identities()
  pins <- vapply(identities, function(identity) {
    .dsvert_relay_normalize_identity_pk(identity$identity_pk)
  }, character(1L))
  policy <- list(peer_pinset = pins,
    peer_pinset_sha256 = .dsvert_joint_dp_hash(as.list(pins)),
    designated_noise_peers = c("peer_a", "peer_b"), unit_capacity = capacity,
    numeric_grid_bits = bits, adjacency = adjacency)
  snapshot <- list(logical_snapshot_id = "family-b-cohort", version = "v1",
    alignment_protocol_version = 1)
  schema <- list(version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = snapshot, peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = list(cohort = list(dataset_id = "cohort", dataset_version = "v1",
      schema_version = "v1", alignment_group = "aligned", patient_keys = list(
        peer_a = "id", peer_b = "id"), columns = list(
          x = list(kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 1),
          z = list(kind = "numeric", owner_peer = "peer_b", lower = 0, upper = 1),
          y = list(kind = "categorical", owner_peer = "peer_a", levels = sort(levels))))))
  schema$signatures <- lapply(identities, function(identity) {
    .dsvert_relay_sign_message(.dsvert_dp_capsule_schema_message(schema), identity$identity_sk)
  })
  authenticated <- .dsvert_dp_capsule_schema(policy, snapshot, schema,
    .dsvert_relay_verify_message)
  raw <- list(version = paste0(family, "_grid_cross_v1"), analysis_id = "family-b-grid",
    dataset = "cohort", outcome = "peer_a$y",
    predictor_order = c("peer_a$x", "peer_b$z"), alignment = list(
      version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "aligned",
      public_alignment_contract_sha256 = .dsvert_joint_dp_hash(list(
        logical_snapshot = snapshot, alignment_group = "aligned",
        method = "pinned_psi_ordered_manifest_v1")), public_patient_dependent_hash = FALSE))
  if (family == "multinomial") {
    raw$levels <- levels
    raw$reference <- levels[1L]
    if (is.null(beta_grid)) beta_grid <- list(rep(0, 3L * (length(levels) - 1L)),
      rep(c(0, 0.5, -0.5), length(levels) - 1L))
    beta_grid <- lapply(beta_grid, as.list)
    raw$beta_grid <- beta_grid[order(vapply(beta_grid,
      .dsvert_dp_canonical_json, character(1L)), method = "radix")]
  } else {
    raw$ordered_levels <- levels
    if (is.null(candidate_grid)) candidate_grid <- list(
      list(beta = c(0, 0, 0), thresholds = seq(-1, 1, length.out = length(levels) - 1L)),
      list(beta = c(0, 0.5, -0.5), thresholds = seq(-1, 1, length.out = length(levels) - 1L)))
    candidate_grid <- lapply(candidate_grid, function(candidate) {
      list(beta = as.list(candidate$beta), thresholds = as.list(candidate$thresholds))
    })
    raw$candidate_grid <- candidate_grid[order(vapply(candidate_grid,
      .dsvert_dp_canonical_json, character(1L)), method = "radix")]
  }
  spec <- .dsvert_dp_categorical_grid_cross_spec(raw, policy, authenticated, family)
  artifact <- .dsvert_dp_categorical_grid_cross_artifact(spec)
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

.family_b_validate <- function(fixture, value = fixture$contract, schema = fixture$schema) {
  .dsvert_dp_categorical_grid_cross_contract_validate(value, fixture$policy,
    schema, sub("_grid_cross_v1$", "", fixture$raw$version))
}
