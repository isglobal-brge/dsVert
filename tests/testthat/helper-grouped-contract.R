.grouped_contract_fixture <- function(family = "lmm", correlation = "independence", owners = 2L) {
  peers <- paste0("peer_", letters[seq_len(owners)])
  identities <- setNames(lapply(seq_len(owners), function(i) {
    .callMpcTool("derive-identity", list(seed = jsonlite::base64_enc(
      as.raw((seq_len(32) + 61L*i) %% 256L))))
  }), peers)
  pins <- vapply(identities, function(x) {
    .dsvert_relay_normalize_identity_pk(x$identity_pk)
  }, character(1L))
  policy <- list(peer_pinset = pins,
    peer_pinset_sha256 = .dsvert_joint_dp_hash(as.list(pins)),
    designated_noise_peers = peers[1:2], unit_capacity = 8,
    numeric_grid_bits = 16, adjacency = "add_remove_patient")
  snapshot <- list(logical_snapshot_id = "grouped-cohort", version = "v1",
                   alignment_protocol_version = 1)
  maximum <- if (startsWith(family, "poisson")) 4 else 1
  covariate_peers <- if (owners == 2L) peers[1L] else peers[seq.int(3L, owners)]
  covariate_names <- if (length(covariate_peers) == 1L) "x" else
    paste0("x", seq_along(covariate_peers))
  covariates <- setNames(lapply(seq_along(covariate_peers), function(i) {
    list(kind = "numeric", owner_peer = covariate_peers[i], lower = 0, upper = 1)
  }), covariate_names)
  predictor_order <- paste0(covariate_peers, "$", covariate_names)
  schema <- list(version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = snapshot, peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = list(cohort = list(dataset_id = "cohort", dataset_version = "v1",
      schema_version = "v1", alignment_group = "aligned",
      patient_keys = setNames(as.list(rep("id", owners)), peers), columns = c(covariates, list(
        y = list(kind = "numeric", owner_peer = "peer_b", lower = 0, upper = maximum),
        cluster = list(kind = "categorical", owner_peer = "peer_a",
                       levels = c("c1", "c2")))))))
  schema$signatures <- lapply(identities, function(identity) {
    .dsvert_relay_sign_message(.dsvert_dp_capsule_schema_message(schema), identity$identity_sk)
  })
  authenticated <- .dsvert_dp_capsule_schema(
    policy, snapshot, schema, .dsvert_relay_verify_message)
  parameters <- if (family == "lmm") {
    list(residual_variance = 1, random_intercept_variance = .25)
  } else if (grepl("_glmm$", family)) {
    list(random_intercept_variance = .25, quadrature = "gh5_fixed_v1")
  } else list(correlation = correlation,
              rho = if (correlation == "independence") 0 else .25, score_clip = 1)
  raw <- list(version = paste0(family, "_grid_cross_v1"), analysis_id = "grouped",
    dataset = "cohort", outcome = "peer_b$y", predictor_order = predictor_order,
    beta_grid = list(c(-.25, rep(.5/2^(length(covariates)-1), length(covariates))),
      rep(0, 1+length(covariates)), c(.25, rep(.5/2^(length(covariates)-1), length(covariates)))),
    max_outcome = maximum,
    alignment = list(version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "aligned",
      public_alignment_contract_sha256 = .dsvert_joint_dp_hash(list(
        logical_snapshot = snapshot, alignment_group = "aligned",
        method = "pinned_psi_ordered_manifest_v1")), public_patient_dependent_hash = FALSE),
    grouping = list(reference = "peer_a$cluster", cluster_capacity = 2,
      max_patients_per_cluster = 4, patient_rule = "one_analysis_row_per_patient_v1",
      ordering = "stable_signed_slots_preserve_gaps_v1"), parameters = parameters)
  spec <- .dsvert_dp_grouped_cross_spec(raw, policy, authenticated)
  artifact <- .dsvert_dp_grouped_cross_artifact(spec)
  unsigned <- list(version = .DSVERT_DP_GROUPED_CROSS_VERSION, spec = spec,
    artifact = artifact,
    source_contract = .dsvert_dp_grouped_cross_source_contract(spec, artifact))
  sign <- function(value) {
    value$signatures <- NULL
    message <- .dsvert_dp_grouped_cross_message(value)
    value$signatures <- lapply(identities, function(identity) {
      .dsvert_relay_sign_message(message, identity$identity_sk)
    })
    value
  }
  list(raw = raw, policy = policy, schema = schema, authenticated = authenticated,
       unsigned = unsigned, contract = sign(unsigned), sign = sign)
}
