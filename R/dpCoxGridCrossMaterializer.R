# Internal Cox projection for authenticated source/lifecycle wiring.
# Public workload discovery stays closed until the complete staged path is proved.
.dsvert_dp_cox_cross_workload_artifact <- function(contract) {
  spec <- contract$spec
  artifact <- contract$artifact
  artifact$transcript$producer <- artifact$transcript$operation
  artifact$transcript$operation <- NULL
  c(artifact, list(dataset = spec$dataset, family = spec$family,
    time = spec$time[c("column", "dataset", "owner_peer", "lower", "upper")],
    event = spec$event[c("column", "dataset", "owner_peer", "lower", "upper")],
    predictors = lapply(spec$predictors, function(x)
      x[c("column", "dataset", "owner_peer", "lower", "upper")]),
    predictor_order = unlist(spec$predictor_order, use.names = FALSE),
    input_variable_order = unlist(spec$input_variable_order, use.names = FALSE),
    design_terms = unlist(spec$design_terms, use.names = FALSE),
    beta_grid = spec$beta_grid, intercept = FALSE,
    observation_capacity = spec$observation_capacity, padded_capacity = spec$padded_capacity,
    ties = spec$ties, time_semantics = spec$time_semantics,
    predictor_normalization = spec$predictor_normalization,
    complete_case = spec$complete_case,
    statistic_maximum = spec$sensitivity$maximum_coordinates,
    source_raw_l1_sensitivity = spec$sensitivity$raw_l1_sensitivity,
    source_raw_l2_sensitivity = spec$sensitivity$raw_l2_sensitivity,
    natural_l1_sensitivity = spec$sensitivity$natural_l1_sensitivity,
    natural_l2_sensitivity = spec$sensitivity$natural_l2_sensitivity,
    numeric_certificate = spec$numeric_contract, adjacency = spec$adjacency,
    signed_contract = .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(contract))))
}

# Decode the observed binary64 itself, not its printed decimal approximation.
# Reuse the existing exact rational operations and ties-to-even quantizer.
.dsvert_dp_cox_cross_binary64 <- function(value) {
  if (!is.numeric(value) || length(value) != 1L || !is.finite(value)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  bytes <- as.numeric(writeBin(as.double(value), raw(), size = 8L, endian = "little"))
  exponent <- (bytes[8L] %% 128) * 16 + floor(bytes[7L] / 16)
  mantissa <- sum(bytes[1:6] * 256^(0:5)) + (bytes[7L] %% 16) * 2^48
  if (exponent != 0) mantissa <- mantissa + 2^52
  shift <- if (exponent == 0) -1074 else exponent - 1075
  numerator <- .dsvert_formal_glm_phase18_bn(sprintf("%.0f", mantissa))
  denominator <- .dsvert_formal_glm_phase18_bn(1)
  two <- .dsvert_formal_glm_phase18_bn(2)
  if (shift >= 0) numerator <- numerator * two^shift else denominator <- two^(-shift)
  .dsvert_formal_glm_phase18_rat_new(if (bytes[8L] >= 128) -1L else 1L,
    numerator, denominator)
}

.dsvert_dp_cox_cross_normalize <- function(values, lower, upper) {
  lo <- .dsvert_dp_cox_cross_binary64(lower)
  hi <- .dsvert_dp_cox_cross_binary64(upper)
  if (.dsvert_formal_glm_phase18_rat_cmp(lo, hi) >= 0L ||
      !is.numeric(values) || any(!is.finite(values))) .dsvert_dp_cox_grid_cross_fail()
  width <- .dsvert_formal_glm_phase18_rat_sub(hi, lo)
  vapply(pmin(upper, pmax(lower, values)), function(value) {
    unit <- .dsvert_formal_glm_phase18_rat_div(
      .dsvert_formal_glm_phase18_rat_sub(.dsvert_dp_cox_cross_binary64(value), lo), width)
    as.numeric(.dsvert_formal_glm_phase18_rat_scaled_integer(
      .dsvert_formal_glm_phase18_rat_round(unit, 50L), 50L))
  }, numeric(1L), USE.NAMES = FALSE)
}

# Internal authenticated snapshot adapter. Outputs are private producer inputs,
# never public receipts. The existing source transport still owns commitments,
# sharing and persistence; no Cox endpoint is enabled by this adapter.
.dsvert_dp_cox_cross_materialize_inputs <- function(policy, manifest,
    source_contract, schema_manifest, analysis_id, resolved_snapshots) {
  context <- .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  spec <- context$spec
  snapshots <- .dsvert_dp_capsule_resolved_snapshots(policy, resolved_snapshots)
  if (!policy$peer_name %in% unlist(spec$participating_peers, use.names = FALSE) ||
      !identical(as.numeric(policy$unit_capacity), as.numeric(spec$observation_capacity))) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  descriptors <- c(spec$predictors, setNames(list(spec$event, spec$time),
    c(spec$event$reference, spec$time$reference)))
  local <- descriptors[vapply(descriptors, function(x)
    identical(x$owner_peer, policy$peer_name), logical(1L))]
  admissions <- list()
  alignment <- character()
  for (dataset in unique(vapply(local, `[[`, character(1L), "dataset"))) {
    descriptor <- policy$datasets[[dataset]]
    signed <- schema_manifest$datasets[[dataset]]
    if (is.null(descriptor$alignment_manifest_hash) ||
        is.null(descriptor$alignment_manifest_version) || is.null(snapshots[[dataset]]) ||
        !identical(descriptor$id, signed$dataset_id) ||
        !identical(descriptor$version, signed$dataset_version) ||
        !identical(policy$patient_column, signed$patient_keys[[policy$peer_name]])) {
      .dsvert_dp_cox_grid_cross_fail()
    }
    data <- snapshots[[dataset]]$data
    alignment <- c(alignment, .dsvert_dp_validate_descriptor_alignment(
      data, descriptor, policy$patient_column, expected_pinset = policy$peer_pinset)$hash)
    admission <- .dsvert_dp_admit_units(data, policy)
    if (any(admission$record_count > 1L)) .dsvert_dp_cox_grid_cross_fail()
    admissions[[dataset]] <- admission
  }
  if (length(unique(alignment)) != 1L) .dsvert_dp_cox_grid_cross_fail()
  blocks <- list()
  times <- time_valid <- NULL
  for (reference in names(local)) {
    descriptor <- local[[reference]]
    data <- snapshots[[descriptor$dataset]]$data
    admission <- admissions[[descriptor$dataset]]
    raw <- data[[descriptor$column]]
    if (!is.numeric(raw) || length(raw) != nrow(data)) .dsvert_dp_cox_grid_cross_fail()
    valid <- is.finite(raw)
    event <- identical(reference, spec$event$reference)
    time <- identical(reference, spec$time$reference)
    if (event) valid <- valid & raw %in% c(0, 1)
    value <- numeric(spec$padded_capacity)
    present <- rep(FALSE, spec$padded_capacity)
    slots <- admission$group[valid]
    present[slots] <- TRUE
    bounded <- pmin(descriptor$upper, pmax(descriptor$lower, raw[valid]))
    value[slots] <- if (event || time) bounded else
      .dsvert_dp_cox_cross_normalize(bounded, descriptor$lower, descriptor$upper)
    key <- paste(analysis_id, reference, sep = "::")
    blocks[[paste0(key, "::validity")]] <- as.numeric(present)
    if (time) {
      value[value == 0] <- 0
      times <- value[seq_len(spec$observation_capacity)]
      time_valid <- present[seq_len(spec$observation_capacity)]
    } else blocks[[paste0(key, "::value")]] <- value
  }
  order <- names(context$layout$blocks)
  blocks <- blocks[order[order %in% names(blocks)]]
  list(context = context, blocks = blocks, times = times, time_valid = time_valid,
    private_alignment_consensus_hash = alignment[[1L]],
    snapshot_binding_sha256 = .dsvert_joint_dp_hash(list(
      protocol = "dsvert-biomedical-capsule-local-snapshots-v1",
      capsule_id = source_contract$capsule_id, peer_name = policy$peer_name,
      datasets = lapply(snapshots, function(snapshot) list(public = snapshot$dataset$public,
        protected_fingerprint = snapshot$dataset$fingerprint)))))
}
