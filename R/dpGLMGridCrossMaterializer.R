# Signed-grid projection into the existing capsule coordinate/source machinery.
.dsvert_dp_glm_grid_cross_artifacts <- function(manifest) {
  artifacts <- manifest$workload$families$gaussian_models$artifacts
  if (!is.list(artifacts)) return(list())
  artifacts[vapply(artifacts, function(artifact) is.list(artifact) &&
    (artifact$version %in% c(unname(.DSVERT_DP_GLM_GRID_CROSS_ARTIFACT_VERSIONS),
      "bounded-lmm-cross-grid-v1", "bounded-binomial-glmm-cross-grid-v1", "bounded-poisson-glmm-cross-grid-v1",
      .DSVERT_DP_COX_GRID_CROSS_ARTIFACT_VERSION) ||
      .dsvert_dp_staged_grouped_artifact(artifact)),
    logical(1L))]
}

.dsvert_dp_glm_grid_cross_workload_artifact <- function(contract) {
  spec <- contract$spec
  artifact <- contract$artifact
  artifact$transcript$producer <- artifact$transcript$operation
  artifact$transcript$operation <- NULL
  descriptors <- lapply(spec$predictors, function(x)
    x[c("column", "dataset", "owner_peer", "lower", "upper")])
  categorical <- spec$family %in% c("multinomial", "ordinal")
  extra <- list(
    dataset = spec$dataset, family = spec$family,
    outcome = spec$outcome[c("column", "dataset", "owner_peer",
      if (categorical) "levels" else c("lower", "upper"))],
    predictors = descriptors,
    predictor_order = unlist(spec$predictor_order, use.names = FALSE),
    input_variable_order = unlist(spec$input_variable_order, use.names = FALSE),
    design_terms = unlist(spec$design_terms, use.names = FALSE),
    beta_grid = spec$beta_grid, intercept = TRUE,
    observation_capacity = spec$observation_capacity,
    max_outcome = spec$max_outcome,
    statistic_maximum = spec$sensitivity$maximum_coordinates,
    source_raw_l1_sensitivity = spec$sensitivity$raw_l1_sensitivity,
    source_raw_l2_sensitivity = spec$sensitivity$raw_l2_sensitivity,
    natural_l1_sensitivity = spec$sensitivity$natural_l1_sensitivity,
    natural_l2_sensitivity = spec$sensitivity$natural_l2_sensitivity,
    candidate_loss_bounds = lapply(spec$sensitivity$candidate_bounds,
                                   `[[`, "loss_bound"),
    numeric_certificate = spec$numeric_contract,
    adjacency = spec$adjacency,
    estimation_scope = "certified_bounded_cross_owner_signed_grid_only_v2",
    signed_contract = .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(contract)))
  if (identical(spec$family, "nb")) extra$theta_grid <- spec$theta_grid
  if (categorical) {
    extra$class_count <- spec$class_count
    extra$class_order <- spec$class_order
  }
  c(artifact, extra)
}

.dsvert_dp_glm_grid_cross_source_blocks <- function(artifact, cursor) {
  spec <- .dsvert_dp_glm_grid_cross_embedded_contract(artifact)$spec
  if (spec$family %in% .DSVERT_DP_GROUPED_CROSS_FAMILIES) {
    return(.dsvert_dp_grouped_cross_source_blocks(artifact, cursor))
  }
  blocks <- list()
  for (variable in artifact$input_variable_order) {
    outcome <- identical(variable, spec$outcome$reference)
    descriptor <- if (outcome) artifact$outcome else artifact$predictors[[variable]]
    categorical_outcome <- outcome && spec$family %in% c("multinomial", "ordinal")
    if (categorical_outcome) {
      descriptor$lower <- 0
      descriptor$upper <- spec$max_outcome
    }
    for (kind in c("value", "validity")) {
      size <- spec$observation_capacity
      end <- cursor + size - 1
      if (end > .DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES) {
        .dsvert_dp_glm_grid_cross_fail()
      }
      key <- paste(artifact$analysis_id, variable, kind, sep = "::")
      blocks[[key]] <- c(list(input_family = "glm_grid",
        analysis_id = artifact$analysis_id, variable = descriptor$column,
        kind = kind, outcome = outcome), descriptor[c(
          "dataset", "owner_peer", "lower", "upper")], list(
        start = as.integer(cursor), end = as.integer(end), length = as.integer(size),
        fraction_bits = if (identical(kind, "validity") || outcome) 0L else 50L,
        maximum = if (identical(kind, "validity")) 1 else
          if (outcome) spec$max_outcome else 2^50))
      if (categorical_outcome) blocks[[key]]$levels <- unlist(spec$class_order, use.names = FALSE)
      cursor <- end + 1
    }
  }
  list(blocks = blocks, cursor = cursor)
}

.dsvert_dp_glm_grid_cross_source_values <- function(input, block) {
  if ((isTRUE(block$outcome) || isTRUE(block$private_routing_input)) &&
      !is.null(block$levels)) {
    valid <- !is.na(input$cell)
    result <- if (identical(block$kind, "validity")) as.numeric(valid) else as.numeric(input$cell) - 1
    result[!valid] <- 0
    return(result)
  }
  valid <- input$valid
  integer_outcome <- isTRUE(block$outcome) &&
    !identical(block$outcome_encoding$kind, "fixed_point")
  if (integer_outcome) {
    valid <- valid & is.finite(input$unit_values) &
      input$unit_values == floor(input$unit_values) &
      input$unit_values >= 0 & input$unit_values <= block$upper
  }
  result <- if (identical(block$kind, "validity")) {
    as.numeric(valid)
  } else if (integer_outcome) {
    input$unit_values
  } else {
    round(pmin(1, pmax(0, (input$unit_values - block$lower) /
      (block$upper - block$lower))) * 2^block$fraction_bits)
  }
  result[!valid] <- 0
  result
}

# Routing labels travel only in the authenticated private Ring128 suffix. The
# signed source contract pins their owner, level order and value/validity blocks;
# the staged router consumes these shares without opening label membership.
.dsvert_dp_grouped_cross_workload_artifact <- function(contract) {
  artifact <- .dsvert_dp_glm_grid_cross_workload_artifact(contract)
  spec <- contract$spec
  artifact$transcript$producer <- paste0("dp.", spec$family, "-grid-cross.v1")
  artifact$outcome_encoding <- spec$outcome_encoding
  artifact$predictor_encoding <- spec$predictor_encoding
  artifact$routing_inputs <- spec$routing_inputs
  artifact$grouping <- spec$grouping
  artifact$parameters <- spec$parameters
  artifact$candidate_loss_bounds <- lapply(spec$sensitivity$candidate_bounds,
                                           `[[`, "per_cluster_caps")
  if (spec$family %in% c("lmm", "binomial_glmm", "poisson_glmm") ||
      identical(spec$parameters$composition, "staged_fixed_rho_v1")) {
    artifact$source_coordinate_scaling <- "all_coordinates_already_on_common_numeric_lattice_v1"
    # Capsule manifests use homogeneous vectors, including scalar leaves.
    # Preserve the original signed contract string while projecting its arrays.
    artifact$candidate_loss_bounds <- unlist(artifact$candidate_loss_bounds, use.names = FALSE)
    artifact <- .dsvert_dp_canonical_query_value(jsonlite::fromJSON(
      .dsvert_dp_canonical_json(artifact), simplifyVector = TRUE,
      simplifyDataFrame = FALSE, simplifyMatrix = FALSE))
    artifact$participating_peers <- as.list(artifact$participating_peers)
    artifact$computation_peers <- as.list(artifact$computation_peers)
  }
  artifact
}

.dsvert_dp_grouped_cross_source_blocks <- function(artifact, cursor) {
  spec <- .dsvert_dp_glm_grid_cross_embedded_contract(artifact)$spec
  layout <- .dsvert_dp_grouped_cross_layout(spec)
  blocks <- list()
  for (signed_block in layout$blocks) {
    variable <- signed_block$reference
    outcome <- identical(variable, spec$outcome$reference)
    routing <- isTRUE(signed_block$private_routing_input)
    descriptor <- if (routing) spec$routing_inputs[[variable]] else {
      if (outcome) spec$outcome else spec$predictors[[variable]]
    }
    for (kind in c("value", "validity")) {
      size <- signed_block$length
      end <- cursor + size - 1
      if (end > .DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES) {
        .dsvert_dp_grouped_cross_fail()
      }
      key <- paste(artifact$analysis_id, variable, kind, sep = "::")
      block <- list(input_family = "grouped_grid", analysis_id = artifact$analysis_id,
        variable = descriptor$column, kind = kind, outcome = outcome,
        dataset = descriptor$dataset, owner_peer = descriptor$owner_peer,
        start = as.integer(cursor), end = as.integer(end), length = as.integer(size),
        fraction_bits = if (kind == "validity") 0L else signed_block$value_fraction_bits,
        maximum = if (kind == "validity") 1 else signed_block$value_maximum,
        private_routing_input = routing)
      if (routing) block$levels <- unlist(descriptor$levels, use.names = FALSE) else {
        block$lower <- descriptor$lower
        block$upper <- descriptor$upper
        if (outcome) block$outcome_encoding <- spec$outcome_encoding
      }
      blocks[[key]] <- block
      cursor <- end + 1
    }
  }
  list(blocks = blocks, cursor = cursor)
}

.dsvert_dp_grouped_cross_source_values <- function(input, block) {
  result <- .dsvert_dp_glm_grid_cross_source_values(input, block)
  if (length(result) > block$length) .dsvert_dp_grouped_cross_fail()
  c(result, rep(0, block$length - length(result)))
}

.dsvert_dp_glm_grid_cross_embedded_contract <- function(artifact) {
  if (!is.character(artifact$signed_contract) || length(artifact$signed_contract) != 1L ||
      is.na(artifact$signed_contract)) .dsvert_dp_glm_grid_cross_fail()
  .dsvert_dp_capsule_source_decode_json(artifact$signed_contract,
    "signed cross-grid contract", .DSVERT_DP_CAPSULE_SOURCE_MAX_MANIFEST_BYTES)
}

# Snapshot identity binds the public plan, excluding only fields derived from
# that identity and signatures. The complete contract remains bound separately
# by workload/admission hashes and unanimous signatures.
.dsvert_dp_glm_grid_cross_snapshot_workload <- function(workload) {
  for (id in names(workload$gaussian)) {
    raw <- workload$gaussian[[id]]$spec
    # Snapshot identity must not recursively include its own signatures/hashes.
    # Recognizing a public plan here does not authorize its producer or reader.
    versions <- c(unname(.DSVERT_DP_GLM_GRID_CROSS_SPEC_VERSIONS),
      paste0(.DSVERT_DP_GROUPED_CROSS_FAMILIES, "_grid_cross_v1"), "cox_grid_cross_v1")
    if (!raw$version %in% versions) next
    contract <- .dsvert_dp_glm_grid_cross_raw_contract(raw)
    plan <- contract$spec
    plan$schema_sha256 <- NULL
    plan$logical_snapshot <- NULL
    plan$alignment$public_alignment_contract_sha256 <- NULL
    workload$gaussian[[id]]$spec <- list(version = raw$version,
      dataset = raw$dataset, public_candidate_plan = plan)
  }
  workload
}

.dsvert_dp_glm_grid_cross_raw_contract <- function(raw) {
  .dsvert_dp_glm_grid_cross_fields(raw, c("version", "dataset", "contract"))
  value <- raw$contract
  if (is.character(value) && length(value) == 1L && !is.na(value)) {
    value <- .dsvert_dp_capsule_source_decode_json(value, "signed cross-grid contract",
      .DSVERT_DP_CAPSULE_SOURCE_MAX_MANIFEST_BYTES)
  }
  if (!is.list(value) || !identical(value$spec$version, raw$version) ||
      !identical(value$spec$dataset, raw$dataset)) .dsvert_dp_glm_grid_cross_fail()
  value
}

# Scoped to signed new-family catalogs; sealed family choices retain policy v1.
.dsvert_dp_glm_grid_cross_noise_policy <- function(manifest) {
  artifacts <- .dsvert_dp_glm_grid_cross_artifacts(manifest)
  if (length(artifacts)) {
    if (!identical(manifest$workload$capsule_mechanism$mechanism, "discrete-laplace")) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    # Preserve published small-grid policy identities; larger LMM grids
    # need one admitted-count coordinate plus up to 256 signed candidates.
    if (length(artifacts) == 1L &&
        identical(artifacts[[1L]]$version, "bounded-lmm-cross-grid-v1") &&
        isTRUE(manifest$workload$coordinate_count > 51L)) {
      return("dsvert-lmm-grid-exact-gc-cost-policy-v1")
    }
    "dsvert-cross-grid-exact-gc-cost-policy-v2"
  } else .DSVERT_JOINT_DP_VECTOR_EXACT_GC_COST_POLICY_VERSION
}
