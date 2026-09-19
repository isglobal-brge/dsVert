# Signed-grid projection into the existing capsule coordinate/source machinery.
.dsvert_dp_glm_grid_cross_artifacts <- function(manifest) {
  artifacts <- manifest$workload$families$gaussian_models$artifacts
  if (!is.list(artifacts)) return(list())
  artifacts[vapply(artifacts, function(artifact) is.list(artifact) &&
    artifact$version %in% unname(.DSVERT_DP_GLM_GRID_CROSS_ARTIFACT_VERSIONS),
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
  if (isTRUE(block$outcome) && !is.null(block$levels)) {
    valid <- !is.na(input$cell)
    result <- if (identical(block$kind, "validity")) as.numeric(valid) else as.numeric(input$cell) - 1
    result[!valid] <- 0
    return(result)
  }
  valid <- input$valid
  if (isTRUE(block$outcome)) {
    valid <- valid & is.finite(input$unit_values) &
      input$unit_values == floor(input$unit_values) &
      input$unit_values >= 0 & input$unit_values <= block$upper
  }
  result <- if (identical(block$kind, "validity")) {
    as.numeric(valid)
  } else if (isTRUE(block$outcome)) {
    input$unit_values
  } else {
    round(pmin(1, pmax(0, (input$unit_values - block$lower) /
      (block$upper - block$lower))) * 2^50)
  }
  result[!valid] <- 0
  result
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
  if (length(.dsvert_dp_glm_grid_cross_artifacts(manifest))) {
    if (!identical(manifest$workload$capsule_mechanism$mechanism, "discrete-laplace")) {
      .dsvert_dp_glm_grid_cross_fail()
    }
    "dsvert-cross-grid-exact-gc-cost-policy-v2"
  } else .DSVERT_JOINT_DP_VECTOR_EXACT_GC_COST_POLICY_VERSION
}
