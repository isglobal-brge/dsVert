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
