# Public fixed-cohort policy value.  This endpoint has no add/remove branch,
# noise sampler, allocator or analyst-controlled arguments beyond the bound
# dataset name.  It therefore cannot be repurposed as a legacy count release.

#' Return the custodian's public fixed-cohort size
#'
#' This reports configuration metadata only. It neither resolves nor validates
#' the current protected object; route-specific admission is a separate step.
#'
#' @param data_name Name of the policy-bound server-side data frame.
#' @return The public policy constant and a zero-sensitivity certificate.
#' @export
dsvertPublicFixedCohortCountDS <- function(data_name) {
  .validate_data_name(data_name)
  policy <- .dsvert_dp_policy()
  if (!identical(policy$adjacency, "replace_one_fixed_cohort")) {
    stop("The public fixed-cohort count endpoint is unavailable under ",
         "add/remove adjacency", call. = FALSE)
  }
  if (!data_name %in% names(policy$datasets)) {
    .dsvert_dp_capsule_manifest_abort(
      "unknown_policy_dataset",
      "The requested dataset is not published in the custodian capsule policy")
  }
  list(
    released = TRUE,
    value = as.numeric(policy$fixed_cohort_size),
    mechanism = "public_fixed_cohort_size_v1",
    implementation = "custodian_owned_policy_constant",
    sampler = "none",
    randomness = "none",
    sensitivity = 0,
    postprocessing = "none_public_policy_value",
    clipped_coordinates = 0L,
    accuracy_95_abs = 0,
    data_dependency = "none_public_fixed_cohort_policy",
    epsilon = 0,
    delta = 0,
    adjacency = policy$adjacency,
    peer_count = as.integer(length(policy$peer_pinset)))
}
