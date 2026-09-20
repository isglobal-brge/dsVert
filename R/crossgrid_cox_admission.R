# Public, signed resource admission. Rebuilt by both contract validators.
.dsvert_dp_cox_grid_cross_admission <- function(capacity, candidates) {
  capacity <- .dsvert_dp_glm_grid_cross_integer(capacity, 2, 4000)
  candidates <- .dsvert_dp_glm_grid_cross_integer(candidates, 1, 50)
  list(version = "cox_measured_shared_envelope_v2", maximum_rows = 4000,
    maximum_candidates = 50, maximum_bytes = 256000000000,
    maximum_seconds = 21600, scope = "family_kernel_excludes_source_psi_joint_dp")
}
