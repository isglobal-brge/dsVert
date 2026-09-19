# The established LMM lifecycle is shared only by these two typed producers.
# Keep LMM identifiers unchanged; every GLMM record uses a separate domain.
.dsvert_dp_staged_grouped_kind <- function(family) {
  switch(family, lmm = "lmm", binomial_glmm = "glmm",
    .dsvert_dp_glm_grid_cross_fail())
}

.dsvert_dp_staged_grouped_artifact <- function(artifact) {
  is.list(artifact) && isTRUE(artifact$family %in% c("lmm", "binomial_glmm")) &&
    identical(artifact$version, paste0("bounded-", gsub("_", "-", artifact$family), "-cross-grid-v1")) &&
    identical(artifact$spec_version, paste0(artifact$family, "_grid_cross_v1"))
}

.dsvert_dp_staged_grouped_tag <- function(artifact, suffix, prefix = "") {
  paste0(prefix, .dsvert_dp_staged_grouped_kind(artifact$family), suffix)
}
