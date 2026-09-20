# The staged producers share a lifecycle with distinct family domains.
.dsvert_dp_staged_grouped_kind <- function(family) {
  switch(family, lmm = "lmm", binomial_glmm = "glmm", poisson_glmm = "glmm",
    binomial_gee = "gee-fixed-rho", poisson_gee = "gee-fixed-rho",
    .dsvert_dp_glm_grid_cross_fail())
}

.dsvert_dp_staged_grouped_artifact <- function(artifact) {
  is.list(artifact) && isTRUE(artifact$family %in% c("lmm", "binomial_glmm", "poisson_glmm", "binomial_gee", "poisson_gee")) &&
    (!grepl("_gee$", artifact$family) ||
      identical(artifact$composition, "staged_fixed_rho_v1")) &&
    identical(artifact$version, paste0("bounded-", gsub("_", "-", artifact$family), "-cross-grid-v1")) &&
    identical(artifact$spec_version, paste0(artifact$family, "_grid_cross_v1"))
}

.dsvert_dp_staged_grouped_tag <- function(artifact, suffix, prefix = "") {
  paste0(prefix, .dsvert_dp_staged_grouped_kind(artifact$family), suffix)
}

.dsvert_dp_staged_grouped_input_key <- function(family) {
  kind <- .dsvert_dp_staged_grouped_kind(family)
  paste0("grouped_", if (kind == "gee-fixed-rho") "gee" else kind)
}
