# Internal artifact-bound source contract for a stateless sticky synopsis.
#
# This file defines no endpoint.  It namespaces the existing durable capsule
# transport by the validated artifact while preserving the manifest capsule ID
# needed by the source producer.

.DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION <-
  "dsvert-stateless-catalog-synopsis-source-contract-v1"
.DSVERT_DP_SYNOPSIS_SOURCE_NAMESPACE_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/source-namespace/v1|"

.dsvert_dp_synopsis_source_namespace_id_v1 <- function(binding) {
  fields <- c(
    "version", "manifest_capsule_id", "artifact_key",
    "source_claim_set_sha256")
  if (!is.list(binding) || is.null(names(binding)) || anyNA(names(binding)) ||
      anyDuplicated(names(binding)) || !setequal(names(binding), fields) ||
      !identical(
        binding$version, .DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION)) {
    stop("Invalid synopsis source namespace binding.", call. = FALSE)
  }
  lapply(binding[setdiff(fields, "version")],
         .dsvert_dp_synopsis_hex_v1, what = "source namespace hash")
  digest::digest(charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_SOURCE_NAMESPACE_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(binding)))),
  algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_source_contract_v1 <- function(
    policy, manifest, artifact, claim_set,
    .verifier = .dsvert_relay_verify_message) {
  artifact <- .dsvert_dp_synopsis_artifact_validate_v1(
    artifact, policy, manifest, claim_set, .verifier = .verifier)
  base <- .dsvert_dp_capsule_source_contract(policy, manifest)
  binding <- list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION,
    manifest_capsule_id = base$capsule_id,
    artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256)
  base$capsule_id <-
    .dsvert_dp_synopsis_source_namespace_id_v1(binding)
  base$synopsis_binding <- binding
  .dsvert_dp_capsule_source_contract_validate(
    .dsvert_dp_canonical_query_value(base))
}
