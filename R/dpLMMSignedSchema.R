# Public schema provenance is retained in the MAC-authenticated Synopsis cache,
# separately from immutable manifest bytes and the sticky release identity.
.dsvert_dp_lmm_cross_signed_schema <- function(policy, secret, manifest_sha256, manifest) {
  record <- .dsvert_dp_synopsis_manifest_cache_get_readonly_v1(
    policy, secret, manifest_sha256 = manifest_sha256)
  cached <- .dsvert_dp_synopsis_cached_manifest_v1(manifest_sha256, policy, secret,
    cache_get = function(...) record)
  .dsvert_dp_glm_grid_cross_equal(manifest, .dsvert_dp_capsule_source_manifest(cached))
  if (!is.list(record$signed_schema)) .dsvert_dp_grouped_cross_fail()
  schema <- .dsvert_dp_capsule_schema(policy, manifest$logical_snapshot,
    record$signed_schema, .dsvert_relay_verify_message)
  attestation <- manifest$workload$schema_attestation
  if (!identical(schema$sha256, record$schema_sha256) ||
      !identical(schema$sha256, attestation$manifest_sha256)) .dsvert_dp_grouped_cross_fail()
  .dsvert_dp_glm_grid_cross_equal(schema$signatures, attestation$signatures)
  .dsvert_dp_glm_grid_cross_equal(as.list(schema$signers), as.list(attestation$signers))
  record$signed_schema
}
