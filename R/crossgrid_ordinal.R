# Stable cumulative-logit identity and probability-domain restrictions are
# signed in the categorical family contract. No production release is enabled
# by returning this descriptor to the future fused producer.
.dsvert_dp_ordinal_grid_cross_spec <- function(raw, policy, schema) {
  .dsvert_dp_categorical_grid_cross_spec(raw, policy, schema, "ordinal")
}
.dsvert_dp_ordinal_grid_cross_spec_validate <- function(value, policy, schema) {
  .dsvert_dp_categorical_grid_cross_spec_validate(value, policy, schema, "ordinal")
}
.dsvert_dp_ordinal_grid_cross_contract_validate <- function(
    value, policy, schema_manifest, .verifier = .dsvert_relay_verify_message) {
  .dsvert_dp_categorical_grid_cross_contract_validate(value, policy,
    schema_manifest, "ordinal", .verifier)
}
.dsvert_dp_ordinal_grid_cross_register <- function() {
  list(family = "ordinal", spec_version = "ordinal_grid_cross_v1",
    operation = "dp.ordinal-grid-cross.v1", release_enabled = FALSE,
    spec = .dsvert_dp_ordinal_grid_cross_spec,
    validate = .dsvert_dp_ordinal_grid_cross_contract_validate,
    artifact = .dsvert_dp_categorical_grid_cross_artifact,
    source_contract = .dsvert_dp_glm_grid_cross_source_contract,
    release = function(...) .dsvert_dp_glm_grid_cross_fail())
}
