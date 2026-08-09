.psi_padded_test_source_public <- function(
    id_col = "id", id = "test-logical-cohort", version = "v1",
    purpose = "patient-record-alignment-v1") {
  value <- list(
    alignment_purpose = purpose,
    dataset_id = id,
    dataset_version = version,
    id_column = id_col)
  value$source_binding_id <- paste0("source_", digest::digest(
    .psi_padded_canonical_json(value), algo = "sha256", serialize = FALSE))
  value
}

.psi_padded_test_source_options <- function(
    data, data_name = "D", id_col = "id", id = "test-logical-cohort",
    version = "v1", purpose = "patient-record-alignment-v1") {
  descriptor <- list(
    id = id,
    version = version,
    id_col = id_col,
    purpose = purpose,
    snapshot_sha256 = .dsvert_dp_snapshot_digest(data))
  list(dsvert.psi.authorized_sources = stats::setNames(
    list(descriptor), data_name))
}
