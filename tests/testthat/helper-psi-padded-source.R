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

# Fixtures still exercise production complete-vector validation and durable
# seals. Deterministic test epochs are never used by the production allocator.
.psi_padded_test_epoch_vector <- function(pinset = NULL, count = 2L) {
  if (is.null(pinset)) pinset <- lapply(seq_len(count), function(index) {
    .dsvert_relay_b64url_encode(as.raw(rep(index, 32L)))
  })
  entries <- lapply(pinset, function(pk) {
    pk <- .dsvert_relay_normalize_identity_pk(pk)
    list(peer_identity = pk,
         authorization_epoch = digest::digest(paste0("test-epoch/", pk),
           algo = "sha256", serialize = FALSE),
         source_contract_id = strrep("e", 64L))
  })
  unname(entries[order(vapply(entries, `[[`, character(1L),
                              "peer_identity"), method = "radix")])
}
