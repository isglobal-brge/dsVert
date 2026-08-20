.dsvert_test_padded_dp_binding <- function(
    data, id_col, dataset_id, dataset_version, pinset,
    privacy_unit_id = id_col) {
  source <- list(
    alignment_purpose = "patient-record-alignment-v1",
    dataset_id = dataset_id,
    dataset_version = dataset_version,
    id_column = privacy_unit_id)
  source$source_binding_id <- paste0("source_", digest::digest(
    .psi_padded_canonical_json(source), algo = "sha256", serialize = FALSE))
  peers <- sort(names(pinset), method = "radix")
  token <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(0:31))))
  contract <- c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = digest::digest(
      .psi_padded_canonical_json(list(source = source, peers = peers)),
      algo = "sha256", serialize = FALSE),
    attestation_id = paste0("attest_", digest::digest(
      .psi_padded_canonical_json(list(peers = peers, source = source)),
      algo = "sha256", serialize = FALSE)),
    policy_id = paste0("policy_", digest::digest(
      .psi_padded_canonical_json(source),
      algo = "sha256", serialize = FALSE))), source, list(
    pinset_id = .psi_padded_pinset_id(as.list(pinset)),
    capacity = 64L,
    relay_frame_bytes = 65536L,
    inline_max_bytes = 65536L,
    peer_names = peers,
    reference_peer = peers[[1L]],
    compute_peers = peers[1:2]))
  aligned <- .psi_padded_attach_attestation(
    .psi_attach_alignment_manifest(data, id_col, token), contract)
  list(
    data = aligned,
    descriptor = dsvertDPDatasetDescriptor(
      aligned, dataset_id, dataset_version))
}
