# Server Claim compiler for one fixed-domain categorical Frequency analysis.

.DSVERT_DP_FREQUENCY_CLAIM_VERSION <- "dsvert-dp-frequency-factor-claim-v1"
.DSVERT_DP_FREQUENCY_CLAIM_DOMAIN <- "dsVert/dp-frequency/factor-claim/v1|"
.DSVERT_DP_FREQUENCY_PSI_RUN_DOMAIN <- "dsVert/dp-frequency/psi-run/v1|"
.dsvert_dp_frequency_hash_v1 <- function(domain, value) {
  .dsvert_dp_analysis_frequency_hash_v1(domain, value)
}

.dsvert_dp_frequency_hex_v1 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid Frequency ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_dp_frequency_peer_name_v1 <- function(value) {
  tryCatch(.psi_padded_scalar(
    value, "Frequency peer name", "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"),
    error = function(error) stop("Invalid Frequency peer name.", call. = FALSE))
}

.dsvert_dp_frequency_identity_pk_v1 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nchar(value, type = "bytes") %in% c(43L, 44L) ||
      !(grepl("^[A-Za-z0-9_-]{43}$", value) ||
        grepl("^[A-Za-z0-9+/]{43}=$", value))) {
    stop("Invalid Frequency ", what, ".", call. = FALSE)
  }
  tryCatch(.dsvert_relay_normalize_identity_pk(value),
    error = function(error) stop(
      "Invalid Frequency ", what, ".", call. = FALSE))
}

.dsvert_dp_frequency_peer_pins_v1 <- function(value) {
  if (!is.character(value) || length(value) < 2L || length(value) > 4096L ||
      is.null(names(value)) || anyNA(names(value)) ||
      any(!nzchar(names(value))) || anyDuplicated(names(value))) {
    stop("Invalid Frequency peer pins.", call. = FALSE)
  }
  peers <- tryCatch(vapply(
    names(value), .dsvert_dp_frequency_peer_name_v1, character(1L)),
    error = function(error) character())
  pins <- tryCatch(vapply(
    value, .dsvert_dp_frequency_identity_pk_v1, character(1L),
    what = "peer identity"),
    error = function(error) character())
  if (length(peers) != length(value) || length(pins) != length(value) ||
      anyDuplicated(pins)) {
    stop("Invalid Frequency peer pins.", call. = FALSE)
  }
  names(pins) <- peers
  pins[order(names(pins), method = "radix")]
}

.dsvert_dp_frequency_signature_v1 <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") != 86L ||
      !grepl("^[A-Za-z0-9_-]{86}$", value)) {
    stop("Invalid Frequency signature.", call. = FALSE)
  }
  decoded <- tryCatch(
    .dsvert_relay_b64url_decode(value, "Frequency signature"),
    error = function(error) raw())
  if (length(decoded) != 64L) {
    stop("Invalid Frequency signature.", call. = FALSE)
  }
  value
}

.dsvert_dp_frequency_factor_entry_validate_v1 <- function(entry) {
  required <- c(
    "version", "variable_name", "variable_id", "levels", "dimension")
  if (!is.list(entry) || is.null(names(entry)) || anyNA(names(entry)) ||
      anyDuplicated(names(entry)) || !setequal(names(entry), required) ||
      !identical(entry$version, .DSVERT_PSI_PADDED_FACTOR_ENTRY_VERSION) ||
      !is.list(entry$levels) || !is.null(names(entry$levels))) {
    stop("Invalid Frequency public factor entry.", call. = FALSE)
  }
  dimension <- .dsvert_dp_analysis_frequency_levels_dimension_v1(
    entry$levels, entry$dimension, entry$variable_name)
  if (is.null(dimension)) stop(
    "Invalid Frequency public factor entry.", call. = FALSE)
  variable_name <- tryCatch(
    .psi_padded_factor_text_v1(entry$variable_name, "variable name"),
    error = function(error) NULL)
  levels <- tryCatch(vapply(
    entry$levels, .psi_padded_factor_text_v1, character(1L), what = "level"),
    error = function(error) character())
  expected_id <- if (!is.null(variable_name)) paste0(
    "var_", digest::digest(
      paste0(
        .DSVERT_PSI_PADDED_FACTOR_VARIABLE_DOMAIN,
        .psi_padded_canonical_json(list(variable_name = variable_name))),
      algo = "sha256", serialize = FALSE)) else ""
  if (is.null(variable_name) || anyDuplicated(levels) ||
      !identical(levels, sort(levels, method = "radix")) ||
      !identical(entry$variable_id, expected_id)) {
    stop("Invalid Frequency public factor entry.", call. = FALSE)
  }
  list(
    version = .DSVERT_PSI_PADDED_FACTOR_ENTRY_VERSION,
    variable_name = variable_name,
    variable_id = expected_id,
    levels = as.list(unname(levels)),
    dimension = as.integer(dimension))
}

.dsvert_dp_frequency_claim_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_FREQUENCY_CLAIM_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_analysis_canonical_value_v1(unsigned))))
}

.dsvert_dp_frequency_claim_validate_v1 <- function(
    claim, peer_pins, .verifier = .dsvert_relay_verify_message) {
  required <- c(
    "version", "source_peer_name", "source_identity_pk", "psi_run_sha256",
    "attestation_id", "contract_hash", "source_binding_id", "alignment_hash",
    "alignment_purpose", "dataset_id", "dataset_version",
    "privacy_unit_column", "pinset_id", "capacity_bucket", "factor_entry",
    "factor_entry_sha256", "signature")
  if (!is.list(claim) || is.null(names(claim)) || anyNA(names(claim)) ||
      anyDuplicated(names(claim)) || !setequal(names(claim), required) ||
      !identical(claim$version, .DSVERT_DP_FREQUENCY_CLAIM_VERSION) ||
      !is.function(.verifier)) {
    stop("Invalid signed Frequency Claim.", call. = FALSE)
  }
  pins <- .dsvert_dp_frequency_peer_pins_v1(peer_pins)
  peer <- .dsvert_dp_frequency_peer_name_v1(claim$source_peer_name)
  identity_pk <- tryCatch(
    .dsvert_dp_frequency_identity_pk_v1(
      claim$source_identity_pk, "Claim source identity"),
    error = function(error) stop(
      "Invalid signed Frequency Claim.", call. = FALSE))
  if (!peer %in% names(pins) ||
      !identical(identity_pk, unname(pins[[peer]])) ||
      !identical(claim$pinset_id, .psi_padded_pinset_id(as.list(pins)))) {
    stop("The Frequency Claim source identity is not pinned.", call. = FALSE)
  }
  entry <- .dsvert_dp_frequency_factor_entry_validate_v1(claim$factor_entry)
  for (field in c("psi_run_sha256", "contract_hash", "alignment_hash",
                  "factor_entry_sha256")) {
    .dsvert_dp_frequency_hex_v1(claim[[field]], paste("Claim", field))
  }
  if (!identical(
      claim$factor_entry_sha256, .psi_padded_factor_entry_hash_v1(entry))) {
    stop("Invalid signed Frequency Claim.", call. = FALSE)
  }
  tryCatch({
    .psi_padded_scalar(
      claim$attestation_id, "Frequency attestation id",
      "^attest_[0-9a-f]{64}$")
    .psi_padded_scalar(
      claim$source_binding_id, "Frequency source binding",
      "^source_[0-9a-f]{64}$")
    .psi_padded_scalar(
      claim$pinset_id, "Frequency pinset", "^pinset_[0-9a-f]{64}$")
    .psi_padded_validate_source_public(list(
      alignment_purpose = claim$alignment_purpose,
      dataset_id = claim$dataset_id,
      dataset_version = claim$dataset_version,
      id_column = claim$privacy_unit_column,
      source_binding_id = claim$source_binding_id))
  }, error = function(error) stop(
    "Invalid signed Frequency Claim.", call. = FALSE))
  capacity <- tryCatch(
    .psi_padded_validate_capacity(claim$capacity_bucket),
    error = function(error) stop(
      "Invalid signed Frequency Claim.", call. = FALSE))
  signature <- .dsvert_dp_frequency_signature_v1(claim$signature)
  normalized <- claim
  normalized$source_peer_name <- peer
  normalized$source_identity_pk <- identity_pk
  normalized$capacity_bucket <- capacity
  normalized$factor_entry <- entry
  normalized$signature <- signature
  valid <- isTRUE(tryCatch(
    .verifier(
      .dsvert_dp_frequency_claim_message_v1(normalized),
      identity_pk, signature),
    error = function(error) FALSE))
  if (!valid) {
    stop("Frequency Claim signature verification failed.", call. = FALSE)
  }
  normalized
}

.dsvert_dp_frequency_claim_v1 <- function(
    data, variable_name, peer_name, identity, peer_pins,
    .registry_verifier = .dsvert_relay_verify_message,
    .signer = .dsvert_relay_sign_message) {
  pins <- .dsvert_dp_frequency_peer_pins_v1(peer_pins)
  peer_name <- .dsvert_dp_frequency_peer_name_v1(peer_name)
  if (!peer_name %in% names(pins) || !is.list(identity) ||
      is.null(identity$identity_pk) || is.null(identity$identity_sk) ||
      !is.function(.registry_verifier) || !is.function(.signer)) {
    stop("Invalid Frequency Claim source identity.", call. = FALSE)
  }
  identity_pk <- tryCatch(
    .dsvert_dp_frequency_identity_pk_v1(
      identity$identity_pk, "Claim source identity"),
    error = function(error) NULL)
  if (is.null(identity_pk) ||
      !identical(identity_pk, unname(pins[[peer_name]]))) {
    stop("The Frequency Claim source identity is not pinned.", call. = FALSE)
  }
  variable_name <- tryCatch(
    .psi_padded_factor_text_v1(variable_name, "variable name"),
    error = function(error) stop(
      "Invalid Frequency public factor variable.", call. = FALSE))
  registry <- .psi_padded_validate_factor_registry_v1(
    data,
    expected_peer_name = peer_name,
    expected_identity_pk = identity_pk,
    .verifier = .registry_verifier,
    metadata_only = TRUE)
  matches <- vapply(registry$entries, function(entry) {
    identical(entry$variable_name, variable_name)
  }, logical(1L))
  if (sum(matches) != 1L) {
    stop("The requested Frequency public factor is not declared.",
         call. = FALSE)
  }
  entry <- .dsvert_dp_frequency_factor_entry_validate_v1(
    registry$entries[[which(matches)]])
  attestation <- attr(
    data, .PSI_PADDED_ATTESTATION_ATTRIBUTE, exact = TRUE)$public
  alignment <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  psi_run_sha256 <- .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_PSI_RUN_DOMAIN,
    list(alignment = alignment, attestation = attestation))
  unsigned <- list(
    version = .DSVERT_DP_FREQUENCY_CLAIM_VERSION,
    source_peer_name = peer_name,
    source_identity_pk = identity_pk,
    psi_run_sha256 = psi_run_sha256,
    attestation_id = attestation$attestation_id,
    contract_hash = attestation$contract_hash,
    source_binding_id = attestation$source_binding_id,
    alignment_hash = alignment$hash,
    alignment_purpose = attestation$alignment_purpose,
    dataset_id = attestation$dataset_id,
    dataset_version = attestation$dataset_version,
    privacy_unit_column = attestation$id_column,
    pinset_id = attestation$pinset_id,
    capacity_bucket = attestation$capacity_bucket,
    factor_entry = entry,
    factor_entry_sha256 = .psi_padded_factor_entry_hash_v1(entry))
  signature <- .signer(
    .dsvert_dp_frequency_claim_message_v1(unsigned), identity$identity_sk)
  .dsvert_dp_frequency_claim_validate_v1(
    c(unsigned, list(signature = signature)), pins, .verifier = function(
        message, signed_identity_pk, signed_signature) {
      identical(signed_identity_pk, identity_pk) &&
        identical(signed_signature, signature) &&
        identical(message, .dsvert_dp_frequency_claim_message_v1(unsigned))
    })
}
