# Internal Count analysis compiler.
#
# The compiler is deliberately stateless.  Callers supply an already validated
# configuration, a sampler planner and receipt signing/verification functions.
# The canonical snapshot helper derives its key from the persistent identity.
# PSI run evidence authorizes receipts but is not part of the semantic artifact.

.DSVERT_DP_COUNT_CONFIG_VERSION <- "dsvert-dp-count-config-v1"
.DSVERT_DP_COUNT_RECEIPT_VERSION <- "dsvert-dp-count-receipt-v1"
.DSVERT_DP_COUNT_RECEIPT_DOMAIN <- "dsVert/dp-count/receipt/v1|"
.DSVERT_DP_COUNT_CONFIG_DOMAIN <- "dsVert/dp-count/config/v1|"
.DSVERT_DP_COUNT_MEMBERSHIP_DOMAIN <- "dsVert/dp-count/membership/v1|"
.DSVERT_DP_COUNT_ALIGNMENT_DOMAIN <- "dsVert/dp-count/alignment/v1|"
.DSVERT_DP_COUNT_ALIGNMENT_VERSION <- "dsvert-count-alignment-v1"
.DSVERT_DP_COUNT_PSI_RUN_DOMAIN <- "dsVert/dp-count/psi-run/v1|"

.dsvert_dp_count_hash_v1 <- function(domain, value) {
  digest::digest(
    charToRaw(paste0(
      domain,
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(value)))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_dp_count_hash_scalar_v1 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid Count ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_dp_count_peer_name_v1 <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", value)) {
    stop("Invalid Count peer name.", call. = FALSE)
  }
  value
}

.dsvert_dp_count_positive_integer_v1 <- function(value, what,
                                                  maximum = Inf) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < 1 || value != floor(value) ||
      value > maximum) {
    stop("Invalid Count ", what, ".", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_dp_count_decimal_text <- function(value) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < 0) {
    stop("Invalid Count exact decimal value.", call. = FALSE)
  }
  sprintf("%.17g", as.numeric(value))
}

.dsvert_dp_count_decimal_rational_v1 <- function(value) {
  text <- if (is.character(value) && length(value) == 1L && !is.na(value)) {
    value
  } else {
    .dsvert_dp_count_decimal_text(value)
  }
  if (nchar(text, type = "bytes") > 1024L) {
    stop("Invalid Count exact decimal value.", call. = FALSE)
  }
  match <- regexec(
    "^([0-9]+)(?:\\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$",
    text, perl = TRUE)
  parts <- regmatches(text, match)[[1L]]
  if (!length(parts)) {
    stop("Invalid Count exact decimal value.", call. = FALSE)
  }
  fraction <- if (length(parts) >= 3L && nzchar(parts[[3L]])) {
    parts[[3L]]
  } else {
    ""
  }
  exponent <- if (length(parts) >= 4L && nzchar(parts[[4L]])) {
    suppressWarnings(as.integer(parts[[4L]]))
  } else {
    0L
  }
  if (is.na(exponent) || abs(exponent) > 4096L) {
    stop("Invalid Count exact decimal value.", call. = FALSE)
  }
  coefficient <- sub("^0+(?=[0-9])", "", paste0(parts[[2L]], fraction),
                     perl = TRUE)
  power <- exponent - nchar(fraction, type = "bytes")
  numerator <- openssl::bignum(coefficient)
  denominator <- openssl::bignum(1)
  if (power >= 0L) {
    numerator <- numerator * openssl::bignum(10)^power
  } else {
    denominator <- denominator * openssl::bignum(10)^(-power)
  }
  list(numerator = numerator, denominator = denominator)
}

.dsvert_dp_count_integer_text_v1 <- function(value, allow_zero = FALSE) {
  is.character(value) && length(value) == 1L && !is.na(value) &&
    nchar(value, type = "bytes") <= 4096L &&
    grepl(if (isTRUE(allow_zero)) "^(0|[1-9][0-9]*)$" else
      "^[1-9][0-9]*$", value)
}

.dsvert_dp_count_rational_leq_v1 <- function(
    numerator, denominator, bound) {
  numerator <- openssl::bignum(numerator)
  denominator <- openssl::bignum(denominator)
  numerator * bound$denominator <= bound$numerator * denominator
}

.dsvert_dp_count_config_validate_v1 <- function(config) {
  fields <- c(
    "version", "domain", "cohort_id", "dataset_id", "dataset_version",
    "privacy_unit_column", "alignment_purpose", "max_records_per_unit",
    "overflow_policy", "privacy", "calibration", "peer_pins",
    "backend_build_sha256", "transport_chunk_coordinates")
  if (!is.list(config) || is.null(names(config)) || anyNA(names(config)) ||
      anyDuplicated(names(config)) || !setequal(names(config), fields) ||
      !identical(config$version, .DSVERT_DP_COUNT_CONFIG_VERSION)) {
    stop("Invalid Count configuration.", call. = FALSE)
  }
  for (field in c(
      "domain", "cohort_id", "dataset_id", "dataset_version",
      "alignment_purpose")) {
    .dsvert_dp_analysis_scalar_id(config[[field]], paste("Count", field))
  }
  if (!is.character(config$privacy_unit_column) ||
      length(config$privacy_unit_column) != 1L ||
      is.na(config$privacy_unit_column) ||
      !grepl("^[A-Za-z._][A-Za-z0-9._]{0,127}$",
             config$privacy_unit_column)) {
    stop("Invalid Count privacy-unit column.", call. = FALSE)
  }
  records <- .dsvert_dp_count_positive_integer_v1(
    config$max_records_per_unit, "maximum records per privacy unit",
    .Machine$integer.max)
  if (!identical(records, 1) ||
      !identical(config$overflow_policy, "reject_operation")) {
    stop("Count requires one aligned record per privacy unit.",
         call. = FALSE)
  }
  numeric_scalar <- function(value) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value)
  }
  privacy <- config$privacy
  calibration <- config$calibration
  if (!is.list(privacy) || !identical(sort(names(privacy)),
                                      c("delta", "epsilon")) ||
      !is.list(calibration) ||
      !identical(names(calibration), "implementation_delta") ||
      !numeric_scalar(privacy$epsilon) || privacy$epsilon <= 0 ||
      !numeric_scalar(privacy$delta) || privacy$delta <= 0 ||
      privacy$delta >= 1 ||
      !numeric_scalar(calibration$implementation_delta) ||
      calibration$implementation_delta <= 0) {
    stop("Invalid Count privacy parameters.", call. = FALSE)
  }
  implementation <- .dsvert_dp_count_decimal_rational_v1(
    .dsvert_dp_count_decimal_text(calibration$implementation_delta))
  total <- .dsvert_dp_count_decimal_rational_v1(
    .dsvert_dp_count_decimal_text(privacy$delta))
  if (!.dsvert_dp_count_rational_leq_v1(
      as.character(implementation$numerator),
      as.character(implementation$denominator), total)) {
    stop("Count implementation delta exceeds the total privacy delta.",
         call. = FALSE)
  }
  pins <- config$peer_pins
  if (!is.character(pins) || length(pins) < 2L || length(pins) > 4096L ||
      is.null(names(pins)) || anyNA(names(pins)) ||
      anyDuplicated(names(pins)) || any(!nzchar(names(pins))) ||
      any(!vapply(names(pins), function(peer) {
        tryCatch({
          .dsvert_dp_count_peer_name_v1(peer)
          TRUE
        }, error = function(error) FALSE)
      }, logical(1L)))) {
    stop("Invalid Count peer pins.", call. = FALSE)
  }
  normalized <- tryCatch(vapply(pins, function(pin) {
    .dsvert_relay_normalize_identity_pk(pin)
  }, character(1L)), error = function(error) character())
  if (length(normalized) != length(pins) || anyDuplicated(normalized)) {
    stop("Invalid Count peer pins.", call. = FALSE)
  }
  names(normalized) <- names(pins)
  normalized <- normalized[order(names(normalized), method = "radix")]
  .dsvert_dp_count_hash_scalar_v1(
    config$backend_build_sha256, "backend build digest")
  chunk <- .dsvert_dp_count_positive_integer_v1(
    config$transport_chunk_coordinates, "transport chunk size",
    .Machine$integer.max)

  result <- config
  result$max_records_per_unit <- records
  result$privacy <- list(
    delta = as.numeric(privacy$delta), epsilon = as.numeric(privacy$epsilon))
  result$calibration <- list(
    implementation_delta = as.numeric(calibration$implementation_delta))
  result$peer_pins <- normalized
  result$transport_chunk_coordinates <- chunk
  result[sort(names(result), method = "radix")]
}

.dsvert_dp_count_config_hash_v1 <- function(config) {
  config <- .dsvert_dp_count_config_validate_v1(config)
  config$peer_pins <- as.list(config$peer_pins)
  .dsvert_dp_count_hash_v1(.DSVERT_DP_COUNT_CONFIG_DOMAIN, config)
}

.dsvert_dp_count_plan_certificate_validate_v1 <- function(
    certificate, config = NULL) {
  fields <- c(
    "version", "sampler", "bernoulli_bits", "stop_numerator",
    "max_geometric_steps", "sensitivity_steps", "coordinate_count",
    "epsilon_effective_upper_numerator",
    "epsilon_effective_upper_denominator",
    "implementation_delta_numerator", "implementation_delta_denominator",
    "implementation_delta_bound", "accounting", "bernoulli_trials",
    "aes_blocks")
  scalar_integer <- function(value, expected = NULL) {
    valid <- is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && value == floor(value)
    isTRUE(valid) &&
      (is.null(expected) || identical(as.numeric(value), expected))
  }
  if (!is.list(certificate) || is.null(names(certificate)) ||
      anyNA(names(certificate)) || anyDuplicated(names(certificate)) ||
      !setequal(names(certificate), fields) ||
      !identical(certificate$version,
                 "dsvert-joint-dp-laplace-plan-v2") ||
      !identical(certificate$sampler,
                 .DSVERT_DP_ANALYSIS_COUNT_TV_SAMPLER) ||
      !scalar_integer(certificate$bernoulli_bits, 8) ||
      !.dsvert_dp_count_integer_text_v1(certificate$stop_numerator) ||
      openssl::bignum(certificate$stop_numerator) >= openssl::bignum(2)^8L ||
      !.dsvert_dp_count_integer_text_v1(certificate$sensitivity_steps) ||
      !identical(certificate$sensitivity_steps, "1") ||
      !scalar_integer(certificate$coordinate_count, 1) ||
      !.dsvert_dp_count_integer_text_v1(
        certificate$epsilon_effective_upper_numerator,
        allow_zero = TRUE) ||
      !.dsvert_dp_count_integer_text_v1(
        certificate$epsilon_effective_upper_denominator) ||
      !.dsvert_dp_count_integer_text_v1(
        certificate$implementation_delta_numerator) ||
      !.dsvert_dp_count_integer_text_v1(
        certificate$implementation_delta_denominator) ||
      !is.character(certificate$implementation_delta_bound) ||
      length(certificate$implementation_delta_bound) != 1L ||
      is.na(certificate$implementation_delta_bound) ||
      !identical(certificate$implementation_delta_bound, paste0(
        certificate$implementation_delta_numerator, "/",
        certificate$implementation_delta_denominator)) ||
      !is.character(certificate$accounting) ||
      length(certificate$accounting) != 1L ||
      is.na(certificate$accounting) || !nzchar(certificate$accounting)) {
    stop("The Count planner returned an invalid exact certificate.",
         call. = FALSE)
  }
  for (field in c(
      "max_geometric_steps", "bernoulli_trials", "aes_blocks")) {
    .dsvert_dp_count_positive_integer_v1(
      certificate[[field]], paste("planner", field), 4096^2)
  }
  if (certificate$max_geometric_steps > 4096) {
    stop("The Count planner returned an invalid exact certificate.",
         call. = FALSE)
  }
  if (!is.null(config)) {
    config <- .dsvert_dp_count_config_validate_v1(config)
    epsilon_bound <- .dsvert_dp_count_decimal_rational_v1(
      .dsvert_dp_count_decimal_text(config$privacy$epsilon))
    implementation_bound <- .dsvert_dp_count_decimal_rational_v1(
      .dsvert_dp_count_decimal_text(
        config$calibration$implementation_delta))
    total_bound <- .dsvert_dp_count_decimal_rational_v1(
      .dsvert_dp_count_decimal_text(config$privacy$delta))
    if (!.dsvert_dp_count_rational_leq_v1(
        certificate$epsilon_effective_upper_numerator,
        certificate$epsilon_effective_upper_denominator, epsilon_bound)) {
      stop("The Count effective epsilon certificate exceeds epsilon.",
           call. = FALSE)
    }
    if (!.dsvert_dp_count_rational_leq_v1(
        certificate$implementation_delta_numerator,
        certificate$implementation_delta_denominator,
        implementation_bound)) {
      stop("The Count implementation delta certificate exceeds calibration.",
           call. = FALSE)
    }
    if (!.dsvert_dp_count_rational_leq_v1(
        certificate$implementation_delta_numerator,
        certificate$implementation_delta_denominator, total_bound)) {
      stop("The Count total delta certificate exceeds privacy delta.",
           call. = FALSE)
    }
  }
  .dsvert_dp_canonical_query_value(certificate)
}

.dsvert_dp_count_plan_certificate_v1 <- function(plan, config) {
  operational_fields <- c("capability_available", "unavailable_reason")
  if (!is.list(plan) || is.null(names(plan)) || anyNA(names(plan)) ||
      anyDuplicated(names(plan)) ||
      !all(operational_fields %in% names(plan)) ||
      !is.logical(plan$capability_available) ||
      length(plan$capability_available) != 1L ||
      is.na(plan$capability_available) ||
      !is.character(plan$unavailable_reason) ||
      length(plan$unavailable_reason) != 1L ||
      is.na(plan$unavailable_reason) ||
      (!isTRUE(plan$capability_available) && !nzchar(plan$unavailable_reason))) {
    stop("The Count planner returned an invalid exact certificate.",
         call. = FALSE)
  }
  certificate <- plan[setdiff(names(plan), operational_fields)]
  .dsvert_dp_count_plan_certificate_validate_v1(certificate, config)
}

.dsvert_dp_count_membership_commitment_v1 <- function(
    data, config, peer_name) {
  identifiers <- .dsvert_canonical_label_values(
    .subset2(data, config$privacy_unit_column),
    "Count privacy-unit identifiers",
    allow_na = FALSE, allow_blank = FALSE)
  if (anyNA(identifiers) || any(!nzchar(identifiers)) ||
      anyDuplicated(identifiers)) {
    stop("Count requires one aligned record per privacy unit.",
         call. = FALSE)
  }
  membership <- list(
    version = "dsvert-dp-count-membership-v1",
    members = as.list(sort(identifiers, method = "radix")))
  snapshot_sha256 <- digest::digest(
    charToRaw(paste0(
      .DSVERT_DP_COUNT_MEMBERSHIP_DOMAIN,
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(membership)))),
    algo = "sha256", serialize = FALSE)
  alignment_sha256 <- .dsvert_dp_count_hash_v1(
    .DSVERT_DP_COUNT_ALIGNMENT_DOMAIN,
    list(
      version = .DSVERT_DP_COUNT_ALIGNMENT_VERSION,
      alignment_purpose = config$alignment_purpose,
      membership_sha256 = snapshot_sha256))
  .dsvert_dp_analysis_snapshot_commitment_v1(list(
    domain = config$domain,
    cohort_id = config$cohort_id,
    owner_identity_pk = unname(config$peer_pins[[peer_name]]),
    dataset_id = config$dataset_id,
    dataset_version = config$dataset_version,
    snapshot_sha256 = snapshot_sha256,
    alignment_version = .DSVERT_DP_COUNT_ALIGNMENT_VERSION,
    alignment_sha256 = alignment_sha256))
}

.dsvert_dp_count_local_draft_v1 <- function(
    data, config, peer_name,
    .planner = .dsvert_joint_dp_laplace_plan_v2,
    .alignment_validator = .psi_validate_alignment_manifest,
    .attestation_validator = .psi_padded_validate_persistent_attestation) {
  config <- .dsvert_dp_count_config_validate_v1(config)
  peer_name <- .dsvert_dp_count_peer_name_v1(peer_name)
  if (!peer_name %in% names(config$peer_pins)) {
    stop("The Count peer is not pinned by the configuration.",
         call. = FALSE)
  }
  if (!is.function(.planner) || !is.function(.alignment_validator) ||
      !is.function(.attestation_validator)) {
    stop("Invalid Count compiler dependency.", call. = FALSE)
  }
  alignment <- .alignment_validator(data)
  attestation <- .attestation_validator(data)
  expected_alignment <- c("version", "hash", "n", "id_col")
  if (!is.list(alignment) || is.null(names(alignment)) ||
      !setequal(names(alignment), expected_alignment) ||
      !identical(alignment$version, .PSI_ALIGNMENT_VERSION) ||
      !is.character(alignment$hash) || length(alignment$hash) != 1L ||
      is.na(alignment$hash) || !grepl("^[0-9a-f]{64}$", alignment$hash) ||
      !identical(alignment$id_col, config$privacy_unit_column) ||
      !identical(as.numeric(alignment$n), as.numeric(nrow(data)))) {
    stop("The Count PSI alignment does not match the configuration.",
         call. = FALSE)
  }
  expected_pinset <- .psi_padded_pinset_id(as.list(config$peer_pins))
  attestation_fields <- c(
    "attestation_version", "alignment_attested", "alignment_protocol",
    "attestation_id", "contract_hash", "policy_id", "alignment_purpose",
    "dataset_id", "dataset_version", "id_column", "source_binding_id",
    "pinset_id", "capacity_bucket", "relay_frame_bytes",
    "inline_max_bytes", "peer_count", "reference_peer", "compute_peers")
  if (!is.list(attestation) || !identical(names(attestation),
                                          attestation_fields) ||
      !identical(attestation$attestation_version, 2L) ||
      !identical(attestation$alignment_attested, TRUE) ||
      !identical(attestation$alignment_protocol,
                 .DSVERT_PSI_PADDED_PROTOCOL) ||
      !identical(attestation$dataset_id, config$dataset_id) ||
      !identical(attestation$dataset_version, config$dataset_version) ||
      !identical(attestation$id_column, config$privacy_unit_column) ||
      !identical(attestation$alignment_purpose,
                 config$alignment_purpose) ||
      !identical(attestation$pinset_id, expected_pinset) ||
      !identical(as.numeric(attestation$peer_count),
                 as.numeric(length(config$peer_pins))) ||
      !attestation$reference_peer %in% names(config$peer_pins) ||
      any(!attestation$compute_peers %in% names(config$peer_pins))) {
    stop("The Count PSI attestation does not match the configuration.",
         call. = FALSE)
  }
  snapshot <- .dsvert_dp_count_membership_commitment_v1(
    data, config, peer_name)
  psi_run <- .dsvert_dp_count_hash_v1(
    .DSVERT_DP_COUNT_PSI_RUN_DOMAIN,
    list(alignment = alignment, attestation = attestation))
  plan <- .planner(
    epsilon = .dsvert_dp_count_decimal_text(config$privacy$epsilon),
    delta = .dsvert_dp_count_decimal_text(
      config$calibration$implementation_delta),
    sensitivity_steps = "1", coordinate_count = 1L,
    bernoulli_bits = 8L, max_steps = 4096L)
  certificate <- .dsvert_dp_count_plan_certificate_v1(plan, config)
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_COUNT_RECEIPT_VERSION,
    peer_name = peer_name,
    peer_identity_pk = unname(config$peer_pins[[peer_name]]),
    config_sha256 = .dsvert_dp_count_config_hash_v1(config),
    psi_run_sha256 = psi_run,
    snapshot_commitment = snapshot,
    sampler_plan = certificate))
}

.dsvert_dp_count_unsigned_receipt_validate_v1 <- function(
    receipt, config = NULL) {
  fields <- c(
    "version", "peer_name", "peer_identity_pk", "config_sha256",
    "psi_run_sha256", "snapshot_commitment", "sampler_plan")
  if (!is.list(receipt) || is.null(names(receipt)) || anyNA(names(receipt)) ||
      anyDuplicated(names(receipt)) || !setequal(names(receipt), fields) ||
      !identical(receipt$version, .DSVERT_DP_COUNT_RECEIPT_VERSION)) {
    stop("Invalid signed Count receipt fields.", call. = FALSE)
  }
  receipt$peer_name <- .dsvert_dp_count_peer_name_v1(receipt$peer_name)
  receipt$peer_identity_pk <- tryCatch(
    .dsvert_relay_normalize_identity_pk(receipt$peer_identity_pk),
    error = function(error) stop("Invalid Count receipt identity.",
                                 call. = FALSE))
  for (field in c(
      "config_sha256", "psi_run_sha256", "snapshot_commitment")) {
    receipt[[field]] <- .dsvert_dp_count_hash_scalar_v1(
      receipt[[field]], paste("receipt", field))
  }
  receipt$sampler_plan <- .dsvert_dp_count_plan_certificate_validate_v1(
    receipt$sampler_plan, config)
  .dsvert_dp_canonical_query_value(receipt)
}

.dsvert_dp_count_receipt_message_v1 <- function(receipt) {
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  unsigned <- .dsvert_dp_count_unsigned_receipt_validate_v1(unsigned)
  charToRaw(paste0(
    .DSVERT_DP_COUNT_RECEIPT_DOMAIN,
    .dsvert_dp_canonical_json(unsigned)))
}

.dsvert_dp_count_signature_v1 <- function(value) {
  decoded <- tryCatch(
    .dsvert_relay_b64url_decode(value, "Count receipt signature"),
    error = function(error) raw(0L))
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      length(decoded) != 64L) {
    stop("Invalid Count receipt signature.", call. = FALSE)
  }
  value
}

.dsvert_dp_count_sign_receipt_v1 <- function(draft, .signer) {
  draft <- .dsvert_dp_count_unsigned_receipt_validate_v1(draft)
  if (!is.function(.signer)) {
    stop("Invalid Count receipt signer.", call. = FALSE)
  }
  signature <- .signer(
    .dsvert_dp_count_receipt_message_v1(draft),
    draft$peer_name, draft$peer_identity_pk)
  .dsvert_dp_count_signature_v1(signature)
  .dsvert_dp_canonical_query_value(c(draft, list(signature = signature)))
}

.dsvert_dp_count_receipt_verify_v1 <- function(
    receipt, config, .verifier = .dsvert_relay_verify_message) {
  fields <- c(
    "version", "peer_name", "peer_identity_pk", "config_sha256",
    "psi_run_sha256", "snapshot_commitment", "sampler_plan", "signature")
  if (!is.list(receipt) || is.null(names(receipt)) || anyNA(names(receipt)) ||
      anyDuplicated(names(receipt)) || !setequal(names(receipt), fields)) {
    stop("Invalid signed Count receipt fields.", call. = FALSE)
  }
  config <- .dsvert_dp_count_config_validate_v1(config)
  unsigned <- .dsvert_dp_count_unsigned_receipt_validate_v1(
    receipt[setdiff(names(receipt), "signature")], config)
  signature <- .dsvert_dp_count_signature_v1(receipt$signature)
  if (!identical(unsigned$config_sha256,
                 .dsvert_dp_count_config_hash_v1(config))) {
    stop("The Count receipt targets a different configuration.",
         call. = FALSE)
  }
  if (!unsigned$peer_name %in% names(config$peer_pins) ||
      !identical(unsigned$peer_identity_pk,
                 unname(config$peer_pins[[unsigned$peer_name]]))) {
    stop("The Count receipt identity is not pinned.", call. = FALSE)
  }
  if (!is.function(.verifier)) {
    stop("Invalid Count receipt verifier.", call. = FALSE)
  }
  message <- .dsvert_dp_count_receipt_message_v1(unsigned)
  verified <- if (identical(.verifier, .dsvert_relay_verify_message)) {
    .verifier(message, unsigned$peer_identity_pk, signature)
  } else {
    .verifier(message, unsigned$peer_identity_pk, signature,
              unsigned$peer_name)
  }
  if (!isTRUE(verified)) {
    stop("Count receipt signature verification failed.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(c(unsigned, list(signature = signature)))
}

.dsvert_dp_count_compile_v1 <- function(
    receipts, config, .verifier = .dsvert_relay_verify_message) {
  config <- .dsvert_dp_count_config_validate_v1(config)
  k <- length(config$peer_pins)
  if (!is.list(receipts) || length(receipts) != k) {
    stop("Count requires exactly one signed receipt per pinned peer.",
         call. = FALSE)
  }
  verified <- lapply(receipts, .dsvert_dp_count_receipt_verify_v1,
                     config = config, .verifier = .verifier)
  peers <- vapply(verified, `[[`, character(1L), "peer_name")
  if (anyDuplicated(peers) || !setequal(peers, names(config$peer_pins))) {
    stop("Invalid Count receipt coverage.", call. = FALSE)
  }
  names(verified) <- peers
  verified <- verified[names(config$peer_pins)]
  if (length(unique(vapply(
      verified, `[[`, character(1L), "config_sha256"))) != 1L) {
    stop("Count receipts disagree on their configuration.", call. = FALSE)
  }
  if (length(unique(vapply(
      verified, `[[`, character(1L), "psi_run_sha256"))) != 1L) {
    stop("Count receipts disagree on the PSI run.", call. = FALSE)
  }
  plan <- verified[[1L]]$sampler_plan
  if (!all(vapply(verified, function(receipt) {
    identical(receipt$sampler_plan, plan)
  }, logical(1L)))) {
    stop("Count receipts disagree on the sampler certificate.",
         call. = FALSE)
  }

  owner_snapshots <- stats::setNames(lapply(verified, function(receipt) {
    list(
      version = .DSVERT_DP_ANALYSIS_SNAPSHOT_VERSION,
      dataset_id = config$dataset_id,
      dataset_version = config$dataset_version,
      snapshot_commitment = receipt$snapshot_commitment)
  }), vapply(verified, `[[`, character(1L), "peer_identity_pk"))
  owner_snapshots <- owner_snapshots[
    order(names(owner_snapshots), method = "radix")]
  identities <- sort(names(owner_snapshots), method = "radix")
  constraints <- list(
    version = "dsvert-contribution-constraints-v1",
    policy_sha256 = .dsvert_dp_count_hash_v1(
      "dsVert/dp-count/contribution/v1|", list(
        max_records_per_unit = config$max_records_per_unit,
        overflow_policy = config$overflow_policy)))
  semantic <- list(
    version = .DSVERT_DP_ANALYSIS_SEMANTIC_VERSION,
    domain = config$domain,
    cohort_id = config$cohort_id,
    owner_snapshots = owner_snapshots,
    noise_authorities = as.list(unname(identities[1:2])),
    analysis = list(
      primitive = "joint-dp-laplace-v2",
      formula = NULL,
      effective_arguments = list(
        statistic = "aligned_privacy_unit_count",
        owner_combination = "vertical_membership_once_v1",
        sampler_plan = plan)),
    privacy = list(
      version = "dsvert-per-analysis-dp-v1",
      adjacency = "add_remove_patient",
      privacy_unit = "patient",
      contribution = list(
        version = "dsvert-contribution-policy-v1",
        max_records_per_unit = config$max_records_per_unit,
        overflow_policy = config$overflow_policy,
        constraints = constraints),
      mechanism = list(
        family = "discrete_laplace",
        version = .DSVERT_DP_ANALYSIS_COUNT_TV_MECHANISM,
        sensitivity = list(
          version = "dsvert-sensitivity-v1", norm = "l1", value = 1),
        calibration = list(
          version = "dsvert-calibration-v1",
          noise_scale = 1 / config$privacy$epsilon,
          sampler = .DSVERT_DP_ANALYSIS_COUNT_TV_SAMPLER,
          implementation_delta =
            config$calibration$implementation_delta),
        randomness = list(
          version = "dsvert-randomness-plan-v1",
          lanes = list(
            final_noise = list(
              version = "dsvert-randomness-lane-v1",
              purpose = "privatize_final_vector",
              primitive = .DSVERT_DP_ANALYSIS_COUNT_TV_SAMPLER,
              coordinates = 1)))),
      epsilon = config$privacy$epsilon,
      delta = config$privacy$delta),
    numeric = list(
      version = "dsvert-numeric-semantics-v1",
      value_bits = 127,
      fractional_bits = 0,
      rounding = "toward_zero",
      overflow = "reject",
      sampler_encoding = "aes128ctr_integer_coordinate_v2",
      output_encoding = "twos_complement_integer_v1"),
    public_shape = list(count = 1))
  execution <- list(
    version = .DSVERT_DP_ANALYSIS_EXECUTION_VERSION,
    peer_pins = as.list(config$peer_pins),
    backend = list(
      kernel = "joint-dp-laplace-v2",
      ring = "ring127",
      build_sha256 = config$backend_build_sha256),
    transport = list(
      chunk_coordinates = config$transport_chunk_coordinates))
  .dsvert_dp_analysis_contract_v1(semantic, execution)
}
