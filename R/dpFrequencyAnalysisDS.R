# K-wide compiler for one fixed-domain categorical Frequency analysis.

.DSVERT_DP_FREQUENCY_CONFIG_VERSION <- "dsvert-dp-frequency-config-v1"
.DSVERT_DP_FREQUENCY_RECEIPT_VERSION <- "dsvert-dp-frequency-receipt-v1"
.DSVERT_DP_FREQUENCY_CONFIG_DOMAIN <- "dsVert/dp-frequency/config/v1|"
.DSVERT_DP_FREQUENCY_RECEIPT_DOMAIN <- "dsVert/dp-frequency/receipt/v1|"
.DSVERT_DP_FREQUENCY_CLAIM_HASH_DOMAIN <- "dsVert/dp-frequency/source-claim/v1|"
.DSVERT_DP_FREQUENCY_RUNTIME_DOMAIN <- "dsVert/dp-frequency/runtime-protocol/v1|"
.DSVERT_DP_FREQUENCY_MEMBERSHIP_DOMAIN <- "dsVert/dp-frequency/membership/v1|"
.DSVERT_DP_FREQUENCY_VECTOR_DOMAIN <- "dsVert/dp-frequency/fixed-categorical-vector/v1|"
.DSVERT_DP_FREQUENCY_ALIGNMENT_DOMAIN <- "dsVert/dp-frequency/semantic-alignment/v1|"

.dsvert_dp_frequency_number_v1 <- function(
    value, what, lower, upper, integer = FALSE) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < lower || value > upper ||
      (isTRUE(integer) && value != floor(value))) {
    stop("Invalid Frequency ", what, ".", call. = FALSE)
  }
  if (isTRUE(integer)) as.numeric(value) else as.numeric(value)
}

.dsvert_dp_frequency_settings_v1 <- function(settings) {
  fields <- c("domain", "cohort_id", "source_owner",
              "coordinate_upper_bound", "privacy", "calibration")
  if (!is.list(settings) || is.null(names(settings)) || anyNA(names(settings)) ||
      anyDuplicated(names(settings)) || !setequal(names(settings), fields)) {
    stop("Invalid Frequency server settings.", call. = FALSE)
  }
  for (field in c("domain", "cohort_id")) {
    .dsvert_dp_analysis_scalar_id(settings[[field]], paste("Frequency", field))
  }
  owner <- settings$source_owner
  if (!is.list(owner) || is.null(names(owner)) || anyNA(names(owner)) ||
      anyDuplicated(names(owner)) || !setequal(
        names(owner), c("peer_name", "identity_pk"))) {
    stop("Invalid Frequency source owner.", call. = FALSE)
  }
  owner <- list(
    peer_name = .dsvert_dp_frequency_peer_name_v1(owner$peer_name),
    identity_pk = .dsvert_dp_frequency_identity_pk_v1(
      owner$identity_pk, "source owner"))
  privacy <- settings$privacy
  calibration <- settings$calibration
  if (!is.list(privacy) || is.null(names(privacy)) || anyNA(names(privacy)) ||
      anyDuplicated(names(privacy)) || !setequal(names(privacy),
      c("adjacency", "epsilon", "delta")) ||
      !privacy$adjacency %in%
        c("add_remove_patient", "replace_one_fixed_cohort") ||
      !is.list(calibration) ||
      !identical(names(calibration), "implementation_delta")) {
    stop("Invalid Frequency privacy parameters.", call. = FALSE)
  }
  epsilon <- .dsvert_dp_frequency_number_v1(
    privacy$epsilon, "epsilon", .Machine$double.xmin, 8)
  delta <- .dsvert_dp_frequency_number_v1(
    privacy$delta, "delta", .Machine$double.xmin, 1 - .Machine$double.eps)
  implementation <- .dsvert_dp_frequency_number_v1(
    calibration$implementation_delta, "implementation delta",
    .Machine$double.xmin, delta)
  list(
    domain = settings$domain, cohort_id = settings$cohort_id,
    source_owner = owner,
    coordinate_upper_bound = .dsvert_dp_frequency_number_v1(
      settings$coordinate_upper_bound, "coordinate upper bound", 1, 1e6,
      integer = TRUE),
    privacy = list(adjacency = privacy$adjacency, epsilon = epsilon,
                   delta = delta),
    calibration = list(implementation_delta = implementation))
}

.dsvert_dp_frequency_sensitivity_v1 <- function(adjacency, profile) {
  l1 <- if (identical(adjacency, "replace_one_fixed_cohort")) 2 else 1
  if (isTRUE(profile$gaussian)) sqrt(l1) else l1
}

.dsvert_dp_frequency_plan_summary_v1 <- function(config) {
  selection <- config$backend_selection
  required <- c("summary", "selected_request", "selected_plan",
                "selected_accuracy_certificate", "selection_certificate")
  if (!is.list(selection) || is.null(names(selection)) ||
      anyNA(names(selection)) || anyDuplicated(names(selection)) ||
      !setequal(names(selection), required)) {
    stop("Invalid Frequency backend selection.", call. = FALSE)
  }
  primitive <- selection$summary$selected_primitive
  profile <- .dsvert_dp_analysis_frequency_profile_v1(primitive)
  if (is.null(profile)) {
    stop("Invalid Frequency backend selection.", call. = FALSE)
  }
  kind <- if (isTRUE(profile$gaussian)) "gaussian" else "convolution"
  candidate <- tryCatch(selection$summary$candidates[[kind]],
                        error = function(error) NULL)
  full_plan <- selection$selected_plan
  plan_sha256 <- .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_ANALYSIS_FREQUENCY_PLAN_DOMAIN_V1, full_plan)
  request_sha256 <- .dsvert_dp_frequency_hash_v1(
    profile$request_domain, selection$selected_request)
  allocated <- tryCatch(
    .dsvert_dp_analysis_frequency_decimal_fraction_v1(
      selection$selected_request$delta), error = function(error) NULL)
  fraction <- function(numerator, denominator) list(
    numerator = as.character(numerator), denominator = as.character(denominator))
  implementation <- if (isTRUE(profile$gaussian)) fraction(
    full_plan$per_peer_implementation_delta_numerator,
    full_plan$per_peer_implementation_delta_denominator) else fraction(
    full_plan$implementation_delta_numerator,
    full_plan$implementation_delta_denominator)
  core <- if (isTRUE(profile$gaussian)) fraction(
    full_plan$core_delta_numerator, full_plan$core_delta_denominator) else
      fraction("0", "1")
  maximum_noise <- if (isTRUE(profile$gaussian)) {
    full_plan$maximum_noise_magnitude_per_peer
  } else full_plan$maximum_noise_magnitude
  if (is.null(candidate) || is.null(allocated) ||
      !identical(candidate$full_plan_sha256, plan_sha256) ||
      !identical(candidate$planner_request_sha256, request_sha256) ||
      !identical(candidate$accuracy_certificate_sha256,
        .dsvert_dp_frequency_hash_v1(
          .DSVERT_DP_ANALYSIS_FREQUENCY_ACCURACY_DOMAIN_V1,
          selection$selected_accuracy_certificate)) ||
      !identical(selection$summary$selection_certificate_sha256,
        .dsvert_dp_frequency_hash_v1(
          .DSVERT_DP_ANALYSIS_FREQUENCY_SELECTION_DOMAIN_V1,
          selection$selection_certificate))) {
    stop("Invalid Frequency backend selection.", call. = FALSE)
  }
  no_wrap <- list(
    version = "dsvert-frequency-ring128-no-wrap-v1",
    coordinate_upper_bound = format(
      config$coordinate_upper_bound, scientific = FALSE, trim = TRUE),
    maximum_noise_per_peer = maximum_noise,
    maximum_noise_release = as.character(
      2 * openssl::bignum(maximum_noise)))
  plan <- list(
    version = "dsvert-frequency-plan-summary-v1",
    physical_plan_version = profile$plan,
    full_plan_sha256 = plan_sha256,
    planner_request_sha256 = request_sha256,
    coordinate_order_sha256 =
      .dsvert_dp_analysis_frequency_coordinate_order_sha256_v1(
        config$factor_domain$levels),
    d = config$factor_domain$dimension,
    chunk_coordinates = min(profile$max_chunk_coordinates,
                            config$factor_domain$dimension),
    allocated_delta = fraction(allocated$numerator, allocated$denominator),
    core_delta = core, implementation_delta = implementation,
    maximum_noise_per_peer = maximum_noise,
    no_wrap_sha256 = .dsvert_dp_frequency_hash_v1(
      "dsVert/frequency/ring128-no-wrap/v1|", no_wrap),
    profile_sha256 = .dsvert_dp_frequency_hash_v1(
      "dsVert/frequency/physical-profile/v1|", profile),
    backend_selection = selection$summary)
  privacy <- list(
    adjacency = config$privacy$adjacency,
    epsilon = config$privacy$epsilon, delta = config$privacy$delta)
  sensitivity <- list(value = .dsvert_dp_frequency_sensitivity_v1(
    config$privacy$adjacency, profile))
  tryCatch(.dsvert_dp_analysis_frequency_plan_validate_v1(
    plan, profile, privacy, sensitivity, config$factor_domain$dimension,
    config$coordinate_upper_bound, config$calibration),
    error = function(error) stop(
      "Invalid Frequency backend selection.", call. = FALSE))
  expected_request <- .dsvert_dp_analysis_frequency_candidate_requests_v2(
    privacy, config$calibration, config$factor_domain$dimension)[[kind]]
  if (!identical(
      .dsvert_dp_analysis_canonical_value_v1(selection$selected_request),
      .dsvert_dp_analysis_canonical_value_v1(expected_request)) ||
      !identical(config$transport_chunk_coordinates,
                 plan$chunk_coordinates)) {
    stop("Invalid Frequency backend selection.", call. = FALSE)
  }
  plan
}

.dsvert_dp_frequency_config_validate_v1 <- function(config) {
  fields <- c(
    "version", "domain", "cohort_id", "dataset_id", "dataset_version",
    "privacy_unit_column", "alignment_purpose", "source_owner",
    "source_binding_id", "factor_domain", "factor_entry_sha256",
    "coordinate_upper_bound", "max_records_per_unit",
    "repeated_record_policy", "overflow_policy", "missingness_policy",
    "privacy", "calibration", "peer_pins", "backend_build_sha256",
    "transport_chunk_coordinates", "backend_selection")
  if (!is.list(config) || is.null(names(config)) || anyNA(names(config)) ||
      anyDuplicated(names(config)) || !setequal(names(config), fields) ||
      !identical(config$version, .DSVERT_DP_FREQUENCY_CONFIG_VERSION)) {
    stop("Invalid Frequency configuration.", call. = FALSE)
  }
  pins <- .dsvert_dp_frequency_peer_pins_v1(config$peer_pins)
  entry <- .dsvert_dp_frequency_factor_entry_validate_v1(config$factor_domain)
  settings <- .dsvert_dp_frequency_settings_v1(list(
    domain = config$domain, cohort_id = config$cohort_id,
    source_owner = config$source_owner,
    coordinate_upper_bound = config$coordinate_upper_bound,
    privacy = config$privacy, calibration = config$calibration))
  owner <- settings$source_owner
  if (!owner$peer_name %in% names(pins) ||
      !identical(owner$identity_pk, unname(pins[[owner$peer_name]]))) {
    stop("The Frequency source owner is not pinned.", call. = FALSE)
  }
  tryCatch(.psi_padded_validate_source_public(list(
    alignment_purpose = config$alignment_purpose,
    dataset_id = config$dataset_id, dataset_version = config$dataset_version,
    id_column = config$privacy_unit_column,
    source_binding_id = config$source_binding_id)),
    error = function(error) stop("Invalid Frequency source binding.",
                                 call. = FALSE))
  if (!identical(config$factor_entry_sha256,
      .psi_padded_factor_entry_hash_v1(entry)) ||
      !identical(as.numeric(config$max_records_per_unit), 1) ||
      !identical(config$repeated_record_policy,
        "psi_v4_first_eligible_source_record_per_privacy_unit_v1") ||
      !identical(config$overflow_policy,
        "clip_to_psi_v4_first_eligible_source_record_v1") ||
      !identical(config$missingness_policy,
        "missing_or_out_of_domain_rows_are_ignored")) {
    stop("Invalid Frequency contribution policy.", call. = FALSE)
  }
  .dsvert_dp_frequency_hex_v1(
    config$backend_build_sha256, "backend build digest")
  result <- config
  result$source_owner <- owner
  result$factor_domain <- entry
  result$coordinate_upper_bound <- settings$coordinate_upper_bound
  result$max_records_per_unit <- 1
  result$privacy <- settings$privacy
  result$calibration <- settings$calibration
  result$peer_pins <- pins
  result$transport_chunk_coordinates <- .dsvert_dp_frequency_number_v1(
    config$transport_chunk_coordinates, "transport chunk size", 1,
    .Machine$integer.max, integer = TRUE)
  .dsvert_dp_frequency_plan_summary_v1(result)
  result
}

.dsvert_dp_frequency_config_hash_v1 <- function(config) {
  config <- .dsvert_dp_frequency_config_validate_v1(config)
  config$peer_pins <- as.list(config$peer_pins)
  .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_CONFIG_DOMAIN, config)
}

.dsvert_dp_frequency_claim_hash_v1 <- function(claim, peer_pins, .verifier) {
  claim <- .dsvert_dp_frequency_claim_validate_v1(
    claim, peer_pins, .verifier = .verifier)
  .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_CLAIM_HASH_DOMAIN, claim)
}

.dsvert_dp_frequency_runtime_v1 <- function(.capability) {
  if (!is.function(.capability)) {
    stop("Invalid Frequency runtime capability gate.", call. = FALSE)
  }
  manifest <- .capability("joint_dp_frequency_backend_selection")
  capability <- tryCatch(
    manifest$capabilities$joint_dp_frequency_backend_selection,
    error = function(error) NULL)
  feature_fields <- c(
    "available", "capability_id", "protocol_version", "commands",
    "operations")
  if (!is.list(manifest) || !is.list(capability) ||
      !setequal(names(capability), feature_fields) ||
      anyNA(names(capability)) || anyDuplicated(names(capability)) ||
      !identical(capability$available, TRUE) ||
      !identical(capability$capability_id,
        "joint_dp_frequency_backend_selection_v1") ||
      !identical(capability$protocol_version,
        "dsvert-joint-dp-frequency-backend-selection-v1") ||
      !identical(unname(unlist(capability$commands, use.names = FALSE)),
        "joint-dp-frequency-backend-select-v1") ||
      !identical(unname(unlist(capability$operations, use.names = FALSE)),
        "public-data-free-certified-frequency-backend-selection-v1")) {
    stop("The Frequency runtime capability is unavailable.", call. = FALSE)
  }
  .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_RUNTIME_DOMAIN, manifest)
}

.dsvert_dp_frequency_server_config_v1 <- function(
    claim, peer_pins, settings, backend_build_sha256, backend_selection,
    .verifier) {
  settings <- .dsvert_dp_frequency_settings_v1(settings)
  claim <- .dsvert_dp_frequency_claim_validate_v1(
    claim, peer_pins, .verifier = .verifier)
  if (!identical(settings$source_owner, list(
      peer_name = claim$source_peer_name,
      identity_pk = claim$source_identity_pk))) {
    stop("The Frequency Claim does not match the configured source owner.",
         call. = FALSE)
  }
  profile <- .dsvert_dp_analysis_frequency_profile_v1(
    backend_selection$summary$selected_primitive)
  config <- list(
    version = .DSVERT_DP_FREQUENCY_CONFIG_VERSION,
    domain = settings$domain, cohort_id = settings$cohort_id,
    dataset_id = claim$dataset_id, dataset_version = claim$dataset_version,
    privacy_unit_column = claim$privacy_unit_column,
    alignment_purpose = claim$alignment_purpose,
    source_owner = settings$source_owner,
    source_binding_id = claim$source_binding_id,
    factor_domain = claim$factor_entry,
    factor_entry_sha256 = claim$factor_entry_sha256,
    coordinate_upper_bound = settings$coordinate_upper_bound,
    max_records_per_unit = 1L,
    repeated_record_policy =
      "psi_v4_first_eligible_source_record_per_privacy_unit_v1",
    overflow_policy = "clip_to_psi_v4_first_eligible_source_record_v1",
    missingness_policy = "missing_or_out_of_domain_rows_are_ignored",
    privacy = settings$privacy, calibration = settings$calibration,
    peer_pins = .dsvert_dp_frequency_peer_pins_v1(peer_pins),
    backend_build_sha256 = backend_build_sha256,
    transport_chunk_coordinates = min(
      profile$max_chunk_coordinates, claim$factor_entry$dimension),
    backend_selection = backend_selection)
  .dsvert_dp_frequency_config_validate_v1(config)
}

.dsvert_dp_frequency_snapshot_v1 <- function(
    data, config, peer_name, claim, .registry_verifier) {
  alignment <- .psi_validate_alignment_manifest(data)
  attestation <- .psi_padded_validate_persistent_attestation(data)
  raw_alignment <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  raw_attestation <- attr(
    data, .PSI_PADDED_ATTESTATION_ATTRIBUTE, exact = TRUE)$public
  psi_run <- .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_PSI_RUN_DOMAIN,
    list(alignment = raw_alignment, attestation = raw_attestation))
  expected <- list(
    attestation_id = claim$attestation_id,
    contract_hash = claim$contract_hash,
    source_binding_id = claim$source_binding_id,
    alignment_hash = claim$alignment_hash,
    alignment_purpose = config$alignment_purpose,
    dataset_id = config$dataset_id, dataset_version = config$dataset_version,
    id_column = config$privacy_unit_column,
    pinset_id = .psi_padded_pinset_id(as.list(config$peer_pins)))
  actual <- list(
    attestation_id = attestation$attestation_id,
    contract_hash = attestation$contract_hash,
    source_binding_id = attestation$source_binding_id,
    alignment_hash = alignment$hash,
    alignment_purpose = attestation$alignment_purpose,
    dataset_id = attestation$dataset_id,
    dataset_version = attestation$dataset_version,
    id_column = attestation$id_column, pinset_id = attestation$pinset_id)
  capacity <- tryCatch(.psi_padded_validate_capacity(
    attestation$capacity_bucket), error = function(error) NA_integer_)
  if (!identical(actual, expected) || !identical(psi_run, claim$psi_run_sha256) ||
      nrow(data) > config$coordinate_upper_bound || is.na(capacity) ||
      nrow(data) > capacity) {
    stop("The Frequency PSI run does not match its signed Claim.",
         call. = FALSE)
  }
  identifiers <- .dsvert_canonical_label_values(
    .subset2(data, config$privacy_unit_column),
    "Frequency privacy-unit identifiers", allow_na = FALSE,
    allow_blank = FALSE)
  if (anyNA(identifiers) || any(!nzchar(identifiers)) ||
      anyDuplicated(identifiers)) {
    stop("Invalid Frequency aligned privacy units.", call. = FALSE)
  }
  ordering <- order(identifiers, method = "radix")
  members <- as.list(identifiers[ordering])
  source <- identical(peer_name, config$source_owner$peer_name)
  payload <- if (!source) list(
    version = "dsvert-dp-frequency-membership-v1", members = members) else {
    registry <- .psi_padded_validate_factor_registry_v1(
      data, expected_peer_name = config$source_owner$peer_name,
      expected_identity_pk = config$source_owner$identity_pk,
      .verifier = .registry_verifier, metadata_only = FALSE)
    matches <- vapply(registry$entries, function(entry) {
      identical(entry$variable_id, config$factor_domain$variable_id)
    }, logical(1L))
    index <- which(enc2utf8(names(data)) == config$factor_domain$variable_name)
    if (sum(matches) != 1L || length(index) != 1L ||
        !identical(registry$entries[[which(matches)]], config$factor_domain)) {
      stop("The Frequency factor registry does not match the Claim.",
           call. = FALSE)
    }
    column <- .subset2(data, index)
    level_coordinate <- match(
      enc2utf8(attr(column, "levels", exact = TRUE)),
      unlist(config$factor_domain$levels, use.names = FALSE), nomatch = 0L)
    codes <- unclass(column)
    attributes(codes) <- NULL
    coordinate <- integer(length(codes))
    if (is.integer(codes) || is.double(codes)) {
      valid <- !is.na(codes) & is.finite(codes) &
        codes == trunc(codes) & codes >= 1 &
        codes <= length(level_coordinate)
      coordinate[valid] <- level_coordinate[codes[valid]]
    }
    list(
      version = "dsvert-dp-frequency-fixed-categorical-vector-v1",
      factor_entry_sha256 = config$factor_entry_sha256,
      rows = lapply(ordering, function(row) list(
        privacy_unit = identifiers[[row]],
        coordinate = as.integer(coordinate[[row]]))))
  }
  content_domain <- if (source) .DSVERT_DP_FREQUENCY_VECTOR_DOMAIN else
    .DSVERT_DP_FREQUENCY_MEMBERSHIP_DOMAIN
  snapshot_sha256 <- .dsvert_dp_frequency_hash_v1(content_domain, payload)
  membership_sha256 <- .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_MEMBERSHIP_DOMAIN,
    list(version = "dsvert-dp-frequency-membership-v1", members = members))
  alignment_sha256 <- .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_ALIGNMENT_DOMAIN, list(
      version = "dsvert-dp-frequency-semantic-alignment-v1",
      alignment_purpose = config$alignment_purpose,
      membership_sha256 = membership_sha256,
      source_binding_id = config$source_binding_id))
  list(psi_run_sha256 = psi_run, snapshot_commitment =
    .dsvert_dp_analysis_snapshot_commitment_v1(list(
      domain = config$domain, cohort_id = config$cohort_id,
      owner_identity_pk = unname(config$peer_pins[[peer_name]]),
      dataset_id = config$dataset_id,
      dataset_version = config$dataset_version,
      snapshot_sha256 = snapshot_sha256,
      alignment_version = "dsvert-dp-frequency-semantic-alignment-v1",
      alignment_sha256 = alignment_sha256)))
}

.dsvert_dp_frequency_unsigned_receipt_validate_v1 <- function(receipt) {
  fields <- c(
    "version", "peer_name", "peer_identity_pk", "config_sha256",
    "source_claim_sha256", "psi_run_sha256", "snapshot_commitment")
  if (!is.list(receipt) || is.null(names(receipt)) || anyNA(names(receipt)) ||
      anyDuplicated(names(receipt)) || !setequal(names(receipt), fields) ||
      !identical(receipt$version, .DSVERT_DP_FREQUENCY_RECEIPT_VERSION)) {
    stop("Invalid signed Frequency receipt fields.", call. = FALSE)
  }
  receipt$peer_name <- .dsvert_dp_frequency_peer_name_v1(receipt$peer_name)
  receipt$peer_identity_pk <- tryCatch(
    .dsvert_dp_frequency_identity_pk_v1(
      receipt$peer_identity_pk, "receipt identity"),
    error = function(error) stop("Invalid Frequency receipt identity.",
                                 call. = FALSE))
  for (field in c("config_sha256", "source_claim_sha256", "psi_run_sha256",
                  "snapshot_commitment")) {
    .dsvert_dp_frequency_hex_v1(receipt[[field]], paste("receipt", field))
  }
  receipt
}

.dsvert_dp_frequency_receipt_message_v1 <- function(receipt) {
  unsigned <- .dsvert_dp_frequency_unsigned_receipt_validate_v1(
    receipt[setdiff(names(receipt), "signature")])
  charToRaw(paste0(
    .DSVERT_DP_FREQUENCY_RECEIPT_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_analysis_canonical_value_v1(unsigned))))
}

.dsvert_dp_frequency_sign_receipt_v1 <- function(draft, identity, .signer) {
  draft <- .dsvert_dp_frequency_unsigned_receipt_validate_v1(draft)
  if (!is.list(identity) || is.null(identity$identity_sk) ||
      !is.function(.signer)) {
    stop("Invalid Frequency receipt signer.", call. = FALSE)
  }
  signature <- .signer(
    .dsvert_dp_frequency_receipt_message_v1(draft), identity$identity_sk)
  .dsvert_dp_frequency_signature_v1(signature)
  c(draft, list(signature = signature))
}

.dsvert_dp_frequency_local_compile_v1 <- function(
    source_claim, peer_name, peer_pins, settings, .source_resolver,
    .capability = .dsvert_mpc_require_capabilities, .selector = NULL,
    .registry_verifier = .dsvert_relay_verify_message,
    .signer = .dsvert_relay_sign_message) {
  if (!is.function(.source_resolver) || !is.function(.registry_verifier)) {
    stop("Invalid Frequency compiler dependency.", call. = FALSE)
  }
  pins <- .dsvert_dp_frequency_peer_pins_v1(peer_pins)
  peer_name <- .dsvert_dp_frequency_peer_name_v1(peer_name)
  claim <- .dsvert_dp_frequency_claim_validate_v1(
    source_claim, pins, .verifier = .registry_verifier)
  settings <- .dsvert_dp_frequency_settings_v1(settings)
  owner <- settings$source_owner
  if (!owner$peer_name %in% names(pins) ||
      !identical(owner$identity_pk, unname(pins[[owner$peer_name]])) ||
      !identical(owner, list(
      peer_name = claim$source_peer_name,
      identity_pk = claim$source_identity_pk))) {
    stop("The Frequency Claim does not match the configured source owner.",
         call. = FALSE)
  }
  backend_build <- .dsvert_dp_frequency_runtime_v1(.capability)
  backend_selection <- .dsvert_dp_analysis_frequency_backend_selection_v2(
    settings$privacy, settings$calibration,
    claim$factor_entry$dimension, settings$coordinate_upper_bound,
    .selector = .selector)
  config <- .dsvert_dp_frequency_server_config_v1(
    claim, pins, settings, backend_build, backend_selection,
    .registry_verifier)
  identity <- .get_identity_keypair()
  identity_pk <- tryCatch(.dsvert_dp_frequency_identity_pk_v1(
    identity$identity_pk, "local compiler identity"),
    error = function(error) NULL)
  if (!peer_name %in% names(pins) || is.null(identity_pk) ||
      !identical(identity_pk, unname(pins[[peer_name]]))) {
    stop("The local Frequency compiler identity is not pinned.",
         call. = FALSE)
  }
  data <- .source_resolver()
  if (!is.data.frame(data)) {
    stop("The Frequency source must be a padded-PSI aligned data frame.",
         call. = FALSE)
  }
  snapshot <- .dsvert_dp_frequency_snapshot_v1(
    data, config, peer_name, claim, .registry_verifier)
  draft <- list(
    version = .DSVERT_DP_FREQUENCY_RECEIPT_VERSION,
    peer_name = peer_name, peer_identity_pk = identity_pk,
    config_sha256 = .dsvert_dp_frequency_config_hash_v1(config),
    source_claim_sha256 = .dsvert_dp_frequency_claim_hash_v1(
      claim, pins, .registry_verifier),
    psi_run_sha256 = snapshot$psi_run_sha256,
    snapshot_commitment = snapshot$snapshot_commitment)
  list(config = config, receipt = .dsvert_dp_frequency_sign_receipt_v1(
    draft, identity, .signer))
}

.dsvert_dp_frequency_receipt_verify_v1 <- function(
    receipt, config, source_claim, .verifier = .dsvert_relay_verify_message) {
  fields <- c(
    "version", "peer_name", "peer_identity_pk", "config_sha256",
    "source_claim_sha256", "psi_run_sha256", "snapshot_commitment",
    "signature")
  if (!is.list(receipt) || is.null(names(receipt)) || anyNA(names(receipt)) ||
      anyDuplicated(names(receipt)) || !setequal(names(receipt), fields)) {
    stop("Invalid signed Frequency receipt fields.", call. = FALSE)
  }
  config <- .dsvert_dp_frequency_config_validate_v1(config)
  unsigned <- .dsvert_dp_frequency_unsigned_receipt_validate_v1(
    receipt[setdiff(names(receipt), "signature")])
  signature <- .dsvert_dp_frequency_signature_v1(receipt$signature)
  if (!identical(unsigned$config_sha256,
      .dsvert_dp_frequency_config_hash_v1(config))) {
    stop("The Frequency receipt targets a different configuration.",
         call. = FALSE)
  }
  source_claim <- .dsvert_dp_frequency_claim_validate_v1(
    source_claim, config$peer_pins, .verifier = .verifier)
  if (!identical(unsigned$source_claim_sha256,
      .dsvert_dp_frequency_hash_v1(
        .DSVERT_DP_FREQUENCY_CLAIM_HASH_DOMAIN, source_claim)) ||
      !identical(unsigned$psi_run_sha256, source_claim$psi_run_sha256)) {
    stop("Frequency receipt disagrees with its Claim or PSI run.", call. = FALSE)
  }
  if (!unsigned$peer_name %in% names(config$peer_pins) ||
      !identical(unsigned$peer_identity_pk,
                 unname(config$peer_pins[[unsigned$peer_name]]))) {
    stop("The Frequency receipt identity is not pinned.", call. = FALSE)
  }
  message <- .dsvert_dp_frequency_receipt_message_v1(unsigned)
  valid <- if (identical(.verifier, .dsvert_relay_verify_message)) {
    .verifier(message, unsigned$peer_identity_pk, signature)
  } else .verifier(message, unsigned$peer_identity_pk, signature,
                   unsigned$peer_name)
  if (!isTRUE(valid)) {
    stop("Frequency receipt signature verification failed.", call. = FALSE)
  }
  c(unsigned, list(signature = signature))
}

.dsvert_dp_frequency_compile_v1 <- function(
    receipts, config, source_claim,
    .verifier = .dsvert_relay_verify_message) {
  config <- .dsvert_dp_frequency_config_validate_v1(config)
  k <- length(config$peer_pins)
  if (!is.list(receipts) || length(receipts) != k) {
    stop("Frequency requires exactly one signed receipt per pinned peer.",
         call. = FALSE)
  }
  verified <- lapply(
    receipts, .dsvert_dp_frequency_receipt_verify_v1, config = config,
    source_claim = source_claim, .verifier = .verifier)
  peers <- vapply(verified, `[[`, character(1L), "peer_name")
  if (anyDuplicated(peers) || !setequal(peers, names(config$peer_pins))) {
    stop("Invalid Frequency receipt coverage.", call. = FALSE)
  }
  names(verified) <- peers
  verified <- verified[names(config$peer_pins)]
  common <- function(field) length(unique(vapply(
    verified, `[[`, character(1L), field))) == 1L
  if (!common("config_sha256")) {
    stop("Frequency receipts disagree on their configuration.", call. = FALSE)
  }
  if (!common("source_claim_sha256")) {
    stop("Frequency receipts disagree on the signed Claim.", call. = FALSE)
  }
  if (!common("psi_run_sha256")) {
    stop("Frequency receipts disagree on the PSI run.", call. = FALSE)
  }
  snapshots <- stats::setNames(lapply(verified, function(receipt) list(
    version = .DSVERT_DP_ANALYSIS_SNAPSHOT_VERSION,
    dataset_id = config$dataset_id, dataset_version = config$dataset_version,
    snapshot_commitment = receipt$snapshot_commitment)),
    vapply(verified, `[[`, character(1L), "peer_identity_pk"))
  snapshots <- snapshots[order(names(snapshots), method = "radix")]
  source <- config$source_owner$identity_pk
  secondary <- sort(setdiff(names(snapshots), source), method = "radix")[[1L]]
  roles <- list(
    version = "dsvert-frequency-noise-authority-roles-v1",
    role_order = list("source_owner", "secondary_noise_authority"),
    authority_ids = list(source, secondary))
  profile <- .dsvert_dp_analysis_frequency_profile_v1(
    config$backend_selection$summary$selected_primitive)
  plan <- .dsvert_dp_frequency_plan_summary_v1(config)
  constraints <- list(
    version = "dsvert-contribution-constraints-v1",
    policy_sha256 = .dsvert_dp_analysis_frequency_contribution_sha256_v1())
  semantic <- list(
    version = .DSVERT_DP_ANALYSIS_FREQUENCY_SEMANTIC_VERSION,
    domain = config$domain, cohort_id = config$cohort_id,
    owner_snapshots = snapshots, noise_authority_roles = roles,
    analysis = list(
      primitive = config$backend_selection$summary$selected_primitive,
      formula = NULL, effective_arguments = list(
        version = "dsvert-fixed-domain-categorical-frequency-v2",
        statistic = "aligned_fixed_domain_categorical_frequency",
        source_owner = source, dataset_id = config$dataset_id,
        dataset_version = config$dataset_version,
        variable_id = config$factor_domain$variable_id,
        levels = config$factor_domain$levels,
        dimension = config$factor_domain$dimension,
        repeated_record_policy = config$repeated_record_policy,
        missingness_policy = config$missingness_policy,
        coordinate_bounds = list(
          lower = 0, upper = config$coordinate_upper_bound),
        sampler_plan = plan)),
    privacy = list(
      version = "dsvert-per-analysis-dp-v1",
      adjacency = config$privacy$adjacency, privacy_unit = "patient",
      contribution = list(
        version = "dsvert-contribution-policy-v1",
        max_records_per_unit = 1,
        overflow_policy = config$overflow_policy, constraints = constraints),
      mechanism = list(
        family = profile$mechanism_family, version = profile$mechanism,
        sensitivity = list(
          version = "dsvert-sensitivity-v1", norm = profile$sensitivity_norm,
          value = .dsvert_dp_frequency_sensitivity_v1(
            config$privacy$adjacency, profile)),
        calibration = list(
          version = "dsvert-calibration-v1", sampler = profile$sampler,
          implementation_delta = config$calibration$implementation_delta),
        randomness = list(
          version = "dsvert-randomness-plan-v1", lanes = list(
            final_noise = list(
              version = "dsvert-randomness-lane-v1",
              purpose = "privatize_final_vector", primitive = profile$sampler,
              coordinates = config$factor_domain$dimension)))),
      epsilon = config$privacy$epsilon, delta = config$privacy$delta),
    numeric = list(
      version = "dsvert-numeric-semantics-v1", value_bits = 128,
      fractional_bits = 0, rounding = "toward_zero", overflow = "reject",
      output_encoding = "twos_complement_integer_v1"),
    public_shape = list(counts = config$factor_domain$dimension))
  execution <- list(
    version = .DSVERT_DP_ANALYSIS_EXECUTION_VERSION,
    peer_pins = as.list(config$peer_pins),
    backend = list(
      kernel = config$backend_selection$summary$selected_primitive,
      ring = "ring128", build_sha256 = config$backend_build_sha256),
    transport = list(
      chunk_coordinates = config$transport_chunk_coordinates))
  .dsvert_dp_analysis_contract_v1(semantic, execution)
}
