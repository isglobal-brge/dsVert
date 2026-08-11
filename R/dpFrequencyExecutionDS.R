# Internal execution core for an authorized fixed-domain Frequency release.
# Only a fixed recipient-encrypted packet crosses the analyst relay.

.DSVERT_DP_FREQUENCY_EXECUTION_VERSION <- "dsvert-dp-frequency-execution-v1"

.DSVERT_DP_FREQUENCY_SOURCE_RESULT_VERSION <- "dsvert-dp-frequency-source-window-v1"

.DSVERT_DP_FREQUENCY_FINAL_RESULT_VERSION <- "dsvert-dp-frequency-finalization-v1"

.DSVERT_DP_FREQUENCY_RELEASE_VERSION <- "dsvert-dp-frequency-release-v1"

.DSVERT_DP_FREQUENCY_AUTH_SET_DOMAIN <- "dsVert/dp-frequency/authorization-set/v1|"

.DSVERT_DP_FREQUENCY_CHUNK_DOMAIN <- "dsVert/dp-frequency/final-binary-chunk/v1|"

.DSVERT_DP_FREQUENCY_WINDOW_DOMAIN <- "dsVert/dp-frequency/final-window/v1|"

.DSVERT_DP_FREQUENCY_RELEASE_DOMAIN <- "dsVert/dp-frequency/release/v1|"

.DSVERT_DP_FREQUENCY_RELEASE_SIGNATURE_DOMAIN <- "dsVert/dp-frequency/release-signature/v1|"

.DSVERT_DP_FREQUENCY_CHUNK_COORDINATES <- 8192L

.DSVERT_DP_FREQUENCY_WINDOW_COORDINATES <- 65536L

.DSVERT_DP_FREQUENCY_PLAINTEXT_BYTES <- 1056768L

.DSVERT_DP_FREQUENCY_SEALED_BYTES <- 1056828L

.dsvert_dp_frequency_execution_index_v1 <- function(x, what, min = 0, max = 1e+06) {
    if (!is.numeric(x) || length(x) != 1L || is.na(x) || !is.finite(x) || x != floor(x) || x < min || x > max)
        stop("Invalid Frequency ", what, ".", call. = FALSE)
    as.integer(x)
}

.dsvert_dp_frequency_execution_closed_v1 <- function(x, fields) {
    is.list(x) && !is.null(names(x)) && !anyNA(names(x)) && !anyDuplicated(names(x)) && setequal(names(x), fields)
}

.dsvert_dp_frequency_execution_geometry_v1 <- function(worker) {
    if (!is.list(worker))
        stop("Invalid Frequency execution geometry.", call. = FALSE)
    d <- .dsvert_dp_frequency_execution_index_v1(worker$d, "dimension", 1L, 1e+06)
    chunks <- as.integer(ceiling(d/.DSVERT_DP_FREQUENCY_CHUNK_COORDINATES))
    expected_chunk <- min(.DSVERT_DP_FREQUENCY_CHUNK_COORDINATES, d)
    if (!identical(as.integer(worker$chunk_coordinates), expected_chunk) || !identical(as.integer(worker$chunk_count), chunks))
        stop("Invalid Frequency execution geometry.", call. = FALSE)
    list(d = d, chunk_count = chunks, window_count = as.integer(ceiling(d/.DSVERT_DP_FREQUENCY_WINDOW_COORDINATES)))
}

.dsvert_dp_frequency_execution_window_v1 <- function(geometry, window_index) {
    index <- .dsvert_dp_frequency_execution_index_v1(window_index, "window index", 0L, geometry$window_count - 1L)
    offset <- index * .DSVERT_DP_FREQUENCY_WINDOW_COORDINATES
    count <- min(.DSVERT_DP_FREQUENCY_WINDOW_COORDINATES, geometry$d - offset)
    list(window_index = index, window_count = geometry$window_count, first_chunk_index = as.integer(8L * index), chunks_in_window = as.integer(ceiling(count/8192L)),
        coordinate_offset = as.integer(offset), coordinate_count = as.integer(count), padded_coordinate_count = .DSVERT_DP_FREQUENCY_WINDOW_COORDINATES,
        plaintext_bytes = .DSVERT_DP_FREQUENCY_PLAINTEXT_BYTES, ciphertext_chars = .DSVERT_TYPED_BLOB_FREQUENCY_CIPHERTEXT_CHARS)
}

.dsvert_dp_frequency_execution_public_auth_v1 <- function(value, .verifier) {
    fields <- sort(c("version", "session_id", "artifact_key", "config_sha256", "source_claim_sha256", "receipt_set_sha256",
        "psi_run_sha256", "contract_sha256", "analysis_binding_sha256", "worker_static_sha256", "local_authority", "commitment_context",
        "seed_commitment", "authorization_sha256", "signature"), method = "radix")
    if (!is.function(.verifier) || !is.list(value) || !identical(names(value), fields) || !identical(value$version, .DSVERT_DP_FREQUENCY_PUBLIC_AUTHORIZATION_VERSION))
        stop("Invalid Frequency public authorization.", call. = FALSE)
    value$session_id <- .dsvert_relay_validate_session_id(value$session_id)
    hashes <- setdiff(fields, c("version", "session_id", "local_authority", "signature"))
    for (field in hashes) value[[field]] <- .dsvert_dp_frequency_hex_v1(value[[field]], paste("public authorization", field))
    local <- value$local_authority
    if (!is.list(local) || !identical(names(local), sort(c("peer_name", "identity_pk", "role"), method = "radix")) || !is.character(local$role) ||
        length(local$role) != 1L || !local$role %in% c("source_owner", "secondary_noise_authority"))
        stop("Invalid Frequency public authorization.", call. = FALSE)
    local$peer_name <- .dsvert_dp_frequency_peer_name_v1(local$peer_name)
    local$identity_pk <- .dsvert_dp_frequency_identity_pk_v1(local$identity_pk, "public authorization identity")
    value$local_authority <- local
    value$signature <- .dsvert_dp_frequency_signature_v1(value$signature)
    if (!identical(value, .dsvert_dp_analysis_canonical_value_v1(value)))
        stop("Invalid Frequency public authorization.", call. = FALSE)
    unsigned <- value[setdiff(names(value), "signature")]
    message <- .dsvert_dp_frequency_public_authorization_message_v1(unsigned)
    valid <- tryCatch(if (identical(.verifier, .dsvert_relay_verify_message))
        .verifier(message, local$identity_pk, value$signature)
    else .verifier(message, local$identity_pk, value$signature, local$peer_name), error = function(error) FALSE)
    if (!isTRUE(valid))
        stop("Frequency public authorization signature verification failed.", call. = FALSE)
    value
}

.dsvert_dp_frequency_execution_authorization_set_v1 <- function(ss, session_id, public_authorizations, .verifier = .dsvert_relay_verify_message) {
    authorization <- .dsvert_dp_frequency_session_authorization_validate_v1(ss, session_id)
    if (!is.list(public_authorizations) || length(public_authorizations) != 2L || any(!vapply(public_authorizations, is.list,
        logical(1L))))
        stop("Frequency execution requires two public authorizations.", call. = FALSE)
    values <- lapply(public_authorizations, .dsvert_dp_frequency_execution_public_auth_v1, .verifier = .verifier)
    roles <- vapply(values, function(x) x$local_authority$role, character(1L))
    order <- c("source_owner", "secondary_noise_authority")
    if (!identical(unname(roles), order))
        stop("Frequency public authorizations are not in canonical role order.", call. = FALSE)
    names(values) <- roles
    common <- c("session_id", "artifact_key", "config_sha256", "source_claim_sha256", "receipt_set_sha256", "psi_run_sha256",
        "contract_sha256", "analysis_binding_sha256", "worker_static_sha256")
    expected_roles <- authorization$worker_static$authority_roles[order]
    valid <- all(vapply(values, function(x) identical(x[common], authorization[common]), logical(1L))) && all(vapply(order,
        function(role) {
            x <- values[[role]]
            peer <- x$local_authority$peer_name
            identical(x$local_authority$identity_pk, expected_roles[[role]]) && identical(x$commitment_context, authorization$worker_static$commitment_contexts[[role]]) &&
                peer %in% names(authorization$config$peer_pins) && identical(unname(authorization$config$peer_pins[[peer]]),
                x$local_authority$identity_pk)
        }, logical(1L)))
    identities <- vapply(values, function(x) x$local_authority$identity_pk, character(1L))
    peers <- vapply(values, function(x) x$local_authority$peer_name, character(1L))
    local_role <- authorization$local_authority$role
    local_seed <- .dsvert_dp_frequency_seed_material_v1(authorization)
    if (!isTRUE(valid) || anyDuplicated(identities) || anyDuplicated(peers) || !local_role %in% order || !identical(values[[local_role]]$authorization_sha256,
        authorization$authorization_sha256) || !identical(values[[local_role]]$seed_commitment, local_seed$sha256))
        stop("Frequency public authorizations do not match local authorization.", call. = FALSE)
    list(values = values, sha256 = .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_AUTH_SET_DOMAIN, unname(values)))
}

.dsvert_dp_frequency_execution_context_v1 <- function(authorization, auth_set, operation_id, window) {
    roles <- lapply(auth_set$values, function(x) x$local_authority$peer_name)
    value <- list(version = .DSVERT_TYPED_BLOB_FREQUENCY_CONTEXT_VERSION, purpose = .DSVERT_TYPED_BLOB_FREQUENCY_PURPOSE,
        artifact_key = authorization$artifact_key, contract_sha256 = authorization$contract_sha256, analysis_binding_sha256 = authorization$analysis_binding_sha256,
        worker_static_sha256 = authorization$worker_static_sha256, authorization_set_sha256 = auth_set$sha256, release_contract_hash = authorization$worker_static$release_contract_hash,
        operation_id = operation_id, window_index = as.character(window$window_index), window_count = as.character(window$window_count),
        first_chunk_index = as.character(window$first_chunk_index), chunks_in_window = as.character(window$chunks_in_window),
        coordinate_offset = as.character(window$coordinate_offset), coordinate_count = as.character(window$coordinate_count),
        padded_coordinate_count = "65536", ring_bits = "128", frac_bits = "0", roles = roles, sender = roles$source_owner,
        recipient = roles$secondary_noise_authority)
    .dsvert_typed_blob_frequency_context_v1(value, roles$source_owner)
}

.dsvert_dp_frequency_execution_transport_v1 <- function(ss, authorization, auth_set, operation_id, window) {
    typed <- .dsvert_typed_blob_session_context(ss)
    local <- authorization$local_authority
    other_role <- setdiff(names(auth_set$values), local$role)
    other_peer <- auth_set$values[[other_role]]$local_authority$peer_name
    parent <- ss$.typed_blob_parent_binding_digest
    exact <- ss$.exact_gc_peer_binding_digest
    peer_keys <- ss$peer_transport_pks
    valid <- identical(typed$self_name, local$peer_name) && is.character(parent) && length(parent) == 1L && grepl("^[0-9a-f]{64}$",
        parent) && identical(parent, exact) && is.list(peer_keys) && length(peer_keys) == 1L && identical(names(peer_keys),
        other_peer) && !is.null(typed$peer_identity_pks[[other_peer]])
    if (!isTRUE(valid))
        stop("Frequency execution requires its identity-bound typed peer transport.", call. = FALSE)
    recipient_pk <- NULL
    if (identical(local$role, "source_owner")) {
        recipient_pk <- peer_keys[[other_peer]]
        if (!identical(.dsvert_typed_blob_recipient_name(ss, recipient_pk), other_peer))
            stop("Frequency recipient transport binding changed.", call. = FALSE)
    }
    context <- .dsvert_dp_frequency_execution_context_v1(authorization, auth_set, operation_id, window)
    list(context = context, peer_binding_digest = typed$peer_binding_digest, recipient_pk = recipient_pk)
}

.dsvert_dp_frequency_execution_reserve_v1 <- function(ss, authorization) {
    expected <- list(session_id = authorization$session_id, artifact_key = authorization$artifact_key, role = authorization$local_authority$role,
        dimension = as.numeric(authorization$worker_static$d), window_coordinates = 65536)
    prior <- ss$.dp_frequency_resource_reservation
    if (is.null(prior))
        .dsvert_dp_frequency_resource_reserve_v1(ss, expected$session_id, expected$artifact_key, expected$role, expected$dimension,
            expected$window_coordinates)
    else if (!is.list(prior) || !identical(prior[names(expected)], expected))
        stop("Conflicting Frequency resource reservation.", call. = FALSE)
    invisible(TRUE)
}

.dsvert_dp_frequency_execution_profile_v1 <- function(worker) {
    gaussian <- isTRUE(worker$selected_profile$gaussian)
    if (gaussian && identical(worker$selected_primitive, paste0("independent_full_global_dyadic_discrete_gaussian_", "tv_bounded_ring128_v2")))
        return(list(gaussian = TRUE, input = "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-input-v2", share = "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-share-v2",
            final_input = paste0("dsvert-joint-dp-vector-dyadic-discrete-gaussian-", "tv-bounded-finalizer-input-v2"), final = paste0("dsvert-joint-dp-vector-dyadic-discrete-gaussian-",
                "tv-bounded-finalizer-v2"), share_command = "joint-dp-vector-gaussian-share-v2", final_command = "joint-dp-vector-gaussian-finalize-v2",
            mechanism = "dyadic_discrete_gaussian_truncated_tv_bounded"))
    if (!gaussian && identical(worker$selected_primitive, "independent_full_global_draw_convolution_ring128_v3"))
        return(list(gaussian = FALSE, input = "dsvert-joint-dp-vector-independent-full-draw-convolution-input-v3", share = "dsvert-joint-dp-vector-independent-full-draw-convolution-share-v3",
            final_input = "dsvert-joint-dp-vector-independent-full-draw-finalizer-input-v3", final = "dsvert-joint-dp-vector-independent-full-draw-finalizer-v3",
            share_command = "joint-dp-vector-convolution-share-v3", final_command = "joint-dp-vector-convolution-finalize-v3",
            mechanism = "discrete_laplace_convolution"))
    stop("Unsupported Frequency execution profile.", call. = FALSE)
}

.dsvert_dp_frequency_execution_b64_v1 <- function(value, bytes, what) {
    raw <- tryCatch(jsonlite::base64_dec(value), error = function(error) NULL)
    canonical <- if (is.raw(raw))
        gsub("[\r\n]", "", jsonlite::base64_enc(raw))
    else NULL
    if (!is.character(value) || length(value) != 1L || is.na(value) || is.null(canonical) || !identical(canonical, value) ||
        length(raw) != bytes)
        stop("Invalid Frequency ", what, ".", call. = FALSE)
    raw
}

.dsvert_dp_frequency_execution_ring128_v1 <- function(values) {
    if (!is.numeric(values) || anyNA(values) || any(!is.finite(values)) || any(values != floor(values)) || any(values < 0) ||
        any(values > 1e+06))
        stop("Invalid Frequency vector values.", call. = FALSE)
    values <- as.integer(values)
    raw <- raw(16L * length(values))
    if (length(values)) {
        starts <- seq.int(1L, length(raw), by = 16L)
        for (byte in 0:3) raw[starts + byte] <- as.raw(bitwAnd(bitwShiftR(values, 8L * byte), 255L))
    }
    raw
}

.dsvert_dp_frequency_execution_policy_v1 <- function(authorization, offset, count) {
    worker <- authorization$worker_static
    request <- worker$selected_request
    value <- list(ring_bits = 128L, frac_bits = 0L, total_coordinate_count = worker$d, chunk_start = as.integer(offset),
        coordinate_count = as.integer(count), output_lattice_bits = worker$output_lattice_bits, epsilon = request$epsilon,
        allocated_delta = request$delta, scale_shifts = rep(0L, count), raw_upper_bounds = rep(worker$raw_bound$upper, count),
        release_contract_hash = worker$release_contract_hash, transcript_hash = worker$transcript_hash)
    profile <- .dsvert_dp_frequency_execution_profile_v1(worker)
    if (profile$gaussian)
        value$l2_sensitivity_steps <- request$l2_sensitivity_steps
    else value$sensitivity_steps <- request$sensitivity_steps
    value
}

.dsvert_dp_frequency_execution_sampler_input_v1 <- function(authorization, auth_set, role, offset, count, source_share) {
    profile <- .dsvert_dp_frequency_execution_profile_v1(authorization$worker_static)
    c(list(version = profile$input), .dsvert_dp_frequency_execution_policy_v1(authorization, offset, count), list(peer_name = authorization$worker_static$authority_tokens[[role]],
        commitment_context = authorization$worker_static$commitment_contexts[[role]], seed_commitment = auth_set$values[[role]]$seed_commitment,
        private_seed = .dsvert_dp_sticky_subseed_v1(authorization$contract, "final_noise"), source_share = source_share))
}

.dsvert_dp_frequency_execution_expected_v1 <- function(authorization) list(backend = authorization$worker_static$selected_primitive,
    sampler = authorization$worker_static$selected_profile$sampler, plan = authorization$worker_static$selected_plan)

.dsvert_dp_frequency_execution_share_v1 <- function(value, input, authorization) {
    profile <- .dsvert_dp_frequency_execution_profile_v1(authorization$worker_static)
    fields <- c("version", "backend", "sampler", "release_contract_hash", "sampler_contract_hash", "transcript_hash", "peer_name",
        "seed_commitment", "ring_bits", "frac_bits", "total_coordinate_count", "chunk_start", "coordinate_count", "noised_share",
        "maximum_noise_magnitude_per_peer", "maximum_noise_magnitude_two_peers", "full_capsule_parameters_per_peer", "epsilon_divided_by_peer_count",
        "source_values_returned", "noise_values_returned", "private_seed_returned", "preclamp_values_returned", "no_wrap_headroom_certified",
        "source_bound_precondition", "nominal_variance_multiplier", "plan")
    if (profile$gaussian)
        fields <- c(fields, "mechanism", "tail_projection_applied", "tail_truncation_applied", "fixed_work_shape_verified")
    expected <- .dsvert_dp_frequency_execution_expected_v1(authorization)
    exact <- list(version = profile$share, backend = expected$backend, sampler = expected$sampler, release_contract_hash = input$release_contract_hash,
        transcript_hash = input$transcript_hash, peer_name = input$peer_name, seed_commitment = input$seed_commitment, full_capsule_parameters_per_peer = TRUE,
        epsilon_divided_by_peer_count = FALSE, source_values_returned = FALSE, noise_values_returned = FALSE, private_seed_returned = FALSE,
        preclamp_values_returned = FALSE, no_wrap_headroom_certified = TRUE, source_bound_precondition = paste0("authenticated_semi_honest_capsule_materializer_",
            "and_source_transport"), plan = expected$plan)
    numeric_fields <- c("ring_bits", "frac_bits", "total_coordinate_count", "chunk_start", "coordinate_count")
    valid <- .dsvert_dp_frequency_execution_closed_v1(value, fields) && all(vapply(names(exact), function(field) identical(value[[field]],
        exact[[field]]), logical(1L))) && all(vapply(numeric_fields, function(field) identical(as.numeric(value[[field]]),
        as.numeric(input[[field]])), logical(1L))) && identical(as.numeric(value$nominal_variance_multiplier), 2) && is.character(value$sampler_contract_hash) &&
        grepl("^[0-9a-f]{64}$", value$sampler_contract_hash) && all(vapply(c("maximum_noise_magnitude_per_peer", "maximum_noise_magnitude_two_peers"),
        function(field) is.character(value[[field]]) && length(value[[field]]) == 1L && grepl("^(0|[1-9][0-9]*)$", value[[field]]),
        logical(1L)))
    if (profile$gaussian)
        valid <- valid && identical(value$mechanism, profile$mechanism) && identical(value$tail_projection_applied, FALSE) &&
            identical(value$tail_truncation_applied, TRUE) && identical(value$fixed_work_shape_verified, TRUE)
    raw <- if (isTRUE(valid))
        tryCatch(.dsvert_dp_frequency_execution_b64_v1(value$noised_share, 16L * input$coordinate_count, "noised share"),
            error = function(error) NULL)
    else NULL
    if (!is.raw(raw))
        stop("Frequency sampler returned an invalid share.", call. = FALSE)
    raw
}

.dsvert_dp_frequency_execution_final_input_v1 <- function(authorization, offset, count, left, right) {
    profile <- .dsvert_dp_frequency_execution_profile_v1(authorization$worker_static)
    c(list(version = profile$final_input), .dsvert_dp_frequency_execution_policy_v1(authorization, offset, count), list(left_noised_share = left,
        right_noised_share = right))
}

.dsvert_dp_frequency_execution_final_v1 <- function(value, input, authorization) {
    profile <- .dsvert_dp_frequency_execution_profile_v1(authorization$worker_static)
    fields <- c("version", "backend", "sampler", "release_contract_hash", "transcript_hash", "ring_bits", "frac_bits", "total_coordinate_count",
        "chunk_start", "coordinate_count", "output_lattice_bits", "clamped_scaled_values", "preclamp_values_returned", "signed_decode",
        "clamping", "no_wrap_headroom_certified", "plan")
    if (profile$gaussian)
        fields <- c(fields, "mechanism")
    expected <- .dsvert_dp_frequency_execution_expected_v1(authorization)
    values <- tryCatch(unlist(value$clamped_scaled_values, use.names = FALSE), error = function(error) NULL)
    numeric <- suppressWarnings(as.numeric(values))
    valid <- .dsvert_dp_frequency_execution_closed_v1(value, fields) && identical(value$version, profile$final) && identical(value$backend,
        expected$backend) && identical(value$sampler, expected$sampler) && identical(value$plan, expected$plan) && identical(value$release_contract_hash,
        input$release_contract_hash) && identical(value$transcript_hash, input$transcript_hash) && all(vapply(c("ring_bits",
        "frac_bits", "total_coordinate_count", "chunk_start", "coordinate_count", "output_lattice_bits"), function(field) identical(as.numeric(value[[field]]),
        as.numeric(input[[field]])), logical(1L))) && identical(value$preclamp_values_returned, FALSE) && identical(value$signed_decode,
        "canonical_Ring128_twos_complement_after_proven_no_wrap") && identical(value$clamping, "single_fixed_public_per_coordinate_interval_postprocessing") &&
        identical(value$no_wrap_headroom_certified, TRUE) && is.character(values) && length(values) == input$coordinate_count &&
        all(grepl("^(0|[1-9][0-9]*)$", values)) && all(is.finite(numeric)) && all(numeric >= 0) && all(numeric <= as.numeric(authorization$worker_static$raw_bound$upper))
    if (profile$gaussian)
        valid <- valid && identical(value$mechanism, profile$mechanism)
    if (!isTRUE(valid))
        stop("Frequency finalizer returned an invalid chunk.", call. = FALSE)
    numeric
}

.dsvert_dp_frequency_execution_header_raw_v1 <- function(context, binding) {
    header <- .dsvert_typed_blob_frequency_header_v1(context, binding)
    raw <- charToRaw(.dsvert_dp_canonical_json(.dsvert_dp_analysis_canonical_value_v1(header)))
    if (length(raw) > .DSVERT_TYPED_BLOB_FREQUENCY_HEADER_BYTES)
        stop("Frequency public header exceeds its fixed geometry.", call. = FALSE)
    c(raw, raw(.DSVERT_TYPED_BLOB_FREQUENCY_HEADER_BYTES - length(raw)))
}

.dsvert_dp_frequency_execution_packet_v1 <- function(context, binding, share) {
    if (!is.raw(share) || length(share) > 65536L * 16L)
        stop("Invalid Frequency packet share.", call. = FALSE)
    c(.dsvert_dp_frequency_execution_header_raw_v1(context, binding), share, raw(65536L * 16L - length(share)))
}

.dsvert_dp_frequency_execution_packet_open_v1 <- function(frame, context, binding, coordinate_count) {
    expected <- .dsvert_dp_frequency_execution_header_raw_v1(context, binding)
    share_bytes <- coordinate_count * 16L
    if (!is.raw(frame) || length(frame) != .DSVERT_DP_FREQUENCY_PLAINTEXT_BYTES || !identical(frame[seq_len(8192L)], expected))
        stop("Invalid Frequency ciphertext frame.", call. = FALSE)
    payload <- frame[-seq_len(8192L)]
    if (share_bytes < length(payload) && any(payload[seq.int(share_bytes + 1L, length(payload))] != as.raw(0L)))
        stop("Invalid Frequency ciphertext frame padding.", call. = FALSE)
    payload[seq_len(share_bytes)]
}

.dsvert_dp_frequency_execution_ciphertext_v1 <- function(value) {
    raw <- tryCatch(.dsvert_relay_b64url_decode(value, "Frequency ciphertext"), error = function(error) NULL)
    if (!is.character(value) || length(value) != 1L || is.na(value) || nchar(value, type = "bytes") != .DSVERT_TYPED_BLOB_FREQUENCY_CIPHERTEXT_CHARS ||
        !is.raw(raw) || length(raw) != .DSVERT_DP_FREQUENCY_SEALED_BYTES)
        stop("Invalid Frequency ciphertext geometry.", call. = FALSE)
    value
}

.dsvert_dp_frequency_execution_encrypt_v1 <- function(frame, recipient_pk) {
    if (!is.raw(frame) || length(frame) != .DSVERT_DP_FREQUENCY_PLAINTEXT_BYTES)
        stop("Invalid Frequency transport plaintext.", call. = FALSE)
    recipient_pk <- .dsvert_normalize_crypto_b64(recipient_pk, 32L, "Frequency recipient transport public key")
    sealed <- .callMpcTool("transport-encrypt", list(data = gsub("[\r\n]", "", jsonlite::base64_enc(frame)), recipient_pk = recipient_pk))
    value <- if (is.list(sealed)) tryCatch(base64_to_base64url(sealed$sealed), error = function(error) NULL) else NULL
    .dsvert_dp_frequency_execution_ciphertext_v1(value)
}

.dsvert_dp_frequency_execution_decrypt_v1 <- function(ss, ciphertext) {
    ciphertext <- .dsvert_dp_frequency_execution_ciphertext_v1(ciphertext)
    secret <- .dsvert_normalize_crypto_b64(.key_get("transport_sk", ss), 32L, "Frequency recipient transport secret key")
    opened <- .callMpcTool("transport-decrypt", list(sealed = .base64url_to_base64(ciphertext), recipient_sk = secret))
    value <- if (is.list(opened)) opened$data else NULL
    .dsvert_dp_frequency_execution_b64_v1(value, .DSVERT_DP_FREQUENCY_PLAINTEXT_BYTES, "transport plaintext")
}

.dsvert_dp_frequency_execution_transfer_v1 <- function(transfer, context = NULL) {
    fields <- c("ticket", "transfer_id", "capability_id", "sender_name", "recipient_name", "payload_chars", "payload_sha256")
    valid <- .dsvert_dp_frequency_execution_closed_v1(transfer, fields) && is.character(transfer$transfer_id) && grepl(.DSVERT_TYPED_BLOB_TRANSFER_RE,
        transfer$transfer_id) && identical(transfer$capability_id, .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY) && identical(as.numeric(transfer$payload_chars),
        1409104) && is.character(transfer$payload_sha256) && grepl("^[0-9a-f]{64}$", transfer$payload_sha256)
    if (!is.null(context))
        valid <- valid && identical(transfer$sender_name, context$sender) && identical(transfer$recipient_name, context$recipient)
    if (!isTRUE(valid))
        stop("Invalid Frequency typed transfer.", call. = FALSE)
    transfer
}

.dsvert_dp_frequency_execution_delivery_v1 <- function(ss, transfer) {
    transfer <- .dsvert_dp_frequency_execution_transfer_v1(transfer)
    id <- transfer$transfer_id
    if (!is.null((ss$.typed_blob_outbound_receipts %||% list())[[id]]))
        return(TRUE)
    pending <- (ss$.typed_blob_outbound %||% list())[[id]]
    if (is.null(pending) || !all(vapply(c("capability_id", "sender_name", "recipient_name", "payload_sha256"), function(field) identical(pending[[field]],
        transfer[[field]]), logical(1L))) || !identical(as.numeric(pending$payload_chars), 1409104))
        stop("Frequency typed delivery is neither pending nor acknowledged.", call. = FALSE)
    FALSE
}

.dsvert_dp_frequency_execution_state_v1 <- function(ss, authorization, auth_set, operation_id, role, geometry) {
    request <- .dsvert_dp_analysis_canonical_value_v1(list(version = .DSVERT_DP_FREQUENCY_EXECUTION_VERSION, session_id = authorization$session_id,
        operation_id = operation_id, artifact_key = authorization$artifact_key, contract_sha256 = authorization$contract_sha256,
        analysis_binding_sha256 = authorization$analysis_binding_sha256, worker_static_sha256 = authorization$worker_static_sha256,
        authorization_set_sha256 = auth_set$sha256, role = role))
    state <- ss$.dp_frequency_execution
    if (is.null(state)) {
        state <- list(request = request, values = numeric(geometry$d), values_ready = FALSE, windows = vector("list", geometry$window_count),
            next_window = 0L, release = NULL)
        ss$.dp_frequency_execution <- state
    }
    else if (!is.list(state) || !identical(state$request, request) || !is.double(state$values) || length(state$values) !=
        geometry$d || !is.list(state$windows))
        stop("Conflicting Frequency execution retry.", call. = FALSE)
    state
}

.dsvert_dp_frequency_execution_histogram_v1 <- function(data, authorization, claim, .verifier) {
    config <- authorization$config
    shape <- tryCatch(.psi_padded_raw_data_frame_shape_v1(data), error = function(error) NULL)
    index <- if (is.list(shape)) which(enc2utf8(shape$names) == config$factor_domain$variable_name) else integer()
    if (length(index) != 1L || shape$n > config$coordinate_upper_bound)
        stop("Invalid Frequency source factor.", call. = FALSE)
    levels <- unlist(config$factor_domain$levels, use.names = FALSE)
    column <- .subset2(data, index)
    level_coordinate <- match(enc2utf8(attr(column, "levels", exact = TRUE)), levels, 0L)
    codes <- unclass(column)
    attributes(codes) <- NULL
    coordinates <- integer(length(codes))
    if (is.integer(codes) || is.double(codes)) {
        valid <- !is.na(codes) & is.finite(codes) & codes == trunc(codes) & codes >= 1 & codes <= length(level_coordinate)
        coordinates[valid] <- level_coordinate[codes[valid]]
    }
    labels <- rep(NA_character_, length(coordinates))
    labels[coordinates > 0L] <- levels[coordinates[coordinates > 0L]]
    normalized <- data
    normalized[[index]] <- factor(labels, levels = levels)
    snapshot <- .dsvert_dp_frequency_snapshot_v1(normalized, config, authorization$local_authority$peer_name, claim, .registry_verifier = .verifier)
    expected <- authorization$contract$semantic$owner_snapshots[[authorization$local_authority$identity_pk]]
    if (!is.list(snapshot) || !identical(snapshot$psi_run_sha256, authorization$psi_run_sha256) || !is.list(expected) ||
        !identical(snapshot$snapshot_commitment, expected$snapshot_commitment))
        stop("Frequency source snapshot changed after authorization.", call. = FALSE)
    as.numeric(tabulate(coordinates[coordinates > 0L], nbins = authorization$worker_static$d))
}

.dsvert_dp_frequency_execution_source_ack_v1 <- function(authorization, window) {
    .dsvert_dp_analysis_canonical_value_v1(list(version = .DSVERT_DP_FREQUENCY_SOURCE_RESULT_VERSION, state = "delivered",
        artifact_key = authorization$artifact_key, window_index = window$window_index, window_count = window$window_count,
        intermediate_values_exposed = FALSE))
}

.dsvert_dp_frequency_execution_source_window_v1 <- function(ss, session_id, operation_id, window_index, public_authorizations,
    claim, .source_resolver, .sampler = function(command, input, expected) .callMpcTool(command, input), .encrypt = .dsvert_dp_frequency_execution_encrypt_v1,
    .typed_mint = NULL, .typed_commit = NULL, .delivery_status = NULL, .verifier = .dsvert_relay_verify_message) {
    if (!is.environment(ss) || !is.function(.source_resolver) || !is.function(.sampler) || !is.function(.encrypt))
        stop("Invalid Frequency source-window dependency.", call. = FALSE)
    operation_id <- .dsvert_relay_validate_operation_id(operation_id)
    auth_set <- .dsvert_dp_frequency_execution_authorization_set_v1(ss, session_id, public_authorizations, .verifier)
    authorization <- .dsvert_dp_frequency_session_authorization_validate_v1(ss, session_id)
    if (!identical(authorization$local_authority$role, "source_owner"))
        stop("Only the Frequency source owner may materialize its histogram.", call. = FALSE)
    claim <- .dsvert_dp_frequency_claim_validate_v1(claim, authorization$config$peer_pins, .verifier = .verifier)
    claim_hash <- .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_CLAIM_HASH_DOMAIN, claim)
    if (!identical(claim_hash, authorization$source_claim_sha256) || !identical(claim$psi_run_sha256, authorization$psi_run_sha256))
        stop("Frequency Claim does not match its authorization.", call. = FALSE)
    geometry <- .dsvert_dp_frequency_execution_geometry_v1(authorization$worker_static)
    window <- .dsvert_dp_frequency_execution_window_v1(geometry, window_index)
    transport <- .dsvert_dp_frequency_execution_transport_v1(ss, authorization, auth_set, operation_id, window)
    .dsvert_dp_frequency_execution_reserve_v1(ss, authorization)
    state <- .dsvert_dp_frequency_execution_state_v1(ss, authorization, auth_set, operation_id, "source_owner", geometry)
    key <- window$window_index + 1L
    prior <- state$windows[[key]]
    request <- list(context = transport$context)
    if (is.null(.delivery_status))
        .delivery_status <- function(transfer) .dsvert_dp_frequency_execution_delivery_v1(ss, transfer)
    if (!is.function(.delivery_status))
        stop("Invalid Frequency delivery lookup.", call. = FALSE)
    if (!is.null(prior)) {
        if (!is.list(prior) || !identical(prior$request, request))
            stop("Conflicting Frequency source-window retry.", call. = FALSE)
        if (identical(prior$status, "delivered"))
            return(prior$result)
        if (identical(prior$status, "issued")) {
            delivered <- .delivery_status(prior$transfer)
            if (!is.logical(delivered) || length(delivered) != 1L || is.na(delivered))
                stop("Invalid Frequency typed delivery status.", call. = FALSE)
            if (isTRUE(delivered)) {
                prior$status <- "delivered"
                prior$ciphertext <- NULL
                prior$result <- .dsvert_dp_frequency_execution_source_ack_v1(authorization, window)
                state$windows[[key]] <- prior
                state$next_window <- max(state$next_window, key)
                ss$.dp_frequency_execution <- state
            }
            return(prior$result)
        }
        if (!identical(prior$status, "staged") && !identical(prior$status, "minted"))
            stop("Invalid Frequency source-window state.", call. = FALSE)
    }
    if (window$window_index > 0L) {
        previous <- state$windows[[key - 1L]]
        if (!is.list(previous) || !identical(previous$status, "delivered"))
            stop("The previous Frequency source window is not delivered.", call. = FALSE)
    }
    if (!isTRUE(state$values_ready)) {
        state$values <- .dsvert_dp_frequency_execution_histogram_v1(.source_resolver(), authorization, claim, .verifier)
        state$values_ready <- TRUE
        ss$.dp_frequency_execution <- state
    }
    profile <- .dsvert_dp_frequency_execution_profile_v1(authorization$worker_static)
    if (is.null(prior)) {
        packed <- raw(65536L * 16L)
        for (position in seq_len(window$chunks_in_window)) {
            offset <- window$coordinate_offset + (position - 1L) * 8192L
            count <- min(8192L, geometry$d - offset)
            source_b64 <- gsub("[\r\n]", "", jsonlite::base64_enc(.dsvert_dp_frequency_execution_ring128_v1(state$values[seq.int(offset +
                1L, offset + count)])))
            input <- .dsvert_dp_frequency_execution_sampler_input_v1(authorization, auth_set, "source_owner", offset, count,
                source_b64)
            share <- .dsvert_dp_frequency_execution_share_v1(.sampler(profile$share_command, input, .dsvert_dp_frequency_execution_expected_v1(authorization)),
                input, authorization)
            start <- (position - 1L) * 8192L * 16L + 1L
            packed[seq.int(start, start + length(share) - 1L)] <- share
        }
        frame <- .dsvert_dp_frequency_execution_packet_v1(transport$context, transport$peer_binding_digest, packed[seq_len(window$coordinate_count *
            16L)])
        ciphertext <- .dsvert_dp_frequency_execution_ciphertext_v1(.encrypt(frame, transport$recipient_pk))
        prior <- list(status = "staged", request = request, ciphertext = ciphertext, transfer = NULL, result = NULL)
        state$windows[[key]] <- prior
        ss$.dp_frequency_execution <- state
        rm(packed, frame)
    }
    if (is.null(.typed_mint))
        .typed_mint <- function(context, ciphertext, recipient_pk) .dsvert_typed_blob_mint(ss, session_id, .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
            recipient_pk, ciphertext, context, producer = "dsvertDPFrequencySourceWindowDS")
    if (!is.function(.typed_mint))
        stop("Invalid Frequency typed mint.", call. = FALSE)
    if (identical(prior$status, "staged")) {
        suspendInterrupts({
            transfer <- .dsvert_dp_frequency_execution_transfer_v1(.typed_mint(transport$context, prior$ciphertext,
                transport$recipient_pk), transport$context)
            prior$status <- "minted"
            prior$transfer <- transfer
            state$windows[[key]] <- prior
            ss$.dp_frequency_execution <- state
        })
    }
    else transfer <- .dsvert_dp_frequency_execution_transfer_v1(prior$transfer, transport$context)
    result <- .dsvert_dp_analysis_canonical_value_v1(list(version = .DSVERT_DP_FREQUENCY_SOURCE_RESULT_VERSION, state = "issued",
        artifact_key = authorization$artifact_key, window_index = window$window_index, window_count = window$window_count,
        context = transport$context, ciphertext_chars = prior$ciphertext, transfer = transfer, intermediate_values_exposed = FALSE))
    typed_request <- list(operation_id = operation_id, window_index = transport$context$window_index)
    if (is.null(.typed_commit))
        .typed_commit <- function(request, result) .dsvert_typed_blob_operation_commit(ss, "dsvertDPFrequencySourceWindowDS",
            request, result)
    if (!is.function(.typed_commit))
        stop("Invalid Frequency typed commit.", call. = FALSE)
    result <- .typed_commit(typed_request, result)
    prior$status <- "issued"
    prior$transfer <- transfer
    prior$result <- result
    state$windows[[key]] <- prior
    ss$.dp_frequency_execution <- state
    result
}

.dsvert_dp_frequency_execution_chunk_hash_v1 <- function(values, index, offset) {
    raw <- .dsvert_dp_frequency_execution_ring128_v1(values)
    .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_CHUNK_DOMAIN, list(version = "dsvert-dp-frequency-final-binary-chunk-v1",
        chunk_index = as.integer(index), coordinate_offset = as.integer(offset), coordinate_count = length(values), ring128_b64 = gsub("[\r\n]",
            "", jsonlite::base64_enc(raw))))
}

.dsvert_dp_frequency_execution_window_record_v1 <- function(values, window) {
    hashes <- vapply(seq_len(window$chunks_in_window), function(position) {
        local <- (position - 1L) * 8192L
        count <- min(8192L, window$coordinate_count - local)
        .dsvert_dp_frequency_execution_chunk_hash_v1(values[seq.int(local + 1L, local + count)], window$first_chunk_index +
            position - 1L, window$coordinate_offset + local)
    }, character(1L))
    core <- list(version = "dsvert-dp-frequency-final-window-v1", window_index = window$window_index, coordinate_offset = window$coordinate_offset,
        coordinate_count = window$coordinate_count, chunk_hashes = as.list(hashes))
    list(chunk_hashes = hashes, sha256 = .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_WINDOW_DOMAIN, core))
}

.dsvert_dp_frequency_execution_merkle_v1 <- function(hashes) {
    decode <- function(x) .dsvert_joint_dp_backend_hex_raw_v2(x, "Frequency Merkle hash")
    hash <- function(domain, values) digest::digest(do.call(c, c(list(charToRaw(domain), as.raw(0L)), lapply(values, decode))),
        algo = "sha256", serialize = FALSE)
    nodes <- vapply(hashes, function(x) hash("dsVert/dp-frequency/merkle-leaf/v1", x), character(1L))
    while (length(nodes) > 1L) {
        if (length(nodes)%%2L)
            nodes <- c(nodes, tail(nodes, 1L))
        nodes <- vapply(seq.int(1L, length(nodes), by = 2L), function(i) hash("dsVert/dp-frequency/merkle-parent/v1", nodes[i +
            0:1]), character(1L))
    }
    unname(nodes[[1L]])
}

.dsvert_dp_frequency_execution_release_v1 <- function(authorization, auth_set, windows, .signer) {
    identity <- .get_identity_keypair()
    secondary <- auth_set$values$secondary_noise_authority$local_authority
    local_pk <- tryCatch(.dsvert_dp_frequency_identity_pk_v1(identity$identity_pk, "release signer"), error = function(error) NULL)
    if (!is.function(.signer) || !identical(local_pk, secondary$identity_pk))
        stop("Only the Frequency secondary authority may sign the release.", call. = FALSE)
    chunks <- unlist(lapply(windows, `[[`, "chunk_hashes"), use.names = FALSE)
    worker <- authorization$worker_static
    profile <- worker$selected_profile
    core <- .dsvert_dp_analysis_canonical_value_v1(list(version = .DSVERT_DP_FREQUENCY_RELEASE_VERSION, artifact_key = authorization$artifact_key,
        contract_sha256 = authorization$contract_sha256, analysis_binding_sha256 = authorization$analysis_binding_sha256,
        worker_static_sha256 = authorization$worker_static_sha256, authorization_set_sha256 = auth_set$sha256, release_contract_hash = worker$release_contract_hash,
        primitive = worker$selected_primitive, mechanism = profile$mechanism, sampler = profile$sampler, d = worker$d, chunk_coordinates = 8192L,
        chunk_count = worker$chunk_count, window_count = length(windows), coordinate_order_sha256 = authorization$contract$semantic$analysis$effective_arguments$sampler_plan$coordinate_order_sha256,
        bounds = worker$raw_bound, authority_roles = worker$authority_roles, final_chunk_hashes = as.list(chunks), final_window_hashes = lapply(windows,
            `[[`, "sha256"), final_vector_root = .dsvert_dp_frequency_execution_merkle_v1(chunks), postprocessing = profile$output_transform,
        intermediate_values_exposed = FALSE, public_openings = 1L))
    release_sha256 <- .dsvert_dp_frequency_hash_v1(.DSVERT_DP_FREQUENCY_RELEASE_DOMAIN, core)
    signed <- .dsvert_dp_analysis_canonical_value_v1(c(core, list(release_sha256 = release_sha256)))
    message <- charToRaw(paste0(.DSVERT_DP_FREQUENCY_RELEASE_SIGNATURE_DOMAIN, .dsvert_dp_canonical_json(signed)))
    signature <- .dsvert_dp_frequency_signature_v1(.signer(message, identity$identity_sk))
    .dsvert_dp_analysis_canonical_value_v1(c(signed, list(signature = signature)))
}

.dsvert_dp_frequency_execution_consume_v1 <- function(ss, state, key, transport, .typed_fetch) {
    entry <- state$windows[[key]]
    if (!isTRUE(entry$typed_consumed)) {
        consumed <- .typed_fetch(transport$context, consume = TRUE)
        if (!is.null(consumed) && !identical(consumed, entry$ciphertext))
            stop("Frequency ciphertext changed during typed consumption.", call. = FALSE)
        entry$typed_consumed <- TRUE
        entry$ciphertext <- NULL
        state$windows[[key]] <- entry
        ss$.dp_frequency_execution <- state
    }
    state$windows[[key]]$result
}

.dsvert_dp_frequency_execution_finalize_window_v1 <- function(ss, session_id, operation_id, window_index, public_authorizations,
    .sampler = function(command, input, expected) .callMpcTool(command, input), .decrypt = function(value) .dsvert_dp_frequency_execution_decrypt_v1(ss, value), .typed_fetch = NULL, .verifier = .dsvert_relay_verify_message,
    .signer = .dsvert_relay_sign_message) {
    if (!is.environment(ss) || !is.function(.sampler))
        stop("Invalid Frequency finalizer dependency.", call. = FALSE)
    operation_id <- .dsvert_relay_validate_operation_id(operation_id)
    auth_set <- .dsvert_dp_frequency_execution_authorization_set_v1(ss, session_id, public_authorizations, .verifier)
    authorization <- .dsvert_dp_frequency_session_authorization_validate_v1(ss, session_id)
    if (!identical(authorization$local_authority$role, "secondary_noise_authority"))
        stop("Only the Frequency secondary authority may finalize.", call. = FALSE)
    geometry <- .dsvert_dp_frequency_execution_geometry_v1(authorization$worker_static)
    window <- .dsvert_dp_frequency_execution_window_v1(geometry, window_index)
    transport <- .dsvert_dp_frequency_execution_transport_v1(ss, authorization, auth_set, operation_id, window)
    .dsvert_dp_frequency_execution_reserve_v1(ss, authorization)
    state <- .dsvert_dp_frequency_execution_state_v1(ss, authorization, auth_set, operation_id, "secondary_noise_authority",
        geometry)
    key <- window$window_index + 1L
    prior <- state$windows[[key]]
    sender <- transport$context$sender
    if (is.null(.typed_fetch))
        .typed_fetch <- function(context, consume = FALSE) .dsvert_typed_blob_consume(ss, .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
            context, sender_name = sender, required = !isTRUE(consume), consume = consume)
    if (!is.function(.typed_fetch))
        stop("Invalid Frequency typed fetch.", call. = FALSE)
    if (!is.null(prior)) {
        if (!is.list(prior) || !identical(prior$request, list(context = transport$context)) || !is.list(prior$result))
            stop("Conflicting Frequency finalizer retry.", call. = FALSE)
        return(.dsvert_dp_frequency_execution_consume_v1(ss, state, key, transport, .typed_fetch))
    }
    if (!identical(window$window_index, state$next_window))
        stop("Frequency windows must be finalized in order.", call. = FALSE)
    ciphertext <- .dsvert_dp_frequency_execution_ciphertext_v1(.typed_fetch(transport$context, consume = FALSE))
    if (!is.function(.decrypt))
        stop("Invalid Frequency decryptor.", call. = FALSE)
    frame <- tryCatch(.decrypt(ciphertext), error = function(error) stop("Invalid Frequency ciphertext authentication.",
        call. = FALSE))
    source <- .dsvert_dp_frequency_execution_packet_open_v1(frame, transport$context, transport$peer_binding_digest, window$coordinate_count)
    profile <- .dsvert_dp_frequency_execution_profile_v1(authorization$worker_static)
    for (position in seq_len(window$chunks_in_window)) {
        local <- (position - 1L) * 8192L
        offset <- window$coordinate_offset + local
        count <- min(8192L, window$coordinate_count - local)
        range <- seq.int(local * 16L + 1L, (local + count) * 16L)
        left <- gsub("[\r\n]", "", jsonlite::base64_enc(source[range]))
        zero <- gsub("[\r\n]", "", jsonlite::base64_enc(raw(count * 16L)))
        input <- .dsvert_dp_frequency_execution_sampler_input_v1(authorization, auth_set, "secondary_noise_authority", offset,
            count, zero)
        right_raw <- .dsvert_dp_frequency_execution_share_v1(.sampler(profile$share_command, input, .dsvert_dp_frequency_execution_expected_v1(authorization)),
            input, authorization)
        right <- gsub("[\r\n]", "", jsonlite::base64_enc(right_raw))
        final_input <- .dsvert_dp_frequency_execution_final_input_v1(authorization, offset, count, left, right)
        values <- .dsvert_dp_frequency_execution_final_v1(.sampler(profile$final_command, final_input, .dsvert_dp_frequency_execution_expected_v1(authorization)),
            final_input, authorization)
        state$values[seq.int(offset + 1L, offset + count)] <- values
    }
    record <- .dsvert_dp_frequency_execution_window_record_v1(state$values[seq.int(window$coordinate_offset + 1L, window$coordinate_offset +
        window$coordinate_count)], window)
    final <- identical(key, geometry$window_count)
    result <- if (!final)
        .dsvert_dp_analysis_canonical_value_v1(list(version = .DSVERT_DP_FREQUENCY_FINAL_RESULT_VERSION, state = "window_committed",
            artifact_key = authorization$artifact_key, window_index = window$window_index, window_count = window$window_count,
            intermediate_values_exposed = FALSE))
    else NULL
    state$windows[[key]] <- list(request = list(context = transport$context), ciphertext = ciphertext, typed_consumed = FALSE,
        record = record, result = result)
    state$next_window <- key
    if (final) {
        release <- .dsvert_dp_frequency_execution_release_v1(authorization, auth_set, lapply(state$windows, `[[`, "record"),
            .signer)
        result <- .dsvert_dp_analysis_canonical_value_v1(list(version = .DSVERT_DP_FREQUENCY_FINAL_RESULT_VERSION, state = "release_committed",
            artifact_key = authorization$artifact_key, release = release, intermediate_values_exposed = FALSE))
        state$release <- release
        state$values_ready <- TRUE
        state$windows[[key]]$result <- result
    }
    ss$.dp_frequency_execution <- state
    rm(frame, source)
    .dsvert_dp_frequency_execution_consume_v1(ss, state, key, transport, .typed_fetch)
}

.dsvert_dp_frequency_execution_replay_window_v1 <- function(ss, session_id, operation_id, window_index) {
    authorization <- .dsvert_dp_frequency_session_authorization_validate_v1(ss, session_id)
    operation_id <- .dsvert_relay_validate_operation_id(operation_id)
    geometry <- .dsvert_dp_frequency_execution_geometry_v1(authorization$worker_static)
    window <- .dsvert_dp_frequency_execution_window_v1(geometry, window_index)
    state <- ss$.dp_frequency_execution
    if (!is.list(state) || !identical(state$request$session_id, authorization$session_id) || !identical(state$request$operation_id,
        operation_id) || !identical(state$request$role, "secondary_noise_authority") || !is.list(state$release) || !isTRUE(state$values_ready))
        stop("Frequency release is not complete.", call. = FALSE)
    record <- state$windows[[window$window_index + 1L]]$record
    values <- state$values[seq.int(window$coordinate_offset + 1L, window$coordinate_offset + window$coordinate_count)]
    expected <- .dsvert_dp_frequency_execution_window_record_v1(values, window)
    hashes <- unlist(lapply(state$windows, function(x) x$record$chunk_hashes), use.names = FALSE)
    if (!identical(record, expected) || !identical(unlist(state$release$final_chunk_hashes, use.names = FALSE), hashes) ||
        !identical(state$release$final_vector_root, .dsvert_dp_frequency_execution_merkle_v1(hashes)))
        stop("Frequency committed release state is invalid.", call. = FALSE)
    chunks <- lapply(seq_len(window$chunks_in_window), function(position) {
        local <- (position - 1L) * 8192L
        count <- min(8192L, window$coordinate_count - local)
        chunk_values <- values[seq.int(local + 1L, local + count)]
        list(version = "dsvert-dp-frequency-final-chunk-v1", chunk_index = window$first_chunk_index + position - 1L, coordinate_offset = window$coordinate_offset +
            local, coordinate_count = count, values = as.list(as.character(as.integer(chunk_values))), chunk_sha256 = record$chunk_hashes[[position]])
    })
    public <- .dsvert_dp_analysis_canonical_value_v1(list(version = "dsvert-dp-frequency-final-window-v1", window_index = window$window_index,
        coordinate_offset = window$coordinate_offset, coordinate_count = window$coordinate_count, chunks = chunks, window_sha256 = record$sha256))
    .dsvert_dp_analysis_canonical_value_v1(list(version = .DSVERT_DP_FREQUENCY_FINAL_RESULT_VERSION, state = "release_replay",
        release = state$release, window = public, intermediate_values_exposed = FALSE))
}

.dsvert_dp_frequency_execution_cleanup_v1 <- function(ss) {
    if (!is.environment(ss))
        stop("Invalid Frequency cleanup state.", call. = FALSE)
    ss$.dp_frequency_execution <- NULL
    TRUE
}
