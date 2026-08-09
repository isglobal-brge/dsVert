# Exact two-peer garbled-circuit transport over DSI.
#
# The analyst process is an opaque byte relay only.  Source and result shares
# live in server session state; the four registered methods below can start,
# pump, inspect, or abort a high-level operation, but none can export a share.

.DSVERT_EXACT_GC_CAPABILITY <- "exact_gc_v1"
.DSVERT_EXACT_GC_ENVELOPE_VERSION <- "dsvert-exact-gc-envelope-v1"
.DSVERT_EXACT_GC_ENVELOPE_DOMAIN <- "dsVert/exact-gc/dsi-envelope/v1|"
.DSVERT_EXACT_GC_INPUT_RE <- "^exact_gc_in_[0-9a-f]{32}$"
.DSVERT_EXACT_GC_OUTPUT_RE <- "^exact_gc_out_[0-9a-f]{32}$"
# DSI fans the peer-bound expression list out concurrently. Keep each idle
# request open for one fixed, public window so circuit compilation/garbling does
# not turn into hundreds of empty analyst relay calls. The file check remains
# fine-grained, so an available protocol chunk returns within a few milliseconds.
.DSVERT_EXACT_GC_COALESCE_SECONDS <- 0.05
.DSVERT_EXACT_GC_COALESCE_POLL_SECONDS <- 0.002
.DSVERT_EXACT_GC_FAILURE_VERSION <- "dsvert-exact-gc-failure-v1"
.DSVERT_EXACT_GC_RETRY_CONTRACT <-
  "same-operation-query-transcript-no-reroll-v1"
.DSVERT_EXACT_GC_CLEANUP_CAPABILITY_VERSION <-
  "dsvert-exact-gc-cleanup-capability-v1"
.DSVERT_EXACT_GC_CLEANUP_CAPABILITY_DOMAIN <-
  "dsVert/exact-gc/cleanup-capability/v1|"
.DSVERT_EXACT_GC_CROSS_CLEANUP_PURPOSE <-
  "dp.cross-owner.exact-session.v1"
.DSVERT_EXACT_GC_ANALYSIS_BINDING_VERSION <-
  "dsvert-exact-gc-analysis-binding-v1"
.DSVERT_EXACT_GC_ANALYSIS_PEER_BINDING_VERSION <-
  "dsvert-exact-gc-analysis-peer-binding-v1"
.DSVERT_EXACT_GC_FAILURE_CODES <- c(
  "infrastructure_unavailable", "non_identifiable", "bound_exceeded",
  "numeric_backend_unavailable")
.DSVERT_EXACT_GC_SPOOL_VERSION <- "dsvert-exact-gc-segment-spool-v1"
.DSVERT_EXACT_GC_INBOUND_STATE_VERSION <-
  "dsvert-exact-gc-inbound-state-v1"
.DSVERT_EXACT_GC_SEGMENT_RE <-
  "^segment-([0-9]{16})-([0-9]{16})-([0-9a-f]{64})\\.bin$"
.DSVERT_EXACT_GC_MAX_RING_BITS <- 4096L
.DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS <- 1200L
.DSVERT_EXACT_GC_MAX_RESIDUE_DIGITS <- 1234L
.DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS <- 512L * 1024L
.DSVERT_EXACT_GC_DIRECT_MUL_BIT_WORK <- 512L * 512L * 64L
.DSVERT_EXACT_GC_WIRE_CONTAINER_BITS <-
  c(64L, 128L, 256L, 512L, 1024L, 2048L, 4096L)

.exact_gc_capability_probe <- function() {
  runtime <- tryCatch(
    .dsvert_mpc_require_capabilities(c("exact_gc")),
    error = function(e) NULL)
  if (is.null(runtime)) return(NULL)
  result <- tryCatch(.callMpcTool("exact-gc-capability", list()),
                     error = function(e) NULL)
  required_true <- c(
    "canonical_encoding", "canonical_input_encoding",
    "shape_bounds_enforced",
    "exact_truncation", "core_exact_comparison", "kos_checked_ot",
    "authenticated_records", "selective_output", "pinned_peers_required",
    "relay_opaque", "e2e_verified",
    "count_guard_e2e_verified", "clamp_count_e2e_verified",
    "joint_dp_count_e2e_verified",
    "joint_dp_vector_e2e_verified",
    "alignment_mask_e2e_verified",
    "multiprecision_truncation_e2e_verified")
  valid <- is.list(result) &&
    identical(result$capability_id, .DSVERT_EXACT_GC_CAPABILITY) &&
    identical(as.integer(result$supported_ring_bits),
              63L:.DSVERT_EXACT_GC_MAX_RING_BITS) &&
    identical(as.integer(result$wire_container_bits),
              .DSVERT_EXACT_GC_WIRE_CONTAINER_BITS) &&
    identical(as.integer(result$min_ring_bits), 63L) &&
    identical(as.integer(result$max_ring_bits),
              .DSVERT_EXACT_GC_MAX_RING_BITS) &&
    identical(as.integer(result$max_frac_bits),
              .DSVERT_EXACT_GC_MAX_RING_BITS - 1L) &&
    identical(as.integer(result$max_decimal_bound_digits),
              .DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS) &&
    identical(as.integer(result$max_circuit_type_bits),
              .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS) &&
    identical(as.integer(result$direct_mul_bit_work_budget),
              .DSVERT_EXACT_GC_DIRECT_MUL_BIT_WORK) &&
    identical(as.character(result$operations),
              c("truncate-floor", "count-guard", "clamp-count",
                "joint-dp-laplace-v2", "joint-dp-vector-laplace-v3",
                "alignment-mask-ring128")) &&
    identical(as.character(result$core_operations),
              c("compare-signed", "truncate-floor", "mul-truncate-checked",
                "count-guard", "clamp-count", "joint-dp-laplace-v2",
                "joint-dp-vector-laplace-v3", "alignment-mask-ring128")) &&
    identical(as.character(result$verified_purposes), c(
      "count-guard", "multiprecision-truncate", "joint-dp-count-clamp",
      "joint-dp-count-one-draw",
      "joint-dp-biomedical-vector-one-draw",
      "private-alignment-mask-ring128")) &&
    identical(result$truncation_semantics, "floor") &&
    identical(result$fail_closed_overflow, FALSE) &&
    identical(result$runtime_bounds_enforced, FALSE) &&
    identical(result$raw_product_overflow_guard, FALSE) &&
    identical(result$checked_mul_truncate, FALSE) &&
    identical(result$vecmul_truncation_e2e_verified, FALSE) &&
    identical(result$dynamic_ring_fallback, TRUE) &&
    identical(result$vecmul_numeric_precondition,
              "strict producer-minted input manifest required for promotion") &&
    identical(result$exact_comparison, FALSE) &&
    identical(result$comparison_e2e_verified, FALSE) &&
    identical(result$workload_glm_e2e_verified, FALSE) &&
    all(vapply(required_true, function(name) isTRUE(result[[name]]),
               logical(1L)))
  if (!valid) return(NULL)
  result
}

.exact_gc_scalar <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  enc2utf8(value)
}

.exact_gc_integer <- function(value, what, minimum, maximum) {
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value != floor(value) || value < minimum || value > maximum) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  value
}

.exact_gc_decimal_bound <- function(value, what) {
  value <- .exact_gc_scalar(value, what)
  if (nchar(value, type = "bytes") >
      .DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS ||
      !grepl("^[1-9][0-9]*$", value)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  value
}

.exact_gc_numeric_backend_unrepresentable <- function() {
  stop(structure(
    list(
      message = paste(
        paste0("No certified signed ring through Ring",
               .DSVERT_EXACT_GC_MAX_RING_BITS, " represents the public"),
        "operand and exactly truncated-output bounds."),
      call = NULL,
      code = "numeric_backend_unrepresentable",
      max_ring_bits = .DSVERT_EXACT_GC_MAX_RING_BITS),
    class = c(
      "dsvert_numeric_backend_unrepresentable", "error", "condition")))
}

.exact_gc_mul_plan <- function(bound_x, bound_y, frac_bits,
                               fixed_ring_bits = 0L) {
  bound_x <- .exact_gc_decimal_bound(bound_x, "exact-gc x bound")
  bound_y <- .exact_gc_decimal_bound(bound_y, "exact-gc y bound")
  frac_bits <- as.integer(.exact_gc_integer(
    frac_bits, "exact-gc multiplication fractional bits", 0,
    .DSVERT_EXACT_GC_MAX_RING_BITS - 1L))
  fixed_ring_bits <- as.integer(.exact_gc_integer(
    fixed_ring_bits, "exact-gc fixed ring", 0,
    .DSVERT_EXACT_GC_MAX_RING_BITS))
  if (fixed_ring_bits != 0L && fixed_ring_bits < 63L) {
    stop("Invalid exact-gc fixed ring.", call. = FALSE)
  }
  result <- tryCatch(
    .callMpcTool("exact-gc-plan-mul", list(
      bound_x = bound_x, bound_y = bound_y, frac_bits = frac_bits,
      fixed_ring_bits = fixed_ring_bits)),
    error = function(e) {
      if (grepl("exact-gc multiplication planning failed",
                conditionMessage(e), fixed = TRUE)) {
        .exact_gc_numeric_backend_unrepresentable()
      }
      stop(e)
    })
  required <- c(
    "version", "plan_id", "ring_bits", "container_bits", "frac_bits",
    "bound_x", "bound_y", "truncated_bound", "rounding_mode",
    "backend", "max_chunk",
    "raw_product_headroom", "output_headroom")
  if (!is.list(result) || !identical(sort(names(result)), sort(required)) ||
      !identical(result$version, "dsvert-exact-gc-mul-plan-v3") ||
      !is.character(result$plan_id) ||
      !grepl("^[0-9a-f]{64}$", result$plan_id) ||
      !identical(result$bound_x, bound_x) ||
      !identical(result$bound_y, bound_y) ||
      !grepl("^[1-9][0-9]*$", result$truncated_bound) ||
      !identical(result$rounding_mode, "floor") ||
      !result$backend %in% c("ring127-ot", "direct-wide") ||
      !is.logical(result$raw_product_headroom) ||
      length(result$raw_product_headroom) != 1L ||
      is.na(result$raw_product_headroom) ||
      !isTRUE(result$output_headroom)) {
    stop("The exact-gc multiplication planner returned an invalid contract.",
         call. = FALSE)
  }
  ring_bits <- as.integer(.exact_gc_integer(
    result$ring_bits, "planned exact-gc ring", 63,
    .DSVERT_EXACT_GC_MAX_RING_BITS))
  if (!identical(as.integer(result$frac_bits), frac_bits) ||
      (fixed_ring_bits != 0L && ring_bits != fixed_ring_bits) ||
      !identical(as.integer(result$container_bits),
                 .exact_gc_record_bytes(ring_bits) * 8L) ||
      !identical(as.integer(result$max_chunk),
                 if (identical(result$backend, "ring127-ot")) 256L else
                   .exact_gc_direct_mul_max_chunk(ring_bits)) ||
      (identical(result$backend, "ring127-ot") &&
       (ring_bits != 127L || frac_bits != 50L ||
        !isTRUE(result$raw_product_headroom)))) {
    stop("The exact-gc multiplication planner returned a conflicting contract.",
         call. = FALSE)
  }
  result$ring_bits <- ring_bits
  result$frac_bits <- frac_bits
  result$container_bits <- as.integer(result$container_bits)
  result$max_chunk <- as.integer(result$max_chunk)
  result
}

.exact_gc_option_integer <- function(name, default, minimum, maximum) {
  value <- getOption(paste0("dsvert.exact_gc.", name))
  if (is.null(value)) {
    value <- getOption(paste0("default.dsvert.exact_gc.", name), default)
  }
  .exact_gc_integer(value, paste0("exact-gc ", name, " policy"),
                    minimum, maximum)
}

.exact_gc_chunk_bytes <- function() {
  as.integer(.exact_gc_option_integer(
    "chunk_bytes", 480 * 1024, 16 * 1024, 8 * 1024^2))
}

.exact_gc_spool_max_bytes <- function(chunk_bytes = .exact_gc_chunk_bytes()) {
  .exact_gc_option_integer(
    "spool_max_bytes", 1024^3,
    max(8 * as.numeric(chunk_bytes), 1024^2), 64 * 1024^3)
}

.exact_gc_request_max_bytes <- function(chunk_bytes = .exact_gc_chunk_bytes()) {
  .exact_gc_option_integer(
    "request_max_bytes", 64 * 1024^2,
    max(1024^2, 4 * ceiling(as.numeric(chunk_bytes) / 3) + 16384),
    256 * 1024^2)
}

.exact_gc_ttl_seconds <- function() {
  as.integer(.exact_gc_option_integer("ttl_seconds", 180, 10, 86400))
}

.exact_gc_max_runtime_seconds <- function(
    ttl_seconds = .exact_gc_ttl_seconds()) {
  ttl_seconds <- .exact_gc_integer(
    ttl_seconds, "exact-gc inactivity lease", 10, 86400)
  default <- max(21600, ttl_seconds)
  .exact_gc_option_integer(
    "max_runtime_seconds", default, ttl_seconds, 7 * 86400)
}

.exact_gc_validate_key <- function(key, output = FALSE) {
  key <- .exact_gc_scalar(key, if (output) "exact-gc output key" else
    "exact-gc input key")
  pattern <- if (output) .DSVERT_EXACT_GC_OUTPUT_RE else
    .DSVERT_EXACT_GC_INPUT_RE
  if (!grepl(pattern, key)) {
    stop("Invalid exact-gc state key.", call. = FALSE)
  }
  key
}

.exact_gc_validate_purpose <- function(purpose) {
  purpose <- .exact_gc_scalar(purpose, "exact-gc purpose")
  if (nchar(purpose, type = "bytes") > 128L ||
      !grepl("^[a-z][a-z0-9_.:/-]*$", purpose)) {
    stop("Invalid exact-gc purpose.", call. = FALSE)
  }
  purpose
}

.exact_gc_output_kind <- function(operation) {
  operation <- .exact_gc_scalar(operation, "exact-gc operation")
  if (identical(operation, "compare-signed")) return("ring-share")
  if (identical(operation, "truncate-floor")) return("ring-share")
  if (identical(operation, "clamp-count")) return("ring-share")
  if (identical(operation, "joint-dp-laplace-v2")) {
    return("joint-dp-ring-share-v2")
  }
  if (identical(operation, "joint-dp-vector-laplace-v3")) {
    return("joint-dp-vector-ring128-share-v1")
  }
  if (identical(operation, "joint-dp-vector-gaussian-one-draw-v1")) {
    return("joint-dp-vector-gaussian-one-draw-ring128-share-v1")
  }
  if (identical(operation, "mul-truncate-checked")) {
    return("checked-ring-share")
  }
  if (identical(operation, "alignment-mask-ring128")) {
    return("alignment-masked-ring128-share-v1")
  }
  if (identical(operation, "count-guard")) return("xor-bit-share")
  stop("Unsupported exact-gc high-level operation.", call. = FALSE)
}

.exact_gc_allowed_spec <- function(operation, purpose, frac_bits, output_kind,
                                   ring_bits) {
  operation <- .exact_gc_scalar(operation, "exact-gc operation")
  expected_kind <- .exact_gc_output_kind(operation)
  purpose <- .exact_gc_validate_purpose(purpose)
  ring_bits <- as.integer(.exact_gc_integer(
    ring_bits, "exact-gc ring", 63, .DSVERT_EXACT_GC_MAX_RING_BITS))
  frac_bits <- as.integer(.exact_gc_integer(
    frac_bits, "exact-gc fractional bits", 0, ring_bits - 1L))
  output_kind <- .exact_gc_scalar(output_kind, "exact-gc output kind")
  if (!identical(output_kind, expected_kind) ||
      (operation %in% c(
         "compare-signed", "count-guard", "clamp-count",
         "joint-dp-laplace-v2", "joint-dp-vector-laplace-v3",
         "joint-dp-vector-gaussian-one-draw-v1",
         "alignment-mask-ring128") &&
       frac_bits != 0L)) {
    stop("Invalid exact-gc staged-source contract.", call. = FALSE)
  }
  list(operation = operation, purpose = purpose, frac_bits = frac_bits,
       output_kind = output_kind)
}

.exact_gc_alignment_source_count <- function(value) {
  if (is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^(?:[2-9]|[1-5][0-9]|6[0-4])$", value)) {
    return(as.integer(value))
  }
  candidate <- suppressWarnings(as.numeric(value))
  if (length(candidate) != 1L || is.na(candidate) || !is.finite(candidate) ||
      candidate != floor(candidate) || candidate < 2L || candidate > 64L) {
    stop("Invalid exact-gc alignment source count.", call. = FALSE)
  }
  as.integer(candidate)
}

.exact_gc_bound_protocol_purpose <- function(producer, purpose) {
  producer <- .exact_gc_validate_purpose(producer)
  purpose <- .exact_gc_validate_purpose(purpose)
  paste0("source=", nchar(producer, type = "bytes"), ":", producer,
         "|purpose=", nchar(purpose, type = "bytes"), ":", purpose)
}

.exact_gc_transport_public <- function(ss) {
  transport_pk <- .key_get("transport_pk", ss)
  identity_pk <- .key_get("identity_pk", ss)
  if (is.null(transport_pk) || is.null(identity_pk)) {
    stop("Exact-gc transport is not initialized.", call. = FALSE)
  }
  identity <- .get_identity_keypair()
  signature <- .sign_transport_pk(transport_pk, identity$identity_sk)
  list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    transport_pk = base64_to_base64url(transport_pk),
    identity_pk = base64_to_base64url(identity_pk),
    signature = base64_to_base64url(signature))
}

.exact_gc_validate_handshake_map <- function(value, what,
                                             expected_names = NULL) {
  decoded <- .exact_gc_b64url_decode(value, what, 64 * 1024)
  result <- tryCatch(jsonlite::fromJSON(
    rawToChar(decoded), simplifyVector = FALSE), error = function(e) NULL)
  if (!is.list(result) || !length(result) || is.null(names(result)) ||
      anyDuplicated(names(result)) || any(!nzchar(names(result))) ||
      any(nchar(names(result), type = "bytes") > 128L) ||
      any(!grepl("^[A-Za-z0-9][A-Za-z0-9_.-]*$", names(result)))) {
    stop("Invalid exact-gc peer handshake map.", call. = FALSE)
  }
  if (!is.null(expected_names) &&
      (length(result) != length(expected_names) ||
       !setequal(names(result), expected_names))) {
    stop("Exact-gc handshake must contain exactly the custodian-designated ",
         "pair.", call. = FALSE)
  }
  result
}

.exact_gc_designated_policy_context <- function() {
  configured_name <- .dsvert_require_configured_local_peer_name()
  context <- .dsvert_joint_dp_policy_context(
    .dsvert_dp_policy(), require_designated = TRUE)
  if (!identical(context$peer_name, configured_name)) {
    stop("The joint-DP policy peer_name disagrees with the server-authoritative ",
         "dsvert.peer_name.", call. = FALSE)
  }
  pins <- context$pins
  if (!is.character(pins) || length(pins) != 2L || is.null(names(pins)) ||
      anyDuplicated(names(pins)) || anyDuplicated(unname(pins)) ||
      !configured_name %in% names(pins)) {
    stop("Invalid server-authoritative exact-gc designated-peer policy.",
         call. = FALSE)
  }
  designated <- sort(names(pins), method = "radix")
  pins <- pins[designated]
  full_pinset_hash <- context$common$peer_pinset_sha256
  if (!is.character(full_pinset_hash) ||
      length(full_pinset_hash) != 1L || is.na(full_pinset_hash) ||
      !grepl("^[0-9a-f]{64}$", full_pinset_hash)) {
    stop("Invalid server-authoritative exact-gc pinned-peer digest.",
         call. = FALSE)
  }
  list(
    peer_name = configured_name,
    designated = designated,
    pins = pins,
    full_pinset_sha256 = full_pinset_hash,
    consortium_id = context$consortium_id)
}

.exact_gc_verify_designated_pair <- function(
    identity_info, transport_keys, own_identity_pk, own_transport_pk,
    policy_context) {
  expected_names <- policy_context$designated
  if (length(identity_info) != 2L || length(transport_keys) != 2L ||
      !setequal(names(identity_info), expected_names) ||
      !setequal(names(transport_keys), expected_names)) {
    stop("Exact-gc handshake must contain exactly the custodian-designated ",
         "pair.", call. = FALSE)
  }
  own_name <- policy_context$peer_name
  own_identity_pk <- .dsvert_normalize_crypto_b64(
    own_identity_pk, 32L, "own Ed25519 identity public key")
  own_transport_pk <- .dsvert_normalize_crypto_b64(
    own_transport_pk, 32L, "own transport public key")
  expected_pins <- vapply(
    policy_context$pins, .dsvert_normalize_crypto_b64, character(1L),
    expected_bytes = 32L, what = "designated Ed25519 identity public key",
    USE.NAMES = TRUE)
  if (!identical(own_identity_pk, unname(expected_pins[[own_name]]))) {
    stop("The local Ed25519 identity disagrees with its server-authoritative ",
         "joint-DP pin.", call. = FALSE)
  }

  peer_transport <- character(0)
  normalized_identity <- character(0)
  normalized_transport <- character(0)
  for (name in expected_names) {
    info <- identity_info[[name]]
    if (!is.list(info) ||
        !identical(sort(names(info)), c("identity_pk", "signature"))) {
      stop("Invalid exact-gc signed identity entry.", call. = FALSE)
    }
    identity_pk <- .dsvert_normalize_crypto_b64(
      info$identity_pk, 32L,
      paste0("identity public key for '", name, "'"))
    signature <- .dsvert_normalize_crypto_b64(
      info$signature, 64L,
      paste0("transport signature for '", name, "'"))
    transport_pk <- .dsvert_normalize_crypto_b64(
      transport_keys[[name]], 32L,
      paste0("transport public key for '", name, "'"))
    expected_identity <- unname(expected_pins[[name]])
    if (!identical(identity_pk, expected_identity)) {
      if (identical(name, own_name)) {
        stop("Exact-gc handshake relabels or substitutes this server's ",
             "identity.", call. = FALSE)
      }
      .dsvert_stop_peer_not_recognized(
        name, identity_pk, expected_identity,
        reason = "Pinned identity mismatch")
    }
    if (!.verify_peer_identity(transport_pk, identity_pk, signature)) {
      stop("Identity verification failed for '", name,
           "': invalid signature on transport PK.", call. = FALSE)
    }
    if (identical(name, own_name)) {
      if (!identical(identity_pk, own_identity_pk) ||
          !identical(transport_pk, own_transport_pk)) {
        stop("Exact-gc self identity binding is invalid.", call. = FALSE)
      }
    } else {
      peer_transport[[name]] <- transport_pk
    }
    normalized_identity[[name]] <- base64_to_base64url(identity_pk)
    normalized_transport[[name]] <- base64_to_base64url(transport_pk)
  }
  if (length(peer_transport) != 1L) {
    stop("Exact-gc requires exactly one signed pinned peer.", call. = FALSE)
  }
  list(
    peer_transport = peer_transport,
    identity_pks = normalized_identity[expected_names],
    transport_pks = normalized_transport[expected_names])
}

.exact_gc_designated_binding_digest <- function(
    session_id, policy_context, verified) {
  contract <- list(
    version = "dsvert-exact-gc-designated-binding-v2",
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    session_id = session_id,
    consortium_id = policy_context$consortium_id,
    full_peer_pinset_sha256 = policy_context$full_pinset_sha256,
    designated_peers = as.list(policy_context$designated),
    designated_peer_pinset = as.list(stats::setNames(
      vapply(policy_context$pins, .dsvert_relay_normalize_identity_pk,
             character(1L)), policy_context$designated)),
    identity_pks = as.list(verified$identity_pks),
    transport_pks = as.list(verified$transport_pks))
  list(
    contract = contract,
    sha256 = .exact_gc_peer_binding_contract_digest(contract))
}

.exact_gc_analysis_contract_binding <- function(contract) {
  contract <- .dsvert_dp_analysis_contract_validate_v1(contract)
  semantic <- contract$semantic
  if (!identical(semantic$analysis$primitive, "joint-dp-laplace-v2") ||
      !identical(contract$execution$backend$kernel,
                 "joint-dp-laplace-v2") ||
      !identical(contract$execution$backend$ring, "ring127")) {
    stop("The exact-gc analysis contract is not the audited Count shape.",
         call. = FALSE)
  }
  full_pins <- unlist(contract$execution$peer_pins, use.names = TRUE)
  if (any(!grepl("^[A-Za-z0-9][A-Za-z0-9_.-]*$", names(full_pins))) ||
      any(nchar(names(full_pins), type = "bytes") > 128L)) {
    stop("Invalid full K peer names in the exact-gc analysis contract.",
         call. = FALSE)
  }
  full_pins <- full_pins[order(names(full_pins), method = "radix")]
  authorities <- unlist(
    semantic$noise_authorities, use.names = FALSE)
  authority_names <- names(full_pins)[match(authorities, unname(full_pins))]
  authority_peer_ids <- vapply(
    authorities, .dsvert_relay_peer_id, character(1L), USE.NAMES = FALSE)
  authority_order <- order(authority_peer_ids, method = "radix")
  authority_roles <- as.list(stats::setNames(
    authorities[authority_order], c("garbler", "evaluator")))
  semantic_sha256 <- digest::digest(
    .dsvert_dp_canonical_json(semantic), algo = "sha256",
    serialize = FALSE)
  binding <- .dsvert_dp_analysis_canonical_value_v1(list(
    version = .DSVERT_EXACT_GC_ANALYSIS_BINDING_VERSION,
    artifact_key = contract$artifact_key,
    semantic_contract_sha256 = semantic_sha256,
    authority_roles = authority_roles))
  list(
    contract = contract,
    full_pins = full_pins,
    authority_names = authority_names,
    binding = binding,
    sha256 = .exact_gc_peer_binding_contract_digest(binding))
}

.exact_gc_analysis_policy_context <- function(
    analysis, identity_info, own_identity_pk) {
  expected <- analysis
  authority_names <- expected$authority_names
  if (!is.list(identity_info) || length(identity_info) != 2L ||
      is.null(names(identity_info)) || anyNA(names(identity_info)) ||
      anyDuplicated(names(identity_info)) ||
      !setequal(names(identity_info), authority_names)) {
    stop("Exact-gc peer names do not match the two noise authorities.",
         call. = FALSE)
  }
  supplied <- vapply(names(identity_info), function(name) {
    info <- identity_info[[name]]
    if (!is.list(info) || !is.character(info$identity_pk) ||
        length(info$identity_pk) != 1L || is.na(info$identity_pk)) {
      stop("Invalid exact-gc noise authority identity.", call. = FALSE)
    }
    .dsvert_relay_normalize_identity_pk(info$identity_pk)
  }, character(1L), USE.NAMES = TRUE)
  supplied <- supplied[authority_names]
  if (!identical(supplied, expected$full_pins[authority_names])) {
    stop("Exact-gc peer name and pin do not match the noise authorities.",
         call. = FALSE)
  }
  own_identity_pk <- .dsvert_relay_normalize_identity_pk(own_identity_pk)
  own_name <- authority_names[match(
    own_identity_pk, unname(expected$full_pins[authority_names]))]
  if (length(own_name) != 1L || is.na(own_name)) {
    stop("The local identity is not an exact-gc noise authority.",
         call. = FALSE)
  }
  designated <- sort(authority_names, method = "radix")
  list(
    peer_name = unname(own_name),
    designated = designated,
    pins = expected$full_pins[designated],
    full_pins = expected$full_pins,
    full_pinset_sha256 = digest::digest(
      .dsvert_dp_canonical_json(as.list(expected$full_pins)),
      algo = "sha256", serialize = FALSE),
    consortium_id = expected$contract$artifact_key)
}

.exact_gc_analysis_peer_binding_digest <- function(
    session_id, analysis, policy_context, verified) {
  contract <- list(
    version = .DSVERT_EXACT_GC_ANALYSIS_PEER_BINDING_VERSION,
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    session_id = session_id,
    consortium_id = policy_context$consortium_id,
    full_peer_pinset_sha256 = policy_context$full_pinset_sha256,
    designated_peers = as.list(policy_context$designated),
    designated_peer_pinset = as.list(policy_context$pins),
    identity_pks = as.list(verified$identity_pks),
    transport_pks = as.list(verified$transport_pks),
    analysis_binding = analysis$binding,
    analysis_binding_sha256 = analysis$sha256)
  list(
    contract = contract,
    sha256 = .exact_gc_peer_binding_contract_digest(contract))
}

.exact_gc_analysis_count_worker_validate_v1 <- function(
    ss, session_id, joint_dp, ring, frac_bits, vector_len, purpose,
    .compiler = NULL) {
  binding <- ss$.exact_gc_peer_binding_contract
  if (!is.list(binding) || !identical(
        binding$version, .DSVERT_EXACT_GC_ANALYSIS_PEER_BINDING_VERSION)) {
    stop("Invalid analysis-bound exact-gc Count worker contract.",
         call. = FALSE)
  }
  authorization <- .dsvert_dp_count_session_authorization_validate_v1(
    ss, session_id, binding$consortium_id)
  expected <- authorization$worker_static
  static_fields <- c(
    "sampler", "stop_numerator", "sensitivity_steps", "epsilon",
    "allocated_delta", "encoded_lower", "encoded_upper",
    "transcript_hash", "garbler_commitment_context",
    "evaluator_commitment_context", "implementation_delta_numerator",
    "implementation_delta_denominator")
  if (ring != expected$ring_bits || frac_bits != expected$frac_bits ||
      vector_len != expected$coordinate_count || !is.list(joint_dp) ||
      !identical(joint_dp$version,
                 .DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2) ||
      !identical(as.integer(joint_dp$bernoulli_bits),
                 as.integer(expected$bernoulli_bits)) ||
      !identical(as.integer(joint_dp$max_geometric_steps),
                 as.integer(expected$max_geometric_steps)) ||
      !all(vapply(static_fields, function(field) {
        identical(joint_dp[[field]], expected[[field]])
      }, logical(1L)))) {
    stop("Invalid analysis-bound exact-gc Count worker contract.",
         call. = FALSE)
  }
  input <- list(
    version = .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT_INPUT,
    ring_bits = expected$ring_bits, frac_bits = expected$frac_bits,
    coordinate_count = expected$coordinate_count,
    epsilon = expected$epsilon,
    allocated_delta = expected$allocated_delta,
    sensitivity_steps = expected$sensitivity_steps,
    encoded_lower = expected$encoded_lower,
    encoded_upper = expected$encoded_upper,
    bernoulli_bits = expected$bernoulli_bits, max_steps = 4096L,
    transcript_hash = expected$transcript_hash,
    garbler_commitment_context = expected$garbler_commitment_context,
    evaluator_commitment_context = expected$evaluator_commitment_context,
    garbler_seed_commitment = joint_dp$garbler_seed_commitment,
    evaluator_seed_commitment = joint_dp$evaluator_seed_commitment)
  compiler <- if (is.null(.compiler)) function(value) {
    .callMpcTool("joint-dp-laplace-worker-contract-v2", value)
  } else .compiler
  if (!is.function(compiler)) {
    stop("Invalid analysis-bound Count worker compiler.", call. = FALSE)
  }
  compiled <- compiler(input)
  required <- c(
    "version", "capability_id", "operation", "purpose", "circuit_digest",
    "input_contract", "protected_inputs_accepted", "private_seed_accepted",
    "worker_policy", "capability_available")
  valid <- is.list(compiled) && !is.null(names(compiled)) &&
    !anyNA(names(compiled)) && !anyDuplicated(names(compiled)) &&
    setequal(names(compiled), required) &&
    identical(compiled$version,
              .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT) &&
    identical(compiled$capability_id,
              .DSVERT_JOINT_DP_COUNT_EXACT_CAPABILITY) &&
    identical(compiled$operation, "joint-dp-laplace-v2") &&
    identical(compiled$input_contract, "public-data-free-count-v1") &&
    identical(compiled$protected_inputs_accepted, FALSE) &&
    identical(compiled$private_seed_accepted, FALSE) &&
    identical(compiled$capability_available, TRUE) &&
    is.character(compiled$circuit_digest) &&
    length(compiled$circuit_digest) == 1L &&
    grepl("^[0-9a-f]{64}$", compiled$circuit_digest) &&
    identical(compiled$purpose,
              paste0("joint-dp-laplace-v2/", compiled$circuit_digest)) &&
    identical(compiled$purpose, purpose) &&
    identical(compiled$worker_policy$circuit_digest,
              compiled$circuit_digest) &&
    identical(.dsvert_dp_canonical_query_value(compiled$worker_policy),
              .dsvert_dp_canonical_query_value(joint_dp))
  if (!isTRUE(valid)) {
    stop("Invalid analysis-bound exact-gc Count worker contract.",
         call. = FALSE)
  }
  authorization
}

.exact_gc_peer_binding_contract_digest <- function(contract) {
  digest::digest(
    .dsvert_dp_canonical_json(contract), algo = "sha256",
    serialize = FALSE)
}

.exact_gc_binding_named_pks <- function(value, expected_names, what) {
  if (is.list(value)) value <- unlist(value, use.names = TRUE)
  if (!is.character(value) || length(value) != 2L ||
      is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) ||
      !setequal(names(value), expected_names)) {
    stop("Invalid ", what, " in exact-gc peer binding.", call. = FALSE)
  }
  normalized <- vapply(
    value, .dsvert_relay_normalize_identity_pk, character(1L),
    USE.NAMES = TRUE)
  normalized[expected_names]
}

.exact_gc_validate_bound_peer_context <- function(ss, session_id) {
  if (!is.environment(ss)) stop("Invalid exact-gc session state.", call. = FALSE)
  binding_digest <- ss$.exact_gc_peer_binding_digest
  contract <- ss$.exact_gc_peer_binding_contract
  if (!is.character(binding_digest) || length(binding_digest) != 1L ||
      is.na(binding_digest) ||
      !grepl("^[0-9a-f]{64}$", binding_digest) || !is.list(contract) ||
      !identical(.exact_gc_peer_binding_contract_digest(contract),
                 binding_digest)) {
    stop("Exact-gc requires an intact authenticated peer-binding contract.",
         call. = FALSE)
  }
  required <- c(
    "version", "capability_id", "session_id", "consortium_id",
    "full_peer_pinset_sha256", "designated_peers",
    "designated_peer_pinset", "identity_pks", "transport_pks")
  analysis_bound <- identical(
    contract$version, .DSVERT_EXACT_GC_ANALYSIS_PEER_BINDING_VERSION)
  if (analysis_bound) {
    required <- c(required, "analysis_binding", "analysis_binding_sha256")
  }
  if (is.null(names(contract)) || anyNA(names(contract)) ||
      anyDuplicated(names(contract)) || !setequal(names(contract), required) ||
      !contract$version %in% c(
        "dsvert-exact-gc-designated-binding-v2",
        "dsvert-exact-gc-psi-binding-v1",
        .DSVERT_EXACT_GC_ANALYSIS_PEER_BINDING_VERSION) ||
      !identical(contract$capability_id, .DSVERT_EXACT_GC_CAPABILITY) ||
      !identical(contract$session_id, session_id) ||
      !is.character(contract$consortium_id) ||
      length(contract$consortium_id) != 1L || is.na(contract$consortium_id) ||
      !nzchar(contract$consortium_id) ||
      !is.character(contract$full_peer_pinset_sha256) ||
      length(contract$full_peer_pinset_sha256) != 1L ||
      is.na(contract$full_peer_pinset_sha256) ||
      !grepl("^[0-9a-f]{64}$", contract$full_peer_pinset_sha256)) {
    stop("Invalid exact-gc authenticated peer-binding contract.",
         call. = FALSE)
  }
  designated <- unlist(contract$designated_peers, use.names = FALSE)
  if (!is.character(designated) || length(designated) != 2L ||
      anyNA(designated) || anyDuplicated(designated) ||
      !identical(designated, sort(designated, method = "radix"))) {
    stop("Invalid exact-gc designated peer binding.", call. = FALSE)
  }
  self_name <- ss$.exact_gc_self_name
  peer_names <- names(ss$peer_transport_pks %||% list())
  if (!is.character(self_name) || length(self_name) != 1L ||
      is.na(self_name) || !self_name %in% designated ||
      length(peer_names) != 1L ||
      !identical(peer_names, setdiff(designated, self_name))) {
    stop("Exact-gc session peers disagree with the authenticated binding.",
         call. = FALSE)
  }
  bound_identities <- .exact_gc_binding_named_pks(
    contract$identity_pks, designated, "identity map")
  bound_transports <- .exact_gc_binding_named_pks(
    contract$transport_pks, designated, "transport map")
  bound_pins <- .exact_gc_binding_named_pks(
    contract$designated_peer_pinset, designated, "designated pinset")
  current_identities <- c(
    stats::setNames(
      .dsvert_relay_normalize_identity_pk(.key_get("identity_pk", ss)),
      self_name),
    vapply(
      ss$.exact_gc_peer_identity_pks[peer_names],
      .dsvert_relay_normalize_identity_pk, character(1L),
      USE.NAMES = TRUE))
  current_transports <- c(
    stats::setNames(
      .dsvert_relay_normalize_identity_pk(.key_get("transport_pk", ss)),
      self_name),
    vapply(
      ss$peer_transport_pks[peer_names],
      .dsvert_relay_normalize_identity_pk, character(1L),
      USE.NAMES = TRUE))
  current_identities <- current_identities[designated]
  current_transports <- current_transports[designated]
  if (!identical(bound_identities, current_identities) ||
      !identical(bound_transports, current_transports) ||
      !identical(bound_pins, bound_identities)) {
    stop("Exact-gc session keys disagree with the authenticated peer binding.",
         call. = FALSE)
  }

  if (identical(contract$version,
                "dsvert-exact-gc-designated-binding-v2") ||
      analysis_bound) {
    # exactGCBindPeersDS installs the typed producer manifest as a child of
    # this policy/session binding. Recompute its digest from the immutable
    # contract instead of trusting the cached value consumed by ticket minting.
    # Padded PSI stages its fixed-shape share directly and has no typed manifest.
    typed_identity_info <- lapply(
      as.list(bound_identities), function(identity_pk) {
        list(identity_pk = identity_pk)
      })
    expected_typed_digest <- .dsvert_typed_blob_peer_binding(
      typed_identity_info, as.list(bound_transports),
      parent_binding_digest = binding_digest)
    typed_peers <- ss$.typed_blob_peer_identity_pks
    if (!is.list(typed_peers) || is.null(names(typed_peers)) ||
        anyNA(names(typed_peers)) || anyDuplicated(names(typed_peers)) ||
        !setequal(names(typed_peers), peer_names) ||
        !identical(ss$.typed_blob_self_name, self_name) ||
        !identical(ss$.typed_blob_parent_binding_digest, binding_digest) ||
        !identical(ss$.typed_blob_peer_binding_digest,
                   expected_typed_digest)) {
      stop("Exact-gc typed transport disagrees with the authenticated peer ",
           "binding.", call. = FALSE)
    }
    normalized_typed_peers <- vapply(
      typed_peers[peer_names], .dsvert_relay_normalize_identity_pk,
      character(1L), USE.NAMES = TRUE)
    if (!identical(normalized_typed_peers, bound_identities[peer_names])) {
      stop("Exact-gc typed transport disagrees with the authenticated peer ",
           "binding.", call. = FALSE)
    }
    if (analysis_bound) {
      authorization <-
        .dsvert_dp_count_session_authorization_validate_v1(
          ss, session_id, contract$consortium_id)
      analysis <- .exact_gc_analysis_contract_binding(
        authorization$contract)
      identity_info <- lapply(as.list(bound_identities), function(identity_pk) {
        list(identity_pk = identity_pk)
      })
      context <- .exact_gc_analysis_policy_context(
        analysis, identity_info, .key_get("identity_pk", ss))
      if (!identical(ss$.exact_gc_analysis_contract,
                     authorization$contract) ||
          !identical(ss$.exact_gc_analysis_binding, analysis$binding) ||
          !identical(ss$.exact_gc_analysis_binding_sha256,
                     analysis$sha256) ||
          !identical(contract$analysis_binding, analysis$binding) ||
          !identical(contract$analysis_binding_sha256, analysis$sha256) ||
          !identical(context$peer_name, self_name) ||
          !identical(context$designated, designated) ||
          !identical(context$consortium_id, contract$consortium_id) ||
          !identical(context$full_pinset_sha256,
                     contract$full_peer_pinset_sha256) ||
          !identical(context$pins[designated], bound_pins)) {
        stop("The analysis contract conflicts with the authenticated ",
             "exact-gc peer binding.", call. = FALSE)
      }
    } else {
      context <- .exact_gc_designated_policy_context()
      current_pins <- vapply(
        context$pins[context$designated],
        .dsvert_relay_normalize_identity_pk, character(1L),
        USE.NAMES = TRUE)
      if (!identical(context$peer_name, self_name) ||
          !identical(context$designated, designated) ||
          !identical(context$consortium_id, contract$consortium_id) ||
          !identical(context$full_pinset_sha256,
                     contract$full_peer_pinset_sha256) ||
          !identical(current_pins, bound_pins)) {
        stop("The current server policy conflicts with the authenticated ",
             "exact-gc peer binding.", call. = FALSE)
      }
    }
  } else {
    state <- ss$.psi_padded_state
    psi_contract <- if (is.list(state)) state$contract else NULL
    expected_pin_hash <- if (is.list(psi_contract) &&
                             is.character(psi_contract$pinset_id)) {
      sub("^pinset_", "", psi_contract$pinset_id)
    } else ""
    if (!is.list(psi_contract) ||
        !identical(psi_contract$contract_hash, contract$consortium_id) ||
        !identical(expected_pin_hash,
                   contract$full_peer_pinset_sha256) ||
        !identical(sort(psi_contract$compute_peers, method = "radix"),
                   designated)) {
      stop("The padded PSI contract conflicts with its exact-gc peer binding.",
           call. = FALSE)
    }
  }
  binding_digest
}

.exact_gc_b64url_encode <- function(value) {
  if (!is.raw(value)) stop("Exact-gc payload must be raw.", call. = FALSE)
  base64_to_base64url(gsub("[\r\n]", "", jsonlite::base64_enc(value)))
}

.exact_gc_b64url_decode <- function(value, what, max_bytes = Inf) {
  value <- .exact_gc_scalar(value, what)
  encoded_bytes <- as.numeric(nchar(value, type = "bytes"))
  if (is.finite(max_bytes)) {
    encoded_capacity <- 4 * ceiling(max_bytes / 3) + 4
    if (encoded_bytes > encoded_capacity) {
      .dsvert_resource_oversize(
        encoded_bytes, encoded_capacity,
        paste("exact-gc", what, "wire value"))
    }
  }
  if (!grepl("^[A-Za-z0-9_-]+$", value) || nchar(value) %% 4L == 1L) {
    stop("Invalid or oversized ", what, ".", call. = FALSE)
  }
  decoded <- tryCatch(
    jsonlite::base64_dec(.base64url_to_base64(value)),
    error = function(e) NULL)
  if (!is.null(decoded) && is.finite(max_bytes) &&
      length(decoded) > max_bytes) {
    .dsvert_resource_oversize(
      length(decoded), max_bytes, paste("exact-gc", what))
  }
  if (is.null(decoded) ||
      !identical(.exact_gc_b64url_encode(decoded), value)) {
    stop("Invalid or non-canonical ", what, ".", call. = FALSE)
  }
  decoded
}

.exact_gc_standard_b64_raw <- function(value, expected_bytes, what) {
  value <- .exact_gc_scalar(value, what)
  encoded_bytes <- as.numeric(nchar(value, type = "bytes"))
  encoded_capacity <- 4 * ceiling(as.numeric(expected_bytes) / 3)
  if (encoded_bytes > encoded_capacity) {
    .dsvert_resource_oversize(
      encoded_bytes, encoded_capacity,
      paste("exact-gc", what, "wire value"))
  }
  if (!grepl("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
             value)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  decoded <- tryCatch(jsonlite::base64_dec(value), error = function(e) NULL)
  canonical <- if (is.null(decoded)) NULL else
    gsub("[\r\n]", "", jsonlite::base64_enc(decoded))
  if (is.null(decoded) || length(decoded) != expected_bytes ||
      !identical(canonical, value)) {
    stop("Invalid or non-canonical ", what, ".", call. = FALSE)
  }
  decoded
}

.exact_gc_record_bytes <- function(ring_bits) {
  container_bits <- 64L
  while (container_bits < ring_bits) {
    container_bits <- container_bits * 2L
  }
  as.integer(container_bits / 8L)
}

.exact_gc_direct_mul_max_chunk <- function(ring_bits) {
  container_bits <- .exact_gc_record_bytes(ring_bits) * 8L
  as.integer(min(
    64,
    floor((.DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS / container_bits - 1) / 7),
    floor(.DSVERT_EXACT_GC_DIRECT_MUL_BIT_WORK / container_bits^2)))
}

# Convert exact non-negative decimal residues to the worker's fixed-width,
# little-endian record format.  R doubles are deliberately never involved:
# Ring128 includes values well beyond 2^53 and every boundary must survive
# byte-for-byte.  This helper is internal to server-side producers/finalizers.
.exact_gc_decimal_residues_b64 <- function(values, ring_bits) {
  ring_candidate <- suppressWarnings(as.numeric(ring_bits))
  if (length(ring_candidate) == 1L && !is.na(ring_candidate) &&
      is.finite(ring_candidate) && ring_candidate == floor(ring_candidate) &&
      ring_candidate > .DSVERT_EXACT_GC_MAX_RING_BITS) {
    .dsvert_resource_oversize(
      ring_candidate, .DSVERT_EXACT_GC_MAX_RING_BITS,
      "exact-gc decimal residue ring")
  }
  ring_bits <- as.integer(.exact_gc_integer(
    ring_bits, "exact-gc residue ring", 63,
    .DSVERT_EXACT_GC_MAX_RING_BITS))
  if (is.character(values) && length(values) > 4096L) {
    .dsvert_resource_oversize(
      length(values), 4096L, "exact-gc decimal residue vector")
  }
  digit_lengths <- if (is.character(values) && length(values)) {
    nchar(values, type = "bytes")
  } else {
    numeric()
  }
  if (length(digit_lengths) &&
      any(digit_lengths > .DSVERT_EXACT_GC_MAX_RESIDUE_DIGITS,
          na.rm = TRUE)) {
    .dsvert_resource_oversize(
      max(digit_lengths, na.rm = TRUE),
      .DSVERT_EXACT_GC_MAX_RESIDUE_DIGITS,
      "exact-gc decimal residue digits")
  }
  if (!is.character(values) || !length(values) || anyNA(values) ||
      any(!grepl("^(0|[1-9][0-9]*)$", values))) {
    stop("Invalid exact-gc decimal residue vector.", call. = FALSE)
  }
  modulus <- openssl::bignum(2) ^ ring_bits
  record_bytes <- .exact_gc_record_bytes(ring_bits)
  records <- lapply(values, function(value) {
    number <- tryCatch(openssl::bignum(value), error = function(e) NULL)
    if (is.null(number) || number < openssl::bignum(0) ||
        number >= modulus) {
      stop("An exact-gc decimal residue is outside the requested ring.",
           call. = FALSE)
    }
    big_endian <- as.raw(number)
    if (length(big_endian) > record_bytes) {
      stop("An exact-gc decimal residue exceeds its wire container.",
           call. = FALSE)
    }
    rev(c(raw(record_bytes - length(big_endian)), big_endian))
  })
  encoded <- gsub("[\r\n]", "", jsonlite::base64_enc(do.call(c, records)))
  .exact_gc_validate_residue_records(
    encoded, ring_bits, length(values), "exact-gc decimal residue")
  encoded
}

.exact_gc_validate_residue_records <- function(value, ring_bits, vector_len,
                                               what) {
  record_bytes <- .exact_gc_record_bytes(ring_bits)
  decoded <- .exact_gc_standard_b64_raw(
    value, record_bytes * vector_len, what)
  if (ring_bits == 63L) return(decoded)
  used_bytes <- as.integer(ceiling(ring_bits / 8))
  used_bits <- ring_bits %% 8L
  for (index in seq_len(vector_len)) {
    first <- (index - 1L) * record_bytes + 1L
    if (used_bits) {
      last_used <- first + used_bytes - 1L
      allowed <- bitwShiftL(1L, used_bits) - 1L
      if (bitwAnd(as.integer(decoded[[last_used]]),
                  bitwXor(allowed, 255L)) != 0L) {
        stop("Non-canonical ", what, ".", call. = FALSE)
      }
    }
    if (used_bytes < record_bytes) {
      unused <- decoded[seq.int(first + used_bytes,
                                first + record_bytes - 1L)]
      if (any(as.integer(unused) != 0L)) {
        stop("Non-canonical ", what, ".", call. = FALSE)
      }
    }
  }
  decoded
}

# Internal producer boundary.  Downstream MPC code stages one canonical share;
# no registered method exposes this helper or accepts arbitrary source bytes.
.exact_gc_stage_share <- function(ss, key, share, ring_bits, vector_len,
                                  producer, operation, purpose, frac_bits,
                                  output_kind,
                                  alignment_source_count = NULL,
                                  gaussian_one_draw_authority_sha256 = NULL) {
  if (!is.environment(ss)) stop("Invalid exact-gc session state.", call. = FALSE)
  key <- .exact_gc_validate_key(key)
  ring_candidate <- suppressWarnings(as.numeric(ring_bits))
  if (length(ring_candidate) == 1L && !is.na(ring_candidate) &&
      is.finite(ring_candidate) && ring_candidate == floor(ring_candidate) &&
      ring_candidate > .DSVERT_EXACT_GC_MAX_RING_BITS) {
    .dsvert_resource_oversize(
      ring_candidate, .DSVERT_EXACT_GC_MAX_RING_BITS,
      "exact-gc source ring")
  }
  ring_bits <- as.integer(.exact_gc_integer(
    ring_bits, "exact-gc ring", 63, .DSVERT_EXACT_GC_MAX_RING_BITS))
  vector_candidate <- suppressWarnings(as.numeric(vector_len))
  if (length(vector_candidate) == 1L && !is.na(vector_candidate) &&
      is.finite(vector_candidate) &&
      vector_candidate == floor(vector_candidate) &&
      vector_candidate > 4096) {
    .dsvert_resource_oversize(
      vector_candidate, 4096, "exact-gc source vector shape")
  }
  vector_len <- as.integer(.exact_gc_integer(
    vector_len, "exact-gc vector length", 1, 4096))
  producer <- .exact_gc_validate_purpose(producer)
  allowed_spec <- .exact_gc_allowed_spec(
    operation, purpose, frac_bits, output_kind, ring_bits)
  alignment_k <- NULL
  if (identical(operation, "alignment-mask-ring128")) {
    alignment_k <- .exact_gc_alignment_source_count(alignment_source_count)
    if (ring_bits != 128L || allowed_spec$frac_bits != 0L) {
      stop("Invalid exact-gc alignment-mask staged source.", call. = FALSE)
    }
    allowed_spec$alignment_source_count <- alignment_k
  } else if (!is.null(alignment_source_count)) {
    stop("Unexpected exact-gc alignment source count.", call. = FALSE)
  }
  if (identical(operation, "joint-dp-vector-gaussian-one-draw-v1")) {
    if (!is.character(gaussian_one_draw_authority_sha256) ||
        length(gaussian_one_draw_authority_sha256) != 1L ||
        is.na(gaussian_one_draw_authority_sha256) ||
        !grepl("^[0-9a-f]{64}$",
               gaussian_one_draw_authority_sha256)) {
      stop("One-draw Gaussian staging requires exact recipient authority.",
           call. = FALSE)
    }
  } else if (!is.null(gaussian_one_draw_authority_sha256)) {
    stop("Unexpected one-draw Gaussian source authority.", call. = FALSE)
  }
  input_containers <- if (identical(operation, "mul-truncate-checked")) {
    7L * vector_len + 1L
  } else if (identical(
      operation, "joint-dp-vector-gaussian-one-draw-v1")) {
    # Two 128-bit source shares, two private 128-bit sampler words and sign
    # bits, plus the garbler's public bounds and fresh output masks. Seven
    # Ring128 containers per coordinate is a conservative type-size envelope.
    7L * vector_len + 1L
  } else if (identical(operation, "alignment-mask-ring128")) {
    3L * vector_len + 4L * alignment_k + 1L
  } else if (identical(operation, "count-guard")) {
    2L * vector_len + 1L
  } else if (identical(operation, "truncate-floor")) {
    3L * vector_len
  } else {
    3L * vector_len
  }
  max_vector <- if (identical(
      operation, "joint-dp-vector-gaussian-one-draw-v1")) {
    128L
  } else if (identical(operation, "mul-truncate-checked")) {
    if (ring_bits == 127L && allowed_spec$frac_bits == 50L) 256L else
      .exact_gc_direct_mul_max_chunk(ring_bits)
  } else 4096L
  if (vector_len > max_vector) {
    .dsvert_resource_oversize(
      vector_len, max_vector, "exact-gc source vector shape")
  }
  circuit_bits <- .exact_gc_record_bytes(ring_bits) * 8L * input_containers
  if (circuit_bits > .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS) {
    .dsvert_resource_oversize(
      circuit_bits, .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS,
      "exact-gc source circuit type")
  }
  source_records <- if (identical(operation, "mul-truncate-checked")) {
    2L * vector_len
  } else if (identical(operation, "alignment-mask-ring128")) {
    vector_len + 2L * alignment_k
  } else {
    vector_len
  }
  .exact_gc_validate_residue_records(
    share, ring_bits, source_records, "exact-gc source share")
  if (is.null(ss$.exact_gc_inputs)) ss$.exact_gc_inputs <- list()
  previous <- ss$.exact_gc_inputs[[key]]
  staged <- list(
    share = share, ring_bits = ring_bits, vector_len = vector_len,
    producer = producer, allowed_spec = allowed_spec, claimed_by = NULL,
    gaussian_one_draw_authority_sha256 =
      gaussian_one_draw_authority_sha256)
  if (!is.null(previous)) {
    same_value <- identical(previous$share, share) &&
      identical(previous$ring_bits, ring_bits) &&
      identical(previous$vector_len, vector_len) &&
      identical(previous$producer, producer) &&
      identical(previous$allowed_spec, allowed_spec) &&
      identical(previous$gaussian_one_draw_authority_sha256,
                gaussian_one_draw_authority_sha256)
    if (!is.null(previous$claimed_by) || !same_value) {
      stop("Exact-gc source key is already in use.", call. = FALSE)
    }
    return(invisible(key))
  }
  ss$.exact_gc_inputs[[key]] <- staged
  invisible(key)
}

# Internal consumer boundary.  A caller must know the operation and expected
# result kind; consumption is one-shot and never crosses the DSI API.
.exact_gc_consume_output <- function(ss, key, operation_id, expected_kind,
                                     expected_operation, expected_purpose,
                                     expected_ring_bits, expected_frac_bits,
                                     expected_vector_len,
                                     expected_source_producer,
                                     consume = TRUE) {
  if (!is.environment(ss)) stop("Invalid exact-gc session state.", call. = FALSE)
  if (!is.logical(consume) || length(consume) != 1L || is.na(consume)) {
    stop("Invalid exact-gc consumption mode.", call. = FALSE)
  }
  key <- .exact_gc_validate_key(key, output = TRUE)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  expected_kind <- .exact_gc_scalar(expected_kind, "exact-gc output kind")
  expected_source_producer <- .exact_gc_validate_purpose(
    expected_source_producer)
  expected_ring_bits <- as.integer(.exact_gc_integer(
    expected_ring_bits, "exact-gc ring", 63,
    .DSVERT_EXACT_GC_MAX_RING_BITS))
  expected_spec <- .exact_gc_allowed_spec(
    expected_operation, expected_purpose, expected_frac_bits, expected_kind,
    expected_ring_bits)
  expected_vector_len <- as.integer(.exact_gc_integer(
    expected_vector_len, "exact-gc vector length", 1, 4096))
  state <- .exact_gc_operation_state(ss, operation_id)
  value <- ss$.exact_gc_outputs[[key]]
  context_matches <- identical(state$status, "complete") &&
    identical(state$output_key, key) &&
    identical(state$context_hash, value$context_hash) &&
    identical(state$operation, expected_spec$operation) &&
    identical(state$purpose, expected_spec$purpose) &&
    identical(state$ring_bits, expected_ring_bits) &&
    identical(state$frac_bits, expected_spec$frac_bits) &&
    identical(state$vector_len, expected_vector_len) &&
    identical(state$output_kind, expected_spec$output_kind) &&
    identical(state$source_producer, expected_source_producer)
  if (is.null(value) || !isTRUE(context_matches) ||
      !identical(value$operation_id, operation_id) ||
      !identical(value$kind, expected_kind) ||
      !identical(value$operation, expected_spec$operation) ||
      !identical(value$purpose, expected_spec$purpose) ||
      !identical(value$ring_bits, expected_ring_bits) ||
      !identical(value$frac_bits, expected_spec$frac_bits) ||
      !identical(value$vector_len, expected_vector_len) ||
      !identical(value$source_producer, expected_source_producer)) {
    stop("Exact-gc output is unavailable or has the wrong context.", call. = FALSE)
  }
  if (isTRUE(consume)) ss$.exact_gc_outputs[[key]] <- NULL
  value
}

.exact_gc_ops <- function(ss) {
  if (!is.environment(ss$.exact_gc_ops)) {
    ss$.exact_gc_ops <- new.env(parent = emptyenv())
  }
  ss$.exact_gc_ops
}

.exact_gc_operation_state <- function(ss, operation_id, required = TRUE) {
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  state <- .exact_gc_ops(ss)[[operation_id]]
  if (is.null(state) && isTRUE(required)) {
    stop("Unknown exact-gc operation.", call. = FALSE)
  }
  state
}

.exact_gc_spool_dir <- function(ss, operation_id, create = FALSE) {
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  root <- file.path(.ensure_session_dir(ss), "exact_gc")
  path <- file.path(root, operation_id)
  if (isTRUE(create)) {
    dir.create(path, recursive = TRUE, showWarnings = FALSE, mode = "0700")
    Sys.chmod(root, mode = "0700")
    Sys.chmod(path, mode = "0700")
  }
  normalized_root <- normalizePath(root, mustWork = FALSE)
  normalized_path <- normalizePath(path, mustWork = FALSE)
  if (!identical(dirname(normalized_path), normalized_root)) {
    stop("Unsafe exact-gc spool path.", call. = FALSE)
  }
  if (dir.exists(path)) {
    info <- file.info(path)
    if (isTRUE(info$isdir) && bitwAnd(as.integer(info$mode), 63L) != 0L) {
      stop("Exact-gc spool is group/world accessible.", call. = FALSE)
    }
    if (!isTRUE(info$isdir) || nzchar(Sys.readlink(path))) {
      stop("Unsafe exact-gc spool directory.", call. = FALSE)
    }
  }
  path
}

.exact_gc_private_file <- function(path, bytes = raw(0)) {
  con <- file(path, "wb")
  on.exit(close(con), add = TRUE)
  if (length(bytes)) writeBin(bytes, con)
  flush(con)
  Sys.chmod(path, mode = "0600")
  invisible(path)
}

# Commit one private control file through a same-directory temporary file.
# A short write, failed close, or failed rename leaves the previous committed
# value untouched. Segment contents carry their own SHA-256 name, so a storage
# failure that survives a machine crash is detected before any byte is used.
.exact_gc_private_replace <- function(path, bytes) {
  if (!is.raw(bytes)) stop("Invalid exact-gc private state.", call. = FALSE)
  tmp <- tempfile(".exact-gc-state-", tmpdir = dirname(path))
  committed <- FALSE
  on.exit(if (!committed && file.exists(tmp)) unlink(tmp), add = TRUE)
  con <- file(tmp, "wb")
  closed <- FALSE
  on.exit(if (!closed) tryCatch(close(con), error = function(e) NULL),
          add = TRUE)
  if (length(bytes)) writeBin(bytes, con)
  flush(con)
  close(con)
  closed <- TRUE
  size <- file.size(tmp)
  if (length(size) != 1L || is.na(size) || size != length(bytes)) {
    stop("Could not persist exact-gc private state.", call. = FALSE)
  }
  Sys.chmod(tmp, mode = "0600")
  if (!file.rename(tmp, path)) {
    stop("Could not commit exact-gc private state.", call. = FALSE)
  }
  Sys.chmod(path, mode = "0600")
  committed <- TRUE
  invisible(path)
}

.exact_gc_offset_text <- function(value, what = "exact-gc byte offset") {
  value <- .exact_gc_integer(value, what, 0, 2^53)
  format(value, scientific = FALSE, trim = TRUE)
}

.exact_gc_offset_read <- function(path, what = "exact-gc byte offset") {
  info <- file.info(path)
  if (!file.exists(path) || length(info$isdir) != 1L || is.na(info$isdir) ||
      isTRUE(info$isdir) || nzchar(Sys.readlink(path)) ||
      bitwAnd(as.integer(info$mode), 63L) != 0L ||
      info$size < 1L || info$size > 32L) {
    stop("Unsafe exact-gc offset state.", call. = FALSE)
  }
  # Read through one open/close operation. `file.info(path)` and a subsequent
  # size-limited read can otherwise observe different generations while the Go
  # worker atomically renames a longer/shorter decimal offset, fabricating an
  # apparent rollback from two individually valid files.
  bytes <- tryCatch(
    readBin(path, what = "raw", n = 33L),
    error = function(e) stop("Unsafe exact-gc offset state.", call. = FALSE))
  if (!length(bytes) || length(bytes) > 32L) {
    stop("Unsafe exact-gc offset state.", call. = FALSE)
  }
  value <- rawToChar(bytes)
  if (!grepl("^(0|[1-9][0-9]{0,15})$", value)) {
    stop("Invalid exact-gc offset state.", call. = FALSE)
  }
  parsed <- .exact_gc_integer(value, what, 0, 2^53)
  if (!identical(.exact_gc_offset_text(parsed, what), value)) {
    stop("Non-canonical exact-gc offset state.", call. = FALSE)
  }
  parsed
}

.exact_gc_offset_write <- function(path, value, what = "exact-gc byte offset") {
  text <- .exact_gc_offset_text(value, what)
  .exact_gc_private_replace(path, charToRaw(text))
  invisible(as.numeric(value))
}

.exact_gc_inbound_state_read <- function(state) {
  path <- file.path(state$spool, "inbound.state")
  info <- file.info(path)
  if (!file.exists(path) || length(info$isdir) != 1L || is.na(info$isdir) ||
      isTRUE(info$isdir) || nzchar(Sys.readlink(path)) ||
      bitwAnd(as.integer(info$mode), 63L) != 0L ||
      info$size < 1L || info$size > 256L) {
    stop("Unsafe exact-gc inbound state.", call. = FALSE)
  }
  value <- readChar(path, nchars = info$size, useBytes = TRUE)
  fields <- strsplit(value, "|", fixed = TRUE)[[1L]]
  if (length(fields) != 5L ||
      !identical(fields[[1L]], .DSVERT_EXACT_GC_INBOUND_STATE_VERSION)) {
    stop("Invalid exact-gc inbound state.", call. = FALSE)
  }
  head <- .exact_gc_integer(fields[[2L]], "exact-gc inbound head", 0, 2^53)
  if (!identical(fields[[2L]], .exact_gc_offset_text(
      head, "exact-gc inbound head"))) {
    stop("Non-canonical exact-gc inbound state.", call. = FALSE)
  }
  if (identical(fields[[3L]], "-") && identical(fields[[4L]], "-") &&
      identical(fields[[5L]], "-")) {
    if (head != 0) stop("Invalid exact-gc inbound state.", call. = FALSE)
    return(list(head = 0, last_offset = NULL, last_end = NULL,
                last_hash = NULL))
  }
  last_offset <- .exact_gc_integer(
    fields[[3L]], "exact-gc inbound retry offset", 0, 2^53)
  last_end <- .exact_gc_integer(
    fields[[4L]], "exact-gc inbound retry end", 1, 2^53)
  if (!identical(fields[[3L]], .exact_gc_offset_text(
        last_offset, "exact-gc inbound retry offset")) ||
      !identical(fields[[4L]], .exact_gc_offset_text(
        last_end, "exact-gc inbound retry end")) ||
      last_offset >= last_end || last_end != head ||
      !grepl("^[0-9a-f]{64}$", fields[[5L]])) {
    stop("Invalid exact-gc inbound state.", call. = FALSE)
  }
  list(head = head, last_offset = last_offset, last_end = last_end,
       last_hash = fields[[5L]])
}

.exact_gc_inbound_state_write <- function(state, head, last_offset,
                                           last_hash) {
  head <- .exact_gc_integer(head, "exact-gc inbound head", 1, 2^53)
  last_offset <- .exact_gc_integer(
    last_offset, "exact-gc inbound retry offset", 0, head - 1)
  if (!is.character(last_hash) || length(last_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", last_hash)) {
    stop("Invalid exact-gc inbound retry hash.", call. = FALSE)
  }
  fields <- c(
    .DSVERT_EXACT_GC_INBOUND_STATE_VERSION,
    .exact_gc_offset_text(head), .exact_gc_offset_text(last_offset),
    .exact_gc_offset_text(head), last_hash)
  .exact_gc_private_replace(
    file.path(state$spool, "inbound.state"),
    charToRaw(paste(fields, collapse = "|")))
  invisible(head)
}

.exact_gc_segment_name <- function(offset, end, hash) {
  offset <- .exact_gc_integer(offset, "exact-gc segment offset", 0, 2^53)
  end <- .exact_gc_integer(end, "exact-gc segment end", 1, 2^53)
  if (offset >= end || !is.character(hash) || length(hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", hash)) {
    stop("Invalid exact-gc segment descriptor.", call. = FALSE)
  }
  sprintf("segment-%016.0f-%016.0f-%s.bin", offset, end, hash)
}

.exact_gc_segment_list <- function(path) {
  if (!dir.exists(path) || nzchar(Sys.readlink(path))) {
    stop("Unsafe exact-gc segment directory.", call. = FALSE)
  }
  dir_info <- file.info(path)
  if (!isTRUE(dir_info$isdir) ||
      bitwAnd(as.integer(dir_info$mode), 63L) != 0L) {
    stop("Unsafe exact-gc segment directory.", call. = FALSE)
  }
  names <- list.files(path, all.files = TRUE, no.. = TRUE)
  temporary <- grepl("^\\.exact-gc-(segment|state)-", names)
  unexpected <- names[!temporary & !grepl(.DSVERT_EXACT_GC_SEGMENT_RE, names)]
  if (length(unexpected)) {
    stop("Unexpected exact-gc segment artifact.", call. = FALSE)
  }
  names <- names[grepl(.DSVERT_EXACT_GC_SEGMENT_RE, names)]
  if (!length(names)) {
    return(data.frame(
      name = character(), path = character(), offset = numeric(),
      end = numeric(), hash = character(), size = numeric(),
      stringsAsFactors = FALSE))
  }
  parsed <- lapply(names, function(name) {
    captures <- regmatches(name, regexec(
      .DSVERT_EXACT_GC_SEGMENT_RE, name, perl = TRUE))[[1L]]
    if (length(captures) != 4L) {
      stop("Invalid exact-gc segment name.", call. = FALSE)
    }
    offset <- .exact_gc_integer(
      captures[[2L]], "exact-gc segment offset", 0, 2^53)
    end <- .exact_gc_integer(captures[[3L]], "exact-gc segment end", 1, 2^53)
    if (offset >= end || !identical(
        .exact_gc_segment_name(offset, end, captures[[4L]]), name)) {
      stop("Non-canonical exact-gc segment name.", call. = FALSE)
    }
    segment_path <- file.path(path, name)
    # The worker is the only process allowed to remove inbound segments and R
    # the only one allowed to remove acknowledged outbound segments. A name
    # disappearing between list.files() and file.info() is therefore safe
    # compaction, not transcript corruption.
    if (!file.exists(segment_path)) return(NULL)
    info <- file.info(segment_path)
    if (!file.exists(segment_path)) return(NULL)
    if (!identical(info$isdir, FALSE) ||
        nzchar(Sys.readlink(segment_path)) ||
        bitwAnd(as.integer(info$mode), 63L) != 0L ||
        is.na(info$size) || info$size != end - offset) {
      stop("Unsafe or truncated exact-gc segment.", call. = FALSE)
    }
    list(name = name, path = segment_path, offset = offset, end = end,
         hash = captures[[4L]], size = as.numeric(info$size))
  })
  parsed <- Filter(Negate(is.null), parsed)
  if (!length(parsed)) {
    return(data.frame(
      name = character(), path = character(), offset = numeric(),
      end = numeric(), hash = character(), size = numeric(),
      stringsAsFactors = FALSE))
  }
  order_index <- order(vapply(parsed, `[[`, numeric(1L), "offset"),
                       vapply(parsed, `[[`, numeric(1L), "end"))
  parsed <- parsed[order_index]
  result <- data.frame(
    name = vapply(parsed, `[[`, character(1L), "name"),
    path = vapply(parsed, `[[`, character(1L), "path"),
    offset = vapply(parsed, `[[`, numeric(1L), "offset"),
    end = vapply(parsed, `[[`, numeric(1L), "end"),
    hash = vapply(parsed, `[[`, character(1L), "hash"),
    size = vapply(parsed, `[[`, numeric(1L), "size"),
    stringsAsFactors = FALSE)
  if (nrow(result) > 1L &&
      any(result$offset[-1L] < result$end[-nrow(result)])) {
    stop("Overlapping exact-gc segments.", call. = FALSE)
  }
  result
}

.exact_gc_segment_verify <- function(segment) {
  actual <- digest::digest(
    file = segment$path, algo = "sha256", serialize = FALSE)
  if (!identical(actual, segment$hash)) {
    stop("Exact-gc segment hash mismatch.", call. = FALSE)
  }
  invisible(TRUE)
}

.exact_gc_segment_retained_bytes <- function(path) {
  segments <- .exact_gc_segment_list(path)
  total <- sum(segments$size)
  if (!is.finite(total) || total < 0 || total > 2^53) {
    stop("Invalid exact-gc retained segment size.", call. = FALSE)
  }
  as.numeric(total)
}

.exact_gc_segment_publish <- function(path, offset, value, max_bytes) {
  if (!is.raw(value) || !length(value)) {
    stop("Invalid exact-gc segment payload.", call. = FALSE)
  }
  offset <- .exact_gc_integer(offset, "exact-gc segment offset", 0, 2^53)
  end <- offset + length(value)
  end <- .exact_gc_integer(end, "exact-gc segment end", 1, 2^53)
  max_bytes <- .exact_gc_integer(
    max_bytes, "exact-gc spool limit", 1, 64 * 1024^3)
  hash <- digest::digest(value, algo = "sha256", serialize = FALSE)
  name <- .exact_gc_segment_name(offset, end, hash)
  target <- file.path(path, name)
  segments <- .exact_gc_segment_list(path)
  same_range <- segments$offset == offset & segments$end == end
  if (any(same_range)) {
    existing <- segments[which(same_range)[[1L]], , drop = FALSE]
    if (!file.exists(existing$path[[1L]])) {
      segments <- segments[!same_range, , drop = FALSE]
    } else if (!identical(existing$name[[1L]], name)) {
      stop("Conflicting exact-gc segment retry.", call. = FALSE)
    } else {
      verified <- tryCatch({
        .exact_gc_segment_verify(existing[1L, , drop = FALSE])
        TRUE
      }, error = function(e) {
        if (!file.exists(existing$path[[1L]])) FALSE else stop(e)
      })
      if (isTRUE(verified)) return(invisible(end))
      segments <- segments[!same_range, , drop = FALSE]
    }
  }
  if (any(segments$offset < end & segments$end > offset)) {
    stop("Conflicting exact-gc segment overlap.", call. = FALSE)
  }
  retained <- sum(segments$size)
  if (length(value) > max_bytes) {
    .dsvert_resource_oversize(
      length(value), max_bytes, "exact-gc segmented spool")
  }
  if (!is.finite(retained) || retained > max_bytes - length(value)) {
    .dsvert_resource_backpressure(
      retained, length(value), max_bytes, "exact-gc segmented spool")
  }
  .exact_gc_private_replace(target, value)
  # The atomic rename transfers ownership to the worker. It verifies the
  # filename hash through its already-open descriptor and may consume and
  # unlink the segment before this publisher returns. Re-opening the pathname
  # here would therefore turn successful hand-off into a false failure.
  invisible(end)
}

.exact_gc_backpressure_pause <- function() Sys.sleep(0.002)

.exact_gc_wait_inbound_capacity <- function(state, head, additional) {
  head <- .exact_gc_integer(head, "exact-gc inbound head", 0, 2^53)
  numeric_additional <- suppressWarnings(as.numeric(additional))
  if (length(numeric_additional) == 1L &&
      !is.na(numeric_additional) && is.finite(numeric_additional) &&
      numeric_additional > state$spool_max_bytes) {
    .dsvert_resource_oversize(
      numeric_additional, state$spool_max_bytes,
      "exact-gc inbound spool")
  }
  additional <- .exact_gc_integer(
    additional, "exact-gc inbound segment length", 1, state$spool_max_bytes)
  ttl <- suppressWarnings(as.numeric(state$ttl_seconds))
  if (length(ttl) != 1L || is.na(ttl) || !is.finite(ttl) || ttl <= 0) {
    ttl <- 180
  }
  deadline <- proc.time()[["elapsed"]] + ttl
  repeat {
    consumed <- .exact_gc_offset_read(
      file.path(state$spool, "inbound.ack"),
      "exact-gc consumed inbound offset")
    if (consumed > head) {
      stop("Exact-gc inbound consumption offset is ahead of its stream.",
           call. = FALSE)
    }
    physical <- .exact_gc_segment_retained_bytes(
      file.path(state$spool, "inbound.segments"))
    logical <- head - consumed
    if (max(physical, logical) + additional <= state$spool_max_bytes) {
      return(invisible(TRUE))
    }
    alive <- isTRUE(tryCatch(
      state$process$is_alive(), error = function(e) FALSE))
    if (!alive || file.exists(file.path(state$spool, "error")) ||
        file.exists(file.path(state$spool, "failure.json"))) {
      stop("Exact-gc worker stopped while applying spool backpressure.",
           call. = FALSE)
    }
    if (proc.time()[["elapsed"]] >= deadline) {
      retained <- max(physical, logical)
      .dsvert_resource_backpressure(
        retained, additional, state$spool_max_bytes,
        "exact-gc inbound spool")
    }
    .exact_gc_backpressure_pause()
  }
}

.exact_gc_inbound_append <- function(state, offset, value) {
  offset <- .exact_gc_integer(offset, "exact-gc delivery offset", 0, 2^53)
  if (!is.raw(value) || !length(value)) {
    stop("Invalid exact-gc delivery.", call. = FALSE)
  }
  inbound <- .exact_gc_inbound_state_read(state)
  hash <- digest::digest(value, algo = "sha256", serialize = FALSE)
  end <- offset + length(value)
  if (offset < inbound$head) {
    if (!identical(offset, inbound$last_offset) ||
        !identical(end, inbound$last_end) ||
        !identical(hash, inbound$last_hash)) {
      stop("Conflicting exact-gc delivery retry.", call. = FALSE)
    }
    return(invisible(inbound$head))
  }
  if (offset > inbound$head) {
    stop("Exact-gc delivery offset gap.", call. = FALSE)
  }
  target <- file.path(
    state$spool, "inbound.segments",
    .exact_gc_segment_name(offset, end, hash))
  if (file.exists(target)) {
    # Recovery after publication succeeded but the atomic inbound-state commit
    # was interrupted. Re-verify and commit; do not count the same segment as
    # a second capacity reservation.
    .exact_gc_segment_publish(
      file.path(state$spool, "inbound.segments"), offset, value,
      state$spool_max_bytes)
    .exact_gc_inbound_state_write(state, end, offset, hash)
    return(invisible(end))
  }
  .exact_gc_wait_inbound_capacity(state, inbound$head, length(value))
  .exact_gc_segment_publish(
    file.path(state$spool, "inbound.segments"), offset, value,
    state$spool_max_bytes)
  .exact_gc_inbound_state_write(state, end, offset, hash)
  invisible(end)
}

.exact_gc_segment_read <- function(state, offset, max_bytes) {
  offset <- .exact_gc_integer(offset, "exact-gc read offset", 0, 2^53)
  max_bytes <- .exact_gc_integer(
    max_bytes, "exact-gc read length", 1, state$chunk_bytes)
  head <- .exact_gc_offset_read(
    file.path(state$spool, "outbound.head"), "exact-gc outbound head")
  if (offset > head) stop("Exact-gc read offset gap.", call. = FALSE)
  if (offset == head) return(raw(0))
  remaining <- min(max_bytes, head - offset)
  segments <- .exact_gc_segment_list(
    file.path(state$spool, "outbound.segments"))
  cursor <- offset
  chunks <- list()
  while (remaining > 0) {
    selected <- which(segments$offset <= cursor & segments$end > cursor)
    if (length(selected) != 1L) {
      stop("Exact-gc outbound segment gap.", call. = FALSE)
    }
    segment <- segments[selected, , drop = FALSE]
    .exact_gc_segment_verify(segment)
    local_offset <- cursor - segment$offset[[1L]]
    n <- min(remaining, segment$end[[1L]] - cursor)
    chunks[[length(chunks) + 1L]] <- .exact_gc_read_at(
      segment$path[[1L]], local_offset, n)
    cursor <- cursor + n
    remaining <- remaining - n
  }
  do.call(c, chunks)
}

.exact_gc_outbound_offer_write <- function(state, envelope) {
  start <- .exact_gc_integer(
    envelope$offset, "exact-gc offered offset", 0, 2^53)
  n <- .exact_gc_integer(
    envelope$chunk_bytes, "exact-gc offered length", 1, state$chunk_bytes)
  end <- .exact_gc_integer(start + n, "exact-gc offered end", 1, 2^53)
  hash <- envelope$payload_hash
  if (!is.character(hash) || length(hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", hash)) {
    stop("Invalid exact-gc offered payload hash.", call. = FALSE)
  }
  value <- paste(
    .DSVERT_EXACT_GC_SPOOL_VERSION, .exact_gc_offset_text(start),
    .exact_gc_offset_text(end), hash, sep = "|")
  .exact_gc_private_replace(
    file.path(state$spool, "outbound.offer"), charToRaw(value))
  invisible(list(offset = start, end = end, hash = hash))
}

.exact_gc_outbound_offer_read <- function(state) {
  path <- file.path(state$spool, "outbound.offer")
  info <- file.info(path)
  if (!file.exists(path) || is.na(info$size) || info$size < 1L ||
      info$size > 256L || isTRUE(info$isdir) || nzchar(Sys.readlink(path)) ||
      bitwAnd(as.integer(info$mode), 63L) != 0L) {
    stop("Missing exact-gc outbound offer.", call. = FALSE)
  }
  fields <- strsplit(readChar(
    path, nchars = info$size, useBytes = TRUE), "|", fixed = TRUE)[[1L]]
  if (length(fields) != 4L ||
      !identical(fields[[1L]], .DSVERT_EXACT_GC_SPOOL_VERSION) ||
      !grepl("^[0-9a-f]{64}$", fields[[4L]])) {
    stop("Invalid exact-gc outbound offer.", call. = FALSE)
  }
  start <- .exact_gc_integer(fields[[2L]], "exact-gc offered offset", 0, 2^53)
  end <- .exact_gc_integer(fields[[3L]], "exact-gc offered end", 1, 2^53)
  if (!identical(fields[[2L]], .exact_gc_offset_text(
        start, "exact-gc offered offset")) ||
      !identical(fields[[3L]], .exact_gc_offset_text(
        end, "exact-gc offered end")) || start >= end) {
    stop("Invalid exact-gc outbound offer.", call. = FALSE)
  }
  list(offset = start, end = end, hash = fields[[4L]])
}

.exact_gc_outbound_compact <- function(state, acknowledged) {
  acknowledged <- .exact_gc_integer(
    acknowledged, "exact-gc acknowledged outbound offset", 0, 2^53)
  ack_path <- file.path(state$spool, "outbound.ack")
  previous <- .exact_gc_offset_read(
    ack_path, "exact-gc acknowledged outbound offset")
  head <- .exact_gc_offset_read(
    file.path(state$spool, "outbound.head"), "exact-gc outbound head")
  if (acknowledged < previous || acknowledged > head) {
    stop("Invalid exact-gc outbound compaction offset.", call. = FALSE)
  }
  if (acknowledged > previous) {
    # The durable absolute base advances before reclamation. A crash after this
    # point can retain extra ciphertext, but can never make it readable again.
    .exact_gc_offset_write(
      ack_path, acknowledged, "exact-gc acknowledged outbound offset")
  }
  state$outbound_ack_offset <- acknowledged
  segments <- .exact_gc_segment_list(
    file.path(state$spool, "outbound.segments"))
  drop <- segments$end <= acknowledged
  if (any(drop)) {
    for (path in segments$path[drop]) {
      status <- if (file.exists(path)) unlink(path) else 0L
      if (!identical(as.integer(status), 0L) || file.exists(path)) {
        stop("Could not compact exact-gc outbound spool.", call. = FALSE)
      }
    }
  }
  invisible(acknowledged)
}

.exact_gc_segment_read_coalesced <- function(state, offset, long_poll = TRUE) {
  offset <- .exact_gc_integer(offset, "exact-gc read offset", 0, 2^53)
  if (!is.logical(long_poll) || length(long_poll) != 1L || is.na(long_poll)) {
    stop("Invalid exact-gc long-poll policy.", call. = FALSE)
  }
  head_path <- file.path(state$spool, "outbound.head")
  head <- .exact_gc_offset_read(head_path, "exact-gc outbound head")
  if (offset > head) stop("Exact-gc read offset gap.", call. = FALSE)
  if (isTRUE(long_poll) && identical(state$status, "running") &&
      head - offset < state$chunk_bytes) {
    started <- proc.time()[["elapsed"]]
    deadline <- started + .DSVERT_EXACT_GC_COALESCE_SECONDS
    repeat {
      remaining <- deadline - proc.time()[["elapsed"]]
      if (remaining <= 0) break
      Sys.sleep(min(.DSVERT_EXACT_GC_COALESCE_POLL_SECONDS, remaining))
      head <- .exact_gc_offset_read(head_path, "exact-gc outbound head")
      if (offset > head) stop("Exact-gc outbound spool rolled back.", call. = FALSE)
      if (head - offset >= state$chunk_bytes) break
    }
  }
  .exact_gc_segment_read(state, offset, state$chunk_bytes)
}

.exact_gc_now <- function() floor(as.numeric(Sys.time()))

.exact_gc_worker_heartbeat_record <- function(state) {
  path <- file.path(state$spool, "worker.hb")
  info <- file.info(path)
  valid <- file.exists(path) && length(info$isdir) == 1L &&
    !is.na(info$isdir) && !isTRUE(info$isdir) &&
    !nzchar(Sys.readlink(path)) &&
    bitwAnd(as.integer(info$mode), 63L) == 0L &&
    is.finite(info$size) && info$size >= 1L && info$size <= 1024L
  if (!isTRUE(valid)) {
    stop("Unsafe exact-gc worker heartbeat.", call. = FALSE)
  }
  bytes <- tryCatch(
    readBin(path, what = "raw", n = 1025L), error = function(e) raw(0))
  if (!length(bytes) || length(bytes) > 1024L) {
    stop("Unsafe exact-gc worker heartbeat.", call. = FALSE)
  }
  record <- tryCatch(jsonlite::fromJSON(
    rawToChar(bytes), simplifyVector = TRUE), error = function(e) NULL)
  required <- c("version", "session_id", "pid", "counter", "mac")
  if (!is.list(record) || !identical(sort(names(record)), sort(required)) ||
      !identical(record$version, "dsvert-exact-gc-worker-heartbeat-v1") ||
      !identical(record$session_id, state$worker_heartbeat_session) ||
      !is.character(record$mac) || length(record$mac) != 1L ||
      is.na(record$mac) || !grepl("^[0-9a-f]{64}$", record$mac)) {
    stop("Unauthenticated exact-gc worker heartbeat.", call. = FALSE)
  }
  pid <- .exact_gc_integer(record$pid, "exact-gc worker PID", 1, 2^31 - 1)
  counter <- .exact_gc_integer(
    record$counter, "exact-gc worker heartbeat counter", 1, 2^53 - 1)
  if (!identical(pid, as.numeric(state$worker_pid))) {
    stop("Exact-gc worker heartbeat PID mismatch.", call. = FALSE)
  }
  material <- paste(
    record$version, record$session_id,
    format(pid, scientific = FALSE, trim = TRUE),
    format(counter, scientific = FALSE, trim = TRUE), sep = "|")
  expected <- digest::hmac(
    key = state$worker_heartbeat_key, object = charToRaw(material),
    algo = "sha256", serialize = FALSE)
  if (!identical(record$mac, expected)) {
    stop("Unauthenticated exact-gc worker heartbeat.", call. = FALSE)
  }
  list(pid = pid, counter = counter)
}

.exact_gc_relay_heartbeat <- function(state, now = .exact_gc_now(),
                                       force = FALSE) {
  interval <- max(1, min(5, floor(state$ttl_seconds / 4)))
  previous <- suppressWarnings(as.numeric(state$relay_heartbeat_at))
  due <- isTRUE(force) || length(previous) != 1L || is.na(previous) ||
    !is.finite(previous) || now - previous >= interval
  if (isTRUE(due)) {
    .exact_gc_private_replace(
      file.path(state$spool, "exchange.hb"), charToRaw("."))
    state$relay_heartbeat_at <- as.numeric(now)
  }
  invisible(isTRUE(due))
}

.exact_gc_observe_worker_heartbeat <- function(
    ss, state, now = .exact_gc_now()) {
  record <- .exact_gc_worker_heartbeat_record(state)
  previous <- suppressWarnings(as.numeric(state$worker_heartbeat_counter))
  if (length(previous) != 1L || is.na(previous) || !is.finite(previous) ||
      previous < 1 || previous != floor(previous)) {
    stop("Invalid exact-gc worker heartbeat state.", call. = FALSE)
  }
  if (record$counter < previous) {
    stop("Exact-gc worker heartbeat rolled back.", call. = FALSE)
  }
  # Only a newly authenticated counter from the bound PID/session renews the
  # lease. Re-reading the same marker through empty DSI polls changes nothing.
  if (record$counter > previous) {
    state$worker_heartbeat_seen_at <- as.numeric(now)
    state$worker_heartbeat_counter <- record$counter
    .session_progress(ss, now)
    return(invisible(TRUE))
  }
  invisible(FALSE)
}

.exact_gc_touch <- function(state, now = .exact_gc_now(), ss = NULL) {
  if (!is.environment(state) || !is.numeric(now) || length(now) != 1L ||
      is.na(now) || !is.finite(now)) {
    stop("Invalid exact-gc progress timestamp.", call. = FALSE)
  }
  .exact_gc_relay_heartbeat(state, now, force = TRUE)
  state$last_activity <- as.numeric(now)
  if (!is.null(ss)) .session_progress(ss, now)
  invisible(state$last_activity)
}

.exact_gc_with_lock <- function(state, code) {
  lock <- tryCatch(
    filelock::lock(file.path(state$spool, "exchange.lock"), timeout = 5000),
    error = function(e) NULL)
  if (is.null(lock)) stop("Exact-gc operation is busy.", call. = FALSE)
  on.exit(filelock::unlock(lock), add = TRUE)
  force(code)
}

.exact_gc_file_size <- function(path) {
  size <- if (file.exists(path)) file.size(path) else 0
  if (length(size) != 1L || is.na(size) || !is.finite(size) || size < 0) {
    stop("Invalid exact-gc spool size.", call. = FALSE)
  }
  as.numeric(size)
}

.exact_gc_read_at <- function(path, offset, max_bytes) {
  offset <- .exact_gc_integer(offset, "exact-gc read offset", 0, 2^53)
  size <- .exact_gc_file_size(path)
  if (offset > size) stop("Exact-gc read offset gap.", call. = FALSE)
  if (offset == size) return(raw(0))
  con <- file(path, "rb")
  on.exit(close(con), add = TRUE)
  seek(con, where = offset, origin = "start")
  readBin(con, "raw", n = min(size - offset, max_bytes))
}

# Give a running worker one small, public, fixed window to fill the outbound
# chunk. This is transport coalescing only: the wait does not depend on secret
# values, has no request-count limit, and cannot exceed the fixed deadline.
# A full public-size chunk returns early to preserve backpressure.
.exact_gc_read_coalesced <- function(state, path, offset, long_poll = TRUE) {
  offset <- .exact_gc_integer(offset, "exact-gc read offset", 0, 2^53)
  if (!is.logical(long_poll) || length(long_poll) != 1L || is.na(long_poll)) {
    stop("Invalid exact-gc long-poll policy.", call. = FALSE)
  }
  size <- .exact_gc_file_size(path)
  if (offset > size) stop("Exact-gc read offset gap.", call. = FALSE)
  if (isTRUE(long_poll) && identical(state$status, "running") &&
      size - offset < state$chunk_bytes) {
    started <- proc.time()[["elapsed"]]
    deadline <- started + .DSVERT_EXACT_GC_COALESCE_SECONDS
    repeat {
      remaining <- deadline - proc.time()[["elapsed"]]
      if (remaining <= 0) break
      Sys.sleep(min(.DSVERT_EXACT_GC_COALESCE_POLL_SECONDS, remaining))
      size <- .exact_gc_file_size(path)
      if (offset > size) stop("Exact-gc outbound spool shrank.", call. = FALSE)
      if (size - offset >= state$chunk_bytes) break
    }
  }
  .exact_gc_read_at(path, offset, state$chunk_bytes)
}

# Append at an acknowledged offset.  Retries compare every overlapping byte;
# silently skipping overlap would let a conflicting retry corrupt the stream.
.exact_gc_append_at <- function(path, offset, value, max_bytes) {
  if (!is.raw(value) || !length(value)) {
    stop("Invalid exact-gc delivery.", call. = FALSE)
  }
  offset <- .exact_gc_integer(offset, "exact-gc delivery offset", 0, 2^53)
  size <- .exact_gc_file_size(path)
  if (offset > size) stop("Exact-gc delivery offset gap.", call. = FALSE)
  overlap <- min(length(value), size - offset)
  if (overlap > 0) {
    con <- file(path, "rb")
    seek(con, where = offset, origin = "start")
    existing <- readBin(con, "raw", n = overlap)
    close(con)
    if (!identical(existing, value[seq_len(overlap)])) {
      stop("Conflicting exact-gc delivery retry.", call. = FALSE)
    }
  }
  pending <- length(value) - overlap
  if (pending > 0) {
    if (pending > max_bytes) {
      .dsvert_resource_oversize(
        pending, max_bytes, "exact-gc compatibility spool")
    }
    if (size > max_bytes - pending) {
      .dsvert_resource_backpressure(
        size, pending, max_bytes, "exact-gc compatibility spool")
    }
    append_con <- file(path, "ab")
    on.exit(close(append_con), add = TRUE)
    writeBin(value[seq.int(overlap + 1, length(value))], append_con)
    flush(append_con)
  }
  .exact_gc_file_size(path)
}

.exact_gc_envelope_message <- function(envelope) {
  fields <- c(
    envelope$version, envelope$capability_id, envelope$session_id,
    envelope$operation_id, envelope$context_hash,
    envelope$sender_peer_id, envelope$recipient_peer_id,
    format(envelope$offset, scientific = FALSE, trim = TRUE),
    format(envelope$chunk_bytes, scientific = FALSE, trim = TRUE),
    envelope$payload_hash)
  framed <- vapply(fields, function(value) {
    value <- enc2utf8(as.character(value))
    paste0(nchar(value, type = "bytes"), ":", value)
  }, character(1L))
  charToRaw(paste0(.DSVERT_EXACT_GC_ENVELOPE_DOMAIN,
                   paste0(framed, collapse = "")))
}

.exact_gc_make_envelope <- function(state, offset, payload) {
  envelope <- list(
    version = .DSVERT_EXACT_GC_ENVELOPE_VERSION,
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    session_id = state$session_id,
    operation_id = state$operation_id,
    context_hash = state$context_hash,
    sender_peer_id = state$self_peer_id,
    recipient_peer_id = state$peer_id,
    offset = as.numeric(offset),
    chunk_bytes = as.numeric(length(payload)),
    payload_hash = digest::digest(payload, algo = "sha256", serialize = FALSE),
    payload = .exact_gc_b64url_encode(payload))
  identity <- .get_identity_keypair()
  if (!identical(.dsvert_relay_peer_id(identity$identity_pk),
                 state$self_peer_id)) {
    stop("Runtime identity does not match exact-gc pinned identity.",
         call. = FALSE)
  }
  envelope$signature <- .dsvert_relay_sign_message(
    .exact_gc_envelope_message(envelope), identity$identity_sk)
  envelope
}

.exact_gc_validate_envelope <- function(state, envelope) {
  required <- c(
    "version", "capability_id", "session_id", "operation_id",
    "context_hash", "sender_peer_id", "recipient_peer_id", "offset",
    "chunk_bytes", "payload_hash", "payload", "signature")
  if (!is.list(envelope) || !identical(sort(names(envelope)), sort(required))) {
    stop("Invalid exact-gc envelope schema.", call. = FALSE)
  }
  normalized <- list(
    version = .exact_gc_scalar(envelope$version, "exact-gc envelope version"),
    capability_id = .exact_gc_scalar(envelope$capability_id,
                                      "exact-gc capability"),
    session_id = .dsvert_relay_validate_session_id(envelope$session_id),
    operation_id = .dsvert_relay_validate_operation_id(envelope$operation_id),
    context_hash = .exact_gc_scalar(envelope$context_hash,
                                    "exact-gc context hash"),
    sender_peer_id = .dsvert_relay_validate_peer_id(envelope$sender_peer_id),
    recipient_peer_id = .dsvert_relay_validate_peer_id(
      envelope$recipient_peer_id),
    offset = .exact_gc_integer(envelope$offset, "exact-gc envelope offset",
                               0, 2^53),
    chunk_bytes = .exact_gc_integer(
      envelope$chunk_bytes, "exact-gc envelope length", 1,
      state$chunk_bytes),
    payload_hash = .exact_gc_scalar(envelope$payload_hash,
                                    "exact-gc payload hash"),
    payload = .exact_gc_scalar(envelope$payload, "exact-gc payload"),
    signature = .exact_gc_scalar(envelope$signature, "exact-gc signature"))
  if (!identical(normalized$version, .DSVERT_EXACT_GC_ENVELOPE_VERSION) ||
      !identical(normalized$capability_id, .DSVERT_EXACT_GC_CAPABILITY) ||
      !identical(normalized$session_id, state$session_id) ||
      !identical(normalized$operation_id, state$operation_id) ||
      !identical(normalized$context_hash, state$context_hash) ||
      !identical(normalized$sender_peer_id, state$peer_id) ||
      !identical(normalized$recipient_peer_id, state$self_peer_id) ||
      !grepl("^[0-9a-f]{64}$", normalized$context_hash) ||
      !grepl("^[0-9a-f]{64}$", normalized$payload_hash)) {
    stop("Exact-gc envelope context mismatch.", call. = FALSE)
  }
  if (!isTRUE(.dsvert_relay_verify_message(
    .exact_gc_envelope_message(normalized), state$peer_identity_pk,
    normalized$signature))) {
    stop("Exact-gc envelope signature verification failed.", call. = FALSE)
  }
  payload <- .exact_gc_b64url_decode(
    normalized$payload, "exact-gc payload", state$chunk_bytes)
  if (length(payload) != normalized$chunk_bytes ||
      !identical(digest::digest(payload, algo = "sha256", serialize = FALSE),
                 normalized$payload_hash)) {
    stop("Exact-gc envelope payload mismatch.", call. = FALSE)
  }
  list(envelope = normalized, payload = payload)
}

.exact_gc_protocol_session <- function(session_id, operation_id,
                                       attempt = 1L,
                                       peer_binding_digest) {
  attempt <- .exact_gc_integer(
    attempt, "exact-gc transport attempt", 1, 2^31 - 1)
  if (!is.character(peer_binding_digest) ||
      length(peer_binding_digest) != 1L || is.na(peer_binding_digest) ||
      !grepl("^[0-9a-f]{64}$", peer_binding_digest)) {
    stop("Exact-gc protocol session requires an authenticated peer binding.",
         call. = FALSE)
  }
  digest::digest(
    charToRaw(paste0("dsVert/exact-gc/protocol-session/v3|",
                     nchar(session_id, type = "bytes"), ":", session_id,
                     nchar(operation_id, type = "bytes"), ":", operation_id,
                     nchar(peer_binding_digest, type = "bytes"), ":",
                     peer_binding_digest,
                     nchar(format(attempt, scientific = FALSE, trim = TRUE),
                           type = "bytes"), ":",
                     format(attempt, scientific = FALSE, trim = TRUE))),
    algo = "sha256", serialize = FALSE)
}

.exact_gc_count_threshold <- function() {
  value <- .dsvert_disclosure_settings()$nfilter.tab
  override <- getOption("dsvert.exact_gc.count_threshold")
  if (is.null(override)) {
    override <- getOption("default.dsvert.exact_gc.count_threshold")
  }
  if (!is.null(override)) value <- max(value, suppressWarnings(as.numeric(override)))
  value <- .exact_gc_integer(value, "exact-gc count threshold", 1,
                             .Machine$integer.max)
  format(value, scientific = FALSE, trim = TRUE)
}

.exact_gc_public_state <- function(state) {
  result <- list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    peer_id = state$self_peer_id,
    peer_peer_id = state$peer_id,
    role = state$role,
    context_hash = state$context_hash,
    operation = state$operation,
    output_kind = state$output_kind,
    purpose = state$purpose,
    source_producer = state$source_producer,
    ring_bits = state$ring_bits,
    frac_bits = state$frac_bits,
    vector_len = state$vector_len,
    threshold = state$threshold,
    chunk_bytes = state$chunk_bytes,
    ttl_seconds = state$ttl_seconds,
    max_runtime_seconds = state$max_runtime_seconds,
    worker_heartbeat = state$worker_heartbeat_counter,
    state = state$status,
    stored = identical(state$status, "complete"))
  if (!is.null(state$analysis_binding_sha256)) {
    result$analysis_binding_sha256 <- state$analysis_binding_sha256
  }
  if (identical(state$operation, "mul-truncate-checked")) {
    result$mul_plan_id <- state$mul_plan$plan_id
    result$mul_backend <- state$mul_plan$backend
    result$bound_x <- state$mul_plan$bound_x
    result$bound_y <- state$mul_plan$bound_y
  }
  if (identical(state$status, "failed") &&
      is.character(state$failure_code) && length(state$failure_code) == 1L &&
      state$failure_code %in% .DSVERT_EXACT_GC_FAILURE_CODES) {
    result$failure_code <- state$failure_code
    result$retryable <- isTRUE(state$retryable)
    result$retry_contract <- .DSVERT_EXACT_GC_RETRY_CONTRACT
  }
  result
}

.exact_gc_public_liveness <- function(state) {
  result <- list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    context_hash = state$context_hash,
    state = state$status,
    stored = identical(state$status, "complete"))
  if (identical(state$status, "failed") &&
      is.character(state$failure_code) && length(state$failure_code) == 1L &&
      state$failure_code %in% .DSVERT_EXACT_GC_FAILURE_CODES) {
    result$failure_code <- state$failure_code
    result$retryable <- isTRUE(state$retryable)
    result$retry_contract <- .DSVERT_EXACT_GC_RETRY_CONTRACT
  }
  result
}

.exact_gc_record_private_error <- function(state, message) {
  if (is.null(state) || is.null(state$spool) || !dir.exists(state$spool)) {
    return(invisible(NULL))
  }
  line <- paste0(format(Sys.time(), tz = "UTC", usetz = TRUE), " ", message, "\n")
  tryCatch({
    cat(line, file = file.path(state$spool, "server-private.log"), append = TRUE)
    Sys.chmod(file.path(state$spool, "server-private.log"), mode = "0600")
  }, error = function(e) NULL)
  invisible(NULL)
}

.exact_gc_compact_resource_reservation <- function(state) {
  if (!is.environment(state) || is.null(state$spool) ||
      !dir.exists(state$spool)) {
    if (is.environment(state)) state$resource_reservation_bytes <- 0
    return(invisible(0))
  }
  paths <- c(state$spool, list.files(
    state$spool, recursive = TRUE, full.names = TRUE,
    all.files = TRUE, no.. = TRUE))
  info <- file.info(paths)
  valid <- nrow(info) == length(paths) && !anyNA(info$size) &&
    !any(nzchar(Sys.readlink(paths)))
  if (!isTRUE(valid)) return(invisible(state$resource_reservation_bytes))
  retained <- sum(as.numeric(info$size))
  if (!is.finite(retained) || retained < 0 || retained > 2^53) {
    return(invisible(state$resource_reservation_bytes))
  }
  state$resource_reservation_bytes <- retained
  invisible(retained)
}

.exact_gc_worker_failure <- function(state) {
  path <- file.path(state$spool, "failure.json")
  if (!file.exists(path)) return(NULL)
  result <- tryCatch(
    jsonlite::read_json(path, simplifyVector = TRUE),
    error = function(e) NULL)
  required <- c("version", "code", "retryable", "retry_contract",
                "operation", "ring_bits", "context_hash")
  if (!is.list(result) ||
      !identical(sort(names(result)), sort(required)) ||
      !identical(result$version, .DSVERT_EXACT_GC_FAILURE_VERSION) ||
      !is.character(result$code) || length(result$code) != 1L ||
      is.na(result$code) ||
      !result$code %in% .DSVERT_EXACT_GC_FAILURE_CODES ||
      !is.logical(result$retryable) || length(result$retryable) != 1L ||
      is.na(result$retryable) ||
      !identical(result$retry_contract, .DSVERT_EXACT_GC_RETRY_CONTRACT) ||
      !identical(result$operation, state$operation) ||
      !is.numeric(result$ring_bits) || length(result$ring_bits) != 1L ||
      is.na(result$ring_bits) ||
      !identical(as.integer(result$ring_bits), state$ring_bits) ||
      !is.character(result$context_hash) ||
      length(result$context_hash) != 1L || is.na(result$context_hash) ||
      !identical(result$context_hash, state$context_hash) ||
      !grepl("^[0-9a-f]{64}$", result$context_hash) ||
      !identical(isTRUE(result$retryable), result$code %in% c(
        "infrastructure_unavailable", "numeric_backend_unavailable"))) {
    return(NULL)
  }
  result
}

.exact_gc_mark_failed <- function(ss, state, code) {
  if (!is.character(code) || length(code) != 1L || is.na(code) ||
      !code %in% .DSVERT_EXACT_GC_FAILURE_CODES) {
    code <- "infrastructure_unavailable"
  }
  state$status <- "failed"
  state$worker_heartbeat_key <- raw(0)
  .exact_gc_compact_resource_reservation(state)
  state$failure_code <- code
  state$retryable <- code %in% c(
    "infrastructure_unavailable", "numeric_backend_unavailable")
  state$out_cache <- NULL
  if (!is.null(ss$.exact_gc_outputs)) {
    ss$.exact_gc_outputs[[state$output_key]] <- NULL
  }
  if (identical(state$worker_kind %||% "",
                .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_KIND) &&
      exists(".dsvert_formal_glm_phase19_drop_output",
             mode = "function", inherits = TRUE)) {
    .dsvert_formal_glm_phase19_drop_output(ss, state$operation_id)
  }
  for (name in c("result.json", "done")) {
    path <- file.path(state$spool, name)
    if (file.exists(path)) unlink(path)
  }
  .exact_gc_release_source(ss, state)
  invisible(state$status)
}

.exact_gc_validate_result <- function(state, result) {
  required <- c("version", "kind", "ring_bits", "vector_len", "share",
                "context_hash")
  if (state$operation %in% c(
      "mul-truncate-checked", "joint-dp-laplace-v2",
      "joint-dp-vector-laplace-v3",
      "joint-dp-vector-gaussian-one-draw-v1",
      "alignment-mask-ring128")) {
    required <- c(required, "validity_share")
  }
  if (!is.list(result) || !identical(sort(names(result)), sort(required)) ||
      !identical(result$version, "dsvert-exact-gc-result-v1") ||
      !identical(as.integer(result$ring_bits), state$ring_bits) ||
      !identical(as.integer(result$vector_len), state$vector_len) ||
      !identical(result$context_hash, state$context_hash)) {
    stop("Invalid exact-gc worker result context.", call. = FALSE)
  }
  expected_kind <- .exact_gc_output_kind(state$operation)
  if (!identical(result$kind, expected_kind)) {
    stop("Invalid exact-gc worker result kind.", call. = FALSE)
  }
  output_len <- if (identical(state$operation, "count-guard")) 1L else
    state$vector_len
  expected_bytes <- if (expected_kind %in% c(
      "ring-share", "checked-ring-share", "joint-dp-ring-share-v2",
      "joint-dp-vector-ring128-share-v1",
      "joint-dp-vector-gaussian-one-draw-ring128-share-v1",
      "alignment-masked-ring128-share-v1")) {
    state$vector_len * .exact_gc_record_bytes(state$ring_bits)
  } else {
    as.integer(ceiling(output_len / 8))
  }
  decoded <- if (expected_kind %in% c(
      "ring-share", "checked-ring-share", "joint-dp-ring-share-v2",
      "joint-dp-vector-ring128-share-v1",
      "joint-dp-vector-gaussian-one-draw-ring128-share-v1",
      "alignment-masked-ring128-share-v1")) {
    .exact_gc_validate_residue_records(
      result$share, state$ring_bits, state$vector_len,
      "exact-gc result share")
  } else {
    .exact_gc_standard_b64_raw(
      result$share, expected_bytes, "exact-gc result share")
  }
  if (identical(expected_kind, "xor-bit-share") && output_len %% 8L) {
    used <- output_len %% 8L
    allowed <- bitwShiftL(1L, used) - 1L
    if (bitwAnd(as.integer(decoded[[length(decoded)]]),
                bitwXor(allowed, 255L)) != 0L) {
      stop("Non-canonical exact-gc bit share.", call. = FALSE)
    }
  }
  output <- list(
    operation_id = state$operation_id, operation = state$operation,
    purpose = state$purpose, source_producer = state$source_producer,
    kind = expected_kind, share = result$share, ring_bits = state$ring_bits,
    frac_bits = state$frac_bits, vector_len = state$vector_len,
    context_hash = state$context_hash, producer = .DSVERT_EXACT_GC_CAPABILITY)
  if (expected_kind %in% c(
      "checked-ring-share", "joint-dp-ring-share-v2",
      "joint-dp-vector-ring128-share-v1",
      "joint-dp-vector-gaussian-one-draw-ring128-share-v1",
      "alignment-masked-ring128-share-v1")) {
    validity <- .exact_gc_standard_b64_raw(
      result$validity_share, 1L, "exact-gc result validity share")
    if (!as.integer(validity[[1L]]) %in% 0:1) {
      stop("Non-canonical exact-gc validity share.", call. = FALSE)
    }
    output$validity_share <- result$validity_share
  }
  output
}

.exact_gc_refresh <- function(ss, state) {
  if (state$status %in% c("complete", "aborted", "failed")) return(state$status)
  done <- file.exists(file.path(state$spool, "done"))
  failed_marker <- file.exists(file.path(state$spool, "error")) ||
    file.exists(file.path(state$spool, "failure.json"))
  if (isTRUE(failed_marker)) {
    failure <- .exact_gc_worker_failure(state)
    code <- if (is.null(failure)) "infrastructure_unavailable" else
      failure$code
    return(.exact_gc_mark_failed(ss, state, code))
  }
  if (done) {
    if (identical(state$worker_kind %||% "",
                  .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_KIND)) {
      return(.dsvert_formal_glm_phase19_finish(ss, state))
    }
    result_path <- file.path(state$spool, "result.json")
    result <- tryCatch(
      jsonlite::read_json(result_path, simplifyVector = TRUE),
      error = function(e) NULL)
    if (is.null(result)) {
      .exact_gc_mark_failed(ss, state, "infrastructure_unavailable")
      stop("Exact-gc worker did not publish a valid result.", call. = FALSE)
    }
    output <- tryCatch(
      .exact_gc_validate_result(state, result),
      error = function(e) {
        .exact_gc_mark_failed(ss, state, "infrastructure_unavailable")
        stop(e)
      })
    if (is.null(ss$.exact_gc_outputs)) ss$.exact_gc_outputs <- list()
    existing <- ss$.exact_gc_outputs[[state$output_key]]
    if (!is.null(existing) && !identical(existing, output)) {
      .exact_gc_mark_failed(ss, state, "infrastructure_unavailable")
      stop("Conflicting exact-gc output key.", call. = FALSE)
    }
    ss$.exact_gc_outputs[[state$output_key]] <- output
    if (!is.null(ss$.exact_gc_inputs[[state$source_key]]) &&
        identical(ss$.exact_gc_inputs[[state$source_key]]$claimed_by,
                  state$operation_id)) {
      ss$.exact_gc_inputs[[state$source_key]] <- NULL
    }
    unlink(result_path)
    state$status <- "complete"
    state$worker_heartbeat_key <- raw(0)
    .exact_gc_compact_resource_reservation(state)
    .session_progress(ss)
    return(state$status)
  }
  alive <- isTRUE(tryCatch(state$process$is_alive(), error = function(e) FALSE))
  if (!alive) {
    .exact_gc_mark_failed(ss, state, "infrastructure_unavailable")
  }
  state$status
}

.exact_gc_release_source <- function(ss, state) {
  source <- ss$.exact_gc_inputs[[state$source_key]]
  if (!is.null(source) && identical(source$claimed_by, state$operation_id)) {
    source$claimed_by <- NULL
    ss$.exact_gc_inputs[[state$source_key]] <- source
  }
  invisible(NULL)
}

.exact_gc_abort_state <- function(ss, state, release_source = TRUE,
                                  abort_complete = FALSE) {
  if (is.null(state) ||
      (identical(state$status, "complete") && !isTRUE(abort_complete))) {
    return(invisible(TRUE))
  }
  if (!is.null(state$spool) && dir.exists(state$spool)) {
    tryCatch(.exact_gc_private_file(
      file.path(state$spool, "abort"), charToRaw("1")),
      error = function(e) NULL)
  }
  if (!is.null(state$process) && inherits(state$process, "process")) {
    tryCatch(state$process$kill(), error = function(e) NULL)
    tryCatch(state$process$wait(timeout = 1000), error = function(e) NULL)
  }
  if (isTRUE(release_source)) .exact_gc_release_source(ss, state)
  if (!is.null(ss$.exact_gc_outputs)) ss$.exact_gc_outputs[[state$output_key]] <- NULL
  if (identical(state$worker_kind %||% "",
                .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_KIND) &&
      exists(".dsvert_formal_glm_phase19_drop_output",
             mode = "function", inherits = TRUE)) {
    .dsvert_formal_glm_phase19_drop_output(ss, state$operation_id)
  }
  if (!is.null(state$spool) && dir.exists(state$spool)) {
    unlink(state$spool, recursive = TRUE)
  }
  state$worker_heartbeat_key <- raw(0)
  state$resource_reservation_bytes <- 0
  state$status <- "aborted"
  invisible(TRUE)
}

.exact_gc_expire_if_idle <- function(ss, state, now = .exact_gc_now()) {
  if (state$status %in% c("complete", "aborted")) {
    return(invisible(FALSE))
  }
  ttl <- state$ttl_seconds
  last_activity <- state$last_activity
  heartbeat_seen <- state$worker_heartbeat_seen_at
  started_at <- state$started_at
  max_runtime <- state$max_runtime_seconds
  valid <- is.numeric(ttl) && length(ttl) == 1L && !is.na(ttl) &&
    is.finite(ttl) && ttl >= 10 &&
    is.numeric(last_activity) && length(last_activity) == 1L &&
    !is.na(last_activity) && is.finite(last_activity) &&
    is.numeric(heartbeat_seen) && length(heartbeat_seen) == 1L &&
    !is.na(heartbeat_seen) && is.finite(heartbeat_seen) &&
    is.numeric(started_at) && length(started_at) == 1L &&
    !is.na(started_at) && is.finite(started_at) &&
    is.numeric(max_runtime) && length(max_runtime) == 1L &&
    !is.na(max_runtime) && is.finite(max_runtime) &&
    max_runtime >= ttl &&
    is.numeric(now) && length(now) == 1L && !is.na(now) &&
    is.finite(now) && now >= last_activity && now >= heartbeat_seen &&
    now >= started_at
  if (!isTRUE(valid)) {
    .exact_gc_abort_state(ss, state)
    stop("Exact-gc inactivity lease state is invalid.", call. = FALSE)
  }
  if (now - started_at > max_runtime) {
    .exact_gc_abort_state(ss, state)
    stop("Exact-gc operation exceeded its total runtime lease.",
         call. = FALSE)
  }
  alive <- isTRUE(tryCatch(
    state$process$is_alive(), error = function(e) FALSE))
  if (!alive) {
    .exact_gc_abort_state(ss, state)
    stop("Exact-gc worker is no longer alive.", call. = FALSE)
  }
  observed <- tryCatch(
    .exact_gc_observe_worker_heartbeat(ss, state, now),
    error = function(e) {
      .exact_gc_abort_state(ss, state)
      stop(e)
    })
  if (isTRUE(observed)) heartbeat_seen <- state$worker_heartbeat_seen_at
  if (now - max(last_activity, heartbeat_seen) <= ttl) {
    return(invisible(FALSE))
  }
  .exact_gc_abort_state(ss, state)
  stop("Exact-gc operation expired after its worker/progress lease.",
       call. = FALSE)
}

.exact_gc_reset_retryable_state <- function(ss, state) {
  if (!state$status %in% c("failed", "aborted") ||
      (identical(state$status, "failed") && !isTRUE(state$retryable))) {
    stop("Exact-gc operation is not retryable.", call. = FALSE)
  }
  if (!is.null(state$process) && inherits(state$process, "process")) {
    tryCatch(state$process$kill(), error = function(e) NULL)
    tryCatch(state$process$wait(timeout = 1000), error = function(e) NULL)
  }
  .exact_gc_release_source(ss, state)
  if (!is.null(ss$.exact_gc_outputs)) {
    ss$.exact_gc_outputs[[state$output_key]] <- NULL
  }
  if (identical(state$worker_kind %||% "",
                .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_KIND) &&
      exists(".dsvert_formal_glm_phase19_drop_output",
             mode = "function", inherits = TRUE)) {
    .dsvert_formal_glm_phase19_drop_output(ss, state$operation_id)
  }
  if (!is.null(state$spool) && dir.exists(state$spool)) {
    unlink(state$spool, recursive = TRUE)
  }
  state$resource_reservation_bytes <- 0
  operations <- .exact_gc_ops(ss)
  operations[[state$operation_id]] <- NULL
  invisible(TRUE)
}

.exact_gc_abort_all <- function(ss) {
  if (!is.environment(ss) || !is.environment(ss$.exact_gc_ops)) {
    return(invisible(TRUE))
  }
  for (operation_id in ls(ss$.exact_gc_ops, all.names = TRUE)) {
    state <- ss$.exact_gc_ops[[operation_id]]
    tryCatch(.exact_gc_abort_state(ss, state), error = function(e) NULL)
  }
  invisible(TRUE)
}

.exact_gc_gaussian_one_draw_policy <- function(
    policy, ring, frac_bits, vector_len, purpose, private_seed) {
  fields <- c(
    "version", "mechanism", "allocation", "ring_bits", "frac_bits",
    "total_coordinate_count", "chunk_start", "coordinate_count",
    "output_lattice_bits", "epsilon", "allocated_delta",
    "l2_sensitivity_steps", "l2_sensitivity_certificate_kind",
    "l2_sensitivity_certificate_sha256", "release_binding_domain",
    "release_binding_canonical_json", "scale_shifts", "raw_upper_bounds",
    "release_binding_sha256", "cross_signed_policy_sha256",
    "transcript_hash", "pinset_sha256", "custodian_count",
    "designated_compute_peer_count", "garbler_peer_id",
    "evaluator_peer_id", "garbler_commitment_context",
    "evaluator_commitment_context", "garbler_seed_commitment",
    "evaluator_seed_commitment", "cdf_cumulative", "circuit_digest",
    "plan")
  integer_value <- function(value, minimum, maximum) tryCatch(
    as.integer(.exact_gc_integer(
      value, "one-draw Gaussian policy integer", minimum, maximum)),
    error = function(e) NA_integer_)
  exact_hash <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[0-9a-f]{64}$", value)
  }
  hashes <- if (is.list(policy)) policy[c(
    "l2_sensitivity_certificate_sha256", "release_binding_sha256",
    "cross_signed_policy_sha256", "transcript_hash", "pinset_sha256",
    "garbler_commitment_context", "evaluator_commitment_context",
    "garbler_seed_commitment", "evaluator_seed_commitment",
    "circuit_digest")] else list()
  coordinate_count <- if (is.list(policy)) integer_value(
    policy$coordinate_count, 1L, 128L) else NA_integer_
  total_count <- if (is.list(policy)) integer_value(
    policy$total_coordinate_count, 1L, 1000000L) else NA_integer_
  chunk_start <- if (is.list(policy)) integer_value(
    policy$chunk_start, 0L, 999999L) else NA_integer_
  lattice_bits <- if (is.list(policy)) integer_value(
    policy$output_lattice_bits, 1L, 62L) else NA_integer_
  custodians <- if (is.list(policy)) integer_value(
    policy$custodian_count, 2L, 64L) else NA_integer_
  compute_peers <- if (is.list(policy)) integer_value(
    policy$designated_compute_peer_count, 2L, 2L) else NA_integer_
  scale_shifts <- if (is.list(policy)) suppressWarnings(
    as.numeric(policy$scale_shifts)) else numeric()
  raw_bounds <- if (is.list(policy)) as.character(
    policy$raw_upper_bounds) else character()
  cdf <- if (is.list(policy)) as.character(
    policy$cdf_cumulative) else character()
  plan <- if (is.list(policy)) policy$plan else NULL
  plan_max_chunk <- if (is.list(plan)) integer_value(
    plan$maximum_chunk_coordinates, 1L, 128L) else NA_integer_
  valid <- ring == 128L && frac_bits == 0L &&
    is.list(policy) && !is.null(names(policy)) && !anyNA(names(policy)) &&
    !anyDuplicated(names(policy)) && setequal(names(policy), fields) &&
    identical(policy$version,
              "dsvert-joint-dp-vector-discrete-gaussian-one-draw-gc-template-v1") &&
    identical(policy$mechanism,
              "joint_discrete_gaussian_one_global_draw") &&
    identical(policy$allocation, "one_stacked_capsule_vector") &&
    identical(integer_value(policy$ring_bits, 128L, 128L), 128L) &&
    identical(integer_value(policy$frac_bits, 0L, 0L), 0L) &&
    identical(coordinate_count, as.integer(vector_len)) &&
    !is.na(total_count) && !is.na(chunk_start) &&
    chunk_start <= total_count - coordinate_count &&
    !is.na(lattice_bits) &&
    is.character(policy$epsilon) && length(policy$epsilon) == 1L &&
    !is.na(policy$epsilon) &&
    is.character(policy$allocated_delta) &&
    length(policy$allocated_delta) == 1L && !is.na(policy$allocated_delta) &&
    is.character(policy$l2_sensitivity_steps) &&
    length(policy$l2_sensitivity_steps) == 1L &&
    !is.na(policy$l2_sensitivity_steps) &&
    identical(policy$l2_sensitivity_certificate_kind,
              "machine_proven_integer_lattice_l2_v1") &&
    is.character(policy$release_binding_domain) &&
    length(policy$release_binding_domain) == 1L &&
    !is.na(policy$release_binding_domain) &&
    policy$release_binding_domain %in% c(
      "dsVert/formal-glm/phase16/release-adapter/v1",
      "dsVert/formal-cox/runtime-release-binding/v1") &&
    is.character(policy$release_binding_canonical_json) &&
    length(policy$release_binding_canonical_json) == 1L &&
    !is.na(policy$release_binding_canonical_json) &&
    nzchar(policy$release_binding_canonical_json) &&
    nchar(policy$release_binding_canonical_json, type = "bytes") <=
      4L * 1024L^2L &&
    length(scale_shifts) == coordinate_count && !anyNA(scale_shifts) &&
    all(is.finite(scale_shifts)) && all(scale_shifts == floor(scale_shifts)) &&
    all(scale_shifts >= 0L) && all(scale_shifts <= lattice_bits) &&
    length(raw_bounds) == coordinate_count && !anyNA(raw_bounds) &&
    all(grepl("^(0|[1-9][0-9]{0,38})$", raw_bounds)) &&
    length(hashes) == 10L && all(vapply(hashes, exact_hash, logical(1L))) &&
    identical(policy$release_binding_sha256,
              policy$cross_signed_policy_sha256) &&
    identical(custodians >= 2L, TRUE) && identical(compute_peers, 2L) &&
    is.character(policy$garbler_peer_id) &&
    length(policy$garbler_peer_id) == 1L && !is.na(policy$garbler_peer_id) &&
    grepl("^dsv1_[0-9a-f]{64}$", policy$garbler_peer_id) &&
    is.character(policy$evaluator_peer_id) &&
    length(policy$evaluator_peer_id) == 1L &&
    !is.na(policy$evaluator_peer_id) &&
    grepl("^dsv1_[0-9a-f]{64}$", policy$evaluator_peer_id) &&
    !identical(policy$garbler_peer_id, policy$evaluator_peer_id) &&
    length(cdf) >= 1L && length(cdf) <= 65537L && !anyNA(cdf) &&
    all(grepl("^(0|[1-9][0-9]{0,38})$", cdf)) &&
    is.list(plan) &&
    identical(plan$version,
              "dsvert-joint-dp-vector-discrete-gaussian-one-draw-plan-v1") &&
    identical(plan$mechanism, policy$mechanism) &&
    identical(plan$allocation, policy$allocation) &&
    identical(plan$sampler,
              paste0("fixed-work-outward-rational-dyadic-cdf-hkdf-",
                     "sha256-chacha20-xor-exact-gc-v1")) &&
    identical(integer_value(plan$ring_bits, 128L, 128L), 128L) &&
    identical(integer_value(plan$frac_bits, 0L, 0L), 0L) &&
    identical(integer_value(plan$noise_draw_count, 1L, 1L), 1L) &&
    identical(integer_value(
      plan$total_coordinate_count, 1L, 1000000L), total_count) &&
    !is.na(plan_max_chunk) && coordinate_count <= plan_max_chunk &&
    identical(as.character(plan$cdf_cumulative), cdf) &&
    identical(plan$finite_support_transfer_charged, TRUE) &&
    identical(plan$fixed_work_sampler, TRUE) &&
    identical(plan$no_wrap_certified, TRUE) &&
    identical(integer_value(
      plan$designated_compute_peer_count, 2L, 2L), 2L) &&
    identical(plan$capability_available, TRUE) &&
    identical(purpose, paste0(
      "joint-dp-vector-gaussian-one-draw-v1/", policy$circuit_digest)) &&
    is.character(private_seed) && length(private_seed) == 1L &&
    !is.na(private_seed)
  seed_raw <- if (isTRUE(valid)) tryCatch(
    jsonlite::base64_dec(private_seed), error = function(e) raw(0L)) else
    raw(0L)
  canonical_seed <- if (length(seed_raw) == 32L) {
    gsub("[\r\n]", "", jsonlite::base64_enc(seed_raw))
  } else ""
  if (!isTRUE(valid) || !identical(canonical_seed, private_seed)) {
    stop("Invalid purpose-bound one-draw Gaussian worker contract.",
         call. = FALSE)
  }
  rm(seed_raw, canonical_seed)
  .dsvert_dp_canonical_query_value(policy)
}

.exact_gc_gaussian_one_draw_authority <- function(
    authority, worker_policy, purpose, .policy = NULL, .verifier = NULL) {
  required <- c(
    "version", "manifest_json", "recipient_ticket_jsons",
    "local_recipient_name", "source_fan_in_transcript_sha256")
  if (!is.list(authority) || is.null(names(authority)) ||
      anyNA(names(authority)) || anyDuplicated(names(authority)) ||
      !setequal(names(authority), required) ||
      !identical(authority$version,
                 "dsvert-joint-dp-gaussian-one-draw-r-authority-v1") ||
      !is.list(authority$recipient_ticket_jsons) ||
      length(authority$recipient_ticket_jsons) != 2L ||
      !is.character(authority$local_recipient_name) ||
      length(authority$local_recipient_name) != 1L ||
      is.na(authority$local_recipient_name) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
             authority$local_recipient_name) ||
      !is.character(authority$source_fan_in_transcript_sha256) ||
      length(authority$source_fan_in_transcript_sha256) != 1L ||
      is.na(authority$source_fan_in_transcript_sha256) ||
      !grepl("^[0-9a-f]{64}$",
             authority$source_fan_in_transcript_sha256)) {
    stop("Invalid one-draw Gaussian source authority.", call. = FALSE)
  }
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  parsed <- .dsvert_dp_capsule_source_contract_json(
    .policy, authority$manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  tickets <- lapply(
    authority$recipient_ticket_jsons,
    .dsvert_dp_capsule_source_ticket_validate,
    policy = .policy, contract = contract, verifier = .verifier)
  recipients <- vapply(tickets, function(value) {
    value$ticket$recipient_name
  }, character(1L))
  expected_recipients <- .dsvert_dp_capsule_source_names(
    contract$designated_noise_peers, "noise-peer list")
  if (anyDuplicated(recipients) ||
      !setequal(recipients, expected_recipients) ||
      !identical(authority$local_recipient_name, .policy$peer_name) ||
      !authority$local_recipient_name %in% recipients) {
    stop("One-draw Gaussian tickets do not cover the exact recipients.",
         call. = FALSE)
  }
  tickets <- tickets[order(recipients, method = "radix")]
  names(tickets) <- sort(recipients, method = "radix")
  binding <- tryCatch(jsonlite::fromJSON(
    worker_policy$release_binding_canonical_json,
    simplifyVector = TRUE, simplifyDataFrame = FALSE,
    simplifyMatrix = FALSE), error = function(e) NULL)
  binding_fields <- c(
    "capsule_id", "manifest_sha256", "source_fan_in_transcript_sha256",
    "pinset_sha256", "garbler_peer_name", "garbler_peer_id",
    "evaluator_peer_name", "evaluator_peer_id")
  if (!is.list(binding) || !all(binding_fields %in% names(binding))) {
    stop("Invalid one-draw Gaussian release authority binding.",
         call. = FALSE)
  }
  manifest_sha256 <- digest::digest(
    authority$manifest_json, algo = "sha256", serialize = FALSE)
  role_names <- c(binding$garbler_peer_name, binding$evaluator_peer_name)
  role_ids <- c(binding$garbler_peer_id, binding$evaluator_peer_id)
  pinned_role_ids <- tryCatch(vapply(role_names, function(peer) {
    .dsvert_relay_peer_id(unname(.policy$peer_pinset[[peer]]))
  }, character(1L)), error = function(e) character())
  valid <- identical(binding$capsule_id, contract$capsule_id) &&
    identical(binding$manifest_sha256, manifest_sha256) &&
    identical(binding$source_fan_in_transcript_sha256,
              authority$source_fan_in_transcript_sha256) &&
    identical(binding$pinset_sha256, contract$peer_pinset_sha256) &&
    identical(worker_policy$pinset_sha256, contract$peer_pinset_sha256) &&
    length(role_names) == 2L && !anyNA(role_names) &&
    !anyDuplicated(role_names) && setequal(role_names, recipients) &&
    identical(unname(pinned_role_ids), unname(role_ids)) &&
    identical(worker_policy$garbler_peer_id, binding$garbler_peer_id) &&
    identical(worker_policy$evaluator_peer_id, binding$evaluator_peer_id) &&
    identical(purpose, paste0(
      "joint-dp-vector-gaussian-one-draw-v1/",
      worker_policy$circuit_digest))
  if (!isTRUE(valid)) {
    stop("The one-draw Gaussian authority does not match its signed source.",
         call. = FALSE)
  }
  ticket_hashes <- as.list(vapply(
    tickets, `[[`, character(1L), "hash"))
  summary <- .dsvert_dp_canonical_query_value(list(
    version = "dsvert-joint-dp-gaussian-one-draw-r-authority-summary-v1",
    purpose = purpose, capsule_id = contract$capsule_id,
    manifest_sha256 = manifest_sha256,
    source_contract_sha256 = parsed$contract_hash,
    source_fan_in_transcript_sha256 =
      authority$source_fan_in_transcript_sha256,
    recipient_ticket_sha256 = ticket_hashes,
    recipient_ticket_set_sha256 =
      .dsvert_joint_dp_hash(ticket_hashes),
    local_recipient_name = authority$local_recipient_name,
    worker_policy_sha256 = .dsvert_joint_dp_hash(worker_policy)))
  summary$authority_sha256 <- .dsvert_joint_dp_hash(summary)
  summary
}

.exact_gc_joint_dp_vector_wire_policy <- function(policy) {
  array_fields <- c(
    "scale_shifts", "raw_upper_bounds", "bernoulli_thresholds")
  if (!is.list(policy) || is.null(names(policy)) || anyNA(names(policy)) ||
      anyDuplicated(names(policy)) || !all(array_fields %in% names(policy))) {
    stop("Invalid purpose-bound joint-DP vector worker wire policy.",
         call. = FALSE)
  }
  wire <- policy
  for (field in array_fields) {
    value <- policy[[field]]
    numeric_field <- identical(field, "scale_shifts")
    scalar <- function(item) {
      if (length(item) != 1L || !is.null(names(item)) || is.object(item)) {
        return(FALSE)
      }
      if (numeric_field) {
        is.numeric(item) && !is.na(item) && is.finite(item)
      } else {
        is.character(item) && !is.na(item)
      }
    }
    if (is.list(value)) {
      if (!length(value) || !is.null(names(value)) ||
          !all(vapply(value, scalar, logical(1L)))) {
        stop("Invalid purpose-bound joint-DP vector worker wire policy.",
             call. = FALSE)
      }
      value <- unlist(value, use.names = FALSE)
    }
    invalid_value <- is.object(value) || if (numeric_field) {
      !is.numeric(value) || anyNA(value) || any(!is.finite(value))
    } else {
      !is.character(value) || anyNA(value)
    }
    if (!length(value) || !is.null(names(value)) || invalid_value) {
      stop("Invalid purpose-bound joint-DP vector worker wire policy.",
           call. = FALSE)
    }
    wire[[field]] <- as.list(unname(value))
  }
  wire
}

.exact_gc_init_impl <- function(ss, session_id, operation_id,
                                capability_id, source_key, output_key,
                                operation, ring, frac_bits, vector_len,
                                purpose, mul_plan = NULL, threshold = NULL,
                                binary = .findMpcBinary(),
                                deterministic_output_seed = NULL,
                                joint_dp = NULL, joint_dp_vector = NULL,
                                joint_dp_gaussian_one_draw = NULL,
                                joint_dp_gaussian_one_draw_authority = NULL,
                                private_seed = NULL) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  capability_id <- .exact_gc_scalar(capability_id, "exact-gc capability")
  if (!identical(capability_id, .DSVERT_EXACT_GC_CAPABILITY)) {
    stop("Unsupported exact-gc capability.", call. = FALSE)
  }
  source_key <- .exact_gc_validate_key(source_key)
  output_key <- .exact_gc_validate_key(output_key, output = TRUE)
  operation <- .exact_gc_scalar(operation, "exact-gc operation")
  if (!operation %in% c(
      "compare-signed", "truncate-floor", "mul-truncate-checked",
      "count-guard", "clamp-count", "joint-dp-laplace-v2",
      "joint-dp-vector-laplace-v3",
      "joint-dp-vector-gaussian-one-draw-v1",
      "alignment-mask-ring128")) {
    stop("Unsupported exact-gc high-level operation.", call. = FALSE)
  }
  ring_candidate <- suppressWarnings(as.numeric(ring))
  if (length(ring_candidate) == 1L && !is.na(ring_candidate) &&
      is.finite(ring_candidate) && ring_candidate == floor(ring_candidate) &&
      ring_candidate > .DSVERT_EXACT_GC_MAX_RING_BITS) {
    .dsvert_resource_oversize(
      ring_candidate, .DSVERT_EXACT_GC_MAX_RING_BITS,
      "exact-gc operation ring")
  }
  ring <- as.integer(.exact_gc_integer(
    ring, "exact-gc ring", 63, .DSVERT_EXACT_GC_MAX_RING_BITS))
  frac_bits <- as.integer(.exact_gc_integer(
    frac_bits, "exact-gc fractional bits", 0, ring - 1L))
  if (operation %in% c(
      "compare-signed", "count-guard", "clamp-count",
      "joint-dp-laplace-v2", "joint-dp-vector-laplace-v3",
      "joint-dp-vector-gaussian-one-draw-v1",
      "alignment-mask-ring128") &&
      frac_bits != 0L) {
    stop("Exact comparisons do not use fractional bits.", call. = FALSE)
  }
  vector_candidate <- suppressWarnings(as.numeric(vector_len))
  if (length(vector_candidate) == 1L && !is.na(vector_candidate) &&
      is.finite(vector_candidate) &&
      vector_candidate == floor(vector_candidate) &&
      vector_candidate > 4096) {
    .dsvert_resource_oversize(
      vector_candidate, 4096, "exact-gc circuit vector shape")
  }
  vector_len <- as.integer(.exact_gc_integer(
    vector_len, "exact-gc vector length", 1, 4096))
  alignment_k <- if (identical(operation, "alignment-mask-ring128")) {
    .exact_gc_alignment_source_count(threshold)
  } else {
    NULL
  }
  input_containers <- if (identical(operation, "mul-truncate-checked")) {
    7L * vector_len + 1L
  } else if (identical(
      operation, "joint-dp-vector-gaussian-one-draw-v1")) {
    7L * vector_len + 1L
  } else if (identical(operation, "alignment-mask-ring128")) {
    3L * vector_len + 4L * alignment_k + 1L
  } else if (identical(operation, "count-guard")) {
    2L * vector_len + 1L
  } else if (identical(operation, "truncate-floor")) {
    3L * vector_len
  } else {
    3L * vector_len
  }
  if (identical(operation, "mul-truncate-checked")) {
    if (!is.list(mul_plan) ||
        !identical(as.integer(mul_plan$ring_bits), ring) ||
        !identical(as.integer(mul_plan$frac_bits), frac_bits) ||
        !is.character(mul_plan$plan_id) ||
        !grepl("^[0-9a-f]{64}$", mul_plan$plan_id) ||
        !mul_plan$backend %in% c("ring127-ot", "direct-wide") ||
        !is.character(mul_plan$bound_x) ||
        !is.character(mul_plan$bound_y)) {
      stop("Exact-gc checked multiplication requires a server-owned plan.",
           call. = FALSE)
    }
  } else if (!is.null(mul_plan)) {
    stop("Unexpected exact-gc multiplication plan.", call. = FALSE)
  }
  max_vector <- if (identical(
      operation, "joint-dp-vector-gaussian-one-draw-v1")) {
    128L
  } else if (identical(operation, "mul-truncate-checked")) {
    as.integer(mul_plan$max_chunk)
  } else 4096L
  if (vector_len > max_vector) {
    .dsvert_resource_oversize(
      vector_len, max_vector, "exact-gc circuit vector shape")
  }
  circuit_bits <- .exact_gc_record_bytes(ring) * 8L * input_containers
  if (circuit_bits > .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS) {
    .dsvert_resource_oversize(
      circuit_bits, .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS,
      "exact-gc circuit type")
  }
  purpose <- .exact_gc_validate_purpose(purpose)
  joint_policy_hash <- ""
  joint_dp_vector_wire <- NULL
  gaussian_one_draw_authority <- NULL
  if (identical(operation, "joint-dp-laplace-v2")) {
    policy_fields <- c(
      "version", "sampler", "bernoulli_bits", "stop_numerator",
      "max_geometric_steps", "sensitivity_steps", "epsilon",
      "allocated_delta", "encoded_lower", "encoded_upper",
      "transcript_hash", "garbler_commitment_context",
      "evaluator_commitment_context", "garbler_seed_commitment",
      "evaluator_seed_commitment", "circuit_digest",
      "implementation_delta_numerator",
      "implementation_delta_denominator")
    valid_joint <- ring == 127L && frac_bits == 0L && vector_len == 1L &&
      is.list(joint_dp) && !is.null(names(joint_dp)) &&
      !anyNA(names(joint_dp)) && !anyDuplicated(names(joint_dp)) &&
      setequal(names(joint_dp), policy_fields) &&
      identical(joint_dp$version,
                .DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2) &&
      identical(joint_dp$sampler,
                .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2) &&
      is.character(joint_dp$circuit_digest) &&
      length(joint_dp$circuit_digest) == 1L &&
      grepl("^[0-9a-f]{64}$", joint_dp$circuit_digest) &&
      identical(purpose, paste0(
        "joint-dp-laplace-v2/", joint_dp$circuit_digest)) &&
      is.character(private_seed) && length(private_seed) == 1L &&
      !is.na(private_seed)
    seed_raw <- if (isTRUE(valid_joint)) tryCatch(
      jsonlite::base64_dec(private_seed), error = function(e) raw(0L)) else
      raw(0L)
    canonical_seed <- if (length(seed_raw) == 32L) {
      gsub("[\r\n]", "", jsonlite::base64_enc(seed_raw))
    } else ""
    if (!isTRUE(valid_joint) || !identical(canonical_seed, private_seed)) {
      stop("Invalid purpose-bound joint-DP Count worker contract.",
           call. = FALSE)
    }
    joint_dp <- .dsvert_dp_canonical_query_value(joint_dp)
    joint_policy_hash <- digest::digest(
      .dsvert_dp_canonical_json(joint_dp),
      algo = "sha256", serialize = FALSE)
    rm(seed_raw, canonical_seed)
  } else if (identical(operation, "joint-dp-vector-laplace-v3")) {
    policy_fields <- c(
      "version", "sampler", "total_coordinate_count", "chunk_start",
      "coordinate_count", "output_lattice_bits", "sensitivity_steps",
      "epsilon", "allocated_delta", "stop_bits", "stop_numerator",
      "uniform_bits", "binary_geometric_bits", "bernoulli_thresholds",
      "scale_shifts", "raw_upper_bounds", "transcript_hash",
      "garbler_commitment_context", "evaluator_commitment_context",
      "garbler_seed_commitment", "evaluator_seed_commitment",
      "circuit_digest", "implementation_delta_numerator",
      "implementation_delta_denominator")
    hashes <- if (is.list(joint_dp_vector)) joint_dp_vector[c(
      "transcript_hash", "garbler_commitment_context",
      "evaluator_commitment_context", "garbler_seed_commitment",
      "evaluator_seed_commitment", "circuit_digest")] else list()
    valid_vector <- ring == 128L && frac_bits == 0L &&
      is.null(joint_dp) && is.list(joint_dp_vector) &&
      !is.null(names(joint_dp_vector)) && !anyNA(names(joint_dp_vector)) &&
      !anyDuplicated(names(joint_dp_vector)) &&
      setequal(names(joint_dp_vector), policy_fields) &&
      identical(joint_dp_vector$version,
                "dsvert-joint-dp-vector-laplace-gc-template-v3") &&
      identical(joint_dp_vector$sampler,
                "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3") &&
      identical(as.integer(joint_dp_vector$coordinate_count), vector_len) &&
      is.numeric(joint_dp_vector$output_lattice_bits) &&
      length(joint_dp_vector$output_lattice_bits) == 1L &&
      !is.na(joint_dp_vector$output_lattice_bits) &&
      joint_dp_vector$output_lattice_bits >= 1 &&
      joint_dp_vector$output_lattice_bits <= 62 &&
      joint_dp_vector$output_lattice_bits ==
        floor(joint_dp_vector$output_lattice_bits) &&
      is.numeric(joint_dp_vector$scale_shifts) &&
      !anyNA(joint_dp_vector$scale_shifts) &&
      all(is.finite(joint_dp_vector$scale_shifts)) &&
      all(joint_dp_vector$scale_shifts ==
            floor(joint_dp_vector$scale_shifts)) &&
      all(joint_dp_vector$scale_shifts >= 0) &&
      all(joint_dp_vector$scale_shifts <=
            joint_dp_vector$output_lattice_bits) &&
      length(joint_dp_vector$scale_shifts) == vector_len &&
      length(joint_dp_vector$raw_upper_bounds) == vector_len &&
      length(joint_dp_vector$bernoulli_thresholds) ==
        as.integer(joint_dp_vector$binary_geometric_bits) &&
      length(hashes) == 6L && all(vapply(hashes, function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          grepl("^[0-9a-f]{64}$", value)
      }, logical(1L))) &&
      identical(purpose, paste0(
        "joint-dp-vector-laplace-v3/", joint_dp_vector$circuit_digest)) &&
      is.character(private_seed) && length(private_seed) == 1L &&
      !is.na(private_seed)
    seed_raw <- if (isTRUE(valid_vector)) tryCatch(
      jsonlite::base64_dec(private_seed), error = function(e) raw(0L)) else
      raw(0L)
    canonical_seed <- if (length(seed_raw) == 32L) {
      gsub("[\r\n]", "", jsonlite::base64_enc(seed_raw))
    } else ""
    if (!isTRUE(valid_vector) || !identical(canonical_seed, private_seed)) {
      stop("Invalid purpose-bound joint-DP vector worker contract.",
           call. = FALSE)
    }
    joint_dp_vector <- .dsvert_dp_canonical_query_value(joint_dp_vector)
    joint_policy_hash <- digest::digest(
      .dsvert_dp_canonical_json(joint_dp_vector),
      algo = "sha256", serialize = FALSE)
    joint_dp_vector_wire <-
      .exact_gc_joint_dp_vector_wire_policy(joint_dp_vector)
    rm(seed_raw, canonical_seed)
  } else if (identical(
      operation, "joint-dp-vector-gaussian-one-draw-v1")) {
    if (!is.null(joint_dp) || !is.null(joint_dp_vector)) {
      stop("Ambiguous one-draw Gaussian worker material.", call. = FALSE)
    }
    joint_dp_gaussian_one_draw <-
      .exact_gc_gaussian_one_draw_policy(
        joint_dp_gaussian_one_draw, ring, frac_bits, vector_len,
        purpose, private_seed)
    gaussian_one_draw_authority <-
      .exact_gc_gaussian_one_draw_authority(
        joint_dp_gaussian_one_draw_authority,
        joint_dp_gaussian_one_draw, purpose)
    joint_policy_hash <- digest::digest(
      .dsvert_dp_canonical_json(joint_dp_gaussian_one_draw),
      algo = "sha256", serialize = FALSE)
  } else if (!is.null(joint_dp) || !is.null(joint_dp_vector) ||
             !is.null(joint_dp_gaussian_one_draw) ||
             !is.null(joint_dp_gaussian_one_draw_authority) ||
             !is.null(private_seed)) {
    stop("Unexpected joint-DP worker material.", call. = FALSE)
  }
  peer_binding_digest <- .exact_gc_validate_bound_peer_context(ss, session_id)
  analysis_bound <- identical(
    ss$.exact_gc_peer_binding_contract$version,
    .DSVERT_EXACT_GC_ANALYSIS_PEER_BINDING_VERSION)
  analysis_binding_sha256 <- if (analysis_bound) {
    ss$.exact_gc_analysis_binding_sha256
  } else {
    NULL
  }
  if (analysis_bound) {
    if (!identical(operation, "joint-dp-laplace-v2") ||
        !identical(.exact_gc_output_kind(operation),
                   "joint-dp-ring-share-v2")) {
      stop("Invalid analysis-bound exact-gc Count worker contract.",
           call. = FALSE)
    }
    .exact_gc_analysis_count_worker_validate_v1(
      ss, session_id, joint_dp, ring, frac_bits, vector_len, purpose)
  }
  output_seed_commitment <- ""
  if (!is.null(deterministic_output_seed)) {
    if (!identical(operation, "clamp-count") ||
        !is.character(deterministic_output_seed) ||
        length(deterministic_output_seed) != 1L ||
        is.na(deterministic_output_seed)) {
      stop("A deterministic output seed is valid only for Count clamp.",
           call. = FALSE)
    }
    seed_raw <- tryCatch(
      jsonlite::base64_dec(deterministic_output_seed),
      error = function(e) raw(0L))
    canonical_seed <- if (is.raw(seed_raw)) {
      gsub("[\r\n]", "", jsonlite::base64_enc(seed_raw))
    } else ""
    if (length(seed_raw) != 32L ||
        !identical(canonical_seed, deterministic_output_seed)) {
      stop("The Count deterministic output seed is invalid.", call. = FALSE)
    }
    output_seed_commitment <- digest::digest(
      seed_raw, algo = "sha256", serialize = FALSE)
    rm(seed_raw, canonical_seed)
  }
  output_kind <- .exact_gc_output_kind(operation)
  if (identical(operation, "compare-signed")) {
    if (!is.character(threshold) || length(threshold) != 1L ||
        !grepl(paste0("^-?(0|[1-9][0-9]{0,",
                       .DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS - 1L,
                       "})$"), threshold, perl = TRUE)) {
      stop("Signed comparison requires a server-minted threshold.",
           call. = FALSE)
    }
  } else if (identical(operation, "count-guard")) {
    if (is.null(threshold)) {
      threshold <- .exact_gc_count_threshold()
    } else if (!is.character(threshold) || length(threshold) != 1L ||
               !grepl(paste0("^[1-9][0-9]{0,",
                              .DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS - 1L,
                              "}$"), threshold, perl = TRUE)) {
      stop("Count guard requires a server-minted threshold.",
           call. = FALSE)
    }
  } else if (identical(operation, "clamp-count")) {
    if (!is.character(threshold) || length(threshold) != 1L ||
        !grepl(paste0("^[1-9][0-9]{0,",
                       .DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS - 1L,
                       "}$"), threshold, perl = TRUE)) {
      stop("Count clamp requires a server-minted positive upper bound.",
           call. = FALSE)
    }
  } else if (identical(operation, "alignment-mask-ring128")) {
    threshold <- as.character(
      .exact_gc_alignment_source_count(threshold))
  } else {
    if (!is.null(threshold)) {
      stop("Unexpected exact-gc threshold.", call. = FALSE)
    }
    threshold <- ""
  }

  previous <- .exact_gc_operation_state(ss, operation_id, required = FALSE)
  requested_spec <- list(
    session_id = session_id, operation_id = operation_id,
    capability_id = capability_id, source_key = source_key,
    output_key = output_key, operation = operation, ring_bits = ring,
    frac_bits = frac_bits, vector_len = vector_len, purpose = purpose,
    output_kind = output_kind, threshold = threshold,
    deterministic_output_seed_commitment = output_seed_commitment,
    peer_binding_digest = peer_binding_digest,
    joint_dp_policy_hash = joint_policy_hash,
    gaussian_one_draw_authority_sha256 = if (
      is.null(gaussian_one_draw_authority)) "" else
        gaussian_one_draw_authority$authority_sha256,
    mul_plan_id = if (is.null(mul_plan)) "" else mul_plan$plan_id,
    mul_backend = if (is.null(mul_plan)) "" else mul_plan$backend,
    bound_x = if (is.null(mul_plan)) "" else mul_plan$bound_x,
    bound_y = if (is.null(mul_plan)) "" else mul_plan$bound_y)
  if (analysis_bound) {
    requested_spec$analysis_binding_sha256 <- analysis_binding_sha256
  }
  attempt <- 1L
  if (!is.null(previous)) {
    if (!identical(previous$requested_spec, requested_spec)) {
      stop("Conflicting retry for exact-gc initialization.", call. = FALSE)
    }
    tryCatch(
      .exact_gc_refresh(ss, previous),
      error = function(e) .exact_gc_record_private_error(
        previous, conditionMessage(e)))
    retryable <- identical(previous$status, "aborted") ||
      (identical(previous$status, "failed") && isTRUE(previous$retryable))
    if (!isTRUE(retryable)) return(.exact_gc_public_state(previous))
    previous_attempt <- previous$attempt
    if (is.null(previous_attempt)) previous_attempt <- 1L
    attempt <- as.integer(.exact_gc_integer(
      previous_attempt + 1, "exact-gc transport attempt", 2, 2^31 - 1))
    .exact_gc_reset_retryable_state(ss, previous)
  }
  source <- ss$.exact_gc_inputs[[source_key]]
  if (is.null(source) || !is.null(source$claimed_by) ||
      !identical(source$ring_bits, ring) ||
      !identical(source$vector_len, vector_len)) {
    stop("Exact-gc source is unavailable or has the wrong context.", call. = FALSE)
  }
  if (identical(operation, "joint-dp-vector-gaussian-one-draw-v1") &&
      !identical(source$gaussian_one_draw_authority_sha256,
                 gaussian_one_draw_authority$authority_sha256)) {
    stop("The one-draw Gaussian source lacks exact recipient authority.",
         call. = FALSE)
  }
  allowed_spec <- .exact_gc_allowed_spec(
    operation, purpose, frac_bits, output_kind, ring)
  if (identical(operation, "alignment-mask-ring128")) {
    allowed_spec$alignment_source_count <- alignment_k
  }
  if (!is.character(source$producer) || length(source$producer) != 1L ||
      !identical(source$allowed_spec, allowed_spec)) {
    stop("Exact-gc source is not allowlisted for this operation context.",
         call. = FALSE)
  }
  source_producer <- .exact_gc_validate_purpose(source$producer)
  public_spec <- c(requested_spec, list(source_producer = source_producer))
  protocol_purpose <- if (operation %in% c(
      "joint-dp-laplace-v2", "joint-dp-vector-laplace-v3",
      "joint-dp-vector-gaussian-one-draw-v1")) {
    # The joint-DP circuit purpose is already the digest of a transcript that
    # binds the server-minted bounded-source producer and both pinned peers.
    # The specialised worker independently requires this exact digest string.
    purpose
  } else {
    .exact_gc_bound_protocol_purpose(source_producer, purpose)
  }
  if (!is.null(ss$.exact_gc_outputs[[output_key]])) {
    stop("Exact-gc output key is already in use.", call. = FALSE)
  }
  if (!.key_exists("transport_sk", ss) || !.key_exists("transport_pk", ss) ||
      !.key_exists("identity_pk", ss) ||
      !isTRUE(ss$.exact_gc_transport_initialized) ||
      is.null(ss$.exact_gc_peer_binding_digest) ||
      is.null(ss$peer_transport_pks) || length(ss$peer_transport_pks) != 1L ||
      is.null(names(ss$peer_transport_pks)) ||
      !nzchar(names(ss$peer_transport_pks)[[1L]])) {
    stop("Exact-gc requires exactly two initialized pinned peers.", call. = FALSE)
  }
  peer_name <- names(ss$peer_transport_pks)[[1L]]
  if (analysis_bound) {
    peer_identity_pk <- ss$.exact_gc_peer_identity_pks[[peer_name]]
    if (is.null(peer_identity_pk)) {
      stop("Exact-gc requires an analysis-bound pinned peer identity.",
           call. = FALSE)
    }
  } else {
    trusted <- .get_trusted_peers()
    if (is.null(trusted[[peer_name]])) {
      stop("Exact-gc requires a name-bound pinned peer identity.",
           call. = FALSE)
    }
    peer_identity_pk <- trusted[[peer_name]]
  }
  own_identity_pk <- .key_get("identity_pk", ss)
  self_peer_id <- .dsvert_relay_peer_id(own_identity_pk)
  peer_id <- .dsvert_relay_peer_id(peer_identity_pk)
  if (identical(self_peer_id, peer_id)) {
    stop("Exact-gc peers must have distinct pinned identities.", call. = FALSE)
  }
  ordered <- sort(c(self_peer_id, peer_id))
  garbler_id <- ordered[[1L]]
  evaluator_id <- ordered[[2L]]
  role <- if (identical(self_peer_id, garbler_id)) "garbler" else "evaluator"
  if (analysis_bound) {
    peer_role <- if (identical(role, "garbler")) "evaluator" else "garbler"
    if (!identical(
          .dsvert_relay_normalize_identity_pk(own_identity_pk),
          ss$.exact_gc_analysis_binding$authority_roles[[role]]) ||
        !identical(
          .dsvert_relay_normalize_identity_pk(peer_identity_pk),
          ss$.exact_gc_analysis_binding$authority_roles[[peer_role]])) {
      stop("Exact-gc roles disagree with the analysis noise authorities.",
           call. = FALSE)
    }
  }
  protocol_session <- .exact_gc_protocol_session(
    session_id, operation_id, attempt,
    peer_binding_digest = peer_binding_digest)
  derived <- .callMpcTool("exact-gc-derive-master", list(
    local_secret = .key_get("transport_sk", ss),
    local_public = .key_get("transport_pk", ss),
    peer_public = unname(ss$peer_transport_pks[[1L]]),
    session_id = protocol_session, garbler_id = garbler_id,
    evaluator_id = evaluator_id, purpose = protocol_purpose,
    operation = operation,
    ring_bits = ring, frac_bits = frac_bits, threshold = threshold,
    mul_backend = if (is.null(mul_plan)) "" else mul_plan$backend,
    bound_x = if (is.null(mul_plan)) "" else mul_plan$bound_x,
    bound_y = if (is.null(mul_plan)) "" else mul_plan$bound_y,
    vector_len = vector_len))
  if (!is.character(derived$context_hash) ||
      !grepl("^[0-9a-f]{64}$", derived$context_hash)) {
    stop("Exact-gc key agreement returned invalid context.", call. = FALSE)
  }

  chunk_bytes <- .exact_gc_chunk_bytes()
  spool_max <- .exact_gc_spool_max_bytes(chunk_bytes)
  request_max <- .exact_gc_request_max_bytes(chunk_bytes)
  ttl <- .exact_gc_ttl_seconds()
  max_runtime <- .exact_gc_max_runtime_seconds(ttl)
  # Reserve the worker's full advertised spool before it can write
  # concurrently. This is process-wide byte backpressure, not a request quota;
  # a rejected attempt records no identity, query or penalty state.
  resource_reservation <- 2 * spool_max + 16 * 1024^2
  .dsvert_resource_admit(ss, resource_reservation)
  spool <- normalizePath(
    .exact_gc_spool_dir(ss, operation_id, create = TRUE), mustWork = TRUE)
  if (length(list.files(spool, all.files = TRUE, no.. = TRUE))) {
    stop("Exact-gc operation spool is not empty.", call. = FALSE)
  }
  for (name in c(
      "inbound.bin", "outbound.bin", "exchange.hb", "worker.hb")) {
    # The zero-length .bin files are compatibility sentinels only. Protocol
    # bytes live in immutable segment directories so either process may reclaim
    # acknowledged data without renaming a file open in the other process.
    .exact_gc_private_file(
      file.path(spool, name),
      if (name %in% c("exchange.hb", "worker.hb")) charToRaw(".") else raw(0))
  }
  for (name in c("inbound.segments", "outbound.segments")) {
    path <- file.path(spool, name)
    if (!dir.create(path, mode = "0700", showWarnings = FALSE)) {
      stop("Could not create exact-gc segment spool.", call. = FALSE)
    }
    Sys.chmod(path, mode = "0700")
  }
  .exact_gc_private_file(
    file.path(spool, "inbound.state"), charToRaw(paste(
      .DSVERT_EXACT_GC_INBOUND_STATE_VERSION, "0", "-", "-", "-",
      sep = "|")))
  for (name in c("inbound.ack", "outbound.head", "outbound.ack")) {
    .exact_gc_private_file(file.path(spool, name), charToRaw("0"))
  }
  heartbeat_key <- .dsvert_secure_random_bytes(32L)
  if (!is.raw(heartbeat_key) || length(heartbeat_key) != 32L) {
    stop("Could not create exact-gc worker heartbeat key.", call. = FALSE)
  }
  heartbeat_key_b64 <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(heartbeat_key))
  config_path <- file.path(spool, "worker-config.json")
  config <- list(
    version = "dsvert-exact-gc-worker-v4", role = role,
    session_id = protocol_session, master_key = derived$master_key,
    garbler_id = garbler_id, evaluator_id = evaluator_id,
    purpose = protocol_purpose,
    operation = operation, ring_bits = ring, frac_bits = frac_bits,
    threshold = threshold,
    mul_backend = if (is.null(mul_plan)) "" else mul_plan$backend,
    bound_x = if (is.null(mul_plan)) "" else mul_plan$bound_x,
    bound_y = if (is.null(mul_plan)) "" else mul_plan$bound_y,
    vector_len = vector_len,
    source_share = source$share, spool_dir = normalizePath(spool),
    joint_dp = if (identical(operation, "joint-dp-laplace-v2")) {
      joint_dp
    } else NULL,
    joint_dp_vector = if (identical(
      operation, "joint-dp-vector-laplace-v3")) {
      joint_dp_vector_wire
    } else NULL,
    joint_dp_gaussian_one_draw = if (identical(
      operation, "joint-dp-vector-gaussian-one-draw-v1")) {
      joint_dp_gaussian_one_draw
    } else NULL,
    private_seed = if (operation %in% c(
      "joint-dp-laplace-v2", "joint-dp-vector-laplace-v3",
      "joint-dp-vector-gaussian-one-draw-v1")) {
      private_seed
    } else if (identical(operation, "clamp-count") &&
                          identical(role, "garbler")) {
      deterministic_output_seed %||% ""
    } else "",
    max_spool_bytes = spool_max, ttl_seconds = ttl,
    heartbeat_key = heartbeat_key_b64)
  deterministic_output_seed <- NULL
  private_seed <- NULL
  joint_dp <- NULL
  joint_dp_vector <- NULL
  joint_dp_vector_wire <- NULL
  joint_dp_gaussian_one_draw <- NULL
  joint_dp_gaussian_one_draw_authority <- NULL
  gaussian_one_draw_authority <- NULL
  .private_write_lines(as.character(jsonlite::toJSON(
    config, auto_unbox = TRUE, null = "null")), config_path)
  config$master_key <- NULL
  config$source_share <- NULL
  config$private_seed <- NULL
  config$joint_dp <- NULL
  config$joint_dp_vector <- NULL
  config$joint_dp_gaussian_one_draw <- NULL
  config$heartbeat_key <- NULL
  derived$master_key <- NULL
  heartbeat_key_b64 <- NULL
  binary <- normalizePath(binary, mustWork = TRUE)
  log_path <- file.path(spool, "worker-private.log")
  process <- NULL
  committed <- FALSE
  on.exit(if (!committed) {
    if (!is.null(process) && inherits(process, "process")) {
      tryCatch(process$kill(), error = function(e) NULL)
      tryCatch(process$wait(timeout = 1000), error = function(e) NULL)
    }
    unlink(spool, recursive = TRUE)
  }, add = TRUE)
  process <- processx::process$new(
    binary, c("exact-gc-worker", config_path), env = "current",
    stdout = log_path, stderr = "2>&1", cleanup = FALSE,
    cleanup_tree = FALSE)
  ready <- FALSE
  for (ready_poll in seq_len(100L)) {
    alive <- isTRUE(tryCatch(process$is_alive(), error = function(e) FALSE))
    if (!alive) break
    if (file.exists(file.path(spool, "ready"))) {
      ready <- TRUE
      break
    }
    Sys.sleep(0.05)
  }
  if (!ready || !isTRUE(tryCatch(process$is_alive(), error = function(e) FALSE))) {
    .exact_gc_record_private_error(
      list(spool = spool), "Exact-gc worker failed before readiness.")
    stop("Exact-gc worker failed to become ready.", call. = FALSE)
  }
  state <- new.env(parent = emptyenv())
  state$session_id <- session_id
  state$operation_id <- operation_id
  state$attempt <- attempt
  state$requested_spec <- requested_spec
  state$public_spec <- public_spec
  state$self_peer_id <- self_peer_id
  state$peer_id <- peer_id
  state$peer_identity_pk <- peer_identity_pk
  state$role <- role
  state$context_hash <- derived$context_hash
  state$peer_binding_digest <- peer_binding_digest
  if (analysis_bound) {
    state$analysis_binding_sha256 <- analysis_binding_sha256
  }
  state$operation <- operation
  state$output_kind <- output_kind
  state$purpose <- purpose
  state$source_producer <- source_producer
  state$ring_bits <- ring
  state$frac_bits <- frac_bits
  state$vector_len <- vector_len
  state$threshold <- threshold
  state$mul_plan <- mul_plan
  state$source_key <- source_key
  state$output_key <- output_key
  state$chunk_bytes <- chunk_bytes
  state$spool_max_bytes <- spool_max
  state$resource_reservation_bytes <- resource_reservation
  state$request_max_bytes <- request_max
  state$ttl_seconds <- ttl
  state$max_runtime_seconds <- max_runtime
  state$spool <- spool
  state$process <- process
  state$worker_pid <- suppressWarnings(as.numeric(process$get_pid()))
  if (length(state$worker_pid) != 1L || is.na(state$worker_pid) ||
      !is.finite(state$worker_pid) || state$worker_pid < 1 ||
      state$worker_pid != floor(state$worker_pid)) {
    stop("Exact-gc worker returned an invalid PID.", call. = FALSE)
  }
  state$worker_heartbeat_session <- protocol_session
  state$worker_heartbeat_key <- heartbeat_key
  state$out_cache <- NULL
  state$outbound_ack_offset <- .exact_gc_offset_read(
    file.path(spool, "outbound.ack"),
    "exact-gc acknowledged outbound offset")
  state$status <- "running"
  state$failure_code <- NULL
  state$retryable <- FALSE
  started_at <- .exact_gc_now()
  state$started_at <- started_at
  state$relay_heartbeat_at <- started_at
  state$worker_heartbeat_seen_at <- started_at
  state$worker_heartbeat_counter <-
    .exact_gc_worker_heartbeat_record(state)$counter
  .exact_gc_touch(state, now = started_at, ss = ss)
  source$claimed_by <- operation_id
  ss$.exact_gc_inputs[[source_key]] <- source
  operations <- .exact_gc_ops(ss)
  operations[[operation_id]] <- state
  committed <- TRUE
  .exact_gc_public_state(state)
}

.exact_gc_decode_route <- function(
    state, peer_id, read_offset,
    delivery_offset, delivery_chunk_bytes, delivery_payload_hash,
    delivery_payload, delivery_signature, long_poll) {
  if (!is.character(peer_id) || length(peer_id) != 1L || is.na(peer_id) ||
      !identical(peer_id, state$self_peer_id) ||
      !is.logical(long_poll) || length(long_poll) != 1L ||
      is.na(long_poll)) {
    stop("Invalid exact-gc route.", call. = FALSE)
  }
  delivery_strings <- list(
    payload_hash = delivery_payload_hash,
    payload = delivery_payload,
    signature = delivery_signature)
  valid_strings <- all(vapply(delivery_strings, function(value) {
    is.character(value) && length(value) == 1L && !is.na(value)
  }, logical(1L)))
  valid_numbers <- is.numeric(delivery_offset) &&
    length(delivery_offset) == 1L && !is.na(delivery_offset) &&
    is.finite(delivery_offset) && is.numeric(delivery_chunk_bytes) &&
    length(delivery_chunk_bytes) == 1L && !is.na(delivery_chunk_bytes) &&
    is.finite(delivery_chunk_bytes)
  if (!isTRUE(valid_strings) || !isTRUE(valid_numbers)) {
    stop("Invalid exact-gc route.", call. = FALSE)
  }
  empty <- delivery_offset == 0 && delivery_chunk_bytes == 0 &&
    all(!nzchar(unlist(delivery_strings, use.names = FALSE)))
  present <- all(nzchar(unlist(delivery_strings, use.names = FALSE)))
  if (!isTRUE(empty) && !isTRUE(present)) {
    stop("Invalid exact-gc route.", call. = FALSE)
  }
  delivery_bytes <- sum(nchar(
    unlist(delivery_strings, use.names = FALSE), type = "bytes")) +
    nchar(format(delivery_offset, scientific = FALSE, trim = TRUE),
          type = "bytes") +
    nchar(format(delivery_chunk_bytes, scientific = FALSE, trim = TRUE),
          type = "bytes") + 256
  if (delivery_bytes > state$request_max_bytes) {
    .dsvert_resource_oversize(
      delivery_bytes, state$request_max_bytes, "exact-gc DSI request")
  }
  delivery <- NULL
  if (isTRUE(present)) {
    delivery_offset <- .exact_gc_integer(
      delivery_offset, "exact-gc envelope offset", 0, 2^53)
    delivery_chunk_bytes <- .exact_gc_integer(
      delivery_chunk_bytes, "exact-gc envelope length", 1,
      state$chunk_bytes)
    if (!grepl("^[0-9a-f]{64}$", delivery_payload_hash) ||
        !grepl("^[A-Za-z0-9_-]+$", delivery_payload) ||
        !grepl("^[A-Za-z0-9_-]+$", delivery_signature)) {
      stop("Invalid exact-gc route.", call. = FALSE)
    }
    delivery <- list(
      version = .DSVERT_EXACT_GC_ENVELOPE_VERSION,
      capability_id = .DSVERT_EXACT_GC_CAPABILITY,
      session_id = state$session_id,
      operation_id = state$operation_id,
      context_hash = state$context_hash,
      sender_peer_id = state$peer_id,
      recipient_peer_id = state$self_peer_id,
      offset = delivery_offset,
      chunk_bytes = delivery_chunk_bytes,
      payload_hash = delivery_payload_hash,
      payload = delivery_payload,
      signature = delivery_signature)
  }
  list(
    read_offset = .exact_gc_integer(
      read_offset, "exact-gc read offset", 0, 2^53),
    delivery = delivery, long_poll = long_poll)
}

.exact_gc_exchange_impl <- function(
    ss, session_id, operation_id, peer_id, read_offset,
    delivery_offset = 0, delivery_chunk_bytes = 0,
    delivery_payload_hash = "", delivery_payload = "",
    delivery_signature = "", long_poll) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  state <- .exact_gc_operation_state(ss, operation_id)
  if (!identical(state$session_id, session_id) ||
      state$status %in% c("aborted", "failed")) {
    stop("Exact-gc operation is not active.", call. = FALSE)
  }
  route <- .exact_gc_decode_route(
    state, peer_id, read_offset,
    delivery_offset, delivery_chunk_bytes, delivery_payload_hash,
    delivery_payload, delivery_signature, long_poll)
  .exact_gc_with_lock(state, {
    # This proves only that the authenticated relay is still present. It keeps
    # the worker's spool I/O lease alive but never renews operation progress.
    .exact_gc_relay_heartbeat(state)
    .exact_gc_refresh(ss, state)
    .exact_gc_expire_if_idle(ss, state)
    progressed <- FALSE
    acknowledged <- .exact_gc_offset_read(
      file.path(state$spool, "outbound.ack"),
      "exact-gc acknowledged outbound offset")
    # Finish any safe reclamation left after an interruption between the
    # durable ACK-base commit and segment deletion.
    .exact_gc_outbound_compact(state, acknowledged)
    if (route$read_offset < acknowledged) {
      stop("Exact-gc outbound acknowledgement rolled back.", call. = FALSE)
    }
    ack_progress <- route$read_offset > acknowledged
    if (isTRUE(ack_progress)) {
      offer <- .exact_gc_outbound_offer_read(state)
      if (!identical(offer$offset, acknowledged) ||
          route$read_offset != offer$end) {
        stop("Exact-gc outbound acknowledgement skipped unconfirmed bytes.",
             call. = FALSE)
      }
    }
    if (!is.null(route$delivery)) {
      checked <- .exact_gc_validate_envelope(state, route$delivery)
      before <- .exact_gc_inbound_state_read(state)$head
      after <- .exact_gc_inbound_append(
        state, checked$envelope$offset, checked$payload)
      progressed <- after > before
    }
    inbound_size <- .exact_gc_inbound_state_read(state)$head
    if (isTRUE(ack_progress)) {
      .exact_gc_outbound_compact(state, route$read_offset)
      progressed <- TRUE
    }
    if (isTRUE(progressed)) .exact_gc_touch(state, ss = ss)
    .exact_gc_refresh(ss, state)
    outbound <- NULL
    if (!identical(state$status, "failed")) {
      cache <- state$out_cache
      if (!is.null(cache) && identical(cache$offset, route$read_offset)) {
        outbound <- cache$envelope
      } else {
        payload <- .exact_gc_segment_read_coalesced(
          state, route$read_offset, route$long_poll)
        .exact_gc_refresh(ss, state)
        if (length(payload)) {
          outbound <- .exact_gc_make_envelope(
            state, route$read_offset, payload)
          .exact_gc_outbound_offer_write(state, outbound)
          state$out_cache <- list(offset = route$read_offset,
                                  envelope = outbound)
          .exact_gc_touch(state, ss = ss)
        }
      }
    }
    list(
      capability_id = .DSVERT_EXACT_GC_CAPABILITY,
      peer_id = state$self_peer_id, state = state$status,
      stored = identical(state$status, "complete"),
      inbound_size = inbound_size, outbound = outbound,
      worker_heartbeat = state$worker_heartbeat_counter)
  })
}

.exact_gc_status_impl <- function(ss, session_id, operation_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  state <- .exact_gc_operation_state(ss, operation_id)
  if (!identical(state$session_id, session_id)) {
    stop("Exact-gc session mismatch.", call. = FALSE)
  }
  if (identical(state$status, "running")) {
    .exact_gc_with_lock(state, {
      .exact_gc_refresh(ss, state)
      .exact_gc_expire_if_idle(ss, state)
    })
  }
  .exact_gc_public_liveness(state)
}

.exact_gc_cleanup_capability_message <- function(contract) {
  charToRaw(paste0(
    .DSVERT_EXACT_GC_CLEANUP_CAPABILITY_DOMAIN,
    .dsvert_dp_canonical_json(contract)))
}

.exact_gc_cleanup_capability_create <- function(
    ss, session_id, cleanup_purpose) {
  cleanup_purpose <- .exact_gc_scalar(
    cleanup_purpose, "exact-gc cleanup purpose")
  if (!identical(cleanup_purpose,
                 .DSVERT_EXACT_GC_CROSS_CLEANUP_PURPOSE) ||
      !is.character(ss$.exact_gc_peer_binding_digest) ||
      length(ss$.exact_gc_peer_binding_digest) != 1L ||
      !grepl("^[0-9a-f]{64}$", ss$.exact_gc_peer_binding_digest)) {
    stop("Exact-gc cleanup capability purpose is unavailable.", call. = FALSE)
  }
  contract <- list(
    version = .DSVERT_EXACT_GC_CLEANUP_CAPABILITY_VERSION,
    session_id = .dsvert_relay_validate_session_id(session_id),
    cleanup_purpose = cleanup_purpose,
    operation_scope = "all_and_only_operations_in_bound_exact_session_v1",
    peer_binding_digest = ss$.exact_gc_peer_binding_digest)
  previous <- ss$.exact_gc_cleanup_capability
  if (!is.null(previous)) {
    if (!is.list(previous) ||
        !identical(previous$contract, contract) ||
        !is.character(previous$json) || length(previous$json) != 1L) {
      stop("Conflicting exact-gc cleanup capability retry.", call. = FALSE)
    }
    return(previous$json)
  }
  identity <- .get_identity_keypair()
  envelope <- list(
    version = .DSVERT_EXACT_GC_CLEANUP_CAPABILITY_VERSION,
    contract = contract,
    signature = .dsvert_relay_sign_message(
      .exact_gc_cleanup_capability_message(contract), identity$identity_sk))
  encoded <- .dsvert_dp_canonical_json(envelope)
  ss$.exact_gc_cleanup_capability <- list(
    contract = contract, json = encoded)
  encoded
}

.exact_gc_cleanup_capability_decode <- function(
    cleanup_capability_json, session_id) {
  cleanup_capability_json <- .exact_gc_scalar(
    cleanup_capability_json, "exact-gc cleanup capability")
  if (nchar(cleanup_capability_json, type = "bytes") > 16384L) {
    stop("Invalid exact-gc cleanup capability.", call. = FALSE)
  }
  envelope <- tryCatch(jsonlite::fromJSON(
    cleanup_capability_json, simplifyVector = FALSE),
    error = function(error) NULL)
  required_contract <- c(
    "version", "session_id", "cleanup_purpose", "operation_scope",
    "peer_binding_digest")
  if (!is.list(envelope) ||
      !identical(sort(names(envelope)),
                 sort(c("version", "contract", "signature"))) ||
      !identical(envelope$version,
                 .DSVERT_EXACT_GC_CLEANUP_CAPABILITY_VERSION) ||
      !is.list(envelope$contract) ||
      !identical(sort(names(envelope$contract)), sort(required_contract)) ||
      !identical(envelope$contract$version,
                 .DSVERT_EXACT_GC_CLEANUP_CAPABILITY_VERSION) ||
      !identical(envelope$contract$session_id, session_id) ||
      !identical(envelope$contract$cleanup_purpose,
                 .DSVERT_EXACT_GC_CROSS_CLEANUP_PURPOSE) ||
      !identical(envelope$contract$operation_scope,
                 "all_and_only_operations_in_bound_exact_session_v1") ||
      !is.character(envelope$contract$peer_binding_digest) ||
      length(envelope$contract$peer_binding_digest) != 1L ||
      !grepl("^[0-9a-f]{64}$", envelope$contract$peer_binding_digest) ||
      !is.character(envelope$signature) || length(envelope$signature) != 1L ||
      !identical(.dsvert_dp_canonical_json(envelope),
                 cleanup_capability_json)) {
    stop("Invalid exact-gc cleanup capability.", call. = FALSE)
  }
  identity <- .get_identity_keypair()
  if (!isTRUE(.dsvert_relay_verify_message(
        .exact_gc_cleanup_capability_message(envelope$contract),
        identity$identity_pk, envelope$signature))) {
    stop("Invalid exact-gc cleanup capability.", call. = FALSE)
  }
  envelope
}

.exact_gc_bind_public <- function(ss, session_id, cleanup_purpose = "") {
  result <- list(
    bound = TRUE, capability_id = .DSVERT_EXACT_GC_CAPABILITY)
  if (!is.null(ss$.exact_gc_analysis_binding)) {
    result$analysis_binding <- ss$.exact_gc_analysis_binding
    result$analysis_binding_sha256 <-
      ss$.exact_gc_analysis_binding_sha256
  }
  if (is.character(cleanup_purpose) && length(cleanup_purpose) == 1L &&
      !is.na(cleanup_purpose) && nzchar(cleanup_purpose)) {
    result$cleanup_purpose <- cleanup_purpose
    result$cleanup_capability_json <-
      .exact_gc_cleanup_capability_create(
        ss, session_id, cleanup_purpose)
  } else if (!identical(cleanup_purpose, "")) {
    stop("Invalid exact-gc cleanup purpose.", call. = FALSE)
  }
  result
}

#' Initialize an idempotent exact-GC peer transport (AGGREGATE)
#'
#' @param session_id Active exact-GC session identifier.
#' @export
exactGCTransportInitDS <- function(session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  if (isTRUE(ss$.exact_gc_transport_initialized)) {
    return(.exact_gc_transport_public(ss))
  }
  existing <- c(.key_exists("transport_sk", ss),
                .key_exists("transport_pk", ss),
                .key_exists("identity_pk", ss))
  if (any(existing) && !all(existing)) {
    stop("Session contains an incomplete transport identity.", call. = FALSE)
  }
  if (all(existing)) {
    ss$.exact_gc_transport_initialized <- TRUE
    return(.exact_gc_transport_public(ss))
  }
  identity <- .get_identity_keypair()
  transport <- .callMpcTool("transport-keygen", list())
  .key_put("transport_sk", transport$secret_key, ss)
  .key_put("transport_pk", transport$public_key, ss)
  .key_put("identity_pk", identity$identity_pk, ss)
  ss$.exact_gc_transport_initialized <- TRUE
  .exact_gc_transport_public(ss)
}

#' Bind a signed exact-GC peer pair (AGGREGATE)
#'
#' Existing policy-bound routes derive the accepted two-peer set exclusively
#' from the custodian's joint-DP policy. A server-held Count authorization is
#' resolved only by its artifact key and supplies the full K pinset and exact
#' two noise authorities. In both cases the binding commits the signed
#' identities, ephemeral transport keys, session and exact-GC capability; no
#' analyst-selected subset or role is accepted.
#'
#' @param transport_keys_b64 Canonical map of the designated peers' ephemeral
#'   transport public keys.
#' @param identity_info_b64 Canonical map of the designated peers' signed
#'   identities.
#' @param session_id Exact-GC session identifier.
#' @param cleanup_purpose Empty for routes that do not need session cleanup,
#'   or the fixed cross-owner cleanup purpose. The server does not accept an
#'   analyst-defined purpose.
#' @param artifact_key Empty for policy-bound routes, or the artifact key of an
#'   intact server-held Count authorization in this session.
#'
#' @export
exactGCBindPeersDS <- function(transport_keys_b64, identity_info_b64,
                               session_id, cleanup_purpose = "",
                               artifact_key = "") {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  if (!isTRUE(ss$.exact_gc_transport_initialized) ||
      !.key_exists("transport_sk", ss) ||
      !.key_exists("transport_pk", ss) ||
      !.key_exists("identity_pk", ss)) {
    stop("Exact-gc transport is not initialized.", call. = FALSE)
  }
  if (!is.character(artifact_key) || length(artifact_key) != 1L ||
      is.na(artifact_key) ||
      (!identical(artifact_key, "") &&
       !grepl("^[0-9a-f]{64}$", artifact_key))) {
    stop("Invalid exact-gc analysis artifact key.", call. = FALSE)
  }
  analysis <- NULL
  if (identical(artifact_key, "")) {
    if (!is.null(ss$.dp_count_authorization)) {
      stop("An authorized Count session requires its analysis artifact key.",
           call. = FALSE)
    }
    policy_context <- .exact_gc_designated_policy_context()
  } else {
    authorization <- .dsvert_dp_count_session_authorization_validate_v1(
      ss, session_id, artifact_key)
    analysis <- .exact_gc_analysis_contract_binding(
      authorization$contract)
  }
  transport_keys <- .exact_gc_validate_handshake_map(
    transport_keys_b64, "exact-gc transport-key map",
    expected_names = if (is.null(analysis)) policy_context$designated else NULL)
  identity_info <- .exact_gc_validate_handshake_map(
    identity_info_b64, "exact-gc identity map",
    expected_names = if (is.null(analysis)) policy_context$designated else NULL)
  if (!is.null(analysis)) {
    policy_context <- .exact_gc_analysis_policy_context(
      analysis, identity_info, .key_get("identity_pk", ss))
    if (length(transport_keys) != 2L ||
        !setequal(names(transport_keys), policy_context$designated)) {
      stop("Exact-gc handshake must contain exactly the two noise ",
           "authorities.", call. = FALSE)
    }
  }
  if (!identical(sort(names(transport_keys)), sort(names(identity_info)))) {
    stop("Exact-gc handshake maps name different peers.", call. = FALSE)
  }
  for (name in names(transport_keys)) {
    transport_raw <- .exact_gc_b64url_decode(
      transport_keys[[name]], "exact-gc transport public key", 32L)
    info <- identity_info[[name]]
    if (!is.list(info) || !identical(sort(names(info)),
                                     c("identity_pk", "signature"))) {
      stop("Invalid exact-gc signed identity entry.", call. = FALSE)
    }
    identity_raw <- .exact_gc_b64url_decode(
      info$identity_pk, "exact-gc identity public key", 32L)
    signature_raw <- .exact_gc_b64url_decode(
      info$signature, "exact-gc transport signature", 64L)
    if (length(transport_raw) != 32L || length(identity_raw) != 32L ||
        length(signature_raw) != 64L) {
      stop("Invalid exact-gc signed transport field length.", call. = FALSE)
    }
  }
  own_transport <- .key_get("transport_pk", ss)
  own_identity <- .key_get("identity_pk", ss)
  verified <- .exact_gc_verify_designated_pair(
    identity_info, transport_keys, own_identity, own_transport,
    policy_context)
  binding <- if (is.null(analysis)) {
    .exact_gc_designated_binding_digest(
      session_id, policy_context, verified)
  } else {
    .exact_gc_analysis_peer_binding_digest(
      session_id, analysis, policy_context, verified)
  }
  canonical_digest <- binding$sha256
  if (!is.null(ss$.exact_gc_peer_binding_digest)) {
    if (!identical(ss$.exact_gc_peer_binding_digest, canonical_digest)) {
      stop("Conflicting retry for exact-gc peer binding.", call. = FALSE)
    }
    if (!identical(
          ss$.typed_blob_parent_binding_digest, canonical_digest)) {
      stop("Exact-gc typed transport lost its parent policy binding.",
           call. = FALSE)
    }
    .exact_gc_validate_bound_peer_context(ss, session_id)
    return(.exact_gc_bind_public(
      ss, session_id, cleanup_purpose))
  }
  # Purpose-bound producer tickets nest the complete policy/session binding,
  # not merely the selected pair's key manifest.  Thus the same two peers and
  # transport keys cannot mint cross-policy-equivalent typed tickets.
  .dsvert_typed_blob_install_peer_manifest(
    ss, identity_info = identity_info, transport_keys = transport_keys,
    parent_binding_digest = canonical_digest)
  ss$peer_transport_pks <- as.list(verified$peer_transport)
  peer_names <- names(verified$peer_transport)
  ss$.exact_gc_peer_identity_pks <- stats::setNames(
    lapply(identity_info[peer_names], function(info) {
      .base64url_to_base64(info$identity_pk)
    }), peer_names)
  ss$.exact_gc_self_name <- policy_context$peer_name
  ss$.exact_gc_designated_peers <- policy_context$designated
  ss$.exact_gc_full_peer_pinset_sha256 <- policy_context$full_pinset_sha256
  if (!is.null(analysis)) {
    ss$.exact_gc_analysis_contract <- analysis$contract
    ss$.exact_gc_analysis_binding <- analysis$binding
    ss$.exact_gc_analysis_binding_sha256 <- analysis$sha256
  }
  ss$.exact_gc_peer_binding_contract <- binding$contract
  ss$.exact_gc_peer_binding_digest <- canonical_digest
  .exact_gc_bind_public(ss, session_id, cleanup_purpose)
}

#' Pump one idempotent opaque byte exchange (AGGREGATE)
#' @param session_id Active exact-GC session identifier.
#' @param operation_id Active exact-GC operation identifier.
#' @param peer_id Authenticated identifier of the bound peer.
#' @param read_offset Outbound byte offset acknowledged by the peer.
#' @param delivery_offset,delivery_chunk_bytes Exact numeric bounds for an
#'   inbound opaque delivery, or zero when no bytes are delivered.
#' @param delivery_payload_hash,delivery_payload,delivery_signature Direct
#'   scalar fields from the authenticated opaque envelope, or empty strings
#'   when no bytes are delivered. The server reconstructs the fixed signed
#'   context; no outer JSON or second Base64 layer crosses DSI.
#' @param long_poll Logical; wait briefly for outbound progress when possible.
#' @export
exactGCExchangeDS <- function(
    session_id, operation_id, peer_id, read_offset,
    delivery_offset = 0, delivery_chunk_bytes = 0,
    delivery_payload_hash = "", delivery_payload = "",
    delivery_signature = "", long_poll = TRUE) {
  ss <- .S(session_id)
  tryCatch(
    .exact_gc_exchange_impl(
      ss, session_id, operation_id, peer_id, read_offset,
      delivery_offset, delivery_chunk_bytes, delivery_payload_hash,
      delivery_payload, delivery_signature, long_poll),
    error = function(e) {
      if (inherits(e, "dsvert_resource_backpressure") ||
          inherits(e, "dsvert_resource_oversize")) stop(e)
      state <- tryCatch(.exact_gc_operation_state(
        ss, operation_id, required = FALSE), error = function(e2) NULL)
      .exact_gc_record_private_error(state, conditionMessage(e))
      if (!is.null(state) && identical(state$status, "running")) {
        .exact_gc_mark_failed(
          ss, state, "infrastructure_unavailable")
      }
      stop("Exact MPC exchange failed.", call. = FALSE)
    })
}

#' Abort one exact operation and remove its private spool (AGGREGATE)
#' @inheritParams exactGCExchangeDS
#' @export
exactGCAbortDS <- function(session_id, operation_id) {
  ss <- .S(session_id)
  tryCatch({
    .dsvert_relay_validate_session_id(session_id)
    operation_id <- .dsvert_relay_validate_operation_id(operation_id)
    state <- .exact_gc_operation_state(ss, operation_id, required = FALSE)
    if (!is.null(state) && !identical(state$session_id, session_id)) {
      stop("Exact-gc session mismatch.", call. = FALSE)
    }
    direct <- !is.null(state) &&
      identical(state$operation, "mul-truncate-checked")
    batch <- !is.null(ss$.exact_gc_vecmul_input_stages[[operation_id]])
    chisq_guard <- !is.null(
      ss$.exact_gc_chisq_guard_stages[[operation_id]])
    if (isTRUE(chisq_guard)) {
      .exact_gc_chisq_abort(ss, operation_id, state)
    } else if (isTRUE(direct) || isTRUE(batch)) {
      .exact_gc_checked_mul_abort_batch(ss, operation_id, state)
    } else if (!is.null(state)) {
      # Cleanup is transactional even if one peer reached its local complete
      # marker before the fan-out failed on the other peer. A lone output share
      # must not remain reusable after the client aborts the joint operation.
      .exact_gc_abort_state(ss, state, abort_complete = TRUE)
    }
    if (exists(".dsvert_dp_alignment_mask_abort_operation",
               mode = "function", inherits = TRUE)) {
      .dsvert_dp_alignment_mask_abort_operation(ss, operation_id)
    }
    TRUE
  }, error = function(e) stop("Exact MPC abort failed.", call. = FALSE))
}

#' Remove one capability-bound exact-GC session (AGGREGATE)
#'
#' The signed bearer capability is minted only after the server has committed
#' its designated pinned-peer binding. It commits the exact session, binding
#' digest and the fixed cross-owner purpose. It cannot name or remove any other
#' session, and a retry after successful deletion returns `already_cleaned`.
#'
#' @param session_id Exact-GC session identifier committed by the capability.
#' @param cleanup_capability_json Canonical peer-signed cleanup capability
#'   returned by [exactGCBindPeersDS()].
#' @return A fixed cleanup state containing no protected data.
#'
#' @export
exactGCCleanupDS <- function(session_id, cleanup_capability_json) {
  tryCatch({
    cleanup_capability_json <- .dsvert_dsi_text_decode(
      cleanup_capability_json, "exact-gc cleanup capability", 16384L)
    session_id <- .dsvert_relay_validate_session_id(session_id)
    envelope <- .exact_gc_cleanup_capability_decode(
      cleanup_capability_json, session_id)
    storage <- .session_storage()
    ss <- storage[[session_id]]
    if (is.null(ss)) {
      return(list(
        cleaned = TRUE, state = "already_cleaned",
        cleanup_purpose = envelope$contract$cleanup_purpose))
    }
    stored <- ss$.exact_gc_cleanup_capability
    if (!is.list(stored) ||
        !identical(stored$json, cleanup_capability_json) ||
        !identical(ss$.exact_gc_peer_binding_digest,
                   envelope$contract$peer_binding_digest)) {
      stop("Exact-gc cleanup capability does not own this session.",
           call. = FALSE)
    }
    .cleanup_session(session_id)
    list(
      cleaned = TRUE, state = "cleaned",
      cleanup_purpose = envelope$contract$cleanup_purpose)
  }, error = function(error) {
    stop("Exact MPC capability-bound cleanup failed.", call. = FALSE)
  })
}
