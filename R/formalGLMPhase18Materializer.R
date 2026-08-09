# Server-authoritative protected-row materializer for the sealed formal GLM.
#
# Phase 1.8 deliberately has no AggregateMethod, export, command handler or
# opening.  The pre-execution type accepts only an exact, unanimously approved
# Phase-1.5 plan and a locally durable biomedical manifest.  It emits two
# purpose-bound encrypted share envelopes per fixed public block.  A separate
# local validity bit is secret-shared for every slot; it is never folded into a
# predictor or silently treated as a reference category.
#
# The internal Go Phase-1.9 circuit consumes the K local validity, alignment
# gate, and consensus shares inside exact GC and masks the full tuple.  An
# internal R bridge consumes the durable local inbox, but this type remains
# sealed and production_ready is always FALSE until the registered R/DSI
# lifecycle is proven and the private Phase-1.9 output is consumed by the
# single durable joint-DP release path.

.DSVERT_FORMAL_GLM_PHASE18_PRE_VERSION <-
  "dsvert-formal-glm-phase18-pre-execution-materializer-v1"
.DSVERT_FORMAL_GLM_PHASE18_TICKET_VERSION <-
  "dsvert-formal-glm-phase18-recipient-ticket-v1"
.DSVERT_FORMAL_GLM_PHASE18_BLOCK_VERSION <-
  "dsvert-formal-glm-phase18-encrypted-block-v2"
.DSVERT_FORMAL_GLM_PHASE18_BUNDLE_VERSION <-
  "dsvert-formal-glm-phase18-encrypted-block-bundle-v2"
.DSVERT_FORMAL_GLM_PHASE18_PRIVATE_BLOCK_VERSION <-
  "dsvert-formal-glm-phase18-private-block-v2"
.DSVERT_FORMAL_GLM_PHASE18_LOCAL_RECEIPT_VERSION <-
  "dsvert-formal-glm-phase18-local-materialization-receipt-v2"
.DSVERT_FORMAL_GLM_PHASE18_POST_VERSION <-
  "dsvert-formal-glm-phase18-post-execution-binding-v1"
.DSVERT_FORMAL_GLM_PHASE18_SEALED_TOKEN_VERSION <-
  "dsvert-formal-glm-phase18-sealed-post-execution-token-v1"

.DSVERT_FORMAL_GLM_PHASE18_PURPOSE <-
  "formal_glm_fixed_rows_and_local_validity_shares_phase19_only_v1"
.DSVERT_FORMAL_GLM_PHASE18_PLAN_DOMAIN <-
  "dsVert/formal-glm/phase15-plan/v1|"
.DSVERT_FORMAL_GLM_PHASE18_PLAN_APPROVAL_DOMAIN <-
  "dsVert/formal-glm/phase15/plan-approval/v1"
.DSVERT_FORMAL_GLM_PHASE18_KERNEL_DOMAIN <-
  "dsVert/formal-glm/phase1-policy/v1|"
.DSVERT_FORMAL_GLM_PHASE18_SOURCE_DOMAIN <-
  "dsVert/formal-glm/phase17/source-contribution/v1"
.DSVERT_FORMAL_GLM_PHASE18_SOURCE_ATTESTATION_DOMAIN <-
  "dsVert/formal-glm/phase17/source-contribution-attestation/v1"
.DSVERT_FORMAL_GLM_PHASE18_ADMISSION_DOMAIN <-
  "dsVert/formal-glm/phase17/authenticated-admission/v1"
.DSVERT_FORMAL_GLM_PHASE18_TICKET_DOMAIN <-
  "dsVert/formal-glm/phase18/recipient-ticket/v1"
.DSVERT_FORMAL_GLM_PHASE18_BLOCK_DOMAIN <-
  "dsVert/formal-glm/phase18/encrypted-block/v1"
.DSVERT_FORMAL_GLM_PHASE18_RECEIPT_DOMAIN <-
  "dsVert/formal-glm/phase18/local-materialization-receipt/v1"
.DSVERT_FORMAL_GLM_PHASE18_POST_DOMAIN <-
  "dsVert/formal-glm/phase18/post-execution-binding/v1"
.DSVERT_FORMAL_GLM_PHASE18_TOKEN_DOMAIN <-
  "dsVert/formal-glm/phase18/sealed-token/v1"

.DSVERT_FORMAL_GLM_PHASE18_CAPACITY_SEMANTICS <-
  "fixed_public_total_capacity_zero_weight_padded_slots_v1"
.DSVERT_FORMAL_GLM_PHASE18_ADJACENCY_SEMANTICS <-
  "patient_slot_vs_zero_weight_slot_add_remove_or_two_slots_replace_one_v1"
.DSVERT_FORMAL_GLM_PHASE18_PATIENT_CONTRIBUTION <-
  "at_most_one_active_aligned_record_per_patient_all_duplicates_zero_weight_v1"
.DSVERT_FORMAL_GLM_PHASE18_VALIDITY <-
  "one_xor_shared_local_validity_bit_per_peer_and_capacity_slot_v1"
.DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING <-
  "recipient_specific_xor_shared_gate_and_consensus_digest_v2"
.DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_ACCEPTED <-
  "accepted_phase19_consensus_v1"
.DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_REJECTED <-
  "rejected_phase19_consensus_v1"
.DSVERT_FORMAL_GLM_PHASE18_PRIVATE_LANE_DOMAIN <-
  "dsVert/formal-glm/phase18/private-lane-prf/v2"
.DSVERT_FORMAL_GLM_PHASE18_PHASE19_BLOCKER <-
  "formal_glm_phase19_private_output_not_wired_to_durable_joint_dp_release"

.dsvert_formal_glm_phase18_abort <- function(message, code) {
  stop(structure(
    list(message = message, call = NULL, code = code,
         openings_performed = 0L),
    class = c("dsvert_formal_glm_phase18_error", "error", "condition")))
}

.dsvert_formal_glm_phase18_scalar <- function(
    value, what, pattern = NULL, maximum_bytes = 4096L) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes ||
      (!is.null(pattern) && !grepl(pattern, value))) {
    .dsvert_formal_glm_phase18_abort(
      paste0("Invalid formal-GLM ", what, "."), "invalid_public_contract")
  }
  enc2utf8(value)
}

.dsvert_formal_glm_phase18_integer <- function(
    value, what, minimum = 0, maximum = 2^53 - 1) {
  value <- tryCatch(suppressWarnings(as.numeric(value)),
                    error = function(error) NA_real_)
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value != floor(value) || value < minimum || value > maximum) {
    .dsvert_formal_glm_phase18_abort(
      paste0("Invalid formal-GLM ", what, "."), "invalid_public_contract")
  }
  value
}

.dsvert_formal_glm_phase18_names <- function(value, what, minimum = 1L) {
  if (is.list(value)) value <- unlist(value, use.names = FALSE)
  if (!is.character(value) || length(value) < minimum || anyNA(value) ||
      any(!grepl("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", value)) ||
      anyDuplicated(value)) {
    .dsvert_formal_glm_phase18_abort(
      paste0("Invalid formal-GLM ", what, "."), "invalid_pinned_consortium")
  }
  unname(enc2utf8(value))
}

.dsvert_formal_glm_phase18_sha256 <- function(value) {
  if (is.character(value)) value <- charToRaw(value)
  digest::digest(value, algo = "sha256", serialize = FALSE)
}

.dsvert_formal_glm_phase18_hash_object <- function(domain, value) {
  .dsvert_formal_glm_phase18_sha256(paste0(
    domain,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value))))
}

.dsvert_formal_glm_phase18_private_lane_bytes <- function(
    authorization, block_index, lane, n) {
  secret <- authorization$alignment_secret
  if (!is.raw(secret) || length(secret) < 32L ||
      !is.character(lane) || length(lane) != 1L || is.na(lane) ||
      !grepl("^[a-z0-9_-]{1,64}$", lane) ||
      !is.numeric(n) || length(n) != 1L || is.na(n) ||
      !is.finite(n) || n < 1L || n > 1024L * 1024L ||
      n != as.integer(n)) {
    .dsvert_formal_glm_phase18_abort(
      "The local formal-GLM private-lane key is unavailable.",
      "local_alignment_seal_unavailable")
  }
  block_index <- .dsvert_formal_glm_phase18_integer(
    block_index, "private-lane block index", 0,
    authorization$pre$total_blocks - 1)
  source_slot <- match(
    authorization$policy$peer_name, authorization$peers) - 1L
  if (is.na(source_slot)) {
    .dsvert_formal_glm_phase18_abort(
      "The private-lane source is outside the pinned consortium.",
      "invalid_pinned_consortium")
  }
  output <- raw()
  counter <- 0L
  while (length(output) < as.integer(n)) {
    payload <- .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(list(
        domain = .DSVERT_FORMAL_GLM_PHASE18_PRIVATE_LANE_DOMAIN,
        purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
        capsule_id = authorization$pre$capsule_id,
        plan_sha256 = authorization$pre$plan_sha256,
        pre_execution_sha256 = authorization$pre_execution_sha256,
        run_id = authorization$pre$run_id,
        source_name = authorization$policy$peer_name,
        source_slot = source_slot,
        block_index = block_index,
        total_blocks = authorization$pre$total_blocks,
        garbler_peer_name = authorization$pre$garbler_peer_name,
        evaluator_peer_name = authorization$pre$evaluator_peer_name,
        release_token = authorization$pre$release_token,
        lane = lane, counter = counter)))
    output <- c(output, digest::hmac(
      key = secret, object = charToRaw(payload), algo = "sha256",
      serialize = FALSE, raw = TRUE))
    counter <- counter + 1L
  }
  output[seq_len(as.integer(n))]
}

.dsvert_formal_glm_phase18_hex_raw <- function(value, what) {
  value <- .dsvert_formal_glm_phase18_scalar(
    value, what, pattern = "^[0-9a-f]{64}$", maximum_bytes = 64L)
  starts <- seq.int(1L, 63L, by = 2L)
  as.raw(strtoi(substring(value, starts, starts + 1L), base = 16L))
}

.dsvert_formal_glm_phase18_alignment_shares <- function(
    authorization, block_index, consensus_sha256, status) {
  if (!status %in% c(.DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_ACCEPTED,
                     .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_REJECTED)) {
    .dsvert_formal_glm_phase18_abort(
      "The private alignment state is invalid.",
      "invalid_local_materialization")
  }
  gate_mask <- as.integer(.dsvert_formal_glm_phase18_private_lane_bytes(
    authorization, block_index, "alignment_gate", 1L)) %% 2L
  consensus_mask <- .dsvert_formal_glm_phase18_private_lane_bytes(
    authorization, block_index, "alignment_consensus", 32L)
  consensus <- .dsvert_formal_glm_phase18_hex_raw(
    consensus_sha256, "private alignment consensus")
  accepted <- as.integer(identical(
    status, .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_ACCEPTED))
  result <- list(
    list(gate = gate_mask, consensus = consensus_mask),
    list(gate = bitwXor(gate_mask, accepted),
         consensus = as.raw(bitwXor(
           as.integer(consensus_mask), as.integer(consensus)))))
  names(result) <- c(
    authorization$pre$garbler_peer_name,
    authorization$pre$evaluator_peer_name)
  result
}

.dsvert_formal_glm_phase18_uint64 <- function(value) {
  value <- .dsvert_formal_glm_phase18_integer(
    value, "message length", 0, 2^53 - 1)
  result <- raw(8L)
  for (index in 8:1) {
    result[[index]] <- as.raw(value %% 256)
    value <- floor(value / 256)
  }
  result
}

.dsvert_formal_glm_phase18_append <- function(target, value) {
  if (is.character(value)) value <- charToRaw(value)
  if (!is.raw(value)) {
    .dsvert_formal_glm_phase18_abort(
      "Invalid formal-GLM authenticated message.",
      "invalid_authenticated_message")
  }
  c(target, .dsvert_formal_glm_phase18_uint64(length(value)), value)
}

.dsvert_formal_glm_phase18_domain_message <- function(domain, json) {
  json <- .dsvert_formal_glm_phase18_scalar(
    json, "canonical signed JSON", maximum_bytes = 32L * 1024L^2)
  .dsvert_formal_glm_phase18_append(
    .dsvert_formal_glm_phase18_append(raw(), domain), charToRaw(json))
}

.dsvert_formal_glm_phase18_json <- function(value) {
  as.character(jsonlite::toJSON(
    value, auto_unbox = TRUE, null = "null", na = "null", digits = 17,
    pretty = FALSE))
}

.dsvert_formal_glm_phase18_decode_json <- function(
    value, what, maximum_bytes = 32L * 1024L^2) {
  value <- .dsvert_formal_glm_phase18_scalar(
    value, what, maximum_bytes = maximum_bytes)
  decoded <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = FALSE), error = function(error) NULL)
  encoded <- tryCatch(.dsvert_formal_glm_phase18_json(decoded),
                      error = function(error) NULL)
  if (!is.list(decoded) || is.null(encoded) || !identical(encoded, value)) {
    .dsvert_formal_glm_phase18_abort(
      paste0("The formal-GLM ", what, " is not canonical JSON."),
      "noncanonical_public_contract")
  }
  list(value = decoded, json = value)
}

.dsvert_formal_glm_phase18_signature <- function(value) {
  value <- .dsvert_formal_glm_phase18_scalar(
    value, "signature", maximum_bytes = 128L)
  if (grepl("^[A-Za-z0-9_-]{86}$", value)) return(value)
  raw <- tryCatch(jsonlite::base64_dec(value), error = function(error) raw())
  if (!is.raw(raw) || length(raw) != 64L) {
    .dsvert_formal_glm_phase18_abort(
      "Invalid formal-GLM signature.", "invalid_signature_set")
  }
  .dsvert_relay_b64url_encode(raw)
}

.dsvert_formal_glm_phase18_verify_signature_set <- function(
    message, signatures, peers, policy,
    verifier = .dsvert_relay_verify_message, what = "signature set") {
  if (!is.raw(message) || !is.function(verifier) || !is.list(signatures) ||
      length(signatures) != length(peers)) {
    .dsvert_formal_glm_phase18_abort(
      paste0("The formal-GLM ", what, " is not unanimously signed."),
      "invalid_signature_set")
  }
  observed <- vapply(signatures, function(entry) {
    if (!is.list(entry) || !setequal(names(entry), c("signer", "signature"))) {
      return(NA_character_)
    }
    tryCatch(.dsvert_formal_glm_phase18_scalar(
      entry$signer, "signature identity", maximum_bytes = 128L),
      error = function(error) NA_character_)
  }, character(1L))
  if (anyNA(observed) || anyDuplicated(observed) ||
      !setequal(observed, peers)) {
    .dsvert_formal_glm_phase18_abort(
      paste0("The formal-GLM ", what, " does not cover exactly all K peers."),
      "invalid_signature_set")
  }
  ordered <- signatures[match(peers, observed)]
  valid <- vapply(seq_along(peers), function(index) {
    peer <- peers[[index]]
    signature <- tryCatch(
      .dsvert_formal_glm_phase18_signature(ordered[[index]]$signature),
      error = function(error) NA_character_)
    !is.na(signature) && isTRUE(tryCatch(
      verifier(message, unname(policy$peer_pinset[[peer]]), signature),
      error = function(error) FALSE))
  }, logical(1L))
  if (!all(valid)) {
    .dsvert_formal_glm_phase18_abort(
      paste0("The formal-GLM ", what, " failed pinned Ed25519 verification."),
      "invalid_signature_set")
  }
  invisible(ordered)
}

.dsvert_formal_glm_phase18_sign <- function(
    unsigned, policy, domain, signer = NULL) {
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(unsigned))
  message <- .dsvert_formal_glm_phase18_domain_message(domain, json)
  pin <- unname(policy$peer_pinset[[policy$peer_name]])
  if (is.null(signer)) {
    identity <- .get_identity_keypair()
    if (!identical(.dsvert_relay_normalize_identity_pk(identity$identity_pk),
                   .dsvert_relay_normalize_identity_pk(pin))) {
      .dsvert_formal_glm_phase18_abort(
        "The runtime identity differs from the formal-GLM materializer pin.",
        "local_identity_mismatch")
    }
    signature <- .dsvert_relay_sign_message(message, identity$identity_sk)
  } else {
    if (!is.function(signer)) {
      .dsvert_formal_glm_phase18_abort(
        "Invalid formal-GLM signer.", "local_identity_mismatch")
    }
    signature <- signer(message, policy$peer_name, pin)
  }
  signature <- .dsvert_formal_glm_phase18_signature(signature)
  c(unsigned, list(signature = signature))
}

.dsvert_formal_glm_phase18_peer_id <- function(pin) {
  pin <- .dsvert_relay_normalize_identity_pk(pin)
  raw <- .dsvert_relay_b64url_decode(pin, "formal-GLM identity pin")
  paste0("dsv1_", .dsvert_formal_glm_phase18_sha256(c(
    charToRaw("dsVert/peer-capability/v1|"), raw)))
}

.dsvert_formal_glm_phase18_roles <- function(policy, peers, designated) {
  pins <- policy$peer_pinset
  if (!is.character(pins) || is.null(names(pins)) ||
      !identical(sort(names(pins), method = "radix"), peers) ||
      !identical(policy$peer_pinset_sha256,
        digest::digest(
          .dsvert_dp_canonical_json(as.list(
            pins[order(names(pins), method = "radix")])),
          algo = "sha256", serialize = FALSE))) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM plan does not use the complete local pinset.",
      "invalid_pinned_consortium")
  }
  ids <- vapply(designated, function(peer) {
    .dsvert_formal_glm_phase18_peer_id(unname(pins[[peer]]))
  }, character(1L))
  order <- order(ids, method = "radix")
  list(
    garbler_peer_name = designated[[order[[1L]]]],
    garbler_peer_id = ids[[order[[1L]]]],
    evaluator_peer_name = designated[[order[[2L]]]],
    evaluator_peer_id = ids[[order[[2L]]]],
    role_selection = "lexicographic_pinned_cryptographic_peer_id_v1")
}

# Small exact rational implementation used only to reproduce the signed
# clamp/round lattice before values are secret-shared.  Signs remain separate
# because openssl::bignum is unsigned.
.dsvert_formal_glm_phase18_bn <- function(value) {
  openssl::bignum(as.character(value))
}

.dsvert_formal_glm_phase18_rat_new <- function(sign, numerator, denominator) {
  zero <- .dsvert_formal_glm_phase18_bn(0)
  one <- .dsvert_formal_glm_phase18_bn(1)
  if (denominator == zero) stop("zero denominator", call. = FALSE)
  if (numerator == zero) {
    return(structure(list(sign = 0L, numerator = zero, denominator = one),
                     class = "dsvert_formal_glm_phase18_rational"))
  }
  left <- numerator
  right <- denominator
  while (right != zero) {
    remainder <- left %% right
    left <- right
    right <- remainder
  }
  structure(list(
    sign = if (sign < 0L) -1L else 1L,
    numerator = numerator %/% left,
    denominator = denominator %/% left),
    class = "dsvert_formal_glm_phase18_rational")
}

.dsvert_formal_glm_phase18_rat <- function(value) {
  if (inherits(value, "dsvert_formal_glm_phase18_rational")) return(value)
  if (is.list(value) && setequal(names(value), c("numerator", "denominator"))) {
    numerator <- value$numerator
    denominator <- value$denominator
    if (!is.character(numerator) || length(numerator) != 1L ||
        !grepl("^[+-]?[0-9]+$", numerator) ||
        !is.character(denominator) || length(denominator) != 1L ||
        !grepl("^[1-9][0-9]*$", denominator)) {
      stop("invalid rational", call. = FALSE)
    }
    sign <- if (startsWith(numerator, "-")) -1L else 1L
    numerator <- sub("^[+-]", "", numerator)
    return(.dsvert_formal_glm_phase18_rat_new(
      sign, .dsvert_formal_glm_phase18_bn(numerator),
      .dsvert_formal_glm_phase18_bn(denominator)))
  }
  if (is.numeric(value)) {
    if (length(value) != 1L || !is.finite(value)) stop("invalid number")
    value <- sprintf("%.17g", value)
  }
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop("invalid decimal", call. = FALSE)
  }
  value <- trimws(value)
  fields <- regmatches(value, regexec(
    "^([+-]?)([0-9]+)(?:\\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?$",
    value, perl = TRUE))[[1L]]
  if (!length(fields) || nchar(value, type = "bytes") > 4096L) {
    stop("invalid decimal", call. = FALSE)
  }
  sign <- if (identical(fields[[2L]], "-")) -1L else 1L
  fraction <- fields[[4L]]
  if (is.na(fraction)) fraction <- ""
  exponent <- fields[[5L]]
  if (is.na(exponent) || !nzchar(exponent)) exponent <- "0"
  exponent <- suppressWarnings(as.integer(exponent))
  if (is.na(exponent) || abs(exponent) > 4096L) stop("invalid exponent")
  digits <- sub("^0+(?=[0-9])", "", paste0(fields[[3L]], fraction),
                perl = TRUE)
  numerator <- .dsvert_formal_glm_phase18_bn(digits)
  power <- exponent - nchar(fraction, type = "bytes")
  ten <- .dsvert_formal_glm_phase18_bn(10)
  denominator <- .dsvert_formal_glm_phase18_bn(1)
  if (power >= 0L) numerator <- numerator * (ten ^ power) else
    denominator <- ten ^ (-power)
  .dsvert_formal_glm_phase18_rat_new(sign, numerator, denominator)
}

.dsvert_formal_glm_phase18_rat_neg <- function(value) {
  value <- .dsvert_formal_glm_phase18_rat(value)
  .dsvert_formal_glm_phase18_rat_new(
    -value$sign, value$numerator, value$denominator)
}

.dsvert_formal_glm_phase18_rat_add <- function(left, right) {
  left <- .dsvert_formal_glm_phase18_rat(left)
  right <- .dsvert_formal_glm_phase18_rat(right)
  if (!left$sign) return(right)
  if (!right$sign) return(left)
  a <- left$numerator * right$denominator
  b <- right$numerator * left$denominator
  denominator <- left$denominator * right$denominator
  if (left$sign == right$sign) {
    return(.dsvert_formal_glm_phase18_rat_new(
      left$sign, a + b, denominator))
  }
  if (a == b) return(.dsvert_formal_glm_phase18_rat("0"))
  if (a > b) {
    .dsvert_formal_glm_phase18_rat_new(left$sign, a - b, denominator)
  } else {
    .dsvert_formal_glm_phase18_rat_new(right$sign, b - a, denominator)
  }
}

.dsvert_formal_glm_phase18_rat_sub <- function(left, right) {
  .dsvert_formal_glm_phase18_rat_add(
    left, .dsvert_formal_glm_phase18_rat_neg(right))
}

.dsvert_formal_glm_phase18_rat_mul <- function(left, right) {
  left <- .dsvert_formal_glm_phase18_rat(left)
  right <- .dsvert_formal_glm_phase18_rat(right)
  .dsvert_formal_glm_phase18_rat_new(
    left$sign * right$sign,
    left$numerator * right$numerator,
    left$denominator * right$denominator)
}

.dsvert_formal_glm_phase18_rat_div <- function(left, right) {
  left <- .dsvert_formal_glm_phase18_rat(left)
  right <- .dsvert_formal_glm_phase18_rat(right)
  if (!right$sign) stop("division by zero", call. = FALSE)
  .dsvert_formal_glm_phase18_rat_new(
    left$sign * right$sign,
    left$numerator * right$denominator,
    left$denominator * right$numerator)
}

.dsvert_formal_glm_phase18_rat_cmp <- function(left, right) {
  .dsvert_formal_glm_phase18_rat_sub(left, right)$sign
}

.dsvert_formal_glm_phase18_rat_clamp <- function(value, lower, upper) {
  if (.dsvert_formal_glm_phase18_rat_cmp(value, lower) < 0L) {
    return(.dsvert_formal_glm_phase18_rat(lower))
  }
  if (.dsvert_formal_glm_phase18_rat_cmp(value, upper) > 0L) {
    return(.dsvert_formal_glm_phase18_rat(upper))
  }
  .dsvert_formal_glm_phase18_rat(value)
}

.dsvert_formal_glm_phase18_rat_round <- function(value, bits) {
  value <- .dsvert_formal_glm_phase18_rat(value)
  bits <- .dsvert_formal_glm_phase18_integer(bits, "dyadic bits", 0, 256)
  scale <- .dsvert_formal_glm_phase18_bn(2) ^ as.integer(bits)
  scaled <- value$numerator * scale
  quotient <- scaled %/% value$denominator
  remainder <- scaled %% value$denominator
  twice <- remainder * .dsvert_formal_glm_phase18_bn(2)
  odd <- quotient %% .dsvert_formal_glm_phase18_bn(2) ==
    .dsvert_formal_glm_phase18_bn(1)
  if (twice > value$denominator ||
      (twice == value$denominator && isTRUE(odd))) {
    quotient <- quotient + .dsvert_formal_glm_phase18_bn(1)
  }
  .dsvert_formal_glm_phase18_rat_new(value$sign, quotient, scale)
}

.dsvert_formal_glm_phase18_rat_scaled_integer <- function(value, bits) {
  value <- .dsvert_formal_glm_phase18_rat(value)
  scale <- .dsvert_formal_glm_phase18_bn(2) ^ as.integer(bits)
  numerator <- value$numerator * scale
  if (numerator %% value$denominator != .dsvert_formal_glm_phase18_bn(0)) {
    stop("non-lattice rational", call. = FALSE)
  }
  magnitude <- as.character(numerator %/% value$denominator)
  if (value$sign < 0L && !identical(magnitude, "0")) paste0("-", magnitude)
  else magnitude
}

.dsvert_formal_glm_phase18_rat_pow <- function(value, exponent) {
  value <- .dsvert_formal_glm_phase18_rat(value)
  exponent <- as.integer(exponent)
  .dsvert_formal_glm_phase18_rat_new(
    if (value$sign < 0L && exponent %% 2L) -1L else 1L,
    value$numerator ^ exponent, value$denominator ^ exponent)
}

.dsvert_formal_glm_phase18_rat_log_interval <- function(value, bits) {
  value <- .dsvert_formal_glm_phase18_rat(value)
  if (value$sign <= 0L) stop("nonpositive log", call. = FALSE)
  one <- .dsvert_formal_glm_phase18_rat("1")
  two <- .dsvert_formal_glm_phase18_rat("2")
  mantissa <- value
  exponent <- 0L
  while (.dsvert_formal_glm_phase18_rat_cmp(mantissa, two) >= 0L) {
    mantissa <- .dsvert_formal_glm_phase18_rat_div(mantissa, two)
    exponent <- exponent + 1L
    if (exponent > 4096L) stop("log range", call. = FALSE)
  }
  while (.dsvert_formal_glm_phase18_rat_cmp(mantissa, one) < 0L) {
    mantissa <- .dsvert_formal_glm_phase18_rat_mul(mantissa, two)
    exponent <- exponent - 1L
    if (exponent < -4096L) stop("log range", call. = FALSE)
  }
  series <- function(argument) {
    z <- .dsvert_formal_glm_phase18_rat_div(
      .dsvert_formal_glm_phase18_rat_sub(argument, one),
      .dsvert_formal_glm_phase18_rat_add(argument, one))
    z2 <- .dsvert_formal_glm_phase18_rat_mul(z, z)
    power <- total <- z
    target <- .dsvert_formal_glm_phase18_rat_div(
      "1", .dsvert_formal_glm_phase18_rat_pow("2", bits + 4L))
    for (index in seq_len(8L * bits)) {
      power <- .dsvert_formal_glm_phase18_rat_mul(power, z2)
      denominator <- 2L * index + 1L
      addend <- .dsvert_formal_glm_phase18_rat_div(
        power, as.character(denominator))
      total <- .dsvert_formal_glm_phase18_rat_add(total, addend)
      remainder <- .dsvert_formal_glm_phase18_rat_div(
        .dsvert_formal_glm_phase18_rat_mul(
          .dsvert_formal_glm_phase18_rat_mul("2", power), z2),
        .dsvert_formal_glm_phase18_rat_mul(
          as.character(denominator + 2L),
          .dsvert_formal_glm_phase18_rat_sub(one, z2)))
      if (.dsvert_formal_glm_phase18_rat_cmp(remainder, target) <= 0L) {
        centre <- .dsvert_formal_glm_phase18_rat_mul("2", total)
        return(list(lower = centre, upper =
          .dsvert_formal_glm_phase18_rat_add(centre, remainder)))
      }
    }
    stop("log convergence", call. = FALSE)
  }
  log_mantissa <- series(mantissa)
  log_two <- series(two)
  if (exponent >= 0L) {
    lower <- .dsvert_formal_glm_phase18_rat_add(
      log_mantissa$lower,
      .dsvert_formal_glm_phase18_rat_mul(as.character(exponent),
                                         log_two$lower))
    upper <- .dsvert_formal_glm_phase18_rat_add(
      log_mantissa$upper,
      .dsvert_formal_glm_phase18_rat_mul(as.character(exponent),
                                         log_two$upper))
  } else {
    lower <- .dsvert_formal_glm_phase18_rat_sub(
      log_mantissa$lower,
      .dsvert_formal_glm_phase18_rat_mul(as.character(-exponent),
                                         log_two$upper))
    upper <- .dsvert_formal_glm_phase18_rat_sub(
      log_mantissa$upper,
      .dsvert_formal_glm_phase18_rat_mul(as.character(-exponent),
                                         log_two$lower))
  }
  list(lower = lower, upper = upper)
}

.dsvert_formal_glm_phase18_quantize <- function(
    value, lower, upper, source_bits, common_bits) {
  rounded <- .dsvert_formal_glm_phase18_rat_round(
    .dsvert_formal_glm_phase18_rat_clamp(value, lower, upper), source_bits)
  .dsvert_formal_glm_phase18_rat_scaled_integer(rounded, common_bits)
}

.dsvert_formal_glm_phase18_signed_bn <- function(value) {
  value <- .dsvert_formal_glm_phase18_scalar(
    value, "signed lattice integer", pattern = "^-?(0|[1-9][0-9]*)$")
  negative <- startsWith(value, "-")
  magnitude <- .dsvert_formal_glm_phase18_bn(sub("^-", "", value))
  list(sign = if (magnitude == .dsvert_formal_glm_phase18_bn(0)) 0L else
    if (negative) -1L else 1L, magnitude = magnitude)
}

.dsvert_formal_glm_phase18_signed_cmp <- function(left, right) {
  left <- .dsvert_formal_glm_phase18_signed_bn(left)
  right <- .dsvert_formal_glm_phase18_signed_bn(right)
  if (left$sign != right$sign) return(sign(left$sign - right$sign))
  if (!left$sign) return(0L)
  comparison <- if (left$magnitude == right$magnitude) 0L else
    if (left$magnitude > right$magnitude) 1L else -1L
  as.integer(comparison * left$sign)
}

.dsvert_formal_glm_phase18_go_object_json <- function(value) {
  .dsvert_formal_glm_phase18_json(value)
}

.dsvert_formal_glm_phase18_plan_hash <- function(plan_json) {
  .dsvert_formal_glm_phase18_sha256(paste0(
    .DSVERT_FORMAL_GLM_PHASE18_PLAN_DOMAIN, plan_json))
}

.dsvert_formal_glm_phase18_kernel_hash <- function(kernel) {
  .dsvert_formal_glm_phase18_sha256(paste0(
    .DSVERT_FORMAL_GLM_PHASE18_KERNEL_DOMAIN,
    .dsvert_formal_glm_phase18_go_object_json(kernel)))
}

.dsvert_formal_glm_phase18_plan_approval_message <- function(plan_hash) {
  plan_hash <- .dsvert_formal_glm_phase18_scalar(
    plan_hash, "plan hash", pattern = "^[0-9a-f]{64}$", maximum_bytes = 64L)
  octets <- substring(plan_hash, seq.int(1L, 63L, by = 2L),
                      seq.int(2L, 64L, by = 2L))
  digest <- as.raw(strtoi(octets, base = 16L))
  c(.dsvert_formal_glm_phase18_append(
      raw(), .DSVERT_FORMAL_GLM_PHASE18_PLAN_APPROVAL_DOMAIN), digest)
}

.dsvert_formal_glm_phase18_artifact_contract <- function(artifact, plan) {
  required <- c(
    "version", "compiler_version", "theorem_version", "authority",
    "estimand", "adjacency", "optimizer", "link_surrogate", "numeric",
    "theorem_certificate", "privacy", "execution_requirements",
    "transcript")
  if (!is.list(artifact) || !setequal(names(artifact), required) ||
      !identical(artifact$version, "dsvert-formal-glm-schema-v1")) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM scientific artifact is invalid.",
      "artifact_plan_mismatch")
  }
  kernel <- plan$kernel
  estimand <- artifact$estimand
  coefficients <- estimand$coefficients
  coefficient_count <- .dsvert_formal_glm_phase18_integer(
    kernel$coefficient_count, "coefficient count", 1, 4)
  if (!is.list(coefficients) || length(coefficients) != coefficient_count ||
      !identical(estimand$family, kernel$family) ||
      !kernel$family %in% c("binomial", "poisson") ||
      !identical(estimand$missingness, "complete_tuple_zero_weight") ||
      !identical(kernel$missingness, "complete_tuple_zero_weight") ||
      !identical(kernel$patient_collapse,
                 "one_aligned_record_duplicates_zero_weight_v1") ||
      !identical(artifact$optimizer$algorithm,
                 "fixed_iteration_projected_full_gradient_v1") ||
      !identical(artifact$optimizer$data_dependent_branching, FALSE) ||
      !identical(artifact$privacy$mechanism,
                 "joint_discrete_gaussian_one_global_draw") ||
      !identical(artifact$privacy$allocation,
                 "one_stacked_capsule_vector")) {
    .dsvert_formal_glm_phase18_abort(
      "The artifact and exact-GC scientific contracts differ.",
      "artifact_plan_mismatch")
  }
  collapse <- estimand$patient_collapse
  if (!is.list(collapse) ||
      !identical(collapse$unit, "aligned_patient") ||
      !identical(collapse$repeated_records, "reject_duplicates") ||
      !identical(collapse$row_order_invariant, TRUE) ||
      !identical(as.numeric(collapse$max_records_per_unit), 1) ||
      !identical(collapse$conflict_policy, "zero_weight")) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM patient-collapse contract is not certified.",
      "artifact_plan_mismatch")
  }
  common_bits <- .dsvert_formal_glm_phase18_integer(
    kernel$frac_bits, "common fraction bits", 8, 256)
  if (!identical(as.numeric(artifact$numeric$working_fraction_bits),
                 common_bits) ||
      as.numeric(artifact$numeric$x_fraction_bits) > common_bits ||
      as.numeric(artifact$numeric$offset_fraction_bits) > common_bits) {
    .dsvert_formal_glm_phase18_abort(
      "The artifact cannot be embedded exactly in the Go input lattice.",
      "artifact_plan_mismatch")
  }
  list(
    artifact = artifact, estimand = estimand, coefficients = coefficients,
    common_bits = as.integer(common_bits),
    x_bits = as.integer(artifact$numeric$x_fraction_bits),
    offset_bits = as.integer(artifact$numeric$offset_fraction_bits),
    reference_bits = as.integer(artifact$numeric$reference_precision_bits))
}

.dsvert_formal_glm_phase18_expected_owners <- function(
    contract, peers) {
  estimand <- contract$estimand
  constant_owner <- peers[[1L]]
  column_owner <- function(column) {
    if (is.null(column) || !is.character(column) || length(column) != 1L ||
        is.null(estimand$column_registry[[column]]$owner)) {
      .dsvert_formal_glm_phase18_abort(
        "A formal-GLM input coordinate has no signed owner.",
        "artifact_plan_mismatch")
    }
    estimand$column_registry[[column]]$owner
  }
  weight_owner <- if (identical(estimand$weights$mode, "unit")) {
    constant_owner
  } else column_owner(estimand$weights$column)
  design_owners <- vapply(contract$coefficients, function(coefficient) {
    term <- coefficient$term
    if (identical(term$kind, "intercept")) constant_owner else {
      if (!is.character(term$owner) || length(term$owner) != 1L) {
        .dsvert_formal_glm_phase18_abort(
          "A formal-GLM design coordinate has no signed owner.",
          "artifact_plan_mismatch")
      }
      term$owner
    }
  }, character(1L))
  outcome_owner <- column_owner(estimand$response)
  offset_owner <- if (identical(estimand$offset$mode, "none")) {
    constant_owner
  } else column_owner(estimand$offset$column)
  owners <- c(weight_owner, design_owners, outcome_owner, offset_owner)
  if (any(!owners %in% peers)) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM coordinate owner is outside the pinset.",
      "artifact_plan_mismatch")
  }
  owners
}

.dsvert_formal_glm_phase18_validate_lattice <- function(contract, plan) {
  kernel <- plan$kernel
  common_bits <- contract$common_bits
  scaled <- function(value) {
    tryCatch(.dsvert_formal_glm_phase18_rat_scaled_integer(value, common_bits),
             error = function(error) NA_character_)
  }
  x_lower <- vapply(contract$coefficients, function(coefficient) {
    scaled(coefficient$term$lower)
  }, character(1L))
  x_upper <- vapply(contract$coefficients, function(coefficient) {
    scaled(coefficient$term$upper)
  }, character(1L))
  kernel_lower <- unname(as.character(unlist(kernel$x_lower,
                                               use.names = FALSE)))
  kernel_upper <- unname(as.character(unlist(kernel$x_upper,
                                               use.names = FALSE)))
  registry <- contract$estimand$column_registry
  response <- registry[[contract$estimand$response]]
  outcome_upper <- if (identical(kernel$family, "binomial")) {
    scaled(list(numerator = "1", denominator = "1"))
  } else scaled(response$upper)
  weight_upper <- scaled(contract$estimand$weights$maximum_patient_weight)
  offset_lower <- scaled(contract$estimand$offset$lower)
  offset_upper <- scaled(contract$estimand$offset$upper)
  if (anyNA(c(x_lower, x_upper, outcome_upper, weight_upper,
              offset_lower, offset_upper)) ||
      !identical(kernel_lower, x_lower) ||
      !identical(kernel_upper, x_upper) ||
      !identical(kernel$weight_upper, weight_upper) ||
      !identical(kernel$outcome_upper, outcome_upper) ||
      !identical(kernel$offset_lower, offset_lower) ||
      !identical(kernel$offset_upper, offset_upper)) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM materializer lattice differs from the Go plan.",
      "artifact_plan_mismatch")
  }
  invisible(TRUE)
}

.dsvert_formal_glm_phase18_manifest_binding <- function(
    policy, manifest_json, manifest) {
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  list(
    manifest = manifest,
    validated = validated,
    manifest_sha256 = .dsvert_formal_glm_phase18_sha256(manifest_json),
    capsule_id = validated$identity$capsule_id,
    workload_sha256 = .dsvert_joint_dp_hash(manifest$workload),
    schema_manifest_sha256 =
      manifest$workload$schema_attestation$manifest_sha256,
    source_context_sha256 =
      manifest$workload$capsule_mechanism$source_context_hash,
    snapshot_sha256 = .dsvert_joint_dp_hash(manifest$logical_snapshot))
}

.dsvert_formal_glm_phase18_pre_authorize <- function(
    manifest_json, artifact_json, plan_json, plan_approvals,
    .policy = NULL, .secret = NULL,
    .verifier = .dsvert_relay_verify_message) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  .dsvert_dp_capsule_manifest_require_built(
    .policy, manifest_json, .secret)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  manifest_binding <- .dsvert_formal_glm_phase18_manifest_binding(
    .policy, manifest_json, manifest)
  artifact_parsed <- .dsvert_formal_glm_phase18_decode_json(
    artifact_json, "scientific artifact")
  plan_parsed <- .dsvert_formal_glm_phase18_decode_json(
    plan_json, "Phase-1.5 plan")
  plan <- plan_parsed$value
  required_plan <- c(
    "version", "run_id", "kernel", "total_capacity", "block_capacity",
    "total_blocks", "iterations", "coordinate_owners", "ring_bits",
    "container_bits", "maximum_magnitude", "rho_total_upper",
    "schedule_steps", "block_cost", "finalize_cost", "backend_selection",
    "transcript_shape", "crash_recovery", "output", "production_ready")
  if (!setequal(names(plan), required_plan) ||
      !identical(plan$version, "dsvert-formal-glm-phase15-plan-v1") ||
      !identical(plan$kernel$version,
                 "dsvert-formal-glm-phase1-policy-v1") ||
      !identical(plan$backend_selection,
                 "streamed_exact_gc_ot_no_runtime_fallback_v1") ||
      !identical(plan$output,
                 "sealed_coefficient_additive_shares_only_v1") ||
      !identical(plan$production_ready, FALSE)) {
    .dsvert_formal_glm_phase18_abort(
      "The pre-execution formal-GLM plan type is invalid.",
      "invalid_pre_execution_plan")
  }
  plan_hash <- .dsvert_formal_glm_phase18_plan_hash(plan_json)
  artifact_hash <- .dsvert_formal_glm_phase18_sha256(artifact_json)
  kernel_hash <- .dsvert_formal_glm_phase18_kernel_hash(plan$kernel)
  peers <- .dsvert_formal_glm_phase18_names(
    plan$kernel$custodian_peers, "custodian set", 2L)
  designated <- .dsvert_formal_glm_phase18_names(
    plan$kernel$compute_peers, "compute-peer set", 2L)
  if (length(designated) != 2L ||
      !identical(peers, sort(peers, method = "radix")) ||
      !identical(designated, sort(designated, method = "radix")) ||
      !identical(peers, sort(names(.policy$peer_pinset), method = "radix")) ||
      !identical(designated,
                 sort(.policy$designated_noise_peers, method = "radix")) ||
      !identical(plan$kernel$pinset_sha256, .policy$peer_pinset_sha256)) {
    .dsvert_formal_glm_phase18_abort(
      "The pre-execution plan changed K, the pinset or designated peers.",
      "invalid_pinned_consortium")
  }
  total_capacity <- .dsvert_formal_glm_phase18_integer(
    plan$total_capacity, "total capacity", 1, 1e8)
  block_capacity <- .dsvert_formal_glm_phase18_integer(
    plan$block_capacity, "block capacity", 1, 8)
  total_blocks <- .dsvert_formal_glm_phase18_integer(
    plan$total_blocks, "block count", 1, 1e8)
  iterations <- .dsvert_formal_glm_phase18_integer(
    plan$iterations, "iteration count", 1, 64)
  ring_bits <- .dsvert_formal_glm_phase18_integer(
    plan$ring_bits, "ring bits", 128, 4096)
  container_bits <- 64
  while (container_bits < ring_bits) container_bits <- container_bits * 2
  if (!identical(as.numeric(plan$container_bits), container_bits) ||
      !identical(as.numeric(plan$kernel$capacity), block_capacity) ||
      !identical(as.numeric(plan$kernel$iterations), 1) ||
      !identical(total_blocks, ceiling(total_capacity / block_capacity)) ||
      !identical(as.numeric(plan$schedule_steps),
                 iterations * (total_blocks + 1)) ||
      !identical(total_capacity, as.numeric(.policy$unit_capacity))) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM public fixed-shape schedule is inconsistent.",
      "invalid_pre_execution_plan")
  }
  contract <- .dsvert_formal_glm_phase18_artifact_contract(
    artifact_parsed$value, plan)
  owners <- .dsvert_formal_glm_phase18_expected_owners(contract, peers)
  supplied_owners <- unname(as.character(unlist(
    plan$coordinate_owners, use.names = FALSE)))
  if (!identical(supplied_owners, owners) ||
      !identical(as.numeric(plan$kernel$coefficient_count) + 3,
                 as.numeric(length(owners))) ||
      !identical(as.numeric(contract$artifact$optimizer$iterations),
                 iterations) ||
      !identical(plan$kernel$artifact_sha256, artifact_hash) ||
      !identical(plan$kernel$capsule_sha256,
                 manifest_binding$capsule_id) ||
      !identical(plan$kernel$snapshot_sha256,
                 manifest_binding$snapshot_sha256)) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM plan is not bound to its server-authoritative artifact and capsule.",
      "artifact_plan_mismatch")
  }
  policy_adjacency <- if (identical(plan$kernel$adjacency, "add_remove")) {
    "add_remove_patient"
  } else if (identical(plan$kernel$adjacency, "replace_one")) {
    "replace_one_fixed_cohort"
  } else NA_character_
  if (is.na(policy_adjacency) || !identical(.policy$adjacency,
                                            policy_adjacency)) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM adjacency differs from the custodian policy.",
      "artifact_plan_mismatch")
  }
  .dsvert_formal_glm_phase18_validate_lattice(contract, plan)
  roles <- .dsvert_formal_glm_phase18_roles(.policy, peers, designated)
  .dsvert_formal_glm_phase18_verify_signature_set(
    .dsvert_formal_glm_phase18_plan_approval_message(plan_hash),
    plan_approvals, peers, .policy, .verifier, "Phase-1.5 plan approvals")
  pre <- .dsvert_dp_canonical_query_value(c(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_PRE_VERSION,
    phase = "pre_execution_materialization_authorized",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = manifest_binding$capsule_id,
    manifest_sha256 = manifest_binding$manifest_sha256,
    schema_manifest_sha256 = manifest_binding$schema_manifest_sha256,
    workload_sha256 = manifest_binding$workload_sha256,
    source_context_sha256 = manifest_binding$source_context_sha256,
    snapshot_sha256 = manifest_binding$snapshot_sha256,
    artifact_sha256 = artifact_hash,
    plan_sha256 = plan_hash,
    kernel_spec_sha256 = kernel_hash,
    run_id = plan$run_id,
    pinset_sha256 = .policy$peer_pinset_sha256,
    custodian_peers = as.list(peers), custodian_count = length(peers),
    designated_compute_peers = as.list(designated)), roles, list(
    total_capacity = total_capacity,
    block_capacity = block_capacity,
    total_blocks = total_blocks,
    coordinate_count = length(owners),
    coordinate_owners = as.list(owners),
    family = plan$kernel$family,
    adjacency = plan$kernel$adjacency,
    capacity_semantics = .DSVERT_FORMAL_GLM_PHASE18_CAPACITY_SEMANTICS,
    adjacency_semantics = .DSVERT_FORMAL_GLM_PHASE18_ADJACENCY_SEMANTICS,
    patient_contribution = .DSVERT_FORMAL_GLM_PHASE18_PATIENT_CONTRIBUTION,
    missingness = plan$kernel$missingness,
    patient_collapse = plan$kernel$patient_collapse,
    frac_bits = contract$common_bits,
    ring_bits = ring_bits,
    container_bits = container_bits,
    record_bytes = container_bits / 8,
    input_layout = plan$kernel$input_layout,
    input_sharing = plan$kernel$input_sharing,
    validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
    alignment_sharing = .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING,
    release_token = "none_pre_execution",
    worker_token = "none_pre_execution",
    openings_performed = 0L,
    production_ready = FALSE)))
  pre_hash <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/pre-execution/v1|", pre)
  structure(list(
    pre = c(pre, list(pre_execution_sha256 = pre_hash)),
    pre_execution_sha256 = pre_hash,
    policy = .policy,
    alignment_secret = digest::hmac(
      key = .secret,
      object = charToRaw(.DSVERT_FORMAL_GLM_PHASE18_PRIVATE_LANE_DOMAIN),
      algo = "sha256", serialize = FALSE, raw = TRUE),
    manifest = manifest,
    artifact = contract, plan = plan, plan_json = plan_json,
    coordinate_owners = owners, peers = peers, designated = designated),
    class = "dsvert_formal_glm_phase18_pre_authorization")
}

.dsvert_formal_glm_phase18_pre_validate <- function(authorization) {
  if (!inherits(authorization,
                "dsvert_formal_glm_phase18_pre_authorization") ||
      !is.list(authorization$pre) ||
      !identical(authorization$pre$version,
                 .DSVERT_FORMAL_GLM_PHASE18_PRE_VERSION) ||
      !identical(authorization$pre$phase,
                 "pre_execution_materialization_authorized") ||
      !identical(authorization$pre$purpose,
                 .DSVERT_FORMAL_GLM_PHASE18_PURPOSE) ||
      !identical(authorization$pre$validity_sharing,
                 .DSVERT_FORMAL_GLM_PHASE18_VALIDITY) ||
      !identical(authorization$pre$alignment_sharing,
                 .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING) ||
      !identical(authorization$pre$release_token, "none_pre_execution") ||
      !identical(authorization$pre$worker_token, "none_pre_execution") ||
      !identical(as.numeric(authorization$pre$openings_performed), 0) ||
      !identical(authorization$pre$production_ready, FALSE)) {
    .dsvert_formal_glm_phase18_abort(
      "A post-execution object cannot substitute for pre-execution authorization.",
      "phase_type_confusion")
  }
  unsigned <- authorization$pre[
    setdiff(names(authorization$pre), "pre_execution_sha256")]
  expected <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/pre-execution/v1|", unsigned)
  if (!identical(authorization$pre_execution_sha256, expected) ||
      !identical(authorization$pre$pre_execution_sha256, expected)) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM pre-execution authorization was modified.",
      "pre_execution_binding_tampered")
  }
  invisible(authorization)
}

.dsvert_formal_glm_phase18_ticket_unsigned <- function(
    authorization, recipient_name, transport_pk) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  pre <- authorization$pre
  recipient_name <- .dsvert_formal_glm_phase18_scalar(
    recipient_name, "ticket recipient", maximum_bytes = 128L)
  if (!recipient_name %in% authorization$designated) {
    .dsvert_formal_glm_phase18_abort(
      "Only a designated pinned compute peer can mint this ticket.",
      "invalid_recipient_ticket")
  }
  transport_pk <- base64_to_base64url(
    .dsvert_normalize_crypto_b64(
      transport_pk, 32L, "formal-GLM transport key"))
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_TICKET_VERSION,
    phase = "pre_execution_recipient_key_committed",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = pre$capsule_id,
    manifest_sha256 = pre$manifest_sha256,
    artifact_sha256 = pre$artifact_sha256,
    plan_sha256 = pre$plan_sha256,
    kernel_spec_sha256 = pre$kernel_spec_sha256,
    run_id = pre$run_id,
    source_context_sha256 = pre$source_context_sha256,
    snapshot_sha256 = pre$snapshot_sha256,
    pinset_sha256 = pre$pinset_sha256,
    recipient_name = recipient_name,
    recipient_identity_pk = unname(
      authorization$policy$peer_pinset[[recipient_name]]),
    recipient_peer_id = .dsvert_formal_glm_phase18_peer_id(unname(
      authorization$policy$peer_pinset[[recipient_name]])),
    transport_key_id = .dsvert_formal_glm_phase18_hash_object(
      "dsVert/formal-glm/phase18/transport-key/v1|", list(
        pre_execution_sha256 = authorization$pre_execution_sha256,
        recipient_name = recipient_name, transport_pk = transport_pk)),
    transport_pk = transport_pk,
    custodian_peers = pre$custodian_peers,
    designated_compute_peers = pre$designated_compute_peers,
    total_capacity = pre$total_capacity,
    block_capacity = pre$block_capacity,
    total_blocks = pre$total_blocks,
    coordinate_count = pre$coordinate_count,
    ring_bits = pre$ring_bits,
    record_bytes = pre$record_bytes,
    validity_sharing = pre$validity_sharing,
    alignment_sharing = pre$alignment_sharing,
    release_token = "none_pre_execution",
    persistent = TRUE,
    openings_performed = 0L,
    production_ready = FALSE))
}

.dsvert_formal_glm_phase18_ticket_validate <- function(
    ticket_json, authorization,
    verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  parsed <- .dsvert_formal_glm_phase18_decode_json(
    ticket_json, "recipient ticket", 128L * 1024L)
  ticket <- parsed$value
  required <- c(
    "version", "phase", "purpose", "capsule_id", "manifest_sha256",
    "artifact_sha256", "plan_sha256", "kernel_spec_sha256", "run_id",
    "source_context_sha256", "snapshot_sha256", "pinset_sha256",
    "recipient_name", "recipient_identity_pk", "recipient_peer_id",
    "transport_key_id", "transport_pk", "custodian_peers",
    "designated_compute_peers", "total_capacity", "block_capacity",
    "total_blocks", "coordinate_count", "ring_bits", "record_bytes",
    "validity_sharing", "alignment_sharing", "release_token", "persistent",
    "openings_performed", "production_ready", "signature")
  recipient <- ticket$recipient_name
  if (!is.list(ticket) || !setequal(names(ticket), required) ||
      !is.character(recipient) || length(recipient) != 1L ||
      !recipient %in% authorization$designated) {
    .dsvert_formal_glm_phase18_abort(
      "Invalid formal-GLM recipient ticket.", "invalid_recipient_ticket")
  }
  unsigned <- ticket[setdiff(names(ticket), "signature")]
  expected <- .dsvert_formal_glm_phase18_ticket_unsigned(
    authorization, recipient, ticket$transport_pk)
  if (!identical(.dsvert_dp_canonical_json(unsigned),
                 .dsvert_dp_canonical_json(expected)) ||
      !isTRUE(tryCatch(verifier(
        .dsvert_formal_glm_phase18_domain_message(
          .DSVERT_FORMAL_GLM_PHASE18_TICKET_DOMAIN,
          .dsvert_dp_canonical_json(expected)),
        unname(authorization$policy$peer_pinset[[recipient]]),
        .dsvert_formal_glm_phase18_signature(ticket$signature)),
        error = function(error) FALSE))) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM recipient ticket failed its purpose/pin binding.",
      "invalid_recipient_ticket")
  }
  list(
    value = ticket, json = ticket_json,
    sha256 = .dsvert_formal_glm_phase18_hash_object(
      "dsVert/formal-glm/phase18/signed-ticket/v1|", ticket),
    transport_pk = ticket$transport_pk)
}

.dsvert_formal_glm_phase18_resolved_snapshots <- function(
    authorization, snapshots) {
  policy <- authorization$policy
  if (is.null(snapshots)) {
    secret <- .dsvert_dp_secret()
    snapshots <- lapply(names(policy$datasets), function(data_name) {
      .dsvert_dp_resolve_snapshot(
        policy, data_name, parent.frame(), secret)
    })
    names(snapshots) <- names(policy$datasets)
  }
  .dsvert_dp_capsule_resolved_snapshots(policy, snapshots)
}

.dsvert_formal_glm_phase18_local_mapping <- function(authorization) {
  mapping <- .dsvert_dp_capsule_manifest_local_mapping(
    authorization$policy)$datasets
  if (!is.list(mapping) || !length(mapping)) {
    .dsvert_formal_glm_phase18_abort(
      "The local formal-GLM artifact has no server-owned dataset mapping.",
      "local_schema_mismatch")
  }
  mapping
}

.dsvert_formal_glm_phase18_column_dataset <- function(mapping, column) {
  candidates <- names(mapping)[vapply(mapping, function(columns) {
    column %in% columns
  }, logical(1L))]
  if (length(candidates) != 1L) {
    .dsvert_formal_glm_phase18_abort(
      "A local formal-GLM column is absent or ambiguously mapped.",
      "local_schema_mismatch")
  }
  candidates[[1L]]
}

.dsvert_formal_glm_phase18_patient_slots <- function(
    authorization, snapshots, required_datasets) {
  policy <- authorization$policy
  capacity <- as.integer(authorization$pre$total_capacity)
  required_datasets <- sort(unique(required_datasets), method = "radix")
  if (!length(required_datasets)) {
    required_datasets <- sort(names(snapshots), method = "radix")[[1L]]
  }
  primary <- required_datasets[[1L]]
  extract <- function(data_name) {
    data <- snapshots[[data_name]]$data
    column <- policy$patient_column
    if (!column %in% names(data) || !is.atomic(data[[column]])) {
      .dsvert_formal_glm_phase18_abort(
        "A protected formal-GLM snapshot lacks its patient key.",
        "protected_snapshot_outside_admission")
    }
    ids <- tryCatch(.dsvert_canonical_label_values(
      data[[column]], "formal-GLM patient identifiers",
      allow_na = FALSE, allow_blank = FALSE),
      error = function(error) NULL)
    if (!is.character(ids) || length(ids) != nrow(data) || anyNA(ids) ||
        any(!nzchar(ids)) ||
        nrow(data) > as.numeric(policy$unit_capacity) *
          as.numeric(policy$max_records_per_unit)) {
      .dsvert_formal_glm_phase18_abort(
        "The protected formal-GLM snapshot exceeds its fixed admission.",
        "protected_snapshot_outside_admission")
    }
    enc2utf8(ids)
  }
  ids_by_dataset <- lapply(required_datasets, extract)
  names(ids_by_dataset) <- required_datasets
  unit_ids <- sort(unique(ids_by_dataset[[primary]]), method = "radix")
  if (length(unit_ids) > capacity) {
    .dsvert_formal_glm_phase18_abort(
      "The protected formal-GLM snapshot exceeds its public patient capacity.",
      "protected_snapshot_outside_admission")
  }
  rows <- vector("list", length(required_datasets))
  names(rows) <- required_datasets
  dataset_consistent <- rep(TRUE, capacity)
  for (data_name in required_datasets) {
    ids <- ids_by_dataset[[data_name]]
    grouped <- split(seq_along(ids), factor(
      ids, levels = unit_ids, exclude = NULL))
    record <- rep(NA_integer_, capacity)
    count <- integer(capacity)
    if (length(unit_ids)) {
      count[seq_along(unit_ids)] <- lengths(grouped)
      unique_record <- lengths(grouped) == 1L
      record[which(unique_record)] <- vapply(
        grouped[unique_record], `[[`, integer(1L), 1L)
      same_set <- setequal(unique(ids), unit_ids)
      if (!same_set) dataset_consistent[] <- FALSE
    }
    rows[[data_name]] <- record
    dataset_consistent <- dataset_consistent & count == 1L
  }
  present <- rep(FALSE, capacity)
  if (length(unit_ids)) present[seq_along(unit_ids)] <- TRUE
  tokens <- vapply(required_datasets, function(data_name) {
    manifest <- attr(snapshots[[data_name]]$data,
                     .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
    if (is.list(manifest) && is.character(manifest$token) &&
        length(manifest$token) == 1L) manifest$token else NA_character_
  }, character(1L))
  token_consistent <- !anyNA(tokens) && length(unique(tokens)) == 1L
  consensus <- if (token_consistent) {
    digest::hmac(
      key = tokens[[1L]], object = serialize(list(
        domain = "dsVert/formal-glm/phase18/private-slot-consensus/v1",
        capsule_id = authorization$pre$capsule_id,
        plan_sha256 = authorization$pre$plan_sha256,
        unit_ids = unit_ids), NULL, version = 3L),
      algo = "sha256", serialize = FALSE)
  } else {
    # This fallback is local-integrity-only. Production policy normally
    # requires the PSI token; the encrypted header marks that cross-peer
    # consensus is unavailable so Phase 1.9 must reject it.
    .dsvert_dp_hmac(.dsvert_dp_secret(), list(
      "formal-glm-phase18-local-slot-binding", authorization$pre$plan_sha256,
      unit_ids))
  }
  list(
    unit_ids = unit_ids, present = present,
    locally_unique = present & dataset_consistent,
    row_by_dataset = rows,
    consensus_sha256 = consensus,
    consensus_status = if (token_consistent) {
      "shared_psi_token_private_consensus_v1"
    } else "local_only_phase19_must_reject_v1",
    consensus_shape_code = if (token_consistent) {
      .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_ACCEPTED
    } else .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_REJECTED)
}

.dsvert_formal_glm_phase18_raw_value <- function(
    snapshots, slots, data_name, column, slot) {
  row <- slots$row_by_dataset[[data_name]][[slot]]
  if (is.na(row) || !column %in% names(snapshots[[data_name]]$data)) {
    return(NULL)
  }
  value <- snapshots[[data_name]]$data[[column]][row]
  if (length(value) != 1L || is.object(value) && !is.factor(value)) return(NULL)
  value
}

.dsvert_formal_glm_phase18_numeric_try <- function(value) {
  if (is.null(value) || is.factor(value) || is.object(value) ||
      !is.atomic(value) || length(value) != 1L || is.na(value)) return(NULL)
  tryCatch(.dsvert_formal_glm_phase18_rat(value),
           error = function(error) NULL)
}

.dsvert_formal_glm_phase18_materialize_block_values <- function(
    authorization, snapshots, block_index) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  block_index <- .dsvert_formal_glm_phase18_integer(
    block_index, "block index", 0, authorization$pre$total_blocks - 1)
  mapping <- .dsvert_formal_glm_phase18_local_mapping(authorization)
  peer <- authorization$policy$peer_name
  contract <- authorization$artifact
  estimand <- contract$estimand
  coefficients <- contract$coefficients
  owners <- authorization$coordinate_owners
  local_columns <- names(estimand$column_registry)[vapply(
    estimand$column_registry, function(column) identical(column$owner, peer),
    logical(1L))]
  required_columns <- unique(c(
    estimand$response, unlist(estimand$predictors, use.names = FALSE),
    estimand$weights$column, estimand$offset$column))
  required_columns <- required_columns[!vapply(
    required_columns, is.null, logical(1L))]
  required_columns <- intersect(as.character(required_columns), local_columns)
  column_datasets <- if (length(required_columns)) {
    stats::setNames(vapply(required_columns, function(column) {
      .dsvert_formal_glm_phase18_column_dataset(mapping, column)
    }, character(1L)), required_columns)
  } else character()
  required_datasets <- unique(unname(column_datasets))
  if (!length(required_datasets)) {
    required_datasets <- sort(names(snapshots), method = "radix")[[1L]]
  }
  slots <- .dsvert_formal_glm_phase18_patient_slots(
    authorization, snapshots, required_datasets)
  block_capacity <- as.integer(authorization$pre$block_capacity)
  coordinate_count <- as.integer(authorization$pre$coordinate_count)
  start <- as.integer(block_index * block_capacity + 1L)
  global_slots <- seq.int(start, length.out = block_capacity)
  values <- rep("0", block_capacity * coordinate_count)
  validity <- rep(FALSE, block_capacity)
  scale <- as.character(
    .dsvert_formal_glm_phase18_bn(2) ^ contract$common_bits)
  local_owned <- owners == peer
  raw_for <- function(column, slot) {
    data_name <- unname(column_datasets[[column]])
    if (is.null(data_name) || is.na(data_name)) return(NULL)
    .dsvert_formal_glm_phase18_raw_value(
      snapshots, slots, data_name, column, slot)
  }
  for (physical in seq_len(block_capacity)) {
    slot <- global_slots[[physical]]
    if (slot > authorization$pre$total_capacity ||
        !isTRUE(slots$locally_unique[[slot]])) next
    row_valid <- TRUE
    row <- rep("0", coordinate_count)

    if (local_owned[[1L]]) {
      if (identical(estimand$weights$mode, "unit")) {
        row[[1L]] <- scale
      } else {
        raw <- .dsvert_formal_glm_phase18_numeric_try(
          raw_for(estimand$weights$column, slot))
        if (is.null(raw)) row_valid <- FALSE else {
          row[[1L]] <- .dsvert_formal_glm_phase18_quantize(
            raw, "0", estimand$weights$source_maximum_patient_weight,
            contract$x_bits, contract$common_bits)
        }
      }
    }

    for (index in seq_along(coefficients)) {
      coordinate <- index + 1L
      if (!local_owned[[coordinate]]) next
      term <- coefficients[[index]]$term
      if (identical(term$kind, "intercept")) {
        row[[coordinate]] <- scale
      } else if (identical(term$kind, "numeric")) {
        raw <- .dsvert_formal_glm_phase18_numeric_try(
          raw_for(term$source_column, slot))
        if (is.null(raw)) row_valid <- FALSE else {
          row[[coordinate]] <- .dsvert_formal_glm_phase18_quantize(
            raw, term$clipping_lower, term$clipping_upper,
            contract$x_bits, contract$common_bits)
        }
      } else if (identical(term$kind, "categorical_indicator")) {
        raw <- raw_for(term$source_column, slot)
        registered <- unlist(
          estimand$column_registry[[term$source_column]]$levels,
          use.names = FALSE)
        label <- if (is.null(raw) || length(raw) != 1L || is.na(raw)) {
          NA_character_
        } else enc2utf8(as.character(raw))
        if (is.na(label) || !label %in% registered) row_valid <- FALSE else
          row[[coordinate]] <- if (identical(label, term$source_level)) {
            scale
          } else "0"
      } else {
        row_valid <- FALSE
      }
    }

    outcome_coordinate <- length(coefficients) + 2L
    if (local_owned[[outcome_coordinate]]) {
      raw <- .dsvert_formal_glm_phase18_numeric_try(
        raw_for(estimand$response, slot))
      if (is.null(raw)) row_valid <- FALSE else if (
          identical(estimand$family, "binomial")) {
        if (.dsvert_formal_glm_phase18_rat_cmp(raw, "0") == 0L) {
          row[[outcome_coordinate]] <- "0"
        } else if (.dsvert_formal_glm_phase18_rat_cmp(raw, "1") == 0L) {
          row[[outcome_coordinate]] <- scale
        } else row_valid <- FALSE
      } else {
        rounded <- .dsvert_formal_glm_phase18_rat_round(raw, 0L)
        if (.dsvert_formal_glm_phase18_rat_cmp(raw, rounded) != 0L) {
          row_valid <- FALSE
        } else {
          upper <- estimand$column_registry[[estimand$response]]$upper
          row[[outcome_coordinate]] <-
            .dsvert_formal_glm_phase18_rat_scaled_integer(
              .dsvert_formal_glm_phase18_rat_clamp(raw, "0", upper),
              contract$common_bits)
        }
      }
    }

    offset_coordinate <- length(coefficients) + 3L
    if (local_owned[[offset_coordinate]]) {
      mode <- estimand$offset$mode
      if (identical(mode, "none")) {
        row[[offset_coordinate]] <- "0"
      } else {
        raw <- .dsvert_formal_glm_phase18_numeric_try(
          raw_for(estimand$offset$column, slot))
        if (is.null(raw)) row_valid <- FALSE else if (
            identical(mode, "bounded_offset")) {
          row[[offset_coordinate]] <- .dsvert_formal_glm_phase18_quantize(
            raw, estimand$offset$source_lower,
            estimand$offset$source_upper,
            contract$offset_bits, contract$common_bits)
        } else if (identical(mode, "log_exposure")) {
          if (.dsvert_formal_glm_phase18_rat_cmp(raw, "0") <= 0L) {
            row_valid <- FALSE
          } else {
            source <- estimand$column_registry[[estimand$offset$column]]
            clipped <- .dsvert_formal_glm_phase18_rat_clamp(
              raw, source$lower, source$upper)
            interval <- tryCatch(
              .dsvert_formal_glm_phase18_rat_log_interval(
                clipped, contract$reference_bits),
              error = function(error) NULL)
            if (is.null(interval)) row_valid <- FALSE else {
              middle <- .dsvert_formal_glm_phase18_rat_div(
                .dsvert_formal_glm_phase18_rat_add(
                  interval$lower, interval$upper), "2")
              rounded <- .dsvert_formal_glm_phase18_rat_round(
                middle, contract$offset_bits)
              rounded <- .dsvert_formal_glm_phase18_rat_clamp(
                rounded, estimand$offset$lower, estimand$offset$upper)
              row[[offset_coordinate]] <-
                .dsvert_formal_glm_phase18_rat_scaled_integer(
                  rounded, contract$common_bits)
            }
          }
        } else row_valid <- FALSE
      }
    }

    if (!row_valid) row[] <- "0"
    if (row_valid) {
      lower <- c("0", unname(as.character(unlist(
        authorization$plan$kernel$x_lower, use.names = FALSE))), "0",
        authorization$plan$kernel$offset_lower)
      upper <- c(authorization$plan$kernel$weight_upper,
        unname(as.character(unlist(
          authorization$plan$kernel$x_upper, use.names = FALSE))),
        authorization$plan$kernel$outcome_upper,
        authorization$plan$kernel$offset_upper)
      invalid <- which(local_owned & vapply(seq_along(row), function(index) {
        .dsvert_formal_glm_phase18_signed_cmp(row[[index]], lower[[index]]) < 0L ||
          .dsvert_formal_glm_phase18_signed_cmp(row[[index]], upper[[index]]) > 0L
      }, logical(1L)))
      if (length(invalid)) {
        .dsvert_formal_glm_phase18_abort(
          "A quantized formal-GLM value escaped its signed Go-plan bounds.",
          "quantization_bound_violation")
      }
    }
    validity[[physical]] <- row_valid
    base <- (physical - 1L) * coordinate_count
    values[base + seq_len(coordinate_count)] <- row
  }
  list(
    values = values, validity = validity,
    private_alignment_consensus_sha256 = slots$consensus_sha256,
    private_alignment_consensus_status = slots$consensus_status,
    private_alignment_consensus_shape_code = slots$consensus_shape_code,
    block_index = as.integer(block_index),
    global_slot_offset = as.integer(start - 1L))
}

.dsvert_formal_glm_phase18_bn_raw_le <- function(value, width) {
  bytes <- as.raw(unlist(as.list(value)))
  if (length(bytes) > width) {
    .dsvert_formal_glm_phase18_abort(
      "A formal-GLM residue exceeds its selected ring container.",
      "numeric_no_wrap_failure")
  }
  rev(c(raw(width - length(bytes)), bytes))
}

.dsvert_formal_glm_phase18_residue <- function(value, ring_bits) {
  signed <- .dsvert_formal_glm_phase18_signed_bn(value)
  modulus <- .dsvert_formal_glm_phase18_bn(2) ^ as.integer(ring_bits)
  half <- modulus %/% .dsvert_formal_glm_phase18_bn(2)
  maximum <- half - .dsvert_formal_glm_phase18_bn(1)
  if (signed$magnitude > if (signed$sign < 0L) half else maximum) {
    .dsvert_formal_glm_phase18_abort(
      "A formal-GLM source value is outside its certified signed ring.",
      "numeric_no_wrap_failure")
  }
  if (signed$sign < 0L) modulus - signed$magnitude else signed$magnitude
}

.dsvert_formal_glm_phase18_split <- function(
    values, validity, ring_bits, record_bytes,
    random_bytes = .dsvert_secure_random_bytes,
    validity_left = NULL) {
  if (!is.character(values) || !length(values) ||
      !is.logical(validity) || anyNA(validity) || !length(validity) ||
      !is.function(random_bytes)) {
    .dsvert_formal_glm_phase18_abort(
      "Invalid formal-GLM protected block.", "invalid_local_materialization")
  }
  count <- length(values)
  left <- random_bytes(record_bytes * count)
  if (is.null(validity_left)) {
    validity_left <- random_bytes(length(validity))
  }
  if (!is.raw(left) || length(left) != record_bytes * count ||
      !is.raw(validity_left) || length(validity_left) != length(validity)) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM CSPRNG returned the wrong fixed shape.",
      "invalid_local_randomness")
  }
  validity_left <- as.raw(as.integer(validity_left) %% 2L)
  validity_right <- as.raw(bitwXor(
    as.integer(validity_left), as.integer(validity)))
  modulus <- .dsvert_formal_glm_phase18_bn(2) ^ as.integer(ring_bits)
  left_matrix <- matrix(left, nrow = record_bytes)
  if (ring_bits %% 8L) {
    left_matrix[record_bytes, ] <- as.raw(
      as.integer(left_matrix[record_bytes, ]) %% (2^(ring_bits %% 8L)))
  }
  right_matrix <- matrix(as.raw(0), nrow = record_bytes, ncol = count)
  for (index in seq_len(count)) {
    left_bn <- openssl::bignum(rev(left_matrix[, index]))
    residue <- .dsvert_formal_glm_phase18_residue(values[[index]], ring_bits)
    right_bn <- (residue + modulus - left_bn) %% modulus
    right_matrix[, index] <- .dsvert_formal_glm_phase18_bn_raw_le(
      right_bn, record_bytes)
  }
  list(
    coordinate_left = as.raw(as.vector(left_matrix)),
    coordinate_right = as.raw(as.vector(right_matrix)),
    validity_left = validity_left, validity_right = validity_right)
}

.dsvert_formal_glm_phase18_block_unsigned <- function(
    authorization, ticket, block, ciphertext,
    pair_commitment_sha256) {
  pre <- authorization$pre
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_BLOCK_VERSION,
    phase = "pre_execution_encrypted_source_block_committed",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = pre$capsule_id,
    manifest_sha256 = pre$manifest_sha256,
    artifact_sha256 = pre$artifact_sha256,
    plan_sha256 = pre$plan_sha256,
    kernel_spec_sha256 = pre$kernel_spec_sha256,
    pre_execution_sha256 = authorization$pre_execution_sha256,
    run_id = pre$run_id,
    source_context_sha256 = pre$source_context_sha256,
    snapshot_sha256 = pre$snapshot_sha256,
    pinset_sha256 = pre$pinset_sha256,
    source_name = authorization$policy$peer_name,
    source_identity_pk = unname(authorization$policy$peer_pinset[[
      authorization$policy$peer_name]]),
    recipient_name = ticket$value$recipient_name,
    recipient_peer_id = ticket$value$recipient_peer_id,
    recipient_ticket_sha256 = ticket$sha256,
    block_index = block$block_index,
    total_blocks = pre$total_blocks,
    global_slot_offset = block$global_slot_offset,
    slots_in_block = pre$block_capacity,
    coordinate_count = pre$coordinate_count,
    coordinate_records_in_block =
      as.numeric(pre$block_capacity) * as.numeric(pre$coordinate_count),
    ring_bits = pre$ring_bits,
    record_bytes = pre$record_bytes,
    coordinate_encoding =
      "little_endian_unsigned_fixed_container_masked_to_ring_bits_v1",
    validity_records_in_block = pre$block_capacity,
    validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
    alignment_sharing = .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING,
    pair_commitment_sha256 = pair_commitment_sha256,
    ciphertext_sha256 = .dsvert_formal_glm_phase18_sha256(ciphertext$raw),
    ciphertext_bytes = length(ciphertext$raw),
    ciphertext = ciphertext$encoded,
    release_token = "none_pre_execution",
    openings_performed = 0L,
    production_ready = FALSE))
}

.dsvert_formal_glm_phase18_materialize_block <- function(
    authorization, block_index, first_ticket_json, second_ticket_json,
    .resolved_snapshots = NULL,
    .random_bytes = .dsvert_secure_random_bytes,
    .encryptor = NULL, .signer = NULL,
    .verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  tickets <- lapply(list(first_ticket_json, second_ticket_json),
    .dsvert_formal_glm_phase18_ticket_validate,
    authorization = authorization, verifier = .verifier)
  recipients <- vapply(tickets, function(ticket) {
    ticket$value$recipient_name
  }, character(1L))
  if (anyDuplicated(recipients) ||
      !setequal(recipients, authorization$designated)) {
    .dsvert_formal_glm_phase18_abort(
      "Recipient tickets must cover exactly both designated compute peers.",
      "invalid_recipient_ticket")
  }
  tickets <- tickets[order(recipients, method = "radix")]
  names(tickets) <- sort(recipients, method = "radix")
  snapshots <- .dsvert_formal_glm_phase18_resolved_snapshots(
    authorization, .resolved_snapshots)
  block <- .dsvert_formal_glm_phase18_materialize_block_values(
    authorization, snapshots, block_index)
  validity_mask <- .dsvert_formal_glm_phase18_private_lane_bytes(
    authorization, block$block_index, "validity", length(block$validity))
  split <- .dsvert_formal_glm_phase18_split(
    block$values, block$validity,
    authorization$pre$ring_bits, authorization$pre$record_bytes,
    .random_bytes, validity_left = validity_mask)
  shares <- list(
    c(split$coordinate_left, split$validity_left),
    c(split$coordinate_right, split$validity_right))
  names(shares) <- names(tickets)
  ciphertexts <- vector("list", 2L)
  names(ciphertexts) <- names(tickets)
  alignment_shares <- .dsvert_formal_glm_phase18_alignment_shares(
    authorization, block$block_index,
    block$private_alignment_consensus_sha256,
    block$private_alignment_consensus_shape_code)
  source_slot <- match(
    authorization$policy$peer_name, authorization$peers) - 1L
  for (recipient in names(tickets)) {
    ticket <- tickets[[recipient]]
    role <- if (identical(
      recipient, authorization$pre$garbler_peer_name)) {
      "garbler"
    } else if (identical(
      recipient, authorization$pre$evaluator_peer_name)) {
      "evaluator"
    } else {
      .dsvert_formal_glm_phase18_abort(
        "The encrypted formal-GLM block has an invalid compute role.",
        "invalid_recipient_ticket")
    }
    private_header <- .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_FORMAL_GLM_PHASE18_PRIVATE_BLOCK_VERSION,
      purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
      capsule_id = authorization$pre$capsule_id,
      plan_sha256 = authorization$pre$plan_sha256,
      pre_execution_sha256 = authorization$pre_execution_sha256,
      run_id = authorization$pre$run_id,
      source_name = authorization$policy$peer_name,
      source_slot = source_slot,
      recipient_name = recipient,
      recipient_role = role,
      recipient_ticket_sha256 = ticket$sha256,
      block_index = block$block_index,
      total_blocks = authorization$pre$total_blocks,
      global_slot_offset = block$global_slot_offset,
      slots_in_block = authorization$pre$block_capacity,
      coordinate_count = authorization$pre$coordinate_count,
      coordinate_share_bytes =
        authorization$pre$block_capacity *
          authorization$pre$coordinate_count *
          authorization$pre$record_bytes,
      validity_share_bytes = authorization$pre$block_capacity,
      ring_bits = authorization$pre$ring_bits,
      record_bytes = authorization$pre$record_bytes,
      validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
      alignment_sharing = .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING,
      private_alignment_gate_share =
        alignment_shares[[recipient]]$gate,
      private_alignment_consensus_share =
        .dsvert_relay_b64url_encode(
          alignment_shares[[recipient]]$consensus),
      phase19_required_operation =
        paste0("xor_reconstruct_validity_alignment_and_consensus_then_",
               "all_k_mask_full_tuple_before_glm_kernel_v2"),
      release_token = "none_pre_execution",
      openings_performed = 0L))
    plaintext <- .dsvert_dp_capsule_source_pack(
      private_header, shares[[recipient]])
    ciphertexts[[recipient]] <- .dsvert_dp_capsule_source_encrypt(
      plaintext, ticket$transport_pk, .encryptor)
  }
  cipher_hashes <- lapply(names(ciphertexts), function(recipient) list(
    recipient_name = recipient,
    ciphertext_sha256 = .dsvert_formal_glm_phase18_sha256(
      ciphertexts[[recipient]]$raw),
    ciphertext_bytes = length(ciphertexts[[recipient]]$raw)))
  pair_commitment <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/encrypted-pair/v2|", list(
      pre_execution_sha256 = authorization$pre_execution_sha256,
      source_name = authorization$policy$peer_name,
      block_index = block$block_index,
      recipients = cipher_hashes))
  envelopes <- lapply(names(tickets), function(recipient) {
    unsigned <- .dsvert_formal_glm_phase18_block_unsigned(
      authorization, tickets[[recipient]], block,
      ciphertexts[[recipient]], pair_commitment)
    .dsvert_formal_glm_phase18_sign(
      unsigned, authorization$policy,
      .DSVERT_FORMAL_GLM_PHASE18_BLOCK_DOMAIN, .signer)
  })
  block_commitment <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/block-commitment/v2|", list(
      pre_execution_sha256 = authorization$pre_execution_sha256,
      source_name = authorization$policy$peer_name,
      block_index = block$block_index,
      pair_commitment_sha256 = pair_commitment,
      envelope_sha256 = lapply(envelopes, function(envelope) {
        .dsvert_formal_glm_phase18_hash_object(
          "dsVert/formal-glm/phase18/signed-envelope/v2|", envelope)
      })))
  bundle <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_BUNDLE_VERSION,
    phase = "pre_execution_encrypted_block_pair_committed",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = authorization$pre$capsule_id,
    plan_sha256 = authorization$pre$plan_sha256,
    pre_execution_sha256 = authorization$pre_execution_sha256,
    run_id = authorization$pre$run_id,
    source_name = authorization$policy$peer_name,
    recipients = as.list(names(tickets)),
    block_index = block$block_index,
    total_blocks = authorization$pre$total_blocks,
    slots_in_block = authorization$pre$block_capacity,
    coordinate_count = authorization$pre$coordinate_count,
    ring_bits = authorization$pre$ring_bits,
    validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
    alignment_sharing = .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING,
    pair_commitment_sha256 = pair_commitment,
    block_commitment_sha256 = block_commitment,
    envelopes = unname(envelopes),
    release_token = "none_pre_execution",
    openings_performed = 0L,
    production_ready = FALSE))
  .dsvert_dp_canonical_json(bundle)
}

.dsvert_formal_glm_phase18_block_bundle_validate <- function(
    bundle_json, authorization,
    verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  parsed <- .dsvert_formal_glm_phase18_decode_json(
    bundle_json, "encrypted block bundle", 4L * 1024L^2)
  bundle <- parsed$value
  required <- c(
    "version", "phase", "purpose", "capsule_id", "plan_sha256",
    "pre_execution_sha256", "run_id", "source_name", "recipients",
    "block_index", "total_blocks", "slots_in_block", "coordinate_count",
    "ring_bits", "validity_sharing", "alignment_sharing",
    "pair_commitment_sha256",
    "block_commitment_sha256", "envelopes", "release_token",
    "openings_performed", "production_ready")
  envelopes <- bundle$envelopes
  recipients <- tryCatch(.dsvert_formal_glm_phase18_names(
    bundle$recipients, "bundle recipients", 2L), error = function(error) NULL)
  if (!is.list(bundle) || !setequal(names(bundle), required) ||
      !identical(bundle$version, .DSVERT_FORMAL_GLM_PHASE18_BUNDLE_VERSION) ||
      !identical(bundle$phase,
                 "pre_execution_encrypted_block_pair_committed") ||
      !identical(bundle$purpose, .DSVERT_FORMAL_GLM_PHASE18_PURPOSE) ||
      !identical(bundle$capsule_id, authorization$pre$capsule_id) ||
      !identical(bundle$plan_sha256, authorization$pre$plan_sha256) ||
      !identical(bundle$pre_execution_sha256,
                 authorization$pre_execution_sha256) ||
      !identical(bundle$run_id, authorization$pre$run_id) ||
      !identical(bundle$source_name, authorization$policy$peer_name) ||
      is.null(recipients) || !identical(recipients, authorization$designated) ||
      !is.list(envelopes) || length(envelopes) != 2L ||
      !identical(bundle$alignment_sharing,
                 .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING) ||
      !identical(bundle$release_token, "none_pre_execution") ||
      !identical(as.numeric(bundle$openings_performed), 0) ||
      !identical(bundle$production_ready, FALSE)) {
    .dsvert_formal_glm_phase18_abort(
      "The encrypted formal-GLM block bundle has the wrong binding.",
      "invalid_encrypted_block")
  }
  block_index <- .dsvert_formal_glm_phase18_integer(
    bundle$block_index, "bundle block index", 0,
    authorization$pre$total_blocks - 1)
  common <- envelopes[[1L]]
  observed <- vapply(envelopes, function(envelope) {
    if (!is.list(envelope)) return(NA_character_)
    as.character(envelope$recipient_name)
  }, character(1L))
  if (anyNA(observed) || anyDuplicated(observed) ||
      !identical(sort(observed, method = "radix"), recipients)) {
    .dsvert_formal_glm_phase18_abort(
      "The encrypted formal-GLM block recipients are incomplete.",
      "invalid_encrypted_block")
  }
  envelopes <- envelopes[match(recipients, observed)]
  cipher_hashes <- vector("list", 2L)
  envelope_hashes <- vector("list", 2L)
  for (index in seq_along(recipients)) {
    recipient <- recipients[[index]]
    envelope <- envelopes[[index]]
    signature <- envelope$signature
    unsigned <- envelope[setdiff(names(envelope), "signature")]
    ciphertext <- tryCatch(.dsvert_relay_b64url_decode(
      envelope$ciphertext, "formal-GLM ciphertext"),
      error = function(error) raw())
    fixed <- c(
      "capsule_id", "plan_sha256", "pre_execution_sha256", "run_id",
      "source_name", "block_index", "total_blocks", "slots_in_block",
      "coordinate_count", "ring_bits", "validity_sharing",
      "alignment_sharing",
      "pair_commitment_sha256")
    if (!all(vapply(fixed, function(field) {
      identical(envelope[[field]], bundle[[field]])
    }, logical(1L))) ||
        !identical(envelope$recipient_name, recipient) ||
        !is.raw(ciphertext) || !length(ciphertext) ||
        !identical(envelope$ciphertext_sha256,
                   .dsvert_formal_glm_phase18_sha256(ciphertext)) ||
        !identical(as.numeric(envelope$ciphertext_bytes),
                   as.numeric(length(ciphertext))) ||
        !isTRUE(tryCatch(verifier(
          .dsvert_formal_glm_phase18_domain_message(
            .DSVERT_FORMAL_GLM_PHASE18_BLOCK_DOMAIN,
            .dsvert_dp_canonical_json(unsigned)),
          unname(authorization$policy$peer_pinset[[bundle$source_name]]),
          .dsvert_formal_glm_phase18_signature(signature)),
          error = function(error) FALSE))) {
      .dsvert_formal_glm_phase18_abort(
        "A formal-GLM encrypted block envelope failed authentication.",
        "invalid_encrypted_block")
    }
    cipher_hashes[[index]] <- list(
      recipient_name = recipient,
      ciphertext_sha256 = envelope$ciphertext_sha256,
      ciphertext_bytes = envelope$ciphertext_bytes)
    envelope_hashes[[index]] <- .dsvert_formal_glm_phase18_hash_object(
      "dsVert/formal-glm/phase18/signed-envelope/v2|", envelope)
  }
  pair <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/encrypted-pair/v2|", list(
      pre_execution_sha256 = authorization$pre_execution_sha256,
      source_name = bundle$source_name,
      block_index = block_index,
      recipients = cipher_hashes))
  block_commitment <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/block-commitment/v2|", list(
      pre_execution_sha256 = authorization$pre_execution_sha256,
      source_name = bundle$source_name,
      block_index = block_index,
      pair_commitment_sha256 = pair,
      envelope_sha256 = envelope_hashes))
  if (!identical(pair, bundle$pair_commitment_sha256) ||
      !identical(block_commitment, bundle$block_commitment_sha256)) {
    .dsvert_formal_glm_phase18_abort(
      "The formal-GLM block pair commitment was modified.",
      "invalid_encrypted_block")
  }
  list(value = bundle, json = bundle_json,
       block_index = as.integer(block_index),
       block_commitment_sha256 = block_commitment)
}

.dsvert_formal_glm_phase18_finalize_local <- function(
    authorization, bundle_jsons, .signer = NULL,
    .verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  if (!is.list(bundle_jsons) ||
      length(bundle_jsons) != authorization$pre$total_blocks) {
    .dsvert_formal_glm_phase18_abort(
      "Every fixed public block is required exactly once.",
      "incomplete_local_materialization")
  }
  bundles <- lapply(bundle_jsons,
    .dsvert_formal_glm_phase18_block_bundle_validate,
    authorization = authorization, verifier = .verifier)
  indices <- vapply(bundles, `[[`, integer(1L), "block_index")
  if (anyDuplicated(indices) ||
      !identical(sort(indices), seq.int(
        0L, as.integer(authorization$pre$total_blocks) - 1L))) {
    .dsvert_formal_glm_phase18_abort(
      "A formal-GLM block was omitted, duplicated or replayed conflictually.",
      "conflicting_block_replay")
  }
  bundles <- bundles[order(indices)]
  commitments <- lapply(bundles, function(bundle) list(
    block_index = bundle$block_index,
    block_commitment_sha256 = bundle$block_commitment_sha256))
  root <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/local-materialization-root/v2|", list(
      pre_execution_sha256 = authorization$pre_execution_sha256,
      source_name = authorization$policy$peer_name,
      block_commitments = commitments))
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_LOCAL_RECEIPT_VERSION,
    phase = "local_pre_execution_materialization_committed",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = authorization$pre$capsule_id,
    plan_sha256 = authorization$pre$plan_sha256,
    pre_execution_sha256 = authorization$pre_execution_sha256,
    run_id = authorization$pre$run_id,
    source_name = authorization$policy$peer_name,
    source_identity_pk = unname(authorization$policy$peer_pinset[[
      authorization$policy$peer_name]]),
    pinset_sha256 = authorization$pre$pinset_sha256,
    total_capacity = authorization$pre$total_capacity,
    block_capacity = authorization$pre$block_capacity,
    total_blocks = authorization$pre$total_blocks,
    coordinate_count = authorization$pre$coordinate_count,
    ring_bits = authorization$pre$ring_bits,
    validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
    alignment_consensus_gate = "private_xor_gate_deferred_to_phase19_v2",
    local_materialization_root_sha256 = root,
    release_token = "none_pre_execution",
    phase19_all_k_validity_and_required = TRUE,
    protected_data_e2e_verified = FALSE,
    openings_performed = 0L,
    production_ready = FALSE))
  receipt <- .dsvert_formal_glm_phase18_sign(
    unsigned, authorization$policy,
    .DSVERT_FORMAL_GLM_PHASE18_RECEIPT_DOMAIN, .signer)
  .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(receipt))
}

.dsvert_formal_glm_phase18_exact_fields <- function(value, fields) {
  is.list(value) && !is.null(names(value)) && !anyNA(names(value)) &&
    !anyDuplicated(names(value)) && identical(sort(names(value)), sort(fields))
}

.dsvert_formal_glm_phase18_domain_sha256 <- function(domain, value) {
  json <- .dsvert_formal_glm_phase18_json(value)
  .dsvert_formal_glm_phase18_sha256(
    .dsvert_formal_glm_phase18_domain_message(domain, json))
}

.dsvert_formal_glm_phase18_local_receipt_validate <- function(
    receipt_json, authorization,
    verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  parsed <- .dsvert_formal_glm_phase18_decode_json(
    receipt_json, "local materialization receipt", 256L * 1024L)
  receipt <- parsed$value
  fields <- c(
    "version", "phase", "purpose", "capsule_id", "plan_sha256",
    "pre_execution_sha256", "run_id", "source_name",
    "source_identity_pk", "pinset_sha256", "total_capacity",
    "block_capacity", "total_blocks", "coordinate_count", "ring_bits",
    "validity_sharing", "alignment_consensus_gate",
    "local_materialization_root_sha256",
    "release_token", "phase19_all_k_validity_and_required",
    "protected_data_e2e_verified", "openings_performed",
    "production_ready", "signature")
  source <- receipt$source_name
  fixed <- list(
    version = .DSVERT_FORMAL_GLM_PHASE18_LOCAL_RECEIPT_VERSION,
    phase = "local_pre_execution_materialization_committed",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = authorization$pre$capsule_id,
    plan_sha256 = authorization$pre$plan_sha256,
    pre_execution_sha256 = authorization$pre_execution_sha256,
    run_id = authorization$pre$run_id,
    pinset_sha256 = authorization$pre$pinset_sha256,
    total_capacity = authorization$pre$total_capacity,
    block_capacity = authorization$pre$block_capacity,
    total_blocks = authorization$pre$total_blocks,
    coordinate_count = authorization$pre$coordinate_count,
    ring_bits = authorization$pre$ring_bits,
    validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
    alignment_consensus_gate = "private_xor_gate_deferred_to_phase19_v2",
    release_token = "none_pre_execution",
    phase19_all_k_validity_and_required = TRUE,
    protected_data_e2e_verified = FALSE,
    openings_performed = 0,
    production_ready = FALSE)
  same <- function(left, right) {
    identical(left, right) ||
      is.numeric(left) && is.numeric(right) &&
        identical(as.numeric(left), as.numeric(right))
  }
  if (!.dsvert_formal_glm_phase18_exact_fields(receipt, fields) ||
      !is.character(source) || length(source) != 1L ||
      !source %in% authorization$peers ||
      !identical(receipt$source_identity_pk,
                 unname(authorization$policy$peer_pinset[[source]])) ||
      !is.character(receipt$local_materialization_root_sha256) ||
      length(receipt$local_materialization_root_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$",
             receipt$local_materialization_root_sha256) ||
      !all(vapply(names(fixed), function(field) {
        same(receipt[[field]], fixed[[field]])
      }, logical(1L)))) {
    .dsvert_formal_glm_phase18_abort(
      "A formal-GLM local materialization receipt has the wrong binding.",
      "invalid_local_materialization_receipt")
  }
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  valid <- isTRUE(tryCatch(verifier(
    .dsvert_formal_glm_phase18_domain_message(
      .DSVERT_FORMAL_GLM_PHASE18_RECEIPT_DOMAIN,
      .dsvert_dp_canonical_json(unsigned)),
    unname(authorization$policy$peer_pinset[[source]]),
    .dsvert_formal_glm_phase18_signature(receipt$signature)),
    error = function(error) FALSE))
  if (!valid) {
    .dsvert_formal_glm_phase18_abort(
      "A formal-GLM local materialization receipt failed pinned verification.",
      "invalid_local_materialization_receipt")
  }
  list(value = receipt, json = receipt_json,
       source_name = source,
       local_root = receipt$local_materialization_root_sha256,
       sha256 = .dsvert_formal_glm_phase18_hash_object(
         "dsVert/formal-glm/phase18/signed-local-receipt/v2|", receipt))
}

.dsvert_formal_glm_phase18_local_receipt_set <- function(
    receipt_jsons, authorization,
    verifier = .dsvert_relay_verify_message) {
  if (!is.list(receipt_jsons) ||
      length(receipt_jsons) != length(authorization$peers)) {
    .dsvert_formal_glm_phase18_abort(
      paste0("Exactly one local materialization receipt from every pinned ",
             "custodian is required."),
      "incomplete_materialization_receipt_set")
  }
  receipts <- lapply(
    receipt_jsons, .dsvert_formal_glm_phase18_local_receipt_validate,
    authorization = authorization, verifier = verifier)
  sources <- vapply(receipts, `[[`, character(1L), "source_name")
  if (anyDuplicated(sources) || !setequal(sources, authorization$peers)) {
    .dsvert_formal_glm_phase18_abort(
      "The local materialization receipts do not cover exactly all K custodians.",
      "incomplete_materialization_receipt_set")
  }
  receipts <- receipts[match(authorization$peers, sources)]
  entries <- lapply(receipts, function(receipt) list(
    source_name = receipt$source_name,
    local_materialization_root_sha256 = receipt$local_root,
    signed_receipt_sha256 = receipt$sha256))
  list(
    receipts = receipts,
    receipt_set_sha256 = .dsvert_formal_glm_phase18_hash_object(
      "dsVert/formal-glm/phase18/local-receipt-set/v2|", entries),
    global_materialization_root_sha256 =
      .dsvert_formal_glm_phase18_hash_object(
        "dsVert/formal-glm/phase18/global-materialization-root/v2|",
        list(pre_execution_sha256 = authorization$pre_execution_sha256,
             custodian_roots = entries)))
}

.dsvert_formal_glm_phase18_source_attestation <- function(
    source_json, authorization,
    verifier = .dsvert_relay_verify_message) {
  parsed <- .dsvert_formal_glm_phase18_decode_json(
    source_json, "Phase-1.7 source attestation", 2L * 1024L^2)
  attestation <- parsed$value
  if (!.dsvert_formal_glm_phase18_exact_fields(
        attestation, c("contract", "signatures"))) {
    .dsvert_formal_glm_phase18_abort(
      "Invalid formal-GLM Phase-1.7 source attestation.",
      "invalid_post_execution_evidence")
  }
  contract <- attestation$contract
  fields <- c(
    "version", "plan_sha256", "kernel_spec_sha256", "manifest_sha256",
    "workload_sha256", "source_context_sha256", "snapshot_sha256",
    "source_fan_in_transcript_sha256", "pinset_sha256",
    "custodian_peers", "custodian_count", "total_capacity",
    "capacity_semantics", "adjacency", "adjacency_semantics",
    "maximum_active_rows_per_patient", "patient_contribution",
    "missingness", "patient_collapse", "materializer_verification",
    "protected_data_e2e_verified", "production_ready")
  pre <- authorization$pre
  expected <- list(
    version = "dsvert-formal-glm-phase17-source-contribution-v1",
    plan_sha256 = pre$plan_sha256,
    kernel_spec_sha256 = pre$kernel_spec_sha256,
    manifest_sha256 = pre$manifest_sha256,
    workload_sha256 = pre$workload_sha256,
    source_context_sha256 = pre$source_context_sha256,
    snapshot_sha256 = pre$snapshot_sha256,
    pinset_sha256 = pre$pinset_sha256,
    custodian_peers = pre$custodian_peers,
    custodian_count = pre$custodian_count,
    total_capacity = pre$total_capacity,
    capacity_semantics = .DSVERT_FORMAL_GLM_PHASE18_CAPACITY_SEMANTICS,
    adjacency = pre$adjacency,
    adjacency_semantics = .DSVERT_FORMAL_GLM_PHASE18_ADJACENCY_SEMANTICS,
    maximum_active_rows_per_patient = 1,
    patient_contribution = .DSVERT_FORMAL_GLM_PHASE18_PATIENT_CONTRIBUTION,
    missingness = pre$missingness,
    patient_collapse = pre$patient_collapse,
    materializer_verification =
      "custodian_signed_claim_protected_data_materializer_e2e_pending_v1",
    protected_data_e2e_verified = FALSE,
    production_ready = FALSE)
  same <- function(left, right) {
    identical(left, right) ||
      is.numeric(left) && is.numeric(right) &&
        identical(as.numeric(left), as.numeric(right))
  }
  if (!.dsvert_formal_glm_phase18_exact_fields(contract, fields) ||
      !is.character(contract$source_fan_in_transcript_sha256) ||
      length(contract$source_fan_in_transcript_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$",
             contract$source_fan_in_transcript_sha256) ||
      !all(vapply(names(expected), function(field) {
        same(contract[[field]], expected[[field]])
      }, logical(1L)))) {
    .dsvert_formal_glm_phase18_abort(
      paste0("The Phase-1.7 source contract differs from the ",
             "pre-execution authorization."),
      "invalid_post_execution_evidence")
  }
  .dsvert_formal_glm_phase18_verify_signature_set(
    .dsvert_formal_glm_phase18_domain_message(
      .DSVERT_FORMAL_GLM_PHASE18_SOURCE_DOMAIN,
      .dsvert_formal_glm_phase18_json(contract)),
    attestation$signatures, authorization$peers, authorization$policy,
    verifier, "Phase-1.7 source-contribution attestation")
  observed <- vapply(
    attestation$signatures, `[[`, character(1L), "signer")
  ordered <- attestation$signatures[match(authorization$peers, observed)]
  canonical_attestation <- list(contract = contract, signatures = ordered)
  list(
    value = canonical_attestation,
    contract_sha256 = .dsvert_formal_glm_phase18_domain_sha256(
      .DSVERT_FORMAL_GLM_PHASE18_SOURCE_DOMAIN, contract),
    attestation_sha256 = .dsvert_formal_glm_phase18_domain_sha256(
      .DSVERT_FORMAL_GLM_PHASE18_SOURCE_ATTESTATION_DOMAIN,
      canonical_attestation))
}

.dsvert_formal_glm_phase18_signed_admission <- function(
    admission_json, source, authorization,
    verifier = .dsvert_relay_verify_message) {
  parsed <- .dsvert_formal_glm_phase18_decode_json(
    admission_json, "Phase-1.7 signed admission", 4L * 1024L^2)
  signed <- parsed$value
  if (!.dsvert_formal_glm_phase18_exact_fields(
        signed, c("preimage", "signatures"))) {
    .dsvert_formal_glm_phase18_abort(
      "Invalid formal-GLM Phase-1.7 signed admission.",
      "invalid_post_execution_evidence")
  }
  preimage <- signed$preimage
  fields <- c(
    "version", "capsule_id", "manifest_sha256", "schema_manifest_sha256",
    "workload_sha256", "source_context_sha256", "source_contract_sha256",
    "source_contribution_attestation_sha256", "snapshot_sha256",
    "phase15_plan_sha256", "kernel_spec_sha256", "bounds_sha256",
    "quantization_sha256", "phase15_bridge_sha256",
    "final_receipt_pair_sha256", "sensitivity_certificate_sha256",
    "source_fan_in_transcript_sha256",
    "final_checkpoint_transcript_sha256", "coordinate_order_sha256",
    "phase16_release_binding_sha256", "worker_contract_sha256",
    "release_instance_id", "release_contract_sha256",
    "worker_transcript_sha256", "pinset_sha256", "custodian_peers",
    "custodian_count", "garbler_peer_name", "garbler_peer_id",
    "evaluator_peer_name", "evaluator_peer_id", "role_selection",
    "total_capacity", "capacity_semantics", "adjacency",
    "adjacency_semantics", "maximum_active_rows_per_patient",
    "patient_contribution", "missingness", "patient_collapse",
    "mechanism", "allocation", "epsilon", "allocated_delta",
    "authenticated_opening_count", "protected_data_e2e_verified",
    "production_ready")
  pre <- authorization$pre
  exact <- list(
    version = "dsvert-formal-glm-phase17-authenticated-admission-v1",
    capsule_id = pre$capsule_id, manifest_sha256 = pre$manifest_sha256,
    schema_manifest_sha256 = pre$schema_manifest_sha256,
    workload_sha256 = pre$workload_sha256,
    source_context_sha256 = pre$source_context_sha256,
    source_contract_sha256 = source$contract_sha256,
    source_contribution_attestation_sha256 = source$attestation_sha256,
    snapshot_sha256 = pre$snapshot_sha256,
    phase15_plan_sha256 = pre$plan_sha256,
    kernel_spec_sha256 = pre$kernel_spec_sha256,
    source_fan_in_transcript_sha256 =
      source$value$contract$source_fan_in_transcript_sha256,
    pinset_sha256 = pre$pinset_sha256,
    custodian_peers = pre$custodian_peers,
    custodian_count = pre$custodian_count,
    garbler_peer_name = pre$garbler_peer_name,
    garbler_peer_id = pre$garbler_peer_id,
    evaluator_peer_name = pre$evaluator_peer_name,
    evaluator_peer_id = pre$evaluator_peer_id,
    role_selection = pre$role_selection,
    total_capacity = pre$total_capacity,
    capacity_semantics = .DSVERT_FORMAL_GLM_PHASE18_CAPACITY_SEMANTICS,
    adjacency = pre$adjacency,
    adjacency_semantics = .DSVERT_FORMAL_GLM_PHASE18_ADJACENCY_SEMANTICS,
    maximum_active_rows_per_patient = 1,
    patient_contribution = .DSVERT_FORMAL_GLM_PHASE18_PATIENT_CONTRIBUTION,
    missingness = pre$missingness,
    patient_collapse = pre$patient_collapse,
    mechanism = "joint_discrete_gaussian_one_global_draw",
    allocation = "one_stacked_capsule_vector",
    authenticated_opening_count = 0,
    protected_data_e2e_verified = FALSE,
    production_ready = FALSE)
  same <- function(left, right) {
    identical(left, right) ||
      is.numeric(left) && is.numeric(right) &&
        identical(as.numeric(left), as.numeric(right))
  }
  hash_fields <- c(
    "bounds_sha256", "quantization_sha256", "phase15_bridge_sha256",
    "final_receipt_pair_sha256", "sensitivity_certificate_sha256",
    "final_checkpoint_transcript_sha256", "coordinate_order_sha256",
    "phase16_release_binding_sha256", "worker_contract_sha256",
    "release_contract_sha256", "worker_transcript_sha256")
  valid_hashes <- all(vapply(hash_fields, function(field) {
    is.character(preimage[[field]]) && length(preimage[[field]]) == 1L &&
      grepl("^[0-9a-f]{64}$", preimage[[field]])
  }, logical(1L)))
  if (!.dsvert_formal_glm_phase18_exact_fields(preimage, fields) ||
      !all(vapply(names(exact), function(field) {
        same(preimage[[field]], exact[[field]])
      }, logical(1L))) || !valid_hashes ||
      !is.character(preimage$release_instance_id) ||
      length(preimage$release_instance_id) != 1L ||
      !nzchar(preimage$release_instance_id) ||
      !is.character(preimage$epsilon) || length(preimage$epsilon) != 1L ||
      !is.character(preimage$allocated_delta) ||
      length(preimage$allocated_delta) != 1L ||
      !identical(preimage$release_contract_sha256,
                 preimage$worker_transcript_sha256)) {
    .dsvert_formal_glm_phase18_abort(
      paste0("The Phase-1.7 admission is not bound to the protected ",
             "materialization run."),
      "invalid_post_execution_evidence")
  }
  .dsvert_formal_glm_phase18_verify_signature_set(
    .dsvert_formal_glm_phase18_domain_message(
      .DSVERT_FORMAL_GLM_PHASE18_ADMISSION_DOMAIN,
      .dsvert_formal_glm_phase18_json(preimage)),
    signed$signatures, authorization$peers, authorization$policy,
    verifier, "Phase-1.7 authenticated admission")
  list(
    value = signed, preimage = preimage,
    preimage_sha256 = .dsvert_formal_glm_phase18_domain_sha256(
      .DSVERT_FORMAL_GLM_PHASE18_ADMISSION_DOMAIN, preimage))
}

# This is deliberately a distinct post-execution type.  A Phase-1.7 source
# statement, whose transcript exists only after execution, can never authorize
# the protected-row materializer that has to run before that execution.
.dsvert_formal_glm_phase18_post_prepare <- function(
    authorization, local_receipt_jsons, source_attestation_json,
    signed_admission_json, verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  receipts <- .dsvert_formal_glm_phase18_local_receipt_set(
    local_receipt_jsons, authorization, verifier)
  source <- .dsvert_formal_glm_phase18_source_attestation(
    source_attestation_json, authorization, verifier)
  admission <- .dsvert_formal_glm_phase18_signed_admission(
    signed_admission_json, source, authorization, verifier)
  post <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_POST_VERSION,
    phase = "post_execution_materialization_evidence_bound_but_not_consumed",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = authorization$pre$capsule_id,
    plan_sha256 = authorization$pre$plan_sha256,
    kernel_spec_sha256 = authorization$pre$kernel_spec_sha256,
    pre_execution_sha256 = authorization$pre_execution_sha256,
    run_id = authorization$pre$run_id,
    pinset_sha256 = authorization$pre$pinset_sha256,
    custodian_peers = authorization$pre$custodian_peers,
    custodian_count = authorization$pre$custodian_count,
    local_receipt_set_sha256 = receipts$receipt_set_sha256,
    global_materialization_root_sha256 =
      receipts$global_materialization_root_sha256,
    source_contract_sha256 = source$contract_sha256,
    source_contribution_attestation_sha256 = source$attestation_sha256,
    phase17_admission_preimage_sha256 = admission$preimage_sha256,
    source_fan_in_transcript_sha256 =
      admission$preimage$source_fan_in_transcript_sha256,
    final_receipt_pair_sha256 = admission$preimage$final_receipt_pair_sha256,
    final_checkpoint_transcript_sha256 =
      admission$preimage$final_checkpoint_transcript_sha256,
    release_instance_id = admission$preimage$release_instance_id,
    release_contract_sha256 = admission$preimage$release_contract_sha256,
    phase19_all_k_validity_and_consumed = FALSE,
    phase19_alignment_consensus_equal_across_k = FALSE,
    phase19_materialization_root_in_transcript = FALSE,
    phase19_transcript_consumption = paste0(
      "pending_exact_gc_all_k_validity_alignment_consensus_and_",
      "materialization_root_v1"),
    protected_data_e2e_verified = FALSE,
    release_token = "sealed_only_phase19_pending",
    opening_authorized = FALSE,
    openings_performed = 0L,
    production_ready = FALSE))
  hash <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/post-execution/v1|", post)
  post_authorization <- authorization
  post_authorization$alignment_secret <- NULL
  structure(list(
    post = post, post_execution_sha256 = hash,
    authorization = post_authorization,
    receipts = receipts,
    source = source, admission = admission),
    class = "dsvert_formal_glm_phase18_post_candidate")
}

.dsvert_formal_glm_phase18_post_validate <- function(candidate) {
  if (!inherits(candidate, "dsvert_formal_glm_phase18_post_candidate") ||
      !is.list(candidate$post) ||
      !identical(candidate$post$version,
                 .DSVERT_FORMAL_GLM_PHASE18_POST_VERSION) ||
      !identical(candidate$post$phase19_all_k_validity_and_consumed, FALSE) ||
      !identical(
        candidate$post$phase19_alignment_consensus_equal_across_k, FALSE) ||
      !identical(
        candidate$post$phase19_materialization_root_in_transcript, FALSE) ||
      !identical(candidate$post$opening_authorized, FALSE) ||
      !identical(candidate$post$production_ready, FALSE) ||
      !identical(candidate$post_execution_sha256,
        .dsvert_formal_glm_phase18_hash_object(
          "dsVert/formal-glm/phase18/post-execution/v1|", candidate$post))) {
    .dsvert_formal_glm_phase18_abort(
      "A pre-execution object cannot substitute for post-execution evidence.",
      "phase_type_confusion")
  }
  invisible(candidate)
}

.dsvert_formal_glm_phase18_post_seal <- function(
    candidate, signatures,
    verifier = .dsvert_relay_verify_message) {
  .dsvert_formal_glm_phase18_post_validate(candidate)
  authorization <- candidate$authorization
  .dsvert_formal_glm_phase18_verify_signature_set(
    .dsvert_formal_glm_phase18_domain_message(
      .DSVERT_FORMAL_GLM_PHASE18_POST_DOMAIN,
      .dsvert_dp_canonical_json(candidate$post)),
    signatures, authorization$peers, authorization$policy,
    verifier, "Phase-1.8 post-execution binding")
  observed <- vapply(signatures, `[[`, character(1L), "signer")
  signatures <- signatures[match(authorization$peers, observed)]
  signature_set_sha256 <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/post-signature-set/v1|", signatures)
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_SEALED_TOKEN_VERSION,
    phase = "sealed_post_execution_phase19_pending",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = candidate$post$capsule_id,
    plan_sha256 = candidate$post$plan_sha256,
    pre_execution_sha256 = candidate$post$pre_execution_sha256,
    post_execution_sha256 = candidate$post_execution_sha256,
    global_materialization_root_sha256 =
      candidate$post$global_materialization_root_sha256,
    post_signature_set_sha256 = signature_set_sha256,
    release_instance_id = candidate$post$release_instance_id,
    phase19_blocker = .DSVERT_FORMAL_GLM_PHASE18_PHASE19_BLOCKER,
    opening_authorized = FALSE,
    openings_performed = 0L,
    protected_data_e2e_verified = FALSE,
    production_ready = FALSE))
  token_hash <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/sealed-token/v1|", unsigned)
  structure(list(
    token = c(unsigned, list(sealed_token_sha256 = token_hash)),
    signatures = signatures,
    candidate = candidate),
    class = "dsvert_formal_glm_phase18_sealed_token")
}

.dsvert_formal_glm_phase18_open <- function(token) {
  if (!inherits(token, "dsvert_formal_glm_phase18_sealed_token")) {
    .dsvert_formal_glm_phase18_abort(
      "Only a typed sealed Phase-1.8 token can reach the opening gate.",
      "phase_type_confusion")
  }
  stop(structure(list(
    message = paste0(
      "Formal-GLM opening remains unavailable until the internal Phase-1.8 ",
      "to Phase-1.9 bridge is exercised through the registered R/DSI ",
      "lifecycle and its private output is committed to the single durable ",
      "joint-DP release that consumes the hidden execution-validity shares."),
    call = NULL, code = .DSVERT_FORMAL_GLM_PHASE18_PHASE19_BLOCKER,
    missing = c(
      "registered_r_dsi_lifecycle_for_phase18_to_phase19",
      "phase19_private_output_to_durable_joint_dp_release",
      "joint_dp_release_consumes_hidden_execution_validity"),
    openings_performed = 0L),
    class = c("dsvert_formal_glm_phase18_release_blocker",
              "error", "condition")))
}
