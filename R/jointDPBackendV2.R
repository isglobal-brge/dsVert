# Pre-promotion v2 hand-off for the exact-GC joint-DP backend.
#
# This file is intentionally separate from jointDPControlPlane.R.  Every v1
# receipt remains byte-for-byte governed by the v1 schema and continues to say
# capability_available=FALSE.  The v2 records below commit to the new raw-seed
# commitment scheme and finite-sampler accounting, but also remain FALSE until
# a server-local worker attestation bridge is independently promoted.

.DSVERT_JOINT_DP_BACKEND_PREPARE_V2 <-
  "dsvert-joint-dp-backend-prepare-v2"
.DSVERT_JOINT_DP_BACKEND_TOKEN_V2 <-
  "dsvert-joint-dp-backend-token-v2"
.DSVERT_JOINT_DP_BACKEND_SOURCE_V2 <-
  "dsvert-joint-dp-bounded-source-v2"
.DSVERT_JOINT_DP_BACKEND_SAMPLER_V2 <-
  "hkdf-sha256-aes128ctr-two-geometric-tv-v2"
.DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2 <-
  "dsvert-joint-dp-laplace-gc-template-v2"
.DSVERT_JOINT_DP_BACKEND_UNAVAILABLE_V2 <-
  "v1_opening_receipts_are_not_worker_attestations_and_linear_sampler_is_not_general_workload_promoted"

.dsvert_joint_dp_backend_peers_v2 <- function(context) {
  peers <- context$common$designated_noise_peers
  if (!is.character(peers) || length(peers) != 2L || anyNA(peers) ||
      anyDuplicated(peers) || any(!peers %in% names(context$pins))) {
    stop("Joint-DP v2 requires exactly two designated pinned peers.",
         call. = FALSE)
  }
  peer_ids <- vapply(peers, function(peer) {
    .dsvert_relay_peer_id(unname(context$pins[[peer]]))
  }, character(1L))
  peers[order(peer_ids, method = "radix")]
}

.dsvert_joint_dp_backend_hex_raw_v2 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid joint-DP v2 ", what, ".", call. = FALSE)
  }
  starts <- seq.int(1L, 63L, by = 2L)
  as.raw(strtoi(substring(value, starts, starts + 1L), base = 16L))
}

.dsvert_joint_dp_backend_hash_raw_v2 <- function(value) {
  digest::digest(value, algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_backend_commitment_context_v2 <- function(
    transcript, role, peer_name) {
  if (!role %in% c("garbler", "evaluator") ||
      !is.character(peer_name) || length(peer_name) != 1L ||
      is.na(peer_name) || !nzchar(peer_name)) {
    stop("Invalid joint-DP v2 commitment role.", call. = FALSE)
  }
  .dsvert_joint_dp_backend_hash_raw_v2(c(
    charToRaw("dsvert-joint-dp-private-seed-commitment-v2"), as.raw(0L),
    .dsvert_joint_dp_backend_hex_raw_v2(transcript, "transcript hash"),
    as.raw(0L), charToRaw(role), as.raw(0L), charToRaw(peer_name)))
}

.dsvert_joint_dp_backend_source_v2 <- function(value, mechanism) {
  required <- c(
    "version", "producer", "purpose", "source_context_hash",
    "ring_bits", "frac_bits", "coordinate_count", "encoded_lower",
    "encoded_upper", "sensitivity_steps")
  invalid <- !is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
    anyDuplicated(names(value)) || !setequal(names(value), required)
  if (invalid) {
    stop("Invalid server-minted bounded-source contract for joint-DP v2.",
         call. = FALSE)
  }
  scalar_ring <- function(x) {
    is.numeric(x) && length(x) == 1L && !is.na(x) && is.finite(x) &&
      x == floor(x) && x >= 2 && x <= 512
  }
  if (!is.list(mechanism) || !scalar_ring(value$ring_bits) ||
      !scalar_ring(mechanism$ring_bits) ||
      !identical(as.numeric(value$ring_bits),
                 as.numeric(mechanism$ring_bits))) {
    stop("Invalid server-minted bounded-source contract for joint-DP v2.",
         call. = FALSE)
  }
  ring_bits <- as.integer(value$ring_bits)
  decimal_double <- function(x) {
    digits <- rev(utf8ToInt(x) - utf8ToInt("0"))
    carry <- 0L
    for (index in seq_along(digits)) {
      doubled <- 2L * digits[[index]] + carry
      digits[[index]] <- doubled %% 10L
      carry <- doubled %/% 10L
    }
    if (carry) digits <- c(digits, carry)
    paste0(rev(digits), collapse = "")
  }
  decimal_minus_one <- function(x) {
    digits <- rev(utf8ToInt(x) - utf8ToInt("0"))
    index <- 1L
    while (digits[[index]] == 0L) {
      digits[[index]] <- 9L
      index <- index + 1L
    }
    digits[[index]] <- digits[[index]] - 1L
    paste0(rev(digits), collapse = "")
  }
  signed_limit <- "1"
  for (ignored in seq_len(ring_bits - 1L)) {
    signed_limit <- decimal_double(signed_limit)
  }
  signed_max <- decimal_minus_one(signed_limit)
  signed_min <- paste0("-", signed_limit)
  max_magnitude_digits <- nchar(signed_limit, type = "bytes")
  integer_text <- function(x, signed = FALSE) {
    if (!is.character(x) || length(x) != 1L || is.na(x) ||
        identical(x, "-0") ||
        !grepl(if (signed) "^-?(0|[1-9][0-9]*)$" else "^[1-9][0-9]*$", x)) {
      return(FALSE)
    }
    nchar(x, type = "bytes") <= max_magnitude_digits +
      as.integer(startsWith(x, "-"))
  }
  signed_leq <- function(left, right) {
    negative_left <- startsWith(left, "-") && !identical(left, "0")
    negative_right <- startsWith(right, "-") && !identical(right, "0")
    if (!identical(negative_left, negative_right)) return(negative_left)
    magnitude_left <- sub("^-", "", left)
    magnitude_right <- sub("^-", "", right)
    magnitude_cmp <- if (nchar(magnitude_left) != nchar(magnitude_right)) {
      sign(nchar(magnitude_left) - nchar(magnitude_right))
    } else {
      left_digits <- utf8ToInt(magnitude_left)
      right_digits <- utf8ToInt(magnitude_right)
      difference <- which(left_digits != right_digits)
      if (!length(difference)) 0L else
        sign(left_digits[[difference[[1L]]]] -
               right_digits[[difference[[1L]]]])
    }
    if (negative_left) magnitude_cmp >= 0L else magnitude_cmp <= 0L
  }
  in_signed_ring <- function(x) {
    signed_leq(signed_min, x) && signed_leq(x, signed_max)
  }
  if (!identical(value$version, .DSVERT_JOINT_DP_BACKEND_SOURCE_V2) ||
      !identical(value$producer, mechanism$producer) ||
      !identical(value$purpose, mechanism$purpose) ||
      !identical(value$source_context_hash, mechanism$source_context_hash) ||
      !identical(as.numeric(value$frac_bits),
                 as.numeric(mechanism$frac_bits)) ||
      !identical(as.numeric(value$coordinate_count),
                 as.numeric(mechanism$coordinate_count)) ||
      !integer_text(value$encoded_lower, TRUE) ||
      !integer_text(value$encoded_upper, TRUE) ||
      !integer_text(value$sensitivity_steps) ||
      !in_signed_ring(value$encoded_lower) ||
      !in_signed_ring(value$encoded_upper) ||
      !in_signed_ring(value$sensitivity_steps) ||
      !signed_leq(value$encoded_lower, value$encoded_upper) ||
      !is.numeric(mechanism$sensitivity) ||
      length(mechanism$sensitivity) != 1L ||
      is.na(mechanism$sensitivity) || !is.finite(mechanism$sensitivity) ||
      !isTRUE(all.equal(
        suppressWarnings(as.numeric(value$sensitivity_steps)),
        as.numeric(mechanism$sensitivity), tolerance = 0))) {
    stop("Invalid server-minted bounded-source contract for joint-DP v2.",
         call. = FALSE)
  }
  canonical <- .dsvert_dp_canonical_query_value(value)
  if (!identical(.dsvert_joint_dp_hash(canonical), mechanism$clipping_hash)) {
    stop("The bounded-source contract does not match the committed clipping policy.",
         call. = FALSE)
  }
  canonical
}

.dsvert_joint_dp_laplace_plan_v2 <- function(
    epsilon, delta, sensitivity_steps, coordinate_count,
    bernoulli_bits = 8L, max_steps = 4096L) {
  result <- .callMpcTool("joint-dp-laplace-plan-v2", list(
    epsilon = as.character(epsilon), delta = as.character(delta),
    sensitivity_steps = as.character(sensitivity_steps),
    coordinate_count = as.integer(coordinate_count),
    bernoulli_bits = as.integer(bernoulli_bits),
    max_steps = as.integer(max_steps)))
  required <- c(
    "version", "sampler", "bernoulli_bits", "stop_numerator",
    "max_geometric_steps", "sensitivity_steps", "coordinate_count",
    "epsilon_effective_upper_numerator",
    "epsilon_effective_upper_denominator",
    "implementation_delta_numerator",
    "implementation_delta_denominator", "implementation_delta_bound",
    "accounting", "bernoulli_trials", "aes_blocks",
    "capability_available", "unavailable_reason")
  integer_text <- function(x, allow_zero = FALSE) {
    is.character(x) && length(x) == 1L && !is.na(x) &&
      grepl(if (allow_zero) "^(0|[1-9][0-9]*)$" else "^[1-9][0-9]*$", x)
  }
  if (!is.list(result) || is.null(names(result)) || anyNA(names(result)) ||
      anyDuplicated(names(result)) || !setequal(names(result), required) ||
      !identical(result$version, "dsvert-joint-dp-laplace-plan-v2") ||
      !identical(result$sampler, .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2) ||
      !result$bernoulli_bits %in% c(8L, 16L) ||
      !integer_text(result$stop_numerator) ||
      !integer_text(result$sensitivity_steps) ||
      !integer_text(result$epsilon_effective_upper_numerator, TRUE) ||
      !integer_text(result$epsilon_effective_upper_denominator) ||
      !integer_text(result$implementation_delta_numerator) ||
      !integer_text(result$implementation_delta_denominator) ||
      !is.numeric(result$max_geometric_steps) ||
      result$max_geometric_steps < 1 || result$max_geometric_steps > 4096 ||
      !is.numeric(result$coordinate_count) || result$coordinate_count < 1 ||
      !is.numeric(result$bernoulli_trials) || result$bernoulli_trials < 1 ||
      !is.numeric(result$aes_blocks) || result$aes_blocks < 1 ||
      !identical(result$capability_available, FALSE) ||
      !is.character(result$unavailable_reason) ||
      length(result$unavailable_reason) != 1L ||
      !nzchar(result$unavailable_reason)) {
    stop("The joint-DP v2 sampler planner returned an invalid contract.",
         call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(result)
}

.dsvert_joint_dp_backend_message_v2 <- function(receipt) {
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  charToRaw(paste0(
    "dsVert/joint-dp/backend-signed-receipt/v2|",
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_joint_dp_backend_sign_v2 <- function(receipt, policy, signer = NULL) {
  context <- .dsvert_joint_dp_policy_context(policy)
  message <- .dsvert_joint_dp_backend_message_v2(receipt)
  if (is.null(signer)) {
    identity <- .get_identity_keypair()
    own_pk <- .dsvert_relay_normalize_identity_pk(identity$identity_pk)
    if (!identical(own_pk, unname(context$pins[[context$peer_name]]))) {
      stop("Runtime identity does not match the joint-DP pinned identity.",
           call. = FALSE)
    }
    signature <- .dsvert_relay_sign_message(message, identity$identity_sk)
  } else {
    if (!is.function(signer)) stop("Invalid joint-DP v2 signer.", call. = FALSE)
    signature <- signer(message, context$peer_name,
                        unname(context$pins[[context$peer_name]]))
  }
  if (!is.character(signature) || length(signature) != 1L ||
      is.na(signature) || !nzchar(signature) ||
      nchar(signature, type = "bytes") > 512L) {
    stop("The joint-DP v2 signature is invalid.", call. = FALSE)
  }
  c(receipt, list(signature = signature))
}

.dsvert_joint_dp_backend_verify_v2 <- function(
    receipt, policy, version, phase, verifier = NULL) {
  context <- .dsvert_joint_dp_policy_context(policy)
  prepare_fields <- c(
    "version", "phase", "consortium_id", "peer_name", "peer_identity_pk",
    "query_id", "allocation_index", "transcript_hash", "role",
    "commitment_context", "seed_commitment_v2", "source_contract_hash",
    "plan_hash", "capability_available", "unavailable_reason", "signature")
  token_fields <- c(
    "version", "phase", "consortium_id", "peer_name", "peer_identity_pk",
    "query_id", "allocation_index", "transcript_hash", "prepare_set_hash",
    "ordered_seed_commitments", "source_contract_hash", "plan_hash",
    "semantic_circuit_contract_hash", "worker_attestation_available",
    "capability_available", "unavailable_reason", "signature")
  fields <- if (identical(version, .DSVERT_JOINT_DP_BACKEND_PREPARE_V2)) {
    prepare_fields
  } else if (identical(version, .DSVERT_JOINT_DP_BACKEND_TOKEN_V2)) {
    token_fields
  } else {
    character()
  }
  hash_ok <- function(x) is.character(x) && length(x) == 1L && !is.na(x) &&
    grepl("^[0-9a-f]{64}$", x)
  valid <- is.list(receipt) && !is.null(names(receipt)) &&
    !anyNA(names(receipt)) && !anyDuplicated(names(receipt)) &&
    setequal(names(receipt), fields) && identical(receipt$version, version) &&
    identical(receipt$phase, phase) &&
    identical(receipt$consortium_id, context$consortium_id) &&
    receipt$peer_name %in% names(context$pins) &&
    identical(receipt$peer_identity_pk,
              unname(context$pins[[receipt$peer_name]])) &&
    hash_ok(receipt$query_id) && hash_ok(receipt$transcript_hash) &&
    hash_ok(receipt$source_contract_hash) && hash_ok(receipt$plan_hash) &&
    identical(receipt$capability_available, FALSE) &&
    identical(receipt$unavailable_reason,
              .DSVERT_JOINT_DP_BACKEND_UNAVAILABLE_V2) &&
    is.character(receipt$signature) && length(receipt$signature) == 1L &&
    !is.na(receipt$signature) && nzchar(receipt$signature)
  if (identical(version, .DSVERT_JOINT_DP_BACKEND_PREPARE_V2)) {
    valid <- valid && receipt$role %in% c("garbler", "evaluator") &&
      hash_ok(receipt$commitment_context) &&
      hash_ok(receipt$seed_commitment_v2)
  } else {
    ordered <- .dsvert_joint_dp_backend_peers_v2(context)
    valid <- valid && hash_ok(receipt$prepare_set_hash) &&
      hash_ok(receipt$semantic_circuit_contract_hash) &&
      is.list(receipt$ordered_seed_commitments) &&
      identical(names(receipt$ordered_seed_commitments), ordered) &&
      all(vapply(receipt$ordered_seed_commitments, hash_ok, logical(1L))) &&
      identical(receipt$worker_attestation_available, FALSE)
  }
  if (!isTRUE(valid)) {
    stop("Invalid signed joint-DP v2 backend receipt.", call. = FALSE)
  }
  signature_ok <- if (is.null(verifier)) {
    .dsvert_relay_verify_message(
      .dsvert_joint_dp_backend_message_v2(receipt),
      unname(context$pins[[receipt$peer_name]]), receipt$signature)
  } else {
    if (!is.function(verifier)) stop("Invalid joint-DP v2 verifier.", call. = FALSE)
    verifier(.dsvert_joint_dp_backend_message_v2(receipt),
             unname(context$pins[[receipt$peer_name]]), receipt$signature,
             receipt$peer_name)
  }
  if (!isTRUE(signature_ok)) {
    stop("Joint-DP v2 receipt signature verification failed.", call. = FALSE)
  }
  invisible(receipt)
}

.dsvert_joint_dp_backend_open_record_v2 <- function(
    policy, own_token, peer_token, secret, verifier) {
  tokens <- .dsvert_joint_dp_receipt_set(
    own_token, peer_token, policy, .DSVERT_JOINT_DP_OPEN_VERSION,
    "open_authorized", verifier)
  context <- .dsvert_joint_dp_policy_context(policy)
  common <- c("consortium_id", "query_id", "allocation_index", "new_chain",
              "joint_record_hash", "authorization_set_hash")
  if (!identical(tokens[[1L]][common], tokens[[2L]][common]) ||
      !identical(tokens[[context$peer_name]], own_token)) {
    stop("The two v1 opening receipts do not authorize one immutable allocation.",
         call. = FALSE)
  }
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_initialize_validate(handle$connection, policy, secret)
  record <- .dsvert_joint_dp_load(handle$connection, own_token$query_id, secret)
  if (is.null(record) || !identical(record$state, "open_authorized") ||
      !identical(record$opening_token, own_token)) {
    stop("The local v1 opening receipt is not durably authorized.", call. = FALSE)
  }
  list(tokens = tokens, record = record, context = context)
}

.dsvert_joint_dp_backend_private_seed_v2 <- function(policy, state) {
  if (!is.list(state) || !is.list(state$record)) {
    stop("Invalid joint-DP v2 private-seed state.", call. = FALSE)
  }
  seed_hex <- .dsvert_dp_noise_seed(
    policy, state$record$query_id,
    .dsvert_joint_dp_index(state$record$allocation_index),
    paste0("joint-mpc/", state$record$own_prepare$mechanism_hash),
    as.numeric(state$record$epsilon), as.numeric(state$record$delta),
    state$record$sensitivity)
  seed_raw <- .dsvert_joint_dp_backend_hex_raw_v2(seed_hex, "private seed")
  rm(seed_hex)
  seed_raw
}

.dsvert_joint_dp_backend_prepare_v2 <- function(
    policy, own_opening_token, peer_opening_token, source_contract,
    bernoulli_bits = 8L, max_steps = 4096L, .secret = NULL,
    .signer = NULL, .verifier = NULL,
    .planner = .dsvert_joint_dp_laplace_plan_v2) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  state <- .dsvert_joint_dp_backend_open_record_v2(
    policy, own_opening_token, peer_opening_token, .secret, .verifier)
  mechanism <- state$record$common_query$mechanism
  if (!identical(mechanism$mechanism,
                 "discrete-laplace-geometric-tv-v2") ||
      !identical(mechanism$mechanism_version, "joint-sampler-v2") ||
      !identical(mechanism$sensitivity_norm, "l1") ||
      !identical(mechanism$uses_delta, TRUE) ||
      as.numeric(state$record$delta) <= 0) {
    stop("The v1 allocation is not a delta-reserved Laplace-v2 proposal.",
         call. = FALSE)
  }
  source <- .dsvert_joint_dp_backend_source_v2(source_contract, mechanism)
  if (!is.function(.planner)) stop("Invalid joint-DP v2 planner.", call. = FALSE)
  plan <- .planner(
    state$record$epsilon, state$record$delta, source$sensitivity_steps,
    source$coordinate_count, bernoulli_bits, max_steps)
  source_hash <- .dsvert_joint_dp_hash(source)
  plan_hash <- .dsvert_joint_dp_hash(plan)
  token_hashes <- lapply(state$tokens, .dsvert_joint_dp_hash)
  transcript <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-backend-transcript-v2",
    consortium_id = state$context$consortium_id,
    query_id = state$record$query_id,
    allocation_index = state$record$allocation_index,
    ordered_v1_opening_token_hashes = token_hashes,
    ordered_peer_pinset = as.list(state$context$pins),
    source_contract = source, sampler_plan = plan))
  ordered <- .dsvert_joint_dp_backend_peers_v2(state$context)
  role <- if (identical(state$context$peer_name, ordered[[1L]])) {
    "garbler"
  } else {
    "evaluator"
  }
  commitment_context <- .dsvert_joint_dp_backend_commitment_context_v2(
    transcript, role, state$context$peer_name)
  seed_raw <- .dsvert_joint_dp_backend_private_seed_v2(policy, state)
  seed_commitment <- .dsvert_joint_dp_backend_hash_raw_v2(c(
    .dsvert_joint_dp_backend_hex_raw_v2(
      commitment_context, "commitment context"), seed_raw))
  rm(seed_raw)
  unsigned <- list(
    version = .DSVERT_JOINT_DP_BACKEND_PREPARE_V2,
    phase = "backend_prepared",
    consortium_id = state$context$consortium_id,
    peer_name = state$context$peer_name,
    peer_identity_pk = unname(state$context$pins[[state$context$peer_name]]),
    query_id = state$record$query_id,
    allocation_index = state$record$allocation_index,
    transcript_hash = transcript, role = role,
    commitment_context = commitment_context,
    seed_commitment_v2 = seed_commitment,
    source_contract_hash = source_hash, plan_hash = plan_hash,
    capability_available = FALSE,
    unavailable_reason = .DSVERT_JOINT_DP_BACKEND_UNAVAILABLE_V2)
  .dsvert_joint_dp_backend_sign_v2(unsigned, policy, .signer)
}

.dsvert_joint_dp_backend_token_v2 <- function(
    policy, left_prepare, right_prepare, .signer = NULL, .verifier = NULL) {
  .dsvert_joint_dp_backend_verify_v2(
    left_prepare, policy, .DSVERT_JOINT_DP_BACKEND_PREPARE_V2,
    "backend_prepared", .verifier)
  .dsvert_joint_dp_backend_verify_v2(
    right_prepare, policy, .DSVERT_JOINT_DP_BACKEND_PREPARE_V2,
    "backend_prepared", .verifier)
  context <- .dsvert_joint_dp_policy_context(policy)
  ordered <- .dsvert_joint_dp_backend_peers_v2(context)
  prepares <- list(left_prepare, right_prepare)
  names(prepares) <- vapply(prepares, `[[`, character(1L), "peer_name")
  if (anyDuplicated(names(prepares)) ||
      !setequal(names(prepares), ordered)) {
    stop("Joint-DP v2 requires one backend receipt from each designated peer.",
         call. = FALSE)
  }
  prepares <- prepares[ordered]
  common <- c("consortium_id", "query_id", "allocation_index",
              "transcript_hash", "source_contract_hash", "plan_hash")
  if (!identical(prepares[[1L]][common], prepares[[2L]][common]) ||
      !identical(unname(vapply(prepares, `[[`, character(1L), "role")),
                 c("garbler", "evaluator"))) {
    stop("The two joint-DP v2 backend receipts conflict.", call. = FALSE)
  }
  contexts_valid <- vapply(names(prepares), function(peer) {
    identical(
      prepares[[peer]]$commitment_context,
      .dsvert_joint_dp_backend_commitment_context_v2(
        prepares[[peer]]$transcript_hash, prepares[[peer]]$role, peer))
  }, logical(1L))
  if (!all(contexts_valid)) {
    stop("The joint-DP v2 seed commitment context conflicts with the pinned role.",
         call. = FALSE)
  }
  commitments <- lapply(prepares, `[[`, "seed_commitment_v2")
  prepare_set_hash <- .dsvert_joint_dp_hash(prepares)
  semantic_circuit_hash <- .dsvert_joint_dp_hash(list(
    template = .DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2,
    sampler = .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2,
    transcript_hash = prepares[[1L]]$transcript_hash,
    ordered_seed_commitments = commitments,
    source_contract_hash = prepares[[1L]]$source_contract_hash,
    plan_hash = prepares[[1L]]$plan_hash))
  unsigned <- list(
    version = .DSVERT_JOINT_DP_BACKEND_TOKEN_V2,
    phase = "backend_preflight_only",
    consortium_id = context$consortium_id,
    peer_name = context$peer_name,
    peer_identity_pk = unname(context$pins[[context$peer_name]]),
    query_id = prepares[[1L]]$query_id,
    allocation_index = prepares[[1L]]$allocation_index,
    transcript_hash = prepares[[1L]]$transcript_hash,
    prepare_set_hash = prepare_set_hash,
    ordered_seed_commitments = commitments,
    source_contract_hash = prepares[[1L]]$source_contract_hash,
    plan_hash = prepares[[1L]]$plan_hash,
    semantic_circuit_contract_hash = semantic_circuit_hash,
    worker_attestation_available = FALSE,
    capability_available = FALSE,
    unavailable_reason = .DSVERT_JOINT_DP_BACKEND_UNAVAILABLE_V2)
  .dsvert_joint_dp_backend_sign_v2(unsigned, policy, .signer)
}
