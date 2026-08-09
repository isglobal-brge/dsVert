# One-shot input binding for the exact Ring127 vecmul adapter.  Public slot
# names cross DSI, but their contents and all derived copies stay server-side.

.DSVERT_EXACT_GC_CHECKED_MUL_PURPOSE <-
  "k2.vecmul.mul-truncate.v3"
.DSVERT_EXACT_GC_CHECKED_MUL_PRODUCER <- "k2.vecmul.checked-product.v3"
.DSVERT_EXACT_GC_PROMOTED_VECMUL_PRODUCERS <- c(
  "dp.categorical-cross.v1", "dp.gaussian-cross.v1")
.DSVERT_EXACT_GC_CHECKED_MUL_CHUNK <- 256L
.DSVERT_EXACT_GC_VECMUL_MANIFEST_VERSION <-
  "dsvert-exact-gc-vecmul-manifest-v1"
.DSVERT_EXACT_GC_VECMUL_HANDLE_RE <- "^[A-Za-z0-9_-]{43}$"

.exact_gc_vecmul_compatibility_test_mode <- function() {
  # The installed binding ultimately resolves to the constant FALSE
  # `.dsvert_identity_test_mode()`. Package tests replace that private binding
  # to retain regression coverage for quarantined producers; production cannot.
  isTRUE(.dsvert_identity_test_mode())
}

.exact_gc_vecmul_promoted_producer_purpose <- function(producer, purpose) {
  if (!is.character(producer) || length(producer) != 1L || is.na(producer) ||
      !is.character(purpose) || length(purpose) != 1L || is.na(purpose)) {
    return(FALSE)
  }
  if (identical(producer, "dp.categorical-cross.v1")) {
    return(grepl(
      "^dp[.]categorical-cross[.][0-9a-f]{20}[.]cell-products$",
      purpose))
  }
  identical(producer, "dp.gaussian-cross.v1") && grepl(
    paste0(
      "^dp[.]gaussian-cross[.][0-9a-f]{20}[.]",
      "(validity-[0-9]{4}|masked-values|moments)$"),
    purpose)
}

.exact_gc_vecmul_require_promoted_stage <- function(stage) {
  if (isTRUE(.exact_gc_vecmul_compatibility_test_mode())) {
    return(invisible(stage))
  }
  if (!is.list(stage) ||
      !.exact_gc_vecmul_promoted_producer_purpose(
        stage$producer, stage$purpose) ||
      !is.character(stage$manifest_handle) ||
      length(stage$manifest_handle) != 1L ||
      !grepl(.DSVERT_EXACT_GC_VECMUL_HANDLE_RE, stage$manifest_handle)) {
    stop("The exact-gc multiplication capability is not promoted.",
         call. = FALSE)
  }
  invisible(stage)
}

.exact_gc_vecmul_require_promoted_manifest <- function(
    ss, manifest, manifest_handle) {
  if (isTRUE(.exact_gc_vecmul_compatibility_test_mode())) {
    return(invisible(manifest))
  }
  if (!.exact_gc_vecmul_promoted_producer_purpose(
        manifest$producer, manifest$purpose)) {
    stop("The exact-gc multiplication manifest is not promoted.",
         call. = FALSE)
  }
  record <- if (identical(
      manifest$producer, "dp.categorical-cross.v1")) {
    ss$.dp_categorical_cross_stage
  } else {
    ss$.dp_gaussian_cross_stage
  }
  valid <- is.list(record) && identical(record$status, "prepared") &&
    identical(record$producer, manifest$producer) &&
    identical(record$purpose, manifest$purpose) &&
    identical(record$manifest_handle, manifest_handle) &&
    identical(record$total_n, manifest$total_n) &&
    identical(record$ring_bits, manifest$ring_bits) &&
    identical(record$frac_bits, manifest$frac_bits) &&
    identical(record$x_key, manifest$x_key) &&
    identical(record$y_key, manifest$y_key) &&
    identical(record$output_key, manifest$output_key) &&
    is.list(record$minted) &&
    identical(record$minted$manifest_handle, manifest_handle) &&
    identical(record$minted$context_hash, manifest$context_hash) &&
    identical(record$minted$plan_id, manifest$plan_id)
  if (!isTRUE(valid)) {
    stop("The exact-gc multiplication producer capability is invalid.",
         call. = FALSE)
  }
  invisible(manifest)
}
.DSVERT_EXACT_GC_SOFTPLUS_INVOCATION_RE <- "^[0-9a-f]{32}$"

.exact_gc_glm_softplus_product <- function(stage, invocation_id) {
  stage <- as.integer(.exact_gc_integer(
    stage, "GLM softplus product stage", 0, 36))
  invocation_id <- .exact_gc_scalar(
    invocation_id, "GLM softplus invocation")
  if (!grepl(.DSVERT_EXACT_GC_SOFTPLUS_INVOCATION_RE, invocation_id)) {
    stop("Invalid GLM softplus invocation.", call. = FALSE)
  }
  tag <- invocation_id
  slots <- list(
    scaled = paste0("__r127_spy_", tag),
    two_scaled = paste0("__r127_sptwoY_", tag),
    state_b = paste0("__r127_spbB_", tag),
    state_a = paste0("__r127_spbA_", tag),
    constant = paste0("__r127_spconst_", tag),
    output = if (stage == 0L) paste0("__r127_spy_", tag) else
      sprintf("__r127_spmul%02d_%s", stage, tag))
  if (stage == 0L) {
    slots$x <- "k2_eta_share_fp"
    slots$y <- slots$constant
    slots$bound_x <- "9007199254740992" # 8 * 2^50
    slots$bound_y <- "140737488355328"  # (1 / 8) * 2^50
  } else if (stage <= 35L) {
    slots$x <- slots$two_scaled
    slots$y <- if (stage %% 2L == 1L) slots$state_b else slots$state_a
    slots$bound_x <- "2251799813685248"  # 2 * 2^50
    slots$bound_y <- "18014398509481984" # 16 * 2^50
  } else {
    slots$x <- slots$scaled
    # Thirty-five Clenshaw swaps leave state_a in the active B slot.
    slots$y <- slots$state_a
    slots$bound_x <- "1125899906842624"  # 1 * 2^50
    slots$bound_y <- "18014398509481984" # 16 * 2^50
  }
  slots$stage <- stage
  slots$invocation_id <- invocation_id
  slots$purpose <- sprintf(
    "glm.binomial-softplus.%s.step-%02d", invocation_id, stage)
  slots
}

.exact_gc_vecmul_validate_slot <- function(key, what) {
  key <- .exact_gc_scalar(key, what)
  if (nchar(key, type = "bytes") > 128L ||
      !grepl("^[A-Za-z_][A-Za-z0-9._]*$", key) ||
      startsWith(key, ".") || key %in% c("keys", "blobs") ||
      grepl("^(exact_gc_|k2_exact_vecmul_)", key)) {
    stop("Invalid exact-gc vecmul session slot.", call. = FALSE)
  }
  key
}

.exact_gc_vecmul_value_digest <- function(value) {
  if (is.null(value)) return("absent")
  digest::digest(value, algo = "sha256", serialize = FALSE)
}

.exact_gc_vecmul_public_hash <- function(value) {
  encoded <- charToRaw(as.character(jsonlite::toJSON(
    value, auto_unbox = TRUE, null = "null", digits = NA)))
  digest::digest(encoded, algo = "sha256", serialize = FALSE)
}

.exact_gc_vecmul_handle <- function() {
  value <- base64_to_base64url(jsonlite::base64_enc(
    .dsvert_secure_random_bytes(32L)))
  if (!grepl(.DSVERT_EXACT_GC_VECMUL_HANDLE_RE, value)) {
    stop("Could not generate an exact-gc manifest handle.", call. = FALSE)
  }
  value
}

.exact_gc_vecmul_manifest_policy <- function(producer, purpose,
                                              ss, allow_test = FALSE) {
  producer <- .exact_gc_validate_purpose(producer)
  purpose <- .exact_gc_validate_purpose(purpose)
  if (identical(producer, "glm.weighted-residual.v1")) {
    family <- ss$k2_weights_numeric_family
    if (!is.character(family) || length(family) != 1L ||
        !family %in% c("gaussian", "binomial", "poisson")) {
      stop("The GLM numeric provenance is unavailable.", call. = FALSE)
    }
    residual_bound <- switch(
      family,
      gaussian = "90071992547409920",   # 80 * 2^50
      binomial = "1125899906842624",    # 1 * 2^50
      poisson = "2361183241434822606848" # 2^71, > (1e6 + exp(5))*2^50
    )
    if (identical(purpose, "glm.weighted-residual")) {
      return(list(
        x_key = "k2_weights_share_fp",
        y_key = "k2_weight_residual_share_fp",
        output_key = "k2_weighted_residual_share_fp",
        bound_x = "112589990684262400", # 100 * 2^50
        bound_y = residual_bound,
        ring_bits = 127L, frac_bits = 50L))
    }
    if (identical(purpose, "glm.sqrt-weighted-residual")) {
      return(list(
        x_key = "k2_sqrt_weights_share_fp",
        y_key = "k2_weight_residual_share_fp",
        output_key = "k2_sqrt_weighted_residual_share_fp",
        bound_x = "11258999068426240", # 10 * 2^50
        bound_y = residual_bound,
        ring_bits = 127L, frac_bits = 50L))
    }
  }
  softplus_match <- regmatches(
    purpose,
    regexec(
      "^glm[.]binomial-softplus[.]([0-9a-f]{32})[.]step-([0-9]{2})$",
      purpose))[[1L]]
  if (identical(producer, "glm.binomial-softplus.v1") &&
      length(softplus_match) == 3L) {
    family <- ss$k2_numeric_family
    if (!identical(family, "binomial") ||
        !identical(as.integer(ss$k2_ring %||% 63L), 127L)) {
      stop("The Ring127 binomial GLM provenance is unavailable.",
           call. = FALSE)
    }
    invocation_id <- softplus_match[[2L]]
    stage <- suppressWarnings(as.integer(softplus_match[[3L]]))
    slots <- .exact_gc_glm_softplus_product(stage, invocation_id)
    if (!identical(slots$purpose, purpose)) {
      stop("The GLM softplus product stage is invalid.", call. = FALSE)
    }
    return(list(
      x_key = slots$x, y_key = slots$y, output_key = slots$output,
      bound_x = slots$bound_x, bound_y = slots$bound_y,
      ring_bits = 127L, frac_bits = 50L))
  }
  if (identical(producer, "chisq.cross.cell-product.v1")) {
    stage <- ss$.exact_gc_chisq_product
    if (!is.list(stage) || !identical(stage$status, "preparing") ||
        !identical(stage$purpose, purpose) ||
        !identical(stage$x_key, "k2_beaver_x") ||
        !identical(stage$y_key, "k2_beaver_y") ||
        !identical(stage$output_key, "k2_beaver_z")) {
      stop("The cross-contingency product provenance is unavailable.",
           call. = FALSE)
    }
    return(list(
      x_key = "k2_beaver_x", y_key = "k2_beaver_y",
      output_key = "k2_beaver_z",
      # A one-hot value is exactly either zero or 2^20 in Ring63.
      bound_x = "1048576", bound_y = "1048576",
      ring_bits = 63L, frac_bits = 20L))
  }
  if (identical(producer, .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER)) {
    stage <- ss$.dp_gaussian_cross_stage
    if (!is.list(stage) || !identical(stage$status, "preparing") ||
        !identical(stage$producer, producer) ||
        !identical(stage$purpose, purpose) ||
        !is.character(stage$x_key) || !is.character(stage$y_key) ||
        !is.character(stage$output_key) ||
        !identical(as.integer(stage$ring_bits), 128L) ||
        !is.numeric(stage$frac_bits) || length(stage$frac_bits) != 1L ||
        is.na(stage$frac_bits) || stage$frac_bits < 8L ||
        stage$frac_bits > 18L ||
        !is.character(stage$operand_bound) ||
        !grepl("^[1-9][0-9]*$", stage$operand_bound)) {
      stop("The cross-owner Gaussian exact-product provenance is unavailable.",
           call. = FALSE)
    }
    return(list(
      x_key = stage$x_key, y_key = stage$y_key,
      output_key = stage$output_key,
      bound_x = stage$operand_bound, bound_y = stage$operand_bound,
      ring_bits = 128L, frac_bits = as.integer(stage$frac_bits)))
  }
  if (identical(producer, .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER)) {
    stage <- ss$.dp_categorical_cross_stage
    if (!is.list(stage) || !identical(stage$status, "preparing") ||
        !identical(stage$producer, producer) ||
        !identical(stage$purpose, purpose) ||
        !is.character(stage$x_key) || !is.character(stage$y_key) ||
        !is.character(stage$output_key) ||
        !identical(as.integer(stage$ring_bits), 128L) ||
        !is.numeric(stage$frac_bits) || length(stage$frac_bits) != 1L ||
        is.na(stage$frac_bits) || stage$frac_bits < 8L ||
        stage$frac_bits > 18L ||
        !is.character(stage$operand_bound) ||
        !grepl("^[1-9][0-9]*$", stage$operand_bound)) {
      stop("The cross-owner categorical exact-product provenance is unavailable.",
           call. = FALSE)
    }
    return(list(
      x_key = stage$x_key, y_key = stage$y_key,
      output_key = stage$output_key,
      bound_x = stage$operand_bound, bound_y = stage$operand_bound,
      ring_bits = 128L, frac_bits = as.integer(stage$frac_bits)))
  }
  if (isTRUE(allow_test) && identical(producer, "test.vecmul.v1") &&
      identical(purpose, "test.vecmul")) {
    return(NULL)
  }
  stop("The exact-gc vecmul producer/purpose is not allowlisted.",
       call. = FALSE)
}

#' Mint one fixed-stage binomial softplus multiplication manifest (AGGREGATE)
#'
#' The analyst selects only the public Clenshaw stage. Operand, destination,
#' bounds, ring and purpose are fixed by this server producer.
#'
#' @param stage Integer from 0 through 36.
#' @param invocation_id CSPRNG-derived 32-character lowercase hexadecimal
#'   namespace shared by the two computation peers for this softplus call.
#' @param session_id Active Ring127 GLM session identifier.
#' @return Opaque one-shot manifest metadata; no session slot or share.
exactGCGLMSoftplusPrepareDS <- function(stage, invocation_id, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  slots <- .exact_gc_glm_softplus_product(stage, invocation_id)
  ss <- .S(session_id)
  if (!identical(ss$k2_numeric_family, "binomial") ||
      !identical(as.integer(ss$k2_ring %||% 63L), 127L) ||
      !is.numeric(ss$k2_x_n) || length(ss$k2_x_n) != 1L ||
      is.na(ss$k2_x_n) || !is.finite(ss$k2_x_n) ||
      ss$k2_x_n != floor(ss$k2_x_n) || ss$k2_x_n < 1) {
    stop("The Ring127 binomial GLM producer state is unavailable.",
         call. = FALSE)
  }
  .exact_gc_vecmul_mint_manifest(
    ss = ss, session_id = session_id,
    producer = "glm.binomial-softplus.v1", purpose = slots$purpose,
    total_n = as.integer(ss$k2_x_n))
}

.exact_gc_vecmul_manifest_mac <- function(ss, manifest) {
  secret <- .key_get("transport_sk", ss)
  if (!is.character(secret) || length(secret) != 1L || !nzchar(secret)) {
    stop("Exact-gc transport secret is unavailable.", call. = FALSE)
  }
  body <- manifest[setdiff(names(manifest), "mac")]
  digest::hmac(
    secret,
    .exact_gc_vecmul_public_hash(body),
    algo = "sha256", serialize = FALSE)
}

.exact_gc_vecmul_validate_manifest_mac <- function(ss, manifest) {
  expected <- .exact_gc_vecmul_manifest_mac(ss, manifest)
  if (!is.character(manifest$mac) || length(manifest$mac) != 1L ||
      !identical(manifest$mac, expected)) {
    stop("Exact-gc vecmul manifest authentication failed.", call. = FALSE)
  }
  invisible(TRUE)
}

# Internal only. A purpose-specific server producer calls this immediately
# after it creates the second operand. No remotely registered method accepts
# arbitrary slots, destinations, bounds, or purposes for manifest minting.
.exact_gc_vecmul_mint_manifest <- function(
    ss, session_id, producer, purpose, total_n,
    x_key = NULL, y_key = NULL, output_key = NULL,
    ring_bits = NULL, frac_bits = NULL, bound_x = NULL, bound_y = NULL,
    allow_test = FALSE) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid exact-gc producer session.", call. = FALSE)
  }
  .exact_gc_vecmul_party_context(ss)
  producer <- .exact_gc_validate_purpose(producer)
  purpose <- .exact_gc_validate_purpose(purpose)
  total_n <- as.integer(.exact_gc_integer(
    total_n, "exact-gc vecmul manifest length", 1, 2^31 - 1))
  fixed <- .exact_gc_vecmul_manifest_policy(
    producer, purpose, ss, allow_test = allow_test)
  if (!is.null(fixed)) {
    x_key <- fixed$x_key
    y_key <- fixed$y_key
    output_key <- fixed$output_key
    ring_bits <- fixed$ring_bits
    frac_bits <- fixed$frac_bits
    bound_x <- fixed$bound_x
    bound_y <- fixed$bound_y
  } else {
    if (!isTRUE(allow_test)) {
      stop("Invalid exact-gc producer policy.", call. = FALSE)
    }
  }
  x_key <- .exact_gc_vecmul_validate_slot(x_key, "exact-gc vecmul x slot")
  y_key <- .exact_gc_vecmul_validate_slot(y_key, "exact-gc vecmul y slot")
  output_key <- .exact_gc_vecmul_validate_slot(
    output_key, "exact-gc vecmul output slot")
  ring_bits <- as.integer(.exact_gc_integer(
    ring_bits, "exact-gc vecmul ring", 63,
    .DSVERT_EXACT_GC_MAX_RING_BITS))
  frac_bits <- as.integer(.exact_gc_integer(
    frac_bits, "exact-gc vecmul fractional bits", 0, ring_bits - 1L))
  bound_x <- .exact_gc_decimal_bound(bound_x, "exact-gc x bound")
  bound_y <- .exact_gc_decimal_bound(bound_y, "exact-gc y bound")
  x_share <- ss[[x_key]]
  y_share <- ss[[y_key]]
  if (is.null(x_share) || is.null(y_share)) {
    stop("Producer-bound exact-gc inputs are unavailable.", call. = FALSE)
  }
  .exact_gc_validate_residue_records(
    x_share, ring_bits, total_n, "producer-bound exact-gc x share")
  .exact_gc_validate_residue_records(
    y_share, ring_bits, total_n, "producer-bound exact-gc y share")
  if (!is.null(ss[[output_key]])) {
    stop("Producer-bound exact-gc destination is already in use.",
         call. = FALSE)
  }
  policy <- .dsvert_numeric_policy()
  if (!isTRUE(policy$enabled) || !grepl("^[0-9a-f]{64}$", policy$policy_id)) {
    stop("Exact-gc numeric policy is unavailable.", call. = FALSE)
  }
  plan <- .exact_gc_mul_plan(
    bound_x, bound_y, frac_bits, fixed_ring_bits = ring_bits)
  public <- list(
    version = .DSVERT_EXACT_GC_VECMUL_MANIFEST_VERSION,
    session_id = session_id, producer = producer, purpose = purpose,
    total_n = total_n, ring_bits = ring_bits, frac_bits = frac_bits,
    plan_id = plan$plan_id, numeric_policy_id = policy$policy_id,
    peer_binding_digest = ss$.exact_gc_peer_binding_digest)
  context_hash <- .exact_gc_vecmul_public_hash(public)
  handle <- .exact_gc_vecmul_handle()
  now <- as.numeric(Sys.time())
  manifest <- c(public, list(
    handle = handle, context_hash = context_hash,
    x_key = x_key, y_key = y_key, output_key = output_key,
    x_digest = .exact_gc_vecmul_value_digest(x_share),
    y_digest = .exact_gc_vecmul_value_digest(y_share),
    output_previous_digest = "absent",
    snapshot_digest = .exact_gc_vecmul_public_hash(list(
      session_id = session_id,
      peer_binding_digest = ss$.exact_gc_peer_binding_digest,
      numeric_policy_id = policy$policy_id,
      producer = producer, purpose = purpose,
      x_key = x_key, y_key = y_key, output_key = output_key,
      x_digest = .exact_gc_vecmul_value_digest(x_share),
      y_digest = .exact_gc_vecmul_value_digest(y_share),
      total_n = total_n, ring_bits = ring_bits, frac_bits = frac_bits,
      plan_id = plan$plan_id)),
    plan = list(
      version = plan$version, plan_id = plan$plan_id,
      ring_bits = plan$ring_bits, container_bits = plan$container_bits,
      frac_bits = plan$frac_bits, bound_x = plan$bound_x,
      bound_y = plan$bound_y, truncated_bound = plan$truncated_bound,
      rounding_mode = plan$rounding_mode,
      backend = plan$backend, max_chunk = plan$max_chunk,
      raw_product_headroom = plan$raw_product_headroom,
      output_headroom = plan$output_headroom),
    created_at = now, expires_at = now + .exact_gc_ttl_seconds(),
    state = "fresh", claimed_batch = NULL))
  manifest$mac <- .exact_gc_vecmul_manifest_mac(ss, manifest)
  if (is.null(ss$.exact_gc_vecmul_manifests)) {
    ss$.exact_gc_vecmul_manifests <- list()
  }
  ss$.exact_gc_vecmul_manifests[[handle]] <- manifest
  list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    manifest_handle = handle, context_hash = context_hash,
    plan_id = plan$plan_id, ring_bits = plan$ring_bits,
    frac_bits = plan$frac_bits, backend = plan$backend,
    bound_x = plan$bound_x, bound_y = plan$bound_y,
    max_chunk = plan$max_chunk, total_n = total_n,
    numeric_policy_id = policy$policy_id)
}

.exact_gc_vecmul_claim_manifest_impl <- function(
    manifest_handle, batch_operation_id, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  batch_operation_id <-
    .dsvert_relay_validate_operation_id(batch_operation_id)
  if (!is.character(manifest_handle) || length(manifest_handle) != 1L ||
      is.na(manifest_handle) ||
      !grepl(.DSVERT_EXACT_GC_VECMUL_HANDLE_RE, manifest_handle)) {
    stop("Invalid exact-gc vecmul manifest handle.", call. = FALSE)
  }
  ss <- .S(session_id)
  manifest <- ss$.exact_gc_vecmul_manifests[[manifest_handle]]
  if (is.null(manifest) ||
      !identical(manifest$version,
                 .DSVERT_EXACT_GC_VECMUL_MANIFEST_VERSION) ||
      !identical(manifest$session_id, session_id)) {
    stop("Exact-gc vecmul manifest is unavailable.", call. = FALSE)
  }
  .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
  .exact_gc_vecmul_require_promoted_manifest(
    ss, manifest, manifest_handle)
  if (identical(manifest$state, "claimed") &&
      identical(manifest$claimed_batch, batch_operation_id)) {
    stage <- ss$.exact_gc_vecmul_input_stages[[batch_operation_id]]
    if (is.null(stage) || !identical(stage$manifest_handle, manifest_handle)) {
      stop("Exact-gc vecmul manifest retry is inconsistent.", call. = FALSE)
    }
    return(list(
      capability_id = .DSVERT_EXACT_GC_CAPABILITY,
      state = "claimed", stored = TRUE,
      context_hash = stage$context_hash, policy_id = stage$policy_id,
      plan_id = stage$plan$plan_id, ring_bits = stage$plan$ring_bits,
      frac_bits = stage$plan$frac_bits, backend = stage$plan$backend,
      bound_x = stage$plan$bound_x, bound_y = stage$plan$bound_y,
      max_chunk = stage$plan$max_chunk))
  }
  if (!identical(manifest$state, "fresh") ||
      !is.numeric(manifest$expires_at) ||
      as.numeric(Sys.time()) > manifest$expires_at) {
    stop("Exact-gc vecmul manifest is expired or already consumed.",
         call. = FALSE)
  }
  .exact_gc_vecmul_party_context(ss)
  policy <- .dsvert_numeric_policy()
  x_share <- ss[[manifest$x_key]]
  y_share <- ss[[manifest$y_key]]
  plan <- .exact_gc_mul_plan(
    manifest$plan$bound_x, manifest$plan$bound_y,
    manifest$plan$frac_bits, fixed_ring_bits = manifest$plan$ring_bits)
  if (!identical(ss$.exact_gc_peer_binding_digest,
                 manifest$peer_binding_digest) ||
      !identical(policy$policy_id, manifest$numeric_policy_id) ||
      !identical(plan$plan_id, manifest$plan$plan_id) ||
      !identical(.exact_gc_vecmul_value_digest(x_share),
                 manifest$x_digest) ||
      !identical(.exact_gc_vecmul_value_digest(y_share),
                 manifest$y_digest) ||
      !identical(.exact_gc_vecmul_value_digest(ss[[manifest$output_key]]),
                 manifest$output_previous_digest)) {
    stop("Exact-gc vecmul manifest snapshot changed before claim.",
         call. = FALSE)
  }
  .exact_gc_validate_residue_records(
    x_share, plan$ring_bits, manifest$total_n,
    "producer-bound exact-gc x share")
  .exact_gc_validate_residue_records(
    y_share, plan$ring_bits, manifest$total_n,
    "producer-bound exact-gc y share")
  keys <- .exact_gc_checked_mul_keys(batch_operation_id)
  if (!is.null(ss[[keys$x]]) || !is.null(ss[[keys$y]])) {
    stop("Derived exact-gc vecmul batch state is already in use.",
         call. = FALSE)
  }
  installed <- FALSE
  on.exit(if (!installed) {
    ss[[keys$x]] <- NULL
    ss[[keys$y]] <- NULL
    if (!is.null(ss$.exact_gc_vecmul_input_stages)) {
      ss$.exact_gc_vecmul_input_stages[[batch_operation_id]] <- NULL
    }
  }, add = TRUE)
  batch_context <- list(
    version = "dsvert-exact-gc-vecmul-claim-v1",
    manifest_context_hash = manifest$context_hash,
    session_id = session_id, batch_operation_id = batch_operation_id,
    producer = manifest$producer, purpose = manifest$purpose,
    total_n = manifest$total_n, ring_bits = plan$ring_bits,
    frac_bits = plan$frac_bits, plan_id = plan$plan_id,
    numeric_policy_id = policy$policy_id)
  context_hash <- .exact_gc_vecmul_public_hash(batch_context)
  ss[[keys$x]] <- x_share
  ss[[keys$y]] <- y_share
  if (is.null(ss$.exact_gc_vecmul_input_stages)) {
    ss$.exact_gc_vecmul_input_stages <- list()
  }
  ss$.exact_gc_vecmul_input_stages[[batch_operation_id]] <- list(
    state = "staged", session_id = session_id,
    batch_operation_id = batch_operation_id,
    manifest_handle = manifest_handle, producer = manifest$producer,
    purpose = manifest$purpose, policy_id = policy$policy_id,
    output_key = manifest$output_key, total_n = manifest$total_n,
    context_hash = context_hash, plan = plan,
    output_previous_digest = manifest$output_previous_digest,
    output_digest = NULL)
  manifest$state <- "claimed"
  manifest$claimed_batch <- batch_operation_id
  manifest$mac <- .exact_gc_vecmul_manifest_mac(ss, manifest)
  ss$.exact_gc_vecmul_manifests[[manifest_handle]] <- manifest
  installed <- TRUE
  list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    state = "claimed", stored = TRUE, context_hash = context_hash,
    policy_id = policy$policy_id, plan_id = plan$plan_id,
    ring_bits = plan$ring_bits, frac_bits = plan$frac_bits,
    bound_x = plan$bound_x, bound_y = plan$bound_y,
    backend = plan$backend, max_chunk = plan$max_chunk)
}

#' Claim one server-minted exact multiplication manifest (AGGREGATE)
#'
#' @param manifest_handle Opaque one-shot handle minted by an approved input
#'   producer.
#' @param batch_operation_id Identifier for the complete multiplication batch.
#' @param session_id Active exact-GC session identifier.
#' @export
exactGCVecmulClaimInputsDS <- function(
    manifest_handle, batch_operation_id, session_id) {
  tryCatch(
    .exact_gc_vecmul_claim_manifest_impl(
      manifest_handle, batch_operation_id, session_id),
    error = function(e) stop("Exact MPC multiplication failed.",
                             call. = FALSE))
}

.exact_gc_vecmul_input_context <- function(session_id, batch_operation_id,
                                            x_key, y_key, output_key,
                                            total_n, policy_id) {
  context <- list(
    version = "dsvert-exact-gc-vecmul-input-v2",
    session_id = session_id, batch_operation_id = batch_operation_id,
    purpose = .DSVERT_EXACT_GC_CHECKED_MUL_PURPOSE,
    x_key = x_key, y_key = y_key, output_key = output_key,
    total_n = total_n, ring_bits = 127L, frac_bits = 50L,
    numeric_policy_id = policy_id)
  encoded <- charToRaw(as.character(jsonlite::toJSON(
    context, auto_unbox = TRUE, null = "null", digits = NA)))
  list(context = context, hash = digest::digest(
    encoded, algo = "sha256", serialize = FALSE))
}

.exact_gc_vecmul_party_context <- function(ss) {
  self_name <- ss$.exact_gc_self_name
  peer_names <- names(ss$peer_transport_pks)
  if (!isTRUE(ss$.exact_gc_transport_initialized) ||
      is.null(ss$.exact_gc_peer_binding_digest) ||
      !is.character(self_name) || length(self_name) != 1L ||
      length(peer_names) != 1L ||
      is.null(ss$.exact_gc_peer_identity_pks[[peer_names[[1L]]]])) {
    stop("Exact-gc vecmul requires one initialized pinned peer.",
         call. = FALSE)
  }
  list(self_name = self_name, peer_name = peer_names[[1L]])
}

.exact_gc_vecmul_local_mac <- function(ss, context_hash, x_share, y_share,
                                        output_previous_digest) {
  secret <- .key_get("transport_sk", ss)
  if (is.null(secret) || !is.character(secret) || length(secret) != 1L) {
    stop("Exact-gc transport secret is unavailable.", call. = FALSE)
  }
  material <- paste(
    context_hash,
    digest::digest(x_share, algo = "sha256", serialize = FALSE),
    digest::digest(y_share, algo = "sha256", serialize = FALSE),
    output_previous_digest, sep = "|")
  digest::hmac(secret, material, algo = "sha256", serialize = FALSE)
}

#' Bind one purpose-scoped Ring127 input manifest (AGGREGATE)
#'
#' @keywords internal
.exact_gc_vecmul_bind_inputs_impl <- function(
    x_key, y_key, output_key = "", total_n, batch_operation_id, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  batch_operation_id <-
    .dsvert_relay_validate_operation_id(batch_operation_id)
  total_n <- as.integer(.exact_gc_integer(
    total_n, "exact-gc vecmul input length", 1, 2^31 - 1))
  x_key <- .exact_gc_vecmul_validate_slot(x_key, "exact-gc vecmul x slot")
  y_key <- .exact_gc_vecmul_validate_slot(y_key, "exact-gc vecmul y slot")
  keys <- .exact_gc_checked_mul_keys(batch_operation_id)
  if (identical(output_key, "")) {
    output_key <- keys$destination
  } else {
    output_key <- .exact_gc_vecmul_validate_slot(
      output_key, "exact-gc vecmul output slot")
  }
  ss <- .S(session_id)
  .exact_gc_vecmul_party_context(ss)
  policy <- .dsvert_numeric_policy()
  if (!isTRUE(policy$enabled) || !is.character(policy$policy_id) ||
      length(policy$policy_id) != 1L ||
      !grepl("^[0-9a-f]{64}$", policy$policy_id)) {
    stop("Exact-gc numeric policy is unavailable.", call. = FALSE)
  }
  x_share <- ss[[x_key]]
  y_share <- ss[[y_key]]
  if (is.null(x_share) || is.null(y_share)) {
    stop("Bound Ring127 vecmul input is unavailable.", call. = FALSE)
  }
  .exact_gc_validate_residue_records(
    x_share, 127L, total_n, "exact-gc vecmul x share")
  .exact_gc_validate_residue_records(
    y_share, 127L, total_n, "exact-gc vecmul y share")
  public <- .exact_gc_vecmul_input_context(
    session_id, batch_operation_id, x_key, y_key, output_key, total_n,
    policy$policy_id)
  output_previous_digest <- .exact_gc_vecmul_value_digest(ss[[output_key]])
  if (!identical(output_previous_digest, "absent")) {
    stop("Exact-gc vecmul destination is already in use.", call. = FALSE)
  }
  local_mac <- .exact_gc_vecmul_local_mac(
    ss, public$hash, x_share, y_share, output_previous_digest)
  plan <- .exact_gc_mul_plan(
    "9223372036854775807", "9223372036854775807", 50L,
    fixed_ring_bits = 127L)
  if (is.null(ss$.exact_gc_vecmul_input_stages)) {
    ss$.exact_gc_vecmul_input_stages <- list()
  }
  previous <- ss$.exact_gc_vecmul_input_stages[[batch_operation_id]]
  if (!is.null(previous)) {
    if (!identical(previous$state, "staged")) {
      stop("Exact-gc vecmul input binding was already consumed.",
           call. = FALSE)
    }
    if (!identical(previous$context_hash, public$hash) ||
        !identical(previous$local_mac, local_mac)) {
      stop("Conflicting retry for exact-gc vecmul input binding.",
           call. = FALSE)
    }
    return(list(
      capability_id = .DSVERT_EXACT_GC_CAPABILITY,
      state = "bound", stored = TRUE, context_hash = public$hash,
      policy_id = policy$policy_id, plan_id = plan$plan_id,
      ring_bits = plan$ring_bits, frac_bits = plan$frac_bits,
      backend = plan$backend, bound_x = plan$bound_x,
      bound_y = plan$bound_y, max_chunk = plan$max_chunk))
  }
  if (!is.null(ss[[keys$x]]) || !is.null(ss[[keys$y]]) ||
      (identical(output_key, keys$destination) &&
       !is.null(ss[[output_key]]))) {
    stop("Derived exact-gc vecmul batch state is already in use.",
         call. = FALSE)
  }
  ss[[keys$x]] <- x_share
  ss[[keys$y]] <- y_share
  ss$.exact_gc_vecmul_input_stages[[batch_operation_id]] <- list(
    state = "staged", session_id = session_id,
    batch_operation_id = batch_operation_id,
    purpose = .DSVERT_EXACT_GC_CHECKED_MUL_PURPOSE,
    policy_id = policy$policy_id,
    producer = "legacy.remote-slot-bind.v2",
    x_key = x_key, y_key = y_key, output_key = output_key,
    total_n = total_n, context_hash = public$hash, local_mac = local_mac,
    plan = plan,
    output_previous_digest = output_previous_digest,
    output_digest = NULL)
  list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
       state = "bound", stored = TRUE, context_hash = public$hash,
       policy_id = policy$policy_id, plan_id = plan$plan_id,
       ring_bits = plan$ring_bits, frac_bits = plan$frac_bits,
       backend = plan$backend, bound_x = plan$bound_x,
       bound_y = plan$bound_y, max_chunk = plan$max_chunk)
}

exactGCVecmulBindInputsDS <- function(x_key, y_key, output_key = "",
                                      total_n, batch_operation_id,
                                      session_id) {
  tryCatch(
    .exact_gc_vecmul_bind_inputs_impl(
      x_key, y_key, output_key, total_n, batch_operation_id, session_id),
    error = function(e) stop("Exact MPC multiplication failed.",
                             call. = FALSE))
}
