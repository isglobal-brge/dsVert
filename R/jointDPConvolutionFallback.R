# Pre-promotion independent-full-draw joint-DP fallback.
#
# Each designated peer translates an already uniformly masked additive share
# by one complete, independently rooted DP draw.  No remote method calls these
# helpers and no capability flag is enabled.  A future joint finalizer must
# add exactly the two returned shares, signed-decode inside MPC, apply one
# fixed saturation, and reveal only that postprocessed release.

.DSVERT_JOINT_DP_CONVOLUTION_VERSION <-
  "dsvert-joint-dp-independent-full-draw-convolution-v1"
.DSVERT_JOINT_DP_CONVOLUTION_SOURCE_VERSION <-
  "dsvert-joint-dp-convolution-source-v1"
.DSVERT_JOINT_DP_CONVOLUTION_MASK_VERSION <-
  "dsvert-uniform-additive-mask-v1"
.DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL <-
  "uniform-additive-mod-2k-v1"
.DSVERT_JOINT_DP_CONVOLUTION_MECHANISM_VERSION <-
  "independent-full-draw-convolution-v1"
.DSVERT_JOINT_DP_CONVOLUTION_UNAVAILABLE <-
  "independent_full_draw_convolution_not_e2e_promoted"
.DSVERT_JOINT_DP_CONVOLUTION_LAPLACE_DELTA_FLOOR <- 2^-100
.DSVERT_JOINT_DP_CONVOLUTION_GAUSSIAN_TV_PER_COORDINATE <- 2^-40
.DSVERT_JOINT_DP_UNIFORM_SPLIT_VERSION <-
  "dsvert-joint-dp-uniform-split-ring128-v1"

.dsvert_joint_dp_convolution_integer_text <- function(
    value, signed = FALSE, what = "integer") {
  pattern <- if (isTRUE(signed)) "^(0|-?[1-9][0-9]*)$" else
    "^(0|[1-9][0-9]*)$"
  if (!is.character(value) || !length(value) || anyNA(value) ||
      any(nchar(value, type = "bytes") > 157L) ||
      any(!grepl(pattern, value))) {
    stop("Invalid joint-DP convolution ", what, ".", call. = FALSE)
  }
  unname(value)
}

.dsvert_joint_dp_convolution_mask_contract <- function(
    ring_bits, producer_attestation_hash) {
  if (!is.numeric(ring_bits) || length(ring_bits) != 1L ||
      is.na(ring_bits) || !is.finite(ring_bits) ||
      ring_bits != floor(ring_bits) || ring_bits < 128 || ring_bits > 512 ||
      !is.character(producer_attestation_hash) ||
      length(producer_attestation_hash) != 1L ||
      is.na(producer_attestation_hash) ||
      !grepl("^[0-9a-f]{64}$", producer_attestation_hash)) {
    stop("Invalid joint-DP convolution mask attestation.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_CONVOLUTION_MASK_VERSION,
    protocol = .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL,
    ring_bits = as.integer(ring_bits),
    conditional_min_entropy_bits = as.integer(ring_bits),
    independent_of_statistic = TRUE,
    generator = "os_csprng_uniform_rejection_mod_2k",
    seed_visibility = "generating_custodian_process_only",
    reuse = "forbidden_across_coordinates_snapshots_and_purposes",
    producer_attestation_hash = producer_attestation_hash))
}

.dsvert_joint_dp_convolution_source_contract <- function(
    producer, purpose, source_context_hash, capsule_release_id,
    ring_bits, frac_bits,
    statistic_lower_bounds, statistic_upper_bounds,
    producer_attestation_hash,
    release_lower_bounds = rep("-9007199254740991",
                               length(statistic_lower_bounds)),
    release_upper_bounds = rep("9007199254740991",
                               length(statistic_upper_bounds))) {
  scalar_id <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", value)
  }
  valid_ring <- is.numeric(ring_bits) && length(ring_bits) == 1L &&
    !is.na(ring_bits) && is.finite(ring_bits) &&
    ring_bits == floor(ring_bits) && ring_bits >= 128 && ring_bits <= 512
  if (!scalar_id(producer) || !scalar_id(purpose) || !isTRUE(valid_ring) ||
      !is.character(source_context_hash) ||
      length(source_context_hash) != 1L || is.na(source_context_hash) ||
      !grepl("^[0-9a-f]{64}$", source_context_hash) ||
      !is.character(capsule_release_id) ||
      length(capsule_release_id) != 1L || is.na(capsule_release_id) ||
      !grepl("^[0-9a-f]{64}$", capsule_release_id) ||
      !is.numeric(frac_bits) || length(frac_bits) != 1L ||
      is.na(frac_bits) || !is.finite(frac_bits) ||
      frac_bits != floor(frac_bits) || frac_bits < 0 ||
      frac_bits >= ring_bits) {
    stop("Invalid joint-DP convolution source identity.", call. = FALSE)
  }
  lower <- .dsvert_joint_dp_convolution_integer_text(
    statistic_lower_bounds, TRUE, "statistic lower bounds")
  upper <- .dsvert_joint_dp_convolution_integer_text(
    statistic_upper_bounds, TRUE, "statistic upper bounds")
  release_lower <- .dsvert_joint_dp_convolution_integer_text(
    release_lower_bounds, TRUE, "release lower bounds")
  release_upper <- .dsvert_joint_dp_convolution_integer_text(
    release_upper_bounds, TRUE, "release upper bounds")
  if (length(lower) != length(upper) || !length(lower) ||
      length(lower) != length(release_lower) ||
      length(lower) != length(release_upper) ||
      length(lower) > .DSVERT_DP_MAX_COORDINATES) {
    stop("Invalid joint-DP convolution source shape.", call. = FALSE)
  }
  mask <- .dsvert_joint_dp_convolution_mask_contract(
    ring_bits, producer_attestation_hash)
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_CONVOLUTION_SOURCE_VERSION,
    producer = producer, purpose = purpose,
    source_context_hash = source_context_hash,
    capsule_release_id = capsule_release_id,
    ring_bits = as.integer(ring_bits), frac_bits = as.integer(frac_bits),
    coordinate_count = length(lower),
    statistic_lower_bounds = as.list(lower),
    statistic_upper_bounds = as.list(upper),
    release_lower_bounds = as.list(release_lower),
    release_upper_bounds = as.list(release_upper),
    mask = mask))
}

# The capsule identifier is the hash of the complete immutable capsule
# contract, so it cannot also participate in the hash used *inside* that
# contract without creating a circular definition.  This projection commits
# every source property that affects sensitivity, clipping, shape and masking;
# the finalized source is additionally bound to the capsule ID at each wire
# and durable-state boundary.
.dsvert_joint_dp_convolution_source_binding_hash <- function(source) {
  if (!is.list(source) || is.null(names(source)) ||
      !"capsule_release_id" %in% names(source)) {
    stop("Invalid joint-DP convolution source binding.", call. = FALSE)
  }
  binding <- source[setdiff(names(source), "capsule_release_id")]
  .dsvert_joint_dp_hash(.dsvert_dp_canonical_query_value(list(
    protocol = "dsvert-joint-dp-convolution-source-binding-v1",
    source = binding)))
}

.dsvert_joint_dp_convolution_validate_source <- function(
    source, mechanism) {
  required <- c(
    "version", "producer", "purpose", "source_context_hash",
    "capsule_release_id", "ring_bits",
    "frac_bits", "coordinate_count", "statistic_lower_bounds",
    "statistic_upper_bounds", "release_lower_bounds",
    "release_upper_bounds", "mask")
  mask_fields <- c(
    "version", "protocol", "ring_bits", "conditional_min_entropy_bits",
    "independent_of_statistic", "generator", "seed_visibility", "reuse",
    "producer_attestation_hash")
  valid <- is.list(source) && !is.null(names(source)) &&
    !anyNA(names(source)) && !anyDuplicated(names(source)) &&
    setequal(names(source), required) && is.list(source$mask) &&
    !is.null(names(source$mask)) && !anyNA(names(source$mask)) &&
    !anyDuplicated(names(source$mask)) &&
    setequal(names(source$mask), mask_fields) &&
    identical(source$version,
              .DSVERT_JOINT_DP_CONVOLUTION_SOURCE_VERSION) &&
    identical(source$producer, mechanism$producer) &&
    identical(source$purpose, mechanism$purpose) &&
    identical(source$source_context_hash, mechanism$source_context_hash) &&
    is.character(source$capsule_release_id) &&
    length(source$capsule_release_id) == 1L &&
    grepl("^[0-9a-f]{64}$", source$capsule_release_id) &&
    identical(as.numeric(source$ring_bits), as.numeric(mechanism$ring_bits)) &&
    identical(as.numeric(source$frac_bits), as.numeric(mechanism$frac_bits)) &&
    identical(as.numeric(source$coordinate_count),
              as.numeric(mechanism$coordinate_count)) &&
    source$ring_bits >= 128 && source$ring_bits <= 512 &&
    identical(source$mask$version,
              .DSVERT_JOINT_DP_CONVOLUTION_MASK_VERSION) &&
    identical(source$mask$protocol,
              .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL) &&
    identical(as.numeric(source$mask$ring_bits),
              as.numeric(source$ring_bits)) &&
    identical(as.numeric(source$mask$conditional_min_entropy_bits),
              as.numeric(source$ring_bits)) &&
    identical(source$mask$independent_of_statistic, TRUE) &&
    identical(source$mask$generator,
              "os_csprng_uniform_rejection_mod_2k") &&
    identical(source$mask$seed_visibility,
              "generating_custodian_process_only") &&
    identical(source$mask$reuse,
              "forbidden_across_coordinates_snapshots_and_purposes") &&
    is.character(source$mask$producer_attestation_hash) &&
    length(source$mask$producer_attestation_hash) == 1L &&
    grepl("^[0-9a-f]{64}$", source$mask$producer_attestation_hash)
  if (!isTRUE(valid)) {
    stop("Invalid server-minted joint-DP convolution source contract.",
         call. = FALSE)
  }
  lower <- unlist(source$statistic_lower_bounds, use.names = FALSE)
  upper <- unlist(source$statistic_upper_bounds, use.names = FALSE)
  release_lower <- unlist(source$release_lower_bounds, use.names = FALSE)
  release_upper <- unlist(source$release_upper_bounds, use.names = FALSE)
  .dsvert_joint_dp_convolution_integer_text(
    lower, TRUE, "statistic lower bounds")
  .dsvert_joint_dp_convolution_integer_text(
    upper, TRUE, "statistic upper bounds")
  .dsvert_joint_dp_convolution_integer_text(
    release_lower, TRUE, "release lower bounds")
  .dsvert_joint_dp_convolution_integer_text(
    release_upper, TRUE, "release upper bounds")
  if (length(lower) != source$coordinate_count ||
      length(upper) != source$coordinate_count ||
      length(release_lower) != source$coordinate_count ||
      length(release_upper) != source$coordinate_count ||
      !identical(.dsvert_joint_dp_convolution_source_binding_hash(source),
                 mechanism$clipping_hash)) {
    stop("The joint-DP convolution source is not bound to the allocation.",
         call. = FALSE)
  }
  source
}

.dsvert_joint_dp_convolution_validate_output <- function(
    result, input, coordinate_count) {
  required <- c(
    "version", "backend", "capability_available",
    "payload_delivery_available", "unavailable_reason", "peer_name",
    "peer_identity_pk", "query_id", "capsule_release_id",
    "allocation_index",
    "source_contract_hash", "mask_contract_hash", "ring_bits", "frac_bits",
    "coordinate_count", "noised_shares", "mechanism", "sampler",
    "randomness", "capsule_epsilon", "capsule_delta",
    "delta_impl_sampler", "delta_mechanism", "delta_total",
    "full_capsule_parameters_per_peer",
    "epsilon_divided_by_peer_count", "designated_noise_peer_count",
    "mask_protocol", "mask_conditional_min_entropy_bits",
    "mask_contract_validation", "noise_lower_bound_per_peer",
    "noise_upper_bound_per_peer", "preclip_lower_bounds",
    "preclip_upper_bounds", "release_lower_bounds", "release_upper_bounds",
    "single_draw_marginal_95_abs", "convolution_marginal_95_abs",
    "convolution_simultaneous_95_abs", "accuracy_accounting",
    "nominal_variance_multiplier", "nominal_rmse_multiplier",
    "threat_model", "convolution_privacy_argument", "opening_contract",
    "utility_preferred_backend")
  exact_names <- is.list(result) && !is.null(names(result)) &&
    !anyNA(names(result)) && !anyDuplicated(names(result)) &&
    setequal(names(result), required)
  binding_fields <- c(
    "version", "peer_name", "peer_identity_pk", "query_id",
    "capsule_release_id", "allocation_index", "source_contract_hash",
    "mask_contract_hash",
    "ring_bits", "frac_bits", "mechanism", "capsule_epsilon",
    "capsule_delta")
  valid <- exact_names &&
    identical(result[binding_fields], input[binding_fields]) &&
    identical(result$backend, "independent_full_global_draw_convolution") &&
    identical(result$capability_available, FALSE) &&
    identical(result$payload_delivery_available, FALSE) &&
    identical(result$unavailable_reason,
              .DSVERT_JOINT_DP_CONVOLUTION_UNAVAILABLE) &&
    identical(as.numeric(result$coordinate_count),
              as.numeric(coordinate_count)) &&
    identical(result$randomness, "HMAC-SHA256/ChaCha20") &&
    identical(result$sampler, if (identical(
      input$mechanism, "granular_laplace_int64")) {
      "deterministic_two_sided_geometric"
    } else {
      "deterministic_symmetric_binomial"
    }) &&
    identical(result$full_capsule_parameters_per_peer, TRUE) &&
    identical(result$epsilon_divided_by_peer_count, FALSE) &&
    identical(as.numeric(result$designated_noise_peer_count), 2) &&
    identical(result$mask_protocol,
              .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL) &&
    identical(as.numeric(result$mask_conditional_min_entropy_bits),
              as.numeric(input$ring_bits)) &&
    identical(result$mask_contract_validation,
              "producer_attested_precondition; translation_preserves_uniformity") &&
    identical(result$noise_lower_bound_per_peer,
              "-9223372036854775808") &&
    identical(result$noise_upper_bound_per_peer,
              "9223372036854775807") &&
    identical(as.numeric(result$nominal_variance_multiplier), 2) &&
    isTRUE(all.equal(
      as.numeric(result$nominal_rmse_multiplier), sqrt(2), tolerance = 1e-15)) &&
    identical(result$utility_preferred_backend,
              "exact_gc_one_joint_noise_sample") &&
    identical(result$accuracy_accounting,
              "two_draw_union_bound; each component uses half the failure probability") &&
    identical(result$threat_model,
              "pinned_semi_honest_noncolluding; malicious_noise_contribution_not_covered") &&
    identical(result$convolution_privacy_argument,
              "under pinned semi-honest non-colluding execution, one hidden complete-capsule mechanism remains (epsilon,delta_total)-DP after independent additive post-processing; delta_total explicitly includes sampler approximation/support loss and never exceeds capsule_delta") &&
    identical(result$opening_contract,
              "inside one joint finalizer: sum exactly two purpose-bound raw-noised shares, signed-decode, apply exactly one source-bound fixed saturation, and reveal only that result") &&
    all(vapply(result[c(
      "delta_impl_sampler", "delta_mechanism", "delta_total")],
      function(value) {
        is.numeric(value) && length(value) == 1L && !is.na(value) &&
          is.finite(value) && value >= 0 && value < 1
      }, logical(1L))) &&
    identical(as.numeric(result$delta_total), as.numeric(
      result$delta_impl_sampler + result$delta_mechanism)) &&
    result$delta_total <= input$capsule_delta &&
    if (identical(input$mechanism, "granular_laplace_int64")) {
      identical(as.numeric(result$delta_mechanism), 0) &&
        result$delta_impl_sampler >=
          .DSVERT_JOINT_DP_CONVOLUTION_LAPLACE_DELTA_FLOOR
    } else {
      identical(as.numeric(result$delta_impl_sampler), as.numeric(
        coordinate_count *
          .DSVERT_JOINT_DP_CONVOLUTION_GAUSSIAN_TV_PER_COORDINATE)) &&
        result$delta_mechanism > 0
    }
  vector_fields <- c(
    "noised_shares", "preclip_lower_bounds", "preclip_upper_bounds",
    "release_lower_bounds", "release_upper_bounds",
    "single_draw_marginal_95_abs", "convolution_marginal_95_abs",
    "convolution_simultaneous_95_abs")
  if (isTRUE(valid)) {
    valid <- all(vapply(result[vector_fields], function(value) {
      is.character(value) && length(value) == coordinate_count &&
        !anyNA(value)
    }, logical(1L)))
  }
  if (!isTRUE(valid)) {
    stop("The joint-DP convolution backend returned an invalid contract.",
         call. = FALSE)
  }
  .dsvert_joint_dp_convolution_integer_text(
    result$noised_shares, FALSE, "noised shares")
  signed_fields <- c(
    "preclip_lower_bounds", "preclip_upper_bounds",
    "release_lower_bounds", "release_upper_bounds")
  for (field in signed_fields) {
    .dsvert_joint_dp_convolution_integer_text(
      result[[field]], TRUE, field)
  }
  for (field in setdiff(vector_fields, c("noised_shares", signed_fields))) {
    .dsvert_joint_dp_convolution_integer_text(
      result[[field]], FALSE, field)
  }
  expected_release_lower <- unlist(
    input$release_lower_bounds, use.names = FALSE)
  expected_release_upper <- unlist(
    input$release_upper_bounds, use.names = FALSE)
  if (!identical(result$release_lower_bounds, expected_release_lower) ||
      !identical(result$release_upper_bounds, expected_release_upper) ||
      any(c("seed", "noise_values", "statistic_values") %in%
          names(result))) {
    stop("The joint-DP convolution backend violated its opening envelope.",
         call. = FALSE)
  }
  result
}

.dsvert_joint_dp_convolution_share_provisional <- function(
    policy, own_opening_token, peer_opening_token, source_contract,
    additive_shares, .secret = NULL, .verifier = NULL, .sampler = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  state <- .dsvert_joint_dp_backend_open_record_v2(
    policy, own_opening_token, peer_opening_token, .secret, .verifier)
  mechanism <- state$record$common_query$mechanism
  mechanism_valid <- is.list(mechanism) &&
    identical(mechanism$sampler,
              .DSVERT_JOINT_DP_CONVOLUTION_SAMPLER) &&
    identical(mechanism$mechanism_version,
              .DSVERT_JOINT_DP_CONVOLUTION_MECHANISM_VERSION) &&
    mechanism$mechanism %in% c(
      "granular-laplace-int64", "approximate-gaussian-int64") &&
    identical(mechanism$sensitivity_norm,
      if (identical(mechanism$mechanism,
                    "granular-laplace-int64")) "l1" else "l2") &&
    identical(mechanism$uses_delta, TRUE)
  if (!isTRUE(mechanism_valid)) {
    stop("The authorized allocation is not an independent-full-draw convolution proposal.",
         call. = FALSE)
  }
  source <- .dsvert_joint_dp_convolution_validate_source(
    source_contract, mechanism)
  if (!identical(state$record$query_id, source$capsule_release_id) ||
      !identical(state$record$own_prepare$capsule_id,
                 source$capsule_release_id)) {
    stop("The wire query identity is not the authorized capsule release identity.",
         call. = FALSE)
  }
  shares <- .dsvert_joint_dp_convolution_integer_text(
    additive_shares, FALSE, "additive shares")
  if (length(shares) != source$coordinate_count) {
    stop("The additive share does not match the authorized source shape.",
         call. = FALSE)
  }
  epsilon <- as.numeric(state$record$epsilon)
  delta <- as.numeric(state$record$delta)
  sensitivity <- as.numeric(state$record$sensitivity)
  if (!is.finite(epsilon) || epsilon <= 0 || !is.finite(delta) || delta <= 0 ||
      !is.finite(sensitivity) || sensitivity <= 0 ||
      (identical(mechanism$mechanism, "granular-laplace-int64") &&
       (sensitivity != floor(sensitivity) ||
        sensitivity > .dsvert_dp_exact_integer_limit))) {
    stop("The global joint-DP allocation is not representable by the fallback.",
         call. = FALSE)
  }
  minimum_implementation_delta <- if (identical(
      mechanism$mechanism, "granular-laplace-int64")) {
    .DSVERT_JOINT_DP_CONVOLUTION_LAPLACE_DELTA_FLOOR
  } else {
    source$coordinate_count *
      .DSVERT_JOINT_DP_CONVOLUTION_GAUSSIAN_TV_PER_COORDINATE
  }
  underfunded <- if (identical(
      mechanism$mechanism, "granular-laplace-int64")) {
    delta < minimum_implementation_delta
  } else {
    delta <= minimum_implementation_delta
  }
  if (isTRUE(underfunded)) {
    stop("The global joint-DP delta allocation does not cover the sampler implementation delta before seed derivation.",
         call. = FALSE)
  }
  seed <- .dsvert_dp_noise_seed(
    policy, state$record$query_id,
    .dsvert_joint_dp_index(state$record$allocation_index),
    paste0("joint-mpc/", state$record$own_prepare$mechanism_hash),
    epsilon, delta, sensitivity)
  expected_commitment <- digest::digest(paste0(
    "dsVert/joint-dp/private-seed-commitment/v1|", seed),
    algo = "sha256", serialize = FALSE)
  if (!identical(expected_commitment,
                 state$record$own_prepare$seed_commitment)) {
    stop("The sticky fallback seed does not match the durable allocation commitment.",
         call. = FALSE)
  }
  lower <- unlist(source$statistic_lower_bounds, use.names = FALSE)
  upper <- unlist(source$statistic_upper_bounds, use.names = FALSE)
  release_lower <- unlist(source$release_lower_bounds, use.names = FALSE)
  release_upper <- unlist(source$release_upper_bounds, use.names = FALSE)
  input <- list(
    version = .DSVERT_JOINT_DP_CONVOLUTION_VERSION,
    peer_name = state$context$peer_name,
    peer_identity_pk = unname(
      state$context$pins[[state$context$peer_name]]),
    query_id = state$record$query_id,
    capsule_release_id = source$capsule_release_id,
    allocation_index = state$record$allocation_index,
    source_contract_hash = .dsvert_joint_dp_hash(source),
    mask_contract_hash = .dsvert_joint_dp_hash(source$mask),
    ring_bits = as.integer(source$ring_bits),
    frac_bits = as.integer(source$frac_bits),
    additive_shares = as.list(shares),
    statistic_lower_bounds = as.list(lower),
    statistic_upper_bounds = as.list(upper),
    release_lower_bounds = as.list(release_lower),
    release_upper_bounds = as.list(release_upper),
    mask_protocol = .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL,
    mask_conditional_min_entropy_bits = as.integer(source$ring_bits),
    mask_independent_of_statistic = TRUE,
    designated_noise_peer_count = 2L,
    mechanism = if (identical(
      mechanism$mechanism, "granular-laplace-int64")) {
      "granular_laplace_int64"
    } else {
      "approximate_gaussian_int64"
    },
    capsule_epsilon = epsilon, capsule_delta = delta,
    epsilons = if (identical(
      mechanism$mechanism, "granular-laplace-int64")) {
      as.list(rep(epsilon, source$coordinate_count))
    } else list(),
    sensitivities = if (identical(
      mechanism$mechanism, "granular-laplace-int64")) {
      as.list(rep(as.integer(sensitivity), source$coordinate_count))
    } else list(),
    l2_sensitivity = if (identical(
      mechanism$mechanism, "approximate-gaussian-int64")) sensitivity else 0,
    seed = seed)
  result <- if (is.null(.sampler)) {
    .callMpcTool("joint-dp-convolution-share-v1", input)
  } else {
    if (!is.function(.sampler)) {
      stop("Invalid internal joint-DP convolution sampler.", call. = FALSE)
    }
    .sampler(input)
  }
  input$seed <- NULL
  rm(seed)
  .dsvert_joint_dp_convolution_validate_output(
    result, input, source$coordinate_count)
}

.dsvert_joint_dp_uniform_split_ring128 <- function(
    count, query_id, allocation_index, source_contract,
    coordinate_index = 0, .splitter = NULL) {
  if (!is.numeric(count) || length(count) != 1L || is.na(count) ||
      !is.finite(count) || count < 0 ||
      count > .dsvert_dp_exact_integer_limit || count != floor(count) ||
      !is.character(query_id) || length(query_id) != 1L ||
      is.na(query_id) || !grepl("^[0-9a-f]{64}$", query_id) ||
      !is.list(source_contract) ||
      !identical(source_contract$version,
                 .DSVERT_JOINT_DP_CONVOLUTION_SOURCE_VERSION) ||
      !identical(query_id, source_contract$capsule_release_id) ||
      !identical(as.numeric(source_contract$ring_bits), 128) ||
      !is.list(source_contract$mask) ||
      !identical(source_contract$mask$protocol,
                 .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL) ||
      !identical(as.numeric(
        source_contract$mask$conditional_min_entropy_bits), 128)) {
    stop("Invalid purpose-bound Ring128 uniform split request.",
         call. = FALSE)
  }
  allocation_index <- .dsvert_joint_dp_index(
    allocation_index, "uniform split allocation index")
  coordinate_index <- .dsvert_joint_dp_index(
    coordinate_index, "uniform split coordinate index")
  if (coordinate_index >= as.numeric(source_contract$coordinate_count)) {
    stop("The uniform split coordinate is outside the source contract.",
         call. = FALSE)
  }
  input <- list(
    version = .DSVERT_JOINT_DP_UNIFORM_SPLIT_VERSION,
    query_id = query_id,
    capsule_release_id = source_contract$capsule_release_id,
    allocation_index = format(
      allocation_index, scientific = FALSE, trim = TRUE, digits = 22L),
    source_contract_hash = .dsvert_joint_dp_hash(source_contract),
    mask_contract_hash = .dsvert_joint_dp_hash(source_contract$mask),
    coordinate_index = format(
      coordinate_index, scientific = FALSE, trim = TRUE, digits = 22L),
    count = format(count, scientific = FALSE, trim = TRUE, digits = 22L))
  result <- if (is.null(.splitter)) {
    .callMpcTool("joint-ring128-source-split-v1", input)
  } else {
    if (!is.function(.splitter)) {
      stop("Invalid internal Ring128 split implementation.", call. = FALSE)
    }
    .splitter(input)
  }
  required <- c(
    "version", "capability_available", "unavailable_reason", "query_id",
    "capsule_release_id", "allocation_index", "source_contract_hash",
    "mask_contract_hash",
    "coordinate_index", "ring_bits", "left_share", "right_share",
    "mask_protocol", "mask_conditional_min_entropy_bits", "generator",
    "requires_durable_replay")
  binding <- c(
    "version", "query_id", "capsule_release_id", "allocation_index",
    "source_contract_hash", "mask_contract_hash", "coordinate_index")
  valid <- is.list(result) && !is.null(names(result)) &&
    !anyNA(names(result)) && !anyDuplicated(names(result)) &&
    setequal(names(result), required) &&
    identical(result[binding], input[binding]) &&
    identical(result$capability_available, FALSE) &&
    identical(result$unavailable_reason,
              .DSVERT_JOINT_DP_CONVOLUTION_UNAVAILABLE) &&
    identical(as.numeric(result$ring_bits), 128) &&
    identical(result$mask_protocol,
              .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL) &&
    identical(as.numeric(result$mask_conditional_min_entropy_bits), 128) &&
    identical(result$generator, "os_csprng_uniform_16_bytes") &&
    identical(result$requires_durable_replay, TRUE)
  if (!isTRUE(valid)) {
    stop("The Ring128 uniform split backend returned an invalid contract.",
         call. = FALSE)
  }
  shares <- .dsvert_joint_dp_convolution_integer_text(
    c(result$left_share, result$right_share), FALSE, "uniform split shares")
  maximum <- "340282366920938463463374607431768211455"
  in_ring <- vapply(shares, function(value) {
    nchar(value, type = "bytes") < nchar(maximum) ||
      (nchar(value, type = "bytes") == nchar(maximum) && value <= maximum)
  }, logical(1L))
  if (!all(in_ring) || "count" %in% names(result)) {
    stop("The Ring128 uniform split escaped its canonical residue contract.",
         call. = FALSE)
  }
  result
}
