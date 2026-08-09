# Purpose-bound scalable release of one immutable biomedical capsule vector.
#
# The analyst only relays signed receipts and encrypted, already-noised Ring128
# shares.  Exact source aggregates and sticky seeds are consumed by internal
# helpers and never appear on the AggregateMethods surface.  One durable final
# vector is committed in fixed public chunks under a Merkle root; replay reads
# only those DP chunks and never re-enters source materialization or sampling.

.DSVERT_JOINT_DP_VECTOR_PREPARE_VERSION <-
  "dsvert-joint-dp-vector-prepare-v6"
.DSVERT_JOINT_DP_VECTOR_START_VERSION <-
  "dsvert-joint-dp-vector-chunk-start-v5"
.DSVERT_JOINT_DP_VECTOR_RESULT_VERSION <-
  "dsvert-joint-dp-vector-local-result-v5"
.DSVERT_JOINT_DP_VECTOR_TRANSFER_VERSION <-
  "dsvert-joint-dp-vector-encrypted-noised-share-v3"
.DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION <-
  "dsvert-joint-dp-vector-release-root-v5"
.DSVERT_JOINT_DP_VECTOR_CHUNK_VERSION <-
  "dsvert-joint-dp-vector-final-chunk-v4"
.DSVERT_JOINT_DP_VECTOR_ACK_VERSION <-
  "dsvert-joint-dp-vector-finalization-ack-v5"
# v6 makes the authenticated per-capsule claim row and claim-set state required
# durable-store invariants.  Neither may be inferred by opening a v5 binding.
.DSVERT_JOINT_DP_VECTOR_STORE_VERSION <-
  "dsvert-joint-dp-vector-store-v6"
.DSVERT_JOINT_DP_VECTOR_INSTANCE_CLAIM_VERSION <-
  "dsvert-joint-dp-vector-instance-claim-v1"
.DSVERT_JOINT_DP_VECTOR_INSTANCE_CLAIM_STATE_VERSION <-
  "dsvert-joint-dp-vector-instance-claim-state-v1"
.DSVERT_JOINT_DP_VECTOR_RELEASE_LEDGER_BACKFILL_VERSION <-
  "dsvert-joint-dp-vector-release-ledger-backfill-v1"
.dsvert_joint_dp_vector_release_audit_cache <-
  new.env(parent = emptyenv())
.DSVERT_JOINT_DP_VECTOR_RELEASE_CONTRACT_VERSION <-
  "dsvert-joint-dp-vector-release-contract-v5"
.DSVERT_JOINT_DP_VECTOR_RELEASE_INSTANCE_VERSION <-
  "dsvert-joint-dp-vector-release-instance-v2"
.DSVERT_JOINT_DP_VECTOR_PLAN_VERSION <-
  "dsvert-joint-dp-vector-independent-full-draw-convolution-plan-v3"
.DSVERT_JOINT_DP_VECTOR_SAMPLER <-
  "hkdf-sha256-chacha20-independent-full-draw-binary-geometric-tv-v3"
.DSVERT_JOINT_DP_VECTOR_BACKEND <-
  "independent_full_global_draw_convolution_ring128_v3"
.DSVERT_JOINT_DP_VECTOR_EXACT_BACKEND <-
  "exact_gc_one_joint_discrete_laplace_draw_ring128_v3"
.DSVERT_JOINT_DP_VECTOR_EXACT_SAMPLER <-
  "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3"
.DSVERT_JOINT_DP_VECTOR_EXACT_RELEASE_MECHANISM <-
  "one-joint-complete-vector-discrete-laplace-draw-v3"
.DSVERT_JOINT_DP_VECTOR_RELEASE_MECHANISM <-
  "two-independent-complete-vector-discrete-laplace-draws-v3"
.DSVERT_JOINT_DP_VECTOR_INPUT_VERSION <-
  "dsvert-joint-dp-vector-independent-full-draw-convolution-input-v3"
.DSVERT_JOINT_DP_VECTOR_FINALIZER_INPUT_VERSION <-
  "dsvert-joint-dp-vector-independent-full-draw-finalizer-input-v3"
.DSVERT_JOINT_DP_VECTOR_FINALIZER_VERSION <-
  "dsvert-joint-dp-vector-independent-full-draw-finalizer-v3"
.DSVERT_JOINT_DP_GAUSSIAN_MECHANISM <-
  "dyadic_discrete_gaussian_truncated_tv_bounded"
.DSVERT_JOINT_DP_GAUSSIAN_PLAN_VERSION <-
  "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-plan-v2"
.DSVERT_JOINT_DP_GAUSSIAN_SAMPLER <-
  paste0("cks-target-outward-rational-dyadic-cdf-hkdf-sha256-",
         "chacha20-coordinate-domain-v2")
.DSVERT_JOINT_DP_GAUSSIAN_BACKEND <-
  paste0("independent_full_global_dyadic_discrete_gaussian_",
         "tv_bounded_ring128_v2")
.DSVERT_JOINT_DP_GAUSSIAN_RELEASE_MECHANISM <-
  paste0("two-independent-complete-vector-dyadic-discrete-gaussian-",
         "tv-bounded-draws-v2")
.DSVERT_JOINT_DP_GAUSSIAN_INPUT_VERSION <-
  "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-input-v2"
.DSVERT_JOINT_DP_GAUSSIAN_SHARE_VERSION <-
  "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-share-v2"
.DSVERT_JOINT_DP_GAUSSIAN_FINALIZER_INPUT_VERSION <-
  paste0("dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-",
         "finalizer-input-v2")
.DSVERT_JOINT_DP_GAUSSIAN_FINALIZER_VERSION <-
  paste0("dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-",
         "finalizer-v2")
.DSVERT_JOINT_DP_GAUSSIAN_COMMITMENT_PURPOSE <-
  "dyadic-discrete-gaussian-tv-bounded-v2"
.DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY <-
  "blob.joint-dp.vector-final-share.v3"
.DSVERT_JOINT_DP_VECTOR_TRANSFER_PRODUCER <-
  ".dsvert_joint_dp_vector_final_share_impl"
.DSVERT_JOINT_DP_VECTOR_TRANSFER_CONSUMER <-
  ".dsvert_joint_dp_vector_release_impl"
.DSVERT_JOINT_DP_VECTOR_CHUNK_COORDINATES <- 8192L
.DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES <- 2L * 1024L^2
.DSVERT_JOINT_DP_VECTOR_RETRY_CURRENT_INSTANCE_TOKEN <-
  "dsvert_retry_current_release_instance"

.dsvert_joint_dp_vector_profile <- function(mechanism, backend = NULL) {
  gaussian <- identical(mechanism, .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)
  if (!gaussian && !identical(mechanism, "discrete-laplace")) {
    stop("The biomedical vector mechanism is unsupported.", call. = FALSE)
  }
  if (gaussian) {
    list(
      gaussian = TRUE, exact_gc = FALSE, selection_bound = FALSE,
      plan_version = .DSVERT_JOINT_DP_GAUSSIAN_PLAN_VERSION,
      sampler = .DSVERT_JOINT_DP_GAUSSIAN_SAMPLER,
      backend = .DSVERT_JOINT_DP_GAUSSIAN_BACKEND,
      release_mechanism = .DSVERT_JOINT_DP_GAUSSIAN_RELEASE_MECHANISM,
      input_version = .DSVERT_JOINT_DP_GAUSSIAN_INPUT_VERSION,
      share_version = .DSVERT_JOINT_DP_GAUSSIAN_SHARE_VERSION,
      finalizer_input_version =
        .DSVERT_JOINT_DP_GAUSSIAN_FINALIZER_INPUT_VERSION,
      finalizer_version = .DSVERT_JOINT_DP_GAUSSIAN_FINALIZER_VERSION,
      commitment_purpose = .DSVERT_JOINT_DP_GAUSSIAN_COMMITMENT_PURPOSE,
      plan_command = "joint-dp-vector-gaussian-plan-v2",
      share_command = "joint-dp-vector-gaussian-share-v2",
      finalizer_command = "joint-dp-vector-gaussian-finalize-v2",
      delta_aggregation = "max_per_peer_not_sum",
      postprocessing =
        "signed-Ring128-decode-then-fixed-public-coordinate-clamp-v1")
  } else if (is.null(backend) || identical(
      backend, .DSVERT_JOINT_DP_VECTOR_EXACT_BACKEND)) {
    list(
      gaussian = FALSE, exact_gc = TRUE, selection_bound = TRUE,
      plan_version = "dsvert-joint-dp-vector-laplace-plan-v3",
      sampler = .DSVERT_JOINT_DP_VECTOR_EXACT_SAMPLER,
      backend = .DSVERT_JOINT_DP_VECTOR_EXACT_BACKEND,
      release_mechanism =
        .DSVERT_JOINT_DP_VECTOR_EXACT_RELEASE_MECHANISM,
      input_version = "dsvert-joint-dp-vector-worker-contract-input-v3",
      share_version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_COMMIT_VERSION,
      finalizer_input_version =
        "dsvert-joint-dp-vector-exact-gc-finalizer-input-v1",
      finalizer_version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_FINAL_VERSION,
      commitment_purpose = "one-draw-exact-gc",
      plan_command = "joint-dp-vector-laplace-plan-v3",
      share_command = NULL, finalizer_command = NULL,
      delta_aggregation = "single_joint_draw",
      postprocessing = paste0(
        "fixed-public-coordinate-clamp-inside-exact-GC-before-",
        "selective-sharing-v1"))
  } else if (identical(backend, .DSVERT_JOINT_DP_VECTOR_BACKEND)) {
    list(
      gaussian = FALSE, exact_gc = FALSE, selection_bound = TRUE,
      plan_version = .DSVERT_JOINT_DP_VECTOR_PLAN_VERSION,
      sampler = .DSVERT_JOINT_DP_VECTOR_SAMPLER,
      backend = .DSVERT_JOINT_DP_VECTOR_BACKEND,
      release_mechanism = .DSVERT_JOINT_DP_VECTOR_RELEASE_MECHANISM,
      input_version = .DSVERT_JOINT_DP_VECTOR_INPUT_VERSION,
      share_version =
        "dsvert-joint-dp-vector-independent-full-draw-convolution-share-v3",
      finalizer_input_version =
        .DSVERT_JOINT_DP_VECTOR_FINALIZER_INPUT_VERSION,
      finalizer_version = .DSVERT_JOINT_DP_VECTOR_FINALIZER_VERSION,
      commitment_purpose = "convolution",
      plan_command = "joint-dp-vector-convolution-plan-v3",
      share_command = "joint-dp-vector-convolution-share-v3",
      finalizer_command = "joint-dp-vector-convolution-finalize-v3",
      delta_aggregation = "max_per_peer_not_sum",
      postprocessing =
        "signed-Ring128-decode-then-fixed-public-coordinate-clamp-v1")
  } else {
    stop("The biomedical vector backend is unsupported.", call. = FALSE)
  }
}

.dsvert_joint_dp_vector_call_planner <- function(planner, command, input) {
  if (is.null(planner)) return(.callMpcTool(command, input))
  if (is.function(planner)) return(planner(input))
  candidate <- if (is.list(planner)) planner[[command]] else NULL
  if (!is.function(candidate)) {
    stop("Invalid joint-DP vector planner.", call. = FALSE)
  }
  candidate(input)
}

.dsvert_joint_dp_vector_scalar <- function(value, what,
                                             pattern = NULL,
                                             maximum_bytes = 512L) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes ||
      (!is.null(pattern) && !grepl(pattern, value))) {
    stop("Invalid joint-DP vector ", what, ".", call. = FALSE)
  }
  enc2utf8(value)
}

.dsvert_joint_dp_vector_index <- function(value, what, minimum = 0,
                                            maximum = 2^31 - 1) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < minimum ||
      value > maximum) {
    stop("Invalid joint-DP vector ", what, ".", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_joint_dp_vector_integer_text <- function(value, what,
                                                   positive = FALSE) {
  pattern <- if (isTRUE(positive)) "^[1-9][0-9]*$" else
    "^(0|[1-9][0-9]*)$"
  .dsvert_joint_dp_vector_scalar(
    value, what, pattern = pattern, maximum_bytes = 64L)
}

.dsvert_joint_dp_vector_raw_hex <- function(value, what) {
  .dsvert_joint_dp_backend_hex_raw_v2(
    .dsvert_joint_dp_vector_scalar(
      value, what, "^[0-9a-f]{64}$", 64L), what)
}

.dsvert_joint_dp_vector_context <- function(
    transcript_hash, peer_name, purpose = "convolution") {
  peer_name <- .dsvert_validate_logical_peer_name(peer_name)
  purpose <- .dsvert_joint_dp_vector_scalar(
    purpose, "commitment purpose", "^[a-z0-9-]{1,128}$", 128L)
  digest::digest(c(
    charToRaw("dsvert-joint-dp-private-seed-commitment-v2"), as.raw(0L),
    .dsvert_joint_dp_vector_raw_hex(transcript_hash, "transcript hash"),
    as.raw(0L), charToRaw(purpose), as.raw(0L),
    charToRaw(peer_name)), algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_vector_seed_commitment <- function(context, seed_hex) {
  digest::digest(c(
    .dsvert_joint_dp_vector_raw_hex(context, "commitment context"),
    .dsvert_joint_dp_vector_raw_hex(seed_hex, "private seed")),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_vector_chunk_geometry <- function(contract, chunk_index) {
  chunk_index <- .dsvert_joint_dp_vector_index(
    chunk_index, "chunk index", 0, contract$chunk_count - 1)
  offset <- chunk_index * contract$chunk_coordinates
  count <- min(contract$chunk_coordinates,
               contract$coordinate_count - offset)
  list(index = as.integer(chunk_index), offset = as.integer(offset),
       count = as.integer(count))
}

.dsvert_joint_dp_vector_lattice_vectors <- function(validated) {
  manifest <- validated$manifest
  layout <- validated$layout
  workload <- manifest$workload
  lattice <- workload$release_lattice
  required_lattice <- c(
    "version", "transform_rule", "output_lattice_bits",
    "output_lattice_scale", "natural_l1_sensitivity",
    "integer_l1_sensitivity_steps", "natural_l2_sensitivity",
    "integer_l2_sensitivity_steps")
  valid <- is.list(lattice) && !is.null(names(lattice)) &&
    !anyNA(names(lattice)) && !anyDuplicated(names(lattice)) &&
    setequal(names(lattice), required_lattice) &&
    identical(lattice$version,
              "biomedical-capsule-common-lattice-v1") &&
    identical(lattice$transform_rule,
              "raw_coordinate_left_shift_to_common_numeric_grid_v1")
  if (!isTRUE(valid)) {
    stop("The biomedical capsule release lattice is invalid.", call. = FALSE)
  }
  bits <- .dsvert_joint_dp_vector_index(
    lattice$output_lattice_bits, "output lattice bits", 1, 62)
  scale <- 2^bits
  if (!identical(as.numeric(lattice$output_lattice_scale), scale) ||
      !is.finite(scale) || scale != floor(scale)) {
    stop("The biomedical capsule lattice scale is invalid.", call. = FALSE)
  }
  coordinate_count <- layout$coordinate_count
  shifts <- rep(as.integer(bits), coordinate_count)
  upper <- numeric(coordinate_count)
  for (block in layout$blocks) {
    indices <- seq.int(block$start, block$end)
    if (identical(block$family, "numeric_moments")) {
      if (length(indices) != 3L) {
        stop("The numeric-moment lattice block is invalid.", call. = FALSE)
      }
      shifts[indices] <- c(as.integer(bits), 0L, 0L)
      bound <- unname(as.numeric(block$descriptor$statistic_maximum))
      if (length(bound) != 3L) {
        stop("The numeric-moment bounds are invalid.", call. = FALSE)
      }
      upper[indices] <- bound
    } else if (identical(block$family, "numeric_pair_moments")) {
      if (length(indices) != 6L) {
        stop("The numeric-pair lattice block is invalid.", call. = FALSE)
      }
      shifts[indices] <- c(as.integer(bits), rep(0L, 5L))
      bound <- unname(as.numeric(block$descriptor$statistic_maximum))
      if (length(bound) != 6L) {
        stop("The numeric-pair bounds are invalid.", call. = FALSE)
      }
      upper[indices] <- bound
    } else if (identical(block$family, "gaussian_models")) {
      # Cross-owner v2 artifacts are already emitted on the common lattice,
      # including n. Legacy/same-owner blocks still need n shifted once.
      already_scaled <- identical(
        block$descriptor$source_coordinate_scaling,
        "all_coordinates_already_on_common_numeric_lattice_v1")
      shifts[indices] <- if (already_scaled) {
        rep(0L, length(indices))
      } else {
        c(as.integer(bits), rep(0L, length(indices) - 1L))
      }
      bound <- unname(as.numeric(block$descriptor$statistic_maximum))
      if (length(bound) != length(indices)) {
        stop("The Gaussian-model bounds are invalid.", call. = FALSE)
      }
      upper[indices] <- bound
    } else if (identical(block$family, "categorical_pairs") &&
               identical(
                 block$descriptor$version,
                 "fixed-domain-categorical-cross-contingency-v1")) {
      shifts[indices] <- rep(0L, length(indices))
      bound <- unname(as.numeric(block$descriptor$statistic_maximum))
      if (length(bound) != length(indices)) {
        stop("The cross-owner categorical bounds are invalid.",
             call. = FALSE)
      }
      upper[indices] <- bound
    } else {
      bound <- if (identical(block$family, "categorical_pairs")) {
        sets <- workload$families$categorical_pairs$sets
        left <- block$descriptor$left$column
        right <- block$descriptor$right$column
        matching <- names(sets)[vapply(sets, function(set) {
          columns <- vapply(set$columns, `[[`, character(1L), "column")
          identical(set$owner_peer, block$owner_peer) &&
            identical(set$dataset, block$dataset) &&
            all(c(left, right) %in% columns)
        }, logical(1L))]
        if (length(matching) != 1L) {
          stop("A categorical-pair coordinate bound is ambiguous.",
               call. = FALSE)
        }
        sets[[matching]]$statistic_maximum
      } else {
        block$descriptor$statistic_maximum
      }
      if (!is.numeric(bound) || length(bound) != 1L || is.na(bound) ||
          !is.finite(bound) || bound < 0 || bound != floor(bound)) {
        stop("A biomedical capsule coordinate bound is invalid.",
             call. = FALSE)
      }
      upper[indices] <- bound
    }
  }
  if (anyNA(upper) || any(!is.finite(upper)) || any(upper < 0) ||
      any(upper != floor(upper)) ||
      any(upper * 2^shifts > .dsvert_dp_exact_integer_limit)) {
    stop("A scaled biomedical capsule coordinate is not exactly representable.",
         call. = FALSE)
  }

  families <- workload$families
  numeric_pair_count <- length(families$numeric_pair_moments$artifacts)
  numeric_pair_natural_l1 <- 6 * numeric_pair_count
  if (!is.finite(numeric_pair_natural_l1) ||
      !identical(
        as.numeric(families$numeric_pair_moments$natural_l1_sensitivity),
        as.numeric(numeric_pair_natural_l1))) {
    stop("The numeric-pair lattice sensitivity is inconsistent.",
         call. = FALSE)
  }
  gaussian_natural_l1 <- sum(vapply(
    families$gaussian_models$artifacts, function(artifact) {
      as.numeric(artifact$coordinate_count)
    }, numeric(1L)))
  if (!is.finite(gaussian_natural_l1) || !identical(
        as.numeric(families$gaussian_models$natural_l1_sensitivity),
        as.numeric(gaussian_natural_l1))) {
    stop("The Gaussian-model lattice sensitivity is inconsistent.",
         call. = FALSE)
  }
  natural_l1 <- as.numeric(families$admitted_count$l1_sensitivity) +
    3 * length(families$numeric_moments$artifacts) +
    numeric_pair_natural_l1 +
    gaussian_natural_l1 +
    as.numeric(families$fixed_numeric_histograms$l1_sensitivity) +
    as.numeric(families$categorical_marginals$l1_sensitivity) +
    as.numeric(families$categorical_pairs$l1_sensitivity) +
    sum(vapply(families$survival_artifacts, function(artifact) {
      as.numeric(artifact$l1_sensitivity)
    }, numeric(1L)))
  integer_l1 <- natural_l1 * scale
  mechanism <- workload$capsule_mechanism
  integer_l2 <- as.numeric(lattice$integer_l2_sensitivity_steps)
  gaussian <- identical(
    mechanism$mechanism, .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)
  selected_sensitivity <- if (gaussian) integer_l2 else integer_l1
  selected_norm <- if (gaussian) "l2" else "l1"
  if (!is.finite(integer_l1) || integer_l1 <= 0 ||
      integer_l1 != floor(integer_l1) ||
      !is.finite(integer_l2) || integer_l2 <= 0 ||
      !identical(as.numeric(lattice$natural_l1_sensitivity), natural_l1) ||
      !identical(as.numeric(lattice$integer_l1_sensitivity_steps),
                 integer_l1) ||
      !identical(as.numeric(workload$sensitivity$l1), integer_l1) ||
      !identical(as.numeric(workload$sensitivity$l2), integer_l2) ||
      !identical(as.numeric(mechanism$sensitivity), selected_sensitivity) ||
      !identical(mechanism$sensitivity_norm, selected_norm) ||
      !identical(as.numeric(mechanism$ring_bits), 128) ||
      !identical(as.numeric(mechanism$frac_bits), 0)) {
    stop("The biomedical capsule global lattice sensitivity is inconsistent.",
         call. = FALSE)
  }
  upper_text <- vapply(upper, function(value) {
    format(value, scientific = FALSE, trim = TRUE, digits = 22L)
  }, character(1L))
  sensitivity_text <- format(
    selected_sensitivity, scientific = gaussian, trim = TRUE, digits = 17L)
  list(
    output_lattice_bits = as.integer(bits),
    output_lattice_scale = scale, scale_shifts = shifts,
    raw_upper_bounds = upper_text,
    sensitivity_norm = selected_norm,
    sensitivity_steps = sensitivity_text,
    l1_sensitivity_steps = format(
      integer_l1, scientific = FALSE, trim = TRUE, digits = 22L),
    l2_sensitivity_steps = format(
      integer_l2, scientific = TRUE, trim = TRUE, digits = 17L),
    transform_sha256 = .dsvert_joint_dp_hash(list(
      version = lattice$version, transform_rule = lattice$transform_rule,
      output_lattice_bits = as.integer(bits),
      scale_shifts = as.list(shifts),
      raw_upper_bounds = as.list(upper_text),
      sensitivity_norm = selected_norm,
      sensitivity_steps = sensitivity_text)))
}

.dsvert_joint_dp_vector_plan_validate <- function(plan, contract,
                                                   request = NULL) {
  if (identical(contract$mechanism,
                .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)) {
    validated <- .dsvert_dp_capsule_exact_gaussian_plan_validate(
      plan, contract$coordinate_count, request)
    if (!identical(plan$version, contract$profile$plan_version) ||
        !identical(plan$sampler, contract$profile$sampler) ||
        !identical(plan$mechanism, contract$mechanism)) {
      stop("The joint-DP Gaussian plan targets a different mechanism.",
           call. = FALSE)
    }
    return(invisible(validated))
  }
  if (isTRUE(contract$profile$exact_gc)) {
    required <- c(
      "version", "sampler", "stop_bits", "stop_numerator",
      "uniform_bits", "binary_geometric_bits", "bernoulli_thresholds",
      "sensitivity_steps", "total_coordinate_count",
      "epsilon_effective_upper_numerator",
      "epsilon_effective_upper_denominator",
      "one_geometric_tv_numerator", "one_geometric_tv_denominator",
      "tail_upper_numerator", "tail_upper_denominator",
      "rounding_upper_numerator", "rounding_upper_denominator",
      "implementation_delta_numerator",
      "implementation_delta_denominator", "implementation_delta_bound",
      "maximum_noise_magnitude", "maximum_chunk_coordinates",
      "private_stream_bytes_per_coordinate", "accounting",
      "capability_available")
    integer_fields <- c(
      "stop_numerator", "sensitivity_steps",
      "epsilon_effective_upper_numerator",
      "epsilon_effective_upper_denominator",
      "one_geometric_tv_numerator", "one_geometric_tv_denominator",
      "tail_upper_numerator", "tail_upper_denominator",
      "rounding_upper_numerator", "rounding_upper_denominator",
      "implementation_delta_numerator",
      "implementation_delta_denominator", "maximum_noise_magnitude")
    thresholds <- unlist(plan$bernoulli_thresholds, use.names = FALSE)
    valid <- is.list(plan) && !is.null(names(plan)) && !anyNA(names(plan)) &&
      !anyDuplicated(names(plan)) && setequal(names(plan), required) &&
      identical(plan$version, contract$profile$plan_version) &&
      identical(plan$sampler, contract$profile$sampler) &&
      identical(as.numeric(plan$total_coordinate_count),
                as.numeric(contract$coordinate_count)) &&
      identical(plan$sensitivity_steps, contract$sensitivity_steps) &&
      identical(as.numeric(plan$stop_bits), 128) &&
      as.numeric(plan$uniform_bits) %in% c(128, 256) &&
      is.numeric(plan$binary_geometric_bits) &&
      length(plan$binary_geometric_bits) == 1L &&
      !is.na(plan$binary_geometric_bits) &&
      plan$binary_geometric_bits >= 1 &&
      plan$binary_geometric_bits <= 63 &&
      length(thresholds) == as.numeric(plan$binary_geometric_bits) &&
      is.character(thresholds) &&
      all(grepl("^(0|[1-9][0-9]*)$", thresholds)) &&
      all(vapply(plan[integer_fields], function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          grepl("^(0|[1-9][0-9]*)$", value)
      }, logical(1L))) &&
      is.numeric(plan$maximum_chunk_coordinates) &&
      identical(as.numeric(plan$maximum_chunk_coordinates),
                as.numeric(contract$chunk_coordinates)) &&
      plan$maximum_chunk_coordinates >= 1 &&
      plan$maximum_chunk_coordinates <= 128 &&
      is.numeric(plan$private_stream_bytes_per_coordinate) &&
      length(plan$private_stream_bytes_per_coordinate) == 1L &&
      !is.na(plan$private_stream_bytes_per_coordinate) &&
      is.finite(plan$private_stream_bytes_per_coordinate) &&
      plan$private_stream_bytes_per_coordinate > 0 &&
      plan$private_stream_bytes_per_coordinate ==
        floor(plan$private_stream_bytes_per_coordinate) &&
      is.character(plan$implementation_delta_bound) &&
      length(plan$implementation_delta_bound) == 1L &&
      !is.na(plan$implementation_delta_bound) &&
      is.character(plan$accounting) && length(plan$accounting) == 1L &&
      startsWith(plan$accounting, "global iid discrete Laplace") &&
      identical(plan$capability_available, TRUE)
    if (!isTRUE(valid)) {
      stop("The one-draw exact-GC vector planner returned an invalid certificate.",
           call. = FALSE)
    }
    assessment <- .dsvert_joint_dp_vector_exact_gc_plan_assessment(
      contract$manifest_sha256, plan)
    if (!identical(assessment$plan_sha256,
                   .dsvert_joint_dp_hash(plan))) {
      stop("The one-draw exact-GC plan assessment is inconsistent.",
           call. = FALSE)
    }
    return(invisible(.dsvert_dp_canonical_query_value(plan)))
  }
  required <- c(
    "version", "sampler", "stop_bits", "stop_numerator", "uniform_bits",
    "binary_geometric_bits", "bernoulli_thresholds", "sensitivity_steps",
    "total_coordinate_count", "epsilon_effective_upper_numerator",
    "epsilon_effective_upper_denominator", "one_geometric_tv_numerator",
    "one_geometric_tv_denominator", "tail_upper_numerator",
    "tail_upper_denominator", "rounding_upper_numerator",
    "rounding_upper_denominator", "implementation_delta_numerator",
    "implementation_delta_denominator", "implementation_delta_bound",
    "maximum_noise_magnitude", "maximum_chunk_coordinates",
    "private_stream_bytes_per_coordinate", "accounting",
    "capability_available", "independent_noise_peer_count",
    "complete_epsilon_per_peer", "epsilon_divided_by_peer_count",
    "geometric_variables_per_peer_per_coordinate",
    "geometric_variables_total_per_coordinate",
    "per_peer_implementation_delta_numerator",
    "per_peer_implementation_delta_denominator",
    "per_peer_implementation_delta_bound",
    "release_implementation_delta_aggregation",
    "two_peer_ideal_transfer_delta_numerator",
    "two_peer_ideal_transfer_delta_denominator",
    "two_peer_ideal_transfer_delta_bound", "threat_model",
    "privacy_argument")
  integer_fields <- c(
    "stop_numerator", "sensitivity_steps",
    "epsilon_effective_upper_numerator",
    "epsilon_effective_upper_denominator", "one_geometric_tv_numerator",
    "one_geometric_tv_denominator", "tail_upper_numerator",
    "tail_upper_denominator", "rounding_upper_numerator",
    "rounding_upper_denominator", "implementation_delta_numerator",
    "implementation_delta_denominator", "maximum_noise_magnitude",
    "per_peer_implementation_delta_numerator",
    "per_peer_implementation_delta_denominator",
    "two_peer_ideal_transfer_delta_numerator",
    "two_peer_ideal_transfer_delta_denominator")
  valid <- is.list(plan) && !is.null(names(plan)) && !anyNA(names(plan)) &&
    !anyDuplicated(names(plan)) && setequal(names(plan), required) &&
    identical(plan$version, .DSVERT_JOINT_DP_VECTOR_PLAN_VERSION) &&
    identical(plan$sampler, .DSVERT_JOINT_DP_VECTOR_SAMPLER) &&
    identical(as.numeric(plan$total_coordinate_count),
              as.numeric(contract$coordinate_count)) &&
    identical(plan$sensitivity_steps, contract$sensitivity_steps) &&
    identical(as.numeric(plan$independent_noise_peer_count), 2) &&
    identical(as.numeric(plan$geometric_variables_per_peer_per_coordinate), 2) &&
    identical(as.numeric(plan$geometric_variables_total_per_coordinate), 4) &&
    identical(plan$complete_epsilon_per_peer, TRUE) &&
    identical(plan$epsilon_divided_by_peer_count, FALSE) &&
    identical(plan$release_implementation_delta_aggregation,
              "max_per_peer_not_sum") &&
    identical(plan$capability_available, TRUE) &&
    identical(as.numeric(plan$maximum_chunk_coordinates),
              as.numeric(min(.DSVERT_JOINT_DP_VECTOR_CHUNK_COORDINATES,
                             contract$coordinate_count))) &&
    all(vapply(plan[integer_fields], function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^(0|[1-9][0-9]*)$", value)
    }, logical(1L))) &&
    identical(plan$implementation_delta_numerator,
              plan$per_peer_implementation_delta_numerator) &&
    identical(plan$implementation_delta_denominator,
              plan$per_peer_implementation_delta_denominator) &&
    (is.list(plan$bernoulli_thresholds) ||
       is.character(plan$bernoulli_thresholds)) &&
    length(plan$bernoulli_thresholds) ==
      as.numeric(plan$binary_geometric_bits)
  if (!isTRUE(valid)) {
    stop("The joint-DP vector planner returned an invalid certificate.",
         call. = FALSE)
  }
  invisible(.dsvert_dp_canonical_query_value(plan))
}

.dsvert_joint_dp_vector_release_instance <- function(
    policy, manifest, designated, release_instance_json,
    require_active_local_root = TRUE, active_release_domain = NULL) {
  if (!is.logical(require_active_local_root) ||
      length(require_active_local_root) != 1L ||
      is.na(require_active_local_root)) {
    stop("Invalid release-instance root-validation mode.", call. = FALSE)
  }
  value <- .dsvert_joint_dp_vector_decode_json(
    release_instance_json, "release-instance contract")
  if (is.null(active_release_domain) &&
      !is.null(policy$release_domain)) {
    active_release_domain <- .dsvert_joint_dp_release_domain_validate(
      policy$release_domain)
  }
  fields <- c("version", "capsule_id", "peer_noise_roots")
  roots <- value$peer_noise_roots
  valid_root <- function(root) {
    is.list(root) && !is.null(names(root)) &&
      !anyNA(names(root)) && !anyDuplicated(names(root)) &&
      setequal(names(root), c(
        "privacy_epoch", "noise_key_id", "provider_id",
        "release_domain_generation", "release_domain_id")) &&
      is.numeric(root$privacy_epoch) && length(root$privacy_epoch) == 1L &&
      !is.na(root$privacy_epoch) && is.finite(root$privacy_epoch) &&
      root$privacy_epoch >= 1 && root$privacy_epoch <= 2^53 - 1 &&
      root$privacy_epoch == floor(root$privacy_epoch) &&
      is.character(root$noise_key_id) && length(root$noise_key_id) == 1L &&
      !is.na(root$noise_key_id) && nzchar(root$noise_key_id) &&
      nchar(root$noise_key_id, type = "bytes") <= 256L &&
      is.character(root$provider_id) && length(root$provider_id) == 1L &&
      !is.na(root$provider_id) && nzchar(root$provider_id) &&
      nchar(root$provider_id, type = "bytes") <= 256L &&
      is.numeric(root$release_domain_generation) &&
      length(root$release_domain_generation) == 1L &&
      !is.na(root$release_domain_generation) &&
      is.finite(root$release_domain_generation) &&
      root$release_domain_generation >= 1 &&
      root$release_domain_generation <= 2^53 - 1 &&
      root$release_domain_generation ==
        floor(root$release_domain_generation) &&
      is.character(root$release_domain_id) &&
      length(root$release_domain_id) == 1L &&
      !is.na(root$release_domain_id) &&
      grepl("^rd_[0-9a-f]{64}$", root$release_domain_id)
  }
  local_domain_valid <- is.list(active_release_domain) &&
    identical(active_release_domain$version,
              .DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION) &&
    is.numeric(active_release_domain$generation) &&
    length(active_release_domain$generation) == 1L &&
    is.character(active_release_domain$domain_id) &&
    length(active_release_domain$domain_id) == 1L
  active_local_root <- is.list(roots) &&
    is.list(roots[[policy$peer_name]]) &&
    identical(as.numeric(roots[[policy$peer_name]]$privacy_epoch),
              as.numeric(policy$noise_root$epoch)) &&
    identical(roots[[policy$peer_name]]$noise_key_id,
              policy$noise_root$key_id) &&
    identical(roots[[policy$peer_name]]$provider_id,
              policy$noise_root$provider_id) &&
    isTRUE(local_domain_valid) &&
    identical(
      as.numeric(roots[[policy$peer_name]]$release_domain_generation),
      as.numeric(active_release_domain$generation)) &&
    identical(roots[[policy$peer_name]]$release_domain_id,
              active_release_domain$domain_id)
  structurally_valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) &&
    identical(value$version,
              .DSVERT_JOINT_DP_VECTOR_RELEASE_INSTANCE_VERSION) &&
    identical(value$capsule_id, manifest$capsule_identity$capsule_id) &&
    is.list(roots) && !is.null(names(roots)) &&
    !anyNA(names(roots)) && !anyDuplicated(names(roots)) &&
    identical(names(roots), designated) &&
    all(vapply(roots, valid_root, logical(1L))) &&
    !anyDuplicated(vapply(
      roots, `[[`, character(1L), "noise_key_id"))
  valid <- isTRUE(structurally_valid) &&
    (!isTRUE(require_active_local_root) || isTRUE(active_local_root))
  if (!isTRUE(valid)) {
    duplicated_root <- is.list(roots) && length(roots) == 2L &&
      all(vapply(roots, function(root) {
        is.list(root) && is.character(root$noise_key_id) &&
          length(root$noise_key_id) == 1L
      }, logical(1L))) &&
      identical(roots[[1L]]$noise_key_id, roots[[2L]]$noise_key_id)
    if (isTRUE(duplicated_root)) {
      stop(structure(list(
        message = paste(
          "The two designated peers advertise the same noise-root key ID;",
          "the server administrator must delete and regenerate only the",
          "duplicated peer's privacy/noise_root, then retry."),
        call = NULL, code = "noise_root_not_independent"),
        class = c("dsvert_noise_root_not_independent", "error",
                  "condition")))
    }
    if (isTRUE(structurally_valid) &&
        isTRUE(require_active_local_root) &&
        !isTRUE(active_local_root)) {
      stale <- .dsvert_dp_canonical_query_value(value)
      .dsvert_joint_dp_vector_retry_current_instance(
        list(value = stale, id = .dsvert_joint_dp_hash(stale)),
        action = "new_release_instance",
        reason = "the signed release instance uses a superseded local root")
    }
    stop("The joint-DP vector release instance is invalid or stale.",
         call. = FALSE)
  }
  value <- .dsvert_dp_canonical_query_value(value)
  list(
    value = value,
    json = .dsvert_dp_canonical_json(value),
    id = .dsvert_joint_dp_hash(value))
}

# This signal is an internal pre-claim retry route. The client refreshes both
# signed roots and the immutable manifest, then retries the complete handshake
# once. After the first valid START claims an instance, only that exact instance
# may continue or be restored; a sibling candidate fails closed.
.dsvert_joint_dp_vector_retry_current_instance <- function(
    instance, action = "new_release_instance",
    reason = "the durable final vector is unavailable") {
  if (!action %in% c(
      "new_release_instance", "retry_unpublished_instance")) {
    stop("Invalid joint-DP vector retry action.", call. = FALSE)
  }
  reason <- .dsvert_joint_dp_vector_scalar(
    reason, "release recovery reason", maximum_bytes = 512L,
    pattern = NULL)
  stop(structure(list(
    message = paste(
      paste0("[", .DSVERT_JOINT_DP_VECTOR_RETRY_CURRENT_INSTANCE_TOKEN,
             ":", action, "]"),
      reason,
      "The client must refresh the pinned peers' current roots and retry",
      "the complete vector handshake once."),
    call = NULL,
    code = .DSVERT_JOINT_DP_VECTOR_RETRY_CURRENT_INSTANCE_TOKEN,
    retry_action = action,
    capsule_id = instance$value$capsule_id,
    release_instance_id = instance$id),
    class = c("dsvert_dp_release_retry_current_instance", "error",
              "condition")))
}

.dsvert_joint_dp_vector_release_was_published <- function(
    policy, secret, release_instance_id) {
  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
    audit <- .dsvert_joint_dp_release_ledger_audit(
      connection, config, secret)
    any(vapply(audit$records, function(record) {
      identical(record$release_instance_id, release_instance_id)
    }, logical(1L)))
  })
}

.dsvert_joint_dp_vector_active_release_domain <- function(policy, secret) {
  if (!is.null(policy$release_domain)) {
    return(.dsvert_joint_dp_release_domain_validate(
      policy$release_domain))
  }
  .dsvert_joint_dp_release_domain_current(policy, secret)
}

.dsvert_joint_dp_vector_local_root_is_active <- function(
    policy, instance, active_release_domain) {
  root <- if (is.list(instance) && is.list(instance$value) &&
              is.list(instance$value$peer_noise_roots)) {
    instance$value$peer_noise_roots[[policy$peer_name]]
  } else NULL
  is.list(root) &&
    identical(as.numeric(root$privacy_epoch),
              as.numeric(policy$noise_root$epoch)) &&
    identical(root$noise_key_id, policy$noise_root$key_id) &&
    identical(root$provider_id, policy$noise_root$provider_id) &&
    is.list(active_release_domain) &&
    identical(as.numeric(root$release_domain_generation),
              as.numeric(active_release_domain$generation)) &&
    identical(root$release_domain_id, active_release_domain$domain_id)
}

.dsvert_joint_dp_vector_instance_from_receipts <- function(
    first_json, second_json) {
  values <- lapply(list(first_json, second_json), function(json) {
    receipt <- .dsvert_joint_dp_vector_decode_json(json, "instance receipt")
    instance <- receipt$release_instance
    id <- receipt$release_instance_id
    if (!is.list(instance) || !is.character(id) || length(id) != 1L ||
        is.na(id) || !grepl("^[0-9a-f]{64}$", id) ||
        !identical(.dsvert_joint_dp_hash(instance), id)) {
      stop("The signed vector receipts have no valid release instance.",
           call. = FALSE)
    }
    list(value = instance, id = id)
  })
  if (!identical(values[[1L]], values[[2L]])) {
    stop("The signed vector receipts disagree on the release instance.",
         call. = FALSE)
  }
  .dsvert_dp_canonical_json(values[[1L]]$value)
}

.dsvert_joint_dp_vector_contract <- function(
    policy, manifest_json, release_instance_json,
    planner = NULL, secret = NULL) {
  .dsvert_dp_capsule_manifest_require_built(
    policy, manifest_json, secret = secret)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(validated)
  source <- .dsvert_dp_capsule_source_contract_json(policy, manifest_json)
  source_contract <- .dsvert_dp_capsule_source_contract_validate(
    source$contract)
  designated <- .dsvert_dp_capsule_source_names(
    source_contract$designated_noise_peers, "noise-peer list")
  if (length(designated) != 2L || anyDuplicated(designated) ||
      !identical(designated, sort(designated, method = "radix"))) {
    stop("The joint-DP vector requires two ordered designated peers.",
         call. = FALSE)
  }
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  local_designated <- policy$peer_name %in% designated
  active_release_domain <- if (isTRUE(local_designated)) {
    .dsvert_joint_dp_vector_active_release_domain(policy, secret)
  } else NULL
  release_instance <- .dsvert_joint_dp_vector_release_instance(
    policy, manifest, designated, release_instance_json,
    require_active_local_root = local_designated,
    active_release_domain = active_release_domain)
  declared_epsilon <- .dsvert_joint_dp_decimal(
    policy$global_total_epsilon, "vector epsilon", 0, 8,
    open_minimum = TRUE)
  declared_delta <- .dsvert_joint_dp_decimal(
    policy$global_total_delta, "vector delta", 0, 1,
    open_minimum = TRUE)
  mechanism <- validated$manifest$workload$capsule_mechanism$mechanism
  profile <- .dsvert_joint_dp_vector_profile(mechanism)
  manifest_sha256 <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  plan_input <- if (profile$gaussian) {
    .dsvert_dp_capsule_exact_gaussian_request(
      as.numeric(policy$global_total_epsilon),
      as.numeric(policy$global_total_delta),
      as.numeric(lattice$l2_sensitivity_steps),
      validated$layout$coordinate_count)
  } else {
    list(
      epsilon = declared_epsilon, delta = declared_delta,
      sensitivity_steps = lattice$l1_sensitivity_steps,
      total_coordinate_count =
        as.integer(validated$layout$coordinate_count))
  }
  epsilon <- plan_input$epsilon
  delta <- plan_input$delta
  assessment <- NULL
  backend_selection <- NULL
  if (isTRUE(profile$gaussian)) {
    plan <- .dsvert_joint_dp_vector_call_planner(
      planner, profile$plan_command, plan_input)
  } else {
    exact_profile <- .dsvert_joint_dp_vector_profile(
      mechanism, .DSVERT_JOINT_DP_VECTOR_EXACT_BACKEND)
    exact_plan <- .dsvert_joint_dp_vector_call_planner(
      planner, exact_profile$plan_command, plan_input)
    choice <- .dsvert_joint_dp_vector_public_backend_choice(
      validated$layout$coordinate_count)
    assessment <- .dsvert_joint_dp_vector_exact_gc_plan_assessment(
      manifest_sha256, exact_plan, choice)
    backend_selection <- .dsvert_joint_dp_vector_exact_gc_selection(
      manifest_sha256, assessment)
    profile <- .dsvert_joint_dp_vector_profile(
      mechanism, backend_selection$backend)
    plan <- if (isTRUE(profile$exact_gc)) exact_plan else {
      .dsvert_joint_dp_vector_call_planner(
        planner, profile$plan_command, plan_input)
    }
  }
  plan_hash <- .dsvert_joint_dp_hash(plan)
  chunk_coordinates <- if (isTRUE(profile$exact_gc)) {
    .dsvert_joint_dp_vector_exact_gc_integer(
      plan$maximum_chunk_coordinates,
      "exact-GC vector chunk capacity", 1L, 128L)
  } else {
    .DSVERT_JOINT_DP_VECTOR_CHUNK_COORDINATES
  }
  provisional <- c(list(
    version = .DSVERT_JOINT_DP_VECTOR_RELEASE_CONTRACT_VERSION,
    capsule_id = validated$identity$capsule_id,
    release_instance_id = release_instance$id,
    release_instance = release_instance$value,
    manifest_sha256 = manifest_sha256,
    source_contract_hash = source$contract_hash,
    source_context_hash = source_contract$source_context_hash,
    coordinate_order_sha256 = validated$layout$sha256,
    lattice_transform_sha256 = lattice$transform_sha256,
    coordinate_count = as.integer(validated$layout$coordinate_count),
    chunk_coordinates = chunk_coordinates,
    chunk_count = as.integer(ceiling(
      validated$layout$coordinate_count /
        chunk_coordinates)),
    ring_bits = 128L, frac_bits = 0L,
    output_lattice_bits = lattice$output_lattice_bits,
    output_lattice_scale = lattice$output_lattice_scale,
    mechanism = mechanism,
    sensitivity_norm = lattice$sensitivity_norm,
    sensitivity_steps = if (profile$gaussian) {
      plan_input$l2_sensitivity_steps
    } else lattice$sensitivity_steps,
    epsilon = epsilon, allocated_delta = delta,
    sampler = profile$sampler,
    backend = profile$backend,
    designated_noise_peers = as.list(designated),
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    privacy_delta_aggregation = profile$delta_aggregation,
    history_gate = TRUE, request_limit = FALSE,
    operation_limit = TRUE), if (isTRUE(profile$selection_bound)) list(
      backend_assessment = assessment,
      backend_selection = backend_selection,
      backend_selection_sha256 = backend_selection$selection_sha256,
      one_joint_draw = backend_selection$one_draw) else list())
  .dsvert_joint_dp_vector_plan_validate(
    plan, c(provisional, list(profile = profile)), plan_input)
  if (profile$gaussian) {
    selection <- validated$manifest$workload$mechanism_selection
    if (!identical(
          .dsvert_dp_canonical_query_value(
            selection$gaussian_calibration_request),
          .dsvert_dp_canonical_query_value(plan_input)) ||
        !identical(selection$gaussian_plan_sha256, plan_hash)) {
      stop(paste0(
        "The joint-DP Gaussian contract does not match the fixed-work plan ",
        "certified by the biomedical manifest."), call. = FALSE)
    }
  }
  release_contract <- .dsvert_dp_canonical_query_value(c(
    provisional, list(plan_sha256 = plan_hash)))
  release_hash <- .dsvert_joint_dp_hash(release_contract)
  transcript <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-vector-transcript-v6",
    mechanism = mechanism, sampler = profile$sampler,
    backend_selection_sha256 = if (isTRUE(profile$selection_bound)) {
      backend_selection$selection_sha256
    } else "",
    release_contract_hash = release_hash,
    ordered_designated_peers = as.list(designated),
    ordered_designated_pins = as.list(
      unname(policy$peer_pinset[designated]))))
  list(
    manifest = manifest, validated = validated, lattice = lattice,
    source = source, source_contract = source_contract,
    release_instance = release_instance$value,
    release_instance_id = release_instance$id,
    release_contract = release_contract,
    release_contract_hash = release_hash, transcript_hash = transcript,
    plan = .dsvert_dp_canonical_query_value(plan), plan_sha256 = plan_hash,
    designated = designated, profile = profile)
}

.dsvert_joint_dp_vector_store_path <- function(policy) {
  # v3 is intentionally retained as historical state.  The v4 namespace has
  # a stable policy binding and partitions records by release-instance ID, so
  # rotating one peer's noise root cannot invalidate or overwrite old replay.
  path <- paste0(policy$ledger_path, ".joint-dp-vector-v4.sqlite")
  .dsvert_dp_assert_private_file(
    path, "joint-DP vector store",
    require_private = isTRUE(policy$ledger_private))
  path
}

.dsvert_joint_dp_vector_intermediate_max_bytes <- function() {
  value <- getOption(
    "dsvert.dp.vector_intermediate_max_bytes", 4 * 1024^3)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < 1024 ||
      value > 1024^4) {
    stop("Invalid joint-DP vector intermediate capacity.", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_joint_dp_vector_row_mac <- function(secret, table, json) {
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/joint-dp/vector-store/v4/", table, "|", json)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_vector_record_json <- function(value) {
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value))
}

.dsvert_joint_dp_vector_record_decode <- function(
    row, secret, table, what) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !all(c("record_json", "row_mac") %in% names(row)) ||
      !.dsvert_joint_dp_dsi_hex_equal(
        row$row_mac[[1L]], .dsvert_joint_dp_vector_row_mac(
          secret, table, row$record_json[[1L]]))) {
    stop("The joint-DP vector ", what,
         " failed private-store authentication.", call. = FALSE)
  }
  value <- tryCatch(jsonlite::fromJSON(
    row$record_json[[1L]], simplifyVector = FALSE),
    error = function(e) NULL)
  canonical <- tryCatch(.dsvert_joint_dp_vector_record_json(value),
                        error = function(e) NULL)
  if (is.null(value) || !identical(canonical, row$record_json[[1L]])) {
    stop("The joint-DP vector ", what, " is malformed.", call. = FALSE)
  }
  value
}

.dsvert_joint_dp_vector_record_insert <- function(
    connection, table, columns, values, record, secret) {
  json <- .dsvert_joint_dp_vector_record_json(record)
  mac <- .dsvert_joint_dp_vector_row_mac(secret, table, json)
  fields <- c(columns, "record_json", "row_mac")
  DBI::dbExecute(connection, paste0(
    "INSERT INTO ", table, "(", paste(fields, collapse = ","),
    ") VALUES(", paste(rep("?", length(fields)), collapse = ","), ")"),
    params = c(values, list(json, mac)))
  invisible(record)
}

.dsvert_joint_dp_vector_record_update <- function(
    connection, table, record, secret, assignments = character(),
    assignment_values = list(), where, where_values) {
  json <- .dsvert_joint_dp_vector_record_json(record)
  mac <- .dsvert_joint_dp_vector_row_mac(secret, table, json)
  set <- c(assignments, "record_json = ?", "row_mac = ?")
  changed <- DBI::dbExecute(connection, paste0(
    "UPDATE ", table, " SET ", paste(set, collapse = ","),
    " WHERE ", where),
    params = c(assignment_values, list(json, mac), where_values))
  if (!identical(as.integer(changed), 1L)) {
    stop("The joint-DP vector durable update was lost.", call. = FALSE)
  }
  invisible(record)
}

.dsvert_joint_dp_vector_transaction <- function(connection, code) {
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  committed <- FALSE
  on.exit(if (!committed) try(DBI::dbRollback(connection), silent = TRUE),
          add = TRUE)
  value <- force(code)
  DBI::dbCommit(connection)
  committed <- TRUE
  value
}

.dsvert_joint_dp_vector_instance_claim_material <- function(
    capsule_id, release_instance_id, release_contract_hash) {
  capsule_id <- .dsvert_joint_dp_vector_scalar(
    capsule_id, "claim capsule ID", "^[0-9a-f]{64}$", 64L)
  release_instance_id <- .dsvert_joint_dp_vector_scalar(
    release_instance_id, "claimed release-instance ID",
    "^[0-9a-f]{64}$", 64L)
  release_contract_hash <- .dsvert_joint_dp_vector_scalar(
    release_contract_hash, "claimed release-contract hash",
    "^[0-9a-f]{64}$", 64L)
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_VECTOR_INSTANCE_CLAIM_VERSION,
    capsule_id = capsule_id,
    release_instance_id = release_instance_id,
    release_contract_hash = release_contract_hash))
}

.dsvert_joint_dp_vector_instance_claim_load <- function(
    connection, capsule_id, secret) {
  capsule_id <- .dsvert_joint_dp_vector_scalar(
    capsule_id, "claim capsule ID", "^[0-9a-f]{64}$", 64L)
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT capsule_id,release_instance_id,release_contract_hash,",
    "record_json,row_mac FROM vector_instance_claims WHERE capsule_id=?"),
    params = list(capsule_id))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_joint_dp_vector_record_decode(
    row, secret, "vector_instance_claims", "release-instance claim")
  expected <- tryCatch(.dsvert_joint_dp_vector_instance_claim_material(
    value$capsule_id, value$release_instance_id,
    value$release_contract_hash), error = function(error) NULL)
  if (is.null(expected) || !identical(value, expected) ||
      !identical(row$capsule_id[[1L]], value$capsule_id) ||
      !identical(row$release_instance_id[[1L]],
                 value$release_instance_id) ||
      !identical(row$release_contract_hash[[1L]],
                 value$release_contract_hash)) {
    stop("The joint-DP vector release-instance claim is inconsistent.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_vector_instance_claim_state_material <- function(claims) {
  if (!is.list(claims)) {
    stop("Invalid joint-DP vector release-instance claim state.",
         call. = FALSE)
  }
  if (length(claims)) {
    capsule_ids <- vapply(claims, `[[`, character(1L), "capsule_id")
    if (anyDuplicated(capsule_ids)) {
      stop("Invalid joint-DP vector release-instance claim state.",
           call. = FALSE)
    }
    claims <- claims[order(capsule_ids, method = "radix")]
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_VECTOR_INSTANCE_CLAIM_STATE_VERSION,
    claim_count = as.numeric(length(claims)),
    ordered_claims_sha256 = .dsvert_joint_dp_hash(list(
      protocol = "dsvert-joint-dp-vector-instance-claim-set-v1",
      ordered_claims = unname(claims)))))
}

.dsvert_joint_dp_vector_instance_claim_state_expected_connection <-
    function(connection, secret) {
  capsule_ids <- DBI::dbGetQuery(connection, paste(
    "SELECT capsule_id FROM vector_instance_claims",
    "ORDER BY capsule_id"))$capsule_id
  claims <- lapply(capsule_ids, function(capsule_id) {
    claim <- .dsvert_joint_dp_vector_instance_claim_load(
      connection, capsule_id, secret)
    if (is.null(claim)) {
      stop("The durable release-instance claim set changed while audited.",
           call. = FALSE)
    }
    claim
  })
  .dsvert_joint_dp_vector_instance_claim_state_material(claims)
}

.dsvert_joint_dp_vector_instance_claim_state_validate_connection <-
    function(connection, secret) {
  expected <-
    .dsvert_joint_dp_vector_instance_claim_state_expected_connection(
      connection, secret)
  expected_json <- .dsvert_joint_dp_vector_record_json(expected)
  expected_mac <- .dsvert_joint_dp_vector_row_mac(
    secret, "meta", expected_json)
  observed <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta",
    "WHERE key='release_instance_claim_state'"))
  if (nrow(observed) != 1L ||
      !identical(observed$value[[1L]], expected_json) ||
      !.dsvert_joint_dp_dsi_hex_equal(
        observed$row_mac[[1L]], expected_mac)) {
    stop("The authenticated vector release-instance claim state is inconsistent.",
         call. = FALSE)
  }
  invisible(expected)
}

.dsvert_joint_dp_vector_instance_claim_state_write_connection <-
    function(connection, secret) {
  state <- .dsvert_joint_dp_vector_instance_claim_state_expected_connection(
    connection, secret)
  json <- .dsvert_joint_dp_vector_record_json(state)
  mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", json)
  observed <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta",
    "WHERE key='release_instance_claim_state'"))
  if (!nrow(observed)) {
    DBI::dbExecute(connection, paste(
      "INSERT INTO vector_meta(key,value,row_mac)",
      "VALUES('release_instance_claim_state',?,?)"),
      params = list(json, mac))
  } else if (nrow(observed) == 1L) {
    DBI::dbExecute(connection, paste(
      "UPDATE vector_meta SET value=?,row_mac=?",
      "WHERE key='release_instance_claim_state'"),
      params = list(json, mac))
  } else {
    stop("The authenticated vector release-instance claim state is inconsistent.",
         call. = FALSE)
  }
  invisible(state)
}

.dsvert_joint_dp_vector_instance_claim_insert_connection <- function(
    connection, secret, claim) {
  expected <- .dsvert_joint_dp_vector_instance_claim_material(
    claim$capsule_id, claim$release_instance_id,
    claim$release_contract_hash)
  if (!identical(claim, expected)) {
    stop("Invalid joint-DP vector release-instance claim insert.",
         call. = FALSE)
  }
  .dsvert_joint_dp_vector_schema_validate(
    connection, include_release = TRUE)
  .dsvert_joint_dp_vector_instance_claim_state_validate_connection(
    connection, secret)
  .dsvert_joint_dp_vector_record_insert(
    connection, "vector_instance_claims",
    c("capsule_id", "release_instance_id", "release_contract_hash"),
    list(claim$capsule_id, claim$release_instance_id,
         claim$release_contract_hash), claim, secret)
  .dsvert_joint_dp_vector_instance_claim_state_write_connection(
    connection, secret)
  observed <- .dsvert_joint_dp_vector_instance_claim_require_connection(
    connection, secret, expected$capsule_id,
    expected$release_instance_id, expected$release_contract_hash)
  .dsvert_joint_dp_vector_instance_claim_state_validate_connection(
    connection, secret)
  if (!identical(observed, expected)) {
    stop("The durable joint-DP vector release-instance claim insert was lost.",
         call. = FALSE)
  }
  invisible(expected)
}

.dsvert_joint_dp_vector_instance_claim_require_connection <- function(
    connection, secret, capsule_id, release_instance_id,
    release_contract_hash) {
  expected <- .dsvert_joint_dp_vector_instance_claim_material(
    capsule_id, release_instance_id, release_contract_hash)
  existing <- .dsvert_joint_dp_vector_instance_claim_load(
    connection, expected$capsule_id, secret)
  if (is.null(existing)) {
    stop("The joint-DP vector release instance has no durable capsule claim.",
         call. = FALSE)
  }
  if (!identical(existing$release_instance_id,
                 expected$release_instance_id)) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  if (!identical(existing, expected)) {
    stop("The durable joint-DP vector release-instance claim conflicts with its contract.",
         call. = FALSE)
  }
  existing
}

.dsvert_joint_dp_vector_instance_claim_acquire_connection <- function(
    connection, config, secret, capsule_id, release_instance_id,
    release_contract_hash) {
  .dsvert_joint_dp_vector_schema_validate(
    connection, include_release = TRUE)
  expected <- .dsvert_joint_dp_vector_instance_claim_material(
    capsule_id, release_instance_id, release_contract_hash)
  existing <- .dsvert_joint_dp_vector_instance_claim_load(
    connection, expected$capsule_id, secret)
  if (!is.null(existing)) {
    value <- .dsvert_joint_dp_vector_instance_claim_require_connection(
      connection, secret, expected$capsule_id,
      expected$release_instance_id, expected$release_contract_hash)
    return(list(created = FALSE, claim = value))
  }
  capsule <- .dsvert_joint_dp_vector_capsule_load(
    connection, expected$release_instance_id, secret)
  if (is.null(capsule) ||
      !identical(capsule$capsule_id, expected$capsule_id) ||
      !identical(capsule$release_instance_id,
                 expected$release_instance_id) ||
      !identical(capsule$release_contract_hash,
                 expected$release_contract_hash) ||
      !identical(capsule$allocation_authorized, TRUE) ||
      is.null(capsule$prepare_receipt_json)) {
    stop("A joint-DP vector release-instance claim requires its matching durable prepare.",
         call. = FALSE)
  }
  .dsvert_joint_dp_release_ledger_admit_new_capsule(
    connection, config, secret, expected$capsule_id)
  .dsvert_joint_dp_vector_instance_claim_insert_connection(
    connection, secret, expected)
  list(created = TRUE, claim = expected)
}

.dsvert_joint_dp_vector_instance_claim_contract <- function(
    policy, secret, contract, create = FALSE) {
  if (!is.logical(create) || length(create) != 1L || is.na(create) ||
      !is.list(contract) || !is.list(contract$release_contract)) {
    stop("Invalid joint-DP vector release-instance claim request.",
         call. = FALSE)
  }
  capsule_id <- contract$release_contract$capsule_id
  release_instance_id <- contract$release_contract$release_instance_id
  release_contract_hash <- contract$release_contract_hash
  .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      if (isTRUE(create)) {
        config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
        return(.dsvert_joint_dp_vector_transaction(connection, {
          .dsvert_joint_dp_vector_instance_claim_acquire_connection(
            connection, config, secret, capsule_id,
            release_instance_id, release_contract_hash)
        })$claim)
      }
      .dsvert_joint_dp_vector_instance_claim_require_connection(
        connection, secret, capsule_id, release_instance_id,
        release_contract_hash)
    })
}

.dsvert_joint_dp_vector_instance_claim_preflight <- function(
    policy, secret, release_instance_json) {
  config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
  instance <- .dsvert_joint_dp_release_ledger_instance(
    release_instance_json, config)
  claim <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      .dsvert_joint_dp_vector_instance_claim_load(
        connection, instance$value$capsule_id, secret)
    })
  if (!is.null(claim) &&
      !identical(claim$release_instance_id, instance$id)) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  if (!is.null(claim) &&
      !.dsvert_joint_dp_vector_local_root_is_active(
        policy, instance,
        .dsvert_joint_dp_vector_active_release_domain(policy, secret))) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  list(instance = instance, claim = claim)
}

.dsvert_joint_dp_vector_release_ledger_cross_audit <- function(
    connection, config, secret) {
  fail <- function() {
    stop(paste(
      "The authenticated vector release ledger diverges from durable",
      "release capsules; restore the complete authenticated vector store",
      "from durable backup."), call. = FALSE)
  }
  audit <- .dsvert_joint_dp_release_ledger_audit(
    connection, config, secret)
  .dsvert_joint_dp_vector_instance_claim_state_validate_connection(
    connection, secret)
  ledger_ids <- vapply(
    audit$records, `[[`, character(1L), "release_instance_id")
  if (anyDuplicated(ledger_ids)) fail()
  hash_size <- as.integer(max(
    29L, min(.Machine$integer.max, 2 * length(ledger_ids) + 1L)))
  ledger_records <- new.env(
    hash = TRUE, parent = emptyenv(), size = hash_size)
  for (index in seq_along(ledger_ids)) {
    assign(ledger_ids[[index]], audit$records[[index]],
           envir = ledger_records)
  }
  released_ids <- new.env(
    hash = TRUE, parent = emptyenv(), size = hash_size)
  claim_rows <- DBI::dbGetQuery(connection, paste(
    "SELECT capsule_id,release_instance_id,release_contract_hash,",
    "record_json,row_mac FROM vector_instance_claims ORDER BY capsule_id"))
  claims_by_capsule <- new.env(
    hash = TRUE, parent = emptyenv(),
    size = as.integer(max(29L, 2 * nrow(claim_rows) + 1L)))
  claims_by_instance <- new.env(
    hash = TRUE, parent = emptyenv(),
    size = as.integer(max(29L, 2 * nrow(claim_rows) + 1L)))
  if (nrow(claim_rows)) for (index in seq_len(nrow(claim_rows))) {
    claim <- tryCatch(
      .dsvert_joint_dp_vector_instance_claim_load(
        connection, claim_rows$capsule_id[[index]], secret),
      error = function(error) NULL)
    if (is.null(claim) ||
        exists(claim$capsule_id, envir = claims_by_capsule,
               inherits = FALSE) ||
        exists(claim$release_instance_id, envir = claims_by_instance,
               inherits = FALSE)) {
      fail()
    }
    assign(claim$capsule_id, claim, envir = claims_by_capsule)
    assign(claim$release_instance_id, claim, envir = claims_by_instance)
  }
  matched_claims <- new.env(
    hash = TRUE, parent = emptyenv(),
    size = as.integer(max(29L, 2 * nrow(claim_rows) + 1L)))
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT release_instance_id,record_json,row_mac FROM vector_capsules",
    "ORDER BY release_instance_id"))
  if (nrow(rows)) for (index in seq_len(nrow(rows))) {
    capsule <- .dsvert_joint_dp_vector_record_decode(
      rows[index, , drop = FALSE], secret, "vector_capsules",
      "release-ledger cross-audit capsule")
    if (!identical(
          capsule$release_instance_id,
          rows$release_instance_id[[index]])) {
      fail()
    }
    claim <- if (exists(capsule$release_instance_id,
                        envir = claims_by_instance, inherits = FALSE)) {
      get(capsule$release_instance_id, envir = claims_by_instance,
          inherits = FALSE)
    } else NULL
    if (!is.null(claim)) {
      if (!identical(claim$capsule_id, capsule$capsule_id) ||
          !identical(claim$release_contract_hash,
                     capsule$release_contract_hash) ||
          exists(claim$capsule_id, envir = matched_claims,
                 inherits = FALSE)) {
        fail()
      }
      assign(claim$capsule_id, TRUE, envir = matched_claims)
    }
    if ((!is.null(capsule$local_result_json) ||
         !is.null(capsule$release_receipt_json)) && is.null(claim)) {
      fail()
    }
    if (is.null(capsule$release_receipt_json)) next
    instance <- if (is.list(capsule$release_contract)) {
      capsule$release_contract$release_instance
    } else NULL
    instance_json <- tryCatch(
      .dsvert_joint_dp_vector_encode(instance),
      error = function(error) NULL)
    artifact <- if (!is.null(instance_json)) tryCatch(
      .dsvert_joint_dp_release_ledger_artifact(
        config, instance_json, capsule$release_receipt_json),
      error = function(error) NULL) else NULL
    if (is.null(artifact) ||
        !identical(capsule$release_instance_id, artifact$instance$id) ||
        !identical(capsule$capsule_id, artifact$instance$value$capsule_id)) {
      fail()
    }
    release_instance_id <- artifact$instance$id
    if (exists(release_instance_id, envir = released_ids,
               inherits = FALSE) ||
        !exists(release_instance_id, envir = ledger_records,
                inherits = FALSE)) {
      fail()
    }
    observed <- get(
      release_instance_id, envir = ledger_records, inherits = FALSE)
    expected <- .dsvert_joint_dp_release_ledger_record_material(
      config, artifact, observed$sequence, observed$previous_chain)
    observed_material <- observed[setdiff(names(observed), "chain_hash")]
    if (!identical(
          .dsvert_dp_canonical_query_value(observed_material),
          .dsvert_dp_canonical_query_value(expected))) {
      fail()
    }
    assign(release_instance_id, TRUE, envir = released_ids)
  }
  unmatched_claims <- setdiff(
    ls(claims_by_capsule, all.names = TRUE),
    ls(matched_claims, all.names = TRUE))
  if (length(unmatched_claims) && any(!vapply(
      unmatched_claims, function(capsule_id) {
        claim <- get(capsule_id, envir = claims_by_capsule,
                     inherits = FALSE)
        if (!exists(claim$release_instance_id, envir = ledger_records,
                    inherits = FALSE)) return(FALSE)
        ledger <- get(claim$release_instance_id, envir = ledger_records,
                      inherits = FALSE)
        identical(ledger$capsule_id, claim$capsule_id)
      }, logical(1L)))) {
    fail()
  }
  ledger_without_capsule <- setdiff(
    ledger_ids, ls(released_ids, all.names = TRUE))
  if (length(ledger_without_capsule) && any(vapply(
      ledger_without_capsule, function(release_instance_id) {
        if (!exists(release_instance_id, envir = claims_by_instance,
                    inherits = FALSE)) return(TRUE)
        claim <- get(release_instance_id, envir = claims_by_instance,
                     inherits = FALSE)
        exists(claim$capsule_id, envir = matched_claims, inherits = FALSE)
      }, logical(1L)))) {
    fail()
  }
  irreversible_instances <- unique(c(
    DBI::dbGetQuery(connection, paste(
      "SELECT DISTINCT release_instance_id FROM vector_noised_chunks",
      "ORDER BY release_instance_id"))$release_instance_id,
    DBI::dbGetQuery(connection, paste(
      "SELECT DISTINCT release_instance_id FROM vector_final_chunks",
      "ORDER BY release_instance_id"))$release_instance_id))
  if (length(irreversible_instances) && any(!vapply(
      irreversible_instances, exists, logical(1L),
      envir = claims_by_instance, inherits = FALSE))) {
    fail()
  }
  if (length(ledger_ids) && any(!vapply(
      ledger_ids, exists, logical(1L),
      envir = claims_by_instance, inherits = FALSE))) {
    fail()
  }
  invisible(audit$summary)
}

.dsvert_joint_dp_vector_core_schema_statements <- function() {
  c(
    paste("CREATE TABLE IF NOT EXISTS vector_meta (",
          "key TEXT PRIMARY KEY, value TEXT NOT NULL, row_mac TEXT NOT NULL)"),
    paste("CREATE TABLE IF NOT EXISTS vector_capsules (",
          "release_instance_id TEXT PRIMARY KEY, state TEXT NOT NULL, compacted INTEGER NOT NULL,",
          "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"),
    paste("CREATE TABLE IF NOT EXISTS vector_instance_claims (",
          "capsule_id TEXT PRIMARY KEY, release_instance_id TEXT NOT NULL UNIQUE,",
          "release_contract_hash TEXT NOT NULL,",
          "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"),
    paste("CREATE TABLE IF NOT EXISTS vector_noised_chunks (",
          "release_instance_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,",
          "payload_chars INTEGER NOT NULL, record_json TEXT NOT NULL,",
          "row_mac TEXT NOT NULL, PRIMARY KEY(release_instance_id, chunk_index))"),
    paste("CREATE TABLE IF NOT EXISTS vector_final_chunks (",
          "release_instance_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,",
          "chunk_hash TEXT NOT NULL, record_json TEXT NOT NULL,",
          "row_mac TEXT NOT NULL, PRIMARY KEY(release_instance_id, chunk_index))"))
}

.dsvert_joint_dp_vector_schema_tables <- function(include_release = TRUE) {
  core <- c(
    "vector_meta", "vector_capsules", "vector_instance_claims",
    "vector_noised_chunks", "vector_final_chunks")
  if (!isTRUE(include_release)) return(core)
  c(core, "vector_release_ledger_meta",
    "vector_release_ledger_records", "vector_release_ledger_state")
}

.dsvert_joint_dp_vector_schema_rows <- function(
    connection, include_release = TRUE) {
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT type,name,tbl_name,sql FROM sqlite_master",
    "ORDER BY type,tbl_name,name"))
  rows$sql <- vapply(rows$sql, function(sql) {
    if (is.na(sql)) return(NA_character_)
    gsub("[[:space:]]+", " ", trimws(sql), perl = TRUE)
  }, character(1L))
  rownames(rows) <- NULL
  rows
}

.dsvert_joint_dp_vector_schema_expected <- local({
  core <- NULL
  full <- NULL
  function(include_release = TRUE) {
    cached <- if (isTRUE(include_release)) full else core
    if (!is.null(cached)) return(cached)
    connection <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    for (statement in .dsvert_joint_dp_vector_core_schema_statements()) {
      DBI::dbExecute(connection, statement)
    }
    if (isTRUE(include_release)) {
      .dsvert_joint_dp_release_ledger_schema(connection)
    }
    value <- .dsvert_joint_dp_vector_schema_rows(
      connection, include_release)
    if (isTRUE(include_release)) full <<- value else core <<- value
    value
  }
})

.dsvert_joint_dp_vector_schema_fingerprint <- function(
    connection, include_release = TRUE) {
  digest::digest(list(
    protocol = "dsvert-joint-dp-vector-schema-fingerprint-v2",
    persistent_schema = .dsvert_joint_dp_vector_schema_rows(
      connection, include_release)),
    algo = "sha256", serialize = TRUE, serializeVersion = 3L)
}

.dsvert_joint_dp_vector_schema_validate <- function(
    connection, include_release = TRUE) {
  observed <- .dsvert_joint_dp_vector_schema_rows(
    connection, include_release)
  expected <- .dsvert_joint_dp_vector_schema_expected(include_release)
  if (!identical(observed, expected)) {
    stop("The authenticated joint-DP vector store schema is invalid.",
         call. = FALSE)
  }
  invisible(.dsvert_joint_dp_vector_schema_fingerprint(
    connection, include_release))
}

.dsvert_joint_dp_vector_release_ledger_cache_key <- function(
    connection, config) {
  state <- DBI::dbGetQuery(connection, paste(
    "SELECT release_count,cumulative_epsilon,cumulative_delta,head_chain,",
    "tail_release_instance_id,tail_row_mac,state_mac",
    "FROM vector_release_ledger_state WHERE singleton=1"))
  if (nrow(state) != 1L) {
    stop("The authenticated vector release-ledger cache state is invalid.",
         call. = FALSE)
  }
  records <- DBI::dbGetQuery(connection, paste(
    "SELECT release_instance_id,sequence,capsule_id,local_privacy_epoch,",
    "local_noise_key_id,previous_chain,chain_hash,record_json,row_mac",
    "FROM vector_release_ledger_records ORDER BY sequence"))
  capsules <- DBI::dbGetQuery(connection, paste(
    "SELECT release_instance_id,state,compacted,record_json,row_mac",
    "FROM vector_capsules ORDER BY release_instance_id"))
  claims <- DBI::dbGetQuery(connection, paste(
    "SELECT capsule_id,release_instance_id,release_contract_hash,",
    "record_json,row_mac FROM vector_instance_claims ORDER BY capsule_id"))
  claim_state <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta",
    "WHERE key='release_instance_claim_state'"))
  noised_instances <- DBI::dbGetQuery(connection, paste(
    "SELECT DISTINCT release_instance_id FROM vector_noised_chunks",
    "ORDER BY release_instance_id"))
  final_instances <- DBI::dbGetQuery(connection, paste(
    "SELECT DISTINCT release_instance_id FROM vector_final_chunks",
    "ORDER BY release_instance_id"))
  digest::digest(list(
    protocol = "dsvert-vector-release-cross-audit-cache-v4",
    schema_fingerprint =
      .dsvert_joint_dp_vector_schema_fingerprint(connection, TRUE),
    ledger_id = config$ledger_id,
    state = state,
    records = records,
    capsules = capsules,
    claims = claims,
    claim_state = claim_state,
    noised_instances = noised_instances,
    final_instances = final_instances),
    algo = "sha256", serialize = TRUE, serializeVersion = 3L)
}

.dsvert_joint_dp_vector_store_initialize <- function(
    connection, policy, secret, path) {
  binding <- .dsvert_joint_dp_vector_record_json(list(
    version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_name = policy$peer_name,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    privacy_epoch_scope = "per_peer_signed_release_instance_v1"))
  mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", binding)
  existing_schema <- DBI::dbGetQuery(connection, paste(
    "SELECT type,name,tbl_name,sql FROM sqlite_master",
    "ORDER BY type,tbl_name,name"))
  existing_tables <- existing_schema$name[
    existing_schema$type == "table"]
  expected_release_tables <- sort(c(
    "vector_release_ledger_meta", "vector_release_ledger_records",
    "vector_release_ledger_state"), method = "radix")
  release_tables <- sort(existing_tables[
    existing_tables %in% expected_release_tables], method = "radix")
  existing_store <- "vector_meta" %in% existing_tables
  release_config <-
    .dsvert_joint_dp_release_ledger_config_from_policy(policy)
  backfill_row <- NULL
  if (isTRUE(existing_store)) {
    # Authenticate the durable ABI before any CREATE/ALTER or persistent
    # PRAGMA.  In particular, opening a v5 store must leave it byte-for-byte
    # untouched when the required v6 claim schema is absent.
    row <- DBI::dbGetQuery(connection,
      "SELECT value, row_mac FROM vector_meta WHERE key = 'policy_binding'")
    if (nrow(row) != 1L || !identical(row$value[[1L]], binding) ||
        !.dsvert_joint_dp_dsi_hex_equal(row$row_mac[[1L]], mac)) {
      stop("The joint-DP vector store belongs to another policy or failed authentication.",
           call. = FALSE)
    }
    backfill_row <- DBI::dbGetQuery(connection, paste(
      "SELECT value,row_mac FROM vector_meta",
      "WHERE key='release_ledger_backfill'"))
    if (nrow(backfill_row)) {
      expected_backfill <- .dsvert_joint_dp_vector_record_json(list(
        version = .DSVERT_JOINT_DP_VECTOR_RELEASE_LEDGER_BACKFILL_VERSION,
        vector_store_version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
        release_ledger_id = release_config$ledger_id,
        completed = TRUE))
      expected_backfill_mac <- .dsvert_joint_dp_vector_row_mac(
        secret, "meta", expected_backfill)
      if (nrow(backfill_row) != 1L ||
          !identical(backfill_row$value[[1L]], expected_backfill) ||
          !.dsvert_joint_dp_dsi_hex_equal(
            backfill_row$row_mac[[1L]], expected_backfill_mac)) {
        stop("The vector release-ledger backfill marker failed authentication.",
             call. = FALSE)
      }
      if (!identical(release_tables, expected_release_tables)) {
        stop("The authenticated vector release ledger was removed after migration; restore the complete authenticated vector store from durable backup.",
             call. = FALSE)
      }
    }
  } else if (nrow(existing_schema)) {
    stop("The joint-DP vector store has unauthenticated pre-existing schema.",
         call. = FALSE)
  }
  statements <- .dsvert_joint_dp_vector_core_schema_statements()
  if (isTRUE(existing_store)) {
    if (length(release_tables) &&
        !identical(release_tables, expected_release_tables)) {
      stop("The vector release-ledger history is structurally incomplete.",
           call. = FALSE)
    }
    .dsvert_joint_dp_vector_schema_validate(
      connection,
      include_release = identical(
        release_tables, expected_release_tables))
    .dsvert_joint_dp_vector_instance_claim_state_validate_connection(
      connection, secret)
  } else {
    .dsvert_joint_dp_vector_transaction(connection, {
      for (statement in statements) DBI::dbExecute(connection, statement)
      DBI::dbExecute(connection, paste(
        "INSERT INTO vector_meta(key,value,row_mac)",
        "VALUES('policy_binding',?,?)"), params = list(binding, mac))
      .dsvert_joint_dp_vector_instance_claim_state_write_connection(
        connection, secret)
      .dsvert_joint_dp_vector_schema_validate(
        connection, include_release = FALSE)
      invisible(TRUE)
    })
  }
  if (is.null(backfill_row)) {
    backfill_row <- DBI::dbGetQuery(connection, paste(
      "SELECT value,row_mac FROM vector_meta",
      "WHERE key='release_ledger_backfill'"))
  }
  if (nrow(backfill_row)) {
    release_counts <- vapply(
      c("vector_release_ledger_meta", "vector_release_ledger_state"),
      function(table) DBI::dbGetQuery(
        connection, paste0("SELECT COUNT(*) AS n FROM ", table))$n[[1L]],
      numeric(1L))
    if (release_counts[[1L]] < 1 || release_counts[[2L]] != 1) {
      stop("The authenticated vector release ledger was removed after migration; restore the complete authenticated vector store from durable backup.",
           call. = FALSE)
    }
  } else if (length(release_tables) &&
             !identical(release_tables, expected_release_tables)) {
    stop("The vector release-ledger history is structurally incomplete.",
         call. = FALSE)
  }
  if (identical(release_tables, expected_release_tables)) {
    .dsvert_joint_dp_vector_schema_validate(
      connection, include_release = TRUE)
  }
  .dsvert_joint_dp_release_ledger_initialize(
    connection, release_config, secret)
  .dsvert_joint_dp_vector_schema_validate(
    connection, include_release = TRUE)
  if (nrow(backfill_row)) {
    cache_key <- .dsvert_joint_dp_vector_release_ledger_cache_key(
      connection, release_config)
    cached <- exists(
      path, envir = .dsvert_joint_dp_vector_release_audit_cache,
      inherits = FALSE) && identical(
        get(path, envir = .dsvert_joint_dp_vector_release_audit_cache,
            inherits = FALSE), cache_key)
    if (!isTRUE(cached)) {
      .dsvert_joint_dp_vector_release_ledger_cross_audit(
        connection, release_config, secret)
      assign(
        path, cache_key,
        envir = .dsvert_joint_dp_vector_release_audit_cache)
    }
  }
  .dsvert_joint_dp_vector_release_ledger_backfill(
    connection, policy, secret, release_config)
  invisible(TRUE)
}

.dsvert_joint_dp_vector_release_ledger_backfill <- function(
    connection, policy, secret, config = NULL) {
  if (is.null(config)) {
    config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
  }
  marker <- .dsvert_joint_dp_vector_record_json(list(
    version = .DSVERT_JOINT_DP_VECTOR_RELEASE_LEDGER_BACKFILL_VERSION,
    vector_store_version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
    release_ledger_id = config$ledger_id,
    completed = TRUE))
  marker_mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", marker)
  read_marker <- function() DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta",
    "WHERE key='release_ledger_backfill'"))
  observed <- read_marker()
  if (nrow(observed)) {
    if (nrow(observed) != 1L ||
        !identical(observed$value[[1L]], marker) ||
        !.dsvert_joint_dp_dsi_hex_equal(
          observed$row_mac[[1L]], marker_mac)) {
      stop("The vector release-ledger backfill marker failed authentication.",
           call. = FALSE)
    }
    return(invisible(FALSE))
  }
  .dsvert_joint_dp_vector_transaction(connection, {
    .dsvert_joint_dp_vector_schema_validate(
      connection, include_release = TRUE)
    observed <- read_marker()
    already_completed <- nrow(observed) > 0L
    if (already_completed) {
      if (nrow(observed) != 1L ||
          !identical(observed$value[[1L]], marker) ||
          !.dsvert_joint_dp_dsi_hex_equal(
            observed$row_mac[[1L]], marker_mac)) {
        stop("The vector release-ledger backfill marker failed authentication.",
             call. = FALSE)
      }
    } else {
      rows <- DBI::dbGetQuery(connection, paste(
        "SELECT record_json,row_mac FROM vector_capsules",
        "ORDER BY release_instance_id"))
      if (nrow(rows)) for (index in seq_len(nrow(rows))) {
        record <- .dsvert_joint_dp_vector_record_decode(
          rows[index, , drop = FALSE], secret, "vector_capsules",
          "release-ledger backfill capsule")
        if (is.null(record$release_receipt_json)) next
        instance <- if (is.list(record$release_contract)) {
          record$release_contract$release_instance
        } else NULL
        instance_json <- tryCatch(
          .dsvert_joint_dp_vector_encode(instance),
          error = function(error) NULL)
        if (is.null(instance_json)) {
          stop("A historical vector release lacks its authenticated instance.",
               call. = FALSE)
        }
        claim <- .dsvert_joint_dp_vector_instance_claim_load(
          connection, record$capsule_id, secret)
        if (is.null(claim)) {
          expected_claim <-
            .dsvert_joint_dp_vector_instance_claim_material(
              record$capsule_id, record$release_instance_id,
              record$release_contract_hash)
          .dsvert_joint_dp_vector_instance_claim_insert_connection(
            connection, secret, expected_claim)
        } else {
          .dsvert_joint_dp_vector_instance_claim_require_connection(
            connection, secret, record$capsule_id,
            record$release_instance_id, record$release_contract_hash)
        }
        .dsvert_joint_dp_release_ledger_commit_connection(
          connection, config, secret, instance_json,
          record$release_receipt_json)
      }
      DBI::dbExecute(connection, paste(
        "INSERT INTO vector_meta(key,value,row_mac)",
        "VALUES('release_ledger_backfill',?,?)"),
        params = list(marker, marker_mac))
    }
    invisible(!already_completed)
  })
}

.dsvert_joint_dp_vector_with_store <- function(
    policy, secret, code) {
  if (!is.function(code)) {
    stop("Invalid joint-DP vector store callback.", call. = FALSE)
  }
  path <- .dsvert_joint_dp_vector_store_path(policy)
  require_private <- isTRUE(policy$ledger_private)
  paths <- c(
    store = path, lock = paste0(path, ".lock"),
    wal = paste0(path, "-wal"), shm = paste0(path, "-shm"))
  for (name in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[name]], paste0("joint-DP vector store ", name),
      require_private)
  }
  previous_umask <- Sys.umask("0077")
  on.exit(Sys.umask(previous_umask), add = TRUE)
  lock <- filelock::lock(
    paths[["lock"]], timeout = policy$lock_timeout_ms %||% 30000)
  if (is.null(lock)) {
    stop("The joint-DP vector store is busy.", call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  for (name in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[name]], paste0("joint-DP vector store ", name),
      require_private)
  }
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
  .dsvert_joint_dp_vector_store_initialize(
    connection, policy, secret, path)
  DBI::dbExecute(connection, "PRAGMA journal_mode=WAL")
  DBI::dbExecute(connection, "PRAGMA synchronous=FULL")
  .dsvert_dp_chmod_private_files(paths)
  for (name in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[name]], paste0("joint-DP vector store ", name),
      require_private)
  }
  code(connection)
}

.dsvert_joint_dp_vector_capsule_load <- function(
    connection, release_instance_id, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT state, compacted, record_json, row_mac FROM vector_capsules",
    "WHERE release_instance_id = ?"), params = list(release_instance_id))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_joint_dp_vector_record_decode(
    row, secret, "vector_capsules", "capsule record")
  if (!identical(value$release_instance_id, release_instance_id) ||
      !identical(value$state, row$state[[1L]]) ||
      !identical(as.integer(isTRUE(value$compacted)),
                 as.integer(row$compacted[[1L]]))) {
    stop("The joint-DP vector capsule row is inconsistent.", call. = FALSE)
  }
  value
}

.dsvert_joint_dp_vector_noised_load <- function(
    connection, release_instance_id, chunk_index, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT payload_chars, record_json, row_mac FROM vector_noised_chunks",
    "WHERE release_instance_id = ? AND chunk_index = ?"),
    params = list(release_instance_id, as.integer(chunk_index)))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_joint_dp_vector_record_decode(
    row, secret, "vector_noised_chunks", "noised chunk")
  if (!identical(value$release_instance_id, release_instance_id) ||
      !identical(as.numeric(value$chunk_index), as.numeric(chunk_index)) ||
      !identical(as.numeric(value$payload_chars),
                 as.numeric(row$payload_chars[[1L]]))) {
    stop("The joint-DP vector noised chunk row is inconsistent.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_vector_final_load <- function(
    connection, release_instance_id, chunk_index, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT chunk_hash, record_json, row_mac FROM vector_final_chunks",
    "WHERE release_instance_id = ? AND chunk_index = ?"),
    params = list(release_instance_id, as.integer(chunk_index)))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_joint_dp_vector_record_decode(
    row, secret, "vector_final_chunks", "final DP chunk")
  if (!identical(value$release_instance_id, release_instance_id) ||
      !identical(as.numeric(value$chunk_index), as.numeric(chunk_index)) ||
      !identical(value$chunk_hash, row$chunk_hash[[1L]])) {
    stop("The joint-DP vector final chunk row is inconsistent.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_vector_decode_json <- function(value, what,
                                                 maximum_bytes =
                                                   .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES) {
  value <- .dsvert_joint_dp_vector_scalar(
    value, what, maximum_bytes = maximum_bytes)
  decoded <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = FALSE), error = function(e) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(decoded)), error = function(e) NULL)
  if (!is.list(decoded) || is.null(canonical) || !identical(canonical, value)) {
    stop("Invalid canonical joint-DP vector ", what, ".", call. = FALSE)
  }
  decoded
}

.dsvert_joint_dp_vector_sign <- function(
    unsigned, policy, signer = NULL, require_designated = TRUE) {
  if (identical(require_designated, FALSE) &&
      (!identical(unsigned$version, .DSVERT_JOINT_DP_VECTOR_ACK_VERSION) ||
       !identical(unsigned$phase, "vector_finalized_and_compacted"))) {
    stop(paste(
      "Only a vector finalization acknowledgement may use the full pinned",
      "signer set."), call. = FALSE)
  }
  .dsvert_joint_dp_sign(
    .dsvert_dp_canonical_query_value(unsigned), policy, signer,
    require_designated = require_designated)
}

.dsvert_joint_dp_vector_verify_signature <- function(
    value, policy, verifier = NULL) {
  peer <- value$peer_name
  if (!is.character(peer) || length(peer) != 1L || is.na(peer) ||
      !peer %in% names(policy$peer_pinset) ||
      !identical(value$peer_identity_pk,
                 unname(policy$peer_pinset[[peer]])) ||
      !is.character(value$signature) || length(value$signature) != 1L ||
      is.na(value$signature)) {
    stop("The joint-DP vector receipt has an invalid pinned signer.",
         call. = FALSE)
  }
  public_key <- unname(policy$peer_pinset[[peer]])
  valid <- if (is.null(verifier)) {
    .dsvert_relay_verify_message(
      .dsvert_joint_dp_receipt_message(value),
      public_key, value$signature)
  } else {
    if (!is.function(verifier)) {
      stop("Invalid joint-DP vector verifier.", call. = FALSE)
    }
    verifier(.dsvert_joint_dp_receipt_message(value), public_key,
             value$signature, peer)
  }
  if (!isTRUE(valid)) {
    stop("The joint-DP vector receipt signature is invalid.", call. = FALSE)
  }
  invisible(value)
}

.dsvert_joint_dp_vector_receipt <- function(
    json, policy, version, phase, contract, verifier = NULL,
    what = "receipt") {
  value <- .dsvert_joint_dp_vector_decode_json(json, what)
  common <- c(
    "version", "phase", "capsule_id", "release_instance_id",
    "release_instance", "release_contract_hash",
    "transcript_hash", "peer_name", "peer_identity_pk",
    "coordinate_count", "chunk_count", "backend", "sampler",
    "history_gate", "request_limit", "operation_limit", "signature")
  extras <- if (identical(version,
                          .DSVERT_JOINT_DP_VECTOR_PREPARE_VERSION)) {
    c("source_contract_hash", "coordinate_order_sha256",
      "lattice_transform_sha256", "mechanism_plan", "plan_sha256", "epsilon",
      "allocated_delta", "sensitivity_steps", "commitment_context",
      "seed_commitment", "complete_epsilon_per_peer",
      "delta_aggregation", "capability_available",
      if (isTRUE(contract$profile$selection_bound)) c(
        "backend_assessment", "backend_selection",
        "backend_selection_sha256",
        "one_joint_draw") else character())
  } else if (identical(version, .DSVERT_JOINT_DP_VECTOR_START_VERSION)) {
    c("chunk_index", "coordinate_offset", "coordinates_in_chunk",
      if (isTRUE(contract$profile$exact_gc)) c(
        "backend_selection", "backend_selection_sha256", "binding",
        "binding_sha256", "operation_id", "purpose", "initialization",
        "source_share_exposed", "private_seed_exposed",
        "preclamp_values_exposed") else c(
        "noised_share_sha256", "sampler_contract_hash"),
      "implementation_delta_numerator",
      "implementation_delta_denominator", "intermediate_payload_exposed",
      "capability_available")
  } else if (identical(version, .DSVERT_JOINT_DP_VECTOR_RESULT_VERSION)) {
    c("local_chunk_commitments", "local_chunk_set_root",
      "local_chunk_set_sha256", "all_chunks_durable",
      "intermediate_payload_exposed", "capability_available")
  } else if (identical(version, .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION)) {
    c("result_set_hash", "final_vector_root", "final_chunk_hashes",
      "output_lattice_bits", "output_lattice_scale", "mechanism",
      "epsilon", "delta", "implementation_delta_numerator",
      "implementation_delta_denominator", "delta_aggregation",
      "postprocessing", "intermediate_payload_exposed",
      "durable_replay", "capability_available")
  } else if (identical(version, .DSVERT_JOINT_DP_VECTOR_ACK_VERSION)) {
    c("final_vector_root", "source_intermediates_compacted",
      "sampler_intermediates_compacted", "final_chunks_retained",
      "durable_replay_retained", "idempotent")
  } else character()
  valid <- !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), c(common, extras)) &&
    identical(value$version, version) && identical(value$phase, phase) &&
    identical(value$capsule_id, contract$release_contract$capsule_id) &&
    identical(value$release_instance_id,
              contract$release_contract$release_instance_id) &&
    identical(
      .dsvert_dp_canonical_json(value$release_instance),
      .dsvert_dp_canonical_json(
        contract$release_contract$release_instance)) &&
    identical(value$release_contract_hash,
              contract$release_contract_hash) &&
    identical(value$transcript_hash, contract$transcript_hash) &&
    identical(as.numeric(value$coordinate_count),
              as.numeric(contract$release_contract$coordinate_count)) &&
    identical(as.numeric(value$chunk_count),
              as.numeric(contract$release_contract$chunk_count)) &&
    identical(value$backend, contract$release_contract$backend) &&
    identical(value$sampler, contract$release_contract$sampler) &&
    identical(value$history_gate, TRUE) &&
    identical(value$request_limit, FALSE) &&
    identical(value$operation_limit, TRUE)
  if (!isTRUE(valid)) {
    stop("The joint-DP vector ", what, " has the wrong contract.",
         call. = FALSE)
  }
  .dsvert_joint_dp_vector_verify_signature(value, policy, verifier)
  value
}

.dsvert_joint_dp_vector_receipt_set <- function(
    first_json, second_json, policy, version, phase, contract,
    verifier = NULL, what = "receipt set") {
  values <- list(
    .dsvert_joint_dp_vector_receipt(
      first_json, policy, version, phase, contract, verifier, what),
    .dsvert_joint_dp_vector_receipt(
      second_json, policy, version, phase, contract, verifier, what))
  names(values) <- vapply(values, `[[`, character(1L), "peer_name")
  if (anyDuplicated(names(values)) ||
      !setequal(names(values), contract$designated)) {
    stop("The joint-DP vector requires one receipt from each designated peer.",
         call. = FALSE)
  }
  values[contract$designated]
}

.dsvert_joint_dp_vector_encode <- function(value) {
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value))
}

.dsvert_joint_dp_vector_common_unsigned <- function(
    contract, policy, version, phase) {
  list(
    version = version, phase = phase,
    capsule_id = contract$release_contract$capsule_id,
    release_instance_id = contract$release_contract$release_instance_id,
    release_instance = contract$release_contract$release_instance,
    release_contract_hash = contract$release_contract_hash,
    transcript_hash = contract$transcript_hash,
    peer_name = policy$peer_name,
    peer_identity_pk = unname(policy$peer_pinset[[policy$peer_name]]),
    coordinate_count = contract$release_contract$coordinate_count,
    chunk_count = contract$release_contract$chunk_count,
    backend = contract$release_contract$backend,
    sampler = contract$release_contract$sampler,
    history_gate = TRUE, request_limit = FALSE, operation_limit = TRUE)
}

.dsvert_joint_dp_vector_seed <- function(policy, contract) {
  .dsvert_dp_noise_seed(
    policy, contract$release_contract$release_instance_id, 1,
    paste(
      "joint-mpc/biomedical-vector-v4",
      contract$release_contract$mechanism,
      contract$release_contract$sampler,
      contract$release_contract$capsule_id,
      contract$release_contract$release_instance_id,
      policy$peer_name, sep = "/"),
    as.numeric(contract$release_contract$epsilon),
    as.numeric(contract$release_contract$allocated_delta),
    as.numeric(contract$release_contract$sensitivity_steps))
}

.dsvert_joint_dp_vector_capsule_put <- function(
    connection, record, secret, existing = NULL) {
  if (is.null(existing)) {
    .dsvert_joint_dp_vector_record_insert(
      connection, "vector_capsules",
      c("release_instance_id", "state", "compacted"),
      list(record$release_instance_id, record$state,
           as.integer(isTRUE(record$compacted))), record, secret)
  } else {
    .dsvert_joint_dp_vector_record_update(
      connection, "vector_capsules", record, secret,
      assignments = c("state = ?", "compacted = ?"),
      assignment_values = list(
        record$state, as.integer(isTRUE(record$compacted))),
      where = "release_instance_id = ?",
      where_values = list(record$release_instance_id))
  }
  invisible(record)
}

.dsvert_joint_dp_vector_noised_put <- function(
    connection, record, secret) {
  current <- .dsvert_joint_dp_vector_noised_load(
    connection, record$release_instance_id, record$chunk_index, secret)
  if (!is.null(current)) {
    if (!identical(current, record)) {
      stop("Conflicting durable joint-DP vector noised chunk.",
           call. = FALSE)
    }
    return(current)
  }
  used <- DBI::dbGetQuery(
    connection,
    "SELECT COALESCE(SUM(payload_chars), 0) AS bytes FROM vector_noised_chunks")
  next_bytes <- as.numeric(used$bytes[[1L]]) + record$payload_chars
  if (!is.finite(next_bytes) ||
      next_bytes > .dsvert_joint_dp_vector_intermediate_max_bytes()) {
    stop("Joint-DP vector storage is applying resource backpressure; finalize and compact completed capsules before retrying.",
         call. = FALSE)
  }
  .dsvert_joint_dp_vector_record_insert(
    connection, "vector_noised_chunks",
    c("release_instance_id", "chunk_index", "payload_chars"),
    list(record$release_instance_id, as.integer(record$chunk_index),
         as.integer(record$payload_chars)), record, secret)
  record
}

.dsvert_joint_dp_vector_final_put <- function(
    connection, record, secret) {
  current <- .dsvert_joint_dp_vector_final_load(
    connection, record$release_instance_id, record$chunk_index, secret)
  if (!is.null(current)) {
    if (!identical(current, record)) {
      stop("Conflicting durable joint-DP vector final chunk.",
           call. = FALSE)
    }
    return(current)
  }
  .dsvert_joint_dp_vector_record_insert(
    connection, "vector_final_chunks",
    c("release_instance_id", "chunk_index", "chunk_hash"),
    list(record$release_instance_id, as.integer(record$chunk_index),
         record$chunk_hash), record, secret)
  record
}

.dsvert_joint_dp_vector_merkle_leaf <- function(hash) {
  digest::digest(c(
    charToRaw("dsVert/joint-dp/vector-merkle-leaf/v3"), as.raw(0L),
    .dsvert_joint_dp_vector_raw_hex(hash, "Merkle leaf hash")),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_vector_merkle_parent <- function(left, right) {
  digest::digest(c(
    charToRaw("dsVert/joint-dp/vector-merkle-parent/v3"), as.raw(0L),
    .dsvert_joint_dp_vector_raw_hex(left, "left Merkle node"),
    .dsvert_joint_dp_vector_raw_hex(right, "right Merkle node")),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_vector_merkle_root <- function(hashes) {
  if (!is.character(hashes) || !length(hashes) ||
      anyNA(hashes) || any(!grepl("^[0-9a-f]{64}$", hashes))) {
    stop("Invalid joint-DP vector Merkle leaves.", call. = FALSE)
  }
  nodes <- vapply(hashes, .dsvert_joint_dp_vector_merkle_leaf,
                  character(1L))
  while (length(nodes) > 1L) {
    if (length(nodes) %% 2L) nodes <- c(nodes, tail(nodes, 1L))
    nodes <- vapply(seq.int(1L, length(nodes), by = 2L), function(index) {
      .dsvert_joint_dp_vector_merkle_parent(
        nodes[[index]], nodes[[index + 1L]])
    }, character(1L))
  }
  unname(nodes[[1L]])
}

.dsvert_joint_dp_vector_merkle_proof <- function(hashes, index) {
  index <- .dsvert_joint_dp_vector_index(
    index, "Merkle proof index", 0, length(hashes) - 1)
  nodes <- vapply(hashes, .dsvert_joint_dp_vector_merkle_leaf,
                  character(1L))
  position <- as.integer(index + 1L)
  proof <- list()
  while (length(nodes) > 1L) {
    if (length(nodes) %% 2L) nodes <- c(nodes, tail(nodes, 1L))
    sibling <- if (position %% 2L) position + 1L else position - 1L
    proof[[length(proof) + 1L]] <- list(
      side = if (position %% 2L) "right" else "left",
      sha256 = nodes[[sibling]])
    nodes <- vapply(seq.int(1L, length(nodes), by = 2L), function(node) {
      .dsvert_joint_dp_vector_merkle_parent(
        nodes[[node]], nodes[[node + 1L]])
    }, character(1L))
    position <- as.integer((position + 1L) %/% 2L)
  }
  proof
}

.dsvert_joint_dp_vector_prepare_validate <- function(
    receipt, contract) {
  peer <- receipt$peer_name
  exact <- isTRUE(contract$profile$exact_gc)
  valid <- peer %in% contract$designated &&
    identical(receipt$source_contract_hash,
              contract$release_contract$source_contract_hash) &&
    identical(receipt$coordinate_order_sha256,
              contract$release_contract$coordinate_order_sha256) &&
    identical(receipt$lattice_transform_sha256,
              contract$release_contract$lattice_transform_sha256) &&
    identical(
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(receipt$mechanism_plan)),
      .dsvert_dp_canonical_json(contract$plan)) &&
    identical(.dsvert_joint_dp_hash(receipt$mechanism_plan),
              receipt$plan_sha256) &&
    identical(receipt$plan_sha256, contract$plan_sha256) &&
    identical(receipt$epsilon, contract$release_contract$epsilon) &&
    identical(receipt$allocated_delta,
              contract$release_contract$allocated_delta) &&
    identical(receipt$sensitivity_steps,
              contract$release_contract$sensitivity_steps) &&
    identical(receipt$commitment_context,
              .dsvert_joint_dp_vector_context(
                contract$transcript_hash, peer,
                contract$profile$commitment_purpose)) &&
    is.character(receipt$seed_commitment) &&
    length(receipt$seed_commitment) == 1L &&
    grepl("^[0-9a-f]{64}$", receipt$seed_commitment) &&
    identical(receipt$complete_epsilon_per_peer, !exact) &&
    identical(receipt$delta_aggregation,
              contract$profile$delta_aggregation) &&
    identical(receipt$capability_available, TRUE)
  if (isTRUE(valid) && isTRUE(contract$profile$selection_bound)) {
    selection <- receipt$backend_selection
    assessment <- receipt$backend_assessment
    expected_assessment <-
      contract$release_contract$backend_assessment
    valid <- identical(receipt$one_joint_draw, exact) &&
      identical(receipt$backend_selection_sha256,
                contract$release_contract$backend_selection_sha256) &&
      identical(
        .dsvert_dp_canonical_query_value(selection),
        .dsvert_dp_canonical_query_value(
          contract$release_contract$backend_selection)) &&
      identical(.dsvert_dp_canonical_query_value(assessment),
                .dsvert_dp_canonical_query_value(expected_assessment)) &&
      identical(selection$assessment_sha256,
                assessment$assessment_sha256)
    if (isTRUE(valid)) {
      .dsvert_joint_dp_vector_exact_gc_selection_validate(
        selection,
        contract$release_contract$manifest_sha256,
        require_exact = exact)
    }
  }
  if (!isTRUE(valid)) {
    stop("The joint-DP vector prepare receipt is inconsistent.",
         call. = FALSE)
  }
  invisible(receipt)
}

.dsvert_joint_dp_vector_prepare_set <- function(
    first_json, second_json, policy, contract, verifier = NULL) {
  values <- .dsvert_joint_dp_vector_receipt_set(
    first_json, second_json, policy,
    .DSVERT_JOINT_DP_VECTOR_PREPARE_VERSION, "vector_prepared",
    contract, verifier, "prepare receipt")
  invisible(lapply(values, .dsvert_joint_dp_vector_prepare_validate,
                   contract = contract))
  values
}

.dsvert_joint_dp_vector_prepare_impl <- function(
    manifest_json, release_instance_json,
    first_allocation_opening_json = NULL,
    second_allocation_opening_json = NULL,
    .policy = NULL, .secret = NULL, .signer = NULL, .planner = NULL,
    .verifier = NULL,
    .allocation_local = .dsvert_joint_dp_vector_allocation_require,
    .allocation_observer =
      .dsvert_joint_dp_vector_allocation_observer_require) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (!is.function(.allocation_local) ||
      !is.function(.allocation_observer)) {
    stop("Invalid biomedical vector allocation gates.", call. = FALSE)
  }
  release_config <-
    .dsvert_joint_dp_release_ledger_config_from_policy(.policy)
  requested_instance <- .dsvert_joint_dp_release_ledger_instance(
    release_instance_json, release_config)
  durable <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      list(
        capsule = .dsvert_joint_dp_vector_capsule_load(
          connection, requested_instance$id, .secret),
        claim = .dsvert_joint_dp_vector_instance_claim_load(
          connection, requested_instance$value$capsule_id, .secret))
    })
  existing <- durable$capsule
  if (!is.null(durable$claim) &&
      !identical(durable$claim$release_instance_id,
                 requested_instance$id)) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  if (!is.null(existing)) {
    manifest_sha256 <- digest::digest(
      manifest_json, algo = "sha256", serialize = FALSE)
    if (!identical(existing$manifest_sha256, manifest_sha256) ||
        !identical(existing$capsule_id,
                   requested_instance$value$capsule_id) ||
        !identical(existing$release_instance_id,
                   requested_instance$id) ||
        !identical(existing$allocation_authorized, TRUE) ||
        is.null(existing$prepare_receipt_json)) {
      stop("The durable vector capsule conflicts with this prepare.",
           call. = FALSE)
    }
    return(existing$prepare_receipt_json)
  }
  contract <- .dsvert_joint_dp_vector_contract(
    .policy, manifest_json, release_instance_json,
    .planner, secret = .secret)
  if (!.policy$peer_name %in% contract$designated) {
    stop("Only a designated pinned noise peer may prepare the vector release.",
         call. = FALSE)
  }
  capsule_id <- contract$release_contract$capsule_id
  release_instance_id <- contract$release_contract$release_instance_id
  if (!identical(capsule_id, requested_instance$value$capsule_id) ||
      !identical(release_instance_id, requested_instance$id)) {
    stop("The vector release instance changed during prepare.",
         call. = FALSE)
  }
  .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_release_ledger_admit_new_capsule(
        connection, release_config, .secret, capsule_id)
    })
  allocation <- .allocation_local(
    .policy, manifest_json, .secret, .verifier)
  allocation_proof <- .allocation_observer(
    .policy, manifest_json,
    first_allocation_opening_json, second_allocation_opening_json,
    .secret, .verifier)
  if (!is.list(allocation) || !is.list(allocation_proof) ||
      !identical(allocation$authorized, TRUE) ||
      !identical(allocation_proof$authorized, TRUE) ||
      !identical(allocation$capsule_id, allocation_proof$capsule_id) ||
      !identical(allocation$allocation_index,
                 allocation_proof$allocation_index) ||
      !is.character(allocation_proof$opening_set_hash) ||
      length(allocation_proof$opening_set_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", allocation_proof$opening_set_hash)) {
    stop("The biomedical vector allocation proof is inconsistent.",
         call. = FALSE)
  }
  seed <- .dsvert_joint_dp_vector_seed(.policy, contract)
  context <- .dsvert_joint_dp_vector_context(
    contract$transcript_hash, .policy$peer_name,
    contract$profile$commitment_purpose)
  commitment <- .dsvert_joint_dp_vector_seed_commitment(context, seed)
  unsigned <- c(.dsvert_joint_dp_vector_common_unsigned(
    contract, .policy, .DSVERT_JOINT_DP_VECTOR_PREPARE_VERSION,
    "vector_prepared"), list(
      source_contract_hash = contract$release_contract$source_contract_hash,
      coordinate_order_sha256 =
        contract$release_contract$coordinate_order_sha256,
      lattice_transform_sha256 =
        contract$release_contract$lattice_transform_sha256,
      mechanism_plan = contract$plan,
      plan_sha256 = contract$plan_sha256,
      epsilon = contract$release_contract$epsilon,
      allocated_delta = contract$release_contract$allocated_delta,
      sensitivity_steps = contract$release_contract$sensitivity_steps,
      commitment_context = context, seed_commitment = commitment,
      complete_epsilon_per_peer = !isTRUE(contract$profile$exact_gc),
      delta_aggregation = contract$profile$delta_aggregation,
      capability_available = TRUE), if (
          isTRUE(contract$profile$selection_bound)) {
        list(
          backend_assessment =
            contract$release_contract$backend_assessment,
          backend_selection = contract$release_contract$backend_selection,
          backend_selection_sha256 =
            contract$release_contract$backend_selection_sha256,
          one_joint_draw = isTRUE(contract$profile$exact_gc))
      } else list())
  receipt <- .dsvert_joint_dp_vector_sign(unsigned, .policy, .signer)
  receipt_json <- .dsvert_joint_dp_vector_encode(receipt)
  record <- list(
    version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
    capsule_id = capsule_id, release_instance_id = release_instance_id,
    state = "prepared", compacted = FALSE,
    manifest_sha256 = contract$release_contract$manifest_sha256,
    release_contract_hash = contract$release_contract_hash,
    transcript_hash = contract$transcript_hash,
    release_contract = contract$release_contract,
    plan = contract$plan, designated = as.list(contract$designated),
    allocation_authorized = TRUE,
    allocation_index = allocation$allocation_index,
    allocation_registry_sequence = allocation$registry_sequence,
    allocation_opening_set_hash = allocation_proof$opening_set_hash,
    prepare_receipt_json = receipt_json,
    local_result_json = NULL, release_receipt_json = NULL,
    ack_receipt_json = NULL)
  .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_transaction(connection, {
        raced <- .dsvert_joint_dp_vector_capsule_load(
          connection, release_instance_id, .secret)
        if (is.null(raced)) {
          .dsvert_joint_dp_vector_capsule_put(
            connection, record, .secret, NULL)
          receipt_json
        } else {
          if (!identical(raced$prepare_receipt_json, receipt_json)) {
            stop("Conflicting concurrent vector prepare.", call. = FALSE)
          }
          raced$prepare_receipt_json
        }
      })
    })
}

.dsvert_joint_dp_vector_standard_b64 <- function(value, what,
                                                   expected_bytes) {
  value <- .dsvert_joint_dp_vector_scalar(
    value, what, pattern = "^[A-Za-z0-9+/]*={0,2}$",
    maximum_bytes = 4L * ceiling(expected_bytes / 3L) + 4L)
  decoded <- tryCatch(jsonlite::base64_dec(value), error = function(e) NULL)
  canonical <- if (is.raw(decoded)) gsub(
    "[\r\n]", "", jsonlite::base64_enc(decoded)) else NULL
  if (!is.raw(decoded) || length(decoded) != expected_bytes ||
      !identical(canonical, value)) {
    stop("Invalid joint-DP vector ", what, ".", call. = FALSE)
  }
  decoded
}

.dsvert_joint_dp_vector_sampler_validate <- function(
    output, contract, prepare, chunk) {
  required <- c(
    "version", "backend", "sampler", "release_contract_hash",
    "sampler_contract_hash", "transcript_hash", "peer_name",
    "seed_commitment", "ring_bits", "frac_bits",
    "total_coordinate_count", "chunk_start", "coordinate_count",
    "noised_share", "maximum_noise_magnitude_per_peer",
    "maximum_noise_magnitude_two_peers", "full_capsule_parameters_per_peer",
    "epsilon_divided_by_peer_count", "source_values_returned",
    "noise_values_returned", "private_seed_returned",
    "preclamp_values_returned", "no_wrap_headroom_certified",
    "source_bound_precondition", "nominal_variance_multiplier", "plan")
  if (contract$profile$gaussian) {
    required <- c(required, "mechanism", "tail_projection_applied",
                  "tail_truncation_applied", "fixed_work_shape_verified")
  }
  valid <- is.list(output) && !is.null(names(output)) &&
    !anyNA(names(output)) && !anyDuplicated(names(output)) &&
    setequal(names(output), required) &&
    identical(output$version, contract$profile$share_version) &&
    identical(output$backend, contract$release_contract$backend) &&
    identical(output$sampler, contract$release_contract$sampler) &&
    (!contract$profile$gaussian ||
       (identical(output$mechanism, contract$release_contract$mechanism) &&
        identical(output$tail_projection_applied, FALSE) &&
        identical(output$tail_truncation_applied, TRUE) &&
        identical(output$fixed_work_shape_verified, TRUE))) &&
    identical(output$release_contract_hash,
              contract$release_contract_hash) &&
    identical(output$transcript_hash, contract$transcript_hash) &&
    identical(output$peer_name, prepare$peer_name) &&
    identical(output$seed_commitment, prepare$seed_commitment) &&
    identical(as.numeric(output$ring_bits), 128) &&
    identical(as.numeric(output$frac_bits), 0) &&
    identical(as.numeric(output$total_coordinate_count),
              as.numeric(contract$release_contract$coordinate_count)) &&
    identical(as.numeric(output$chunk_start), as.numeric(chunk$offset)) &&
    identical(as.numeric(output$coordinate_count), as.numeric(chunk$count)) &&
    is.character(output$sampler_contract_hash) &&
    grepl("^[0-9a-f]{64}$", output$sampler_contract_hash) &&
    identical(output$full_capsule_parameters_per_peer, TRUE) &&
    identical(output$epsilon_divided_by_peer_count, FALSE) &&
    identical(output$source_values_returned, FALSE) &&
    identical(output$noise_values_returned, FALSE) &&
    identical(output$private_seed_returned, FALSE) &&
    identical(output$preclamp_values_returned, FALSE) &&
    identical(output$no_wrap_headroom_certified, TRUE) &&
    identical(output$source_bound_precondition,
              "authenticated_semi_honest_capsule_materializer_and_source_transport") &&
    identical(as.numeric(output$nominal_variance_multiplier), 2) &&
    identical(.dsvert_dp_canonical_query_value(output$plan),
              .dsvert_dp_canonical_query_value(contract$plan))
  if (!isTRUE(valid)) {
    stop("The joint-DP vector sampler returned an invalid certificate.",
         call. = FALSE)
  }
  share <- .dsvert_joint_dp_vector_standard_b64(
    output$noised_share, "noised Ring128 share", chunk$count * 16L)
  list(
    output = output, share = share,
    share_sha256 = digest::digest(share, algo = "sha256",
                                  serialize = FALSE))
}

.dsvert_joint_dp_vector_implementation_delta <- function(contract) {
  fields <- if (isTRUE(contract$profile$exact_gc)) {
    c("implementation_delta_numerator", "implementation_delta_denominator")
  } else {
    c("per_peer_implementation_delta_numerator",
      "per_peer_implementation_delta_denominator")
  }
  values <- contract$plan[fields]
  if (length(values) != 2L || any(vapply(values, function(value) {
        !is.character(value) || length(value) != 1L || is.na(value) ||
          !grepl("^(0|[1-9][0-9]*)$", value)
      }, logical(1L))) || !grepl("^[1-9][0-9]*$", values[[2L]])) {
    stop("The vector implementation-delta certificate is invalid.",
         call. = FALSE)
  }
  unname(values)
}

.dsvert_joint_dp_vector_exact_gc_operation <- function(
    ss, contract, prepares, chunk, policy, .compiler = NULL) {
  if (!isTRUE(contract$profile$exact_gc) || !is.environment(ss)) {
    stop("The vector operation is not an exact-GC one-draw contract.",
         call. = FALSE)
  }
  selection <- contract$release_contract$backend_selection
  .dsvert_joint_dp_vector_exact_gc_selection_validate(
    selection, contract$release_contract$manifest_sha256,
    require_exact = TRUE)
  roles <- .dsvert_joint_dp_vector_exact_gc_role_bindings(
    ss, policy$peer_name, prepares, contract$designated)
  positions <- seq.int(chunk$offset + 1L, chunk$offset + chunk$count)
  worker_input <- list(
    version = "dsvert-joint-dp-vector-worker-contract-input-v3",
    ring_bits = 128L, frac_bits = 0L,
    total_coordinate_count = contract$release_contract$coordinate_count,
    chunk_start = chunk$offset, coordinate_count = chunk$count,
    output_lattice_bits = contract$release_contract$output_lattice_bits,
    epsilon = contract$release_contract$epsilon,
    allocated_delta = contract$release_contract$allocated_delta,
    sensitivity_steps = contract$release_contract$sensitivity_steps,
    scale_shifts = as.list(contract$lattice$scale_shifts[positions]),
    raw_upper_bounds = as.list(
      contract$lattice$raw_upper_bounds[positions]),
    transcript_hash = contract$transcript_hash,
    garbler_commitment_context = roles$garbler_commitment_context,
    evaluator_commitment_context = roles$evaluator_commitment_context,
    garbler_seed_commitment = roles$garbler_seed_commitment,
    evaluator_seed_commitment = roles$evaluator_seed_commitment)
  worker <- .dsvert_joint_dp_vector_exact_gc_compile(
    worker_input, .compiler = .compiler)
  if (!identical(
        .dsvert_dp_canonical_query_value(worker$plan),
        .dsvert_dp_canonical_query_value(contract$plan)) ||
      !identical(.dsvert_joint_dp_hash(worker$plan),
                 contract$plan_sha256)) {
    stop("The exact-GC worker changed the signed vector privacy plan.",
         call. = FALSE)
  }
  binding <- .dsvert_joint_dp_vector_exact_gc_binding(
    selection, contract$release_contract$manifest_sha256,
    contract$release_contract_hash, contract$transcript_hash,
    chunk$index, worker)
  list(selection = selection, roles = roles, worker = worker,
       binding = binding)
}

.dsvert_joint_dp_vector_start_validate <- function(
    receipt, contract, chunk = NULL) {
  if (is.null(chunk)) {
    chunk <- .dsvert_joint_dp_vector_chunk_geometry(
      contract$release_contract, receipt$chunk_index)
  }
  delta <- .dsvert_joint_dp_vector_implementation_delta(contract)
  valid <- receipt$peer_name %in% contract$designated &&
    identical(as.numeric(receipt$chunk_index), as.numeric(chunk$index)) &&
    identical(as.numeric(receipt$coordinate_offset),
              as.numeric(chunk$offset)) &&
    identical(as.numeric(receipt$coordinates_in_chunk),
              as.numeric(chunk$count)) &&
    identical(receipt$implementation_delta_numerator,
              delta[[1L]]) &&
    identical(receipt$implementation_delta_denominator,
              delta[[2L]]) &&
    identical(receipt$intermediate_payload_exposed, FALSE) &&
    identical(receipt$capability_available, TRUE)
  if (isTRUE(valid) && isTRUE(contract$profile$exact_gc)) {
    selection <- receipt$backend_selection
    binding <- receipt$binding
    valid <- identical(receipt$backend_selection_sha256,
                       selection$selection_sha256) &&
      identical(receipt$backend_selection_sha256,
                contract$release_contract$backend_selection_sha256) &&
      identical(receipt$binding_sha256, binding$binding_sha256) &&
      identical(receipt$operation_id, binding$operation_id) &&
      identical(receipt$purpose, binding$purpose) &&
      is.list(receipt$initialization) &&
      identical(receipt$source_share_exposed, FALSE) &&
      identical(receipt$private_seed_exposed, FALSE) &&
      identical(receipt$preclamp_values_exposed, FALSE)
    if (isTRUE(valid)) {
      .dsvert_joint_dp_vector_exact_gc_selection_validate(
        selection, contract$release_contract$manifest_sha256,
        require_exact = TRUE)
    }
  } else if (isTRUE(valid)) {
    valid <- is.character(receipt$noised_share_sha256) &&
      grepl("^[0-9a-f]{64}$", receipt$noised_share_sha256) &&
      is.character(receipt$sampler_contract_hash) &&
      grepl("^[0-9a-f]{64}$", receipt$sampler_contract_hash)
  }
  if (!isTRUE(valid)) {
    stop("The joint-DP vector start receipt is inconsistent.",
         call. = FALSE)
  }
  invisible(receipt)
}

.dsvert_joint_dp_vector_start_impl <- function(
    manifest_json, first_prepare_json, second_prepare_json, chunk_index,
    session_id = NULL,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL,
    .planner = NULL, .source_reader = NULL, .sampler = NULL,
    .exact_compiler = NULL,
    .exact_start = .dsvert_joint_dp_vector_exact_gc_start,
    .session = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  release_instance_json <- .dsvert_joint_dp_vector_instance_from_receipts(
    first_prepare_json, second_prepare_json)
  .dsvert_joint_dp_vector_instance_claim_preflight(
    .policy, .secret, release_instance_json)
  contract <- .dsvert_joint_dp_vector_contract(
    .policy, manifest_json, release_instance_json,
    .planner, secret = .secret)
  if (!.policy$peer_name %in% contract$designated) {
    stop("Only a designated pinned noise peer may sample a vector chunk.",
         call. = FALSE)
  }
  prepares <- .dsvert_joint_dp_vector_prepare_set(
    first_prepare_json, second_prepare_json, .policy, contract, .verifier)
  own_prepare <- prepares[[.policy$peer_name]]
  chunk <- .dsvert_joint_dp_vector_chunk_geometry(
    contract$release_contract, chunk_index)
  capsule_id <- contract$release_contract$capsule_id
  release_instance_id <- contract$release_contract$release_instance_id

  capsule <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_capsule_load(
        connection, release_instance_id, .secret)
    })
  if (is.null(capsule) ||
      !identical(capsule$allocation_authorized, TRUE) ||
      !is.character(capsule$allocation_index) ||
      length(capsule$allocation_index) != 1L ||
      !is.character(capsule$allocation_registry_sequence) ||
      length(capsule$allocation_registry_sequence) != 1L ||
      !is.character(capsule$allocation_opening_set_hash) ||
      length(capsule$allocation_opening_set_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", capsule$allocation_opening_set_hash) ||
      !identical(capsule$prepare_receipt_json,
                 .dsvert_joint_dp_vector_encode(own_prepare))) {
    stop("Vector sampling requires a durable cross-signed allocation.",
         call. = FALSE)
  }

  exact_operation <- NULL
  if (isTRUE(contract$profile$exact_gc)) {
    if (!is.function(.exact_start)) {
      stop("Invalid one-draw exact-GC vector starter.", call. = FALSE)
    }
    session_id <- .dsvert_relay_validate_session_id(session_id)
    if (is.null(.session)) .session <- .S(session_id)
    if (!is.environment(.session) ||
        (!is.null(.session$session_id) &&
         !identical(.session$session_id, session_id))) {
      stop("Invalid one-draw exact-GC vector session.", call. = FALSE)
    }
    exact_operation <- .dsvert_joint_dp_vector_exact_gc_operation(
      .session, contract, prepares, chunk, .policy,
      .compiler = .exact_compiler)
  }

  # This irreversible local claim is committed only after every public,
  # session and durable-prepare check above, but before seed derivation,
  # protected source access or sampling.  It binds the capsule to one local
  # release instance; exact replay of that instance remains idempotent.
  .dsvert_joint_dp_vector_instance_claim_contract(
    .policy, .secret, contract, create = TRUE)

  existing <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_noised_load(
        connection, release_instance_id, chunk$index, .secret)
    })
  if (!is.null(existing) && !isTRUE(contract$profile$exact_gc)) {
    .dsvert_joint_dp_vector_start_validate(
      .dsvert_joint_dp_vector_receipt(
        existing$receipt_json, .policy,
        .DSVERT_JOINT_DP_VECTOR_START_VERSION, "vector_chunk_noised",
        contract, .verifier, "stored start receipt"), contract, chunk)
    return(existing$receipt_json)
  }

  seed <- .dsvert_joint_dp_vector_seed(.policy, contract)
  if (!identical(
        .dsvert_joint_dp_vector_seed_commitment(
          own_prepare$commitment_context, seed),
        own_prepare$seed_commitment)) {
    stop("The sticky vector seed no longer matches its signed commitment.",
         call. = FALSE)
  }
  if (is.null(.source_reader)) {
    .source_reader <- function(policy, manifest_json, chunk_index, secret) {
      .dsvert_dp_capsule_source_aggregate_chunk_internal(
        policy, manifest_json, chunk_index, secret)
    }
  }
  if (!is.function(.source_reader)) {
    stop("Invalid joint-DP vector source reader.", call. = FALSE)
  }
  source <- .source_reader(
    .policy, manifest_json, chunk$index, .secret)
  if (!is.raw(source) || length(source) != chunk$count * 16L) {
    stop("The private aggregate vector chunk has the wrong Ring128 shape.",
         call. = FALSE)
  }
  if (isTRUE(contract$profile$exact_gc)) {
    started <- .exact_start(
      .session, session_id, exact_operation$binding,
      exact_operation$selection,
      contract$release_contract$manifest_sha256,
      contract$release_contract_hash, contract$transcript_hash,
      chunk$index, exact_operation$worker, source, seed)
    rm(source, seed)
    delta <- .dsvert_joint_dp_vector_implementation_delta(contract)
    unsigned <- c(.dsvert_joint_dp_vector_common_unsigned(
      contract, .policy, .DSVERT_JOINT_DP_VECTOR_START_VERSION,
      "vector_chunk_noised"), list(
        chunk_index = chunk$index,
        coordinate_offset = chunk$offset,
        coordinates_in_chunk = chunk$count,
        backend_selection = exact_operation$selection,
        backend_selection_sha256 =
          exact_operation$selection$selection_sha256,
        binding = exact_operation$binding,
        binding_sha256 = exact_operation$binding$binding_sha256,
        operation_id = exact_operation$binding$operation_id,
        purpose = exact_operation$binding$purpose,
        initialization = started$initialization,
        source_share_exposed = FALSE, private_seed_exposed = FALSE,
        preclamp_values_exposed = FALSE,
        implementation_delta_numerator = delta[[1L]],
        implementation_delta_denominator = delta[[2L]],
        intermediate_payload_exposed = FALSE,
        capability_available = TRUE))
    receipt <- .dsvert_joint_dp_vector_sign(unsigned, .policy, .signer)
    .dsvert_joint_dp_vector_start_validate(receipt, contract, chunk)
    return(.dsvert_joint_dp_vector_encode(receipt))
  }
  positions <- seq.int(chunk$offset + 1L, chunk$offset + chunk$count)
  input <- c(list(
    version = contract$profile$input_version,
    ring_bits = 128L, frac_bits = 0L,
    total_coordinate_count = contract$release_contract$coordinate_count,
    chunk_start = chunk$offset, coordinate_count = chunk$count,
    output_lattice_bits = contract$release_contract$output_lattice_bits,
    epsilon = contract$release_contract$epsilon,
    allocated_delta = contract$release_contract$allocated_delta
    ), if (contract$profile$gaussian) {
      list(l2_sensitivity_steps = contract$release_contract$sensitivity_steps)
    } else {
      list(sensitivity_steps = contract$release_contract$sensitivity_steps)
    }, list(
    scale_shifts = as.list(contract$lattice$scale_shifts[positions]),
    raw_upper_bounds = as.list(contract$lattice$raw_upper_bounds[positions]),
    release_contract_hash = contract$release_contract_hash,
    transcript_hash = contract$transcript_hash,
    peer_name = .policy$peer_name,
    commitment_context = own_prepare$commitment_context,
    seed_commitment = own_prepare$seed_commitment,
    private_seed = seed,
    source_share = gsub("[\r\n]", "", jsonlite::base64_enc(source))))
  if (is.null(.sampler)) .sampler <- function(value) {
    .callMpcTool(contract$profile$share_command, value)
  }
  if (!is.function(.sampler)) {
    stop("Invalid joint-DP vector sampler.", call. = FALSE)
  }
  output <- .sampler(input)
  input$private_seed <- NULL
  input$source_share <- NULL
  checked <- .dsvert_joint_dp_vector_sampler_validate(
    output, contract, own_prepare, chunk)
  rm(source, seed)
  unsigned <- c(.dsvert_joint_dp_vector_common_unsigned(
    contract, .policy, .DSVERT_JOINT_DP_VECTOR_START_VERSION,
    "vector_chunk_noised"), list(
      chunk_index = chunk$index,
      coordinate_offset = chunk$offset,
      coordinates_in_chunk = chunk$count,
      noised_share_sha256 = checked$share_sha256,
      sampler_contract_hash = output$sampler_contract_hash,
      implementation_delta_numerator =
        contract$plan$per_peer_implementation_delta_numerator,
      implementation_delta_denominator =
        contract$plan$per_peer_implementation_delta_denominator,
      intermediate_payload_exposed = FALSE,
      capability_available = TRUE))
  receipt <- .dsvert_joint_dp_vector_sign(unsigned, .policy, .signer)
  receipt_json <- .dsvert_joint_dp_vector_encode(receipt)
  record <- list(
    version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
    capsule_id = capsule_id, release_instance_id = release_instance_id,
    chunk_index = chunk$index,
    coordinate_offset = chunk$offset,
    coordinates_in_chunk = chunk$count,
    noised_share_b64 = output$noised_share,
    noised_share_sha256 = checked$share_sha256,
    sampler_contract_hash = output$sampler_contract_hash,
    payload_chars = as.numeric(nchar(
      output$noised_share, type = "bytes")),
    receipt_json = receipt_json)
  .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_transaction(connection, {
        capsule <- .dsvert_joint_dp_vector_capsule_load(
          connection, release_instance_id, .secret)
        if (is.null(capsule) ||
            !identical(capsule$release_contract_hash,
                       contract$release_contract_hash)) {
          stop("The vector chunk has no matching durable prepare.",
               call. = FALSE)
        }
        persisted <- .dsvert_joint_dp_vector_noised_put(
          connection, record, .secret)
        persisted$receipt_json
      })
    })
}

.dsvert_joint_dp_vector_result_validate <- function(
    receipt, contract) {
  commitments <- unlist(receipt$local_chunk_commitments, use.names = FALSE)
  valid <- receipt$peer_name %in% contract$designated &&
    is.character(commitments) &&
    length(commitments) == contract$release_contract$chunk_count &&
    !anyNA(commitments) && all(grepl("^[0-9a-f]{64}$", commitments)) &&
    identical(receipt$local_chunk_set_root,
              .dsvert_joint_dp_vector_merkle_root(commitments)) &&
    identical(receipt$local_chunk_set_sha256,
              .dsvert_joint_dp_hash(list(
                protocol = "dsvert-joint-dp-vector-local-chunk-set-v3",
                peer_name = receipt$peer_name,
                commitments = as.list(commitments)))) &&
    identical(receipt$all_chunks_durable, TRUE) &&
    identical(receipt$intermediate_payload_exposed, FALSE) &&
    identical(receipt$capability_available, TRUE)
  if (!isTRUE(valid)) {
    stop("The joint-DP vector result receipt is inconsistent.",
         call. = FALSE)
  }
  invisible(receipt)
}

.dsvert_joint_dp_vector_result_set <- function(
    first_json, second_json, policy, contract, verifier = NULL) {
  values <- .dsvert_joint_dp_vector_receipt_set(
    first_json, second_json, policy,
    .DSVERT_JOINT_DP_VECTOR_RESULT_VERSION, "vector_local_result_committed",
    contract, verifier, "result receipt")
  invisible(lapply(values, .dsvert_joint_dp_vector_result_validate,
                   contract = contract))
  values
}

.dsvert_joint_dp_vector_result_set_hash <- function(results) {
  .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-vector-result-set-v3",
    ordered_results = unname(results)))
}

.dsvert_joint_dp_vector_local_chunk_commitment <- function(record, contract) {
  if (!is.list(record) || !is.list(contract)) {
    stop("Invalid durable vector output record.", call. = FALSE)
  }
  if (!isTRUE(contract$profile$exact_gc)) {
    return(.dsvert_joint_dp_vector_scalar(
      record$noised_share_sha256, "local noised-share commitment",
      "^[0-9a-f]{64}$", 64L))
  }
  required <- c("noised_share_sha256", "validity_share_sha256",
                "binding_sha256")
  if (any(vapply(required, function(name) {
        value <- record[[name]]
        !is.character(value) || length(value) != 1L || is.na(value) ||
          !grepl("^[0-9a-f]{64}$", value)
      }, logical(1L)))) {
    stop("The durable exact-GC vector output commitment is incomplete.",
         call. = FALSE)
  }
  .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-vector-exact-gc-output-commitment-v1",
    noised_share_sha256 = record$noised_share_sha256,
    validity_share_sha256 = record$validity_share_sha256,
    binding_sha256 = record$binding_sha256))
}

.dsvert_joint_dp_vector_result_impl <- function(
    manifest_json, first_prepare_json, second_prepare_json,
    session_id = NULL,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL,
    .planner = NULL, .exact_compiler = NULL,
    .exact_consume = .dsvert_joint_dp_vector_exact_gc_consume,
    .session = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  release_instance_json <- .dsvert_joint_dp_vector_instance_from_receipts(
    first_prepare_json, second_prepare_json)
  .dsvert_joint_dp_vector_instance_claim_preflight(
    .policy, .secret, release_instance_json)
  contract <- .dsvert_joint_dp_vector_contract(
    .policy, manifest_json, release_instance_json,
    .planner, secret = .secret)
  if (!.policy$peer_name %in% contract$designated) {
    stop("Only a designated pinned noise peer may commit a vector result.",
         call. = FALSE)
  }
  prepares <- .dsvert_joint_dp_vector_prepare_set(
    first_prepare_json, second_prepare_json, .policy, contract, .verifier)
  capsule_id <- contract$release_contract$capsule_id
  release_instance_id <- contract$release_contract$release_instance_id
  durable <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      list(
        capsule = .dsvert_joint_dp_vector_capsule_load(
          connection, release_instance_id, .secret),
        claim = .dsvert_joint_dp_vector_instance_claim_load(
          connection, capsule_id, .secret))
    })
  durable_capsule <- durable$capsule
  if (!is.null(durable_capsule) &&
      !identical(durable_capsule$release_contract_hash,
                 contract$release_contract_hash)) {
    stop("The vector result has no matching durable prepare.",
         call. = FALSE)
  }
  expected_claim <- .dsvert_joint_dp_vector_instance_claim_material(
    capsule_id, release_instance_id, contract$release_contract_hash)
  if (!is.null(durable$claim) &&
      !identical(durable$claim$release_instance_id,
                 release_instance_id)) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  if (!is.null(durable$claim) &&
      !identical(durable$claim, expected_claim)) {
    stop("The durable joint-DP vector release-instance claim conflicts with its contract.",
         call. = FALSE)
  }
  # Finalization deliberately removes intermediate noised chunks. A durable,
  # authenticated result must therefore win before session/chunk recovery.
  if (!is.null(durable_capsule$local_result_json)) {
    .dsvert_joint_dp_vector_instance_claim_contract(
      .policy, .secret, contract, create = FALSE)
    return(durable_capsule$local_result_json)
  }
  present <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      lapply(seq.int(0, contract$release_contract$chunk_count - 1L),
             function(index) .dsvert_joint_dp_vector_noised_load(
               connection, release_instance_id, index, .secret))
    })
  missing <- which(vapply(present, is.null, logical(1L))) - 1L
  if (any(!vapply(present, is.null, logical(1L))) &&
      is.null(durable$claim)) {
    .dsvert_joint_dp_vector_instance_claim_contract(
      .policy, .secret, contract, create = FALSE)
  }
  if (length(missing) && is.null(session_id)) {
    expected_miss <- is.list(durable_capsule) &&
      identical(durable_capsule$version,
                .DSVERT_JOINT_DP_VECTOR_STORE_VERSION) &&
      identical(durable_capsule$state, "prepared") &&
      identical(durable_capsule$compacted, FALSE) &&
      identical(durable_capsule$capsule_id, capsule_id) &&
      identical(durable_capsule$release_instance_id,
                release_instance_id) &&
      identical(durable_capsule$manifest_sha256,
                contract$release_contract$manifest_sha256) &&
      identical(durable_capsule$release_contract_hash,
                contract$release_contract_hash) &&
      identical(durable_capsule$transcript_hash,
                contract$transcript_hash) &&
      identical(
        .dsvert_dp_canonical_query_value(durable_capsule$release_contract),
        .dsvert_dp_canonical_query_value(contract$release_contract)) &&
      identical(.dsvert_joint_dp_hash(durable_capsule$plan),
                contract$plan_sha256) &&
      identical(unlist(durable_capsule$designated, use.names = FALSE),
                contract$designated) &&
      identical(durable_capsule$allocation_authorized, TRUE) &&
      is.character(durable_capsule$allocation_index) &&
      length(durable_capsule$allocation_index) == 1L &&
      !is.na(durable_capsule$allocation_index) &&
      is.character(durable_capsule$allocation_registry_sequence) &&
      length(durable_capsule$allocation_registry_sequence) == 1L &&
      !is.na(durable_capsule$allocation_registry_sequence) &&
      is.character(durable_capsule$allocation_opening_set_hash) &&
      length(durable_capsule$allocation_opening_set_hash) == 1L &&
      !is.na(durable_capsule$allocation_opening_set_hash) &&
      grepl("^[0-9a-f]{64}$",
            durable_capsule$allocation_opening_set_hash) &&
      identical(durable_capsule$prepare_receipt_json,
                .dsvert_joint_dp_vector_encode(
                  prepares[[.policy$peer_name]])) &&
      is.null(durable_capsule$local_result_json) &&
      is.null(durable_capsule$release_receipt_json) &&
      is.null(durable_capsule$ack_receipt_json)
    if (!isTRUE(expected_miss)) {
      stop("The incomplete vector result has an invalid durable state.",
           call. = FALSE)
    }
    for (index in setdiff(seq_along(present) - 1L, missing)) {
      chunk <- .dsvert_joint_dp_vector_chunk_geometry(
        contract$release_contract, index)
      record <- present[[index + 1L]]
      if (!identical(record$version,
                     .DSVERT_JOINT_DP_VECTOR_STORE_VERSION) ||
          !identical(record$capsule_id, capsule_id) ||
          !identical(record$release_instance_id, release_instance_id) ||
          !identical(as.numeric(record$chunk_index),
                     as.numeric(chunk$index)) ||
          !identical(as.numeric(record$coordinate_offset),
                     as.numeric(chunk$offset)) ||
          !identical(as.numeric(record$coordinates_in_chunk),
                     as.numeric(chunk$count))) {
        stop("The incomplete vector result has an invalid durable chunk.",
             call. = FALSE)
      }
      .dsvert_joint_dp_vector_local_chunk_commitment(record, contract)
      if (!isTRUE(contract$profile$exact_gc)) {
        receipt <- .dsvert_joint_dp_vector_receipt(
          record$receipt_json, .policy,
          .DSVERT_JOINT_DP_VECTOR_START_VERSION, "vector_chunk_noised",
          contract, .verifier, "stored start receipt")
        .dsvert_joint_dp_vector_start_validate(receipt, contract, chunk)
      }
    }
    stop(.dsvert_phase_not_ready_condition())
  }
  # A non-cold RESULT may consume or commit output next. START must already
  # have bound this exact release instance; RESULT never backfills the claim.
  .dsvert_joint_dp_vector_instance_claim_contract(
    .policy, .secret, contract, create = FALSE)
  if (isTRUE(contract$profile$exact_gc)) {
    if (length(missing)) {
      if (!is.function(.exact_consume)) {
        stop("Invalid one-draw exact-GC vector consumer.", call. = FALSE)
      }
      session_id <- .dsvert_relay_validate_session_id(session_id)
      if (is.null(.session)) .session <- .S(session_id)
      if (!is.environment(.session) ||
          (!is.null(.session$session_id) &&
           !identical(.session$session_id, session_id))) {
        stop("Exact-GC vector output is not yet durable; retry after its pinned session is restored.",
             call. = FALSE)
      }
      for (index in missing) {
        chunk <- .dsvert_joint_dp_vector_chunk_geometry(
          contract$release_contract, index)
        operation <- .dsvert_joint_dp_vector_exact_gc_operation(
          .session, contract, prepares, chunk, .policy,
          .compiler = .exact_compiler)
        commit <- function(internal) {
          record <- list(
            version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
            capsule_id = capsule_id,
            release_instance_id = release_instance_id,
            chunk_index = chunk$index,
            coordinate_offset = chunk$offset,
            coordinates_in_chunk = chunk$count,
            noised_share_b64 = internal$noised_share_b64,
            noised_share_sha256 = internal$noised_share_sha256,
            validity_share_b64 = internal$validity_share_b64,
            validity_share_sha256 = internal$validity_share_sha256,
            binding_sha256 = internal$binding_sha256,
            exact_gc_operation_id = internal$operation_id,
            exact_gc_purpose = internal$purpose,
            backend = internal$backend,
            payload_chars = as.numeric(
              nchar(internal$noised_share_b64, type = "bytes") +
                nchar(internal$validity_share_b64, type = "bytes")),
            receipt_json = NULL)
          record$output_commitment_sha256 <-
            .dsvert_joint_dp_vector_local_chunk_commitment(record, contract)
          .dsvert_joint_dp_vector_with_store(
            .policy, .secret, function(connection) {
              .dsvert_joint_dp_vector_transaction(connection, {
                .dsvert_joint_dp_vector_instance_claim_require_connection(
                  connection, .secret, capsule_id, release_instance_id,
                  contract$release_contract_hash)
                capsule <- .dsvert_joint_dp_vector_capsule_load(
                  connection, release_instance_id, .secret)
                if (is.null(capsule) ||
                    !identical(capsule$release_contract_hash,
                               contract$release_contract_hash)) {
                  stop("The exact-GC vector output has no durable prepare.",
                       call. = FALSE)
                }
                .dsvert_joint_dp_vector_noised_put(
                  connection, record, .secret)
                TRUE
              })
            })
        }
        .exact_consume(
          .session, operation$binding, operation$worker,
          .commit = commit)
      }
    }
  }
  .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_transaction(connection, {
        .dsvert_joint_dp_vector_instance_claim_require_connection(
          connection, .secret, capsule_id, release_instance_id,
          contract$release_contract_hash)
        capsule <- .dsvert_joint_dp_vector_capsule_load(
          connection, release_instance_id, .secret)
        if (is.null(capsule) ||
            !identical(capsule$release_contract_hash,
                       contract$release_contract_hash)) {
          stop("The vector result has no matching durable prepare.",
               call. = FALSE)
        }
        if (!is.null(capsule$local_result_json)) {
          return(capsule$local_result_json)
        }
        chunks <- lapply(
          seq.int(0, contract$release_contract$chunk_count - 1L),
          function(index) {
            .dsvert_joint_dp_vector_noised_load(
              connection, release_instance_id, index, .secret)
          })
        if (any(vapply(chunks, is.null, logical(1L)))) {
          stop("All vector chunks must be durably noised before RESULT.",
               call. = FALSE)
        }
        commitments <- vapply(chunks, function(record) {
          .dsvert_joint_dp_vector_local_chunk_commitment(record, contract)
        }, character(1L))
        unsigned <- c(.dsvert_joint_dp_vector_common_unsigned(
          contract, .policy, .DSVERT_JOINT_DP_VECTOR_RESULT_VERSION,
          "vector_local_result_committed"), list(
            local_chunk_commitments = as.list(commitments),
            local_chunk_set_root =
              .dsvert_joint_dp_vector_merkle_root(commitments),
            local_chunk_set_sha256 = .dsvert_joint_dp_hash(list(
              protocol = "dsvert-joint-dp-vector-local-chunk-set-v3",
              peer_name = .policy$peer_name,
              commitments = as.list(commitments))),
            all_chunks_durable = TRUE,
            intermediate_payload_exposed = FALSE,
            capability_available = TRUE))
        result <- .dsvert_joint_dp_vector_sign(unsigned, .policy, .signer)
        result_json <- .dsvert_joint_dp_vector_encode(result)
        capsule$state <- "result"
        capsule$local_result_json <- result_json
        .dsvert_joint_dp_vector_capsule_put(
          connection, capsule, .secret, existing = capsule)
        result_json
      })
    })
}

.dsvert_joint_dp_vector_transfer_context <- function(
    contract, result_set_hash, chunk, noised_share_sha256) {
  .dsvert_dp_canonical_query_value(list(
    capsule_id = contract$release_contract$capsule_id,
    release_contract_hash = contract$release_contract_hash,
    result_set_hash = result_set_hash,
    chunk_index = as.character(chunk$index),
    chunk_count = as.character(contract$release_contract$chunk_count),
    coordinate_count = as.character(chunk$count), ring = "128",
    noised_share_sha256 = noised_share_sha256))
}

.dsvert_joint_dp_vector_final_share_impl <- function(
    session_id, manifest_json, first_result_json, second_result_json,
    chunk_index, .policy = NULL, .secret = NULL, .verifier = NULL,
    .planner = NULL, .encryptor = NULL, .session = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (is.null(.session)) .session <- .S(session_id)
  if (!is.environment(.session) ||
      (!is.null(.session$session_id) &&
       !identical(.session$session_id, session_id))) {
    stop("Invalid joint-DP vector producer session.", call. = FALSE)
  }
  release_instance_json <- .dsvert_joint_dp_vector_instance_from_receipts(
    first_result_json, second_result_json)
  .dsvert_joint_dp_vector_instance_claim_preflight(
    .policy, .secret, release_instance_json)
  contract <- .dsvert_joint_dp_vector_contract(
    .policy, manifest_json, release_instance_json,
    .planner, secret = .secret)
  if (!.policy$peer_name %in% contract$designated) {
    stop("Only a designated pinned noise peer may send a vector share.",
         call. = FALSE)
  }
  results <- .dsvert_joint_dp_vector_result_set(
    first_result_json, second_result_json, .policy, contract, .verifier)
  result_set_hash <- .dsvert_joint_dp_vector_result_set_hash(results)
  chunk <- .dsvert_joint_dp_vector_chunk_geometry(
    contract$release_contract, chunk_index)
  durable <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_instance_claim_require_connection(
        connection, .secret,
        contract$release_contract$capsule_id,
        contract$release_contract$release_instance_id,
        contract$release_contract_hash)
      list(
        capsule = .dsvert_joint_dp_vector_capsule_load(
          connection, contract$release_contract$release_instance_id,
          .secret),
        chunk = .dsvert_joint_dp_vector_noised_load(
          connection, contract$release_contract$release_instance_id,
          chunk$index, .secret))
    })
  if (is.null(durable$capsule) || is.null(durable$chunk) ||
      !identical(durable$capsule$local_result_json,
                 .dsvert_joint_dp_vector_encode(
                   results[[.policy$peer_name]])) ||
      !identical(
        .dsvert_joint_dp_vector_local_chunk_commitment(
          durable$chunk, contract),
        unlist(results[[.policy$peer_name]]$local_chunk_commitments,
               use.names = FALSE)[[chunk$index + 1L]])) {
    stop("The vector share is not bound to the durable local result.",
         call. = FALSE)
  }
  recipient <- setdiff(contract$designated, .policy$peer_name)
  peer_pk <- (.session$peer_transport_pks %||% list())[[recipient]]
  if (length(recipient) != 1L || is.null(peer_pk)) {
    stop("The vector recipient is absent from the pinned transport map.",
         call. = FALSE)
  }
  context <- .dsvert_joint_dp_vector_transfer_context(
    contract, result_set_hash, chunk,
    .dsvert_joint_dp_vector_local_chunk_commitment(
      durable$chunk, contract))
  request <- list(
    session_id = session_id,
    capsule_id = contract$release_contract$capsule_id,
    release_contract_hash = contract$release_contract_hash,
    result_set_hash = result_set_hash,
    chunk_index = chunk$index, recipient_name = recipient)
  replay <- .dsvert_typed_blob_operation_replay(
    .session, .DSVERT_JOINT_DP_VECTOR_TRANSFER_PRODUCER, request)
  if (isTRUE(replay$hit)) return(replay$result)

  .dsvert_joint_dp_vector_instance_claim_contract(
    .policy, .secret, contract, create = FALSE)
  header <- c(list(
    version = .DSVERT_JOINT_DP_VECTOR_TRANSFER_VERSION,
    capsule_id = contract$release_contract$capsule_id,
    release_contract_hash = contract$release_contract_hash,
    result_set_hash = result_set_hash,
    sender_name = .policy$peer_name,
    chunk_index = chunk$index,
    chunk_count = contract$release_contract$chunk_count,
    coordinate_offset = chunk$offset,
    coordinate_count = chunk$count, ring_bits = 128L,
    noised_share_sha256 = durable$chunk$noised_share_sha256,
    noised_share_b64 = durable$chunk$noised_share_b64),
    if (isTRUE(contract$profile$exact_gc)) list(
      validity_share_sha256 = durable$chunk$validity_share_sha256,
      validity_share_b64 = durable$chunk$validity_share_b64,
      binding_sha256 = durable$chunk$binding_sha256,
      output_commitment_sha256 =
        durable$chunk$output_commitment_sha256) else list())
  plaintext <- charToRaw(.dsvert_joint_dp_vector_encode(header))
  sealed <- if (is.null(.encryptor)) {
    .callMpcTool("transport-encrypt", list(
      data = gsub("[\r\n]", "", jsonlite::base64_enc(plaintext)),
      recipient_pk = peer_pk))$sealed
  } else {
    if (!is.function(.encryptor)) {
      stop("Invalid joint-DP vector encryptor.", call. = FALSE)
    }
    .encryptor(plaintext, peer_pk)
  }
  ciphertext <- base64_to_base64url(
    .dsvert_joint_dp_vector_scalar(
      sealed, "encrypted noised share", maximum_bytes = 32L * 1024L^2))
  transfer <- .dsvert_typed_blob_mint(
    .session, session_id, .DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY,
    base64_to_base64url(peer_pk), ciphertext, context,
    producer = .DSVERT_JOINT_DP_VECTOR_TRANSFER_PRODUCER)
  result <- list(
    ciphertext = ciphertext, transfer = transfer,
    capsule_id = contract$release_contract$capsule_id,
    release_contract_hash = contract$release_contract_hash,
    result_set_hash = result_set_hash, chunk_index = chunk$index,
    intermediate_payload_exposed = FALSE,
    capability_available = TRUE)
  .dsvert_typed_blob_operation_commit(
    .session, .DSVERT_JOINT_DP_VECTOR_TRANSFER_PRODUCER,
    request, result)
}

.dsvert_joint_dp_vector_transfer_decode <- function(
    plaintext, contract, result_set_hash, sender, chunk,
    expected_hash) {
  if (!is.raw(plaintext) || !length(plaintext) ||
      length(plaintext) > 16L * chunk$count + 65536L) {
    stop("Invalid decrypted joint-DP vector transfer.", call. = FALSE)
  }
  header <- .dsvert_joint_dp_vector_decode_json(
    rawToChar(plaintext), "decrypted transfer", 16L * chunk$count + 65536L)
  required <- c(
    "version", "capsule_id", "release_contract_hash", "result_set_hash",
    "sender_name", "chunk_index", "chunk_count", "coordinate_offset",
    "coordinate_count", "ring_bits", "noised_share_sha256",
    "noised_share_b64", if (isTRUE(contract$profile$exact_gc)) c(
      "validity_share_sha256", "validity_share_b64", "binding_sha256",
      "output_commitment_sha256") else character())
  valid <- setequal(names(header), required) &&
    identical(header$version, .DSVERT_JOINT_DP_VECTOR_TRANSFER_VERSION) &&
    identical(header$capsule_id,
              contract$release_contract$capsule_id) &&
    identical(header$release_contract_hash,
              contract$release_contract_hash) &&
    identical(header$result_set_hash, result_set_hash) &&
    identical(header$sender_name, sender) &&
    identical(as.numeric(header$chunk_index), as.numeric(chunk$index)) &&
    identical(as.numeric(header$chunk_count),
              as.numeric(contract$release_contract$chunk_count)) &&
    identical(as.numeric(header$coordinate_offset),
              as.numeric(chunk$offset)) &&
    identical(as.numeric(header$coordinate_count),
              as.numeric(chunk$count)) &&
    identical(as.numeric(header$ring_bits), 128) &&
    if (isTRUE(contract$profile$exact_gc)) {
      identical(header$output_commitment_sha256, expected_hash)
    } else {
      identical(header$noised_share_sha256, expected_hash)
    }
  if (!isTRUE(valid)) {
    stop("The decrypted vector transfer has the wrong result binding.",
         call. = FALSE)
  }
  share <- .dsvert_joint_dp_vector_standard_b64(
    header$noised_share_b64, "decrypted noised share", chunk$count * 16L)
  expected_share_hash <- if (isTRUE(contract$profile$exact_gc)) {
    header$noised_share_sha256
  } else {
    expected_hash
  }
  if (!identical(digest::digest(
        share, algo = "sha256", serialize = FALSE),
      expected_share_hash)) {
    stop("The decrypted noised share failed its signed commitment.",
         call. = FALSE)
  }
  result <- list(share_b64 = header$noised_share_b64)
  if (isTRUE(contract$profile$exact_gc)) {
    validity <- .dsvert_joint_dp_vector_standard_b64(
      header$validity_share_b64, "decrypted validity share", 1L)
    computed <- .dsvert_joint_dp_hash(list(
      protocol = "dsvert-joint-dp-vector-exact-gc-output-commitment-v1",
      noised_share_sha256 = header$noised_share_sha256,
      validity_share_sha256 = digest::digest(
        validity, algo = "sha256", serialize = FALSE),
      binding_sha256 = header$binding_sha256))
    if (!identical(digest::digest(
          validity, algo = "sha256", serialize = FALSE),
        header$validity_share_sha256) ||
        !grepl("^[0-9a-f]{64}$", header$binding_sha256) ||
        !identical(computed, header$output_commitment_sha256)) {
      stop("The exact-GC validity share failed its signed commitment.",
           call. = FALSE)
    }
    result$validity_share_b64 <- header$validity_share_b64
    result$binding_sha256 <- header$binding_sha256
  }
  result
}

.dsvert_joint_dp_vector_finalizer_validate <- function(
    output, contract, chunk, upper_bounds, scale_shifts) {
  required <- c(
    "version", "backend", "sampler", "release_contract_hash",
    "transcript_hash", "ring_bits", "frac_bits",
    "total_coordinate_count", "chunk_start", "coordinate_count",
    "output_lattice_bits", "clamped_scaled_values",
    "preclamp_values_returned", "signed_decode", "clamping",
    "no_wrap_headroom_certified", "plan")
  if (contract$profile$gaussian) required <- c(required, "mechanism")
  values <- unlist(output$clamped_scaled_values, use.names = FALSE)
  valid <- is.list(output) && setequal(names(output), required) &&
    identical(output$version, contract$profile$finalizer_version) &&
    identical(output$backend, contract$release_contract$backend) &&
    identical(output$sampler, contract$release_contract$sampler) &&
    (!contract$profile$gaussian ||
       identical(output$mechanism, contract$release_contract$mechanism)) &&
    identical(output$release_contract_hash,
              contract$release_contract_hash) &&
    identical(output$transcript_hash, contract$transcript_hash) &&
    identical(as.numeric(output$ring_bits), 128) &&
    identical(as.numeric(output$frac_bits), 0) &&
    identical(as.numeric(output$total_coordinate_count),
              as.numeric(contract$release_contract$coordinate_count)) &&
    identical(as.numeric(output$chunk_start), as.numeric(chunk$offset)) &&
    identical(as.numeric(output$coordinate_count), as.numeric(chunk$count)) &&
    identical(as.numeric(output$output_lattice_bits),
              as.numeric(contract$release_contract$output_lattice_bits)) &&
    is.character(values) && length(values) == chunk$count &&
    !anyNA(values) && all(grepl("^(0|[1-9][0-9]*)$", values)) &&
    identical(output$preclamp_values_returned, FALSE) &&
    identical(output$signed_decode,
              "canonical_Ring128_twos_complement_after_proven_no_wrap") &&
    identical(output$clamping,
              "single_fixed_public_per_coordinate_interval_postprocessing") &&
    identical(output$no_wrap_headroom_certified, TRUE) &&
    identical(.dsvert_dp_canonical_query_value(output$plan),
              .dsvert_dp_canonical_query_value(contract$plan))
  if (isTRUE(valid)) {
    valid <- all(vapply(seq_along(values), function(index) {
      value <- tryCatch(openssl::bignum(values[[index]]),
                        error = function(e) NULL)
      upper <- tryCatch(openssl::bignum(upper_bounds[[index]]) *
                          openssl::bignum(as.character(2^scale_shifts[[index]])),
                        error = function(e) NULL)
      !is.null(value) && !is.null(upper) && value <= upper
    }, logical(1L)))
  }
  if (!isTRUE(valid)) {
    stop("The joint-DP vector finalizer returned an invalid certificate.",
         call. = FALSE)
  }
  as.list(values)
}

.dsvert_joint_dp_vector_public_chunk <- function(
    contract, chunk, scaled_values) {
  public <- list(
    version = .DSVERT_JOINT_DP_VECTOR_CHUNK_VERSION,
    capsule_id = contract$release_contract$capsule_id,
    release_contract_hash = contract$release_contract_hash,
    chunk_index = chunk$index,
    chunk_count = contract$release_contract$chunk_count,
    coordinate_offset = chunk$offset,
    coordinates_in_chunk = chunk$count,
    output_lattice_bits = contract$release_contract$output_lattice_bits,
    output_lattice_scale = contract$release_contract$output_lattice_scale,
    scaled_values = scaled_values,
    value_encoding = "nonnegative-decimal-integer-common-lattice-v1",
    postprocessing = contract$profile$postprocessing,
    source_values_exposed = FALSE,
    preclamp_values_exposed = FALSE)
  list(public = .dsvert_dp_canonical_query_value(public),
       hash = .dsvert_joint_dp_hash(public))
}

.dsvert_joint_dp_vector_release_validate <- function(
    receipt, contract) {
  hashes <- unlist(receipt$final_chunk_hashes, use.names = FALSE)
  implementation_delta <-
    .dsvert_joint_dp_vector_implementation_delta(contract)
  valid <- receipt$peer_name %in% contract$designated &&
    is.character(receipt$result_set_hash) &&
    grepl("^[0-9a-f]{64}$", receipt$result_set_hash) &&
    is.character(hashes) &&
    length(hashes) == contract$release_contract$chunk_count &&
    !anyNA(hashes) && all(grepl("^[0-9a-f]{64}$", hashes)) &&
    identical(receipt$final_vector_root,
              .dsvert_joint_dp_vector_merkle_root(hashes)) &&
    identical(as.numeric(receipt$output_lattice_bits),
              as.numeric(contract$release_contract$output_lattice_bits)) &&
    identical(as.numeric(receipt$output_lattice_scale),
              as.numeric(contract$release_contract$output_lattice_scale)) &&
    identical(receipt$mechanism, contract$profile$release_mechanism) &&
    identical(receipt$epsilon, contract$release_contract$epsilon) &&
    identical(receipt$delta,
              contract$release_contract$allocated_delta) &&
    identical(receipt$implementation_delta_numerator,
              implementation_delta[[1L]]) &&
    identical(receipt$implementation_delta_denominator,
              implementation_delta[[2L]]) &&
    identical(receipt$delta_aggregation,
              contract$profile$delta_aggregation) &&
    identical(receipt$postprocessing,
              contract$profile$postprocessing) &&
    identical(receipt$intermediate_payload_exposed, FALSE) &&
    identical(receipt$durable_replay, TRUE) &&
    identical(receipt$capability_available, TRUE)
  if (!isTRUE(valid)) {
    stop("The joint-DP vector release receipt is inconsistent.",
         call. = FALSE)
  }
  invisible(receipt)
}

.dsvert_joint_dp_vector_release_set <- function(
    first_json, second_json, policy, contract, verifier = NULL) {
  values <- .dsvert_joint_dp_vector_receipt_set(
    first_json, second_json, policy,
    .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION, "vector_released",
    contract, verifier, "release receipt")
  invisible(lapply(values, .dsvert_joint_dp_vector_release_validate,
                   contract = contract))
  roots <- vapply(values, `[[`, character(1L), "final_vector_root")
  result_sets <- vapply(values, `[[`, character(1L), "result_set_hash")
  chunk_sets <- lapply(values, `[[`, "final_chunk_hashes")
  if (length(unique(roots)) != 1L || length(unique(result_sets)) != 1L ||
      !identical(chunk_sets[[1L]], chunk_sets[[2L]])) {
    stop("The two vector releases do not commit the same final vector.",
         call. = FALSE)
  }
  values
}

.dsvert_joint_dp_vector_contract_from_record <- function(record) {
  required <- c(
    "capsule_id", "release_instance_id", "release_contract_hash",
    "transcript_hash",
    "release_contract", "plan", "designated")
  if (is.null(record) || any(vapply(required, function(name) {
        is.null(record[[name]])
      }, logical(1L))) ||
      !identical(record$release_contract_hash,
                 .dsvert_joint_dp_hash(record$release_contract)) ||
      !identical(record$capsule_id, record$release_contract$capsule_id) ||
      !identical(record$release_instance_id,
                 record$release_contract$release_instance_id)) {
    stop("The durable joint-DP vector contract is invalid.",
         call. = FALSE)
  }
  profile <- .dsvert_joint_dp_vector_profile(
    record$release_contract$mechanism,
    record$release_contract$backend)
  if (!is.list(record$release_contract$backend_selection)) {
    # v3 convolution records predate the signed public cost selector. They
    # remain replayable, but no new release can omit the selector.
    profile$selection_bound <- FALSE
  }
  list(
    release_contract = record$release_contract,
    release_contract_hash = record$release_contract_hash,
    transcript_hash = record$transcript_hash,
    plan = record$plan,
    plan_sha256 = .dsvert_joint_dp_hash(record$plan),
    designated = unlist(record$designated, use.names = FALSE),
    profile = profile)
}

.dsvert_joint_dp_vector_existing_release <- function(
    policy, secret, manifest_json, release_instance_json) {
  .dsvert_dp_capsule_manifest_require_built(
    policy, manifest_json, secret = secret)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  designated <- .dsvert_joint_dp_policy_context(
    policy)$common$designated_noise_peers
  instance <- .dsvert_joint_dp_vector_release_instance(
    policy, manifest, sort(designated, method = "radix"),
    release_instance_json, require_active_local_root = FALSE)
  record <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      .dsvert_joint_dp_vector_capsule_load(
        connection, instance$id, secret)
    })
  if (is.null(record) || is.null(record$release_receipt_json)) return(NULL)
  if (!identical(record$manifest_sha256,
                 digest::digest(manifest_json, algo = "sha256",
                                serialize = FALSE))) {
    stop("The durable vector release belongs to another manifest.",
         call. = FALSE)
  }
  list(record = record, contract =
         .dsvert_joint_dp_vector_contract_from_record(record))
}

.dsvert_joint_dp_vector_default_peer_reader <- function(
    session, context, sender, contract, result_set_hash, chunk,
    expected_hash) {
  encrypted <- .dsvert_typed_blob_consume(
    session, .DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY,
    context, sender_name = sender, required = FALSE, consume = FALSE)
  if (is.null(encrypted)) {
    stop(.dsvert_phase_not_ready_condition())
  }
  opened <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(encrypted),
    recipient_sk = .key_get("transport_sk", session)))
  plaintext <- tryCatch(
    jsonlite::base64_dec(opened$data), error = function(e) NULL)
  decoded <- .dsvert_joint_dp_vector_transfer_decode(
    plaintext, contract, result_set_hash, sender, chunk, expected_hash)
  c(decoded, list(encrypted = encrypted))
}

.dsvert_joint_dp_vector_release_admit_connection <- function(
    connection, policy, secret, contract) {
  capsule_id <- contract$release_contract$capsule_id
  release_instance_id <- contract$release_contract$release_instance_id
  .dsvert_joint_dp_vector_instance_claim_require_connection(
    connection, secret, capsule_id, release_instance_id,
    contract$release_contract_hash)
  release_config <-
    .dsvert_joint_dp_release_ledger_config_from_policy(policy)
  .dsvert_joint_dp_release_ledger_admit_new_capsule(
    connection, release_config, secret, capsule_id)
  invisible(TRUE)
}

.dsvert_joint_dp_vector_release_impl <- function(
    session_id, manifest_json, first_result_json, second_result_json,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL,
    .planner = NULL, .finalizer = NULL, .peer_share_reader = NULL,
    .exact_finalizer = .dsvert_joint_dp_vector_exact_gc_finalize,
    .session = NULL, .phase_hook = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()

  release_instance_json <- .dsvert_joint_dp_vector_instance_from_receipts(
    first_result_json, second_result_json)

  # A committed release wins before session lookup, source access or sampling.
  existing <- .dsvert_joint_dp_vector_existing_release(
    .policy, .secret, manifest_json, release_instance_json)
  if (!is.null(existing)) {
    .dsvert_joint_dp_vector_instance_claim_contract(
      .policy, .secret, existing$contract, create = FALSE)
    return(existing$record$release_receipt_json)
  }

  .dsvert_joint_dp_vector_allocation_require(
    .policy, manifest_json, .secret, .verifier)

  historical_manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  historical_designated <- sort(
    .dsvert_joint_dp_policy_context(
      .policy)$common$designated_noise_peers,
    method = "radix")
  historical_instance <- .dsvert_joint_dp_vector_release_instance(
    .policy, historical_manifest, historical_designated,
    release_instance_json, require_active_local_root = FALSE)
  release_claim <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_instance_claim_load(
        connection, historical_instance$value$capsule_id, .secret)
    })
  if (!is.null(release_claim) &&
      !identical(release_claim$release_instance_id,
                 historical_instance$id)) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  if (.dsvert_joint_dp_vector_release_was_published(
        .policy, .secret, historical_instance$id)) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  active_release_domain <- .dsvert_joint_dp_vector_active_release_domain(
    .policy, .secret)
  if (!.dsvert_joint_dp_vector_local_root_is_active(
        .policy, historical_instance, active_release_domain)) {
    if (!is.null(release_claim)) {
      stop(.dsvert_dp_lifetime_budget_exhausted_condition())
    }
    .dsvert_joint_dp_vector_retry_current_instance(
      historical_instance, "new_release_instance",
      "The signed release instance uses a rotated or regenerated root.")
  }

  contract <- .dsvert_joint_dp_vector_contract(
    .policy, manifest_json, release_instance_json,
    .planner, secret = .secret)
  if (!.policy$peer_name %in% contract$designated) {
    stop("Only a designated pinned noise peer may finalize the vector.",
         call. = FALSE)
  }
  results <- .dsvert_joint_dp_vector_result_set(
    first_result_json, second_result_json, .policy, contract, .verifier)
  result_set_hash <- .dsvert_joint_dp_vector_result_set_hash(results)
  capsule_id <- contract$release_contract$capsule_id
  release_instance_id <- contract$release_contract$release_instance_id
  capsule <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_capsule_load(
        connection, release_instance_id, .secret)
    })
  if (is.null(capsule) ||
      !identical(capsule$local_result_json,
                 .dsvert_joint_dp_vector_encode(
                   results[[.policy$peer_name]]))) {
    if (!is.null(release_claim)) {
      stop(.dsvert_dp_lifetime_budget_exhausted_condition())
    }
    .dsvert_joint_dp_vector_retry_current_instance(
      historical_instance, "retry_unpublished_instance",
      paste("The sticky vector intermediates are unavailable;",
            "the same active roots will reproduce them."))
  }
  .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_release_admit_connection(
        connection, .policy, .secret, contract)
    })
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (is.null(.session)) .session <- .S(session_id)
  if (!is.environment(.session)) {
    stop("Invalid joint-DP vector release session.", call. = FALSE)
  }
  peer <- setdiff(contract$designated, .policy$peer_name)
  if (length(peer) != 1L) {
    stop("The vector final-share sender is ambiguous.", call. = FALSE)
  }
  if (is.null(.peer_share_reader)) {
    .peer_share_reader <- .dsvert_joint_dp_vector_default_peer_reader
  }
  if (!is.function(.peer_share_reader)) {
    stop("Invalid joint-DP vector peer-share reader.", call. = FALSE)
  }
  if (isTRUE(contract$profile$exact_gc)) {
    if (!is.function(.exact_finalizer)) {
      stop("Invalid one-draw exact-GC vector finalizer.", call. = FALSE)
    }
  } else {
    if (is.null(.finalizer)) .finalizer <- function(value) {
      .callMpcTool(contract$profile$finalizer_command, value)
    }
    if (!is.function(.finalizer)) {
      stop("Invalid joint-DP vector finalizer.", call. = FALSE)
    }
  }
  own_commitments <- unlist(
    results[[.policy$peer_name]]$local_chunk_commitments,
    use.names = FALSE)
  peer_commitments <- unlist(
    results[[peer]]$local_chunk_commitments, use.names = FALSE)
  read_payloads <- vector("list", contract$release_contract$chunk_count)

  for (index in seq.int(0, contract$release_contract$chunk_count - 1L)) {
    chunk <- .dsvert_joint_dp_vector_chunk_geometry(
      contract$release_contract, index)
    present <- .dsvert_joint_dp_vector_with_store(
      .policy, .secret, function(connection) {
        .dsvert_joint_dp_vector_final_load(
          connection, release_instance_id, index, .secret)
      })
    if (!is.null(present)) next
    own <- .dsvert_joint_dp_vector_with_store(
      .policy, .secret, function(connection) {
        .dsvert_joint_dp_vector_noised_load(
          connection, release_instance_id, index, .secret)
      })
    if (is.null(own)) {
      .dsvert_joint_dp_vector_retry_current_instance(
        historical_instance, "retry_unpublished_instance",
        paste("A sticky vector chunk is unavailable;",
              "the same active roots will reproduce it."))
    }
    if (!identical(
          .dsvert_joint_dp_vector_local_chunk_commitment(own, contract),
          own_commitments[[index + 1L]])) {
      stop("The durable local noised vector chunk conflicts with its signed commitment.",
           call. = FALSE)
    }
    context <- .dsvert_joint_dp_vector_transfer_context(
      contract, result_set_hash, chunk,
      peer_commitments[[index + 1L]])
    peer_share <- .peer_share_reader(
      .session, context, peer, contract, result_set_hash, chunk,
      peer_commitments[[index + 1L]])
    if (!is.list(peer_share) ||
        !is.character(peer_share$share_b64) ||
        length(peer_share$share_b64) != 1L) {
      stop("The peer-share reader returned an invalid vector chunk.",
           call. = FALSE)
    }
    .dsvert_joint_dp_vector_standard_b64(
      peer_share$share_b64, "peer noised share", chunk$count * 16L)
    positions <- seq.int(chunk$offset + 1L, chunk$offset + chunk$count)
    if (isTRUE(contract$profile$exact_gc)) {
      exact_peer_fields <- c("validity_share_b64", "binding_sha256")
      if (any(vapply(exact_peer_fields, function(name) {
            value <- peer_share[[name]]
            !is.character(value) || length(value) != 1L || is.na(value)
          }, logical(1L))) ||
          !identical(peer_share$binding_sha256, own$binding_sha256)) {
        stop("The exact-GC vector shares have different operation bindings.",
             call. = FALSE)
      }
      scaled_upper_bounds <- vapply(positions, function(position) {
        upper <- openssl::bignum(
          contract$lattice$raw_upper_bounds[[position]])
        shift <- as.integer(contract$lattice$scale_shifts[[position]])
        as.character(upper * (openssl::bignum(2) ^ shift))
      }, character(1L))
      output <- .exact_finalizer(
        own = list(
          noised_share_b64 = own$noised_share_b64,
          validity_share_b64 = own$validity_share_b64,
          binding_sha256 = own$binding_sha256),
        peer = list(
          noised_share_b64 = peer_share$share_b64,
          validity_share_b64 = peer_share$validity_share_b64,
          binding_sha256 = peer_share$binding_sha256),
        scaled_upper_bounds = scaled_upper_bounds,
        binding_sha256 = own$binding_sha256)
      if (!is.list(output) ||
          !identical(output$version,
                     .DSVERT_JOINT_DP_VECTOR_EXACT_GC_FINAL_VERSION) ||
          !identical(output$backend, contract$profile$backend) ||
          !identical(output$binding_sha256, own$binding_sha256) ||
          !identical(output$validity, TRUE) ||
          !identical(output$preclamp_values_returned, FALSE)) {
        stop("The exact-GC vector finalizer returned an invalid certificate.",
             call. = FALSE)
      }
      values <- unlist(output$clamped_scaled_values, use.names = FALSE)
      if (!is.character(values) || length(values) != chunk$count ||
          anyNA(values) || any(!grepl("^(0|[1-9][0-9]*)$", values)) ||
          any(vapply(seq_along(values), function(value_index) {
            openssl::bignum(values[[value_index]]) >
              openssl::bignum(scaled_upper_bounds[[value_index]])
          }, logical(1L)))) {
        stop("The exact-GC vector finalizer returned invalid clamped values.",
             call. = FALSE)
      }
      values <- as.list(values)
    } else {
      input <- c(list(
        version = contract$profile$finalizer_input_version,
        ring_bits = 128L, frac_bits = 0L,
        total_coordinate_count = contract$release_contract$coordinate_count,
        chunk_start = chunk$offset, coordinate_count = chunk$count,
        output_lattice_bits = contract$release_contract$output_lattice_bits,
        epsilon = contract$release_contract$epsilon,
        allocated_delta = contract$release_contract$allocated_delta
        ), if (contract$profile$gaussian) {
          list(l2_sensitivity_steps =
                 contract$release_contract$sensitivity_steps)
        } else {
          list(sensitivity_steps =
                 contract$release_contract$sensitivity_steps)
        }, list(
        scale_shifts = as.list(contract$lattice$scale_shifts[positions]),
        raw_upper_bounds =
          as.list(contract$lattice$raw_upper_bounds[positions]),
        release_contract_hash = contract$release_contract_hash,
        transcript_hash = contract$transcript_hash,
        left_noised_share =
          if (.policy$peer_name == contract$designated[[1L]]) {
            own$noised_share_b64
          } else peer_share$share_b64,
        right_noised_share =
          if (.policy$peer_name == contract$designated[[1L]]) {
            peer_share$share_b64
          } else own$noised_share_b64))
      output <- .finalizer(input)
      input$left_noised_share <- NULL
      input$right_noised_share <- NULL
      values <- .dsvert_joint_dp_vector_finalizer_validate(
        output, contract, chunk,
        contract$lattice$raw_upper_bounds[positions],
        contract$lattice$scale_shifts[positions])
    }
    public <- .dsvert_joint_dp_vector_public_chunk(
      contract, chunk, values)
    record <- list(
      version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
      capsule_id = capsule_id,
      release_instance_id = release_instance_id,
      chunk_index = chunk$index,
      chunk_hash = public$hash, public_chunk = public$public)
    .dsvert_joint_dp_vector_with_store(
      .policy, .secret, function(connection) {
        .dsvert_joint_dp_vector_transaction(connection, {
          .dsvert_joint_dp_vector_instance_claim_require_connection(
            connection, .secret, capsule_id, release_instance_id,
            contract$release_contract_hash)
          .dsvert_joint_dp_vector_final_put(
            connection, record, .secret)
        })
      })
    read_payloads[[index + 1L]] <- list(
      context = context, encrypted = peer_share$encrypted %||% NULL)
    if (is.function(.phase_hook)) .phase_hook("after_final_chunk_commit")
  }

  final <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      lapply(seq.int(0, contract$release_contract$chunk_count - 1L),
             function(index) {
        .dsvert_joint_dp_vector_final_load(
          connection, release_instance_id, index, .secret)
      })
    })
  if (any(vapply(final, is.null, logical(1L)))) {
    stop("The final DP vector is incomplete.", call. = FALSE)
  }
  hashes <- vapply(final, `[[`, character(1L), "chunk_hash")
  root <- .dsvert_joint_dp_vector_merkle_root(hashes)
  implementation_delta <-
    .dsvert_joint_dp_vector_implementation_delta(contract)
  unsigned <- c(.dsvert_joint_dp_vector_common_unsigned(
    contract, .policy, .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION,
    "vector_released"), list(
      result_set_hash = result_set_hash,
      final_vector_root = root,
      final_chunk_hashes = as.list(hashes),
      output_lattice_bits = contract$release_contract$output_lattice_bits,
      output_lattice_scale = contract$release_contract$output_lattice_scale,
      mechanism = contract$profile$release_mechanism,
      epsilon = contract$release_contract$epsilon,
      delta = contract$release_contract$allocated_delta,
      implementation_delta_numerator = implementation_delta[[1L]],
      implementation_delta_denominator = implementation_delta[[2L]],
      delta_aggregation = contract$profile$delta_aggregation,
      postprocessing = contract$profile$postprocessing,
      intermediate_payload_exposed = FALSE, durable_replay = TRUE,
      capability_available = TRUE))
  release <- .dsvert_joint_dp_vector_sign(unsigned, .policy, .signer)
  release_json <- .dsvert_joint_dp_vector_encode(release)
  committed <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_transaction(connection, {
        release_config <-
          .dsvert_joint_dp_release_ledger_config_from_policy(.policy)
        .dsvert_joint_dp_vector_instance_claim_require_connection(
          connection, .secret, capsule_id, release_instance_id,
          contract$release_contract_hash)
        current <- .dsvert_joint_dp_vector_capsule_load(
          connection, release_instance_id, .secret)
        if (!is.null(current$release_receipt_json)) {
          if (!identical(current$release_receipt_json, release_json)) {
            stop("Conflicting concurrent vector release.", call. = FALSE)
          }
          .dsvert_joint_dp_release_ledger_commit_connection(
            connection, release_config, .secret,
            release_instance_json, release_json, .phase_hook)
          return(current$release_receipt_json)
        }
        current$state <- "released"
        current$release_receipt_json <- release_json
        .dsvert_joint_dp_vector_capsule_put(
          connection, current, .secret, existing = current)
        .dsvert_joint_dp_release_ledger_commit_connection(
          connection, release_config, .secret,
          release_instance_json, release_json, .phase_hook)
        release_json
      })
    })
  if (is.function(.phase_hook)) .phase_hook("after_vector_release_commit")

  # Payloads are no longer needed after the final DP chunks are durable.
  for (index in seq_along(read_payloads)) {
    chunk <- .dsvert_joint_dp_vector_chunk_geometry(
      contract$release_contract, index - 1L)
    context <- .dsvert_joint_dp_vector_transfer_context(
      contract, result_set_hash, chunk, peer_commitments[[index]])
    read <- read_payloads[[index]]
    consumed <- .dsvert_typed_blob_consume(
      .session, .DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY,
      context, sender_name = peer, required = FALSE, consume = TRUE)
    if (!is.null(consumed) && !is.null(read$encrypted) &&
        !identical(consumed, read$encrypted)) {
      stop("The committed vector ciphertext changed before consumption.",
           call. = FALSE)
    }
  }
  committed
}

.dsvert_joint_dp_vector_replay_impl <- function(
    manifest_json, first_release_json, second_release_json, chunk_index,
    .policy = NULL, .secret = NULL, .verifier = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  release_instance_json <- .dsvert_joint_dp_vector_instance_from_receipts(
    first_release_json, second_release_json)
  existing <- .dsvert_joint_dp_vector_existing_release(
    .policy, .secret, manifest_json, release_instance_json)
  if (is.null(existing)) {
    manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
    designated <- sort(
      .dsvert_joint_dp_policy_context(
        .policy)$common$designated_noise_peers,
      method = "radix")
    instance <- .dsvert_joint_dp_vector_release_instance(
      .policy, manifest, designated, release_instance_json,
      require_active_local_root = FALSE)
    claim_state <- .dsvert_joint_dp_vector_instance_claim_preflight(
      .policy, .secret, release_instance_json)
    if (!is.null(claim_state$claim)) {
      stop(.dsvert_dp_lifetime_budget_exhausted_condition())
    }
    published <- .dsvert_joint_dp_vector_release_was_published(
      .policy, .secret, instance$id)
    if (isTRUE(published)) {
      stop(.dsvert_dp_lifetime_budget_exhausted_condition())
    }
    .dsvert_joint_dp_vector_retry_current_instance(
      instance, "new_release_instance",
      paste(
        "The final vector is unavailable without an authenticated durable",
        "publication record, or its roots already changed."))
  }
  contract <- existing$contract
  releases <- .dsvert_joint_dp_vector_release_set(
    first_release_json, second_release_json, .policy, contract, .verifier)
  own <- releases[[.policy$peer_name]]
  if (is.null(own) ||
      !identical(.dsvert_joint_dp_vector_encode(own),
                 existing$record$release_receipt_json)) {
    stop("The replay receipts do not include the durable local release.",
         call. = FALSE)
  }
  chunk <- .dsvert_joint_dp_vector_chunk_geometry(
    contract$release_contract, chunk_index)
  record <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_final_load(
        connection, contract$release_contract$release_instance_id,
        chunk$index, .secret)
    })
  hashes <- unlist(own$final_chunk_hashes, use.names = FALSE)
  if (is.null(record)) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  if (!identical(record$chunk_hash, hashes[[chunk$index + 1L]]) ||
      !identical(record$chunk_hash,
                 .dsvert_joint_dp_hash(record$public_chunk))) {
    stop("The durable final DP chunk conflicts with its signed release commitment.",
         call. = FALSE)
  }
  .dsvert_joint_dp_vector_encode(list(
    version = "dsvert-joint-dp-vector-replay-v4",
    capsule_id = contract$release_contract$capsule_id,
    release_contract_hash = contract$release_contract_hash,
    result_set_hash = own$result_set_hash,
    final_vector_root = own$final_vector_root,
    chunk_hash = record$chunk_hash,
    chunk = record$public_chunk,
    merkle_proof = .dsvert_joint_dp_vector_merkle_proof(
      hashes, chunk$index),
    durable_replay = TRUE,
    source_store_read = FALSE, sampler_invoked = FALSE,
    history_gate = TRUE, request_limit = FALSE, operation_limit = TRUE))
}

.dsvert_joint_dp_vector_source_compaction_authorization <- function(
    contract, releases, secret) {
  if (!is.list(contract) || !is.list(contract$release_contract) ||
      !is.list(releases) || length(releases) != 2L ||
      is.null(names(releases)) || anyNA(names(releases)) ||
      anyDuplicated(names(releases))) {
    stop("Invalid joint-DP source compaction authorization input.",
         call. = FALSE)
  }
  ordered <- releases[order(names(releases), method = "radix")]
  reference <- ordered[[1L]]
  unsigned <- list(
    version = .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_AUTH_VERSION,
    capsule_id = contract$release_contract$capsule_id,
    source_contract_hash = contract$release_contract$source_contract_hash,
    release_instance_id = contract$release_contract$release_instance_id,
    release_contract_hash = contract$release_contract_hash,
    final_vector_root = reference$final_vector_root,
    result_set_hash = reference$result_set_hash,
    final_chunk_commitments_sha256 = .dsvert_joint_dp_hash(
      reference$final_chunk_hashes),
    release_receipts_sha256 = .dsvert_joint_dp_hash(lapply(
      ordered, .dsvert_dp_canonical_query_value)),
    durable_release_receipts_verified = TRUE,
    # The same SQLite commit that deletes source rows persists this
    # authenticated memo, so no committed deletion exists without it.
    public_release_memoized = TRUE,
    final_chunks_retained = TRUE)
  .dsvert_dp_capsule_source_compaction_authorization_seal(
    .dsvert_dp_canonical_query_value(unsigned), secret)
}

.dsvert_dp_capsule_source_compact_after_vector_release_internal <- function(
    policy, manifest_json, authorization, secret = NULL,
    .phase_hook = NULL) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  if (!is.null(.phase_hook) && !is.function(.phase_hook)) {
    stop("Invalid biomedical capsule source compaction phase hook.",
         call. = FALSE)
  }
  parsed <- .dsvert_dp_capsule_source_contract_json(policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  authorization <-
    .dsvert_dp_capsule_source_compaction_authorization_validate(
      authorization, contract, secret)
  capsule_id <- contract$capsule_id
  transfers <- vapply(
    .dsvert_dp_capsule_source_names(contract$source_peers,
                                   "source peer list"),
    function(peer) .dsvert_dp_capsule_source_transfer_id(contract, peer),
    character(1L))
  result <- .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      existing <- .dsvert_dp_capsule_source_compaction_load(
        connection, capsule_id, secret)
      if (!is.null(existing)) {
        if (!identical(
              existing$authorization_sha256,
              .dsvert_joint_dp_hash(authorization))) {
          stop("Conflicting biomedical capsule source compaction replay.",
               call. = FALSE)
        }
        return(list(
          receipt = existing,
          capacity_state = .dsvert_dp_capsule_source_store_state(
            connection, secret)))
      }
      .dsvert_dp_capsule_source_transaction(connection, {
      outbound_rows <- DBI::dbGetQuery(connection, paste(
        "SELECT transfer_id, record_json, row_mac FROM source_outbound",
        "WHERE capsule_id = ?"), params = list(capsule_id))
      outbound_reservation <- 0
      if (nrow(outbound_rows)) {
        outbound_reservation <- sum(vapply(
          seq_len(nrow(outbound_rows)), function(index) {
            record <- .dsvert_dp_capsule_source_record_decode(
              outbound_rows[index, , drop = FALSE], secret,
              "source_outbound", "compaction outbound record")
            if (!identical(record$status, "complete")) {
              stop(paste(
                "The capsule source cannot be compacted before every",
                "outbound chunk is durably complete."), call. = FALSE)
            }
            as.numeric(record$reserved_bytes)
          }, numeric(1L)))
      }
      incoming <- .dsvert_dp_capsule_source_incoming_load(
        connection, capsule_id, secret)
      if (!is.null(incoming) && !isTRUE(incoming$complete)) {
        stop(paste(
          "The capsule source cannot be compacted before aggregation is",
          "durably complete."), call. = FALSE)
      }
      incoming_reservation <- if (is.null(incoming)) 0 else
        as.numeric(incoming$reserved_bytes)
      recipient_rows <- DBI::dbGetQuery(connection, paste(
        "SELECT record_json, row_mac FROM source_recipient_keys",
        "WHERE capsule_id = ?"), params = list(capsule_id))
      recipient_reservation <- 0
      if (nrow(recipient_rows)) {
        recipient_record <- .dsvert_dp_capsule_source_record_decode(
          recipient_rows, secret, "source_recipient_keys",
          "compaction recipient-key record")
        if (!identical(recipient_record$contract_hash,
                       .dsvert_joint_dp_hash(contract))) {
          stop("The capsule source compaction key contract is inconsistent.",
               call. = FALSE)
        }
        recipient_reservation <-
          .dsvert_dp_capsule_source_recipient_reservation_validate(
            recipient_record)
      }
      state <- .dsvert_dp_capsule_source_store_state(connection, secret)
      active_reservation <- outbound_reservation + incoming_reservation +
        recipient_reservation
      retained_receipt <- as.numeric(
        .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES)
      local_peer <- .dsvert_dp_capsule_source_scalar(
        policy$peer_name, "local peer", "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        128L)
      source_peers <- .dsvert_dp_capsule_source_names(
        contract$source_peers, "source peer list")
      designated_peers <- .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")
      roleless <- !local_peer %in% c(source_peers, designated_peers)
      if (isTRUE(roleless)) {
        # A full-pinset ACK-only peer owns no source rows, but still needs a
        # durable tombstone so delayed requests cannot reopen this capsule.
        capsule_tables <- c(
          "source_aggregate_chunks", "source_cross_gaussian_results",
          "source_cross_categorical_results")
        capsule_rows <- vapply(capsule_tables, function(table) {
          DBI::dbGetQuery(connection, paste(
            "SELECT COUNT(*) AS n FROM", table, "WHERE capsule_id = ?"),
            params = list(capsule_id))$n[[1L]]
        }, numeric(1L))
        transfer_rows <- 0
        if (length(transfers)) {
          placeholders <- paste(rep("?", length(transfers)), collapse = ",")
          transfer_rows <- sum(vapply(c(
            "source_outbound_chunks", "source_incoming_receipts"),
            function(table) {
              DBI::dbGetQuery(connection, paste0(
                "SELECT COUNT(*) AS n FROM ", table,
                " WHERE transfer_id IN (", placeholders, ")"),
                params = unname(as.list(transfers)))$n[[1L]]
            }, numeric(1L)))
        }
        if (!identical(active_reservation, 0) || nrow(outbound_rows) ||
            !is.null(incoming) ||
            nrow(recipient_rows) || any(capsule_rows != 0) ||
            transfer_rows != 0) {
          stop("The capsule source compaction role state is inconsistent.",
               call. = FALSE)
        }
        state <- .dsvert_dp_capsule_source_reserve(
          connection, secret, retained_receipt,
          .dsvert_dp_capsule_source_resource_owner(policy))
        active_reservation <- retained_receipt
      }
      released <- active_reservation - retained_receipt
      if (!is.finite(active_reservation) ||
          active_reservation < retained_receipt || released < 0 ||
          active_reservation > as.numeric(state$reserved_bytes)) {
        stop("The capsule source compaction reservation is inconsistent.",
             call. = FALSE)
      }
      receipt <- list(
        version = .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_VERSION,
        capsule_id = capsule_id,
        source_contract_hash = authorization$source_contract_hash,
        release_instance_id = authorization$release_instance_id,
        release_contract_hash = authorization$release_contract_hash,
        final_vector_root = authorization$final_vector_root,
        result_set_hash = authorization$result_set_hash,
        final_chunk_commitments_sha256 =
          authorization$final_chunk_commitments_sha256,
        release_receipts_sha256 = authorization$release_receipts_sha256,
        authorization_sha256 = .dsvert_joint_dp_hash(authorization),
        state = "compacted_after_durable_publication",
        compacted = TRUE, source_intermediates_compacted = TRUE,
        final_chunks_retained_elsewhere = TRUE,
        durable_replay_retained_elsewhere = TRUE,
        active_reservation_bytes = active_reservation,
        released_bytes = released,
        retained_receipt_bytes = retained_receipt)
      .dsvert_dp_capsule_source_record_insert(
        connection, "source_compaction_receipts",
        c("capsule_id", "release_instance_id"),
        list(capsule_id, authorization$release_instance_id),
        receipt, secret)
      if (length(transfers)) {
        placeholders <- paste(rep("?", length(transfers)), collapse = ",")
        DBI::dbExecute(connection, paste0(
          "DELETE FROM source_incoming_receipts WHERE transfer_id IN (",
          placeholders, ")"), params = unname(as.list(transfers)))
        DBI::dbExecute(connection, paste0(
          "DELETE FROM source_outbound_chunks WHERE transfer_id IN (",
          placeholders, ")"), params = unname(as.list(transfers)))
      }
      DBI::dbExecute(connection,
        "DELETE FROM source_aggregate_chunks WHERE capsule_id = ?",
        params = list(capsule_id))
      DBI::dbExecute(connection,
        "DELETE FROM source_incoming_state WHERE capsule_id = ?",
        params = list(capsule_id))
      DBI::dbExecute(connection,
        "DELETE FROM source_outbound WHERE capsule_id = ?",
        params = list(capsule_id))
      DBI::dbExecute(connection,
        "DELETE FROM source_recipient_keys WHERE capsule_id = ?",
        params = list(capsule_id))
      DBI::dbExecute(connection,
        "DELETE FROM source_cross_gaussian_results WHERE capsule_id = ?",
        params = list(capsule_id))
      DBI::dbExecute(connection,
        "DELETE FROM source_cross_categorical_results WHERE capsule_id = ?",
        params = list(capsule_id))
      if (released > 0) {
        state$reserved_bytes <- as.numeric(state$reserved_bytes) - released
        .dsvert_dp_capsule_source_record_update(
          connection, "source_store_state", state, secret,
          "singleton = 1", list())
      }
      if (is.function(.phase_hook)) {
        .phase_hook("before_source_compaction_commit")
      }
      list(receipt = receipt, capacity_state = state)
      })
      if (is.function(.phase_hook)) {
        .phase_hook("after_source_compaction_commit")
      }
      .dsvert_dp_capsule_source_compact_pages(connection)
      # Return the authenticated canonical row on both the committing and the
      # replay path. JSON round-tripping normalises integer/logical scalar
      # representation, so returning the pre-serialization list here would
      # make two concurrent byte-identical commits appear different in R.
      canonical <- .dsvert_dp_capsule_source_compaction_load(
        connection, capsule_id, secret)
      if (is.null(canonical)) {
        stop("The committed source compaction receipt is unavailable.",
             call. = FALSE)
      }
      list(
        receipt = canonical,
        capacity_state = .dsvert_dp_capsule_source_store_state(
          connection, secret))
    })
  .dsvert_dp_capsule_source_resource_reconcile(
    policy, result$capacity_state)
  result$receipt
}

.dsvert_joint_dp_vector_ack_impl <- function(
    manifest_json, first_release_json, second_release_json,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL,
    .planner = NULL, .source_compactor = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  release_instance_json <- .dsvert_joint_dp_vector_instance_from_receipts(
    first_release_json, second_release_json)
  ack_instance <- .dsvert_joint_dp_vector_decode_json(
    release_instance_json, "acknowledgement release instance")
  if (is.list(ack_instance$peer_noise_roots) &&
      .policy$peer_name %in% names(ack_instance$peer_noise_roots)) {
    .dsvert_joint_dp_vector_instance_claim_preflight(
      .policy, .secret, release_instance_json)
  }
  contract <- .dsvert_joint_dp_vector_contract(
    .policy, manifest_json, release_instance_json,
    .planner, secret = .secret)
  releases <- .dsvert_joint_dp_vector_release_set(
    first_release_json, second_release_json, .policy, contract, .verifier)
  root <- releases[[1L]]$final_vector_root
  capsule_id <- contract$release_contract$capsule_id
  release_instance_id <- contract$release_contract$release_instance_id
  current <- .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_capsule_load(
        connection, release_instance_id, .secret)
    })
  if (!is.null(current$ack_receipt_json)) return(current$ack_receipt_json)
  if (is.null(.source_compactor)) {
    .source_compactor <-
      .dsvert_dp_capsule_source_compact_after_vector_release_internal
  }
  if (!is.function(.source_compactor)) {
    stop("Invalid biomedical capsule source compactor.", call. = FALSE)
  }
  source_authorization <-
    .dsvert_joint_dp_vector_source_compaction_authorization(
      contract, releases, .secret)
  .source_compactor(
    .policy, manifest_json, source_authorization, .secret)

  unsigned <- c(.dsvert_joint_dp_vector_common_unsigned(
    contract, .policy, .DSVERT_JOINT_DP_VECTOR_ACK_VERSION,
    "vector_finalized_and_compacted"), list(
      final_vector_root = root,
      source_intermediates_compacted = TRUE,
      sampler_intermediates_compacted = TRUE,
      final_chunks_retained = TRUE,
      durable_replay_retained = TRUE, idempotent = TRUE))
  ack <- .dsvert_joint_dp_vector_sign(
    unsigned, .policy, .signer, require_designated = FALSE)
  ack_json <- .dsvert_joint_dp_vector_encode(ack)
  .dsvert_joint_dp_vector_with_store(
    .policy, .secret, function(connection) {
      .dsvert_joint_dp_vector_transaction(connection, {
        if (.policy$peer_name %in% contract$designated) {
          .dsvert_joint_dp_vector_instance_claim_require_connection(
            connection, .secret, capsule_id, release_instance_id,
            contract$release_contract_hash)
        }
        record <- .dsvert_joint_dp_vector_capsule_load(
          connection, release_instance_id, .secret)
        if (!is.null(record$ack_receipt_json)) {
          if (!identical(record$ack_receipt_json, ack_json)) {
            stop("Conflicting vector compaction acknowledgement.",
                 call. = FALSE)
          }
          return(record$ack_receipt_json)
        }
        if (is.null(record)) {
          record <- list(
            version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
            capsule_id = capsule_id,
            release_instance_id = release_instance_id,
            state = "acked", compacted = TRUE,
            manifest_sha256 = contract$release_contract$manifest_sha256,
            release_contract_hash = contract$release_contract_hash,
            transcript_hash = contract$transcript_hash,
            release_contract = contract$release_contract,
            plan = contract$plan, designated = as.list(contract$designated),
            prepare_receipt_json = NULL, local_result_json = NULL,
            release_receipt_json = NULL, ack_receipt_json = ack_json)
          .dsvert_joint_dp_vector_capsule_put(
            connection, record, .secret, NULL)
        } else {
          if (.policy$peer_name %in% contract$designated &&
              is.null(record$release_receipt_json)) {
            stop("A designated peer cannot compact before its durable release.",
                 call. = FALSE)
          }
          DBI::dbExecute(connection,
            paste("DELETE FROM vector_noised_chunks",
                  "WHERE release_instance_id = ?"),
            params = list(release_instance_id))
          record$state <- "acked"
          record$compacted <- TRUE
          record$ack_receipt_json <- ack_json
          .dsvert_joint_dp_vector_capsule_put(
            connection, record, .secret, existing = record)
        }
        ack_json
      })
    })
}

.dsvert_joint_dp_vector_public <- function(phase, code) {
  tryCatch(force(code), error = function(e) {
    # Preserve only explicitly public recovery/resource/peer conditions.  All
    # protected pre-release failures share one relay-visible representation.
    .dsvert_dp_transcript_stop(e)
  })
}

#' Prepare one sticky, global vector release (AGGREGATE)
#'
#' PREPARE persists an authenticated candidate without claiming the capsule, so
#' sibling candidates may coexist until the first valid START at that peer.
#'
#' @param manifest_json Canonical server-authorized capsule manifest.
#' @param release_instance_json Canonical signed-handshake map from each
#'   designated peer to its current privacy epoch and noise-key identifier.
#' @param first_allocation_opening_json,second_allocation_opening_json The two
#'   pinned peers' signed, capability-free allocation opening proofs.
#' @return Canonical signed prepare receipt; no source value or seed.
#' @export
dsvertJointDPVectorPrepareDS <- function(
    manifest_json, release_instance_json,
    first_allocation_opening_json, second_allocation_opening_json) {
  .dsvert_joint_dp_vector_public("prepare", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    release_instance_json <- .dsvert_dsi_text_decode(
      release_instance_json, "biomedical release-instance contract",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    first_allocation_opening_json <- .dsvert_dsi_text_decode(
      first_allocation_opening_json,
      "first biomedical allocation opening",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    second_allocation_opening_json <- .dsvert_dsi_text_decode(
      second_allocation_opening_json,
      "second biomedical allocation opening",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_prepare_impl(
      manifest_json, release_instance_json,
      first_allocation_opening_json, second_allocation_opening_json)
  })
}

#' Add sticky DP noise to one private capsule chunk (AGGREGATE)
#'
#' At each designated peer, the first valid START atomically and irrevocably
#' claims one release instance before reading its local staged source or
#' sampling. Source transport may already have staged encrypted protected
#' material, but no noised share or public output exists at the claim boundary.
#' The claim is local to that peer; matching bilateral receipts remain required,
#' so split sibling claims cannot produce a release while at least one
#' designated peer is non-colluding and retains its authenticated history.
#' Same-instance retry is idempotent; a sibling instance fails closed.
#'
#' @param manifest_json Canonical server-authorized capsule manifest.
#' @param first_prepare_json,second_prepare_json Signed peer prepare receipts.
#' @param chunk_index Zero-based public chunk index.
#' @param session_id Active pinned-peer exact-GC session for one-draw Laplace
#'   releases. Ignored by the Gaussian route.
#' @return Signed commitment receipt; the noised share stays private.
#' @export
dsvertJointDPVectorStartDS <- function(
    manifest_json, first_prepare_json, second_prepare_json, chunk_index,
    session_id = NULL) {
  .dsvert_joint_dp_vector_public("start", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    first_prepare_json <- .dsvert_dsi_text_decode(
      first_prepare_json, "first biomedical vector prepare receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    second_prepare_json <- .dsvert_dsi_text_decode(
      second_prepare_json, "second biomedical vector prepare receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_start_impl(
      manifest_json, first_prepare_json, second_prepare_json, chunk_index,
      session_id = session_id)
  })
}

#' Commit the complete private noised-vector share (AGGREGATE)
#' @inheritParams dsvertJointDPVectorStartDS
#' @return Signed root of all durable local noised chunks.
#' @export
dsvertJointDPVectorResultDS <- function(
    manifest_json, first_prepare_json, second_prepare_json,
    session_id = NULL) {
  .dsvert_joint_dp_vector_public("result", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    first_prepare_json <- .dsvert_dsi_text_decode(
      first_prepare_json, "first biomedical vector prepare receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    second_prepare_json <- .dsvert_dsi_text_decode(
      second_prepare_json, "second biomedical vector prepare receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_result_impl(
      manifest_json, first_prepare_json, second_prepare_json,
      session_id = session_id)
  })
}

#' Encrypt one noised vector share for its pinned peer (AGGREGATE)
#' @param session_id Active pinned-peer MPC session.
#' @param manifest_json Canonical server-authorized capsule manifest.
#' @param first_result_json,second_result_json Signed peer result receipts.
#' @param chunk_index Zero-based public chunk index.
#' @return Opaque ciphertext and a purpose-bound typed transfer ticket.
#' @export
dsvertJointDPVectorFinalShareDS <- function(
    session_id, manifest_json, first_result_json, second_result_json,
    chunk_index) {
  .dsvert_joint_dp_vector_public("final share", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    first_result_json <- .dsvert_dsi_text_decode(
      first_result_json, "first biomedical vector result receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    second_result_json <- .dsvert_dsi_text_decode(
      second_result_json, "second biomedical vector result receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_final_share_impl(
      session_id, manifest_json, first_result_json, second_result_json,
      chunk_index)
  })
}

#' Finalize and durably commit the public DP vector root (AGGREGATE)
#' @inheritParams dsvertJointDPVectorFinalShareDS
#' @return Canonical signed release-root receipt, never an intermediate share.
#' @export
dsvertJointDPVectorReleaseDS <- function(
    session_id, manifest_json, first_result_json, second_result_json) {
  .dsvert_joint_dp_vector_public("release", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    first_result_json <- .dsvert_dsi_text_decode(
      first_result_json, "first biomedical vector result receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    second_result_json <- .dsvert_dsi_text_decode(
      second_result_json, "second biomedical vector result receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_release_impl(
      session_id, manifest_json, first_result_json, second_result_json)
  })
}

#' Replay one final DP vector chunk with its Merkle proof (AGGREGATE)
#' @param manifest_json Canonical server-authorized capsule manifest.
#' @param first_release_json,second_release_json Signed peer release receipts.
#' @param chunk_index Zero-based public chunk index.
#' @return Canonical final DP chunk and Merkle proof only.
#' @export
dsvertJointDPVectorReplayDS <- function(
    manifest_json, first_release_json, second_release_json, chunk_index) {
  .dsvert_joint_dp_vector_public("replay", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    first_release_json <- .dsvert_dsi_text_decode(
      first_release_json, "first biomedical vector release receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    second_release_json <- .dsvert_dsi_text_decode(
      second_release_json, "second biomedical vector release receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_replay_impl(
      manifest_json, first_release_json, second_release_json, chunk_index)
  })
}

#' Compact source and sampler intermediates after bilateral release (AGGREGATE)
#' @inheritParams dsvertJointDPVectorReplayDS
#' @return Canonical signed idempotent compaction acknowledgement.
#' @export
dsvertJointDPVectorFinalizeAckDS <- function(
    manifest_json, first_release_json, second_release_json) {
  .dsvert_joint_dp_vector_public("finalization acknowledgement", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    first_release_json <- .dsvert_dsi_text_decode(
      first_release_json, "first biomedical vector release receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    second_release_json <- .dsvert_dsi_text_decode(
      second_release_json, "second biomedical vector release receipt",
      .DSVERT_JOINT_DP_VECTOR_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_ack_impl(
      manifest_json, first_release_json, second_release_json)
  })
}
