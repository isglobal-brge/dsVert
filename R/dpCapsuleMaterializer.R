# Internal local sufficient-statistic materializer for biomedical capsules.
#
# This file intentionally defines no DataSHIELD entry point.  Its result
# contains protected exact statistics and must move directly into a future
# secret-sharing boundary; it must never be printed, serialized to the relay,
# or returned by an aggregate method.

.DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION <-
  "dsvert-biomedical-capsule-local-material-v1"
.DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE <-
  "biomedical_capsule_secret_share_input_only"
.DSVERT_DP_CAPSULE_VALUE_BLOCK <- 65536L

.dsvert_dp_capsule_coordinate_range_abort <- function(index, upper_bound) {
  stop(structure(list(
    message = paste0(
      "A local biomedical capsule coordinate is outside its signed ",
      "manifest bound; secret sharing was not started."),
    call = NULL,
    code = "coordinate_out_of_signed_range",
    coordinate_index = as.integer(index),
    signed_upper_bound = as.character(upper_bound),
    phase = "before_secret_sharing"),
    class = c("dsvert_dp_capsule_coordinate_range_error", "error",
              "condition")))
}

.dsvert_dp_capsule_assert_signed_coordinate_bounds <- function(
    values, validated) {
  values <- .dsvert_dp_integer_vector(
    values, "local biomedical capsule coordinates")
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(validated)
  upper_text <- lattice$raw_upper_bounds
  upper <- suppressWarnings(as.numeric(upper_text))
  if (length(values) != length(upper_text) ||
      length(upper) != length(upper_text) || anyNA(upper) ||
      any(!is.finite(upper)) || any(upper < 0) ||
      any(upper != floor(upper))) {
    stop("The signed biomedical capsule coordinate bounds are invalid.",
         call. = FALSE)
  }
  invalid <- which(values < 0 | values > upper)
  if (length(invalid)) {
    index <- invalid[[1L]]
    .dsvert_dp_capsule_coordinate_range_abort(index, upper_text[[index]])
  }
  invisible(values)
}

.dsvert_dp_capsule_local_key <- function(dataset, column) {
  paste0(
    nchar(dataset, type = "bytes"), ":", dataset, "|",
    nchar(column, type = "bytes"), ":", column)
}

.dsvert_dp_capsule_sorted_names <- function(value) {
  if (!length(value)) character() else
    sort(names(value), method = "radix")
}

.dsvert_dp_capsule_coordinate_layout <- function(manifest) {
  families <- manifest$workload$families
  required <- c(
    "admitted_count", "numeric_moments", "numeric_pair_moments",
    "gaussian_models",
    "fixed_numeric_histograms", "categorical_marginals",
    "categorical_pairs", "correlation_artifacts", "describe_artifacts",
    "survival_artifacts")
  if (!is.list(families) || !all(required %in% names(families))) {
    stop("The biomedical capsule coordinate contract is invalid.",
         call. = FALSE)
  }

  cursor <- 1L
  blocks <- list()
  add <- function(family, key, length, owner_peer, dataset, descriptor) {
    if (!is.numeric(length) || length(length) != 1L || is.na(length) ||
        !is.finite(length) || length < 1 || length != floor(length) ||
        length > .DSVERT_DP_MAX_COORDINATES ||
        cursor > .DSVERT_DP_MAX_COORDINATES - length + 1L) {
      stop("The biomedical capsule coordinate layout is invalid.",
           call. = FALSE)
    }
    start <- cursor
    end <- cursor + as.integer(length) - 1L
    block_id <- paste(family, key, sep = "::")
    if (block_id %in% names(blocks)) {
      stop("The biomedical capsule coordinate layout is ambiguous.",
           call. = FALSE)
    }
    blocks[[block_id]] <<- list(
      family = family, key = key, start = start, end = end,
      length = as.integer(length), owner_peer = owner_peer,
      dataset = dataset, descriptor = descriptor)
    cursor <<- end + 1L
  }

  count <- families$admitted_count
  add("admitted_count", "canonical", 1L, count$owner_peer,
      count$dataset, count)

  numeric <- families$numeric_moments$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(numeric)) {
    artifact <- numeric[[key]]
    add("numeric_moments", key, 3L, artifact$owner_peer,
        artifact$dataset, artifact)
  }

  numeric_pairs <- families$numeric_pair_moments$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(numeric_pairs)) {
    artifact <- numeric_pairs[[key]]
    add("numeric_pair_moments", key, 6L, artifact$owner_peer,
        artifact$dataset, artifact)
  }

  gaussian <- families$gaussian_models$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(gaussian)) {
    artifact <- gaussian[[key]]
    add("gaussian_models", key, artifact$coordinate_count,
        artifact$owner_peer, artifact$dataset, artifact)
  }

  histograms <- families$fixed_numeric_histograms$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(histograms)) {
    artifact <- histograms[[key]]
    add("fixed_numeric_histograms", key,
        artifact$coordinate_count, artifact$owner_peer,
        artifact$dataset, artifact)
  }

  marginals <- families$categorical_marginals$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(marginals)) {
    artifact <- marginals[[key]]
    add("categorical_marginals", key, length(artifact$levels),
        artifact$owner_peer, artifact$dataset, artifact)
  }

  pair_sets <- families$categorical_pairs$sets
  for (set_key in .dsvert_dp_capsule_sorted_names(pair_sets)) {
    set <- pair_sets[[set_key]]
    columns <- set$columns
    names(columns) <- vapply(columns, `[[`, character(1L), "column")
    for (pair in set$included_pairs) {
      pair <- unname(unlist(pair, use.names = FALSE))
      left_column <- columns[[pair[[1L]]]]
      right_column <- columns[[pair[[2L]]]]
      if (is.null(left_column) || is.null(right_column)) {
        stop("The biomedical categorical-pair scope is invalid.",
             call. = FALSE)
      }
      key <- paste(left_column$column, right_column$column, sep = "::")
      descriptor <- list(
        left = left_column, right = right_column,
        repeated_record_policy = set$repeated_record_policy,
        missingness_policy = set$missingness_policy)
      add(
        "categorical_pairs", paste(set_key, key, sep = "::"),
        as.double(length(left_column$levels)) *
          as.double(length(right_column$levels)),
        set$owner_peer, set$dataset, descriptor)
    }
  }

  cross_pairs <- families$categorical_pairs$cross_artifacts %||% list()
  for (analysis_id in .dsvert_dp_capsule_sorted_names(cross_pairs)) {
    artifact <- cross_pairs[[analysis_id]]
    add(
      "categorical_pairs", paste("cross", analysis_id, sep = "::"),
      artifact$coordinate_count, artifact$left$owner_peer,
      artifact$left$dataset, artifact)
  }

  survival <- families$survival_artifacts
  for (key in .dsvert_dp_capsule_sorted_names(survival)) {
    artifact <- survival[[key]]
    add("survival_artifacts", key, artifact$coordinate_count,
        artifact$owner_peer, artifact$dataset, artifact)
  }

  coordinate_count <- cursor - 1L
  expected <- manifest$workload$coordinate_count
  if (!is.numeric(expected) || length(expected) != 1L || is.na(expected) ||
      !is.finite(expected) || expected != floor(expected) ||
      !identical(as.numeric(coordinate_count), as.numeric(expected))) {
    stop("The biomedical capsule coordinate layout does not match its manifest.",
         call. = FALSE)
  }
  list(
    version = "dsvert-biomedical-capsule-coordinate-layout-v4",
    coordinate_count = as.integer(coordinate_count), blocks = blocks,
    sha256 = .dsvert_joint_dp_hash(list(
      version = "dsvert-biomedical-capsule-coordinate-layout-v4",
      coordinate_count = as.integer(coordinate_count),
      admitted_count = count,
      numeric_moments = families$numeric_moments,
      numeric_pair_moments = families$numeric_pair_moments,
      gaussian_models = families$gaussian_models,
      fixed_numeric_histograms = families$fixed_numeric_histograms,
      categorical_marginals = families$categorical_marginals,
      categorical_pairs = families$categorical_pairs,
      correlation_artifacts = families$correlation_artifacts,
      survival_artifacts = families$survival_artifacts)))
}

.dsvert_dp_capsule_quantized_pair_moments <- function(
    left, right, grid_bits) {
  if (!is.numeric(left) || !is.numeric(right) ||
      length(left) != length(right) || anyNA(left) || anyNA(right) ||
      any(!is.finite(left)) || any(!is.finite(right)) ||
      any(left < 0 | left > 1) || any(right < 0 | right > 1) ||
      !is.numeric(grid_bits) || length(grid_bits) != 1L ||
      is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("Invalid normalized pairwise capsule values.", call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(left) > floor(.dsvert_dp_exact_integer_limit / scale)) {
    stop("The pairwise capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  statistics <- c(
    count = length(left),
    sum_left = sum(round(left * scale)),
    sum_right = sum(round(right * scale)),
    sumsq_left = sum(round(left^2 * scale)),
    sumsq_right = sum(round(right^2 * scale)),
    cross = sum(round(left * right * scale)))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The quantized pairwise capsule moments are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_gaussian_stats <- function(
    design, outcome, grid_bits) {
  if (!is.list(design) || !length(design) ||
      !is.numeric(outcome) || anyNA(outcome) ||
      any(!is.finite(outcome)) || any(outcome < 0 | outcome > 1) ||
      !is.numeric(grid_bits) || length(grid_bits) != 1L ||
      is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("Invalid normalized Gaussian capsule values.", call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  if (!all(valid_design)) {
    stop("Invalid normalized Gaussian capsule design.", call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(
        .dsvert_dp_exact_integer_limit / scale)) {
    stop("The Gaussian capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  design_count <- length(design)
  gram_count <- design_count * (design_count + 1) / 2
  statistics <- numeric(gram_count + design_count + 2)
  statistics[[1L]] <- length(outcome)
  offset <- 1
  for (right in seq_along(design)) {
    for (left in seq_len(right)) {
      offset <- offset + 1
      statistics[[offset]] <- sum(round(
        design[[left]] * design[[right]] * scale))
    }
  }
  cross <- vapply(design, function(column) {
    sum(round(column * outcome * scale))
  }, numeric(1L))
  statistics[(offset + 1):(offset + design_count)] <- cross
  statistics[[length(statistics)]] <- sum(round(outcome^2 * scale))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The quantized Gaussian capsule statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_random_intercept_stats <- function(
    outcome, cluster, grid_bits, max_patients_per_cluster) {
  if (!is.numeric(outcome) || !is.numeric(cluster) ||
      length(outcome) != length(cluster) || anyNA(outcome) ||
      any(!is.finite(outcome)) || any(outcome < 0 | outcome > 1) ||
      anyNA(cluster) || any(!is.finite(cluster)) || any(cluster < 1) ||
      any(cluster != floor(cluster)) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L ||
      !is.numeric(max_patients_per_cluster) ||
      length(max_patients_per_cluster) != 1L ||
      is.na(max_patients_per_cluster) ||
      !is.finite(max_patients_per_cluster) ||
      max_patients_per_cluster != floor(max_patients_per_cluster) ||
      max_patients_per_cluster < 2) {
    stop("Invalid normalized random-intercept capsule values.",
         call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(.dsvert_dp_exact_integer_limit / scale)) {
    stop("The random-intercept capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  if (!length(outcome)) return(rep.int(0, 6L))
  sizes <- tabulate(cluster, nbins = max(cluster, 0L))
  sizes <- sizes[sizes > 0L]
  if (any(sizes > max_patients_per_cluster)) {
    stop("The protected snapshot exceeds its signed LMM cluster capacity.",
         call. = FALSE)
  }
  quantized <- round(outcome * scale)
  quantized_sq <- round(outcome^2 * scale)
  cluster_sum <- rowsum(quantized, cluster, reorder = FALSE)[, 1L]
  cluster_size <- as.numeric(rowsum(
    rep.int(1, length(cluster)), cluster, reorder = FALSE)[, 1L])
  cluster_mean_sq <- sum(round(
    cluster_sum^2 / (cluster_size * scale)))
  statistics <- c(
    n = length(outcome), clusters = length(sizes),
    cluster_size_sq = sum(sizes^2), sum_y = sum(quantized),
    sum_y_sq = sum(quantized_sq),
    sum_cluster_mean_sq = cluster_mean_sq)
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The random-intercept capsule statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_random_intercept_fixed_stats <- function(
    design, outcome, cluster, grid_bits, max_patients_per_cluster) {
  if (!is.list(design) || !length(design) ||
      !is.numeric(outcome) || length(outcome) != length(cluster) ||
      anyNA(outcome) || any(!is.finite(outcome)) ||
      any(outcome < 0 | outcome > 1) || !is.numeric(cluster) ||
      anyNA(cluster) || any(!is.finite(cluster)) || any(cluster < 1) ||
      any(cluster != floor(cluster)) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L ||
      !is.numeric(max_patients_per_cluster) ||
      length(max_patients_per_cluster) != 1L ||
      is.na(max_patients_per_cluster) ||
      !is.finite(max_patients_per_cluster) ||
      max_patients_per_cluster != floor(max_patients_per_cluster) ||
      max_patients_per_cluster < 2L) {
    stop("Invalid fixed-effect random-intercept capsule values.",
         call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  if (!all(valid_design)) {
    stop("Invalid fixed-effect random-intercept capsule design.",
         call. = FALSE)
  }
  dimension <- length(design)
  gram_count <- dimension * (dimension + 1L) / 2L
  summary_count <- gram_count + dimension + 1L
  expected_length <- (max_patients_per_cluster + 1L) * (summary_count + 1L)
  if (!length(outcome)) return(rep.int(0, expected_length))
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(
        .dsvert_dp_exact_integer_limit /
          (max_patients_per_cluster * scale))) {
    stop("The fixed-effect random-intercept capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  design_matrix <- do.call(cbind, design)
  cluster_sizes <- rowsum(
    rep.int(1, length(cluster)), cluster, reorder = FALSE)[, 1L]
  if (any(cluster_sizes > max_patients_per_cluster)) {
    stop("The protected snapshot exceeds its signed LMM cluster capacity.",
         call. = FALSE)
  }
  summary <- function(matrix, response) {
    result <- numeric(summary_count)
    offset <- 0L
    for (right in seq_len(dimension)) {
      for (left in seq_len(right)) {
        offset <- offset + 1L
        result[[offset]] <- sum(round(
          matrix[, left] * matrix[, right] * scale))
      }
    }
    result[seq.int(offset + 1L, offset + dimension)] <-
      vapply(seq_len(dimension), function(index) {
        sum(round(matrix[, index] * response * scale))
      }, numeric(1L))
    result[[summary_count]] <- sum(round(response^2 * scale))
    result
  }
  cluster_matrix <- rowsum(design_matrix, cluster, reorder = FALSE)
  cluster_outcome <- rowsum(outcome, cluster, reorder = FALSE)[, 1L]
  sizes <- as.integer(rowsum(
    rep.int(1, length(cluster)), cluster, reorder = FALSE)[, 1L])
  if (length(sizes) != nrow(cluster_matrix) ||
      length(sizes) != length(cluster_outcome)) {
    stop("The fixed-effect random-intercept cluster aggregation is invalid.",
         call. = FALSE)
  }
  statistics <- c(length(outcome), summary(design_matrix, outcome))
  for (size in seq_len(max_patients_per_cluster)) {
    selected <- which(sizes == size)
    if (!length(selected)) {
      statistics <- c(statistics, 0, rep.int(0, summary_count))
    } else {
      statistics <- c(
        statistics, length(selected),
        summary(cluster_matrix[selected, , drop = FALSE],
                cluster_outcome[selected]))
    }
  }
  if (length(statistics) != expected_length || anyNA(statistics) ||
      any(!is.finite(statistics)) || any(statistics < 0) ||
      any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The fixed-effect random-intercept capsule statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_binary_random_intercept_grid_losses <- function(
    design, outcome, cluster, beta_grid, variance_grid, grid_bits,
    max_patients_per_cluster) {
  if (!is.list(design) || !length(design) || !is.numeric(outcome) ||
      length(outcome) != length(cluster) || anyNA(outcome) ||
      any(!is.finite(outcome)) || any(!outcome %in% c(0, 1)) ||
      !is.numeric(cluster) || anyNA(cluster) || any(!is.finite(cluster)) ||
      any(cluster < 1) || any(cluster != floor(cluster)) ||
      !is.list(beta_grid) || !length(beta_grid) ||
      !is.numeric(variance_grid) || !length(variance_grid) ||
      anyNA(variance_grid) || any(!is.finite(variance_grid)) ||
      any(variance_grid < 0) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L ||
      !is.numeric(max_patients_per_cluster) ||
      length(max_patients_per_cluster) != 1L ||
      is.na(max_patients_per_cluster) || !is.finite(max_patients_per_cluster) ||
      max_patients_per_cluster != floor(max_patients_per_cluster) ||
      max_patients_per_cluster < 2L) {
    stop("Invalid binary random-intercept likelihood-grid values.",
         call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  if (!all(valid_design) || !all(vapply(beta_grid, function(beta) {
    is.numeric(beta) && length(beta) == length(design) &&
      !anyNA(beta) && all(is.finite(beta))
  }, logical(1L)))) {
    stop("Invalid binary random-intercept likelihood-grid design.",
         call. = FALSE)
  }
  candidate_count <- length(beta_grid) * length(variance_grid)
  if (!length(outcome)) return(rep.int(0, candidate_count))
  cluster_members <- split(seq_along(cluster), as.character(cluster))
  sizes <- lengths(cluster_members)
  if (any(sizes > max_patients_per_cluster)) {
    stop("The protected snapshot exceeds its signed GLMM cluster capacity.",
         call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(
        .dsvert_dp_exact_integer_limit /
          (max_patients_per_cluster * scale))) {
    stop("The GLMM capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  quadrature <- .dsvert_dp_capsule_binary_glmm_quadrature_v1()
  log_weights <- log(quadrature$weights) - 0.5 * log(pi)
  softplus <- function(value) pmax(value, 0) + log1p(exp(-abs(value)))
  design_matrix <- do.call(cbind, design)
  candidates <- unlist(lapply(variance_grid, function(variance) {
    lapply(beta_grid, function(beta) {
      list(beta = beta, variance = variance)
    })
  }), recursive = FALSE)
  statistics <- vapply(candidates, function(candidate) {
    shift <- sqrt(2 * candidate$variance) * quadrature$nodes
    sum(vapply(cluster_members, function(index) {
      eta <- as.numeric(design_matrix[index, , drop = FALSE] %*%
        candidate$beta)
      log_likelihood <- vapply(shift, function(random_intercept) {
        eta_with_intercept <- eta + random_intercept
        sum(outcome[index] * eta_with_intercept -
          softplus(eta_with_intercept))
      }, numeric(1L))
      maximum <- max(log_weights + log_likelihood)
      loss <- -(maximum + log(sum(exp(
        log_weights + log_likelihood - maximum))))
      as.numeric(round(max(0, loss) * scale))
    }, numeric(1L)))
  }, numeric(1L))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The binary random-intercept likelihood-grid statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_gaussian_random_slope_grid_losses <- function(
    design, outcome, cluster, candidate_grid, random_effect_order, grid_bits,
    max_patients_per_cluster, candidate_loss_bounds) {
  if (!is.list(design) || !length(design) || !is.numeric(outcome) ||
      length(outcome) != length(cluster) || anyNA(outcome) ||
      any(!is.finite(outcome)) || any(outcome < 0 | outcome > 1) ||
      !is.numeric(cluster) || anyNA(cluster) || any(!is.finite(cluster)) ||
      any(cluster < 1) || any(cluster != floor(cluster)) ||
      !is.list(candidate_grid) || !length(candidate_grid) ||
      !is.character(random_effect_order) || length(random_effect_order) < 2L ||
      !identical(random_effect_order[[1L]], "(Intercept)") ||
      !is.numeric(candidate_loss_bounds) ||
      length(candidate_loss_bounds) != length(candidate_grid) ||
      anyNA(candidate_loss_bounds) || any(!is.finite(candidate_loss_bounds)) ||
      any(candidate_loss_bounds <= 0) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L ||
      !is.numeric(max_patients_per_cluster) ||
      length(max_patients_per_cluster) != 1L || is.na(max_patients_per_cluster) ||
      !is.finite(max_patients_per_cluster) ||
      max_patients_per_cluster != floor(max_patients_per_cluster) ||
      max_patients_per_cluster < 2L) {
    stop("Invalid Gaussian random-slope likelihood-grid values.", call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) && !anyNA(column) &&
      all(is.finite(column)) && all(column >= 0 & column <= 1)
  }, logical(1L))
  if (!all(valid_design) || is.null(names(design)) ||
      !all(random_effect_order[-1L] %in% names(design))) {
    stop("Invalid Gaussian random-slope likelihood-grid design.", call. = FALSE)
  }
  effect_count <- length(random_effect_order)
  candidates <- lapply(candidate_grid, function(candidate) {
    if (!is.list(candidate) || !setequal(names(candidate),
                                         c("beta", "sigma2", "covariance"))) {
      return(NULL)
    }
    beta <- candidate$beta
    covariance <- candidate$covariance
    if (is.list(beta) && is.null(names(beta))) beta <- unlist(beta, use.names = FALSE)
    if (is.list(covariance) && is.null(names(covariance))) covariance <- unlist(covariance, use.names = FALSE)
    sigma2 <- suppressWarnings(as.numeric(candidate$sigma2))
    if (!is.numeric(beta) || length(beta) != length(design) || anyNA(beta) ||
        any(!is.finite(beta)) || !is.numeric(covariance) ||
        length(covariance) != effect_count^2 || anyNA(covariance) ||
        any(!is.finite(covariance)) || length(sigma2) != 1L ||
        !is.finite(sigma2) || sigma2 <= 0) return(NULL)
    covariance <- matrix(covariance, effect_count, effect_count, byrow = TRUE)
    if (!isTRUE(all.equal(covariance, t(covariance), tolerance = 0)) ||
        any(eigen(covariance, symmetric = TRUE, only.values = TRUE)$values < -1e-10)) {
      return(NULL)
    }
    list(beta = beta, sigma2 = sigma2, covariance = covariance)
  })
  if (any(vapply(candidates, is.null, logical(1L)))) {
    stop("Invalid Gaussian random-slope likelihood-grid candidates.", call. = FALSE)
  }
  if (!length(outcome)) return(rep.int(0, length(candidates)))
  cluster_members <- split(seq_along(cluster), as.character(cluster))
  if (any(lengths(cluster_members) > max_patients_per_cluster)) {
    stop("The protected snapshot exceeds its signed LMM cluster capacity.",
         call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(.dsvert_dp_exact_integer_limit /
                               (max(candidate_loss_bounds) * scale))) {
    stop("The Gaussian random-slope LMM cohort is too large for exact quantization.",
         call. = FALSE)
  }
  design_matrix <- do.call(cbind, design)
  random_columns <- match(random_effect_order[-1L], names(design))
  statistics <- vapply(seq_along(candidates), function(index) {
    candidate <- candidates[[index]]
    sum(vapply(cluster_members, function(members) {
      fixed <- design_matrix[members, , drop = FALSE]
      random <- cbind(1, fixed[, random_columns, drop = FALSE])
      covariance <- candidate$sigma2 * diag(length(members)) +
        random %*% candidate$covariance %*% t(random)
      decomposition <- tryCatch(chol(covariance), error = function(error) NULL)
      if (is.null(decomposition)) {
        stop("The signed Gaussian random-slope covariance is not positive definite.",
             call. = FALSE)
      }
      residual <- outcome[members] - as.numeric(fixed %*% candidate$beta)
      solved <- backsolve(decomposition,
                          forwardsolve(t(decomposition), residual))
      loss <- 0.5 * (length(members) * log(2 * pi) +
        2 * sum(log(diag(decomposition))) + sum(residual * solved))
      as.numeric(round(min(candidate_loss_bounds[[index]], max(0, loss)) * scale))
    }, numeric(1L)))
  }, numeric(1L))
  if (anyNA(statistics) || any(!is.finite(statistics)) || any(statistics < 0) ||
      any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The Gaussian random-slope likelihood-grid statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_negative_binomial_grid_losses <- function(
    design, outcome, beta_grid, theta_grid, grid_bits, max_outcome) {
  if (!is.list(design) || !length(design) || !is.numeric(outcome) ||
      anyNA(outcome) || any(!is.finite(outcome)) || any(outcome < 0) ||
      any(outcome != floor(outcome)) || any(outcome > max_outcome) ||
      !is.list(beta_grid) || !length(beta_grid) || !is.numeric(theta_grid) ||
      !length(theta_grid) || anyNA(theta_grid) || any(!is.finite(theta_grid)) ||
      any(theta_grid <= 0) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L ||
      !is.numeric(max_outcome) || length(max_outcome) != 1L ||
      is.na(max_outcome) || !is.finite(max_outcome) ||
      max_outcome != floor(max_outcome) || max_outcome < 1L) {
    stop("Invalid negative-binomial likelihood-grid values.", call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  if (!all(valid_design) || !all(vapply(beta_grid, function(beta) {
    is.numeric(beta) && length(beta) == length(design) &&
      !anyNA(beta) && all(is.finite(beta))
  }, logical(1L)))) {
    stop("Invalid negative-binomial likelihood-grid design.", call. = FALSE)
  }
  candidate_count <- length(beta_grid) * length(theta_grid)
  if (!length(outcome)) return(rep.int(0, candidate_count))
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(
        .dsvert_dp_exact_integer_limit / (max_outcome * scale))) {
    stop("The NB2 capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  log1pexp <- function(value) pmax(value, 0) + log1p(exp(-abs(value)))
  design_matrix <- do.call(cbind, design)
  candidates <- unlist(lapply(theta_grid, function(theta) {
    lapply(beta_grid, function(beta) list(beta = beta, theta = theta))
  }), recursive = FALSE)
  statistics <- vapply(candidates, function(candidate) {
    eta <- as.numeric(design_matrix %*% candidate$beta)
    value <- lgamma(candidate$theta) + lgamma(outcome + 1) -
      lgamma(outcome + candidate$theta) +
      candidate$theta * log1pexp(eta - log(candidate$theta)) - outcome * eta
    sum(as.numeric(round(pmax(0, value) * scale)))
  }, numeric(1L))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The negative-binomial likelihood-grid statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_glm_grid_losses <- function(
    design, outcome, family, beta_grid, grid_bits, max_outcome = NULL) {
  poisson <- identical(family, "poisson")
  if (!identical(family, "binomial") && !isTRUE(poisson) ||
      !is.list(design) || !length(design) || !is.numeric(outcome) ||
      anyNA(outcome) || any(!is.finite(outcome)) || !is.list(beta_grid) ||
      !length(beta_grid) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("Invalid finite GLM likelihood-grid values.", call. = FALSE)
  }
  valid_outcome <- if (isTRUE(poisson)) {
    is.numeric(max_outcome) && length(max_outcome) == 1L &&
      !is.na(max_outcome) && is.finite(max_outcome) &&
      max_outcome == floor(max_outcome) && max_outcome >= 1L &&
      all(outcome >= 0 & outcome == floor(outcome) & outcome <= max_outcome)
  } else {
    outcome %in% c(0, 1)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  valid_beta <- vapply(beta_grid, function(beta) {
    is.numeric(beta) && length(beta) == length(design) &&
      !anyNA(beta) && all(is.finite(beta)) && all(abs(beta) <= 8) &&
      sum(abs(beta)) <= 16
  }, logical(1L))
  if (!all(valid_outcome) || !all(valid_design) || !all(valid_beta)) {
    stop("Invalid finite GLM likelihood-grid design.", call. = FALSE)
  }
  if (!length(outcome)) return(rep.int(0, length(beta_grid)))
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(.dsvert_dp_exact_integer_limit / scale)) {
    stop("The finite GLM capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  softplus <- function(value) pmax(value, 0) + log1p(exp(-abs(value)))
  design_matrix <- do.call(cbind, design)
  statistics <- vapply(beta_grid, function(beta) {
    eta <- as.numeric(design_matrix %*% beta)
    loss <- if (isTRUE(poisson)) {
      exp(eta) - outcome * eta + lgamma(outcome + 1)
    } else {
      softplus(eta) - outcome * eta
    }
    sum(as.numeric(round(pmax(0, loss) * scale)))
  }, numeric(1L))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The finite GLM likelihood-grid statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_multinomial_grid_losses <- function(
    design, outcome, levels, reference, beta_grid, grid_bits) {
  if (!is.list(design) || !length(design) || !is.numeric(outcome) ||
      anyNA(outcome) || any(!is.finite(outcome)) ||
      any(outcome < 1) || any(outcome != floor(outcome)) ||
      !is.character(levels) || length(levels) < 3L || anyNA(levels) ||
      anyDuplicated(levels) || !is.character(reference) ||
      length(reference) != 1L || is.na(reference) || !reference %in% levels ||
      !is.list(beta_grid) || !length(beta_grid) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("Invalid multinomial likelihood-grid values.", call. = FALSE)
  }
  if (any(outcome > length(levels))) {
    stop("Invalid multinomial likelihood-grid outcome values.", call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  dimension <- length(design)
  non_reference <- setdiff(levels, reference)
  if (!all(valid_design) || !all(vapply(beta_grid, function(beta) {
        is.numeric(beta) && length(beta) == dimension * length(non_reference) &&
          !anyNA(beta) && all(is.finite(beta))
      }, logical(1L)))) {
    stop("Invalid multinomial likelihood-grid design.", call. = FALSE)
  }
  if (!length(outcome)) return(rep.int(0, length(beta_grid)))
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(.dsvert_dp_exact_integer_limit / scale)) {
    stop("The multinomial capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  design_matrix <- do.call(cbind, design)
  statistics <- vapply(beta_grid, function(beta) {
    coefficients <- matrix(
      beta, nrow = dimension, ncol = length(non_reference),
      dimnames = list(NULL, non_reference))
    scores <- matrix(0, nrow = length(outcome), ncol = length(levels))
    scores[, match(non_reference, levels)] <- design_matrix %*% coefficients
    maximum <- apply(scores, 1L, max)
    log_norm <- maximum + log(rowSums(exp(scores - maximum)))
    loss <- log_norm - scores[cbind(seq_along(outcome), outcome)]
    sum(as.numeric(round(pmax(0, loss) * scale)))
  }, numeric(1L))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The multinomial likelihood-grid statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_ordinal_grid_losses <- function(
    design, outcome, levels, ordered_levels, candidate_grid, grid_bits) {
  if (!is.list(design) || !length(design) || !is.numeric(outcome) ||
      anyNA(outcome) || any(!is.finite(outcome)) ||
      any(outcome < 1) || any(outcome != floor(outcome)) ||
      !is.character(levels) || !is.character(ordered_levels) ||
      length(levels) < 3L || anyNA(levels) || anyNA(ordered_levels) ||
      anyDuplicated(levels) || anyDuplicated(ordered_levels) ||
      !setequal(levels, ordered_levels) || !is.list(candidate_grid) ||
      !length(candidate_grid) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("Invalid ordinal likelihood-grid values.", call. = FALSE)
  }
  if (any(outcome > length(levels))) {
    stop("Invalid ordinal likelihood-grid outcome values.", call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  dimension <- length(design)
  valid_candidates <- vapply(candidate_grid, function(candidate) {
    is.list(candidate) && setequal(names(candidate), c("thresholds", "beta")) &&
      is.numeric(candidate$thresholds) &&
      length(candidate$thresholds) == length(levels) - 1L &&
      !anyNA(candidate$thresholds) && all(is.finite(candidate$thresholds)) &&
      all(abs(candidate$thresholds) <= 8) &&
      all(diff(candidate$thresholds) >= 1 / 256) &&
      is.numeric(candidate$beta) && length(candidate$beta) == dimension &&
      !anyNA(candidate$beta) && all(is.finite(candidate$beta)) &&
      all(abs(candidate$beta) <= 8)
  }, logical(1L))
  if (!all(valid_design) || !all(valid_candidates)) {
    stop("Invalid ordinal likelihood-grid design.", call. = FALSE)
  }
  if (!length(outcome)) return(rep.int(0, length(candidate_grid)))
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(.dsvert_dp_exact_integer_limit / scale)) {
    stop("The ordinal capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  log_sigmoid <- function(value) {
    ifelse(value >= 0, -log1p(exp(-value)), value - log1p(exp(value)))
  }
  design_matrix <- do.call(cbind, design)
  ordered_outcome <- match(levels[outcome], ordered_levels)
  statistics <- vapply(candidate_grid, function(candidate) {
    eta <- as.numeric(design_matrix %*% candidate$beta)
    lower <- c(-Inf, candidate$thresholds)
    upper <- c(candidate$thresholds, Inf)
    log_probability <- vapply(seq_along(ordered_outcome), function(index) {
      category <- ordered_outcome[[index]]
      if (category == 1L) {
        log_sigmoid(upper[[category]] - eta[[index]])
      } else if (category == length(ordered_levels)) {
        log_sigmoid(eta[[index]] - lower[[category]])
      } else {
        high <- log_sigmoid(upper[[category]] - eta[[index]])
        low <- log_sigmoid(lower[[category]] - eta[[index]])
        high + log1p(-exp(low - high))
      }
    }, numeric(1L))
    sum(as.numeric(round(pmax(0, -log_probability) * scale)))
  }, numeric(1L))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The ordinal likelihood-grid statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_materializer_manifest <- function(policy, manifest) {
  .dsvert_dp_capsule_workload_require_materializable(manifest)
  required <- c(
    "version", "logical_snapshot", "capsule_schema", "admission", "bounds",
    "workload", "capsule_identity", "execution_state")
  if (!is.list(manifest) || is.null(names(manifest)) || anyNA(names(manifest)) ||
      anyDuplicated(names(manifest)) || !setequal(names(manifest), required) ||
      !identical(manifest$version, .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) ||
      !identical(manifest$capsule_schema,
                 .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) ||
      !identical(manifest$execution_state,
                 .DSVERT_DP_CAPSULE_EXECUTION_STATE) ||
      !is.list(manifest$workload) ||
      !identical(manifest$workload$workload_version,
                 .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) ||
      !identical(manifest$workload$execution_state,
                 .DSVERT_DP_CAPSULE_EXECUTION_STATE) ||
      !identical(manifest$workload$declared_workload_fully_materialized,
                 TRUE) ||
      !identical(manifest$workload$package_family_coverage_complete,
                 FALSE) ||
      !identical(
        manifest$workload$registered_release_lifecycle,
        .dsvert_dp_capsule_registered_release_lifecycle())) {
    stop("The biomedical capsule is not a valid registered-lifecycle contract.",
         call. = FALSE)
  }
  logical_snapshot <- .dsvert_joint_dp_logical_snapshot(
    manifest$logical_snapshot)
  identity <- if (.dsvert_dp_synopsis_policy_is_v1(policy)) {
    .dsvert_dp_synopsis_capsule_identity_validate_v1(
      policy, logical_snapshot, manifest$capsule_identity)
  } else {
    .dsvert_joint_dp_capsule_identity_validate(
      policy, logical_snapshot, manifest$capsule_identity)
  }
  contract <- identity$contract
  if (!identical(contract$logical_snapshot, logical_snapshot) ||
      !identical(contract$admission, manifest$admission) ||
      !identical(contract$bounds, manifest$bounds) ||
      !identical(contract$workload, manifest$workload) ||
      !identical(
        .dsvert_dp_canonical_query_value(
          .dsvert_dp_admission_public(policy)),
        manifest$admission) ||
      !identical(
        manifest$workload$capsule_mechanism$source_context_hash,
        .dsvert_joint_dp_hash(list(
          version = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
          logical_snapshot = logical_snapshot,
          schema_manifest_sha256 =
            manifest$workload$schema_attestation$manifest_sha256,
          admission = manifest$admission, bounds = manifest$bounds,
          families = manifest$workload$families,
          vertical_crosses = manifest$workload$vertical_crosses,
          primitive_scope = manifest$workload$primitive_scope,
          release_lattice = manifest$workload$release_lattice,
          mechanism_selection =
            manifest$workload$mechanism_selection)))) {
    stop("The biomedical capsule materializer contract was modified.",
         call. = FALSE)
  }
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  if (!identical(
        as.numeric(layout$coordinate_count),
        as.numeric(manifest$workload$capsule_mechanism$coordinate_count))) {
    stop("The biomedical capsule mechanism has the wrong vector shape.",
         call. = FALSE)
  }
  list(manifest = manifest, identity = identity, layout = layout)
}

.dsvert_dp_capsule_resolved_snapshots <- function(policy, snapshots) {
  if (is.list(snapshots) && all(c("data", "dataset") %in% names(snapshots))) {
    data_name <- tryCatch(
      snapshots$dataset$public$data_name, error = function(e) NULL)
    if (!is.character(data_name) || length(data_name) != 1L ||
        is.na(data_name) || !nzchar(data_name)) {
      stop("The resolved biomedical capsule snapshot is invalid.",
           call. = FALSE)
    }
    snapshots <- stats::setNames(list(snapshots), data_name)
  }
  expected <- sort(names(policy$datasets), method = "radix")
  if (!is.list(snapshots) || is.null(names(snapshots)) ||
      anyNA(names(snapshots)) || any(!nzchar(names(snapshots))) ||
      anyDuplicated(names(snapshots)) ||
      !identical(sort(names(snapshots), method = "radix"), expected)) {
    stop("Resolved snapshots must exactly cover the local capsule datasets.",
         call. = FALSE)
  }
  snapshots <- snapshots[expected]
  for (data_name in expected) {
    snapshot <- snapshots[[data_name]]
    descriptor <- policy$datasets[[data_name]]
    if (!is.list(snapshot) || !all(c("data", "dataset") %in% names(snapshot)) ||
        !is.data.frame(snapshot$data) || !is.list(snapshot$dataset) ||
        !is.list(snapshot$dataset$public) ||
        !identical(snapshot$dataset$public$data_name, data_name) ||
        !identical(snapshot$dataset$public$id, descriptor$id) ||
        !identical(snapshot$dataset$public$version, descriptor$version) ||
        !is.character(snapshot$dataset$fingerprint) ||
        length(snapshot$dataset$fingerprint) != 1L ||
        is.na(snapshot$dataset$fingerprint) ||
        !grepl("^[0-9a-f]{64}$", snapshot$dataset$fingerprint)) {
      stop("The resolved biomedical capsule snapshot binding is invalid.",
           call. = FALSE)
    }
    invisible(.dsvert_dp_snapshot_columns(snapshot$data))
    snapshot_sha256 <- NULL
    if (!is.null(descriptor$snapshot_sha256)) {
      snapshot_sha256 <- .dsvert_dp_snapshot_digest(snapshot$data)
      if (!identical(snapshot_sha256, descriptor$snapshot_sha256)) {
        stop("The resolved biomedical capsule snapshot digest changed.",
             call. = FALSE)
      }
    }
    if (!is.null(descriptor$alignment_manifest_hash)) {
      tryCatch(
        .dsvert_dp_validate_descriptor_alignment(
          snapshot$data, descriptor, policy$patient_column,
          expected_pinset = policy$peer_pinset,
          snapshot_sha256 = snapshot_sha256),
        error = function(e) {
          stop("The resolved biomedical capsule alignment binding changed.",
               call. = FALSE)
        })
    }
  }
  snapshots
}

.dsvert_dp_capsule_bounded_category <- function(
    data, policy, column, levels, admission, strict = FALSE) {
  if (!is.character(levels) || !length(levels) || anyNA(levels) ||
      anyDuplicated(levels) || !column %in% names(data) ||
      !is.atomic(data[[column]]) || !is.logical(strict) ||
      length(strict) != 1L || is.na(strict)) {
    stop("The protected snapshot does not match its categorical capsule contract.",
         call. = FALSE)
  }
  labels <- tryCatch(
    .dsvert_dp_categorical_label_values(
      data[[column]], "protected categorical values"),
    error = function(e) {
      stop("The protected snapshot does not match its categorical capsule contract.",
           call. = FALSE)
    })
  level <- match(labels, levels)
  if (isTRUE(strict)) {
    present_rows <- admission$present[admission$group]
    unknown <- present_rows & !is.na(labels) & is.na(level)
    if (any(unknown)) {
      stop("The protected snapshot has an unknown categorical value.",
           call. = FALSE)
    }
    known_groups <- admission$group[present_rows & !is.na(level)]
    known_levels <- level[present_rows & !is.na(level)]
    if (length(known_groups)) {
      key <- paste(known_groups, known_levels, sep = "\r")
      distinct <- !duplicated(key)
      per_group <- tabulate(known_groups[distinct],
                            nbins = admission$work_units)
      if (any(per_group > 1L)) {
        stop("The protected snapshot has conflicting categorical values.",
             call. = FALSE)
      }
    }
  }
  valid_rows <- which(!is.na(level))
  selected <- rep(NA_integer_, admission$work_units)
  if (length(valid_rows)) {
    groups <- admission$group[valid_rows]
    valid_levels <- level[valid_rows]
    composite <- (as.double(groups) - 1) * length(levels) + valid_levels
    distinct <- !duplicated(composite)
    distinct_per_group <- tabulate(
      groups[distinct], nbins = admission$work_units)
    first <- !duplicated(groups)
    first_groups <- groups[first]
    first_levels <- valid_levels[first]
    consistent <- distinct_per_group[first_groups] == 1L
    selected[first_groups[consistent]] <- first_levels[consistent]
  }
  selected[!admission$present] <- NA_integer_
  list(cell = unname(selected), levels = levels)
}

.dsvert_dp_capsule_survival_spec <- function(artifact, analysis_id) {
  entry <- if (identical(artifact$entry, "none")) NULL else artifact$entry
  list(
    analysis_id = analysis_id, version = artifact$version,
    dataset = artifact$dataset, time = artifact$time,
    event = artifact$event, entry = entry, censor = artifact$censor,
    causes = artifact$causes,
    outcome_levels = c(artifact$censor, artifact$causes),
    time_grid = artifact$time_grid, time_bounds = artifact$time_bounds,
    delayed_entry = !is.null(entry),
    coordinate_count = artifact$coordinate_count,
    l1_sensitivity = artifact$l1_sensitivity,
    l2_sensitivity = artifact$l2_sensitivity)
}

.dsvert_dp_capsule_value_commitment <- function(values, binding) {
  values <- .dsvert_dp_integer_vector(values, "local capsule coordinates")
  starts <- seq.int(1L, length(values), by = .DSVERT_DP_CAPSULE_VALUE_BLOCK)
  block_hashes <- vapply(starts, function(start) {
    end <- min(length(values), start + .DSVERT_DP_CAPSULE_VALUE_BLOCK - 1L)
    digest::digest(
      unname(values[start:end]), algo = "sha256", serialize = TRUE,
      serializeVersion = 3L)
  }, character(1L))
  .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-value-blocks-v1",
    coordinate_count = length(values),
    block_size = .DSVERT_DP_CAPSULE_VALUE_BLOCK,
    block_hashes = unname(block_hashes), binding = binding))
}

.dsvert_dp_capsule_compact_bounded_numeric <- function(bounded) {
  bounded[c("unit_values", "valid")]
}

.dsvert_dp_capsule_materialize_local <- function(
    policy, manifest, resolved_snapshots) {
  contract <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  snapshots <- .dsvert_dp_capsule_resolved_snapshots(
    policy, resolved_snapshots)
  layout <- contract$layout
  local_peer <- .dsvert_dp_capsule_id(policy$peer_name, "local peer")
  values <- numeric(layout$coordinate_count)
  admissions <- new.env(parent = emptyenv())
  bounded_numeric <- new.env(parent = emptyenv())
  admission_for <- function(data_name) {
    if (!exists(data_name, envir = admissions, inherits = FALSE)) {
      assign(
        data_name,
        .dsvert_dp_admit_units(snapshots[[data_name]]$data, policy),
        envir = admissions)
    }
    get(data_name, envir = admissions, inherits = FALSE)
  }
  bounded_for <- function(data_name, column) {
    key <- .dsvert_dp_capsule_local_key(data_name, column)
    if (!exists(key, envir = bounded_numeric, inherits = FALSE)) {
      assign(
        key,
        .dsvert_dp_bounded_numeric(
          snapshots[[data_name]]$data, policy, column,
          admission_for(data_name)),
        envir = bounded_numeric)
    }
    get(key, envir = bounded_numeric, inherits = FALSE)
  }

  local_blocks <- layout$blocks[vapply(
    layout$blocks, function(block) identical(block$owner_peer, local_peer),
    logical(1L))]
  cross_artifacts <- manifest$workload$families$gaussian_models$artifacts
  cross_artifacts <- cross_artifacts[vapply(
    cross_artifacts, function(artifact) {
      identical(
        artifact$version,
        "bounded-normalized-gaussian-cross-sufficient-statistics-v1")
    }, logical(1L))]
  owns_cross_input <- any(vapply(cross_artifacts, function(artifact) {
    local_peer %in% unlist(artifact$participating_peers, use.names = FALSE)
  }, logical(1L)))
  if (!length(local_blocks) && !isTRUE(owns_cross_input)) {
    stop("The local peer owns no coordinate in this biomedical capsule.",
         call. = FALSE)
  }
  if (any(!vapply(local_blocks, function(block) {
        block$dataset %in% names(snapshots)
      }, logical(1L)))) {
    stop("A local capsule coordinate has no resolved owner dataset.",
         call. = FALSE)
  }

  count_block <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "admitted_count"]
  if (length(count_block)) {
    block <- count_block[[1L]]
    values[block$start] <- admission_for(block$dataset)$unit_count
  }

  histogram_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") ==
      "fixed_numeric_histograms"]
  histograms_by_numeric <- list()
  for (name in names(histogram_blocks)) {
    block <- histogram_blocks[[name]]
    key <- .dsvert_dp_capsule_local_key(
      block$dataset, block$descriptor$column)
    histograms_by_numeric[[key]] <- c(histograms_by_numeric[[key]], name)
  }

  numeric_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "numeric_moments"]
  for (name in names(numeric_blocks)) {
    block <- numeric_blocks[[name]]
    artifact <- block$descriptor
    bounded <- bounded_for(block$dataset, artifact$column)
    normalised <- (bounded$values - artifact$lower) /
      (artifact$upper - artifact$lower)
    normalised <- pmin(1, pmax(0, normalised))
    moments <- .dsvert_dp_quantized_moments(
      normalised, artifact$numeric_grid_bits)$statistics
    values[block$start:block$end] <- unname(moments)

    numeric_key <- .dsvert_dp_capsule_local_key(
      block$dataset, artifact$column)
    for (histogram_name in histograms_by_numeric[[numeric_key]]) {
      histogram_block <- histogram_blocks[[histogram_name]]
      histogram <- histogram_block$descriptor
      bins <- if (length(bounded$values)) {
        as.integer(findInterval(
          bounded$values, histogram$grid, left.open = TRUE) + 1L)
      } else {
        integer()
      }
      exact <- c(
        tabulate(bins, nbins = length(histogram$grid)),
        sum(bounded$present & !bounded$valid))
      values[histogram_block$start:histogram_block$end] <- exact
      rm(bins, exact)
    }
    assign(
      numeric_key, .dsvert_dp_capsule_compact_bounded_numeric(bounded),
      envir = bounded_numeric)
    rm(bounded, normalised, moments)
  }
  filled_histograms <- unlist(histograms_by_numeric, use.names = FALSE)
  if (length(setdiff(names(histogram_blocks), filled_histograms))) {
    stop("A numeric histogram has no matching numeric capsule artifact.",
         call. = FALSE)
  }

  numeric_pair_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") ==
      "numeric_pair_moments"]
  for (name in names(numeric_pair_blocks)) {
    block <- numeric_pair_blocks[[name]]
    artifact <- block$descriptor
    left <- bounded_for(block$dataset, artifact$left$column)
    right <- bounded_for(block$dataset, artifact$right$column)
    complete <- left$valid & right$valid
    left_normalized <- (left$unit_values[complete] - artifact$left$lower) /
      (artifact$left$upper - artifact$left$lower)
    right_normalized <-
      (right$unit_values[complete] - artifact$right$lower) /
      (artifact$right$upper - artifact$right$lower)
    left_normalized <- pmin(1, pmax(0, left_normalized))
    right_normalized <- pmin(1, pmax(0, right_normalized))
    values[block$start:block$end] <-
      .dsvert_dp_capsule_quantized_pair_moments(
        left_normalized, right_normalized, artifact$numeric_grid_bits)
  }

  gaussian_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "gaussian_models"]
  for (name in names(gaussian_blocks)) {
    block <- gaussian_blocks[[name]]
    artifact <- block$descriptor
    if (identical(
          artifact$version,
          "bounded-normalized-gaussian-cross-sufficient-statistics-v1")) {
      # Cross-owner coordinates are injected only after the fixed exact-GC
      # transcript.  Every ordinary source contributes the all-zero public
      # block here, so no exact moment can enter the sampler by accident.
      next
    }
    if (identical(
          artifact$version,
          "bounded-normalized-random-intercept-moments-v1")) {
      outcome <- bounded_for(block$dataset, artifact$outcome$column)
      cluster <- .dsvert_dp_capsule_bounded_category(
        snapshots[[block$dataset]]$data, policy, artifact$cluster$column,
        artifact$cluster$levels, admission_for(block$dataset))
      complete <- outcome$valid & !is.na(cluster$cell)
      normalized_outcome <- pmin(1, pmax(
        0, (outcome$unit_values[complete] - artifact$outcome$lower) /
          (artifact$outcome$upper - artifact$outcome$lower)))
      statistics <- .dsvert_dp_capsule_quantized_random_intercept_stats(
        normalized_outcome, cluster$cell[complete],
        artifact$numeric_grid_bits, artifact$max_patients_per_cluster)
      if (length(statistics) != block$length) {
        stop("The signed random-intercept capsule coordinate shape is invalid.",
             call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    if (identical(artifact$version,
                  "bounded-gaussian-random-slope-likelihood-grid-v1")) {
      outcome <- bounded_for(block$dataset, artifact$outcome$column)
      cluster <- .dsvert_dp_capsule_bounded_category(
        snapshots[[block$dataset]]$data, policy, artifact$cluster$column,
        artifact$cluster$levels, admission_for(block$dataset))
      predictors <- lapply(artifact$predictor_order, function(variable) {
        bounded_for(block$dataset, artifact$predictors[[variable]]$column)
      })
      names(predictors) <- artifact$predictor_order
      complete <- outcome$valid & !is.na(cluster$cell)
      for (predictor in predictors) complete <- complete & predictor$valid
      normalize <- function(values, lower, upper) {
        pmin(1, pmax(0, (values - lower) / (upper - lower)))
      }
      normalized_outcome <- normalize(outcome$unit_values[complete],
                                      artifact$outcome$lower,
                                      artifact$outcome$upper)
      design <- c(list(`(Intercept)` = rep(1, length(normalized_outcome))),
                  stats::setNames(lapply(artifact$predictor_order, function(variable) {
                    descriptor <- artifact$predictors[[variable]]
                    normalize(predictors[[variable]]$unit_values[complete],
                              descriptor$lower, descriptor$upper)
                  }), artifact$predictor_order))
      statistics <- .dsvert_dp_capsule_quantized_gaussian_random_slope_grid_losses(
        design, normalized_outcome, cluster$cell[complete], artifact$candidate_grid,
        artifact$random_effect_order, artifact$numeric_grid_bits,
        artifact$max_patients_per_cluster,
        unlist(artifact$candidate_loss_bounds, use.names = FALSE))
      if (length(statistics) != block$length) {
        stop("The signed Gaussian random-slope LMM coordinate shape is invalid.",
             call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    if (artifact$version %in% c(
          "bounded-normalized-random-intercept-fixed-sufficient-statistics-v2",
          "bounded-normalized-random-intercept-fixed-sufficient-statistics-v3")) {
      outcome <- bounded_for(block$dataset, artifact$outcome$column)
      cluster <- .dsvert_dp_capsule_bounded_category(
        snapshots[[block$dataset]]$data, policy, artifact$cluster$column,
        artifact$cluster$levels, admission_for(block$dataset))
      predictors <- lapply(artifact$predictor_order, function(variable) {
        bounded_for(block$dataset, artifact$predictors[[variable]]$column)
      })
      names(predictors) <- artifact$predictor_order
      complete <- outcome$valid & !is.na(cluster$cell)
      for (predictor in predictors) complete <- complete & predictor$valid
      normalize <- function(values, lower, upper) {
        pmin(1, pmax(0, (values - lower) / (upper - lower)))
      }
      normalized_outcome <- normalize(
        outcome$unit_values[complete], artifact$outcome$lower,
        artifact$outcome$upper)
      design <- c(
        list(rep(1, length(normalized_outcome))),
        lapply(artifact$predictor_order, function(variable) {
          descriptor <- artifact$predictors[[variable]]
          normalize(
            predictors[[variable]]$unit_values[complete],
            descriptor$lower, descriptor$upper)
        }))
      statistics <- .dsvert_dp_capsule_quantized_random_intercept_fixed_stats(
        design, normalized_outcome, cluster$cell[complete],
        artifact$numeric_grid_bits, artifact$max_patients_per_cluster)
      if (length(statistics) != block$length) {
        stop("The signed fixed-effect random-intercept capsule coordinate shape is invalid.",
             call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    if (artifact$version %in% c(
          "bounded-binomial-likelihood-grid-v1",
          "bounded-poisson-likelihood-grid-v1")) {
      family <- if (identical(
            artifact$version, "bounded-poisson-likelihood-grid-v1")) {
        "poisson"
      } else {
        "binomial"
      }
      outcome <- bounded_for(block$dataset, artifact$outcome$column)
      predictors <- lapply(artifact$predictor_order, function(variable) {
        bounded_for(block$dataset, artifact$predictors[[variable]]$column)
      })
      names(predictors) <- artifact$predictor_order
      complete <- outcome$valid
      if (identical(family, "poisson")) {
        complete <- complete & outcome$unit_values >= 0 &
          outcome$unit_values == floor(outcome$unit_values) &
          outcome$unit_values <= artifact$max_outcome
      } else {
        complete <- complete & outcome$unit_values %in% c(0, 1)
      }
      for (predictor in predictors) complete <- complete & predictor$valid
      normalize <- function(value, lower, upper) {
        pmin(1, pmax(0, (value - lower) / (upper - lower)))
      }
      normalized_outcome <- outcome$unit_values[complete]
      design <- c(
        list(rep(1, length(normalized_outcome))),
        lapply(artifact$predictor_order, function(variable) {
          descriptor <- artifact$predictors[[variable]]
          normalize(
            predictors[[variable]]$unit_values[complete],
            descriptor$lower, descriptor$upper)
        }))
      statistics <- .dsvert_dp_capsule_quantized_glm_grid_losses(
        design, normalized_outcome, family, artifact$beta_grid,
        artifact$numeric_grid_bits, artifact$max_outcome)
      if (length(statistics) != block$length) {
        stop("The signed finite GLM grid shape is invalid.", call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    if (identical(
          artifact$version,
          "bounded-negative-binomial-likelihood-grid-v1")) {
      outcome <- bounded_for(block$dataset, artifact$outcome$column)
      predictors <- lapply(artifact$predictor_order, function(variable) {
        bounded_for(block$dataset, artifact$predictors[[variable]]$column)
      })
      names(predictors) <- artifact$predictor_order
      complete <- outcome$valid & outcome$unit_values >= 0 &
        outcome$unit_values == floor(outcome$unit_values) &
        outcome$unit_values <= artifact$max_outcome
      for (predictor in predictors) complete <- complete & predictor$valid
      normalize <- function(value, lower, upper) {
        pmin(1, pmax(0, (value - lower) / (upper - lower)))
      }
      normalized_outcome <- outcome$unit_values[complete]
      design <- c(
        list(rep(1, length(normalized_outcome))),
        lapply(artifact$predictor_order, function(variable) {
          descriptor <- artifact$predictors[[variable]]
          normalize(
            predictors[[variable]]$unit_values[complete],
            descriptor$lower, descriptor$upper)
        }))
      statistics <- .dsvert_dp_capsule_quantized_negative_binomial_grid_losses(
        design, normalized_outcome, artifact$beta_grid, artifact$theta_grid,
        artifact$numeric_grid_bits, artifact$max_outcome)
      if (length(statistics) != block$length) {
        stop("The signed negative-binomial grid shape is invalid.",
             call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    if (identical(
          artifact$version,
          "bounded-multinomial-likelihood-grid-v1")) {
      outcome <- .dsvert_dp_capsule_bounded_category(
        snapshots[[block$dataset]]$data, policy, artifact$outcome$column,
        artifact$outcome$levels, admission_for(block$dataset), strict = TRUE)
      predictors <- lapply(artifact$predictor_order, function(variable) {
        bounded_for(block$dataset, artifact$predictors[[variable]]$column)
      })
      names(predictors) <- artifact$predictor_order
      complete <- !is.na(outcome$cell)
      for (predictor in predictors) complete <- complete & predictor$valid
      normalize <- function(value, lower, upper) {
        pmin(1, pmax(0, (value - lower) / (upper - lower)))
      }
      design <- c(
        list(rep(1, sum(complete))),
        lapply(artifact$predictor_order, function(variable) {
          descriptor <- artifact$predictors[[variable]]
          normalize(
            predictors[[variable]]$unit_values[complete],
            descriptor$lower, descriptor$upper)
        }))
      statistics <- .dsvert_dp_capsule_quantized_multinomial_grid_losses(
        design, outcome$cell[complete], artifact$outcome$levels,
        artifact$outcome$reference, artifact$beta_grid,
        artifact$numeric_grid_bits)
      if (length(statistics) != block$length) {
        stop("The signed multinomial grid shape is invalid.", call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    if (identical(
          artifact$version,
          "bounded-ordinal-likelihood-grid-v1")) {
      outcome <- .dsvert_dp_capsule_bounded_category(
        snapshots[[block$dataset]]$data, policy, artifact$outcome$column,
        artifact$outcome$levels, admission_for(block$dataset), strict = TRUE)
      predictors <- lapply(artifact$predictor_order, function(variable) {
        bounded_for(block$dataset, artifact$predictors[[variable]]$column)
      })
      names(predictors) <- artifact$predictor_order
      complete <- !is.na(outcome$cell)
      for (predictor in predictors) complete <- complete & predictor$valid
      normalize <- function(value, lower, upper) {
        pmin(1, pmax(0, (value - lower) / (upper - lower)))
      }
      design <- c(
        list(rep(1, sum(complete))),
        lapply(artifact$predictor_order, function(variable) {
          descriptor <- artifact$predictors[[variable]]
          normalize(
            predictors[[variable]]$unit_values[complete],
            descriptor$lower, descriptor$upper)
        }))
      statistics <- .dsvert_dp_capsule_quantized_ordinal_grid_losses(
        design, outcome$cell[complete], artifact$outcome$levels,
        artifact$outcome$ordered_levels, artifact$candidate_grid,
        artifact$numeric_grid_bits)
      if (length(statistics) != block$length) {
        stop("The signed ordinal grid shape is invalid.", call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    if (identical(
          artifact$version,
          "bounded-binary-random-intercept-likelihood-grid-v1")) {
      outcome <- bounded_for(block$dataset, artifact$outcome$column)
      cluster <- .dsvert_dp_capsule_bounded_category(
        snapshots[[block$dataset]]$data, policy, artifact$cluster$column,
        artifact$cluster$levels, admission_for(block$dataset))
      predictors <- lapply(artifact$predictor_order, function(variable) {
        bounded_for(block$dataset, artifact$predictors[[variable]]$column)
      })
      names(predictors) <- artifact$predictor_order
      complete <- outcome$valid & outcome$unit_values %in% c(0, 1) &
        !is.na(cluster$cell)
      for (predictor in predictors) complete <- complete & predictor$valid
      normalize <- function(values, lower, upper) {
        pmin(1, pmax(0, (values - lower) / (upper - lower)))
      }
      normalized_outcome <- outcome$unit_values[complete]
      design <- c(
        list(rep(1, length(normalized_outcome))),
        lapply(artifact$predictor_order, function(variable) {
          descriptor <- artifact$predictors[[variable]]
          normalize(
            predictors[[variable]]$unit_values[complete],
            descriptor$lower, descriptor$upper)
        }))
      statistics <-
        .dsvert_dp_capsule_quantized_binary_random_intercept_grid_losses(
          design, normalized_outcome, cluster$cell[complete],
          artifact$beta_grid, artifact$variance_grid,
          artifact$numeric_grid_bits, artifact$max_patients_per_cluster)
      if (length(statistics) != block$length) {
        stop("The signed binary random-intercept GLMM grid shape is invalid.",
             call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    outcome <- bounded_for(block$dataset, artifact$outcome$column)
    predictors <- lapply(artifact$predictor_order, function(variable) {
      bounded_for(block$dataset, artifact$predictors[[variable]]$column)
    })
    names(predictors) <- artifact$predictor_order
    complete <- outcome$valid
    for (predictor in predictors) complete <- complete & predictor$valid
    normalize <- function(values, lower, upper) {
      pmin(1, pmax(0, (values - lower) / (upper - lower)))
    }
    normalized_outcome <- normalize(
      outcome$unit_values[complete], artifact$outcome$lower,
      artifact$outcome$upper)
    normalized_predictors <- lapply(
      artifact$predictor_order, function(variable) {
        descriptor <- artifact$predictors[[variable]]
        normalize(
          predictors[[variable]]$unit_values[complete],
          descriptor$lower, descriptor$upper)
      })
    design <- c(
      if (isTRUE(artifact$intercept)) {
        list(rep(1, length(normalized_outcome)))
      } else {
        list()
      },
      normalized_predictors)
    statistics <- .dsvert_dp_capsule_quantized_gaussian_stats(
      design, normalized_outcome, artifact$numeric_grid_bits)
    if (length(statistics) != block$length) {
      stop("The signed Gaussian capsule coordinate shape is invalid.",
           call. = FALSE)
    }
    values[block$start:block$end] <- statistics
  }

  marginal_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") ==
      "categorical_marginals"]
  for (name in names(marginal_blocks)) {
    block <- marginal_blocks[[name]]
    artifact <- block$descriptor
    data <- snapshots[[block$dataset]]$data
    bounded <- .dsvert_dp_capsule_bounded_category(
      data, policy, artifact$column, artifact$levels,
      admission_for(block$dataset), strict = identical(
        artifact$missingness_policy,
        paste("missing_values_have_no_marginal_cell_and_unknown_or_conflicting",
              "nonmissing_values_reject_before_release_v1", sep = "_")))
    values[block$start:block$end] <- tabulate(
      bounded$cell, nbins = length(artifact$levels))
  }

  pair_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "categorical_pairs"]
  for (name in names(pair_blocks)) {
    block <- pair_blocks[[name]]
    descriptor <- block$descriptor
    if (identical(
          descriptor$version,
          "fixed-domain-categorical-cross-contingency-v1")) {
      # The public block is filled only by the authenticated exact-GC result
      # shares immediately before the one joint-DP opening.
      next
    }
    data <- snapshots[[block$dataset]]$data
    strict_pair <- identical(
      descriptor$missingness_policy,
      paste("missing_values_have_no_joint_cell_and_unknown_or_conflicting",
            "nonmissing_values_reject_before_release_v1", sep = "_"))
    if (isTRUE(strict_pair)) {
      admission <- admission_for(block$dataset)
      left <- .dsvert_dp_capsule_bounded_category(
        data, policy, descriptor$left$column, descriptor$left$levels,
        admission, strict = TRUE)
      right <- .dsvert_dp_capsule_bounded_category(
        data, policy, descriptor$right$column, descriptor$right$levels,
        admission, strict = TRUE)
      complete <- !is.na(left$cell) & !is.na(right$cell)
      cell <- rep(NA_integer_, admission$work_units)
      cell[complete] <- left$cell[complete] +
        (right$cell[complete] - 1L) * length(left$levels)
      bounded <- list(
        cell = cell,
        cell_count = .dsvert_dp_coordinate_count(left$levels, right$levels))
    } else {
      bounded <- .dsvert_dp_bounded_pairs(
        data, policy, descriptor$left$column, descriptor$right$column,
        admission_for(block$dataset))
    }
    values[block$start:block$end] <- tabulate(
      bounded$cell, nbins = bounded$cell_count)
  }

  survival_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "survival_artifacts"]
  for (name in names(survival_blocks)) {
    block <- survival_blocks[[name]]
    spec <- .dsvert_dp_capsule_survival_spec(
      block$descriptor, block$key)
    exact <- .dsvert_dp_survival_histogram(
      snapshots[[block$dataset]]$data, policy, spec,
      admission_for(block$dataset))$exact
    values[block$start:block$end] <- exact
  }

  values <- .dsvert_dp_integer_vector(
    values, "local biomedical capsule coordinates")
  .dsvert_dp_capsule_assert_signed_coordinate_bounds(values, contract)
  snapshot_binding <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-local-snapshots-v1",
    capsule_id = contract$identity$capsule_id,
    peer_name = local_peer,
    datasets = lapply(snapshots, function(snapshot) list(
      public = snapshot$dataset$public,
      protected_fingerprint = snapshot$dataset$fingerprint))))
  binding <- list(
    version = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION,
    purpose = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE,
    capsule_id = contract$identity$capsule_id,
    peer_name = local_peer,
    logical_snapshot = manifest$logical_snapshot,
    source_context_hash =
      manifest$workload$capsule_mechanism$source_context_hash,
    coordinate_count = layout$coordinate_count,
    coordinate_order_sha256 = layout$sha256,
    snapshot_binding_sha256 = snapshot_binding)
  value_commitment <- .dsvert_dp_capsule_value_commitment(values, binding)
  authenticatable <- .dsvert_joint_dp_hash(list(
    authentication_domain =
      "dsVert/biomedical-capsule/local-secret-share-input/v1|",
    binding = binding, value_commitment_sha256 = value_commitment))
  c(binding, list(
    state = "internal_unshared_secret_share_input_never_release",
    values = values,
    value_commitment_sha256 = value_commitment,
    authenticatable_sha256 = authenticatable))
}
