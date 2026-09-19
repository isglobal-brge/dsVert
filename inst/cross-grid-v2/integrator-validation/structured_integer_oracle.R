# Independent integer evaluation of PUBLIC SYNTHETIC fixtures only.
# No callbacks from this file are installed in any custodian or release API.
structured_integer_oracle <- function(server_dir, client_dir, spec, x, y, cluster, time, event) {
  pkgload::load_all(server_dir, quiet = TRUE)
  e <- new.env(parent = asNamespace("dsVert"))
  for (file in c("helper-cross-grid-integer.R", "helper-grouped-integer.R",
      "helper-grouped-lmm-stats-integer.R", "helper-grouped-gee-whitening-integer.R"))
    sys.source(file.path(server_dir, "tests/testthat", file), e)
  sys.source(file.path(client_dir, "tests/testthat/helper-cox-grid-integer.R"), e)
  encode50 <- function(v) sprintf("%.0f", round(v * 2^50))
  x50 <- matrix(encode50(x), nrow(x), ncol(x))
  beta50 <- lapply(spec$beta_grid, function(b) encode50(unlist(b)))
  eta <- function(b, cox) vapply(seq_len(nrow(x)), function(i) {
    features <- if (cox) x50[i, ] else c(encode50(1), x50[i, ])
    z <- e$.cross_int()
    for (k in seq_along(b)) z <- e$.cross_add(z,
      e$.cross_mul(e$.cross_parse(features[k]), e$.cross_parse(b[k])))
    e$.cross_format(e$.cross_round_shift(z, if (cox) 84 else 36))
  }, character(1L))
  if (spec$family == "cox") return(vapply(seq_along(beta50), function(j) {
    as.character(e$.cox_integer_loss(as.numeric(eta(beta50[[j]], TRUE)), time, event,
      rep(TRUE, nrow(x)), spec$sensitivity$maximum_coordinates[[j]], spec$numeric_grid_bits))
  }, character(1L)))
  # GH5 coefficient selection has the signed +2/live-row shift and no factorial.
  glmm_selection <- function(q64, outcomes, live, family, cap) {
    if (!any(live == 1)) return(0)
    nodes <- if (spec$parameters$random_intercept_variance == 0) rep(0, 5) else
      c(-93617, -44421, 0, 44421, 93617)
    terms <- c(-294042, -98614, -41196, -98614, -294042)
    q16 <- vapply(q64, function(v) e$.cross_double(
      e$.cross_round_shift(e$.cross_parse(v), 48)), numeric(1))
    for (q in seq_len(5)) for (i in which(live == 1)) {
      t <- q16[i] + nodes[q]
      terms[q] <- terms[q] - e$.grouped_profile(t,
        if (family == "poisson") "exp" else "softplus") + outcomes[i]*t -
        if (family == "poisson") 2*65536 else 0
    }
    maximum <- max(terms)
    exps <- vapply(terms-maximum, function(v) if (v < -16*65536) 0 else
      e$.grouped_profile(v, "exp_negative"), numeric(1))
    e$.grouped_q16_quantize(-maximum-e$.grouped_profile(sum(exps), "log"),
      cap, spec$numeric_grid_bits)
  }
  bits <- spec$numeric_grid_bits
  B <- spec$grouping$max_patients_per_cluster
  labels <- sort(unique(cluster), method = "radix")
  stopifnot(length(labels) <= spec$grouping$cluster_capacity)
  result <- lapply(seq_along(beta50), function(j) {
    q64 <- eta(beta50[[j]], FALSE)
    caps <- unlist(spec$sensitivity$candidate_bounds[[j]]$per_cluster_caps)
    shifts <- unlist(spec$sensitivity$candidate_bounds[[j]]$coordinate_shifts)
    total <- numeric(length(caps))
    for (c in seq_len(spec$grouping$cluster_capacity)) {
      idx <- if (c <= length(labels)) which(cluster == labels[c]) else integer()
      stopifnot(length(idx) <= B)
      live <- c(rep(1, length(idx)), rep(0, B-length(idx)))
      q <- c(q64[idx], rep("0", B-length(idx)))
      outcomes <- c(y[idx], rep(0, B-length(idx)))
      features <- rbind(x50[idx, , drop = FALSE], matrix("0", B-length(idx), ncol(x)))
      value <- if (spec$family == "lmm") {
        rows <- lapply(seq_len(B), function(i) c(if (live[i]) encode50(1) else "0",
          features[i, ], encode50(outcomes[i])))
        as.numeric(e$.grouped_lmm_stats_integer(rows, beta50[[j]],
          e$.cross_format(e$.cross_shift_left(e$.cross_small(spec$parameters$residual_variance*4), 62)),
          e$.cross_format(e$.cross_shift_left(e$.cross_small(spec$parameters$random_intercept_variance*4), 62)),
          caps[1], bits))
      } else if (grepl("_glmm$", spec$family)) {
        glmm_selection(q, outcomes, live, sub("_glmm$", "", spec$family), caps[1])
      } else {
        e$.grouped_gee_whitening_integer(q, features, outcomes, live,
          sub("_gee$", "", spec$family), spec$parameters$correlation,
          spec$parameters$rho, spec$parameters$score_clip*65536,
          caps[1], caps[2]-shifts[2], bits)
      }
      stopifnot(length(value) == length(caps), all(is.finite(value)),
        all(value >= 0), all(value <= caps), all(value == floor(value)))
      total <- total + value
    }
    sprintf("%.0f", total)
  })
  unlist(result, use.names = FALSE)
}
