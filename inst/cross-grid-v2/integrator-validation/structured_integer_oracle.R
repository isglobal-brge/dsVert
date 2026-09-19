# Independently enclose the PUBLIC variance/count log table using Python's
# exact rational arithmetic and 80 terms, separate from the native 32-term
# enclosure. Both ends must have the same q64 ceiling, proving the integer.
structured_lmm_log_tables <- function(parameters, slots) {
  input <- tempfile(fileext = ".json")
  on.exit(unlink(input), add = TRUE)
  writeLines(jsonlite::toJSON(list(grid = parameters$variance_grid, slots = slots),
    auto_unbox = TRUE, digits = NA), input)
  program <- paste(c(
    "import json, sys",
    "from fractions import Fraction as F",
    "data=json.load(open(sys.argv[1]))",
    "def series(z):",
    "    power=z; square=z*z; lower=F(0)",
    "    for j in range(80):",
    "        lower += 2*power/(2*j+1); power *= square",
    "    return lower, lower+2*power/(161*(1-square))",
    "def log_bounds(x):",
    "    k=0",
    "    while x >= 2: x/=2; k+=1",
    "    lo,hi=series((x-1)/(x+1)); a,b=series(F(1,3))",
    "    return lo+k*a,hi+k*b",
    "def ceil(x): return -(-x.numerator//x.denominator)",
    "tables=[]",
    "for pair in data['grid']:",
    "    sigma=F(str(pair['residual_variance'])); tau=F(str(pair['random_intercept_variance']))",
    "    a,b=log_bounds(4*sigma); values=['0']",
    "    for n in range(1,data['slots']+1):",
    "        lo,hi=log_bounds(4*(sigma+n*tau))",
    "        lower=ceil(((n-1)*a+lo)*(1<<64)); upper=ceil(((n-1)*b+hi)*(1<<64))",
    "        assert lower == upper, 'ambiguous q64 logarithm ceiling'",
    "        values.append(str(upper))",
    "    tables.append(values)",
    "print(json.dumps(tables))"), collapse = "\n")
  result <- processx::run("python3", c("-c", program, input))
  jsonlite::fromJSON(result$stdout, simplifyVector = FALSE)
}

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
  glmm_selection <- function(q64, outcomes, live, family, cap, variance) {
    if (!any(live == 1)) return(0)
    stopifnot(variance %in% c(0, .25))
    nodes <- if (variance == 0) rep(0, 5) else
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
  ml <- identical(spec$family, "lmm") && identical(spec$parameters$objective, "ml")
  glmm_grid <- grepl("_glmm$", spec$family) && !is.null(spec$parameters$variance_grid)
  candidates <- if (ml || glmm_grid) spec$candidate_grid else lapply(seq_along(beta50),
    function(j) list(beta_index = j))
  if (ml) {
    tables <- structured_lmm_log_tables(spec$parameters, B)
    covariance <- lapply(seq_along(spec$parameters$variance_grid), function(v) {
      pair <- spec$parameters$variance_grid[[v]]
      sigma <- e$.cross_shift_left(e$.cross_small(pair$residual_variance*2^16), 48)
      tau <- e$.cross_shift_left(e$.cross_small(pair$random_intercept_variance*2^16), 48)
      list(inverse = e$.grouped_div_even(e$.cross_pow2(128), sigma),
        lambda = lapply(0:B, function(count) e$.grouped_div_even(
          e$.cross_shift_left(tau, 128), e$.cross_mul(sigma,
            e$.cross_add(sigma, e$.cross_mul(tau, e$.cross_small(count)))))),
        logdet = lapply(tables[[v]], e$.cross_parse))
    })
  }
  result <- lapply(seq_along(candidates), function(j) {
    candidate <- candidates[[j]]
    beta <- beta50[[candidate$beta_index]]
    q64 <- eta(beta, FALSE)
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
        if (ml) {
          constants <- covariance[[candidate$variance_index]]
          total_residual <- squares <- e$.cross_int()
          for (row in rows) {
            if (identical(row[[1L]], "0")) next
            residual <- e$.cross_shift_left(e$.cross_parse(tail(row, 1L)), 50)
            for (k in seq_along(beta)) residual <- e$.cross_sub(residual,
              e$.cross_mul(e$.cross_parse(row[[k]]), e$.cross_parse(beta[[k]])))
            total_residual <- e$.cross_add(total_residual, residual)
            squares <- e$.cross_add(squares, e$.cross_mul(residual, residual))
          }
          count_index <- length(idx)+1L
          loss <- e$.cross_add(e$.cross_sub(e$.cross_mul(squares, constants$inverse),
            e$.cross_mul(e$.cross_mul(total_residual, total_residual),
              constants$lambda[[count_index]])),
            e$.cross_shift_left(constants$logdet[[count_index]], 200))
          if (loss$s < 0) loss <- e$.cross_int()
          upper <- e$.cross_shift_left(e$.cross_small(caps[1]), 264-bits)
          if (e$.cross_cmp_abs(loss, upper) > 0) loss <- upper
          as.numeric(e$.cross_format(e$.cross_round_shift(loss, 264-bits)))
        } else as.numeric(e$.grouped_lmm_stats_integer(rows, beta,
          e$.cross_format(e$.cross_shift_left(e$.cross_small(spec$parameters$residual_variance*4), 62)),
          e$.cross_format(e$.cross_shift_left(e$.cross_small(spec$parameters$random_intercept_variance*4), 62)),
          caps[1], bits))
      } else if (grepl("_glmm$", spec$family)) {
        variance <- if (glmm_grid) spec$parameters$variance_grid[[candidate$variance_index]] else
          spec$parameters$random_intercept_variance
        glmm_selection(q, outcomes, live, sub("_glmm$", "", spec$family), caps[1], variance)
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
