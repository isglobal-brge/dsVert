# Public deterministic B1 contract layer. No producer or DataSHIELD endpoint.
# All new identities use fresh domains; existing registries/artifacts are read
# through their established normalizers without altering their wire formats.
.DSVERT_DP_IRLS_VERSION <- "dp_irls_v1"
.DSVERT_DP_IRLS_CONTRACT_VERSION <- "dsvert-dp-irls-contract-v1"
.DSVERT_DP_IRLS_SIGNING_DOMAIN <- "dsVert/dp-irls/contract/v1|"
.DSVERT_DP_IRLS_UPDATE_VERSION <- "dp_irls_update_v1"

.dsvert_dp_irls_fail <- function(what = "contract") {
  stop("Invalid DP IRLS ", what, ".", call. = FALSE)
}
.dsvert_dp_irls_fields <- function(x, fields, what = "fields") {
  if (!is.list(x) || is.null(names(x)) || anyNA(names(x)) ||
      anyDuplicated(names(x)) || !setequal(names(x), fields))
    .dsvert_dp_irls_fail(what)
  invisible(x)
}
.dsvert_dp_irls_text <- function(x, what = "text") {
  if (!is.character(x) || length(x) != 1L || is.na(x) || !nzchar(x) ||
      nchar(x, type = "bytes") > 8192L || grepl("[\r\n\t]", x))
    .dsvert_dp_irls_fail(what)
  x
}
.dsvert_dp_irls_choice <- function(x, choices, what = "choice") {
  .dsvert_dp_irls_text(x, what)
  if (!x %in% choices) .dsvert_dp_irls_fail(what)
  x
}
.dsvert_dp_irls_int <- function(x, lower = NULL, upper = NULL) {
  if (!is.character(x) || length(x) != 1L || is.na(x) ||
      nchar(x) > 1500L || !grepl("^(0|-?[1-9][0-9]*)$", x))
    .dsvert_dp_irls_fail("integer string")
  z <- gmp::as.bigz(x)
  if ((!is.null(lower) && z < gmp::as.bigz(lower)) ||
      (!is.null(upper) && z > gmp::as.bigz(upper)))
    .dsvert_dp_irls_fail("integer range")
  x
}
.dsvert_dp_irls_q <- function(x, lower = NULL, upper = NULL) {
  .dsvert_dp_irls_fields(x, c("n", "d"), "rational")
  n <- .dsvert_dp_irls_int(x$n); d <- .dsvert_dp_irls_int(x$d, "1")
  q <- gmp::as.bigq(n, d)
  if ((!is.null(lower) && q < lower) || (!is.null(upper) && q > upper))
    .dsvert_dp_irls_fail("rational range")
  list(n = as.character(gmp::numerator(q)),
       d = as.character(gmp::denominator(q)))
}
.dsvert_dp_irls_bigq <- function(x) gmp::as.bigq(x$n, x$d)
.dsvert_dp_irls_rational <- function(x) list(
  n = as.character(gmp::numerator(x)), d = as.character(gmp::denominator(x)))
.dsvert_dp_irls_array <- function(x, size = NULL, minimum = 0L) {
  if (is.character(x) && is.null(names(x))) x <- as.list(x)
  if (!is.list(x) || !is.null(names(x)) || length(x) < minimum ||
      (!is.null(size) && length(x) != size)) .dsvert_dp_irls_fail("array")
  x
}
.dsvert_dp_irls_texts <- function(x, minimum = 0L, unique = TRUE) {
  x <- lapply(.dsvert_dp_irls_array(x, minimum = minimum), .dsvert_dp_irls_text)
  if (unique && anyDuplicated(unlist(x))) .dsvert_dp_irls_fail("duplicate text")
  x
}
.dsvert_dp_irls_no_float <- function(x) {
  if (is.list(x)) {
    if (is.object(x)) .dsvert_dp_irls_fail("attributed contract")
    lapply(x, .dsvert_dp_irls_no_float)
  } else if (!is.character(x) || anyNA(x) || !is.null(attributes(x))) {
    .dsvert_dp_irls_fail("non-string contract leaf")
  }
  invisible(NULL)
}
.dsvert_dp_irls_json <- function(x) .dsvert_dp_canonical_json(
  .dsvert_dp_analysis_canonical_value_v1(x))
.dsvert_dp_irls_hash <- function(domain, value) digest::digest(
  charToRaw(paste0(domain, "|", .dsvert_dp_irls_json(value))),
  algo = "sha256", serialize = FALSE)
.dsvert_dp_irls_hex <- function(x) .dsvert_dp_synopsis_hex_v1(x, "IRLS digest")
.dsvert_dp_irls_interval <- function(x) {
  .dsvert_dp_irls_fields(x, c("lower", "upper"))
  x$lower <- .dsvert_dp_irls_q(x$lower); x$upper <- .dsvert_dp_irls_q(x$upper)
  if (.dsvert_dp_irls_bigq(x$lower) > .dsvert_dp_irls_bigq(x$upper))
    .dsvert_dp_irls_fail("reversed interval")
  x
}
.dsvert_dp_irls_flag <- function(x) .dsvert_dp_irls_choice(x, c("0", "1"))
.dsvert_dp_irls_qarray <- function(x, size, lower = NULL, upper = NULL) {
  lapply(.dsvert_dp_irls_array(x, size), .dsvert_dp_irls_q,
         lower = lower, upper = upper)
}

.dsvert_dp_irls_contract_normalize <- function(value) {
  if (!requireNamespace("gmp", quietly = TRUE))
    stop("DP IRLS requires gmp for exact arithmetic.", call. = FALSE)
  .dsvert_dp_irls_no_float(value)
  .dsvert_dp_irls_fields(value, c("mechanism", "profile_id", "estimand",
    "privacy_source", "numeric", "path", "accounting", "inference", "operations"))
  .dsvert_dp_irls_choice(value$mechanism, .DSVERT_DP_IRLS_VERSION)
  .dsvert_dp_analysis_scalar_id(value$profile_id, "IRLS profile")
  e <- value$estimand
  .dsvert_dp_irls_fields(e, c("formula", "coefficient_order", "family", "link",
    "levels", "contrasts", "columns", "offset", "intercept", "clamped_target",
    "model_assumptions"))
  .dsvert_dp_irls_text(e$formula)
  e$coefficient_order <- .dsvert_dp_irls_texts(e$coefficient_order, 1L)
  p <- length(e$coefficient_order); nh <- p * (p + 1L) / 2L
  if (p > 128L) .dsvert_dp_irls_fail("coefficient capacity")
  .dsvert_dp_irls_choice(e$family, c("binomial", "poisson"))
  .dsvert_dp_irls_choice(e$link, if (e$family == "binomial") "logit" else "log")
  e$levels <- lapply(.dsvert_dp_irls_array(e$levels), function(z) {
    .dsvert_dp_irls_fields(z, c("column_id", "values")); .dsvert_dp_irls_text(z$column_id)
    z$values <- .dsvert_dp_irls_texts(z$values, 1L); z
  })
  e$contrasts <- lapply(.dsvert_dp_irls_array(e$contrasts), function(z) {
    .dsvert_dp_irls_fields(z, c("column_id", "coding", "coefficient_names"))
    .dsvert_dp_irls_text(z$column_id); .dsvert_dp_irls_text(z$coding)
    z$coefficient_names <- .dsvert_dp_irls_texts(z$coefficient_names, 1L)
    if (!all(unlist(z$coefficient_names) %in% unlist(e$coefficient_order)))
      .dsvert_dp_irls_fail("contrast order")
    z
  })
  e$columns <- lapply(.dsvert_dp_irls_array(e$columns, minimum = 1L), function(z) {
    .dsvert_dp_irls_fields(z, c("column_id", "owner", "source_id", "role"))
    lapply(z, .dsvert_dp_irls_text)
    .dsvert_dp_irls_choice(z$role, c("predictor", "outcome", "offset", "exposure")); z
  })
  column_ids <- vapply(e$columns, `[[`, character(1L), "column_id")
  if (anyDuplicated(column_ids) ||
      sum(vapply(e$columns, function(z) z$role == "outcome", logical(1L))) != 1L)
    .dsvert_dp_irls_fail("column declarations")
  for (entries in list(e$levels, e$contrasts)) {
    ids <- vapply(entries, `[[`, character(1L), "column_id")
    if (anyDuplicated(ids) || !all(ids %in% column_ids))
      .dsvert_dp_irls_fail("level/contrast columns")
  }
  .dsvert_dp_irls_fields(e$offset, c("kind", "column_id", "zero_exposure"))
  .dsvert_dp_irls_choice(e$offset$kind, c("none", "offset", "log-exposure"))
  if (e$offset$kind == "none") {
    if (e$offset$column_id != "none" || e$offset$zero_exposure != "not-applicable")
      .dsvert_dp_irls_fail("absent offset")
  } else {
    if (!e$offset$column_id %in% column_ids) .dsvert_dp_irls_fail("offset column")
    .dsvert_dp_irls_choice(e$offset$zero_exposure,
      if (e$offset$kind == "log-exposure") "masked-zero-contribution" else "not-applicable")
  }
  .dsvert_dp_irls_flag(e$intercept)
  if ((e$intercept == "1") != (e$coefficient_order[[1L]] == "(Intercept)"))
    .dsvert_dp_irls_fail("intercept order")
  .dsvert_dp_irls_text(e$clamped_target)
  e$model_assumptions <- .dsvert_dp_irls_texts(e$model_assumptions, 1L)
  value$estimand <- e

  s <- value$privacy_source
  .dsvert_dp_irls_fields(s, c("adjacency", "capacity", "row_cap", "closure",
    "source_ids", "alignment_purpose", "missing_rule", "duplicate_rule",
    "ordering_rule", "x_bounds", "y_bounds", "offset_bounds", "person_caps",
    "peer_pins", "pinset_sha256", "computation_peers", "schema_sha256"))
  .dsvert_dp_irls_choice(s$adjacency, c("add-remove-person", "replace-one-person"))
  .dsvert_dp_irls_int(s$capacity, "1"); .dsvert_dp_irls_int(s$row_cap, "1")
  pins <- .dsvert_dp_synopsis_peer_pins_v1(unlist(s$peer_pins))
  s$peer_pins <- as.list(pins)
  if (!identical(s$pinset_sha256, .dsvert_dp_synopsis_pinset_hash_v1(pins)))
    .dsvert_dp_irls_fail("pinset digest")
  s$computation_peers <- .dsvert_dp_irls_texts(s$computation_peers, 2L)
  if (length(s$computation_peers) != 2L ||
      !all(unlist(s$computation_peers) %in% names(pins)))
    .dsvert_dp_irls_fail("designated pair")
  s$closure <- .dsvert_dp_synopsis_closure_validate_v2(s$closure)
  dependencies <- s$closure$dependencies
  if (!length(dependencies)) .dsvert_dp_irls_fail("empty epoch closure")
  s$source_ids <- .dsvert_dp_irls_texts(s$source_ids, 1L)
  if (length(s$source_ids) != length(dependencies))
    .dsvert_dp_irls_fail("complete source vector")
  for (dep in dependencies) {
    epoch_pins <- vapply(dep$dependency$authorization_epochs, `[[`, character(1L), "peer_identity")
    if (!dep$source_identity %in% pins || !all(epoch_pins %in% pins) ||
        (dep$dependency$provenance_kind == "padded_psi" && !setequal(epoch_pins, unname(pins))) ||
        (dep$dependency$provenance_kind == "frozen_materialized_root" &&
         !identical(epoch_pins, dep$source_identity))) .dsvert_dp_irls_fail("epoch pin")
  }
  for (column in e$columns) {
    j <- match(column$source_id, unlist(s$source_ids))
    if (!column$owner %in% names(pins) || is.na(j) ||
        !identical(unname(pins[[column$owner]]), dependencies[[j]]$source_identity))
      .dsvert_dp_irls_fail("source owner")
  }
  for (nm in c("alignment_purpose", "missing_rule", "duplicate_rule", "ordering_rule"))
    .dsvert_dp_irls_text(s[[nm]])
  s$x_bounds <- lapply(.dsvert_dp_irls_array(s$x_bounds, p), .dsvert_dp_irls_interval)
  s$y_bounds <- .dsvert_dp_irls_interval(s$y_bounds)
  s$offset_bounds <- .dsvert_dp_irls_interval(s$offset_bounds)
  if (e$offset$kind == "none" && any(vapply(s$offset_bounds,
      function(q) .dsvert_dp_irls_bigq(q) != 0, logical(1L))))
    .dsvert_dp_irls_fail("absent offset bounds")
  if (e$family == "binomial" && (.dsvert_dp_irls_bigq(s$y_bounds$lower) != 0 ||
      .dsvert_dp_irls_bigq(s$y_bounds$upper) != 1)) .dsvert_dp_irls_fail("Bernoulli bounds")
  if (.dsvert_dp_irls_bigq(s$y_bounds$lower) < 0) .dsvert_dp_irls_fail("outcome bounds")
  .dsvert_dp_irls_fields(s$person_caps, c("score_abs", "curvature_abs"))
  s$person_caps$score_abs <- .dsvert_dp_irls_qarray(s$person_caps$score_abs, p, 0)
  s$person_caps$curvature_abs <- .dsvert_dp_irls_qarray(s$person_caps$curvature_abs, nh, 0)
  .dsvert_dp_irls_hex(s$schema_sha256)
  value$privacy_source <- s

  n <- value$numeric
  .dsvert_dp_irls_fields(n, c("eta_bounds", "score_definition", "curvature_definition",
    "curvature_role", "approximation_certificate_sha256", "lattice", "rounding",
    "rounding_slack", "ring_bits", "source_intermediate_bits", "layout",
    "translation", "person_integer_caps", "translation_margin", "upper_limits",
    "compiler_version", "backend_version", "sampler_version", "certificate",
    "certificate_sha256"))
  n$eta_bounds <- .dsvert_dp_irls_interval(n$eta_bounds)
  for (nm in c("score_definition", "curvature_definition", "compiler_version", "backend_version"))
    .dsvert_dp_irls_text(n[[nm]])
  .dsvert_dp_irls_choice(n$curvature_role, c("derivative", "preconditioner"))
  .dsvert_dp_irls_hex(n$approximation_certificate_sha256)
  .dsvert_dp_irls_fields(n$lattice, c("g", "H", "beta"))
  n$lattice <- lapply(n$lattice, .dsvert_dp_irls_q, lower = 0)
  if (any(vapply(n$lattice, function(q) .dsvert_dp_irls_bigq(q) == 0, logical(1L))))
    .dsvert_dp_irls_fail("zero lattice")
  .dsvert_dp_irls_choice(n$rounding, "nearest-even-per-person-v1")
  .dsvert_dp_irls_fields(n$rounding_slack, c("g", "H"))
  n$rounding_slack <- lapply(n$rounding_slack, .dsvert_dp_irls_q, lower = 0)
  if (.dsvert_dp_irls_bigq(n$rounding_slack$g) < p * .dsvert_dp_irls_bigq(n$lattice$g) / 2 ||
      .dsvert_dp_irls_bigq(n$rounding_slack$H) < nh * .dsvert_dp_irls_bigq(n$lattice$H) / 2)
    .dsvert_dp_irls_fail("rounding slack")
  .dsvert_dp_irls_choice(n$ring_bits, "128")
  .dsvert_dp_irls_int(n$source_intermediate_bits, "1", "4096")
  expected_layout <- c(paste0("g:", seq_len(p)), unlist(lapply(seq_len(p),
    function(i) paste0("H:", i, ":", i:p))))
  n$layout <- .dsvert_dp_irls_texts(n$layout)
  if (!identical(unlist(n$layout), expected_layout)) .dsvert_dp_irls_fail("statistic layout")
  for (group in c("translation", "person_integer_caps", "translation_margin", "upper_limits")) {
    .dsvert_dp_irls_fields(n[[group]], c("g", "H"))
    for (lane in c("g", "H")) n[[group]][[lane]] <- lapply(
      .dsvert_dp_irls_array(n[[group]][[lane]], if (lane == "g") p else nh),
      .dsvert_dp_irls_int, lower = if (group == "translation") "1" else "0")
  }
  for (lane in c("g", "H")) for (i in seq_along(n$translation[[lane]])) {
    a <- gmp::as.bigz(n$translation[[lane]][[i]])
    cap <- gmp::as.bigz(n$person_integer_caps[[lane]][[i]])
    margin <- gmp::as.bigz(n$translation_margin[[lane]][[i]])
    upper <- gmp::as.bigz(n$upper_limits[[lane]][[i]])
    if (a < gmp::as.bigz(s$capacity) * cap + margin || upper != 2 * a ||
        upper >= gmp::as.bigz(2)^127) .dsvert_dp_irls_fail("translation bounds")
    physical <- if (lane == "g") s$person_caps$score_abs[[i]] else s$person_caps$curvature_abs[[i]]
    if (gmp::as.bigq(cap) * .dsvert_dp_irls_bigq(n$lattice[[lane]]) <
        .dsvert_dp_irls_bigq(physical)) .dsvert_dp_irls_fail("integer person cap")
  }
  .dsvert_dp_irls_choice(n$sampler_version, "independent_full_global_draw_convolution_ring128_v4")
  .dsvert_dp_irls_fields(n$certificate, c("common_denominator", "input_bits", "k_max", "temporary_bits"))
  for (nm in names(n$certificate)) .dsvert_dp_irls_int(n$certificate[[nm]], "1")
  .dsvert_dp_irls_int(n$certificate$input_bits, "1", "4096")
  .dsvert_dp_irls_int(n$certificate$temporary_bits, "1", "5000000")
  if (!identical(n$certificate_sha256,
      .dsvert_dp_irls_hash("dsvert-v3-irls-numeric-certificate-v1", n$certificate)))
    .dsvert_dp_irls_fail("numeric certificate digest")
  value$numeric <- n

  a <- value$path
  .dsvert_dp_irls_fields(a, c("T", "start", "box", "floor", "floor_quantum", "ridge",
    "damping", "trust", "refresh_mask", "terminal_audit", "update_version", "tie_rule",
    "root_domain", "stage_domain", "lane_domain", "role_domain", "pin_domain"))
  .dsvert_dp_irls_int(a$T, "1", "10000"); T <- as.integer(a$T)
  .dsvert_dp_irls_fields(a$start, c("kind", "digest", "beta", "epsilon", "composition_sha256"))
  .dsvert_dp_irls_choice(a$start$kind, c("zero", "pilot"))
  .dsvert_dp_irls_hex(a$start$digest); .dsvert_dp_irls_hex(a$start$composition_sha256)
  a$start$beta <- .dsvert_dp_irls_qarray(a$start$beta, p)
  a$start$epsilon <- .dsvert_dp_irls_q(a$start$epsilon, 0)
  if (a$start$kind == "zero" && (any(vapply(a$start$beta,
      function(q) .dsvert_dp_irls_bigq(q) != 0, logical(1L))) ||
      .dsvert_dp_irls_bigq(a$start$epsilon) != 0 ||
      a$start$digest != paste(rep("0", 64L), collapse = "") ||
      a$start$composition_sha256 != paste(rep("0", 64L), collapse = "")))
    .dsvert_dp_irls_fail("zero start")
  if (a$start$kind == "pilot" && .dsvert_dp_irls_bigq(a$start$epsilon) <= 0)
    .dsvert_dp_irls_fail("unbudgeted pilot")
  .dsvert_dp_irls_fields(a$box, c("lower", "upper"))
  a$box <- lapply(a$box, .dsvert_dp_irls_qarray, size = p)
  for (i in seq_len(p)) {
    lo <- .dsvert_dp_irls_bigq(a$box$lower[[i]]); hi <- .dsvert_dp_irls_bigq(a$box$upper[[i]])
    b <- .dsvert_dp_irls_bigq(a$start$beta[[i]])
    quantum <- .dsvert_dp_irls_bigq(n$lattice$beta)
    if (lo > hi || b < lo || b > hi || any(vapply(list(lo, hi, b),
        function(q) gmp::denominator(q / quantum) != 1, logical(1L))))
      .dsvert_dp_irls_fail("coefficient box/lattice")
  }
  for (nm in c("floor", "floor_quantum", "ridge")) a[[nm]] <- .dsvert_dp_irls_q(a[[nm]], 0)
  if (.dsvert_dp_irls_bigq(a$floor) == 0 || .dsvert_dp_irls_bigq(a$floor_quantum) == 0)
    .dsvert_dp_irls_fail("positive floor")
  a$damping <- .dsvert_dp_irls_qarray(a$damping, T, 0, 1)
  if (any(vapply(a$damping, function(q) .dsvert_dp_irls_bigq(q) == 0, logical(1L))))
    .dsvert_dp_irls_fail("positive damping")
  a$trust <- .dsvert_dp_irls_qarray(a$trust, T, 0)
  a$refresh_mask <- lapply(.dsvert_dp_irls_array(a$refresh_mask, T), .dsvert_dp_irls_flag)
  if (a$refresh_mask[[1L]] != "1") .dsvert_dp_irls_fail("initial curvature")
  .dsvert_dp_irls_flag(a$terminal_audit)
  .dsvert_dp_irls_choice(a$update_version, .DSVERT_DP_IRLS_UPDATE_VERSION)
  .dsvert_dp_irls_choice(a$tie_rule, "nearest-even-v1")
  domains <- c(root_domain = "dsvert-v3-irls-root-v1", stage_domain = "dsvert-v3-irls-stage-v1",
    lane_domain = "dsvert-v3-irls-lane-v1", role_domain = "dsvert-v3-irls-role-v1",
    pin_domain = "dsvert-v3-irls-pins-v1")
  for (nm in names(domains)) .dsvert_dp_irls_choice(a[[nm]], domains[[nm]])
  value$path <- a
  .dsvert_dp_irls_certificate_check(value)

  b <- value$accounting
  .dsvert_dp_irls_fields(b, c("geometry", "stages", "sensitivity", "pilot_epsilon",
    "auxiliary", "epsilon_path", "delta", "rho", "noise_law", "draws_per_authority",
    "authority_count", "failure_semantics"))
  .dsvert_dp_irls_choice(b$geometry, "split-block-v1")
  .dsvert_dp_irls_fields(b$sensitivity, c("g", "H"))
  b$sensitivity <- lapply(b$sensitivity, .dsvert_dp_irls_int, lower = "1")
  adjacency <- if (s$adjacency == "replace-one-person") 2L else 1L
  for (lane in c("g", "H")) {
    capsum <- Reduce(`+`, lapply(n$person_integer_caps[[lane]], gmp::as.bigz), gmp::as.bigz(0))
    if (gmp::as.bigz(b$sensitivity[[lane]]) < adjacency * capsum)
      .dsvert_dp_irls_fail("insufficient lane sensitivity")
  }
  nstage <- T + as.integer(a$terminal_audit)
  b$stages <- lapply(.dsvert_dp_irls_array(b$stages, nstage), function(z) {
    .dsvert_dp_irls_fields(z, c("t", "purpose", "g", "H", "epsilon", "alpha_g", "alpha_H"))
    .dsvert_dp_irls_int(z$t, "0")
    for (nm in c("g", "H", "epsilon", "alpha_g", "alpha_H")) z[[nm]] <- .dsvert_dp_irls_q(z[[nm]], 0)
    z
  })
  for (i in seq_len(nstage)) {
    z <- b$stages[[i]]; audit <- i > T
    if (z$t != as.character(i - 1L) || z$purpose != if (audit) "terminal-audit" else "optimizer")
      .dsvert_dp_irls_fail("accounting stage order")
    refresh <- audit || a$refresh_mask[[i]] == "1"
    if (.dsvert_dp_irls_bigq(z$g) <= 0 ||
        ((.dsvert_dp_irls_bigq(z$H) > 0) != refresh) ||
        .dsvert_dp_irls_bigq(z$epsilon) != .dsvert_dp_irls_bigq(z$g) + .dsvert_dp_irls_bigq(z$H))
      .dsvert_dp_irls_fail("stage allocation")
    for (lane in c("g", "H")) if (.dsvert_dp_irls_bigq(z[[paste0("alpha_", lane)]]) !=
        .dsvert_dp_irls_bigq(z[[lane]]) / gmp::as.bigz(b$sensitivity[[lane]]))
      .dsvert_dp_irls_fail("lane alpha")
  }
  for (nm in c("pilot_epsilon", "epsilon_path", "delta", "rho")) b[[nm]] <- .dsvert_dp_irls_q(b[[nm]], 0)
  if (.dsvert_dp_irls_bigq(b$pilot_epsilon) != .dsvert_dp_irls_bigq(a$start$epsilon) ||
      .dsvert_dp_irls_bigq(b$delta) != 0 || .dsvert_dp_irls_bigq(b$rho) != 0)
    .dsvert_dp_irls_fail("pilot/pure Laplace accounting")
  b$auxiliary <- lapply(.dsvert_dp_irls_array(b$auxiliary), function(z) {
    .dsvert_dp_irls_fields(z, c("id", "epsilon")); .dsvert_dp_irls_text(z$id)
    z$epsilon <- .dsvert_dp_irls_q(z$epsilon, 0)
    if (.dsvert_dp_irls_bigq(z$epsilon) <= 0) .dsvert_dp_irls_fail("auxiliary allocation")
    z
  })
  if (anyDuplicated(vapply(b$auxiliary, `[[`, character(1L), "id"))) .dsvert_dp_irls_fail("auxiliary IDs")
  total <- .dsvert_dp_irls_bigq(b$pilot_epsilon) + Reduce(`+`, lapply(
    c(b$stages, b$auxiliary), function(z) .dsvert_dp_irls_bigq(z$epsilon)), gmp::as.bigq(0))
  if (total != .dsvert_dp_irls_bigq(b$epsilon_path)) .dsvert_dp_irls_fail("path allocation sum")
  .dsvert_dp_irls_choice(b$noise_law, "two-independent-full-coordinate-discrete-laplace-draws-v4")
  .dsvert_dp_irls_choice(b$draws_per_authority, "1")
  .dsvert_dp_irls_choice(b$authority_count, "2")
  .dsvert_dp_irls_choice(b$failure_semantics, "reserve-full-path-charge-observed-lanes-no-refund-no-redraw-v1")
  value$accounting <- b

  f <- value$inference
  .dsvert_dp_irls_fields(f, c("mode", "method", "qualification_certificate_sha256", "replay",
    "confidence", "refusal", "thresholds", "tolerances", "allowed_contrasts"))
  .dsvert_dp_irls_choice(f$mode, c("estimate-only", "candidate", "qualified"))
  .dsvert_dp_irls_choice(f$method, if (f$mode == "estimate-only") "none" else "whole-path-replay-plus-terminal-inverse-v1")
  .dsvert_dp_irls_hex(f$qualification_certificate_sha256)
  if (f$mode == "qualified" && f$qualification_certificate_sha256 == paste(rep("0", 64L), collapse = ""))
    .dsvert_dp_irls_fail("missing qualification")
  if (f$mode != "estimate-only" && a$terminal_audit != "1") .dsvert_dp_irls_fail("inference audit")
  .dsvert_dp_irls_fields(f$replay, c("law", "version", "seed", "replicates"))
  .dsvert_dp_irls_choice(f$replay$law, b$noise_law)
  .dsvert_dp_irls_text(f$replay$version); .dsvert_dp_irls_hex(f$replay$seed)
  .dsvert_dp_irls_int(f$replay$replicates, if (f$mode == "estimate-only") "0" else "2")
  f$confidence <- .dsvert_dp_irls_q(f$confidence, 0, 1)
  if (.dsvert_dp_irls_bigq(f$confidence) %in% c(0, 1)) .dsvert_dp_irls_fail("confidence")
  .dsvert_dp_irls_fields(f$refusal, c("any_shift", "any_trust", "any_projection", "any_saturation",
    "ridge", "positive_information", "domain_margin", "terminal_audit"))
  lapply(f$refusal, .dsvert_dp_irls_choice, choices = "1")
  .dsvert_dp_irls_fields(f$thresholds, c("diagnostic_tail", "curvature_error_ratio", "condition_max",
    "bias_sd_ratio", "replay_precision"))
  f$thresholds <- lapply(f$thresholds, .dsvert_dp_irls_q, lower = 0)
  if (any(vapply(f$thresholds, function(q) .dsvert_dp_irls_bigq(q) <= 0, logical(1L))) ||
      .dsvert_dp_irls_bigq(f$thresholds$diagnostic_tail) >= 1)
    .dsvert_dp_irls_fail("refusal thresholds")
  .dsvert_dp_irls_fields(f$tolerances, c("approximation", "bias", "noise_tail"))
  f$tolerances <- lapply(f$tolerances, .dsvert_dp_irls_q, lower = 0)
  if (.dsvert_dp_irls_bigq(f$tolerances$noise_tail) >= 1) .dsvert_dp_irls_fail("noise tail tolerance")
  f$allowed_contrasts <- lapply(.dsvert_dp_irls_array(f$allowed_contrasts), .dsvert_dp_irls_qarray, size = p)
  value$inference <- f

  o <- value$operations
  .dsvert_dp_irls_fields(o, c("shape", "max_compile_bytes", "max_memory_bytes", "max_stage_seconds",
    "max_path_seconds", "recovery_version", "retention_policy", "resource_failure"))
  .dsvert_dp_irls_fields(o$shape, c("p", "coordinates", "capacity", "row_cap"))
  expected <- list(p = as.character(p), coordinates = as.character(p + nh), capacity = s$capacity, row_cap = s$row_cap)
  if (!identical(.dsvert_dp_irls_json(o$shape), .dsvert_dp_irls_json(expected))) .dsvert_dp_irls_fail("admission shape")
  for (nm in c("max_compile_bytes", "max_memory_bytes", "max_stage_seconds", "max_path_seconds"))
    .dsvert_dp_irls_int(o[[nm]], "1")
  if (gmp::as.bigz(o$max_path_seconds) < gmp::as.bigz(o$max_stage_seconds))
    .dsvert_dp_irls_fail("time admission")
  .dsvert_dp_irls_choice(o$recovery_version, "durable-single-successor-v1")
  .dsvert_dp_irls_choice(o$retention_policy, "retain-committed-bytes-signatures-and-reservations-v1")
  .dsvert_dp_irls_choice(o$resource_failure, "fail-closed-no-new-root-no-redraw-v1")
  value$operations <- o
  .dsvert_dp_analysis_canonical_value_v1(value)
}

# Derive the certificate entirely with integers/rationals. This checks admission
# without running the authoritative update engine or accepting a caller's proof.
.dsvert_dp_irls_certificate_check <- function(spec) {
  q <- .dsvert_dp_irls_bigq
  ceilq <- function(x) (gmp::numerator(x) + gmp::denominator(x) - 1) %/% gmp::denominator(x)
  bits <- function(x) {
    x <- abs(gmp::as.bigz(x)); if (x == 0) 0L else nchar(as.character(x, b = 2L))
  }
  n <- spec$numeric; a <- spec$path
  p <- length(a$box$lower); D <- gmp::as.bigz(1)
  ds <- lapply(list(q(n$lattice$H), q(a$floor_quantum), q(a$ridge),
    q(a$floor), q(n$lattice$g), q(a$ridge) * q(n$lattice$beta)), gmp::denominator)
  for (d in ds) D <- (D %/% gmp::gcd.bigz(D, d)) * d
  if (as.character(D) != n$certificate$common_denominator)
    .dsvert_dp_irls_fail("certificate common denominator")
  rh <- replicate(p, gmp::as.bigq(0), simplify = FALSE)
  hmax <- gmp::as.bigq(0); cursor <- 1L
  for (i in seq_len(p)) for (j in i:p) {
    v <- gmp::as.bigq(n$translation$H[[cursor]]) * q(n$lattice$H)
    rh[[i]] <- rh[[i]] + v; if (j != i) rh[[j]] <- rh[[j]] + v
    hmax <- max(hmax, v); cursor <- cursor + 1L
  }
  k <- ceilq((q(a$floor) + Reduce(max, rh)) / q(a$floor_quantum))
  if (as.character(k) != n$certificate$k_max) .dsvert_dp_irls_fail("certificate k_max")
  bmax <- Reduce(max, lapply(c(a$box$lower, a$box$upper), function(z) abs(q(z))))
  gmax <- Reduce(max, lapply(n$translation$g, function(z) gmp::as.bigq(z) * q(n$lattice$g)))
  bound <- max(hmax + k * q(a$floor_quantum) + q(a$ridge) + q(a$floor),
               gmax + q(a$ridge) * bmax)
  static <- c(a$box$lower, a$box$upper, a$damping, a$trust,
              list(a$floor, a$floor_quantum, a$ridge, n$lattice$g, n$lattice$H, n$lattice$beta))
  wmin <- max(vapply(static, function(z) max(bits(z$n), bits(z$d)), integer(1L)),
    vapply(c(n$translation$g, n$translation$H), function(z) bits(2 * gmp::as.bigz(z)), integer(1L)),
    bits(D), bits(ceilq(D * bound)), bits(ceilq(bmax * gmp::as.bigz(n$lattice$beta$d))))
  w <- as.integer(n$certificate$input_bits)
  if (w < wmin) .dsvert_dp_irls_fail("certificate input bits")
  m <- 0L; pp <- gmp::as.bigz(p)^p
  while (gmp::as.bigz(2)^(2L * m) < pp) m <- m + 1L
  L <- p * w + m + 2L
  if (n$certificate$temporary_bits != as.character(8L * L + 16L * w + 64L))
    .dsvert_dp_irls_fail("certificate temporary bits")
  invisible(TRUE)
}

.dsvert_dp_irls_contract_message <- function(unsigned) {
  .dsvert_dp_irls_fields(unsigned, c("version", "contract"))
  .dsvert_dp_irls_choice(unsigned$version, .DSVERT_DP_IRLS_CONTRACT_VERSION)
  unsigned$contract <- .dsvert_dp_irls_contract_normalize(unsigned$contract)
  charToRaw(paste0(.DSVERT_DP_IRLS_SIGNING_DOMAIN, .dsvert_dp_irls_json(unsigned)))
}
.dsvert_dp_irls_contract_validate <- function(value, trusted_pins,
    .verifier = .dsvert_relay_verify_message) {
  .dsvert_dp_irls_fields(value, c("version", "contract", "signatures"))
  .dsvert_dp_irls_choice(value$version, .DSVERT_DP_IRLS_CONTRACT_VERSION)
  spec <- .dsvert_dp_irls_contract_normalize(value$contract)
  # Signing normalized bytes is useful for custodians; accepting a different
  # spelling inside an already signed envelope is not.
  if (!identical(.dsvert_dp_irls_json(value$contract), .dsvert_dp_irls_json(spec)))
    .dsvert_dp_irls_fail("noncanonical signed contract")
  pins <- .dsvert_dp_synopsis_peer_pins_v1(unlist(trusted_pins))
  if (!identical(as.list(pins), spec$privacy_source$peer_pins))
    .dsvert_dp_irls_fail("external pins")
  .dsvert_dp_irls_fields(value$signatures, names(pins), "unanimous signatures")
  message <- .dsvert_dp_irls_contract_message(value[c("version", "contract")])
  for (peer in names(pins)) {
    signature <- .dsvert_dp_synopsis_signature_v1(value$signatures[[peer]])
    if (!isTRUE(.verifier(message, unname(pins[[peer]]), signature)))
      .dsvert_dp_irls_fail("contract signature")
  }
  spec
}
.dsvert_dp_irls_root <- function(contract) {
  contract <- .dsvert_dp_irls_contract_normalize(contract)
  .dsvert_dp_irls_hash(contract$path$root_domain, contract)
}
.dsvert_dp_irls_start_digest <- function(contract) {
  .dsvert_dp_irls_hash("dsvert-v3-irls-start-v1", list(
    root = .dsvert_dp_irls_root(contract), start = contract$path$start))
}
.dsvert_dp_irls_stage <- function(contract, t, purpose = NULL) {
  .dsvert_dp_irls_int(t, "0")
  T <- as.integer(contract$path$T)
  if (gmp::as.bigz(t) > T || (t == as.character(T) && contract$path$terminal_audit != "1"))
    .dsvert_dp_irls_fail("stage number")
  expected <- if (t == as.character(T)) "terminal-audit" else "optimizer"
  if (!is.null(purpose) && !identical(purpose, expected)) .dsvert_dp_irls_fail("stage purpose")
  list(t = t, purpose = expected, refresh = expected == "terminal-audit" ||
    contract$path$refresh_mask[[as.integer(t) + 1L]] == "1")
}
.dsvert_dp_irls_stage_id <- function(contract, t, predecessor, purpose = NULL) {
  contract <- .dsvert_dp_irls_contract_normalize(contract)
  stage <- .dsvert_dp_irls_stage(contract, t, purpose)
  .dsvert_dp_irls_hex(predecessor)
  if (t == "0" && !identical(predecessor, .dsvert_dp_irls_start_digest(contract)))
    .dsvert_dp_irls_fail("initial predecessor")
  .dsvert_dp_irls_hash(contract$path$stage_domain, list(
    root = .dsvert_dp_irls_root(contract), purpose = stage$purpose, t = t,
    predecessor_public_payload_digest = predecessor))
}
.dsvert_dp_irls_lane_id <- function(stage_id, lane) {
  .dsvert_dp_irls_hex(stage_id); .dsvert_dp_irls_choice(lane, c("g", "H"))
  .dsvert_dp_analysis_canonical_value_v1(list(stage_id = stage_id, lane = lane))
}
.dsvert_dp_irls_payload_validate <- function(contract, t, payload) {
  stage <- .dsvert_dp_irls_stage(contract, t)
  .dsvert_dp_irls_fields(payload, if (stage$refresh) c("g", "H") else c("g", "H_reference"))
  for (lane in if (stage$refresh) c("g", "H") else "g") {
    upper <- contract$numeric$upper_limits[[lane]]
    payload[[lane]] <- .dsvert_dp_irls_array(payload[[lane]], length(upper))
    for (i in seq_along(upper)) .dsvert_dp_irls_int(payload[[lane]][[i]], "0", upper[[i]])
  }
  if (!stage$refresh) {
    .dsvert_dp_irls_fields(payload$H_reference, c("stage_id", "payload_digest"))
    lapply(payload$H_reference, .dsvert_dp_irls_hex)
  }
  .dsvert_dp_analysis_canonical_value_v1(payload)
}
.dsvert_dp_irls_payload_digest <- function(contract, t, payload) {
  payload <- .dsvert_dp_irls_payload_validate(contract, t, payload)
  # Array order is normative g || H, or g || signed retained-H reference.
  .dsvert_dp_irls_hash("dsvert-v3-irls-public-payload-v1", if (!is.null(payload$H))
    list(list(lane = "g", values = payload$g), list(lane = "H", values = payload$H)) else
    list(list(lane = "g", values = payload$g), list(lane = "H", reference = payload$H_reference)))
}
.dsvert_dp_irls_accounting <- function(contract, observed = list(), observed_auxiliary = list()) {
  contract <- .dsvert_dp_irls_contract_normalize(contract)
  observed <- .dsvert_dp_irls_array(observed)
  stages <- contract$accounting$stages; seen <- list()
  for (entry in observed) {
    .dsvert_dp_irls_fields(entry, c("t", "lanes"))
    stage <- .dsvert_dp_irls_stage(contract, entry$t)
    lanes <- .dsvert_dp_irls_texts(entry$lanes, 1L)
    if (!all(unlist(lanes) %in% if (stage$refresh) c("g", "H") else "g"))
      .dsvert_dp_irls_fail("observed lane")
    # Repeat observations represent replay; charge the logical lane once.
    seen[[entry$t]] <- union(seen[[entry$t]], unlist(lanes))
  }
  records <- lapply(stages, function(stage) {
    lanes <- seen[[stage$t]]
    charged <- Reduce(`+`, lapply(lanes, function(lane) .dsvert_dp_irls_bigq(stage[[lane]])), gmp::as.bigq(0))
    required <- if (.dsvert_dp_irls_bigq(stage$H) > 0) c("g", "H") else "g"
    list(t = stage$t, purpose = stage$purpose, epsilon = stage$epsilon,
      observed_lanes = as.list(required[required %in% lanes]),
      charged_epsilon = .dsvert_dp_irls_rational(charged),
      status = if (!length(lanes)) "unobserved" else if (setequal(required, lanes)) "complete" else "partial")
  })
  ids <- .dsvert_dp_irls_texts(observed_auxiliary)
  aux <- contract$accounting$auxiliary
  valid_ids <- vapply(aux, `[[`, character(1L), "id")
  if (!all(unlist(ids) %in% valid_ids)) .dsvert_dp_irls_fail("observed auxiliary")
  auxcharged <- Reduce(`+`, lapply(aux[valid_ids %in% unlist(ids)],
    function(z) .dsvert_dp_irls_bigq(z$epsilon)), gmp::as.bigq(0))
  consumed <- .dsvert_dp_irls_bigq(contract$accounting$pilot_epsilon) + auxcharged +
    Reduce(`+`, lapply(records, function(z) .dsvert_dp_irls_bigq(z$charged_epsilon)), gmp::as.bigq(0))
  .dsvert_dp_analysis_canonical_value_v1(list(version = "dsvert-dp-irls-partial-accounting-v1",
    root = .dsvert_dp_irls_root(contract), stages = records,
    epsilon_path = contract$accounting$epsilon_path, reserved_epsilon = contract$accounting$epsilon_path,
    pilot_epsilon = contract$accounting$pilot_epsilon,
    auxiliary_charged_epsilon = .dsvert_dp_irls_rational(auxcharged),
    charged_epsilon = .dsvert_dp_irls_rational(consumed),
    reservation_refund = list(d = "1", n = "0")))
}
