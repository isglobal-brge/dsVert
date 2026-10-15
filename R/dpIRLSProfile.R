# B2 circuit admission is stricter than B1's public-chain wire validation.
# No remote method, source read, sampler, or aggregate opening is defined here.
.DSVERT_DP_IRLS_PRODUCER_VERSION <- "dsvert-dp-irls-producer-p3-q16-q12-v1"
.DSVERT_DP_IRLS_SMOKE_VERSION <- "irls-smoke-k2-c64-p3-v1"
.DSVERT_DP_IRLS_LINK_SHA256 <- "f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84"

# A named schedule is an admission predicate, never an alias for a numeric
# certificate. All remaining path fields are fixed by B1's strict schema.
.dsvert_dp_irls_smoke_check <- function(spec) {
  same <- function(actual, expected) {
    if (!identical(.dsvert_dp_irls_json(actual), .dsvert_dp_irls_json(expected)))
      .dsvert_dp_irls_fail("smoke schedule")
  }
  q <- function(n, d = "1") list(d = d, n = n)
  same(spec$estimand$family, "binomial"); same(spec$estimand$link, "logit")
  same(spec$estimand$intercept, "1"); same(spec$estimand$offset$kind, "none")
  same(spec$privacy_source$capacity, "64"); same(spec$privacy_source$row_cap, "1")
  same(spec$privacy_source$adjacency, "add-remove-person")
  same(spec$operations$shape, list(p = "3", coordinates = "9", capacity = "64", row_cap = "1"))
  same(spec$operations$max_stage_seconds, "240")
  same(spec$operations$max_path_seconds, "840")
  p <- spec$path
  same(p$T, "2"); same(p$start$kind, "zero")
  same(p$start$beta, rep(list(q("0")), 3L))
  same(p$refresh_mask, list("1", "1")); same(p$terminal_audit, "1")
  same(p$box, list(lower = rep(list(q("-1")), 3L), upper = rep(list(q("1")), 3L)))
  same(p$floor, q("8", "5")); same(p$floor_quantum, q("1", "4096"))
  same(p$ridge, q("0")); same(p$damping, rep(list(q("1")), 2L))
  same(p$trust, rep(list(q("1")), 2L))
  same(spec$accounting$geometry, "split-block-v1")
  same(spec$accounting$pilot_epsilon, q("0")); same(spec$accounting$auxiliary, list())
  same(spec$accounting$epsilon_path, q("8"))
  for (i in seq_len(3L)) {
    budget <- if (i == 3L) "2" else "1"
    a <- spec$accounting$stages[[i]]
    same(a$t, as.character(i - 1L))
    same(a$purpose, if (i == 3L) "terminal-audit" else "optimizer")
    same(a$g, q(budget)); same(a$H, q(budget))
  }
  invisible(TRUE)
}

.dsvert_dp_irls_profile_certificate <- function(family, p, rows, row_cap = "1") {
  .dsvert_dp_irls_choice(family, c("binomial", "poisson"))
  .dsvert_dp_irls_choice(p, "3", "uncertified producer dimension")
  .dsvert_dp_irls_int(rows, "1", "64")
  .dsvert_dp_irls_choice(row_cap, "1", "uncertified person row cap")
  q <- function(n, d = "1") list(d = d, n = n)
  poisson <- family == "poisson"
  g <- if (poisson) "225280" else "4096"
  h <- if (poisson) "225280" else "1024"
  product <- function(a, b) as.character(gmp::as.bigz(a) * gmp::as.bigz(b))
  list(eta_rounding_error = q("1", "131072"), family = family,
    g_cap = g, g_translation = product(rows, g), h_cap = h,
    h_coordinate_error = if (poisson) q("98987", "16384000") else q("897", "2621440"),
    h_translation = product(rows, h), intermediate_bits = "64",
    link_error = if (poisson) q("11", "2000") else q("69", "327680"),
    link_profile_sha256 = .DSVERT_DP_IRLS_LINK_SHA256,
    output_fraction_bits = "12", p = "3", ring_bits = "128", row_cap = "1",
    rows = rows, s1_g = product("3", g), s1_h = product("6", h),
    score_coordinate_error = if (poisson) q("98987", "16384000") else q("877", "2621440"),
    source_fraction_bits = "16", version = .DSVERT_DP_IRLS_PRODUCER_VERSION)
}

.dsvert_dp_irls_profile_digest <- function(certificate) {
  digest::digest(c(charToRaw("dsvert-dp-irls-producer-certificate-v1"), as.raw(0),
    charToRaw(.dsvert_dp_irls_json(certificate))), algo = "sha256", serialize = FALSE)
}

.dsvert_dp_irls_profile_check <- function(spec) {
  s <- spec$privacy_source; n <- spec$numeric; p <- spec$path
  if (length(s$peer_pins) != 2L || !setequal(names(s$peer_pins), unlist(s$computation_peers)))
    .dsvert_dp_irls_fail("uncertified producer owner count")
  certificate <- .dsvert_dp_irls_profile_certificate(spec$estimand$family,
    spec$operations$shape$p, s$capacity, s$row_cap)
  same <- function(actual, expected) {
    if (!identical(.dsvert_dp_irls_json(actual), .dsvert_dp_irls_json(expected)))
      .dsvert_dp_irls_fail("uncertified producer constants")
  }
  q <- function(n, d = "1") list(d = d, n = n)
  interval <- function(lo, hi) list(lower = q(lo), upper = q(hi))
  if (identical(spec$profile_id, .DSVERT_DP_IRLS_SMOKE_VERSION)) {
    .dsvert_dp_irls_smoke_check(spec)
  } else same(spec$profile_id, .DSVERT_DP_IRLS_PRODUCER_VERSION)
  x_bounds <- rep(list(interval("-1", "1")), 3L)
  if (spec$estimand$intercept == "1") x_bounds[[1L]] <- interval("1", "1")
  same(s$x_bounds, x_bounds)
  offset_none <- spec$estimand$offset$kind == "none"
  same(s$offset_bounds, if (offset_none) interval("0", "0") else interval("-1", "1"))
  same(s$y_bounds, interval("0", if (spec$estimand$family == "poisson") "8" else "1"))
  .dsvert_dp_irls_choice(spec$estimand$offset$kind, c("none", "offset"))
  same(s$missing_rule, "masked-zero-person-v1")
  same(s$duplicate_rule, "one-row-per-public-person-slot-v1")
  same(s$ordering_rule, "frozen-public-person-slots-v1")
  same(n$eta_bounds, interval("-4", "4"))
  same(n$score_definition, if (spec$estimand$family == "poisson")
    "x-times-clamped-count-minus-q16-exp-v1" else "x-times-binary-y-minus-q16-mu-mask-invalid-v1")
  same(n$curvature_definition, if (spec$estimand$family == "poisson")
    "q16-exp-times-xx-v1" else "q16-rounded-mu-times-one-minus-mu-xx-v1")
  # This is an IRLS preconditioner: table interpolation and eta clamps mean
  # that it is not literally the derivative of the integer score program.
  same(n$curvature_role, "preconditioner")
  same(n$approximation_certificate_sha256, .dsvert_dp_irls_profile_digest(certificate))
  same(n$lattice, list(g = q("1", "4096"), H = q("1", "4096"), beta = q("1", "65536")))
  same(n$rounding_slack, list(g = q("3", "8192"), H = q("3", "4096")))
  same(n$ring_bits, "128"); same(n$source_intermediate_bits, "64")
  same(n$compiler_version, "markkurossi-mpc-c911bbd029d1")
  same(n$backend_version, "cross-grid-dp-irls-fused-exact-gc-v1")
  same(p$box, list(lower = rep(list(q("-1")), 3L), upper = rep(list(q("1")), 3L)))
  poisson <- spec$estimand$family == "poisson"
  same(s$person_caps, list(score_abs = rep(list(q(if (poisson) "55" else "1")), 3L),
    curvature_abs = rep(list(if (poisson) q("55") else q("1", "4")), 6L)))
  for (lane in c("g", "H")) {
    count <- if (lane == "g") 3L else 6L
    prefix <- tolower(lane)
    same(n$person_integer_caps[[lane]], rep(list(certificate[[paste0(prefix, "_cap")]]), count))
    translation <- certificate[[paste0(prefix, "_translation")]]
    same(n$translation[[lane]], rep(list(translation), count))
    same(n$translation_margin[[lane]], rep(list("0"), count))
    same(n$upper_limits[[lane]], rep(list(as.character(2 * gmp::as.bigz(translation))), count))
    multiplier <- if (s$adjacency == "replace-one-person") 2 else 1
    sensitivity <- as.character(multiplier * gmp::as.bigz(certificate[[paste0("s1_", prefix)]]))
    same(spec$accounting$sensitivity[[lane]], sensitivity)
  }
  if (spec$inference$mode == "qualified") .dsvert_dp_irls_fail("unqualified B2 inference")
  certificate
}

.dsvert_dp_irls_profile_admit <- function(signed_contract, trusted_pins) {
  contract <- .dsvert_dp_irls_contract_validate(signed_contract, trusted_pins)
  list(contract = contract, certificate = .dsvert_dp_irls_profile_check(contract))
}

# The only public-point constructor derives beta from the dual-signed B1
# predecessor chain and recomputes every B1 public update before authorizing it.
.dsvert_dp_irls_stage_plan <- function(path, signed_contract, trusted_pins,
    t, predecessor, candidate_beta = NULL) {
  admitted <- .dsvert_dp_irls_profile_admit(signed_contract, trusted_pins)
  .dsvert_dp_irls_store_open(path, function(db) {
    context <- .dsvert_dp_irls_store_context(db, signed_contract, trusted_pins)
    contract <- context$contract
    stage_id <- .dsvert_dp_irls_stage_id(contract, t, predecessor)
    chain <- .dsvert_dp_irls_store_chain(db, context, as.integer(t))
    expected <- if (t == "0") .dsvert_dp_irls_start_digest(contract) else
      chain[[length(chain)]]$body$payload_digest
    if (!identical(expected, predecessor)) .dsvert_dp_irls_fail("alternate evaluation predecessor")
    beta <- if (t == "0") contract$path$start$beta else
      chain[[length(chain)]]$body$update_result$beta
    if (!is.null(candidate_beta) && !identical(.dsvert_dp_irls_json(beta),
        .dsvert_dp_irls_json(candidate_beta))) .dsvert_dp_irls_fail("alternate evaluation beta")
    beta_integer <- lapply(beta, function(value) {
      z <- .dsvert_dp_irls_bigq(value) * 65536L
      if (gmp::denominator(z) != 1 || abs(z) > 65536L)
        .dsvert_dp_irls_fail("evaluation point outside producer lattice")
      as.character(gmp::numerator(z))
    })
    purpose <- .dsvert_dp_irls_stage(contract, t)$purpose
    if (!.dsvert_dp_irls_stage(contract, t)$refresh)
      .dsvert_dp_irls_fail("B2 fused producer requires both budgeted lanes")
    point <- list(beta = beta_integer, predecessor = predecessor, purpose = purpose,
      root = context$root, stage_id = stage_id, stage_index = as.integer(t))
    point_digest <- digest::digest(c(charToRaw("dsvert-dp-irls-public-point-v1"), as.raw(0),
      charToRaw(.dsvert_dp_irls_state_json(point))), algo = "sha256", serialize = FALSE)
    list(beta = beta_integer, certificate_digest = .dsvert_dp_irls_profile_digest(admitted$certificate),
      family = contract$estimand$family, intercept = contract$estimand$intercept == "1",
      offset_mode = if (contract$estimand$offset$kind == "none") "none" else "offset",
      owners = 2L, p = 3L, point_digest = point_digest,
      predecessor = predecessor, purpose = purpose, root = context$root,
      rows = as.integer(contract$privacy_source$capacity), stage_id = stage_id,
      stage_index = as.integer(t), version = "dsvert-dp-irls-stage-v1")
  })
}
