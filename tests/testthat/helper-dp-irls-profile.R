.irls_producer_fixture <- function(family = "binomial", rows = "4") {
  f <- .irls_contract_fixture(); s <- f$spec; q <- .irls_q
  poisson <- family == "poisson"
  c <- .dsvert_dp_irls_profile_certificate(family, "3", rows)
  s$profile_id <- .DSVERT_DP_IRLS_PRODUCER_VERSION
  s$estimand$formula <- "y ~ x + z"
  s$estimand$coefficient_order <- list("(Intercept)", "x", "z")
  s$estimand$family <- family; s$estimand$link <- if (poisson) "log" else "logit"
  z <- s$estimand$columns[[1L]]; z$column_id <- "z"
  s$estimand$columns <- append(s$estimand$columns, list(z))
  s$privacy_source$capacity <- rows
  s$privacy_source$duplicate_rule <- "one-row-per-public-person-slot-v1"
  s$privacy_source$x_bounds <- list(list(lower = q("1"), upper = q("1")),
    list(lower = q("-1"), upper = q("1")), list(lower = q("-1"), upper = q("1")))
  s$privacy_source$y_bounds$upper <- q(if (poisson) "8" else "1")
  s$privacy_source$person_caps <- list(score_abs = rep(list(q(if (poisson) "55" else "1")), 3L),
    curvature_abs = rep(list(if (poisson) q("55") else q("1", "4")), 6L))
  n <- s$numeric
  n$eta_bounds <- list(lower = q("-4"), upper = q("4"))
  n$score_definition <- if (poisson) "x-times-clamped-count-minus-q16-exp-v1" else "x-times-binary-y-minus-q16-mu-mask-invalid-v1"
  n$curvature_definition <- if (poisson) "q16-exp-times-xx-v1" else "q16-rounded-mu-times-one-minus-mu-xx-v1"
  n$curvature_role <- "preconditioner"
  n$approximation_certificate_sha256 <- .dsvert_dp_irls_profile_digest(c)
  n$lattice <- list(g = q("1", "4096"), H = q("1", "4096"), beta = q("1", "65536"))
  n$rounding_slack <- list(g = q("3", "8192"), H = q("3", "4096"))
  n$source_intermediate_bits <- "64"
  n$layout <- list("g:1", "g:2", "g:3", "H:1:1", "H:1:2", "H:1:3", "H:2:2", "H:2:3", "H:3:3")
  n$translation <- list(g = rep(list(c$g_translation), 3L), H = rep(list(c$h_translation), 6L))
  n$person_integer_caps <- list(g = rep(list(c$g_cap), 3L), H = rep(list(c$h_cap), 6L))
  n$translation_margin <- list(g = rep(list("0"), 3L), H = rep(list("0"), 6L))
  n$upper_limits <- lapply(n$translation, function(lane) lapply(lane, function(v) as.character(2 * gmp::as.bigz(v))))
  n$compiler_version <- "markkurossi-mpc-c911bbd029d1"
  n$backend_version <- "cross-grid-dp-irls-fused-exact-gc-v1"
  n$certificate <- list(common_denominator = "4096", input_bits = "64",
    k_max = as.character(ceiling(1 + 3 * as.numeric(c$h_translation) / 4096)), temporary_bits = "2664")
  n$certificate_sha256 <- .dsvert_dp_irls_hash("dsvert-v3-irls-numeric-certificate-v1", n$certificate)
  s$numeric <- n
  s$path$start$beta <- rep(list(q("0")), 3L)
  s$path$box <- list(lower = rep(list(q("-1")), 3L), upper = rep(list(q("1")), 3L))
  s$accounting$sensitivity <- list(g = c$s1_g, H = c$s1_h)
  s$accounting$stages <- lapply(s$accounting$stages, function(stage) {
    for (lane in c("g", "H")) stage[[paste0("alpha_", lane)]] <-
      .dsvert_dp_irls_rational(.dsvert_dp_irls_bigq(stage[[lane]]) / gmp::as.bigz(s$accounting$sensitivity[[lane]]))
    stage
  })
  s$inference$allowed_contrasts <- list(list(q("1"), q("0"), q("0")))
  s$operations$shape <- list(p = "3", coordinates = "9", capacity = rows, row_cap = "1")
  f$spec <- .dsvert_dp_irls_contract_normalize(s); f$signed <- f$sign(f$spec)
  f$payload <- function(t = "0") f$spec$numeric$translation
  f
}

.irls_smoke_fixture <- function() {
  f <- .irls_producer_fixture("binomial", "64")
  s <- f$spec
  s$profile_id <- .DSVERT_DP_IRLS_SMOKE_VERSION
  s$path$floor <- .irls_q("8", "5")
  s$path$floor_quantum <- .irls_q("1", "4096")
  s$numeric$certificate$common_denominator <- "20480"
  s$numeric$certificate$k_max <- "203162"
  s$numeric$certificate_sha256 <- .dsvert_dp_irls_hash(
    "dsvert-v3-irls-numeric-certificate-v1", s$numeric$certificate)
  s$operations$max_compile_bytes <- "1073741824"
  s$operations$max_memory_bytes <- "4294967296"
  f$spec <- .dsvert_dp_irls_contract_normalize(s)
  f$signed <- f$sign(f$spec)
  f$payload <- function(t = "0") f$spec$numeric$translation
  f
}
