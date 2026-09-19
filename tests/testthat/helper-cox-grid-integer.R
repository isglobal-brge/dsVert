# Test-only pure R integer oracle. Every product/sum is <2^53; no exp/log
# participates in profile evaluation and no protected source can call this.
.cox_integer_profile <- function() {
  path <- system.file("cross-cox-v1", "numeric_cox_profile_v1.json", package = "dsVert")
  if (!nzchar(path)) path <- testthat::test_path("..", "..", "..", "dsVert", "inst",
    "cross-cox-v1", "numeric_cox_profile_v1.json")
  jsonlite::fromJSON(path, simplifyVector = FALSE)
}
.cox_integer_exp <- function(eta, profile = .cox_integer_profile()$profile) {
  stopifnot(is.numeric(eta), all(is.finite(eta)), all(eta == floor(eta)),
            all(abs(eta) <= 524288))
  knots <- unlist(profile$exp_knots_q20)
  vapply(eta, function(a) {
    if (a == 524288) return(knots[[65]])
    x <- a + 524288; i <- floor(x / 16384) + 1; r <- x %% 16384
    knots[[i]] + floor((knots[[i + 1]] - knots[[i]]) * r / 16384)
  }, numeric(1L))
}
.cox_integer_log <- function(risk, profile = .cox_integer_profile()$profile) {
  stopifnot(is.numeric(risk), all(is.finite(risk)), all(risk == floor(risk)),
            all(risk >= 352), all(risk <= 31257610020000))
  knots <- unlist(profile$log_knots_q20)
  vapply(risk, function(a) {
    k <- 0; m <- a
    while (m >= 2097152) { m <- floor(m / 2); k <- k + 1 }
    while (m < 1048576) { m <- m * 2; k <- k - 1 }
    x <- m - 1048576; i <- floor(x / 16384) + 1; r <- x %% 16384
    knots[[i]] + floor((knots[[i + 1]] - knots[[i]]) * r / 16384) + k * profile$ln2_q20
  }, numeric(1L))
}
.cox_integer_loss <- function(eta, time, event, valid, cap, bits) {
  stopifnot(length(eta) == length(time), length(eta) == length(event),
            length(eta) == length(valid), all(is.finite(time)),
            all(event %in% 0:1), is.logical(valid), !anyNA(valid),
            bits %in% 8:18, length(eta) <= 10000)
  profile <- .cox_integer_profile()$profile
  # Independent direct risk-set implementation (not the prefix scan).
  active <- which(valid); total <- 0
  weights <- .cox_integer_exp(eta[active], profile)
  for (i in active[event[active] == 1]) {
    risk <- sum(weights[time[active] >= time[[i]]])
    total <- total + .cox_integer_log(risk, profile) - eta[[i]] * 16
  }
  max(0, min(cap, round(total / 2^(20 - bits))))
}
