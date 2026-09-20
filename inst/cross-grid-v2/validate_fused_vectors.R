# Synthetic full f100 dot products through independent signed-limb arithmetic.
source("tests/testthat/helper-cross-grid-integer.R")
bin <- new.env(parent = globalenv())
pois <- new.env(parent = globalenv())
invisible(capture.output(sys.source("inst/cross-grid-v2/validate_profile.R", bin)))
invisible(capture.output(sys.source("inst/cross-grid-v2/validate_exp_reduced.R", pois)))
profiles <- jsonlite::fromJSON("inst/dsvert-mpc/cross_grid_profiles_v2.json", simplifyVector = FALSE)
fixture <- jsonlite::fromJSON("inst/cross-grid-v2/fused_vectors.json", simplifyVector = FALSE)
checks <- 0L
for (group in fixture) {
  p <- group$plan
  bp <- Filter(function(x) x$a == p$A, profiles$binomial)[[1L]]
  q <- if (p$Family == "binomial") 16L else 26L
  for (v in group$vectors) {
    x <- lapply(v$source, .cross_parse)
    xd <- vapply(x, .cross_double, numeric(1))
    valid <- xd[[1]] <= 2^50 && xd[[2]] == 1 && xd[[4]] == 1 &&
      xd[[5]] <= p$MaxOutcome && xd[[6]] == 1 && xd[[8]] == xd[[10]]
    dot <- .cross_shift_left(.cross_parse(p$Beta[[1]][[1]]), 50L)
    for (k in 1:2) dot <- .cross_add(dot, .cross_mul(x[[2*k-1]], .cross_parse(p$Beta[[1]][[k+1]])))
    eta <- .cross_double(.cross_round_shift(dot, 100L-q))
    eta <- min(p$A*2^q, max(-p$A*2^q, eta))
    y <- xd[[5]]
    if (p$Family == "binomial") {
      loss <- bin$evaluate(bp, eta + p$A*65536)-y*eta
    } else {
      loss <- pois$evaluate(profiles$poisson, eta)*1024-y*eta +
        profiles$log_factorial[[y+1]]*1024
    }
    # All loss integers are <2^53; quantization is exact ties-to-even.
    got <- if (valid) min(p$Caps[[1]], round(max(0,loss)*2^(p$GridBits-q))) else 0
    stopifnot(identical(as.character(got), v$expected[[1]]))
    checks <- checks + 1L
  }
}
cat("PASS:", checks, "full f100 source-to-loss integer fixtures in independent R limbs\n")
