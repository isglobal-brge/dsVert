# Layer 1 only: synthetic pooled objectives. No DP draw or production release.
bin <- new.env(parent = globalenv())
pois <- new.env(parent = globalenv())
invisible(capture.output(sys.source("inst/cross-grid-v2/validate_profile.R", bin)))
invisible(capture.output(sys.source("inst/cross-grid-v2/validate_exp_reduced.R", pois)))
bp <- Filter(function(p) p$family == "binomial" && p$a == 4 && p$pieces == 64,
             bin$fixture$profiles)[[1L]]
pp <- Filter(function(p) p$pieces == 64, pois$fixture$profiles)[[1L]]
set.seed(20260918)
n <- 2000L
# Dyadic features and grid coefficients permit exact binary64 dot products.
x <- matrix(sample(0:1024, n*6, replace = TRUE)/1024, nrow = n)
beta <- c(-1/4, 1/2, -3/8, 1/4, -1/2, 3/8, 1/8)
design <- cbind(1, x)
eta <- drop(design %*% beta)
for (family in c("binomial", "poisson")) {
  y <- if (family == "binomial") rbinom(n, 1, plogis(eta)) else pmin(4L, rpois(n, exp(eta)))
  data <- data.frame(y = y, x)
  fit <- glm(y ~ ., data = data, family = family)
  stopifnot(isTRUE(fit$converged))
  candidates <- lapply(seq_len(16), function(j) {
    beta + c(0, rep((j-8)/256, 6))
  })
  candidates <- c(candidates, list(unname(coef(fit))))
  maximum <- 0
  for (j in seq_along(candidates)) {
    b <- candidates[[j]]
    stopifnot(sum(abs(b)) <= 4)
    # The last candidate comes from glm; all other dot products are exact
    # dyadic arithmetic, also when split between owners 3/3.
    linear <- drop(design %*% b)
    if (j <= 16) {
      partial1 <- b[[1]] + drop(x[,1:3,drop=FALSE] %*% b[2:4])
      partial2 <- drop(x[,4:6,drop=FALSE] %*% b[5:7])
      stopifnot(identical(linear, partial1 + partial2))
    }
    if (family == "binomial") {
      encoded <- round(linear*65536)
      approximate <- bin$evaluate(bp, encoded + 4*65536)/65536 - y*encoded/65536
      exact <- -dbinom(y, 1, plogis(linear), log = TRUE)
      bound <- as.numeric(bp$loss_error)
      cap <- bp$caps[[1]]$per_patient_cap
    } else {
      encoded <- round(linear*2^26)
      approximate <- pois$evaluate(pp, encoded)/65536 - y*encoded/2^26 + round(lgamma(y+1)*65536)/65536
      exact <- -dpois(y, exp(linear), log = TRUE)
      bound <- as.numeric(pp$loss_errors[["4"]])
      cap <- Filter(function(c) c$a == 4 && c$max_outcome == 4, pp$caps)[[1]]$per_patient_cap
    }
    stopifnot(max(abs(approximate-exact)) <= bound)
    lattice <- round(pmin(cap, pmax(0, approximate*65536)))/65536
    gap <- abs(sum(lattice)-sum(exact))
    stopifnot(gap <= n*(bound+1/131072))
    maximum <- max(maximum, gap)
    if (j == length(candidates)) {
      stopifnot(abs(sum(exact) + as.numeric(logLik(fit))) < 1e-8)
      stopifnot(abs(sum(lattice) + as.numeric(logLik(fit))) <= n*(bound+1/131072))
    }
  }
  cat("PASS", family, "n=2000 p=6 split=3/3 candidates=17 max_total_loss_error=",
      format(maximum, digits=10), "certified_total_tolerance=", n*(bound+1/131072),
      "glm_logLik_agreement=TRUE\n")
}
