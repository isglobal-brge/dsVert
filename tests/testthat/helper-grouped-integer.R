# Test-only pure-R integer oracles. Signed base-2^15 operations are supplied by
# helper-cross-grid-integer.R; no protected route imports these helpers.
.grouped_div_even <- function(a, b) {
  stopifnot(b$s > 0)
  sign <- a$s
  a$s <- abs(a$s)
  q <- .cross_int()
  remainder <- .cross_int()
  for (i in rev(seq_len(15L*length(a$d)))) {
    remainder <- .cross_shift_left(remainder, 1)
    bit <- floor(a$d[(i-1L)%/%15L+1L] / 2^((i-1L)%%15L)) %% 2
    remainder <- .cross_add(remainder, .cross_small(bit))
    q <- .cross_shift_left(q, 1)
    if (.cross_cmp_abs(remainder, b) >= 0) {
      remainder <- .cross_sub(remainder, b)
      q <- .cross_add(q, .cross_small(1))
    }
  }
  cmp <- .cross_cmp_abs(.cross_shift_left(remainder, 1), b)
  if (cmp > 0 || (cmp == 0 && q$d[1L] %% 2 == 1)) {
    q <- .cross_add(q, .cross_small(1))
  }
  q$s <- sign*q$s
  q
}
.grouped_q16_mul <- function(a, b) {
  .cross_round_shift(.cross_mul(a, b), 16)
}
.grouped_profile_table <- function(name) {
  path <- system.file("certificates", "grouped_pwlinear_q16_v1.json", package = "dsVert")
  if (!nzchar(path)) path <- file.path("inst", "certificates", "grouped_pwlinear_q16_v1.json")
  profiles <- jsonlite::fromJSON(path, simplifyVector = FALSE)$profiles
  profiles[[which(vapply(profiles, `[[`, character(1L), "name") == name)]]
}
.grouped_profile <- function(x, name) {
  if (name %in% c("exp", "exp_negative")) {
    lower <- if (name == "exp") -262144 else -1048576
    upper <- if (name == "exp") 262144 else 0
    stopifnot(length(x) == 1L, x == floor(x), x >= lower, x <= upper)
    k <- floor((abs(x)+22713)/45426)*sign(x)
    residual <- x-k*45426
    return(round(.grouped_profile(residual, "exp_reduced")*2^k))
  }
  table <- .grouped_profile_table(name)
  stopifnot(length(x) == 1L, x == floor(x), x >= table$lower, x <= table$upper)
  k <- min(63, floor((x-table$lower)/table$step))
  fraction <- x-table$lower-k*table$step
  delta <- table$knots[[k+2L]]-table$knots[[k+1L]]
  # q16 knot difference * one interval offset fits binary64's exact integers.
  table$knots[[k+1L]] + round(fraction*delta/table$step)
}
.grouped_q16_quantize <- function(value, cap, bits) {
  value <- .cross_small(max(0, value))
  upper <- .cross_shift_left(.cross_small(cap), max(0, 16-bits))
  if (bits > 16) value <- .cross_shift_left(value, bits-16)
  if (.cross_cmp_abs(value, upper) > 0) value <- upper
  if (bits < 16) value <- .cross_round_shift(value, 16-bits)
  as.numeric(.cross_format(value))
}
.grouped_lmm_integer <- function(residual_q64, live, sigma_q64, tau_q64, cap, bits) {
  stopifnot(length(residual_q64) == length(live), all(live %in% 0:1))
  sigma <- .cross_parse(sigma_q64)
  tau <- .cross_parse(tau_q64)
  inverse <- .grouped_div_even(.cross_pow2(128), sigma)
  count <- sum(live)
  denominator <- .cross_mul(sigma, .cross_add(sigma, .cross_mul(tau, .cross_small(count))))
  lambda <- .grouped_div_even(.cross_shift_left(tau, 128), denominator)
  sum <- .cross_int()
  squares <- .cross_int()
  for (i in seq_along(live)) if (live[i] == 1) {
    r <- .cross_parse(residual_q64[i])
    sum <- .cross_add(sum, r)
    squares <- .cross_add(squares, .cross_round_shift(.cross_mul(r, r), 64))
  }
  loss <- .cross_sub(.cross_qmul(squares, inverse),
    .cross_qmul(.cross_qmul(sum, sum), lambda))
  .cross_format(.cross_quantize(loss, .cross_parse(as.character(cap)), bits))
}
.grouped_glmm_integer <- function(eta_q64, outcome, live, family, variance, cap, bits) {
  stopifnot(length(eta_q64) == length(live), length(live) == length(outcome),
            all(live %in% 0:1), variance %in% c(0, .25),
            family %in% c("binomial", "poisson"))
  if (!any(live == 1)) return("0")
  nodes <- if (variance == 0) rep(0, 5) else c(-93617, -44421, 0, 44421, 93617)
  logweights <- c(-294042, -98614, -41196, -98614, -294042)
  factorial <- c(0, 0, 45426, 117425, 208277)
  eta <- vapply(eta_q64, function(x) .cross_double(.cross_round_shift(.cross_parse(x), 48)), numeric(1L))
  terms <- logweights
  for (q in seq_len(5)) for (i in seq_along(live)) if (live[i] == 1) {
    t <- eta[i]+nodes[q]
    loss <- if (family == "binomial") .grouped_profile(t, "softplus")-outcome[i]*t else {
      .grouped_profile(t, "exp")-outcome[i]*t+factorial[outcome[i]+1L]
    }
    terms[q] <- terms[q]-loss
  }
  maximum <- max(terms)
  exponential <- vapply(terms-maximum, function(value) {
    if (value < -16*65536) 0 else .grouped_profile(value, "exp_negative")
  }, numeric(1L))
  loss <- -maximum-.grouped_profile(sum(exponential), "log")
  as.character(.grouped_q16_quantize(loss, cap, bits))
}

.grouped_gee_integer <- function(eta_q64, features_f50, outcome, live,
                                 family, correlation, rho, clip, bits,
                                 row_cap, bread_cap) {
  # Restricted public domain: B<=8, p<=3, eta<=4, M<=4, rho<=1/2.
  # Every q16 multiply below has magnitude <2^45, so its binary64 integer
  # product is exact; division by a power of two and R ties-even are exact.
  n <- length(live); d <- ncol(features_f50)+1L; S <- 65536
  mul <- function(a,b) round(a*b/S)
  quant <- function(x) round(x*2^(bits-16))
  X <- cbind(S, matrix(vapply(as.vector(features_f50), function(x)
    .cross_double(.cross_round_shift(.cross_parse(x),34)), numeric(1L)), n))
  eta <- vapply(eta_q64, function(x)
    .cross_double(.cross_round_shift(.cross_parse(x),48)), numeric(1L))
  u <- matrix(0,n,d); z <- numeric(n); loss <- 0
  for (i in seq_len(n)) if (live[i]) {
    if (family == "binomial") {
      mu <- .grouped_profile(eta[i],"sigmoid")
      a <- .grouped_profile(eta[i],"sqrt_variance")
      b <- .grouped_profile(eta[i],"inverse_sqrt_variance")
      ell <- .grouped_profile(eta[i],"softplus")-outcome[i]*eta[i]
    } else {
      mu <- .grouped_profile(eta[i],"exp")
      a <- .grouped_profile(round(eta[i]/2),"exp")
      b <- .grouped_profile(-round(eta[i]/2),"exp")
      ell <- mu-outcome[i]*eta[i]+c(0,0,45426,117423,208277)[outcome[i]+1L]
    }
    loss <- loss+min(row_cap,max(0,quant(ell)))
    u[i,] <- mul(X[i,],a); z[i] <- mul(outcome[i]*S-mu,b)
  }
  W <- matrix(0,n,n); idx <- which(live==1)
  if (length(idx)) {
    if (correlation == "ar1") {
      W[idx[1L],idx[1L]] <- S
      if (length(idx)>1L) for (k in 2:length(idx)) {
        i <- idx[k-1L]; j <- idx[k]; a <- rho^(j-i)
        # rho in {0,1/4,1/2}; these rationals and their denominators are
        # exactly represented; none is a half-integer rounding tie.
        W[i,i] <- W[i,i]+round(S*a*a/(1-a*a))
        W[j,j] <- W[j,j]+round(S/(1-a*a))
        W[i,j] <- W[j,i] <- round(-S*a/(1-a*a))
      }
    } else if (correlation == "exchangeable") {
      W[idx,idx] <- -round(S*rho/((1-rho)*(1+(length(idx)-1)*rho)))
      diag(W)[idx] <- diag(W)[idx]+round(S/(1-rho))
    } else diag(W)[idx] <- S
  }
  score <- numeric(d); bread <- matrix(0,d,d)
  for (i in seq_len(n)) {
    wz <- sum(mul(W[i,],z))
    wu <- vapply(seq_len(d),function(k) sum(mul(W[i,],u[,k])),numeric(1L))
    score <- score+mul(u[i,],wz)
    for (k in seq_len(d)) for (l in seq_len(d)) bread[k,l] <- bread[k,l]+mul(u[i,k],wu[l])
  }
  score <- pmax(-clip,pmin(clip,score))
  shift <- if (correlation=="independence") 0 else bread_cap
  meat_shift <- mul(clip,clip)
  bread_out <- meat_out <- numeric()
  for (l in seq_len(d)) for (k in seq_len(l)) {
    bread_out <- c(bread_out,min(bread_cap+shift,max(0,quant(bread[k,l])+shift)))
    meat_out <- c(meat_out,quant(min(2*meat_shift,max(0,meat_shift+mul(score[k],score[l])))))
  }
  c(loss,bread_out,meat_out)
}

.grouped_go_reference <- function(request) {
  binary <- Sys.getenv("DSVERT_GROUPED_REFERENCE_BINARY")
  testthat::skip_if(!nzchar(binary), "tagged synthetic reference executable not requested")
  input <- tempfile(fileext=".json"); output <- tempfile(fileext=".json")
  on.exit(unlink(c(input,output)))
  jsonlite::write_json(request,input,auto_unbox=TRUE,digits=NA)
  status <- system2(binary,"-test.run=^TestGroupedReferenceBridge$",
    env=c(paste0("DSVERT_GROUPED_TEST_INPUT=",input),paste0("DSVERT_GROUPED_TEST_OUTPUT=",output)),
    stdout=TRUE,stderr=TRUE)
  testthat::expect_null(attr(status,"status"))
  jsonlite::fromJSON(output)
}

