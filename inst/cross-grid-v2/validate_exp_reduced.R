# Public/synthetic oracle only. Every integer product below is <= 2^53.
args <- commandArgs(trailingOnly = TRUE)
path <- if (length(args)) args[[1L]] else "inst/cross-grid-v2/exp_reduced_candidate.json"
fixture <- jsonlite::fromJSON(path, simplifyVector = FALSE)
round_even <- function(n, d) {
  q <- floor(n / d)
  r <- n - q * d
  q + as.numeric(2*r > d | (2*r == d & q %% 2 == 1))
}
evaluate <- function(p, eta) {
  stopifnot(all(is.finite(eta)), all(eta == floor(eta)), all(abs(eta) <= 16*2^26))
  # Split reciprocal multiplication: the 61-bit product is never a double.
  x <- abs(eta)
  hi <- floor(x / 65536) * p$inv_ln2
  lo <- (x %% 65536) * p$inv_ln2
  q <- floor(hi / 2^40)
  rhi <- (hi - q*2^40) + floor(lo / 65536)
  q <- q + floor(rhi / 2^40)
  rhi <- rhi %% 2^40
  rlo <- lo %% 65536
  k <- q + as.numeric(rhi > 2^39 | (rhi == 2^39 & (rlo > 0 | q %% 2 == 1)))
  k <- k * sign(eta)
  r <- round_even(eta*16 - k*p$ln2, 64)
  offset <- r + 2^23
  j <- floor(offset / p$width)
  residual <- offset - j*p$width
  c <- do.call(rbind, lapply(p$coefficients, unlist))
  v <- c[j+1,2] + round_even(c[j+1,3]*residual,p$width)
  v <- c[j+1,1] + round_even(v*residual,p$width)
  sh <- 11-k
  ifelse(sh > 0, round_even(v,2^pmax(0,sh)),v*2^pmax(0,-sh))
}
set.seed(20260918)
checks <- 0L
for (p in fixture$profiles) {
  vectors <- do.call(rbind,lapply(p$test_vectors,unlist))
  stopifnot(identical(as.numeric(evaluate(p,vectors[,1])),as.numeric(vectors[,2])))
  for (a in c(1,2,4,8,16)) {
    x <- pmin(a,seq(-a,a,length.out=65537)+0.37/2^26)
    err <- max(abs(evaluate(p,round(x*2^26))/65536-exp(x)))
    bound <- as.numeric(p$loss_errors[[as.character(a)]])
    stopifnot(err <= bound)
    cat(p$identity,"A",a,"dense",length(x),"max_error",err,"bound",bound,"\n")
  }
  for (cap in p$caps) {
    x <- c(-cap$a,cap$a,runif(1000,-cap$a,cap$a))
    y <- sample(0:cap$max_outcome,length(x),replace=TRUE)
    eta <- round(x*2^26)
    # log-factorials independently rounded to the stated f16 table precision.
    loss <- evaluate(p,eta)/65536-y*eta/2^26+round(lgamma(y+1)*65536)/65536
    exact <- -dpois(y,exp(x),log=TRUE)
    error <- as.numeric(p$loss_errors[[as.character(cap$a)]])
    stopifnot(all(abs(loss-exact)<=error),max(loss)+error <= cap$per_patient_cap/65536)
    z <- round(pmax(0,pmin(loss*65536,cap$per_patient_cap)))
    for (trial in seq_len(100)) {
      before <- sample(c(0,z),16,replace=TRUE)
      after <- sample(c(0,z),16,replace=TRUE)
      for (adjacency in 1:2) {
        diff <- if (adjacency==1) after else after-before
        u <- rep(cap$per_patient_cap,16)
        stopifnot(sum(abs(diff))<=adjacency*sum(u),sqrt(sum(diff^2))<=adjacency*sqrt(sum(u^2)))
        checks <- checks+1L
      }
    }
    # Conservative utility check: aggregate approximation error <1% of
    # even Delta2/epsilon at n=2000 and epsilon<=8, for the proposed A=4,
    # K=64, 16 equal-envelope candidates default. This is not yet a
    # production noise calibration test.
    if (p$pieces == 64 && cap$a == 4) {
      stopifnot(2000*(error+1/131072) < 0.01*sqrt(16)*(cap$per_patient_cap/65536)/8)
    }
  }
}
cat("PASS: shared vectors, 983055 dense evaluations, Poisson objective/caps,",checks,"adjacency checks and utility margin\n")
