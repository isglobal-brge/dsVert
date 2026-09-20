# Pure-R candidate-profile oracle, public/synthetic values only. Products are
# bounded below 2^53, so integer arithmetic is exact in binary64 throughout.
args <- commandArgs(trailingOnly = TRUE)
path <- if (length(args)) args[[1L]] else "inst/cross-grid-v2/profile_candidate.json"
fixture <- jsonlite::fromJSON(path, simplifyVector = FALSE)
round_even <- function(n, d) {
  q <- floor(n / d)
  r <- n - q * d
  q + as.numeric(2 * r > d | (2 * r == d & q %% 2 == 1))
}
evaluate <- function(p, offset) {
  stopifnot(all(is.finite(offset)), all(offset == floor(offset)),
            all(offset >= 0), all(offset <= 2 * p$a * 65536))
  j <- pmin(floor(offset / p$interval_integer_width), p$pieces - 1)
  residual <- offset - j * p$interval_integer_width
  c <- do.call(rbind, lapply(p$coefficients, unlist))
  first <- c[j + 1, 2] + round_even(c[j + 1, 3] * residual, p$interval_integer_width)
  c[j + 1, 1] + round_even(first * residual, p$interval_integer_width)
}
rows <- lapply(fixture$profiles, function(p) {
  vectors <- do.call(rbind, lapply(p$test_vectors, unlist))
  stopifnot(identical(as.numeric(evaluate(p, vectors[,1])), as.numeric(vectors[,2])))
  x <- seq(-p$a, p$a, length.out = 16385) + 0.37 / 65536
  x <- pmin(x, p$a)
  got <- evaluate(p, round((x + p$a) * 65536)) / 2^p$fraction_bits
  real <- if (p$family == "binomial") log1p(exp(x)) else exp(x)
  error <- max(abs(got - real))
  stopifnot(error <= as.numeric(p$loss_error))
  data.frame(profile = p$identity, vectors = nrow(vectors), dense_points = length(x),
             max_error = error, certified_error = as.numeric(p$loss_error))
})
write.table(do.call(rbind, rows), row.names = FALSE, quote = FALSE, sep = "\t")
cat("PASS: all public fixtures exactly match the independent R oracle\n")
set.seed(20260918)
checks <- 0L
for (p in fixture$profiles) {
  if (p$pieces != 64 || !p$a %in% c(4,16)) next
  for (cap in p$caps) {
    x <- c(-p$a, p$a, runif(1000, -p$a, p$a))
    y <- sample(0:cap$max_outcome, length(x), replace = TRUE)
    eta <- round((x + p$a) * 65536) / 65536 - p$a
    loss <- evaluate(p, (eta + p$a) * 65536) / 2^p$fraction_bits - y*eta
    exact <- if (p$family == "binomial") -dbinom(y, 1, plogis(x), log = TRUE) else -dpois(y, exp(x), log = TRUE)
    if (p$family == "poisson") loss <- loss + unlist(p$log_factorial)[y+1] / 2^p$fraction_bits
    stopifnot(all(abs(loss-exact) <= as.numeric(p$loss_error)),
              max(loss) + as.numeric(p$loss_error) <= cap$per_patient_cap / 65536)
    z <- round(pmax(0, pmin(loss*65536, cap$per_patient_cap)))
    for (trial in seq_len(100)) {
      before <- sample(c(0,z), 16, replace = TRUE)
      after <- sample(c(0,z), 16, replace = TRUE)
      for (adjacency in 1:2) {
        difference <- if (adjacency == 1) after else after-before
        u <- rep(cap$per_patient_cap, 16)
        stopifnot(sum(abs(difference)) <= adjacency*sum(u),
                  sqrt(sum(difference^2)) <= adjacency*sqrt(sum(u^2)))
        checks <- checks + 1L
      }
    }
  }
}
cat("PASS:", checks, "synthetic adjacency checks; bounded binomial/Poisson objectives vs R distributions\n")
