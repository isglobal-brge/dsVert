vertGLMDS <- function(X_partition, y, eta_partition, family, beta_partition, regularization = 1e-4) {
  n <- length(y)

  eta <- eta_partition + X_partition %*% beta_partition

  #change mean response based on family
  if (family$family == "gaussian") {
    mu <- eta
    W <- diag(1, n)
    z <- y
  } else if (family$family == "binomial") {
    mu <- 1 / (1 + exp(-eta))
    W <- diag(as.vector(mu * (1 - mu)))
    z <- eta + (y - mu) / (mu * (1 - mu))
  } else if (family$family == "poisson") {
    mu <- exp(eta)
    W <- diag(as.vector(mu))
    z <- eta + (y - mu) / mu
  } else {
    stop("Unsupported family")
  }

  #get new beta estimates regarding regularization
  XtWX <- t(X_partition) %*% W %*% X_partition
  XtWX <- XtWX + diag(regularization, nrow(XtWX))

  beta_update <- solve(XtWX, t(X_partition) %*% (W %*% (z - eta)))

  #again ran into large updates, so Im trying to prevent this. Maybe it is bad for certain data
  if (any(abs(beta_update) > 1e2)) {
    beta_update <- beta_update / max(abs(beta_update)) * 1e2
    message("Large beta update detected.")
  }

  beta_partition <- beta_partition + beta_update

  eta <- X_partition %*% beta_partition

  return(list(beta = beta_partition, eta = eta))
}
