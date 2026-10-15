# Synthetic-only independent glm/finite-step comparison. The input is emitted
# by TestDPIRLSB2NoiselessIteration, which invokes the actual B1 Go updater.
args <- commandArgs(trailingOnly=TRUE)
if (length(args)!=1L) stop("usage: Rscript tools/test-dp-irls-b2-iteration.R evidence.json")
items <- jsonlite::fromJSON(args[[1]], simplifyVector=FALSE)
rat <- function(v) as.numeric(v$n)/as.numeric(v$d)
results <- lapply(items,function(item) {
  X <- do.call(rbind,lapply(item$rows,function(r) unlist(r$x)))/65536
  y <- vapply(item$rows,function(r) r$y,numeric(1))
  offset <- vapply(item$rows,function(r) r$offset,numeric(1))/65536
  stopifnot(nrow(X)==64L,ncol(X)==3L,all(X[,1]==1),
            identical(unname(crossprod(X)),diag(c(64,16,16))),
            max(abs(offset))==1/8)
  family <- if(item$family=="binomial") binomial() else poisson()
  fit <- glm(y ~ X - 1,family=family,offset=offset,
             control=glm.control(epsilon=1e-12,maxit=100L))
  stopifnot(fit$converged,all(is.finite(fit$coefficients)))
  oracle_path <- do.call(rbind,lapply(item$path_q16,unlist))/65536
  ideal_path <- matrix(0,nrow=item$iterations+1L,ncol=3L)
  for(i in seq_len(item$iterations)) {
    beta <- ideal_path[i,]
    mu <- family$linkinv(drop(X%*%beta)+offset)
    w <- if(item$family=="binomial") mu*(1-mu) else mu
    g <- drop(crossprod(X,y-mu))
    H <- crossprod(X,w*X)
    # Same public damping/ridge/trust/box as the signed B1 fixture, but exact
    # links and no integer output or coefficient rounding, to isolate T error.
    step <- solve(H,g)
    stopifnot(max(abs(step))<=1,all(abs(beta+step)<1))
    ideal_path[i+1L,] <- beta+step
  }
  cert <- item$certificate
  n <- nrow(X)
  terminal_g <- (as.numeric(unlist(item$terminal_translated_q12)[1:3])-
                 as.numeric(cert$g_translation))/4096
  # On the WHOLE signed box |beta_j|<=1, every fixture |eta|<=17/8.
  # e < sum_{k=0}^3 1/k! + (1/24)/(1-1/5) = 87/32 < 11/4.
  # (11/4)^17 < 9^8 is checked with integers, proving exp(17/8)<9.
  # Thus logit variance >=9/100>1/16,
  # and Poisson variance >=1/9>1/16. X'X=diag(64,16,16), so H>=I.
  # The exact score at the oracle endpoint is bounded by its integer score
  # plus the signed per-coordinate error; strong monotonicity then bounds
  # distance to the exact interior glm root. No empirical error threshold.
  curvature_lower <- 1
  stopifnot(gmp::as.bigz(11)^17 < gmp::as.bigz(9)^8*gmp::as.bigz(4)^17,
            rat(item$box_magnitude)==1)
  numeric_score_bound <- sqrt(3)*n*rat(cert$score_coordinate_error)
  radius <- (sqrt(sum(terminal_g^2))+numeric_score_bound)/curvature_lower
  endpoint <- oracle_path[nrow(oracle_path),]
  glm_error <- sqrt(sum((endpoint-fit$coefficients)^2))
  finite_step <- sqrt(sum((ideal_path[nrow(ideal_path),]-fit$coefficients)^2))
  numeric_difference <- sqrt(sum((endpoint-ideal_path[nrow(ideal_path),])^2))
  stopifnot(glm_error<=radius,
            glm_error<sqrt(sum((oracle_path[1,]-fit$coefficients)^2)),
            all(abs(fit$coefficients)<1),
            max(abs(drop(X%*%endpoint)+offset))<4)
  data.frame(family=item$family,n=n,T=item$iterations,
             oracle_vs_glm_l2=glm_error,finite_T_vs_glm_l2=finite_step,
             link_lattice_vs_ideal_T_l2=numeric_difference,
             terminal_integer_score_l2=sqrt(sum(terminal_g^2)),
             certified_score_error_l2=numeric_score_bound,
             certified_curvature_lower=curvature_lower,
             certified_endpoint_radius=radius)
})
print(do.call(rbind,results),digits=12,row.names=FALSE)
