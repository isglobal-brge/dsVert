test_that("private GEE whitening assembly equals the independent R integer oracle", {
  eta <- vapply(c(-3,0,2), function(x) .cross_format(.cross_shift_left(.cross_small(x),64)), character(1))
  f <- matrix(vapply(c(.5,0,1), function(x) .cross_format(.cross_small(x*2^50)), character(1)),3,1)
  for (family in c("binomial","poisson")) for (correlation in c("independence","exchangeable","ar1")) {
    maximum <- if (family=="binomial") 1 else 4
    rho <- if (correlation=="independence") 0 else .5
    for (live in list(c(1,0,1),c(0,0,0),c(1,1,1))) {
      spec <- list(Slots=3L,Predictors=1L,GridBits=8L,Family=family,Correlation=correlation,
        RhoQ16=rho*65536,ScoreClipQ16=65536,RowLossCap=10000000,BreadCap=100000000,MaxOutcome=maximum)
      got <- .grouped_go_reference(list(Family="gee_whitening",Eta=as.list(eta),
        Features=lapply(f,function(x) list(x)),Outcome=as.list(c(maximum,0,0)),
        Live=as.list(live),GEE=spec,ClusterCap=100000000))
      expected <- .grouped_gee_whitening_integer(eta,f,c(maximum,0,0),live,
        family,correlation,rho,65536,100000000,100000000,8)
      expect_true(got$Valid)
      expect_equal(got$Values,expected,tolerance=0)
      # Independent real estimand, using a dense covariance solve only in this
      # public synthetic oracle. It does not reuse the whitening coefficients.
      X <- cbind(1,c(.5,0,1)); et <- c(-3,0,2); y <- c(maximum,0,0)
      mu <- if (family=="binomial") plogis(et) else exp(et)
      variance <- if (family=="binomial") mu*(1-mu) else mu
      U <- X*sqrt(variance); z <- (y-mu)/sqrt(variance)
      precision <- matrix(0,3,3); idx <- which(live==1)
      if (length(idx)) {
        covariance <- if (correlation=="independence") diag(length(idx)) else {
          if (correlation=="exchangeable") {
            value <- matrix(rho,length(idx),length(idx)); diag(value) <- 1; value
          } else rho^abs(outer(idx,idx,"-"))
        }
        precision[idx,idx] <- solve(covariance)
      }
      score <- pmax(-1,pmin(1,drop(t(U)%*%precision%*%z)))
      bread <- t(U)%*%precision%*%U
      meat <- 1+tcrossprod(score)
      upper <- upper.tri(bread,diag=TRUE)
      shift <- if (correlation=="independence") 0 else 100000000/256
      loss <- if (family=="binomial") log1p(exp(et))-y*et else exp(et)-y*et+lgamma(y+1)
      target <- c(max(0,min(100000000/256,sum(loss[live==1]))),
        pmax(0,pmin(100000000/256+shift,bread[upper]+shift)),meat[upper])
      bounds <- c(got$ErrorBounds$likelihood,rep(got$ErrorBounds$bread,3),rep(got$ErrorBounds$meat,3))
      expect_true(all(abs(got$Values/256-target) <= bounds))
      signed <- .dsvert_dp_grouped_gee_errors(paste0(family,"_gee"),3,1)
      expect_true(all(unlist(signed)[names(got$ErrorBounds)] >= unlist(got$ErrorBounds)))
      expect_equal(unlist(signed)[names(got$ErrorBounds)],unlist(got$ErrorBounds),tolerance=1e-12)
    }
  }
})

test_that("GEE v3 certificate is bound into both signed validators", {
  for (family in c("binomial_gee","poisson_gee")) {
    grouping <- list(max_patients_per_cluster=8)
    parameters <- list(score_clip=4)
    server <- .dsvert_dp_grouped_cross_numeric(family,grouping,parameters)
    client <- get(".dsvert_dp_grouped_grid_cross_numeric",asNamespace("dsVertClient"))(family,grouping,parameters)
    expect_identical(server,client)
    expect_identical(server$profile,"grouped-gee-whitening-f96-q64-v3")
    expect_equal(server$per_cluster_error_bound,max(unlist(server$coordinate_error_bounds)))
    expect_false(identical(server$per_cluster_error_bound,1))
  }
})
