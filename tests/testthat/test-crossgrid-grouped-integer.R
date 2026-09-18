test_that("pure R grouped integer oracles equal tagged Go references", {
  q <- "18446744073709551616"
  fixture <- list(Family="lmm",Residual=list(q,q),Live=list(1,1),Sigma=q,Tau=q,
    LMM=list(Slots=2,GridBits=8,ResidualCap=2,OutputCap=2048))
  got <- .grouped_go_reference(fixture)
  expect_true(got$Valid)
  expect_equal(as.character(got$Values),.grouped_lmm_integer(c(q,q),c(1,1),q,q,2048,8))
  for (family in c("binomial","poisson")) for (variance in c(0,.25)) {
    fixture <- list(Family="glmm",Eta=list(paste0("-",q),q),Live=list(1,1),Outcome=list(0,1),
      GLMM=list(Family=family,Rows=2,OutputBits=16,VarianceQ16=variance*65536))
    got <- .grouped_go_reference(fixture)
    expect_true(got$Valid)
    expect_equal(as.character(got$Values),.grouped_glmm_integer(
      c(paste0("-",q),q),c(0,1),c(1,1),family,variance,2^30,16))
  }
  for (family in c("binomial","poisson")) for (correlation in c("independence","exchangeable","ar1")) {
    rho <- if(correlation=="independence") 0 else .25
    eta <- c(paste0("-",q),"0",q); f <- rep("562949953421312",3)
    fixture <- list(Family="gee",Eta=as.list(eta),Features=lapply(f,function(x) list(x)),
      Live=list(1,0,1),Outcome=list(0,1,1),GEE=list(Slots=3,Predictors=1,GridBits=16,
      Family=family,Correlation=correlation,RhoQ16=rho*65536,ScoreClipQ16=65536,
      RowLossCap=2^24,BreadCap=2^24,MaxOutcome=if(family=="binomial") 1 else 4))
    got <- .grouped_go_reference(fixture)
    expect_true(got$Valid)
    expect_equal(got$Values,.grouped_gee_integer(eta,matrix(f,3),c(0,1,1),c(1,0,1),
      family,correlation,rho,65536,16,2^24,2^24))
  }
})


test_that("range-reduced exp R and tagged Go agree at exponent and knot boundaries", {
  x <- unique(c(-1048576, 262144, 0,
    as.vector(outer((-23:6)*45426, c(-22714,-22713,-22712,22712,22713,22714), `+`)),
    as.vector(outer((-23:6)*45426, seq(-22528,22528,by=1024), `+`))))
  for (name in c("exp", "exp_negative")) {
    lo <- if(name == "exp") -262144 else -1048576
    hi <- if(name == "exp") 262144 else 0
    inputs <- x[x>=lo & x<=hi]
    got <- .grouped_go_reference(list(Family="profile",Profile=name,InputQ16=as.list(inputs)))
    expect_true(got$Valid)
    expected <- vapply(inputs,.grouped_profile,numeric(1),name=name)
    expect_equal(got$Values,expected)
    bound <- if(name == "exp") .0055 else .00013
    expect_lte(max(abs(expected/65536-exp(inputs/65536))),bound)
    expect_error(.grouped_profile(lo-1,name))
    expect_error(.grouped_profile(hi+1,name))
  }
})
