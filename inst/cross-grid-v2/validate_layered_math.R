#!/usr/bin/env Rscript
# Public synthetic fixtures only; no server or DataSHIELD call is made here.
root <- normalizePath(if (length(commandArgs(TRUE))) commandArgs(TRUE)[[1]] else "..")
server <- file.path(root, "dsVert")
build <- file.path(server, "inst/cross-grid-v2/build")
certificate <- jsonlite::fromJSON(file.path(server, "inst/cross-grid-v2/admission_certificate.json"), simplifyVector = FALSE)
binary <- file.path(build, "cross-grid-oracle.test")
stopifnot(file.exists(binary))
rows <- list()
for (family in c("binomial", "poisson")) for (instance in 1:20) {
  set.seed(20260918 + instance)
  n <- 2000L
  x <- matrix(runif(n * 6), n, 6)
  truth <- c(-0.5, 0.5, -0.25, 0.25, 0.5, -0.25, 0.25)
  eta <- drop(cbind(1, x) %*% truth)
  maximum <- if (family == "binomial") 1L else 16L
  y <- if (family == "binomial") rbinom(n, 1, plogis(eta)) else pmin(maximum, rpois(n, exp(eta)))
  beta <- list(truth + c((instance-1)/1024, rep(0,6)), truth + c(0.25+(instance-1)/1024,rep(0,6)))
  beta <- beta[order(vapply(beta, function(b) jsonlite::toJSON(as.list(b), auto_unbox=TRUE, digits=NA), character(1)), method="radix")]
  a <- c(1,2,4,8,16)[which(vapply(c(1,2,4,8,16), function(a) all(vapply(beta,function(b)sum(abs(b))<=a,logical(1))),logical(1)))[[1]]]
  entry <- certificate$caps18[[match(a,c(1,2,4,8,16))]]
  cap <- ceiling((if (family == "binomial") entry$binomial_cap18 else entry$poisson_caps18[[maximum]])/4)
  plan <- list(Family=family, Rows=32, Predictors=6, Owners=2, A=a, GridBits=16, MaxOutcome=maximum,
    Beta=lapply(beta,function(b)as.list(sprintf("%.0f",round(b*2^50)))), Caps=as.list(rep(cap,2)))
  values <- cbind(round(x*2^50),y)
  input <- tempfile(tmpdir=build,fileext=".json")
  output <- tempfile(tmpdir=build,fileext=".json")
  fixture <- list(Plan=plan, Rows=lapply(seq_len(n),function(i)as.list(sprintf("%.0f",values[i,]))),Draws=list(),Output=output)
  writeLines(jsonlite::toJSON(fixture,auto_unbox=TRUE,digits=NA),input)
  result <- processx::run(binary,c("-test.run=^TestCrossGridLayeredOracle$"),
    env=c(DSVERT_CROSS_ORACLE_FIXTURE=input))
  stopifnot(result$status==0)
  exact <- as.numeric(unlist(jsonlite::fromJSON(output)$Exact))/2^16
  python <- Sys.getenv("DSVERT_CERTIFICATE_PYTHON", if (file.exists(
    "/opt/homebrew/opt/python@3.11/bin/python3.11")) "/opt/homebrew/opt/python@3.11/bin/python3.11" else "python3")
  high_output <- tempfile(tmpdir=build,fileext=".json")
  processx::run(python,c(file.path(server,"inst/cross-grid-v2/validate_high_precision.py"),input,high_output))
  high <- as.numeric(jsonlite::fromJSON(high_output))
  unlink(c(input,output,high_output))
  fam <- if(family=="binomial") stats::binomial() else stats::poisson()
  independent <- vapply(beta,function(b) {
    mu <- fam$linkinv(drop(cbind(1,x)%*%b))
    sum(fam$dev.resids(y,mu,rep(1,n)))/2 + if(family=="poisson")
      sum(y-ifelse(y==0,0,y*log(pmax(y,1)))+lgamma(y+1)) else 0
  },numeric(1))
  fit <- stats::glm.fit(cbind(1,x),y,family=fam)
  error <- if(family=="binomial") entry$binomial_error else entry$poisson_error
  tolerance <- n*(as.numeric(error)+0.5/2^16+2^-44)
  stopifnot(max(abs(exact-high))<=tolerance, max(abs(independent-high))<1e-8, max(abs(exact-independent))<=tolerance, all(exact<=n*cap/2^16),all(exact>=0))
  rows[[length(rows)+1L]] <- data.frame(family,instance,n,p=6,candidates=2,
    max_absolute_error=max(abs(exact-independent)),
    max_high_precision_error=max(abs(exact-high)),r_reference_error=max(abs(independent-high)),certified_tolerance=tolerance,
    l1=2*cap,l2=sqrt(2*cap^2),pooled_glm_converged=fit$converged)
}
report <- do.call(rbind,rows)
path <- file.path(server,"inst/cross-grid-v2/layer1-objective-evidence.json")
writeLines(jsonlite::toJSON(list(version="cross-grid-layer1-synthetic-v2",cases=report,
  candidate_evaluations=80,all_within_certificate=TRUE),auto_unbox=TRUE,pretty=TRUE,digits=NA),path)
cat("LAYER1_OBJECTIVE_PASS cases=40 candidates=80 n=2000 p=6\n")
