# Synthetic-only two-peer comparison. This exercises contracts, source alignment,
# tagged integer evaluation and client selection; it is NOT release promotion.
test_that("two DSLite peers compare grouped candidates at epsilon 1 4 8", {
  skip_if(!nzchar(Sys.getenv("DSVERT_GROUPED_REFERENCE_BINARY")), "tagged reference required")
  skip_if_not_installed("DSLite"); skip_if_not_installed("lme4")
  skip_if_not_installed("geepack"); skip_if_not_installed("dsVertClient")
  client_path <- normalizePath(file.path(test_path(),"..","..","..","dsVertClient","R"),mustWork=FALSE)
  skip_if(!file.exists(file.path(client_path,"dp_grouped_grid_cross.R")),"paired client source required")
  client <- new.env(parent=asNamespace("dsVertClient"))
  for(file in list.files(client_path,pattern="[.]R$",full.names=TRUE)) sys.source(file,client)
  set.seed(4927)
  n <- 24L; x <- runif(n); cluster <- rep(seq_len(6),each=4)
  # Explicitly public synthetic fixtures; identity is never registered by dsVert.
  config <- list(AggregateMethods=data.frame(name="syntheticGroupedReference",
    value="base::identity",package="base",version=as.character(getRversion()),
    type="aggregate",class="function"),AssignMethods=data.frame(),Options=list())
  peer <- function(data) {
    server <- DSLite::newDSLiteServer(tables=list(D=data),config=config,strict=TRUE)
    id <- server$newSession(profile="default");server$assignTable(id,"D","D")
    server$aggregate(id,quote(syntheticGroupedReference(D)))
  }
  left <- peer(data.frame(id=seq_len(n),cluster=cluster))
  right <- peer(data.frame(id=seq_len(n),x=x))
  expect_identical(left$id,right$id)
  beta <- list(c(-.25,.5),c(0,0),c(.25,.5))
  q64 <- function(v) .cross_format(.cross_shift_left(.cross_small(round(v*2^16)),48))
  f50 <- vapply(x,function(v) .cross_format(.cross_small(round(v*2^50))),character(1L))
  result <- list()
  for (family in c("lmm","binomial_glmm","poisson_glmm","binomial_gee","poisson_gee")) {
    fixture <- .grouped_contract_fixture(family,"exchangeable")
    fixture$policy$unit_capacity <- n
    fixture$raw$grouping$cluster_capacity <- 6
    spec <- .dsvert_dp_grouped_cross_spec(fixture$raw,fixture$policy,fixture$authenticated)
    artifact <- .dsvert_dp_grouped_cross_artifact(spec)
    poisson <- startsWith(family,"poisson")
    y <- if(family=="lmm") pmin(1,pmax(0,.25+.5*x+rnorm(n,sd=.1))) else
      if(poisson) pmin(4,rpois(n,exp(.25+.5*x))) else rbinom(n,1,plogis(.25+.5*x))
    data <- data.frame(y=y,x=right$x,cluster=factor(left$cluster))
    fit <- suppressWarnings(if(family=="lmm") lme4::lmer(y~x+(1|cluster),data=data) else
      if(grepl("glmm$",family)) lme4::glmer(y~x+(1|cluster),data=data,
        family=if(poisson) stats::poisson() else stats::binomial()) else
      geepack::geeglm(y~x,id=left$cluster,data=data,corstr="exchangeable",
        family=if(poisson) stats::poisson() else stats::binomial()))
    central <- if(grepl("gee$",family)) stats::coef(fit) else lme4::fixef(fit)
    expect_true(all(is.finite(central)))
    losses <- exact_losses <- numeric(3)
    for(j in seq_along(beta)) for(c in seq_len(6)) {
      idx <- which(cluster==c);eta <- beta[[j]][1]+beta[[j]][2]*x[idx]
      if (family=="lmm") {
        residual <- y[idx]-eta
        exact_losses[j] <- exact_losses[j]+sum(residual^2)-.25/(1+length(idx)*.25)*sum(residual)^2
      } else if(grepl("glmm$",family)) {
        nodes <- c(-2.856970013872806,-1.355626179974266,0,1.355626179974266,2.856970013872806)*.5
        weights <- c(.01125741132772069,.2220759220056126,.5333333333333333,.2220759220056126,.01125741132772069)
        logterms <- vapply(seq_along(nodes),function(q) {
          t <- eta+nodes[q]
          log(weights[q])-sum(if(poisson) exp(t)-y[idx]*t+lgamma(y[idx]+1) else log1p(exp(t))-y[idx]*t)
        },numeric(1L))
        maximum <- max(logterms)
        exact_losses[j] <- exact_losses[j]-maximum-log(sum(exp(logterms-maximum)))
      } else exact_losses[j] <- exact_losses[j]+sum(if(poisson) exp(eta)-y[idx]*eta+lgamma(y[idx]+1) else log1p(exp(eta))-y[idx]*eta)
      r <- list(Eta=as.list(vapply(eta,q64,character(1L))),Live=as.list(rep(1,4)),Outcome=as.list(y[idx]))
      if(family=="lmm") {
        r$Outcome <- NULL;r$Family <- "lmm_stats"
        encode50 <- function(v) .cross_format(.cross_small(round(v*2^50)))
        r$Beta <- as.list(vapply(beta[[j]], encode50, character(1L)))
        r$Features <- lapply(idx, function(i) list(encode50(1), f50[i], encode50(y[i])))
        r$Sigma <- q64(1);r$Tau <- q64(.25)
        r$LMM <- list(Slots=4,GridBits=16,ResidualCap=2,OutputCap=2^24)
      } else if(grepl("glmm$",family)) {
        r$Family <- "glmm";r$GLMM <- list(Family=if(poisson) "poisson" else "binomial",Rows=4,OutputBits=16,VarianceQ16=16384)
      } else {
        r$Family <- "gee_whitening";r$ClusterCap <- 4*2^24;r$Features <- lapply(f50[idx],function(v) list(v))
        r$GEE <- list(Slots=4,Predictors=1,GridBits=16,Family=if(poisson) "poisson" else "binomial",
          Correlation="exchangeable",RhoQ16=16384,ScoreClipQ16=65536,RowLossCap=2^24,BreadCap=2^24,MaxOutcome=if(poisson) 4 else 1)
      }
      answer <- .grouped_go_reference(r);expect_true(answer$Valid)
      losses[j] <- losses[j]+answer$Values[1]/65536
    }
    # Synthetic calibration deliberately protects the complete vector by its
    # clamped range, including all bread/meat coordinates for GEE. Each authority
    # adds a full Laplace mechanism; no privacy amplification is assumed.
    U <- if(grepl("gee$",family)) 4*256+3*512+3*2 else if(family=="lmm") 256 else 4*32+1
    delta1 <- 3*U
    exact <- which.min(exact_losses)
    for(epsilon in c(1,4,8)) {
      laplace <- function() {u<-runif(3,-.5,.5);-delta1/epsilon*sign(u)*log1p(-2*abs(u))}
      released <- losses+laplace()+laplace()
      maxima <- unlist(spec$sensitivity$maximum_coordinates,use.names=FALSE)
      coordinates <- numeric(length(maxima))
      width <- length(maxima)/3
      coordinates[seq.int(1,length(maxima),by=width)] <- round(pmax(0,released)*65536)
      coordinates <- pmin(maxima,coordinates)
      selected_result <- client$.dsvert_dp_grouped_grid_cross_moment(coordinates,spec,artifact)
      selected <- selected_result$selected_candidate
      expect_true(selected %in% 1:3)
      result[[length(result)+1L]] <- data.frame(family=family,epsilon=epsilon,
        selected=selected,exact_best=exact,reference_regret=exact_losses[selected]-min(exact_losses),
        profile_error=max(abs(losses-exact_losses)),
        coefficient_distance=sqrt(sum((beta[[selected]]-central)^2)))
    }
  }
  results <- do.call(rbind,result)
  expect_equal(nrow(results),15L)
  path <- Sys.getenv("DSVERT_GROUPED_COMPARISON_OUTPUT")
  if(nzchar(path)) jsonlite::write_json(results,path,pretty=TRUE,auto_unbox=TRUE,digits=NA)
})
