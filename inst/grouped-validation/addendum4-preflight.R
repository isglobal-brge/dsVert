# Run from the workspace root; supply the tag-only reference binary.
stopifnot(nzchar(Sys.getenv('DSVERT_GROUPED_REFERENCE_BINARY')))
devtools::load_all('dsVert', quiet=TRUE)
source('dsVert/tests/testthat/helper-cross-grid-integer.R')
source('dsVert/tests/testthat/helper-grouped-integer.R')
source('dsVert/tests/testthat/helper-grouped-contract.R')
for (name in c('test-crossgrid-grouped.R','test-crossgrid-grouped-integer.R','test-crossgrid-lmm-stats-integer.R')) {
 result <- as.data.frame(testthat::test_file(file.path('dsVert/tests/testthat',name),reporter='silent'))
 cat(name, 'passed=',sum(result$passed),'failed=',sum(result$failed),'errors=',sum(result$error),'warnings=',sum(result$warning),'\n')
 stopifnot(!any(result$failed),!any(result$error),!any(result$warning))
}
records <- list()
for (family in c('lmm','binomial_glmm','binomial_gee')) {
 f <- .grouped_contract_fixture(family)
 for (n in c(2000L,4000L,10000L)) for (m in c(16L,32L,50L)) {
  raw <- f$raw
  policy <- f$policy
  policy$unit_capacity <- n
  raw$grouping$cluster_capacity <- n/10L
  raw$grouping$max_patients_per_cluster <- 10L
  raw$beta_grid <- lapply(seq_len(m),function(j) c(j/(4*m),.25))
  rejected <- tryCatch({.dsvert_dp_grouped_cross_spec(raw,policy,f$authenticated);FALSE},error=function(e) {
   stopifnot(inherits(e,'dsvert_dp_public_failure'),identical(conditionMessage(e),.DSVERT_DP_PUBLIC_FAILURE_MESSAGE));TRUE
  })
  stopifnot(rejected)
  records[[length(records)+1L]] <- list(family=family,n=n,grid=m,cluster_slots=n/10L,rows_per_cluster=10L,Q=if(family=='binomial_glmm') 5L else NULL,status='signed_shape_rejected_not_measured',two_direction_bytes=NULL,elapsed_seconds=NULL,admitted=FALSE)
 }
}
jsonlite::write_json(list(scope='Public signed-shape preflight, NOT a release benchmark or cost extrapolation',source_commit=system('git -C dsVert rev-parse HEAD',intern=TRUE),ceiling_bytes=110e9,ceiling_seconds=14400,matrix=records), 'dsVert/inst/grouped-validation/addendum4-preflight.json',pretty=TRUE,auto_unbox=TRUE,null='null')
cat('Public matrix preflight: 27/27 fail closed; no resource measurement\n')
