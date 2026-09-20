pkgload::load_all('dsVert',quiet=TRUE)
e <- asNamespace('dsVert')
beta <- list(c(0,rep(1/32,3)),c(1/8,rep(1/32,3)))
rows <- list()
for (family in c('binomial_gee','poisson_gee')) for (g in c(16,8)) {
  for (correlation in c('independence','exchangeable','ar1')) for (rho in if (correlation=='independence') 0 else c(0,.25,.5)) {
    parameters <- list(correlation=correlation,rho=rho,score_clip=1,composition='staged_fixed_rho_v1')
    grouping <- list(max_patients_per_cluster=4,cluster_capacity=500)
    numeric <- e$.dsvert_dp_grouped_cross_numeric(family,grouping,parameters)
    s <- e$.dsvert_dp_grouped_cross_sensitivity(beta,family,if (family=='poisson_gee') 4 else 1,
      g,grouping,parameters,'add_remove_patient',numeric)
    grouping$cluster_capacity <- 1
    small <- e$.dsvert_dp_grouped_cross_sensitivity(beta,family,if (family=='poisson_gee') 4 else 1,
      g,grouping,parameters,'add_remove_patient',numeric)
    stopifnot(identical(s$raw_l1_sensitivity,small$raw_l1_sensitivity),identical(s$raw_l2_sensitivity,small$raw_l2_sensitivity))
    # The single admitted count contributes one natural-scale coordinate.
    l1 <- s$raw_l1_sensitivity+2^g
    l2 <- sqrt(s$raw_l2_sensitivity^2+2^(2*g))
    row <- list(family=family,grid_bits=g,correlation=correlation,rho=rho,
      gee_l1=s$raw_l1_sensitivity,gee_l2=s$raw_l2_sensitivity,
      count_plus_gee_l1=l1,count_plus_gee_l2=l2,
      count_plus_gee_natural_l1=l1/2^g,count_plus_gee_natural_l2=l2/2^g,
      coordinate_count=43,c500_sensitivity_same_as_c1=TRUE)
    if (correlation=='exchangeable' && rho==.25 && g==16) {
      # Actual retained selector/planner, public inputs only; no test substitution.
      selection <- e$.dsvert_dp_capsule_mechanism_selection(
        list(global_total_epsilon=8,global_total_delta=2^-100),43,l1,l2)
      row$selection <- selection
      cat('RETAINED_SELECTOR_RESULT',family,selection$mechanism,selection$certificate$decision,'\n')
    }
    rows[[length(rows)+1]] <- row
  }
}
jsonlite::write_json(rows,'dsVert/inst/cross-grid-v2/gee-fixed-rho/evidence/local/gee-public-mechanism-audit.json',auto_unbox=TRUE,pretty=TRUE,digits=NA,null='null')
print(do.call(rbind,lapply(rows,function(x) data.frame(family=x$family,g=x$grid_bits,correlation=x$correlation,rho=x$rho,l1=x$count_plus_gee_l1,l2=x$count_plus_gee_l2,natural_l2=x$count_plus_gee_natural_l2))))
