# Synthetic public-contract check, with real signatures and no MPC execution.
server_dir <- normalizePath(".")
pkgload::load_all(server_dir, quiet = TRUE)
stopifnot(is.null(getOption("dsvert.mpc_binary")))
for (expression in parse("tests/testthat/test-dp-glm-grid-cross-contract.R")) {
  if (is.call(expression) && identical(expression[[1L]], as.name("test_that"))) break
  eval(expression, envir = .GlobalEnv)
}
for (family in c("binomial", "poisson")) {
  fixture <- .cross_grid_contract_fixture(family, bits = 16, capacity = 2000)
  spec <- .dsvert_dp_glm_grid_cross_spec(
    fixture$raw, fixture$policy, fixture$authenticated, "piecewise_v2")
  artifact <- .dsvert_dp_glm_grid_cross_artifact(spec)
  signed <- fixture$sign(list(version = fixture$unsigned$version,
    spec = spec, artifact = artifact,
    source_contract = .dsvert_dp_glm_grid_cross_source_contract(spec, artifact)))
  valid <- callr::r(function(root, contract, policy, schema) {
    pkgload::load_all(root, quiet = TRUE)
    stopifnot(is.null(getOption("dsvert.mpc_binary")))
    dsVert:::.dsvert_dp_glm_grid_profile_admit(contract, policy, schema)
    TRUE
  }, args = list(server_dir, signed, fixture$policy, fixture$schema))
  stopifnot(isTRUE(valid))
  cat("COLD_SIGNED_PROFILE_ADMISSION_EQUAL", family, "n=2000\n")
}
