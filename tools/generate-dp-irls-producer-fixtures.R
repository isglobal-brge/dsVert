# Public synthetic ABI fixtures only; no source reads or aggregate openings.
pkgload::load_all(".", quiet = TRUE)
source("tests/testthat/helper-dp-irls-contract.R")
source("tests/testthat/helper-dp-irls-profile.R")
families <- c("binomial", "poisson")
certificates <- lapply(families, function(family) {
  certificate <- .dsvert_dp_irls_profile_certificate(family, "3", "64")
  list(certificate = certificate, digest = .dsvert_dp_irls_profile_digest(certificate))
})
writeLines(vapply(certificates, .dsvert_dp_irls_json, character(1L)),
  "inst/dsvert-mpc/testdata/dp_irls_certificate_v1.jsonl")
plans <- lapply(families, function(family) {
  f <- .irls_producer_fixture(family, "64")
  base <- tempfile("irls-plan-"); dir.create(base, mode = "0700")
  on.exit(unlink(base, recursive = TRUE), add = TRUE)
  path <- file.path(base, "peer_a", "reservations.sqlite")
  .dsvert_dp_irls_store_create(path, f$signed, f$pins, "peer_a")
  .dsvert_dp_irls_stage_plan(path, f$signed, f$pins, "0",
    .dsvert_dp_irls_start_digest(f$spec))
})
writeLines(vapply(plans, .dsvert_dp_irls_state_json, character(1L)),
  "inst/dsvert-mpc/testdata/dp_irls_signed_point_v1.jsonl")
