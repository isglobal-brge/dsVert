test_that("GEE public admission binds fixed correlation and rejects legacy and LMM swaps", {
  for (family in c("binomial_gee", "poisson_gee")) for (owners in c(2L, 3L, 5L)) {
    f <- .lmm_handoff_fixture(owners, family, staged_gee = TRUE)
    admitted <- .dsvert_dp_glm_grid_profile_admit(f$contract, f$policy, f$schema)
    expect_identical(admitted$spec$family, family)
    expect_identical(admitted$artifact$correlation_contract, "signed-analyst-fixed-rho-v1")
    expect_named(.dsvert_dp_glm_grid_cross_artifacts(f$manifest), "grouped")
    expect_identical(.dsvert_dp_capsule_gaussian_spec(f$policy, "grouped",
      list(grouped = list(version = paste0(family, "_grid_cross_v1"), dataset = "cohort",
        contract = f$contract)))$kind, "lmm_grid_cross")
    outcome <- f$layout$blocks[["grouped::peer_b$y::value"]]
    route <- f$layout$blocks[["grouped::peer_a$cluster::value"]]
    expect_equal(outcome$fraction_bits, 0)
    expect_equal(outcome$maximum, if (family == "binomial_gee") 1 else 4)
    expect_identical(route$owner_peer, "peer_a")
    expect_identical(outcome$owner_peer, "peer_b")
    old <- .grouped_contract_fixture(family, owners = owners)
    expect_error(.dsvert_dp_glm_grid_profile_admit(old$contract, old$policy, old$schema))
    for (mutate in list(
        function(x) { x$artifact$version <- "bounded-lmm-cross-grid-v1"; x },
        function(x) { x$source_contract$purpose <- "lmm"; x },
        function(x) { x$spec$numeric_contract$correlation_contract <- "estimated-alpha-v1"; x },
        function(x) { x$spec$staged_numeric$RhoQ16 <- "16384"; x })) {
      expect_error(.dsvert_dp_glm_grid_profile_admit(f$sign(mutate(f$contract)),
        f$policy, f$schema), class = "dsvert_dp_public_failure")
    }
  }
})

test_that("ordinary local GEE materialization leaves its release block zero for every source owner", {
  local_mocked_bindings(
    .dsvert_dp_capsule_materializer_manifest = function(policy, manifest) {
      list(manifest = manifest, layout = .dsvert_dp_capsule_coordinate_layout(manifest),
        identity = list(capsule_id = manifest$capsule_identity$capsule_id))
    },
    .dsvert_joint_dp_vector_lattice_vectors = function(validated) {
      list(raw_upper_bounds = as.character(c(8,
        unlist(validated$manifest$workload$families$gaussian_models$artifacts$grouped$statistic_maximum))))
    })
  for (family in c("binomial_gee", "poisson_gee")) {
    f <- .lmm_handoff_fixture(5L, family, staged_gee = TRUE)
    policy <- f$policy
    policy$datasets <- list(cohort = list(id = "synthetic", version = "v1"))
    policy$patient_column <- "id"
    policy$max_records_per_unit <- 1L
    policy$overflow_policy <- "reject_snapshot"
    # No outcome or covariate column exists locally in this fixture. Ordinary
    # materialization must not read those inputs or compute any GEE moment.
    snapshots <- list(cohort = list(data = data.frame(id = c("u1", "u2")),
      dataset = list(public = list(data_name = "cohort", id = "synthetic", version = "v1"),
        fingerprint = strrep("a", 64))))
    for (peer in names(policy$peer_pinset)) {
      policy$peer_name <- peer
      material <- .dsvert_dp_capsule_materialize_local(policy, f$manifest, snapshots)
      expect_equal(material$values[-1L], rep(0, f$artifact$coordinate_count))
      expect_equal(material$values[[1L]], if (peer == "peer_a") 2 else 0)
      expect_identical(material$state, "internal_unshared_secret_share_input_never_release")
    }
  }
})
