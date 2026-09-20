.cox_synopsis_schema_fixture <- local({
  helpers <- new.env(parent = asNamespace("dsVert"))
  eval(parse(testthat::test_path("test-crossgrid-cox.R"))[[1L]], helpers)
  helpers$.cox_cross_server_fixture
})

test_that("Synopsis preserves signed Cox time/event contracts without Gaussian outcome resolution", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .cox_synopsis_schema_fixture(capacity = 4, owners = owners)
    policy <- f$policy
    policy$domain <- "cox-test"
    policy$cohort_id <- "cox-cohort"
    policy$datasets <- list(aligned = list(alignment_manifest_version = 1L))
    raw <- list(version = "cox_grid_cross_v1", dataset = "aligned", contract = f$contract)
    dataset <- f$schema_manifest$datasets$aligned
    bootstraps <- setNames(lapply(names(f$keys), function(peer) {
      local <- dataset[c("dataset_id", "dataset_version", "schema_version", "alignment_group")]
      local$patient_column <- "patient"
      local$alignment_protocol_version <- 1L
      local$columns <- Filter(function(column) identical(column$owner_peer, peer), dataset$columns)
      list(draft = list(version = .DSVERT_DP_CAPSULE_MANIFEST_DRAFT_VERSION,
        phase = "custodian_policy_draft", peer_name = peer,
        peer_identity_pk = unname(policy$peer_pinset[[peer]]),
        peer_pinset_sha256 = policy$peer_pinset_sha256,
        domain = policy$domain, cohort_id = policy$cohort_id,
        dataset_mapping_mode = "fixture", datasets = list(aligned = local),
        workload_fragments = list(gaussian = if (peer == "site_a") list(cox_grid = raw) else list()),
        data_access = FALSE, patient_derived_metadata = FALSE,
        operation_limit = NULL, request_limit = NULL, history_can_deny_operation = FALSE))
    }), names(f$keys))
    # Input bootstrap authenticity is tested by the signed DSLite run. Here only
    # the policy-context boundary is supplied; schema/snapshot resolution is real.
    result <- testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_manifest_schema_v1(bootstraps, policy),
      .dsvert_dp_synopsis_policy_context_v1 = function(...) list(pins = policy$peer_pinset),
      .package = "dsVert")
    expect_identical(result$workload$gaussian$cox_grid$spec,
      .dsvert_dp_canonical_query_value(raw))
    expect_null(result$workload$gaussian$cox_grid$spec$outcome)
    expect_identical(result$schema$datasets$aligned$columns,
      .dsvert_dp_canonical_query_value(dataset$columns))
    expect_identical(result$workload_sha256, .dsvert_joint_dp_hash(result$workload))
  }
})
