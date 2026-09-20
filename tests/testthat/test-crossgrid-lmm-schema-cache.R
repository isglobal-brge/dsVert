.lmm_schema_cache_policy <- local({
  helpers <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path("test-dp-synopsis-no-lifetime-red.R"))) {
    if (is.call(expression) && identical(expression[[1L]], as.name("<-")) &&
        as.character(expression[[2L]]) %in% c(
          ".synopsis_no_lifetime_b64url", ".synopsis_no_lifetime_policies")) {
      eval(expression, helpers)
    }
  }
  helpers$.synopsis_no_lifetime_policies
})

test_that("cold LMM schema lookup authenticates cached schema bytes and attestation", {
  f <- .lmm_handoff_fixture()
  policy <- .lmm_schema_cache_policy(2L)[[1L]]
  policy[names(f$policy)] <- f$policy
  policy$own_identity_pk <- unname(policy$peer_pinset[[policy$peer_name]])
  policy$patient_column <- "id"
  policy$datasets <- list(cohort = list(id = "cohort", version = "v1",
    snapshot_sha256 = NULL, alignment_manifest_hash = NULL, alignment_manifest_version = 1L))
  policy$numeric_bounds <- list(x = c(0, 1))
  policy$categorical_levels <- list(cluster = c("c1", "c2"))
  schema <- .dsvert_dp_capsule_schema(policy, f$schema$logical_snapshot,
    f$schema, .dsvert_relay_verify_message)
  f$manifest$workload$schema_attestation <- list(version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    manifest_sha256 = schema$sha256, signatures = schema$signatures, signers = schema$signers)
  manifest <- .dsvert_dp_canonical_query_value(f$manifest)
  manifest_json <- .dsvert_dp_canonical_json(manifest)
  manifest_sha256 <- digest::digest(manifest_json, algo = "sha256", serialize = FALSE)
  record <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION,
    cache_key = strrep("1", 64), public_capsule_key = strrep("2", 64),
    local_authority_sha256 = .dsvert_dp_synopsis_manifest_local_authority_v1(policy, f$secret),
    schema_sha256 = schema$sha256, workload_contract_sha256 = strrep("3", 64),
    manifest_sha256 = manifest_sha256, manifest_json = manifest_json,
    policy_snapshot = .dsvert_dp_synopsis_policy_snapshot_v1(policy), signed_schema = f$schema))
  .dsvert_dp_synopsis_manifest_cache_put_v1(policy, f$secret, record)
  read <- function() .dsvert_dp_lmm_cross_signed_schema(
    policy, f$secret, manifest_sha256, manifest)
  expect_identical(.dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(read())),
                   .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(f$schema)))
  expect_identical(.dsvert_dp_synopsis_cached_manifest_v1(manifest_sha256, policy, f$secret),
                   manifest_json)
  write_record <- function(value, valid_mac = TRUE) {
    json <- .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value))
    mac <- if (valid_mac) .dsvert_dp_synopsis_manifest_mac_v1(f$secret, "record", json) else strrep("0", 64)
    .dsvert_dp_synopsis_manifest_store_with_v1(policy, f$secret, function(con) {
      DBI::dbExecute(con, "UPDATE synopsis_manifests SET record_json=?, row_mac=? WHERE cache_key=?",
        params = list(json, mac, record$cache_key))
    })
  }
  legacy <- record; legacy$signed_schema <- NULL
  write_record(legacy)
  expect_identical(.dsvert_dp_synopsis_cached_manifest_v1(manifest_sha256, policy, f$secret),
                   manifest_json)
  expect_error(read())
  altered <- record
  altered$signed_schema$datasets$cohort$columns$cluster$levels <- c("c1", "different")
  write_record(altered)
  expect_error(read())
  altered <- record; altered$schema_sha256 <- strrep("4", 64)
  write_record(altered)
  expect_error(read())
  altered <- record; altered$signed_schema$signatures$peer_a <- strrep("a", 86)
  write_record(altered)
  expect_error(read())
  write_record(record, valid_mac = FALSE)
  expect_error(read(), "authentication")
  write_record(record)
  altered_manifest <- manifest
  altered_manifest$workload$schema_attestation$signatures$peer_a <- strrep("a", 86)
  expect_error(.dsvert_dp_lmm_cross_signed_schema(
    policy, f$secret, manifest_sha256, altered_manifest))
  expect_identical(.dsvert_dp_synopsis_cached_manifest_v1(manifest_sha256, policy, f$secret),
                   manifest_json)
})
