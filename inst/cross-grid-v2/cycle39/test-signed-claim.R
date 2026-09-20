test_that("Signed Cox Claim commitment agrees with the sharing validator", {
  f <- .cox_cross_server_fixture(capacity = 5, owners = 2L)
  t <- .cox_transport_fixture(f)
  secret <- as.raw(seq_len(32))
  fixture <- .synopsis_test_fixture()
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(fixture$policy, fixture$manifest)
  layout <- .dsvert_dp_capsule_coordinate_layout(t$manifest)
  projection$catalog$coordinate_count <- layout$coordinate_count
  projection$catalog$coordinate_order_sha256 <- layout$sha256
  projection$catalog$peer_pinset_sha256 <- .dsvert_dp_synopsis_pinset_hash_v1(f$policy$peer_pinset)
  projection$sha256 <- .dsvert_dp_synopsis_catalog_hash_v1(projection$catalog)
  projection <- .dsvert_dp_synopsis_catalog_projection_validate_v1(projection)
  namespace <- t$transport
  namespace$synopsis_binding <- list(version = .DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION,
    manifest_capsule_id = t$transport$capsule_id, artifact_key = strrep("d", 64),
    source_claim_set_sha256 = strrep("e", 64))
  namespace$capsule_id <- .dsvert_dp_synopsis_source_namespace_id_v1(namespace$synopsis_binding)
  local_mocked_bindings(
    .dsvert_dp_synopsis_catalog_projection_v1 = function(...) projection,
    .dsvert_dp_analysis_snapshot_key_v1 = function() secret,
    .dsvert_dp_secret = function() secret,
    .dsvert_dp_capsule_source_contract = function(...) t$transport,
    .dsvert_dp_lmm_cross_signed_schema = function(...) f$schema_manifest)
  for (peer in c("site_a", "site_b")) {
    data <- data.frame(patient = c("b", "a", "d", "c"), time = c(5, 2, Inf, 5),
      event = c(0, 1, 1, 0), x = c(.5, 0, Inf, 1), z = c(1, .25, NA, 0))
    resolved <- .cox_resolved_fixture(f, data, peer)
    policy <- resolved$policy
    claim <- .dsvert_dp_synopsis_source_vector_claim_v1(policy, t$manifest,
      resolved$snapshots, list(identity_pk = unname(policy$peer_pinset[[peer]]), identity_sk = "fixture"),
      .signer = function(message, key) f$b64(openssl::ed25519_sign(message, f$keys[[peer]])))
    expect_identical(.dsvert_dp_synopsis_source_vector_claim_validate_v1(claim, projection,
      policy$peer_pinset), claim)
    local_mocked_bindings(.dsvert_dp_synopsis_source_transport_context_v1 = function(...) {
      list(source_contract = namespace, manifest_json = "fixture", local_claim = claim)
    })
    gate <- .dsvert_dp_synopsis_source_transport_gate_v1("fixture", NULL, NULL, NULL,
      .policy = policy, .secret = secret)
    producer <- gate$materializer(policy, t$manifest, resolved$snapshots, TRUE, TRUE)
    expect_true(gate$producer_validator(producer, policy, t$manifest, namespace))
    changed <- producer
    changed$read_range <- function(start, count) {
      result <- producer$read_range(start, count)
      result[1] <- result[1] + 1
      result
    }
    expect_false(gate$producer_validator(changed, policy, t$manifest, namespace))
    tampered <- claim; tampered$source_vector_commitment <- strrep("f", 64)
    expect_error(.dsvert_dp_synopsis_source_vector_claim_validate_v1(tampered, projection,
      policy$peer_pinset), "signature verification")
  }
})
