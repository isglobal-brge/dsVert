test_that("legacy vector ACK and RESULT replay use durable contracts without replanning", {
  instance <- list(peer_noise_roots = list(noise_a = list(), noise_b = list()))
  manifest <- "legacy-signed-manifest"
  contract <- list(
    capsule_id = strrep("a", 64L),
    release_instance_id = .dsvert_joint_dp_hash(instance),
    mechanism = "discrete-laplace",
    backend = .DSVERT_JOINT_DP_VECTOR_BACKEND,
    sampler = .DSVERT_JOINT_DP_VECTOR_SAMPLER)
  record <- list(
    capsule_id = contract$capsule_id,
    release_instance_id = contract$release_instance_id,
    release_contract = contract,
    release_contract_hash = .dsvert_joint_dp_hash(contract),
    transcript_hash = strrep("b", 64L),
    plan = list(version = .DSVERT_JOINT_DP_VECTOR_PLAN_VERSION),
    designated = list("noise_a", "noise_b"),
    manifest_sha256 = digest::digest(manifest, algo = "sha256", serialize = FALSE),
    ack_receipt_json = "historical-signed-ack")
  receipt <- .dsvert_joint_dp_vector_encode(list(
    release_instance = instance,
    release_instance_id = contract$release_instance_id))
  legacy <- .dsvert_joint_dp_vector_contract_from_record(record)
  for (has_release in c(TRUE, FALSE)) {
    checked <- FALSE
    manifest_checked <- FALSE
    actual <- testthat::with_mocked_bindings(
      .dsvert_joint_dp_vector_ack_impl(
        manifest, receipt, receipt,
        .policy = list(peer_name = if (has_release) "noise_a" else "source_only"),
        .secret = "test",
        .planner = function(...) stop("legacy ACK must not replan"),
        .source_compactor = function(...) stop("legacy ACK must not compact again")),
      .dsvert_joint_dp_vector_instance_claim_preflight = function(...) TRUE,
      .dsvert_dp_capsule_manifest_require_built = function(policy, manifest_json, secret) {
        expect_identical(manifest_json, manifest)
        manifest_checked <<- TRUE
      },
      .dsvert_joint_dp_vector_existing_release = function(...) {
        if (!has_release) stop("source-only ACK must not enter designated-peer release lookup")
        list(record = record, contract = legacy)
      },
      .dsvert_joint_dp_vector_with_store = function(policy, secret, code) code(NULL),
      .dsvert_joint_dp_vector_capsule_load = function(connection, id, secret) {
        expect_identical(id, record$release_instance_id)
        record
      },
      .dsvert_joint_dp_vector_release_set = function(first, second, policy,
                                                    contract, verifier) {
        expect_identical(contract, legacy)
        checked <<- TRUE
        list(list(final_vector_root = strrep("c", 64L)))
      },
      .dsvert_joint_dp_vector_contract = function(...) {
        stop("legacy ACK must not construct a current-policy contract")
      },
      .package = "dsVert")
    expect_true(checked)
    expect_identical(manifest_checked, !has_release)
    expect_identical(actual, record$ack_receipt_json)
  }
  record$local_result_json <- "historical-signed-result"
  prepared <- FALSE
  result <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_result_impl(manifest, receipt, receipt,
      session_id = "unavailable-historical-session",
      .policy = list(peer_name = "noise_a"), .secret = "test",
      .planner = function(...) stop("completed legacy RESULT must not replan"),
      .exact_consume = function(...) stop("completed RESULT must not sample")),
    .dsvert_joint_dp_vector_instance_claim_preflight = function(...) TRUE,
    .dsvert_joint_dp_vector_existing_release = function(...) {
      list(record = record, contract = legacy)
    },
    .dsvert_joint_dp_vector_prepare_set = function(first, second, policy,
                                                  contract, verifier) {
      expect_identical(contract, legacy)
      prepared <<- TRUE
      list()
    },
    .dsvert_joint_dp_vector_with_store = function(policy, secret, code) code(NULL),
    .dsvert_joint_dp_vector_capsule_load = function(...) record,
    .dsvert_joint_dp_vector_instance_claim_load = function(...) NULL,
    .dsvert_joint_dp_vector_instance_claim_contract = function(...) TRUE,
    .dsvert_joint_dp_vector_contract = function(...) {
      stop("completed legacy RESULT must not construct a current-policy contract")
    },
    .package = "dsVert")
  expect_true(prepared)
  expect_identical(result, record$local_result_json)
  record$manifest_sha256 <- strrep("d", 64L)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_ack_impl(manifest, receipt, receipt,
      .policy = list(peer_name = "source_only"), .secret = "test"),
    .dsvert_dp_capsule_manifest_require_built = function(...) TRUE,
    .dsvert_joint_dp_vector_existing_release = function(...) {
      stop("source-only ACK must not enter designated-peer release lookup")
    },
    .dsvert_joint_dp_vector_with_store = function(policy, secret, code) code(NULL),
    .dsvert_joint_dp_vector_capsule_load = function(...) record,
    .package = "dsVert"), "another manifest")
})
