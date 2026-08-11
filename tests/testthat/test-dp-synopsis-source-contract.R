.synopsis_source_contract_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-artifact.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_source_contract_input <- function() {
  helpers <- .synopsis_source_contract_helpers
  fixture <- helpers$.synopsis_artifact_exact_fixture(2L)
  compile <- function(commitment, claim_set = NULL) {
    if (is.null(claim_set)) {
      claim_set <- helpers$.synopsis_artifact_claim_set(
        fixture, commitment = commitment)
    }
    artifact <- .dsvert_dp_synopsis_artifact_v1(
      fixture$policy, fixture$manifest, claim_set,
      .planner = helpers$.synopsis_artifact_planner(),
      .verifier = function(...) TRUE)
    list(claim_set = claim_set, artifact = artifact)
  }
  list(fixture = fixture, compile = compile)
}

.synopsis_source_contract_resign <- function(claim_set) {
  claim_set$claims <- lapply(claim_set$claims, function(claim) {
    claim$signature <- .synopsis_source_contract_helpers$
      .synopsis_artifact_helpers$.synopsis_test_b64url(
        as.raw(rep(231L, 64L)))
    claim
  })
  claim_set
}

test_that("durable synopsis source contracts isolate artifact namespaces", {
  input <- .synopsis_source_contract_input()
  fixture <- input$fixture
  first_input <- input$compile(strrep("1", 64L))
  build <- function(artifact = first_input$artifact,
                    claim_set = first_input$claim_set) {
    .dsvert_dp_synopsis_source_contract_v1(
      fixture$policy, fixture$manifest, artifact, claim_set,
      .verifier = function(...) TRUE)
  }

  first <- build()
  replay <- build()
  legacy <- .dsvert_dp_capsule_source_contract_json(
    fixture$policy, .dsvert_dp_canonical_json(fixture$manifest))
  expect_identical(replay, first)
  expect_identical(
    .dsvert_dp_capsule_source_contract_validate(first), first)
  expect_identical(
    first$capsule_id,
    .dsvert_dp_synopsis_source_namespace_id_v1(first$synopsis_binding))
  expect_false(identical(
    first$capsule_id, first_input$artifact$artifact_key))
  expect_named(first$synopsis_binding, c(
    "artifact_key", "manifest_capsule_id", "source_claim_set_sha256",
    "version"),
    ignore.order = FALSE)
  expect_identical(
    first$synopsis_binding$manifest_capsule_id,
    legacy$contract$capsule_id)
  expect_identical(
    first$synopsis_binding$artifact_key, first_input$artifact$artifact_key)
  expect_identical(
    first$synopsis_binding$source_claim_set_sha256,
    first_input$claim_set$sha256)

  resigned_claim_set <- .synopsis_source_contract_resign(
    first_input$claim_set)
  resigned <- input$compile(
    strrep("1", 64L), claim_set = resigned_claim_set)
  expect_identical(resigned_claim_set$sha256, first_input$claim_set$sha256)
  expect_false(identical(
    resigned_claim_set$claims, first_input$claim_set$claims))
  expect_identical(resigned$artifact, first_input$artifact)
  expect_identical(
    build(resigned$artifact, resigned_claim_set), first)

  second_input <- input$compile(strrep("2", 64L))
  second <- build(second_input$artifact, second_input$claim_set)
  expect_false(identical(
    second_input$artifact$artifact_key, first_input$artifact$artifact_key))
  expect_false(identical(second$capsule_id, first$capsule_id))
  expect_false(identical(
    .dsvert_joint_dp_hash(second), .dsvert_joint_dp_hash(first)))
  expect_false(identical(
    .dsvert_dp_capsule_source_transfer_id(second, "peer_a"),
    .dsvert_dp_capsule_source_transfer_id(first, "peer_a")))

  tampered_base <- first
  tampered_base$workload_sha256 <- NULL
  tampered_binding <- first
  tampered_binding$synopsis_binding$source_claim_set_sha256 <- NULL
  tampered_manifest_binding <- first
  tampered_manifest_binding$synopsis_binding$manifest_capsule_id <-
    strrep("e", 64L)
  tampered_id <- first
  tampered_id$capsule_id <- strrep("f", 64L)
  for (tampered in list(
      tampered_base, tampered_binding, tampered_manifest_binding,
      tampered_id)) {
    expect_error(.dsvert_dp_capsule_source_contract_validate(tampered))
  }

  tampered_artifact <- first_input$artifact
  tampered_artifact$artifact_key <- strrep("f", 64L)
  expect_error(build(artifact = tampered_artifact))
  tampered_claim_set <- first_input$claim_set
  tampered_claim_set$sha256 <- strrep("f", 64L)
  expect_error(build(claim_set = tampered_claim_set))

  legacy_golden <-
    "79b06f468913dd865d185bdeff344eeabfd483c22933fe63739b09d1d78c1104"
  expect_identical(legacy$contract_hash, legacy_golden)
  expect_identical(digest::digest(
    legacy$contract_json, algo = "sha256", serialize = FALSE),
    legacy_golden)
  expect_identical(
    legacy$contract,
    .dsvert_dp_capsule_source_contract(fixture$policy, fixture$manifest))
})
