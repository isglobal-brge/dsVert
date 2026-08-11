.synopsis_receipt_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-artifact.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_receipt_fixture <- function(k = 2L) {
  source <- .synopsis_receipt_helpers$.synopsis_artifact_helpers$
    .capsule_source_test_fixture(k = k, count_only = TRUE)
  for (peer in source$peers) {
    source$policies[[peer]]$own_identity_pk <-
      unname(source$policies[[peer]]$peer_pinset[[peer]])
  }
  fixture <- list(
    policy = source$policies[[1L]], manifest = source$manifests[[1L]],
    pins = source$policies[[1L]]$peer_pinset)
  claim_set <- .synopsis_receipt_helpers$.synopsis_artifact_claim_set(fixture)
  manifest_json <- source$manifest_json
  manifest_sha256 <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  signatures <- vapply(
    claim_set$claims, `[[`, character(1L), "signature")
  sign <- function(message, key) {
    .synopsis_receipt_helpers$.synopsis_artifact_helpers$
      .synopsis_test_b64url(
        openssl::sha512(c(charToRaw(key), message)))
  }
  signer <- function(message, identity_sk) sign(message, identity_sk)
  alternate_signer <- function(message, identity_sk) {
    .synopsis_receipt_helpers$.synopsis_artifact_helpers$
      .synopsis_test_b64url(openssl::sha512(c(
        as.raw(255L), charToRaw(identity_sk), message)))
  }
  verifier <- function(message, identity_pk, signature) {
    signature %in% signatures || identical(
      signature, sign(message, identity_pk)) || identical(
      signature, alternate_signer(message, identity_pk))
  }
  cache_get <- function(
      policy, secret, cache_key = NULL, manifest_sha256 = NULL) {
    .dsvert_dp_capsule_manifest_cache_record(
      cache_key = strrep("1", 64L), public_capsule_key = strrep("2", 64L),
      local_authority_sha256 =
        .dsvert_dp_capsule_manifest_local_authority(policy, secret),
      schema_sha256 = strrep("3", 64L),
      workload_contract_sha256 = strrep("4", 64L),
      manifest_json = manifest_json)
  }
  policies <- source$policies
  mint <- function(
      peer,
      planner = .synopsis_receipt_helpers$.synopsis_artifact_planner(),
      cache = cache_get,
      signed = signer) {
    .dsvert_dp_synopsis_local_compile_v1(
      manifest_sha256, claim_set, .policy = policies[[peer]],
      .secret = source$secrets[[peer]],
      .identity = list(
        identity_pk = unname(fixture$pins[[peer]]),
        identity_sk = unname(fixture$pins[[peer]])),
      .cache_get = cache, .planner = planner,
      .signer = signed, .verifier = verifier)
  }
  list(
    fixture = fixture, claim_set = claim_set,
    manifest_json = manifest_json, manifest_sha256 = manifest_sha256,
    secrets = source$secrets, policies = policies, planner =
      .synopsis_receipt_helpers$.synopsis_artifact_planner(),
    signer = signer, alternate_signer = alternate_signer,
    verifier = verifier, cache_get = cache_get, mint = mint)
}

.synopsis_receipt_resign <- function(receipt, signer) {
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  c(unsigned, list(signature = signer(
    .dsvert_dp_synopsis_compile_receipt_message_v1(unsigned),
    unsigned$peer_identity_pk)))
}

test_that("all K peers sign one canonical final synopsis compilation", {
  for (k in c(2L, 3L, 5L)) {
    input <- .synopsis_receipt_fixture(k)
    peers <- names(input$fixture$pins)
    local <- lapply(peers, input$mint)
    artifacts <- lapply(local, `[[`, "artifact")
    expect_true(all(vapply(
      artifacts[-1L], identical, logical(1L), artifacts[[1L]])))
    receipts <- lapply(local, `[[`, "receipt")
    expect_identical(
      vapply(receipts, `[[`, character(1L), "peer_name"), peers)

    compile <- function(value = receipts) .dsvert_dp_synopsis_compile_v1(
      value, artifacts[[1L]], input$claim_set,
      input$fixture$policy, input$fixture$manifest,
      .verifier = input$verifier)
    first <- compile(receipts)
    reversed <- compile(rev(receipts))
    expect_identical(reversed, first)
    resigned <- lapply(receipts, .synopsis_receipt_resign,
                       signer = input$alternate_signer)
    resigned <- compile(resigned)
    expect_identical(
      resigned$receipt_set_sha256, first$receipt_set_sha256)
    expect_false(identical(resigned$receipts, first$receipts))
    expect_identical(names(first$receipts), peers)
    expect_match(first$receipt_set_sha256, "^[0-9a-f]{64}$")
    expect_identical(first$artifact, artifacts[[1L]])
  }
})

test_that("compile receipts reject incomplete, forged and mixed consensus", {
  input <- .synopsis_receipt_fixture(3L)
  peers <- names(input$fixture$pins)
  local <- lapply(peers, input$mint)
  artifact <- local[[1L]]$artifact
  receipts <- lapply(local, `[[`, "receipt")
  compile <- function(value = receipts, expected = artifact) {
    .dsvert_dp_synopsis_compile_v1(
      value, expected, input$claim_set,
      input$fixture$policy, input$fixture$manifest,
      .verifier = input$verifier)
  }

  expect_error(compile(receipts[-1L]), "exactly one|coverage")
  expect_error(compile(c(receipts[-1L], receipts[2L])), "coverage|duplicate")
  bad_signature <- receipts
  bad_signature[[1L]]$signature <-
    .synopsis_receipt_helpers$.synopsis_artifact_helpers$
      .synopsis_test_b64url(as.raw(rep(9L, 64L)))
  expect_error(compile(bad_signature), "signature")
  extra <- receipts
  extra[[1L]]$unexpected <- TRUE
  expect_error(compile(extra), "fields|receipt")

  fields <- c(
    manifest_sha256 = strrep("a", 64L),
    artifact_key = strrep("b", 64L),
    source_claim_set_sha256 = strrep("c", 64L),
    full_plan_sha256 = strrep("d", 64L))
  for (field in names(fields)) {
    mixed <- receipts
    mixed[[2L]][[field]] <- fields[[field]]
    mixed[[2L]] <- .synopsis_receipt_resign(mixed[[2L]], input$signer)
    expect_error(compile(mixed))
    unanimous <- lapply(receipts, function(receipt) {
      receipt[[field]] <- fields[[field]]
      .synopsis_receipt_resign(receipt, input$signer)
    })
    expect_error(compile(unanimous))
  }
  wrong_identity <- receipts
  wrong_identity[[2L]]$peer_identity_pk <- input$fixture$pins[[peers[[1L]]]]
  wrong_identity[[2L]] <- .synopsis_receipt_resign(
    wrong_identity[[2L]], input$signer)
  expect_error(compile(wrong_identity), "pinned|identity|coverage")
})

test_that("local compilation authorizes cache before planner or signer", {
  input <- .synopsis_receipt_fixture(2L)
  events <- character()
  expect_error(input$mint(
    "peer_a",
    planner = function(...) {
      events <<- c(events, "planner")
      stop("planner reached")
    },
    cache = function(...) {
      events <<- c(events, "cache")
      NULL
    },
    signed = function(...) {
      events <<- c(events, "signer")
      stop("signer reached")
    }), "not emitted|authorized")
  expect_identical(events, "cache")
  expect_false(any(c(
    "manifest_json", "artifact", "resolved_snapshots", "data_name") %in%
    names(formals(.dsvert_dp_synopsis_local_compile_v1))))
})

test_that("artifact validation rederives policy semantics and full plan", {
  input <- .synopsis_receipt_fixture(2L)
  artifact <- input$mint("peer_a")$artifact
  rebuild <- function(value) {
    value$semantic <- .dsvert_dp_synopsis_semantic_v1(
      input$fixture$policy, input$fixture$manifest,
      input$claim_set, value$physical_plan)
    value$artifact_key <-
      .dsvert_dp_analysis_artifact_key_v1(value$semantic)
    value
  }
  expect_identical(
    .dsvert_dp_synopsis_artifact_validate_v1(
      artifact, input$fixture$policy, input$fixture$manifest,
      input$claim_set, .verifier = input$verifier),
    artifact)

  roles <- artifact
  roles$semantic$noise_authority_roles$authority_ids <-
    rev(roles$semantic$noise_authority_roles$authority_ids)
  roles$artifact_key <- .dsvert_dp_analysis_artifact_key_v1(roles$semantic)
  expect_error(.dsvert_dp_synopsis_artifact_validate_v1(
    roles, input$fixture$policy, input$fixture$manifest,
    input$claim_set, .verifier = input$verifier), "semantic|authority|artifact")

  plan <- artifact
  plan$physical_plan$full_plan$maximum_noise_magnitude <- "999"
  plan$physical_plan$full_plan_sha256 <-
    .dsvert_joint_dp_hash(plan$physical_plan$full_plan)
  expect_error(.dsvert_dp_synopsis_artifact_validate_v1(
    plan, input$fixture$policy, input$fixture$manifest,
    input$claim_set, .verifier = input$verifier), "plan|draw law|artifact")

  backend <- artifact
  mechanism <- backend$physical_plan$profile$mechanism
  wrong_backend <- if (identical(
      backend$physical_plan$profile$backend,
      .DSVERT_JOINT_DP_VECTOR_EXACT_BACKEND)) {
    .DSVERT_JOINT_DP_VECTOR_BACKEND
  } else .DSVERT_JOINT_DP_VECTOR_EXACT_BACKEND
  wrong_profile <- .dsvert_joint_dp_vector_profile(
    mechanism, wrong_backend)
  wrong_plan <- input$planner[[wrong_profile$plan_command]](
    backend$physical_plan$request)
  backend$physical_plan$profile <- .dsvert_dp_synopsis_profile_v1(
    mechanism, wrong_profile$backend)
  backend$physical_plan$full_plan <-
    .dsvert_dp_analysis_canonical_value_v1(wrong_plan)
  backend$physical_plan$full_plan_sha256 <-
    .dsvert_joint_dp_hash(wrong_plan)
  backend$physical_plan$draw_law <-
    .dsvert_dp_synopsis_draw_law_v1(wrong_plan, wrong_profile)
  backend$physical_plan$draw_law_sha256 <-
    .dsvert_dp_synopsis_artifact_hash_v1(
      .DSVERT_DP_SYNOPSIS_DRAW_LAW_DOMAIN,
      backend$physical_plan$draw_law)
  backend <- rebuild(backend)
  expect_error(.dsvert_dp_synopsis_artifact_validate_v1(
    backend, input$fixture$policy, input$fixture$manifest,
    input$claim_set, .verifier = input$verifier), "backend|selection|plan")

  lattice <- artifact
  lattice$physical_plan$lattice$transform_sha256 <- strrep("f", 64L)
  lattice <- rebuild(lattice)
  expect_error(.dsvert_dp_synopsis_artifact_validate_v1(
    lattice, input$fixture$policy, input$fixture$manifest,
    input$claim_set, .verifier = input$verifier), "lattice|transform|plan")
})
