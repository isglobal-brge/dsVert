test_that("staged LMM rejects samplers that cannot retain private validity before START", {
  manifest <- list(workload = list(families = list(gaussian_models = list(
    artifacts = list(grouped = list(family = "lmm", version = "bounded-lmm-cross-grid-v1",
      spec_version = "lmm_grid_cross_v1"))))))
  context <- list(manifest_json = .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(manifest)),
    vector = list(profile = list(exact_gc = FALSE)))
  source_reads <- 0L
  samples <- 0L
  local_mocked_bindings(
    .dsvert_dp_synopsis_execution_context_v1 = function(...) context,
    .dsvert_dp_synopsis_execution_chunk_v1 = function(...) stop("chunk guard sentinel"),
    .dsvert_dp_synopsis_execution_start_claim_v1 = function(...) stop("claim must not run"),
    .package = "dsVert")
  start <- function() .dsvert_dp_synopsis_execution_start_v1(
    new.env(), "session", NULL, NULL, 0L, .policy = list(), .secret = raw(32L),
    .identity = list(), .source_reader = function(...) { source_reads <<- source_reads + 1L },
    .sampler = function(...) { samples <<- samples + 1L })
  for (exact in list(FALSE, NULL, NA)) {
    context$vector$profile$exact_gc <- exact
    expect_error(start(), "requires the Synopsis exact-GC validity gate", fixed = TRUE)
  }
  expect_identical(source_reads, 0L)
  expect_identical(samples, 0L)
  context$vector$profile$exact_gc <- TRUE
  expect_error(start(), "chunk guard sentinel", fixed = TRUE)
  context$vector$profile$exact_gc <- FALSE
  manifest$workload$families$gaussian_models$artifacts$grouped$version <- "same-owner-lmm-v1"
  context$manifest_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(manifest))
  expect_error(start(), "chunk guard sentinel", fixed = TRUE)
})

test_that("staged LMM cannot bypass the Synopsis gate through the legacy vector lifecycle", {
  fixture <- .lmm_handoff_fixture()
  contract <- list(manifest = fixture$manifest, designated = "peer_a")
  local_mocked_bindings(
    .dsvert_joint_dp_vector_instance_from_receipts = function(...) "bound-instance",
    .dsvert_joint_dp_vector_instance_claim_preflight = function(...) invisible(NULL),
    .dsvert_joint_dp_vector_contract = function(...) contract,
    .dsvert_joint_dp_vector_prepare_set = function(...) stop("prepare guard sentinel"),
    .dsvert_joint_dp_vector_instance_claim_contract = function(...) stop("claim must not run"),
    .package = "dsVert")
  start <- function() .dsvert_joint_dp_vector_start_impl(
    "manifest", "first", "second", 0L, .policy = list(peer_name = "peer_a"),
    .secret = raw(32L), .source_reader = function(...) stop("source must not run"),
    .sampler = function(...) stop("sampler must not run"))
  for (exact in c(FALSE, TRUE)) {
    contract$profile <- list(exact_gc = exact)
    expect_error(start(), "requires the Synopsis exact-GC validity gate", fixed = TRUE)
  }
  contract$manifest$workload$families$gaussian_models$artifacts <- list()
  expect_error(start(), "prepare guard sentinel", fixed = TRUE)
})
