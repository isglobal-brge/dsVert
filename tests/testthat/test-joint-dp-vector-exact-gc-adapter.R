.exact_gc_vector_adapter_fixture <- function() {
  hex <- function(label) digest::digest(
    label, algo = "sha256", serialize = FALSE)
  manifest <- hex("manifest")
  transcript <- hex("transcript")
  plan <- list(
    version = "dsvert-joint-dp-vector-laplace-plan-v3",
    sampler = "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3",
    total_coordinate_count = 1L,
    maximum_chunk_coordinates = 128L,
    accounting = paste(
      "global iid discrete Laplace calibrated once to the workload joint",
      "L1 sensitivity; exact binary-geometric coupling"),
    capability_available = TRUE)
  assessment <- .dsvert_joint_dp_vector_exact_gc_plan_assessment(
    manifest, plan)
  selection <- .dsvert_joint_dp_vector_exact_gc_selection(
    manifest, assessment)
  input <- list(
    version = "dsvert-joint-dp-vector-worker-contract-input-v3",
    ring_bits = 128L, frac_bits = 0L,
    total_coordinate_count = 1L, chunk_start = 0L,
    coordinate_count = 1L, output_lattice_bits = 20L,
    epsilon = "1", allocated_delta = "1/1267650600228229401496703205376",
    sensitivity_steps = "2", scale_shifts = list(0L),
    raw_upper_bounds = list("10"),
    transcript_hash = transcript,
    garbler_commitment_context = hex("garbler-context"),
    evaluator_commitment_context = hex("evaluator-context"),
    garbler_seed_commitment = hex("garbler-commitment"),
    evaluator_seed_commitment = hex("evaluator-commitment"))
  circuit <- hex("circuit")
  policy <- list(
    version = "dsvert-joint-dp-vector-laplace-gc-template-v3",
    sampler = "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3",
    total_coordinate_count = 1L, chunk_start = 0L,
    coordinate_count = 1L, output_lattice_bits = 20L,
    sensitivity_steps = "2", epsilon = "1",
    allocated_delta = input$allocated_delta,
    stop_bits = 128L, stop_numerator = "1", uniform_bits = 128L,
    binary_geometric_bits = 1L, bernoulli_thresholds = list("1"),
    scale_shifts = input$scale_shifts,
    raw_upper_bounds = input$raw_upper_bounds,
    transcript_hash = transcript,
    garbler_commitment_context = input$garbler_commitment_context,
    evaluator_commitment_context = input$evaluator_commitment_context,
    garbler_seed_commitment = input$garbler_seed_commitment,
    evaluator_seed_commitment = input$evaluator_seed_commitment,
    circuit_digest = circuit,
    implementation_delta_numerator = "1",
    implementation_delta_denominator = "1267650600228229401496703205376")
  compiled_plan <- c(plan, list(
    stop_bits = 128L, stop_numerator = "1", uniform_bits = 128L,
    binary_geometric_bits = 1L, bernoulli_thresholds = list("1")))
  output <- list(
    version = "dsvert-joint-dp-vector-worker-contract-v3",
    capability_id = "joint_dp_biomedical_vector_exact_gc_v1",
    operation = "joint-dp-vector-laplace-v3",
    purpose = paste0("joint-dp-vector-laplace-v3/", circuit),
    circuit_digest = circuit,
    input_contract = "public-data-free-biomedical-vector-chunk-v1",
    protected_inputs_accepted = FALSE,
    private_seed_accepted = FALSE,
    worker_policy = policy, plan = compiled_plan,
    capability_available = TRUE)
  worker <- .dsvert_joint_dp_vector_exact_gc_compile(
    input, .compiler = function(value) output)
  binding <- .dsvert_joint_dp_vector_exact_gc_binding(
    selection, manifest, hex("release"), transcript, 0L, worker)
  list(
    hex = hex, manifest = manifest, transcript = transcript,
    release = hex("release"), plan = plan, assessment = assessment,
    selection = selection, input = input, output = output,
    worker = worker, binding = binding)
}

.exact_gc_vector_real_worker <- function(coordinate_count) {
  hex <- function(label) digest::digest(
    label, algo = "sha256", serialize = FALSE)
  .dsvert_joint_dp_vector_exact_gc_compile(list(
    version = "dsvert-joint-dp-vector-worker-contract-input-v3",
    ring_bits = 128L, frac_bits = 0L,
    total_coordinate_count = as.integer(coordinate_count),
    chunk_start = 0L, coordinate_count = as.integer(coordinate_count),
    output_lattice_bits = 20L, epsilon = "4",
    allocated_delta = "7.888609052210118e-31",
    sensitivity_steps = "1",
    scale_shifts = as.list(rep(0L, coordinate_count)),
    raw_upper_bounds = as.list(rep("10", coordinate_count)),
    transcript_hash = hex("real-transcript"),
    garbler_commitment_context = hex("real-garbler-context"),
    evaluator_commitment_context = hex("real-evaluator-context"),
    garbler_seed_commitment = hex("real-garbler-commitment"),
    evaluator_seed_commitment = hex("real-evaluator-commitment")))
}

test_that("one-draw selection is manifest-bound and cannot switch on retry", {
  fixture <- .exact_gc_vector_adapter_fixture()
  expect_identical(
    fixture$selection$backend,
    .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND)
  expect_true(fixture$selection$one_draw)
  expect_identical(
    fixture$selection$selection_reason,
    "within_public_exact_gc_cost_ceiling")
  expect_false(fixture$selection$retry_may_change_backend)
  expect_identical(
    .dsvert_joint_dp_vector_exact_gc_selection(
      fixture$manifest, fixture$assessment),
    fixture$selection)
  expect_error(.dsvert_joint_dp_vector_exact_gc_selection_validate(
    fixture$selection, fixture$hex("other-manifest")),
    "manifest|selection")

  timeout <- fixture$assessment
  timeout$runtime_failure_consulted <- TRUE
  timeout$assessment_sha256 <-
    .dsvert_joint_dp_vector_exact_gc_hash(
      timeout[setdiff(names(timeout), "assessment_sha256")])
  expect_error(.dsvert_joint_dp_vector_exact_gc_selection(
    fixture$manifest, timeout), "assessment|exact-GC backend")
})

test_that("public cost policy selects convolution before private access", {
  fixture <- .exact_gc_vector_adapter_fixture()
  plan <- fixture$plan
  plan$total_coordinate_count <- 2L
  assessment <- .dsvert_joint_dp_vector_exact_gc_plan_assessment(
    fixture$manifest, plan)
  selection <- .dsvert_joint_dp_vector_exact_gc_selection(
    fixture$manifest, assessment)
  expect_identical(selection$backend, .DSVERT_JOINT_DP_VECTOR_BACKEND)
  expect_false(selection$one_draw)
  expect_false(assessment$private_material_accessed)
  expect_false(assessment$runtime_failure_consulted)
  expect_identical(
    selection$selection_reason,
    "above_public_exact_gc_cost_ceiling")
  expect_error(.dsvert_joint_dp_vector_exact_gc_selection_validate(
    selection, fixture$manifest, require_exact = TRUE), "not selected")
})

test_that("worker compilation is data-free and tamper-evident", {
  fixture <- .exact_gc_vector_adapter_fixture()
  encoded <- jsonlite::toJSON(fixture$worker, auto_unbox = TRUE)
  expect_false(grepl('"source_share":|"private_seed":', encoded))
  expect_false(fixture$worker$protected_inputs_accepted)
  expect_false(fixture$worker$private_seed_accepted)

  unsafe <- fixture$input
  unsafe$private_seed <- strrep("0", 64L)
  expect_error(.dsvert_joint_dp_vector_exact_gc_compile(
    unsafe, .compiler = function(value) fixture$output),
    "public metadata")
  changed <- fixture$output
  changed$purpose <- paste0(
    "joint-dp-vector-laplace-v3/", fixture$hex("tampered"))
  expect_error(.dsvert_joint_dp_vector_exact_gc_compile(
    fixture$input, .compiler = function(value) changed),
    "conflicting contract")
})

test_that("real Go vector policies retain array shape in worker config", {
  array_fields <- c(
    "scale_shifts", "raw_upper_bounds", "bernoulli_thresholds")
  for (coordinate_count in c(1L, 2L)) {
    worker <- .exact_gc_vector_real_worker(coordinate_count)
    policy <- worker$worker_policy
    original <- policy
    original_hash <- .dsvert_joint_dp_vector_exact_gc_hash(policy)

    wire <- .exact_gc_joint_dp_vector_wire_policy(policy)
    config_json <- as.character(jsonlite::toJSON(
      list(joint_dp_vector = wire), auto_unbox = TRUE, null = "null"))
    config <- jsonlite::fromJSON(
      config_json, simplifyVector = FALSE)$joint_dp_vector

    expect_identical(policy, original)
    expect_identical(
      .dsvert_joint_dp_vector_exact_gc_hash(policy), original_hash)
    expect_identical(
      wire[setdiff(names(wire), array_fields)],
      policy[setdiff(names(policy), array_fields)])
    expect_true(all(vapply(
      config[array_fields], is.list, logical(1L))))
    expect_length(config$scale_shifts, coordinate_count)
    expect_length(config$raw_upper_bounds, coordinate_count)
    expect_length(
      config$bernoulli_thresholds,
      as.integer(policy$binary_geometric_bits))
    expect_identical(
      as.numeric(unlist(config$scale_shifts, use.names = FALSE)),
      as.numeric(policy$scale_shifts))
    expect_identical(
      unlist(config$raw_upper_bounds, use.names = FALSE),
      as.character(policy$raw_upper_bounds))
    expect_identical(
      unlist(config$bernoulli_thresholds, use.names = FALSE),
      as.character(policy$bernoulli_thresholds))
  }
})

test_that("vector worker wire arrays reject malformed policy values", {
  policy <- .exact_gc_vector_real_worker(1L)$worker_policy

  missing <- policy
  missing$scale_shifts <- NULL
  expect_error(
    .exact_gc_joint_dp_vector_wire_policy(missing), "wire policy")

  classed <- policy
  classed$scale_shifts <- structure(0, class = "malformed")
  expect_error(
    .exact_gc_joint_dp_vector_wire_policy(classed), "wire policy")

  nested <- policy
  nested$raw_upper_bounds <- list(list("10"))
  expect_error(
    .exact_gc_joint_dp_vector_wire_policy(nested), "wire policy")

  named <- policy
  named$bernoulli_thresholds <- stats::setNames(
    named$bernoulli_thresholds,
    paste0("threshold_", seq_along(named$bernoulli_thresholds)))
  expect_error(
    .exact_gc_joint_dp_vector_wire_policy(named), "wire policy")
})

test_that("garbler and evaluator commitments follow pins, not DSI order", {
  fixture <- .exact_gc_vector_adapter_fixture()
  session <- new.env(parent = emptyenv())
  session$peer_transport_pks <- list(site_b = "transport-b")
  prepares <- list(
    site_b = list(
      peer_name = "site_b",
      commitment_context = fixture$hex("ctx-b"),
      seed_commitment = fixture$hex("seed-b")),
    site_a = list(
      peer_name = "site_a",
      commitment_context = fixture$hex("ctx-a"),
      seed_commitment = fixture$hex("seed-a")))
  ids <- list(
    own = paste0("dsv1_", strrep("b", 64L)),
    trusted = paste0("dsv1_", strrep("a", 64L)))
  roles <- .dsvert_joint_dp_vector_exact_gc_role_bindings(
    session, "site_a", prepares, c("site_a", "site_b"),
    .own_identity = function(state) "own-key",
    .trusted = function() list(site_b = "trusted-key"),
    .peer_id = function(key) if (identical(key, "own-key")) {
      ids$own
    } else ids$trusted)
  expect_identical(roles$garbler_peer_name, "site_b")
  expect_identical(roles$evaluator_peer_name, "site_a")
  expect_identical(roles$garbler_commitment_context,
                   fixture$hex("ctx-b"))
  expect_false(roles$analyst_selected_roles)

  session$peer_transport_pks <- list(site_c = "transport-c")
  expect_error(.dsvert_joint_dp_vector_exact_gc_role_bindings(
    session, "site_a", prepares, c("site_a", "site_b"),
    .own_identity = function(state) "own-key",
    .trusted = function() list(site_b = "trusted-key"),
    .peer_id = function(key) ids$own), "pinset")
})

test_that("operation binding is deterministic across retry and reconnect", {
  fixture <- .exact_gc_vector_adapter_fixture()
  retry <- .dsvert_joint_dp_vector_exact_gc_binding(
    fixture$selection, fixture$manifest, fixture$release,
    fixture$transcript, 0L, fixture$worker)
  expect_identical(retry, fixture$binding)
  expect_false("session_id" %in% names(retry))

  changed_worker <- fixture$worker
  changed_worker$worker_policy$transcript_hash <- fixture$hex("new-transcript")
  changed <- .dsvert_joint_dp_vector_exact_gc_binding(
    fixture$selection, fixture$manifest, fixture$release,
    changed_worker$worker_policy$transcript_hash, 0L, changed_worker)
  expect_false(identical(changed$operation_id,
                         fixture$binding$operation_id))

  tampered <- fixture$binding
  tampered$chunk_index <- 1L
  expect_error(.dsvert_joint_dp_vector_exact_gc_binding_validate(
    tampered, fixture$selection, fixture$manifest, fixture$release,
    fixture$transcript, 0L, fixture$worker), "modified")
})

test_that("server start stages secrets internally and returns metadata only", {
  fixture <- .exact_gc_vector_adapter_fixture()
  session <- new.env(parent = emptyenv())
  staged <- initialized <- NULL
  stage <- function(...) {
    staged <<- list(...)
    invisible(TRUE)
  }
  initialize <- function(...) {
    initialized <<- list(...)
    list(
      capability_id = "exact_gc_v1", state = "running",
      stored = FALSE, context_hash = fixture$hex("context"))
  }
  result <- .dsvert_joint_dp_vector_exact_gc_start(
    session, "00000000-0000-4000-8000-000000000001",
    fixture$binding, fixture$selection, fixture$manifest,
    fixture$release, fixture$transcript, 0L, fixture$worker,
    source_share = as.raw(seq.int(0L, 15L)),
    private_seed = strrep("1", 64L),
    .stage = stage, .initialize = initialize)
  expect_length(staged, 10L)
  expect_identical(initialized$operation,
                   "joint-dp-vector-laplace-v3")
  expect_identical(initialized$ring, 128L)
  expect_identical(initialized$joint_dp_vector,
                   fixture$worker$worker_policy)
  expect_false(result$intermediate_payload_exposed)
  public <- jsonlite::toJSON(result, auto_unbox = TRUE)
  expect_false(grepl('"source_share":|"private_seed":|ERERERER', public))
  expect_false(any(c("source_share", "private_seed", "joint_dp_vector") %in%
                     names(result)))
})

test_that("server start leaves retryable exact state to the initializer", {
  fixture <- .exact_gc_vector_adapter_fixture()
  session <- new.env(parent = emptyenv())
  session$.exact_gc_ops <- new.env(parent = emptyenv())
  state <- new.env(parent = emptyenv())
  state$status <- "failed"
  state$retryable <- TRUE
  state$attempt <- 1L
  session$.exact_gc_ops[[fixture$binding$operation_id]] <- state
  staged <- 0L
  initialized <- 0L
  result <- .dsvert_joint_dp_vector_exact_gc_start(
    session, "00000000-0000-4000-8000-000000000001",
    fixture$binding, fixture$selection, fixture$manifest,
    fixture$release, fixture$transcript, 0L, fixture$worker,
    source_share = as.raw(seq.int(0L, 15L)),
    private_seed = strrep("1", 64L),
    .stage = function(...) staged <<- staged + 1L,
    .initialize = function(...) {
      initialized <<- initialized + 1L
      expect_identical(.exact_gc_operation_state(
        session, fixture$binding$operation_id), state)
      list(capability_id = "exact_gc_v1", state = "running",
           stored = FALSE, context_hash = fixture$hex("retry-context"))
    })
  expect_identical(staged, 0L)
  expect_identical(initialized, 1L)
  expect_identical(state$attempt, 1L)
  expect_identical(result$operation_id, fixture$binding$operation_id)
})

test_that("durable consume never returns an output or validity share", {
  fixture <- .exact_gc_vector_adapter_fixture()
  share <- gsub("[\r\n]", "", jsonlite::base64_enc(raw(16L)))
  validity <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(1L)))
  calls <- logical()
  consume <- function(..., consume) {
    calls <<- c(calls, consume)
    list(share = share, validity_share = validity)
  }
  committed <- NULL
  result <- .dsvert_joint_dp_vector_exact_gc_consume(
    new.env(parent = emptyenv()), fixture$binding, fixture$worker,
    .commit = function(value) {
      committed <<- value
      TRUE
    }, .consume = consume)
  expect_identical(calls, c(FALSE, TRUE))
  expect_identical(committed$noised_share_b64, share)
  expect_identical(committed$validity_share_b64, validity)
  expect_true(result$durable)
  expect_false(any(c("noised_share_b64", "validity_share_b64", "share") %in%
                     names(result)))
  expect_false(grepl(share, jsonlite::toJSON(result, auto_unbox = TRUE),
                     fixed = TRUE))
})

test_that("one-draw finalization checks validity and never reveals pre-clamp", {
  fixture <- .exact_gc_vector_adapter_fixture()
  own <- list(
    noised_share_b64 = .exact_gc_decimal_residues_b64("10", 128L),
    validity_share_b64 = gsub(
      "[\r\n]", "", jsonlite::base64_enc(as.raw(0L))),
    binding_sha256 = fixture$binding$binding_sha256)
  peer <- list(
    noised_share_b64 = .exact_gc_decimal_residues_b64(
      "340282366920938463463374607431768211453", 128L),
    validity_share_b64 = gsub(
      "[\r\n]", "", jsonlite::base64_enc(as.raw(1L))),
    binding_sha256 = fixture$binding$binding_sha256)
  final <- .dsvert_joint_dp_vector_exact_gc_finalize(
    own, peer, "7", fixture$binding$binding_sha256)
  expect_identical(final$clamped_scaled_values, list("7"))
  expect_true(final$validity)
  expect_false(final$preclamp_values_returned)
  expect_false(any(c("noised_share_b64", "validity_share_b64") %in%
                     names(final)))

  invalid <- peer
  invalid$validity_share_b64 <- own$validity_share_b64
  expect_error(.dsvert_joint_dp_vector_exact_gc_finalize(
    own, invalid, "7", fixture$binding$binding_sha256), "validity")
  expect_error(.dsvert_joint_dp_vector_exact_gc_finalize(
    own, peer, "6", fixture$binding$binding_sha256), "clamp")
})
