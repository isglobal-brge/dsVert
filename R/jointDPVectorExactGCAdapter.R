# Internal adapter for the one-draw joint-DP vector exact-GC backend.
#
# This file deliberately registers no AggregateMethod.  The existing vector
# capsule owns source material, sticky seeds and durable output records; the
# four generic exact-GC transport methods only relay authenticated ciphertext
# envelopes.  Consequently neither the analyst relay nor the other peer can
# obtain a source share, a private seed, pre-clamp values or an output share.

.DSVERT_JOINT_DP_VECTOR_EXACT_GC_SELECTION_VERSION <-
  "dsvert-joint-dp-vector-backend-selection-v2"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_ASSESSMENT_VERSION <-
  "dsvert-joint-dp-vector-exact-gc-assessment-v2"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_COST_POLICY_VERSION <-
  "dsvert-joint-dp-vector-exact-gc-cost-policy-v1"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_MAX_PROMOTED_COORDINATES <- 1L
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_BINDING_VERSION <-
  "dsvert-joint-dp-vector-exact-gc-binding-v1"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_START_VERSION <-
  "dsvert-joint-dp-vector-exact-gc-start-v1"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_COMMIT_VERSION <-
  "dsvert-joint-dp-vector-exact-gc-commit-v1"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_FINAL_VERSION <-
  "dsvert-joint-dp-vector-exact-gc-final-v1"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND <-
  "exact_gc_one_joint_discrete_laplace_draw_ring128_v3"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION <-
  "joint-dp-vector-laplace-v3"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_OUTPUT_KIND <-
  "joint-dp-vector-ring128-share-v1"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_PRODUCER <-
  "joint.dp.vector.one-draw.v1"
.DSVERT_JOINT_DP_VECTOR_EXACT_GC_CAPABILITY <-
  "joint_dp_biomedical_vector_exact_gc_v1"

.dsvert_joint_dp_vector_exact_gc_hex <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_joint_dp_vector_exact_gc_hash <- function(value) {
  digest::digest(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_vector_exact_gc_integer <- function(
    value, what, minimum, maximum) {
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value != floor(value) || value < minimum || value > maximum) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  as.integer(value)
}

.dsvert_joint_dp_vector_public_backend_choice <- function(
    total_coordinate_count) {
  total <- .dsvert_joint_dp_vector_exact_gc_integer(
    total_coordinate_count, "total coordinate count", 1L, 1000000L)
  promoted <- total <=
    .DSVERT_JOINT_DP_VECTOR_EXACT_GC_MAX_PROMOTED_COORDINATES
  list(
    policy_version =
      .DSVERT_JOINT_DP_VECTOR_EXACT_GC_COST_POLICY_VERSION,
    total_coordinate_count = total,
    maximum_promoted_coordinates =
      .DSVERT_JOINT_DP_VECTOR_EXACT_GC_MAX_PROMOTED_COORDINATES,
    promoted = promoted,
    backend = if (promoted) {
      .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND
    } else {
      .DSVERT_JOINT_DP_VECTOR_BACKEND
    },
    selection_reason = if (promoted) {
      "within_public_exact_gc_cost_ceiling"
    } else {
      "above_public_exact_gc_cost_ceiling"
    })
}

.dsvert_joint_dp_vector_exact_gc_plan_assessment <- function(
    manifest_sha256, plan, choice = NULL) {
  manifest_sha256 <- .dsvert_joint_dp_vector_exact_gc_hex(
    manifest_sha256, "biomedical manifest hash")
  required <- c(
    "version", "sampler", "total_coordinate_count",
    "maximum_chunk_coordinates", "accounting", "capability_available")
  if (!is.list(plan) || !all(required %in% names(plan)) ||
      !identical(plan$version, "dsvert-joint-dp-vector-laplace-plan-v3") ||
      !identical(
        plan$sampler,
        "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3") ||
      !identical(plan$capability_available, TRUE) ||
      !is.character(plan$accounting) || length(plan$accounting) != 1L ||
      !startsWith(plan$accounting, "global iid discrete Laplace") ||
      .dsvert_joint_dp_vector_exact_gc_integer(
        plan$total_coordinate_count, "total coordinate count", 1L,
        1000000L) < 1L) {
    stop("The one-draw exact-GC plan is not release-certified.",
         call. = FALSE)
  }
  maximum <- .dsvert_joint_dp_vector_exact_gc_integer(
    plan$maximum_chunk_coordinates, "exact-GC chunk capacity", 1L, 128L)
  if (is.null(choice)) {
    choice <- .dsvert_joint_dp_vector_public_backend_choice(
      plan$total_coordinate_count)
  }
  expected_choice <- .dsvert_joint_dp_vector_public_backend_choice(
    plan$total_coordinate_count)
  if (!is.list(choice) ||
      !identical(choice, expected_choice)) {
    stop("The exact-GC cost-policy decision is invalid.", call. = FALSE)
  }
  unsigned <- list(
    version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_ASSESSMENT_VERSION,
    manifest_sha256 = manifest_sha256,
    representable = TRUE,
    exact_gc_capability_id =
      .DSVERT_JOINT_DP_VECTOR_EXACT_GC_CAPABILITY,
    plan_sha256 = .dsvert_joint_dp_vector_exact_gc_hash(plan),
    maximum_chunk_coordinates = maximum,
    cost_policy_version = choice$policy_version,
    total_coordinate_count = choice$total_coordinate_count,
    maximum_promoted_coordinates = choice$maximum_promoted_coordinates,
    promoted = choice$promoted,
    selection_reason = choice$selection_reason,
    private_material_accessed = FALSE,
    runtime_failure_consulted = FALSE)
  c(unsigned, list(
    assessment_sha256 =
      .dsvert_joint_dp_vector_exact_gc_hash(unsigned)))
}

.dsvert_joint_dp_vector_exact_gc_selection <- function(
    manifest_sha256, assessment) {
  manifest_sha256 <- .dsvert_joint_dp_vector_exact_gc_hex(
    manifest_sha256, "biomedical manifest hash")
  base_names <- c(
    "version", "manifest_sha256", "representable",
    "exact_gc_capability_id", "plan_sha256",
    "maximum_chunk_coordinates", "cost_policy_version",
    "total_coordinate_count", "maximum_promoted_coordinates",
    "promoted", "selection_reason", "private_material_accessed",
    "runtime_failure_consulted",
    "assessment_sha256")
  if (!is.list(assessment) || is.null(names(assessment)) ||
      anyNA(names(assessment)) || anyDuplicated(names(assessment)) ||
      !identical(assessment$version,
                 .DSVERT_JOINT_DP_VECTOR_EXACT_GC_ASSESSMENT_VERSION) ||
      !identical(assessment$manifest_sha256, manifest_sha256) ||
      !identical(assessment$exact_gc_capability_id,
                 .DSVERT_JOINT_DP_VECTOR_EXACT_GC_CAPABILITY) ||
      !identical(assessment$private_material_accessed, FALSE) ||
      !identical(assessment$runtime_failure_consulted, FALSE) ||
      !is.logical(assessment$representable) ||
      length(assessment$representable) != 1L ||
      is.na(assessment$representable) ||
      !all(base_names %in% names(assessment))) {
    stop("Invalid exact-GC backend assessment.", call. = FALSE)
  }
  expected_names <- base_names
  unsigned_assessment <- assessment[setdiff(names(assessment),
                                             "assessment_sha256")]
  if (!setequal(names(assessment), expected_names) ||
      !identical(
        .dsvert_joint_dp_vector_exact_gc_hash(unsigned_assessment),
        assessment$assessment_sha256)) {
    stop("The exact-GC backend assessment was modified.", call. = FALSE)
  }
  if (!isTRUE(assessment$representable)) {
    stop("The exact-GC plan is not representable.", call. = FALSE)
  }
  maximum <- .dsvert_joint_dp_vector_exact_gc_integer(
    assessment$maximum_chunk_coordinates,
    "exact-GC chunk capacity", 1L, 128L)
  choice <- .dsvert_joint_dp_vector_public_backend_choice(
    assessment$total_coordinate_count)
  if (!identical(assessment$cost_policy_version, choice$policy_version) ||
      !identical(as.numeric(assessment$maximum_promoted_coordinates),
                 as.numeric(choice$maximum_promoted_coordinates)) ||
      !identical(assessment$promoted, choice$promoted) ||
      !identical(assessment$selection_reason, choice$selection_reason)) {
    stop("The exact-GC cost-policy assessment is inconsistent.",
         call. = FALSE)
  }
  unsigned <- list(
    version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_SELECTION_VERSION,
    manifest_sha256 = manifest_sha256,
    backend = choice$backend,
    one_draw = choice$promoted,
    cost_policy_version = choice$policy_version,
    total_coordinate_count = choice$total_coordinate_count,
    maximum_promoted_coordinates = choice$maximum_promoted_coordinates,
    selection_reason = choice$selection_reason,
    assessment_sha256 = assessment$assessment_sha256,
    exact_gc_plan_sha256 = assessment$plan_sha256,
    exact_gc_maximum_chunk_coordinates = maximum,
    selected_before_private_material = TRUE,
    retry_may_change_backend = FALSE)
  c(unsigned, list(
    selection_sha256 =
      .dsvert_joint_dp_vector_exact_gc_hash(unsigned)))
}

.dsvert_joint_dp_vector_exact_gc_selection_validate <- function(
    selection, manifest_sha256, require_exact = FALSE) {
  manifest_sha256 <- .dsvert_joint_dp_vector_exact_gc_hex(
    manifest_sha256, "biomedical manifest hash")
  required <- c(
    "version", "manifest_sha256", "backend", "one_draw",
    "cost_policy_version", "total_coordinate_count",
    "maximum_promoted_coordinates", "selection_reason",
    "assessment_sha256",
    "exact_gc_plan_sha256", "exact_gc_maximum_chunk_coordinates",
    "selected_before_private_material", "retry_may_change_backend",
    "selection_sha256")
  if (!is.list(selection) || !setequal(names(selection), required) ||
      !identical(selection$version,
                 .DSVERT_JOINT_DP_VECTOR_EXACT_GC_SELECTION_VERSION) ||
      !identical(selection$manifest_sha256, manifest_sha256) ||
      !identical(selection$selected_before_private_material, TRUE) ||
      !identical(selection$retry_may_change_backend, FALSE) ||
      !identical(
        .dsvert_joint_dp_vector_exact_gc_hash(
          selection[setdiff(names(selection), "selection_sha256")]),
        selection$selection_sha256)) {
    stop("The immutable vector backend selection is invalid.",
         call. = FALSE)
  }
  choice <- .dsvert_joint_dp_vector_public_backend_choice(
    selection$total_coordinate_count)
  exact <- identical(selection$backend,
                     .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND)
  coherent <- identical(selection$backend, choice$backend) &&
    identical(selection$one_draw, choice$promoted) &&
    identical(selection$cost_policy_version, choice$policy_version) &&
    identical(as.numeric(selection$maximum_promoted_coordinates),
              as.numeric(choice$maximum_promoted_coordinates)) &&
    identical(selection$selection_reason, choice$selection_reason) &&
    .dsvert_joint_dp_vector_exact_gc_integer(
      selection$exact_gc_maximum_chunk_coordinates,
      "exact-GC chunk capacity", 1L, 128L) >= 1L
  if (!isTRUE(coherent)) {
    stop("The vector backend selection conflicts with this operation.",
         call. = FALSE)
  }
  if (isTRUE(require_exact) && !isTRUE(exact)) {
    stop("This operation was not selected for exact-GC.", call. = FALSE)
  }
  invisible(selection)
}

.dsvert_joint_dp_vector_exact_gc_compile <- function(
    input, .compiler = NULL) {
  required <- c(
    "version", "ring_bits", "frac_bits", "total_coordinate_count",
    "chunk_start", "coordinate_count", "output_lattice_bits",
    "epsilon", "allocated_delta", "sensitivity_steps", "scale_shifts",
    "raw_upper_bounds", "transcript_hash",
    "garbler_commitment_context", "evaluator_commitment_context",
    "garbler_seed_commitment", "evaluator_seed_commitment")
  recursive_names <- function(value) {
    if (!is.list(value)) return(character())
    c(names(value), unlist(lapply(value, recursive_names), use.names = FALSE))
  }
  if (!is.list(input) || !setequal(names(input), required) ||
      length(intersect(recursive_names(input),
                       c("source_share", "private_seed")))) {
    stop("The exact-GC compiler accepts public metadata only.",
         call. = FALSE)
  }
  coordinate_count <- .dsvert_joint_dp_vector_exact_gc_integer(
    input$coordinate_count, "exact-GC coordinate count", 1L, 128L)
  total <- .dsvert_joint_dp_vector_exact_gc_integer(
    input$total_coordinate_count, "total coordinate count", 1L, 1000000L)
  start <- .dsvert_joint_dp_vector_exact_gc_integer(
    input$chunk_start, "exact-GC chunk offset", 0L, total - 1L)
  lattice_bits <- .dsvert_joint_dp_vector_exact_gc_integer(
    input$output_lattice_bits, "output lattice bits", 1L, 62L)
  contexts <- input[c(
    "transcript_hash", "garbler_commitment_context",
    "evaluator_commitment_context", "garbler_seed_commitment",
    "evaluator_seed_commitment")]
  if (!identical(input$version,
                 "dsvert-joint-dp-vector-worker-contract-input-v3") ||
      !identical(as.integer(input$ring_bits), 128L) ||
      !identical(as.integer(input$frac_bits), 0L) ||
      start > total - coordinate_count ||
      length(input$scale_shifts) != coordinate_count ||
      length(input$raw_upper_bounds) != coordinate_count ||
      any(vapply(contexts, function(value) {
        !is.character(value) || length(value) != 1L || is.na(value) ||
          !grepl("^[0-9a-f]{64}$", value)
      }, logical(1L))) ||
      anyNA(suppressWarnings(as.numeric(input$scale_shifts))) ||
      any(suppressWarnings(as.numeric(input$scale_shifts)) < 0) ||
      any(suppressWarnings(as.numeric(input$scale_shifts)) > lattice_bits)) {
    stop("Invalid public exact-GC vector worker input.", call. = FALSE)
  }
  if (is.null(.compiler)) .compiler <- function(value) {
    .callMpcTool("joint-dp-vector-worker-contract-v3", value)
  }
  if (!is.function(.compiler)) {
    stop("Invalid exact-GC vector compiler.", call. = FALSE)
  }
  output <- .compiler(input)
  output_names <- c(
    "version", "capability_id", "operation", "purpose",
    "circuit_digest", "input_contract", "protected_inputs_accepted",
    "private_seed_accepted", "worker_policy", "plan",
    "capability_available")
  if (!is.list(output) || !setequal(names(output), output_names) ||
      !identical(output$version,
                 "dsvert-joint-dp-vector-worker-contract-v3") ||
      !identical(output$capability_id,
                 .DSVERT_JOINT_DP_VECTOR_EXACT_GC_CAPABILITY) ||
      !identical(output$operation,
                 .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION) ||
      !identical(output$purpose, paste0(
        .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION, "/",
        output$circuit_digest)) ||
      !identical(output$input_contract,
                 "public-data-free-biomedical-vector-chunk-v1") ||
      !identical(output$protected_inputs_accepted, FALSE) ||
      !identical(output$private_seed_accepted, FALSE) ||
      !identical(output$capability_available, TRUE) ||
      !is.list(output$worker_policy) || !is.list(output$plan) ||
      !grepl("^[0-9a-f]{64}$", output$circuit_digest) ||
      !identical(output$worker_policy$circuit_digest,
                 output$circuit_digest) ||
      !identical(as.integer(output$worker_policy$coordinate_count),
                 coordinate_count) ||
      !identical(as.integer(output$worker_policy$chunk_start), start) ||
      !identical(as.integer(output$worker_policy$total_coordinate_count),
                 total) ||
      !identical(output$worker_policy$transcript_hash,
                 input$transcript_hash) ||
      !identical(output$plan$version,
                 "dsvert-joint-dp-vector-laplace-plan-v3") ||
      !identical(output$plan$sampler,
                 "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3") ||
      !identical(output$plan$capability_available, TRUE) ||
      .dsvert_joint_dp_vector_exact_gc_integer(
        output$plan$maximum_chunk_coordinates,
        "compiled exact-GC chunk capacity", 1L, 128L) < coordinate_count) {
    stop("The exact-GC vector compiler returned a conflicting contract.",
         call. = FALSE)
  }
  output
}

# Resolve the GC roles from the pinned cryptographic identities, never from
# analyst ordering or federation aliases.  Both peers therefore compile the
# same commitment map even when DSI returns sites in a different order.
.dsvert_joint_dp_vector_exact_gc_role_bindings <- function(
    ss, own_peer_name, prepares, designated,
    .own_identity = function(state) .key_get("identity_pk", state),
    .trusted = .get_trusted_peers,
    .peer_id = .dsvert_relay_peer_id) {
  if (!is.environment(ss) || !is.character(own_peer_name) ||
      length(own_peer_name) != 1L || is.na(own_peer_name) ||
      !is.list(prepares) || is.null(names(prepares)) ||
      !is.character(designated) || length(designated) != 2L ||
      anyNA(designated) || anyDuplicated(designated) ||
      !setequal(names(prepares), designated) ||
      !own_peer_name %in% designated || !is.function(.own_identity) ||
      !is.function(.trusted) || !is.function(.peer_id)) {
    stop("Invalid pinned exact-GC vector role context.", call. = FALSE)
  }
  peer_names <- names(ss$peer_transport_pks %||% list())
  peer_name <- setdiff(designated, own_peer_name)
  trusted <- .trusted()
  if (length(peer_names) != 1L || !identical(peer_names, peer_name) ||
      is.null(trusted[[peer_name]])) {
    stop("The exact-GC vector peers are not bound to the designated pinset.",
         call. = FALSE)
  }
  ids <- c(
    .peer_id(.own_identity(ss)),
    .peer_id(trusted[[peer_name]]))
  names(ids) <- c(own_peer_name, peer_name)
  if (anyNA(ids) || anyDuplicated(ids) ||
      any(!grepl("^dsv1_[0-9a-f]{64}$", ids))) {
    stop("The exact-GC vector peer identities are invalid.", call. = FALSE)
  }
  roles <- stats::setNames(
    c("garbler", "evaluator"),
    names(sort(ids, method = "radix")))
  checked <- lapply(designated, function(name) {
    value <- prepares[[name]]
    if (!is.list(value) || !identical(value$peer_name, name) ||
        !is.character(value$commitment_context) ||
        !grepl("^[0-9a-f]{64}$", value$commitment_context) ||
        !is.character(value$seed_commitment) ||
        !grepl("^[0-9a-f]{64}$", value$seed_commitment)) {
      stop("A vector prepare lacks its pinned seed commitment.",
           call. = FALSE)
    }
    value
  })
  names(checked) <- designated
  by_role <- stats::setNames(names(roles), unname(roles))
  garbler <- checked[[by_role[["garbler"]]]]
  evaluator <- checked[[by_role[["evaluator"]]]]
  list(
    garbler_peer_name = garbler$peer_name,
    evaluator_peer_name = evaluator$peer_name,
    garbler_peer_id = unname(ids[[garbler$peer_name]]),
    evaluator_peer_id = unname(ids[[evaluator$peer_name]]),
    garbler_commitment_context = garbler$commitment_context,
    evaluator_commitment_context = evaluator$commitment_context,
    garbler_seed_commitment = garbler$seed_commitment,
    evaluator_seed_commitment = evaluator$seed_commitment,
    analyst_selected_roles = FALSE)
}

.dsvert_joint_dp_vector_exact_gc_binding <- function(
    selection, manifest_sha256, release_contract_hash, transcript_hash,
    chunk_index, worker_contract) {
  .dsvert_joint_dp_vector_exact_gc_selection_validate(
    selection, manifest_sha256, require_exact = TRUE)
  release_contract_hash <- .dsvert_joint_dp_vector_exact_gc_hex(
    release_contract_hash, "vector release contract hash")
  transcript_hash <- .dsvert_joint_dp_vector_exact_gc_hex(
    transcript_hash, "vector transcript hash")
  chunk_index <- .dsvert_joint_dp_vector_exact_gc_integer(
    chunk_index, "vector chunk index", 0L, 1000000L)
  if (!is.list(worker_contract) ||
      !identical(worker_contract$operation,
                 .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION) ||
      !is.character(worker_contract$purpose) ||
      !grepl(paste0("^",
        .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION,
        "/[0-9a-f]{64}$"), worker_contract$purpose) ||
      !identical(worker_contract$worker_policy$transcript_hash,
                 transcript_hash)) {
    stop("The exact-GC worker is not bound to this vector transcript.",
         call. = FALSE)
  }
  identity <- list(
    domain = "dsVert/joint-dp/vector/exact-gc-operation/v1",
    manifest_sha256 = manifest_sha256,
    release_contract_hash = release_contract_hash,
    selection_sha256 = selection$selection_sha256,
    transcript_hash = transcript_hash,
    chunk_index = chunk_index,
    coordinate_count = as.integer(
      worker_contract$worker_policy$coordinate_count),
    circuit_digest = worker_contract$circuit_digest,
    purpose = worker_contract$purpose)
  digest <- .dsvert_joint_dp_vector_exact_gc_hash(identity)
  suffix <- substr(digest, 1L, 32L)
  unsigned <- c(list(
    version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BINDING_VERSION),
    identity, list(
      operation_id = paste0("op_", suffix),
      source_key = paste0("exact_gc_in_", suffix),
      output_key = paste0("exact_gc_out_", suffix),
      operation = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION,
      output_kind = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OUTPUT_KIND,
      source_producer = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_PRODUCER))
  c(unsigned, list(
    binding_sha256 = .dsvert_joint_dp_vector_exact_gc_hash(unsigned)))
}

.dsvert_joint_dp_vector_exact_gc_binding_validate <- function(
    binding, selection, manifest_sha256, release_contract_hash,
    transcript_hash, chunk_index, worker_contract) {
  expected <- .dsvert_joint_dp_vector_exact_gc_binding(
    selection, manifest_sha256, release_contract_hash, transcript_hash,
    chunk_index, worker_contract)
  if (!identical(
        .dsvert_dp_canonical_query_value(binding),
        .dsvert_dp_canonical_query_value(expected))) {
    stop("The exact-GC vector operation binding was modified.",
         call. = FALSE)
  }
  invisible(expected)
}

.dsvert_joint_dp_vector_exact_gc_seed_b64 <- function(value) {
  if (is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[0-9a-f]{64}$", value)) {
    bytes <- as.raw(strtoi(substring(
      value, seq.int(1L, 63L, 2L), seq.int(2L, 64L, 2L)), 16L))
  } else {
    bytes <- tryCatch(jsonlite::base64_dec(value), error = function(e) NULL)
  }
  if (is.null(bytes) || !is.raw(bytes) || length(bytes) != 32L) {
    stop("Invalid private exact-GC vector seed.", call. = FALSE)
  }
  gsub("[\r\n]", "", jsonlite::base64_enc(bytes))
}

.dsvert_joint_dp_vector_exact_gc_start <- function(
    ss, session_id, binding, selection, manifest_sha256,
    release_contract_hash, transcript_hash, chunk_index, worker_contract,
    source_share, private_seed, .stage = .exact_gc_stage_share,
    .initialize = .exact_gc_init_impl, .binary = NULL) {
  if (!is.environment(ss) || !is.function(.stage) ||
      !is.function(.initialize)) {
    stop("Invalid exact-GC vector session adapter.", call. = FALSE)
  }
  .dsvert_joint_dp_vector_exact_gc_binding_validate(
    binding, selection, manifest_sha256, release_contract_hash,
    transcript_hash, chunk_index, worker_contract)
  count <- .dsvert_joint_dp_vector_exact_gc_integer(
    worker_contract$worker_policy$coordinate_count,
    "exact-GC coordinate count", 1L, 128L)
  source_b64 <- if (is.raw(source_share)) {
    if (length(source_share) != count * 16L) {
      stop("The private Ring128 vector share has the wrong shape.",
           call. = FALSE)
    }
    gsub("[\r\n]", "", jsonlite::base64_enc(source_share))
  } else {
    source_share
  }
  .exact_gc_validate_residue_records(
    source_b64, 128L, count, "joint-DP vector source share")
  seed_b64 <- .dsvert_joint_dp_vector_exact_gc_seed_b64(private_seed)
  .stage(
    ss, binding$source_key, source_b64, 128L, count,
    binding$source_producer, binding$operation, binding$purpose, 0L,
    binding$output_kind)
  init_args <- list(
    ss = ss, session_id = session_id,
    operation_id = binding$operation_id,
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    source_key = binding$source_key, output_key = binding$output_key,
    operation = binding$operation, ring = 128L, frac_bits = 0L,
    vector_len = count, purpose = binding$purpose,
    joint_dp_vector = worker_contract$worker_policy,
    private_seed = seed_b64)
  if (!is.null(.binary)) init_args$binary <- .binary
  initialized <- do.call(.initialize, init_args)
  seed_b64 <- NULL
  source_b64 <- NULL
  source_share <- NULL
  private_seed <- NULL
  list(
    version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_START_VERSION,
    backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND,
    binding_sha256 = binding$binding_sha256,
    operation_id = binding$operation_id,
    purpose = binding$purpose,
    initialization = initialized,
    intermediate_payload_exposed = FALSE,
    source_share_exposed = FALSE,
    private_seed_exposed = FALSE,
    preclamp_values_exposed = FALSE)
}

.dsvert_joint_dp_vector_exact_gc_consume <- function(
    ss, binding, worker_contract, .commit,
    .consume = .exact_gc_consume_output) {
  if (!is.environment(ss) || !is.function(.commit) ||
      !is.function(.consume) || !is.list(binding) ||
      !identical(binding$binding_sha256,
        .dsvert_joint_dp_vector_exact_gc_hash(
          binding[setdiff(names(binding), "binding_sha256")])) ||
      !identical(binding$purpose, worker_contract$purpose)) {
    stop("Invalid exact-GC vector output binding.", call. = FALSE)
  }
  count <- .dsvert_joint_dp_vector_exact_gc_integer(
    worker_contract$worker_policy$coordinate_count,
    "exact-GC coordinate count", 1L, 128L)
  read_output <- function(consume) .consume(
    ss, binding$output_key, binding$operation_id,
    .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OUTPUT_KIND,
    .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION,
    binding$purpose, 128L, 0L, count,
    .DSVERT_JOINT_DP_VECTOR_EXACT_GC_PRODUCER,
    consume = consume)
  output <- read_output(FALSE)
  share <- .exact_gc_validate_residue_records(
    output$share, 128L, count, "joint-DP vector exact-GC output share")
  validity <- .exact_gc_standard_b64_raw(
    output$validity_share, 1L,
    "joint-DP vector exact-GC validity share")
  if (!as.integer(validity[[1L]]) %in% 0:1) {
    stop("Non-canonical exact-GC vector validity share.", call. = FALSE)
  }
  internal <- list(
    noised_share_b64 = output$share,
    validity_share_b64 = output$validity_share,
    noised_share_sha256 = digest::digest(
      share, algo = "sha256", serialize = FALSE),
    validity_share_sha256 = digest::digest(
      validity, algo = "sha256", serialize = FALSE),
    binding_sha256 = binding$binding_sha256,
    purpose = binding$purpose,
    operation_id = binding$operation_id,
    backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND)
  if (!identical(.commit(internal), TRUE)) {
    stop("The durable exact-GC vector commit did not complete.",
         call. = FALSE)
  }
  consumed <- read_output(TRUE)
  if (!identical(consumed$share, output$share) ||
      !identical(consumed$validity_share, output$validity_share)) {
    stop("The exact-GC vector output changed during durable commit.",
         call. = FALSE)
  }
  list(
    version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_COMMIT_VERSION,
    backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND,
    binding_sha256 = binding$binding_sha256,
    operation_id = binding$operation_id,
    purpose = binding$purpose,
    noised_share_sha256 = internal$noised_share_sha256,
    validity_share_sha256 = internal$validity_share_sha256,
    durable = TRUE,
    intermediate_payload_exposed = FALSE,
    source_share_exposed = FALSE,
    private_seed_exposed = FALSE,
    preclamp_values_exposed = FALSE)
}

.dsvert_joint_dp_vector_exact_gc_finalize <- function(
    own, peer, scaled_upper_bounds, binding_sha256) {
  binding_sha256 <- .dsvert_joint_dp_vector_exact_gc_hex(
    binding_sha256, "exact-GC vector binding hash")
  required <- c("noised_share_b64", "validity_share_b64",
                "binding_sha256")
  if (!is.list(own) || !is.list(peer) ||
      !all(required %in% names(own)) || !all(required %in% names(peer)) ||
      !identical(own$binding_sha256, binding_sha256) ||
      !identical(peer$binding_sha256, binding_sha256) ||
      !is.character(scaled_upper_bounds) || !length(scaled_upper_bounds) ||
      anyNA(scaled_upper_bounds) ||
      any(!grepl("^(0|[1-9][0-9]*)$", scaled_upper_bounds))) {
    stop("Invalid purpose-bound exact-GC vector share pair.",
         call. = FALSE)
  }
  count <- length(scaled_upper_bounds)
  own_share <- .exact_gc_validate_residue_records(
    own$noised_share_b64, 128L, count, "local exact-GC vector share")
  peer_share <- .exact_gc_validate_residue_records(
    peer$noised_share_b64, 128L, count, "peer exact-GC vector share")
  own_validity <- .exact_gc_standard_b64_raw(
    own$validity_share_b64, 1L, "local exact-GC validity share")
  peer_validity <- .exact_gc_standard_b64_raw(
    peer$validity_share_b64, 1L, "peer exact-GC validity share")
  validity <- bitwXor(as.integer(own_validity[[1L]]),
                      as.integer(peer_validity[[1L]]))
  if (!as.integer(own_validity[[1L]]) %in% 0:1 ||
      !as.integer(peer_validity[[1L]]) %in% 0:1 || validity != 1L) {
    stop("The exact-GC vector validity shares reject this output.",
         call. = FALSE)
  }
  modulus <- openssl::bignum(2) ^ 128L
  values <- vapply(seq_len(count), function(index) {
    offset <- (index - 1L) * 16L
    left <- openssl::bignum(rev(own_share[offset + seq_len(16L)]))
    right <- openssl::bignum(rev(peer_share[offset + seq_len(16L)]))
    value <- (left + right) %% modulus
    upper <- openssl::bignum(scaled_upper_bounds[[index]])
    if (value > upper) {
      stop("The exact-GC output exceeds its fixed public clamp.",
           call. = FALSE)
    }
    as.character(value)
  }, character(1L))
  list(
    version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_FINAL_VERSION,
    backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND,
    operation = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION,
    binding_sha256 = binding_sha256,
    clamped_scaled_values = as.list(values),
    validity = TRUE,
    signed_decode = "not_required_nonnegative_clamped_gc_output",
    clamping = "inside_exact_gc_before_selective_additive_sharing",
    preclamp_values_returned = FALSE,
    source_share_exposed = FALSE,
    private_seed_exposed = FALSE)
}
