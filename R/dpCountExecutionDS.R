# Stateless, per-operation execution for the canonical Count analysis.
#
# Durable randomness is derived only by dpAnalysisContract.R from the local
# persistent identity seed. Everything below is confined to one MPC session
# and the bounded exact-GC / typed-blob spools owned by that session.

.DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_VERSION <-
  "dsvert-dp-count-public-authorization-v1"
.DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_DOMAIN <-
  "dsVert/dp-count/public-authorization/v1|"
.DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_SIGNATURE_DOMAIN <-
  "dsVert/dp-count/public-authorization-signature/v1|"
.DSVERT_DP_COUNT_WORKER_STATIC_DOMAIN <-
  "dsVert/dp-count/worker-static/v1|"
.DSVERT_DP_COUNT_EXECUTION_VERSION <- "dsvert-dp-count-execution-v1"
.DSVERT_DP_COUNT_EXECUTION_PRODUCER <- "count.scalar.v1"
.DSVERT_DP_COUNT_FINAL_PAYLOAD_VERSION <-
  "dsvert-dp-count-final-share-payload-v1"
.DSVERT_DP_COUNT_FINAL_CAPABILITY <-
  "blob.analysis-dp.count-final-share.v1"
.DSVERT_DP_COUNT_FINAL_PRODUCER <- "dsvertDPCountFinalShareDS"
.DSVERT_DP_COUNT_RELEASE_VERSION <- "dsvert-dp-count-release-v1"
.DSVERT_DP_COUNT_RELEASE_DOMAIN <- "dsVert/dp-count/release/v1|"
.DSVERT_DP_COUNT_RELEASE_SIGNATURE_DOMAIN <-
  "dsVert/dp-count/release-signature/v1|"
.DSVERT_DP_COUNT_CONFIG_MAX_BYTES <- 1024L * 1024L
.DSVERT_DP_COUNT_RECEIPTS_MAX_BYTES <- 16L * 1024L^2
.DSVERT_DP_COUNT_AUTHORIZATIONS_MAX_BYTES <- 1024L * 1024L

.dsvert_dp_count_execution_json_v1 <- function(value, what,
                                                maximum_bytes) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    stop("Invalid Count ", what, ".", call. = FALSE)
  }
  parsed <- tryCatch(
    jsonlite::fromJSON(value, simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(parsed)),
    error = function(error) NULL)
  if (is.null(parsed) || is.null(canonical) ||
      !identical(canonical, value)) {
    stop("Invalid or non-canonical Count ", what, ".", call. = FALSE)
  }
  parsed
}

.dsvert_dp_count_execution_decode_config_v1 <- function(value) {
  parsed <- .dsvert_dp_count_execution_json_v1(
    value, "configuration", .DSVERT_DP_COUNT_CONFIG_MAX_BYTES)
  pins <- parsed$peer_pins
  if (!is.list(pins) || !length(pins) || is.null(names(pins)) ||
      anyNA(names(pins)) || anyDuplicated(names(pins)) ||
      any(!vapply(pins, function(pin) {
        is.character(pin) && length(pin) == 1L && !is.na(pin)
      }, logical(1L)))) {
    stop("Invalid Count configuration.", call. = FALSE)
  }
  parsed$peer_pins <- unlist(pins, use.names = TRUE)
  .dsvert_dp_count_config_validate_v1(parsed)
}

.dsvert_dp_count_execution_decode_receipts_v1 <- function(value, config) {
  parsed <- .dsvert_dp_count_execution_json_v1(
    value, "receipt array", .DSVERT_DP_COUNT_RECEIPTS_MAX_BYTES)
  if (!is.list(parsed) || !is.null(names(parsed)) ||
      length(parsed) != length(config$peer_pins) ||
      any(!vapply(parsed, is.list, logical(1L)))) {
    stop("Count receipts must be one canonical JSON array.", call. = FALSE)
  }
  peers <- vapply(parsed, function(receipt) {
    if (!is.character(receipt$peer_name) ||
        length(receipt$peer_name) != 1L || is.na(receipt$peer_name)) "" else
      receipt$peer_name
  }, character(1L))
  if (!identical(peers, sort(names(config$peer_pins), method = "radix"))) {
    stop("Count receipts are not in canonical peer order.", call. = FALSE)
  }
  parsed
}

.dsvert_dp_count_worker_static_sha256_v1 <- function(worker_static) {
  .dsvert_dp_count_hash_v1(
    .DSVERT_DP_COUNT_WORKER_STATIC_DOMAIN, worker_static)
}

.dsvert_dp_count_seed_material_v1 <- function(authorization) {
  contract <- authorization$contract
  sticky <- .dsvert_dp_sticky_subseed_v1(contract, "final_noise")
  seed_raw <- .dsvert_joint_dp_backend_hex_raw_v2(
    sticky, "Count sticky final-noise seed")
  role <- authorization$local_authority$role
  context <- authorization$worker_static[[paste0(
    role, "_commitment_context")]]
  context_raw <- .dsvert_joint_dp_backend_hex_raw_v2(
    context, "Count seed commitment context")
  list(
    seed_raw = seed_raw,
    seed_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(seed_raw)),
    commitment_context = context,
    seed_commitment = .dsvert_joint_dp_backend_hash_raw_v2(c(
      context_raw, seed_raw)))
}

.dsvert_dp_count_public_authorization_message_v1 <- function(value) {
  charToRaw(paste0(
    .DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_SIGNATURE_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value))))
}

.dsvert_dp_count_public_authorization_v1 <- function(
    authorization, .signer = .dsvert_relay_sign_message) {
  local <- authorization$local_authority
  identity <- .get_identity_keypair()
  identity_pk <- .dsvert_relay_normalize_identity_pk(identity$identity_pk)
  if (!identical(identity_pk, local$identity_pk) ||
      !is.function(.signer)) {
    stop("The Count authorization signer is not the local authority.",
         call. = FALSE)
  }
  seed <- .dsvert_dp_count_seed_material_v1(authorization)
  core <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_VERSION,
    session_id = authorization$session_id,
    artifact_key = authorization$artifact_key,
    config_sha256 = authorization$config_sha256,
    receipt_set_sha256 = authorization$receipt_set_sha256,
    psi_run_sha256 = authorization$psi_run_sha256,
    contract_sha256 = authorization$contract_sha256,
    analysis_binding_sha256 = authorization$analysis_binding_sha256,
    worker_static_sha256 = .dsvert_dp_count_worker_static_sha256_v1(
      authorization$worker_static),
    local_authority = local,
    commitment_context = seed$commitment_context,
    seed_commitment = seed$seed_commitment))
  authorization_sha256 <- .dsvert_dp_count_hash_v1(
    .DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_DOMAIN, core)
  signed <- .dsvert_dp_canonical_query_value(c(
    core, list(authorization_sha256 = authorization_sha256)))
  signature <- .signer(
    .dsvert_dp_count_public_authorization_message_v1(signed),
    identity$identity_sk)
  .dsvert_dp_count_signature_v1(signature)
  .dsvert_dp_canonical_query_value(c(
    signed, list(signature = signature)))
}

.dsvert_dp_count_public_authorization_validate_v1 <- function(
    value, .verifier = .dsvert_relay_verify_message) {
  fields <- c(
    "version", "session_id", "artifact_key", "config_sha256",
    "receipt_set_sha256", "psi_run_sha256", "contract_sha256",
    "analysis_binding_sha256", "worker_static_sha256",
    "local_authority", "commitment_context", "seed_commitment",
    "authorization_sha256", "signature")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_VERSION) ||
      !is.function(.verifier)) {
    stop("Invalid signed Count public authorization.", call. = FALSE)
  }
  value$session_id <- .dsvert_relay_validate_session_id(value$session_id)
  for (field in c(
      "artifact_key", "config_sha256", "receipt_set_sha256",
      "psi_run_sha256", "contract_sha256", "analysis_binding_sha256",
      "worker_static_sha256", "commitment_context", "seed_commitment",
      "authorization_sha256")) {
    value[[field]] <- .dsvert_dp_count_hash_scalar_v1(
      value[[field]], paste("public authorization", field))
  }
  local <- value$local_authority
  if (!is.list(local) || is.null(names(local)) || anyNA(names(local)) ||
      anyDuplicated(names(local)) ||
      !setequal(names(local), c("peer_name", "identity_pk", "role")) ||
      !is.character(local$role) || length(local$role) != 1L ||
      !local$role %in% c("garbler", "evaluator")) {
    stop("Invalid signed Count public authorization.", call. = FALSE)
  }
  local$peer_name <- .dsvert_dp_count_peer_name_v1(local$peer_name)
  local$identity_pk <- tryCatch(
    .dsvert_relay_normalize_identity_pk(local$identity_pk),
    error = function(error) stop(
      "Invalid signed Count public authorization.", call. = FALSE))
  value$local_authority <- local
  signature <- .dsvert_dp_count_signature_v1(value$signature)
  core <- value[setdiff(names(value), c("authorization_sha256", "signature"))]
  expected_hash <- .dsvert_dp_count_hash_v1(
    .DSVERT_DP_COUNT_PUBLIC_AUTHORIZATION_DOMAIN, core)
  signed <- .dsvert_dp_canonical_query_value(c(
    core, list(authorization_sha256 = expected_hash)))
  valid <- identical(value$authorization_sha256, expected_hash) &&
    if (identical(.verifier, .dsvert_relay_verify_message)) {
      .verifier(
        .dsvert_dp_count_public_authorization_message_v1(signed),
        local$identity_pk, signature)
    } else {
      .verifier(
        .dsvert_dp_count_public_authorization_message_v1(signed),
        local$identity_pk, signature, local$peer_name)
    }
  if (!isTRUE(valid)) {
    stop("Count public authorization signature verification failed.",
         call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(c(
    signed, list(signature = signature)))
}

.dsvert_dp_count_decode_authorizations_v1 <- function(
    value, authorization, .verifier = .dsvert_relay_verify_message) {
  parsed <- .dsvert_dp_count_execution_json_v1(
    value, "authorization array",
    .DSVERT_DP_COUNT_AUTHORIZATIONS_MAX_BYTES)
  if (!is.list(parsed) || !is.null(names(parsed)) ||
      length(parsed) != 2L || any(!vapply(parsed, is.list, logical(1L)))) {
    stop("Count requires exactly two public authorizations.", call. = FALSE)
  }
  verified <- lapply(
    parsed, .dsvert_dp_count_public_authorization_validate_v1,
    .verifier = .verifier)
  roles <- vapply(verified, function(value) {
    value$local_authority$role
  }, character(1L))
  expected_order <- c("garbler", "evaluator")
  if (!identical(roles, expected_order)) {
    stop("Count public authorizations are not in canonical role order.",
         call. = FALSE)
  }
  names(verified) <- roles
  expected_roles <- authorization$analysis_binding$authority_roles[
    expected_order]
  identities <- lapply(verified, function(value) {
    value$local_authority$identity_pk
  })
  common <- c(
    "session_id", "artifact_key", "config_sha256", "receipt_set_sha256",
    "psi_run_sha256", "contract_sha256", "analysis_binding_sha256",
    "worker_static_sha256")
  expected_common <- list(
    session_id = authorization$session_id,
    artifact_key = authorization$artifact_key,
    config_sha256 = authorization$config_sha256,
    receipt_set_sha256 = authorization$receipt_set_sha256,
    psi_run_sha256 = authorization$psi_run_sha256,
    contract_sha256 = authorization$contract_sha256,
    analysis_binding_sha256 = authorization$analysis_binding_sha256,
    worker_static_sha256 = .dsvert_dp_count_worker_static_sha256_v1(
      authorization$worker_static))
  contexts <- c(
    garbler = authorization$worker_static$garbler_commitment_context,
    evaluator = authorization$worker_static$evaluator_commitment_context)
  common_valid <- all(vapply(verified, function(value) {
    identical(value[common], expected_common)
  }, logical(1L)))
  role_valid <- all(vapply(names(verified), function(role) {
    value <- verified[[role]]
    identical(value$local_authority$identity_pk,
              expected_roles[[role]]) &&
      identical(value$commitment_context, contexts[[role]]) &&
      identical(
        unname(authorization$config$peer_pins[[
          value$local_authority$peer_name]]),
        value$local_authority$identity_pk)
  }, logical(1L)))
  if (!isTRUE(common_valid) || !isTRUE(role_valid) ||
      !identical(unname(identities), unname(expected_roles))) {
    stop("Count public authorizations do not match the local contract.",
         call. = FALSE)
  }
  local_role <- authorization$local_authority$role
  local_seed <- .dsvert_dp_count_seed_material_v1(authorization)
  if (!identical(
        verified[[local_role]]$seed_commitment,
        local_seed$seed_commitment)) {
    stop("The local Count sticky seed conflicts with its authorization.",
         call. = FALSE)
  }
  verified
}

# Internal execution route. Registration and documentation are promoted with
# the matching client orchestration only after the complete flow is verified.
.dsvert_dp_count_authorize_endpoint_v1 <- function(
    config_json, receipts_json, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  config_json <- .dsvert_dsi_text_decode(
    config_json, "Count configuration", .DSVERT_DP_COUNT_CONFIG_MAX_BYTES)
  receipts_json <- .dsvert_dsi_text_decode(
    receipts_json, "Count receipt array",
    .DSVERT_DP_COUNT_RECEIPTS_MAX_BYTES)
  config <- .dsvert_dp_count_execution_decode_config_v1(config_json)
  receipts <- .dsvert_dp_count_execution_decode_receipts_v1(
    receipts_json, config)
  ss <- .S(session_id)
  prior <- ss$.dp_count_authorization
  installed <- NULL
  committed <- FALSE
  on.exit(if (!committed && is.null(prior) &&
              !is.null(installed) &&
              identical(ss$.dp_count_authorization, installed)) {
    ss$.dp_count_authorization <- NULL
  }, add = TRUE)
  installed <- .dsvert_dp_count_authorize_session_v1(
    ss, session_id, config, receipts)
  public <- .dsvert_dp_count_public_authorization_v1(installed)
  committed <- TRUE
  public
}

.dsvert_dp_count_execution_source_share_v1 <- function(count, role) {
  if (!is.numeric(count) || length(count) != 1L || is.na(count) ||
      !is.finite(count) || count != floor(count) || count < 0 ||
      count > 1000000) {
    stop("Invalid Count aligned execution count.", call. = FALSE)
  }
  if (!is.character(role) || length(role) != 1L || is.na(role) ||
      !role %in% c("garbler", "evaluator")) {
    stop("Invalid Count authority role.", call. = FALSE)
  }
  .exact_gc_decimal_residues_b64(
    if (identical(role, "garbler")) as.character(as.integer(count)) else
      "0",
    127L)
}

.dsvert_dp_count_compile_worker_v1 <- function(
    authorization, authorizations,
    .compiler = function(value) {
      .callMpcTool("joint-dp-laplace-worker-contract-v2", value)
    }) {
  if (!is.function(.compiler)) {
    stop("Invalid Count worker compiler.", call. = FALSE)
  }
  static <- authorization$worker_static
  input <- list(
    version = .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT_INPUT,
    ring_bits = static$ring_bits,
    frac_bits = static$frac_bits,
    coordinate_count = static$coordinate_count,
    epsilon = static$epsilon,
    allocated_delta = static$allocated_delta,
    sensitivity_steps = static$sensitivity_steps,
    encoded_lower = static$encoded_lower,
    encoded_upper = static$encoded_upper,
    bernoulli_bits = static$bernoulli_bits,
    max_steps = 4096L,
    transcript_hash = static$transcript_hash,
    garbler_commitment_context = static$garbler_commitment_context,
    evaluator_commitment_context = static$evaluator_commitment_context,
    garbler_seed_commitment = authorizations$garbler$seed_commitment,
    evaluator_seed_commitment = authorizations$evaluator$seed_commitment)
  compiled <- .compiler(input)
  required <- c(
    "version", "capability_id", "operation", "purpose",
    "circuit_digest", "input_contract", "protected_inputs_accepted",
    "private_seed_accepted", "worker_policy", "capability_available")
  policy_fields <- c(
    "version", "sampler", "bernoulli_bits", "stop_numerator",
    "max_geometric_steps", "sensitivity_steps", "epsilon",
    "allocated_delta", "encoded_lower", "encoded_upper",
    "transcript_hash", "garbler_commitment_context",
    "evaluator_commitment_context", "garbler_seed_commitment",
    "evaluator_seed_commitment", "circuit_digest",
    "implementation_delta_numerator",
    "implementation_delta_denominator")
  expected_policy <- list(
    version = .DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2,
    sampler = static$sampler,
    bernoulli_bits = static$bernoulli_bits,
    stop_numerator = static$stop_numerator,
    max_geometric_steps = static$max_geometric_steps,
    sensitivity_steps = static$sensitivity_steps,
    epsilon = static$epsilon,
    allocated_delta = static$allocated_delta,
    encoded_lower = static$encoded_lower,
    encoded_upper = static$encoded_upper,
    transcript_hash = static$transcript_hash,
    garbler_commitment_context = static$garbler_commitment_context,
    evaluator_commitment_context = static$evaluator_commitment_context,
    garbler_seed_commitment =
      authorizations$garbler$seed_commitment,
    evaluator_seed_commitment =
      authorizations$evaluator$seed_commitment,
    implementation_delta_numerator =
      static$implementation_delta_numerator,
    implementation_delta_denominator =
      static$implementation_delta_denominator)
  valid <- is.list(compiled) && !is.null(names(compiled)) &&
    !anyNA(names(compiled)) && !anyDuplicated(names(compiled)) &&
    setequal(names(compiled), required) &&
    is.list(compiled$worker_policy) &&
    !is.null(names(compiled$worker_policy)) &&
    !anyNA(names(compiled$worker_policy)) &&
    !anyDuplicated(names(compiled$worker_policy)) &&
    setequal(names(compiled$worker_policy), policy_fields) &&
    identical(compiled$version,
              .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT) &&
    identical(compiled$capability_id,
              .DSVERT_JOINT_DP_COUNT_EXACT_CAPABILITY) &&
    identical(compiled$operation, "joint-dp-laplace-v2") &&
    identical(compiled$input_contract, "public-data-free-count-v1") &&
    identical(compiled$protected_inputs_accepted, FALSE) &&
    identical(compiled$private_seed_accepted, FALSE) &&
    identical(compiled$capability_available, TRUE) &&
    is.character(compiled$circuit_digest) &&
    length(compiled$circuit_digest) == 1L &&
    grepl("^[0-9a-f]{64}$", compiled$circuit_digest) &&
    identical(compiled$purpose,
              paste0("joint-dp-laplace-v2/", compiled$circuit_digest)) &&
    identical(compiled$worker_policy$circuit_digest,
              compiled$circuit_digest) &&
    all(vapply(names(expected_policy), function(field) {
      if (field %in% c("bernoulli_bits", "max_geometric_steps")) {
        identical(as.numeric(compiled$worker_policy[[field]]),
                  as.numeric(expected_policy[[field]]))
      } else {
        identical(compiled$worker_policy[[field]], expected_policy[[field]])
      }
    }, logical(1L)))
  if (!isTRUE(valid)) {
    stop("The Count worker compiler returned an invalid contract.",
         call. = FALSE)
  }
  compiled
}

.dsvert_dp_count_execution_binding_v1 <- function(
    ss, session_id, authorization) {
  .exact_gc_validate_bound_peer_context(ss, session_id)
  contract <- ss$.exact_gc_peer_binding_contract
  if (!is.list(contract) ||
      !identical(contract$version,
                 .DSVERT_EXACT_GC_ANALYSIS_PEER_BINDING_VERSION) ||
      !identical(contract$consortium_id, authorization$artifact_key) ||
      !identical(ss$.exact_gc_analysis_binding,
                 authorization$analysis_binding) ||
      !identical(ss$.exact_gc_analysis_binding_sha256,
                 authorization$analysis_binding_sha256) ||
      !identical(ss$.exact_gc_analysis_contract,
                 authorization$contract)) {
    stop("Count Start requires its authorized exact-gc peer binding.",
         call. = FALSE)
  }
  invisible(contract)
}

.dsvert_dp_count_execution_snapshot_v1 <- function(
    data, authorization) {
  local <- authorization$local_authority
  signed_plan <- authorization$contract$semantic$analysis$
    effective_arguments$sampler_plan
  signed_planner <- function(...) c(
    signed_plan,
    list(capability_available = TRUE, unavailable_reason = ""))
  draft <- .dsvert_dp_count_local_draft_v1(
    data, authorization$config, local$peer_name,
    .planner = signed_planner)
  expected <- authorization$contract$semantic$owner_snapshots[[
    local$identity_pk]]
  if (!is.list(expected) ||
      !identical(draft$snapshot_commitment,
                 expected$snapshot_commitment) ||
      !identical(draft$psi_run_sha256,
                 authorization$psi_run_sha256) ||
      !identical(draft$sampler_plan, signed_plan) ||
      !identical(draft$config_sha256,
                 authorization$config_sha256)) {
    stop("The current Count source does not match its signed snapshot.",
         call. = FALSE)
  }
  list(
    count = nrow(data),
    snapshot_commitment = draft$snapshot_commitment,
    psi_run_sha256 = draft$psi_run_sha256)
}

.dsvert_dp_count_role_map_v1 <- function(authorizations) {
  list(
    source = list(
      role = "garbler",
      peer_name = authorizations$garbler$local_authority$peer_name,
      identity_pk =
        authorizations$garbler$local_authority$identity_pk),
    finalizer = list(
      role = "evaluator",
      peer_name = authorizations$evaluator$local_authority$peer_name,
      identity_pk =
        authorizations$evaluator$local_authority$identity_pk))
}

.dsvert_dp_count_execution_request_v1 <- function(
    authorization, authorizations, snapshot, operation_id, source_key,
    output_key, worker) {
  role_map <- .dsvert_dp_count_role_map_v1(authorizations)
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_COUNT_EXECUTION_VERSION,
    artifact_key = authorization$artifact_key,
    contract_sha256 = authorization$contract_sha256,
    analysis_binding_sha256 = authorization$analysis_binding_sha256,
    worker_static_sha256 = .dsvert_dp_count_worker_static_sha256_v1(
      authorization$worker_static),
    authorization_set_sha256 = .dsvert_dp_count_hash_v1(
      "dsVert/dp-count/public-authorization-set/v1|",
      authorizations),
    local_authority = authorization$local_authority,
    role_map = role_map,
    snapshot_commitment = snapshot$snapshot_commitment,
    psi_run_sha256 = snapshot$psi_run_sha256,
    operation_id = operation_id,
    source_key = source_key,
    output_key = output_key,
    circuit = worker$purpose))
}

.dsvert_dp_count_start_impl_v1 <- function(
    data, session_id, operation_id, source_key, output_key,
    authorizations_json, .verifier = .dsvert_relay_verify_message,
    .compiler = function(value) {
      .callMpcTool("joint-dp-laplace-worker-contract-v2", value)
    }, binary = .findMpcBinary()) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  source_key <- .exact_gc_validate_key(source_key)
  output_key <- .exact_gc_validate_key(output_key, output = TRUE)
  if (!is.data.frame(data)) {
    stop("The Count source must be a padded-PSI aligned data frame.",
         call. = FALSE)
  }
  ss <- .S(session_id)
  authorization <- .dsvert_dp_count_session_authorization_validate_v1(
    ss, session_id)
  .dsvert_dp_count_execution_binding_v1(
    ss, session_id, authorization)
  authorizations <- .dsvert_dp_count_decode_authorizations_v1(
    authorizations_json, authorization, .verifier = .verifier)
  snapshot <- .dsvert_dp_count_execution_snapshot_v1(data, authorization)
  worker <- .dsvert_dp_count_compile_worker_v1(
    authorization, authorizations, .compiler = .compiler)
  request <- .dsvert_dp_count_execution_request_v1(
    authorization, authorizations, snapshot, operation_id, source_key,
    output_key, worker)
  previous <- ss$.dp_count_execution
  if (!is.null(previous) && !identical(previous, request)) {
    stop("A Count session is bound to exactly one cryptographic operation.",
         call. = FALSE)
  }
  if (is.null(previous)) {
    ss$.dp_count_execution <- request
  }
  exact_previous <- .exact_gc_operation_state(
    ss, operation_id, required = FALSE)
  seed <- .dsvert_dp_count_seed_material_v1(authorization)
  on.exit({
    seed$seed_raw <- raw(0L)
    seed$seed_b64 <- NULL
  }, add = TRUE)
  initialize <- function() .exact_gc_init_impl(
    ss, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
    source_key, output_key, "joint-dp-laplace-v2", 127L, 0L, 1L,
    worker$purpose, joint_dp = worker$worker_policy,
    private_seed = seed$seed_b64, binary = binary)
  if (!is.null(previous) && !is.null(exact_previous)) {
    return(initialize())
  }
  share <- .dsvert_dp_count_execution_source_share_v1(
    snapshot$count, authorization$local_authority$role)
  .exact_gc_stage_share(
    ss, source_key, share, 127L, 1L,
    .DSVERT_DP_COUNT_EXECUTION_PRODUCER,
    "joint-dp-laplace-v2", worker$purpose, 0L,
    "joint-dp-ring-share-v2")
  rm(share)
  initialize()
}

# Internal execution route. The client supplies only the protected object
# locator, opaque operation keys and the two signed public commitments.
.dsvert_dp_count_start_endpoint_v1 <- function(
    data_name, session_id, operation_id, source_key, output_key,
    authorizations_json) {
  data_name <- .psi_padded_data_name(data_name)
  authorizations_json <- .dsvert_dsi_text_decode(
    authorizations_json, "Count authorization array",
    .DSVERT_DP_COUNT_AUTHORIZATIONS_MAX_BYTES)
  data <- get(data_name, envir = parent.frame(), inherits = TRUE)
  .dsvert_dp_count_start_impl_v1(
    data, session_id, operation_id, source_key, output_key,
    authorizations_json)
}

.dsvert_dp_count_execution_record_v1 <- function(
    ss, session_id, operation_id, output_key, required_role) {
  authorization <- .dsvert_dp_count_session_authorization_validate_v1(
    ss, session_id)
  .dsvert_dp_count_execution_binding_v1(
    ss, session_id, authorization)
  record <- ss$.dp_count_execution
  if (!is.list(record) ||
      !identical(record$version, .DSVERT_DP_COUNT_EXECUTION_VERSION) ||
      !identical(record$artifact_key, authorization$artifact_key) ||
      !identical(record$contract_sha256,
                 authorization$contract_sha256) ||
      !identical(record$analysis_binding_sha256,
                 authorization$analysis_binding_sha256) ||
      !identical(record$operation_id, operation_id) ||
      !identical(record$output_key, output_key) ||
      !identical(record$local_authority,
                 authorization$local_authority) ||
      !identical(record$local_authority$role, required_role)) {
    stop("Count execution is unavailable or has the wrong authority role.",
         call. = FALSE)
  }
  state <- .exact_gc_operation_state(ss, operation_id)
  .exact_gc_refresh(ss, state)
  if (!identical(state$status, "complete") ||
      !identical(state$role, required_role) ||
      !identical(state$output_key, output_key) ||
      !identical(state$purpose, record$circuit) ||
      !identical(state$analysis_binding_sha256,
                 authorization$analysis_binding_sha256)) {
    stop("Count exact-gc output is not complete in the required role.",
         call. = FALSE)
  }
  list(authorization = authorization, execution = record,
       exact_state = state)
}

.dsvert_dp_count_output_v1 <- function(ss, record, consume = FALSE) {
  .exact_gc_consume_output(
    ss, record$execution$output_key,
    record$execution$operation_id,
    "joint-dp-ring-share-v2", "joint-dp-laplace-v2",
    record$execution$circuit, 127L, 0L, 1L,
    .DSVERT_DP_COUNT_EXECUTION_PRODUCER, consume = consume)
}

.dsvert_dp_count_final_context_v1 <- function(record) {
  roles <- list(
    source = record$execution$role_map$source$peer_name,
    finalizer = record$execution$role_map$finalizer$peer_name)
  .dsvert_dp_canonical_query_value(list(
    artifact_key = record$authorization$artifact_key,
    contract_hash = record$authorization$contract_sha256,
    circuit = record$execution$circuit,
    roles = roles,
    sender = roles$source,
    recipient = roles$finalizer))
}

.dsvert_dp_count_final_payload_v1 <- function(record, output) {
  .exact_gc_validate_residue_records(
    output$share, 127L, 1L, "Count final output share")
  validity <- .exact_gc_standard_b64_raw(
    output$validity_share, 1L, "Count final validity share")
  if (!as.integer(validity[[1L]]) %in% 0:1) {
    stop("Count final validity share is non-canonical.", call. = FALSE)
  }
  upper <- record$authorization$worker_static$encoded_upper
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_COUNT_FINAL_PAYLOAD_VERSION,
    artifact_key = record$authorization$artifact_key,
    contract_sha256 = record$authorization$contract_sha256,
    analysis_binding_sha256 =
      record$authorization$analysis_binding_sha256,
    worker_static_sha256 = record$execution$worker_static_sha256,
    operation_id = record$execution$operation_id,
    output_key = record$execution$output_key,
    circuit = record$execution$circuit,
    exact_context_hash = output$context_hash,
    lower_bound = "0", upper_bound = upper,
    ring_bits = 127L, vector_len = 1L,
    share = output$share,
    validity_share = output$validity_share))
}

.dsvert_dp_count_final_payload_decode_v1 <- function(value) {
  if (!is.raw(value)) {
    stop("Invalid encrypted Count final-share payload.", call. = FALSE)
  }
  parsed <- tryCatch(
    jsonlite::fromJSON(rawToChar(value), simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(charToRaw(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(parsed))),
    error = function(error) NULL)
  fields <- c(
    "version", "artifact_key", "contract_sha256",
    "analysis_binding_sha256", "worker_static_sha256", "operation_id",
    "output_key", "circuit", "exact_context_hash", "lower_bound",
    "upper_bound", "ring_bits", "vector_len", "share",
    "validity_share")
  valid <- is.list(parsed) && !is.null(names(parsed)) &&
    !anyNA(names(parsed)) && !anyDuplicated(names(parsed)) &&
    setequal(names(parsed), fields) && identical(canonical, value) &&
    identical(parsed$version, .DSVERT_DP_COUNT_FINAL_PAYLOAD_VERSION) &&
    identical(as.numeric(parsed$ring_bits), 127) &&
    identical(as.numeric(parsed$vector_len), 1) &&
    identical(parsed$lower_bound, "0") &&
    is.character(parsed$circuit) && length(parsed$circuit) == 1L &&
    grepl("^joint-dp-laplace-v2/[0-9a-f]{64}$", parsed$circuit)
  if (!isTRUE(valid)) {
    stop("Invalid encrypted Count final-share payload.", call. = FALSE)
  }
  for (field in c(
      "artifact_key", "contract_sha256", "analysis_binding_sha256",
      "worker_static_sha256", "exact_context_hash")) {
    .dsvert_dp_count_hash_scalar_v1(
      parsed[[field]], paste("final payload", field))
  }
  .dsvert_relay_validate_operation_id(parsed$operation_id)
  .exact_gc_validate_key(parsed$output_key, output = TRUE)
  .dsvert_dp_count_positive_integer_v1(
    as.numeric(parsed$upper_bound), "final payload upper bound", 1000000)
  parsed$share_raw <- .exact_gc_validate_residue_records(
    parsed$share, 127L, 1L, "Count final output share")
  parsed$validity_raw <- .exact_gc_standard_b64_raw(
    parsed$validity_share, 1L, "Count final validity share")
  if (!as.integer(parsed$validity_raw[[1L]]) %in% 0:1) {
    stop("Count final validity share is non-canonical.", call. = FALSE)
  }
  parsed
}

.dsvert_dp_count_final_share_state_v1 <- function(ss) {
  if (!is.environment(ss$.dp_count_final_shares)) {
    ss$.dp_count_final_shares <- new.env(parent = emptyenv())
  }
  ss$.dp_count_final_shares
}

.dsvert_dp_count_final_share_impl_v1 <- function(
    ss, session_id, operation_id, output_key, recipient_pk) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  output_key <- .exact_gc_validate_key(output_key, output = TRUE)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid Count final-share session.", call. = FALSE)
  }
  record <- .dsvert_dp_count_execution_record_v1(
    ss, session_id, operation_id, output_key, "garbler")
  recipient_name <- .dsvert_typed_blob_recipient_name(ss, recipient_pk)
  expected_recipient <- record$execution$role_map$finalizer$peer_name
  if (!identical(recipient_name, expected_recipient)) {
    stop("The Count final share must target its identity-bound evaluator.",
         call. = FALSE)
  }
  peer_pk <- (ss$peer_transport_pks %||% list())[[recipient_name]]
  if (is.null(peer_pk)) {
    stop("The Count finalizer transport key is unavailable.",
         call. = FALSE)
  }
  request <- list(
    session_id = session_id,
    operation_id = operation_id,
    output_key = output_key,
    artifact_key = record$authorization$artifact_key,
    exact_context_hash = record$exact_state$context_hash,
    recipient_identity_pk =
      record$execution$role_map$finalizer$identity_pk)
  states <- .dsvert_dp_count_final_share_state_v1(ss)
  previous <- states[[operation_id]]
  if (!is.null(previous)) {
    if (!is.list(previous) || !identical(previous$request, request) ||
        !is.list(previous$result)) {
      stop("Conflicting retry for Count final-share transfer.",
           call. = FALSE)
    }
    return(previous$result)
  }
  replay <- .dsvert_typed_blob_operation_replay(
    ss, .DSVERT_DP_COUNT_FINAL_PRODUCER, request)
  if (isTRUE(replay$hit)) {
    states[[operation_id]] <- list(
      request = request, result = replay$result)
    return(replay$result)
  }
  output <- .dsvert_dp_count_output_v1(ss, record, consume = FALSE)
  payload <- .dsvert_dp_count_final_payload_v1(record, output)
  plaintext <- charToRaw(.dsvert_dp_canonical_json(payload))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = gsub("[\r\n]", "", jsonlite::base64_enc(plaintext)),
    recipient_pk = peer_pk))
  ciphertext <- base64_to_base64url(sealed$sealed)
  context <- .dsvert_dp_count_final_context_v1(record)
  transfer <- .dsvert_typed_blob_mint(
    ss, session_id, .DSVERT_DP_COUNT_FINAL_CAPABILITY,
    base64_to_base64url(peer_pk), ciphertext, context,
    producer = .DSVERT_DP_COUNT_FINAL_PRODUCER)
  result <- .dsvert_dp_canonical_query_value(list(
    version = "dsvert-dp-count-final-share-transfer-v1",
    state = "final_share_sealed",
    artifact_key = record$authorization$artifact_key,
    contract_sha256 = record$authorization$contract_sha256,
    analysis_binding_sha256 =
      record$authorization$analysis_binding_sha256,
    circuit = record$execution$circuit,
    ciphertext = ciphertext,
    transfer = transfer,
    intermediate_values_exposed = FALSE,
    capability_available = TRUE))
  rm(output, payload, plaintext)
  result <- .dsvert_typed_blob_operation_commit(
    ss, .DSVERT_DP_COUNT_FINAL_PRODUCER, request, result)
  states[[operation_id]] <- list(request = request, result = result)
  result
}

.dsvert_dp_count_final_share_endpoint_v1 <- function(
    session_id, operation_id, output_key, recipient_pk) {
  .dsvert_dp_count_final_share_impl_v1(
    .S(session_id), session_id, operation_id, output_key, recipient_pk)
}

.dsvert_dp_count_ring127_add_v1 <- function(left, right) {
  if (!is.raw(left) || !is.raw(right) ||
      length(left) != 16L || length(right) != 16L ||
      bitwAnd(as.integer(left[[16L]]), 128L) != 0L ||
      bitwAnd(as.integer(right[[16L]]), 128L) != 0L) {
    stop("Count release requires two canonical Ring127 shares.",
         call. = FALSE)
  }
  result <- raw(16L)
  carry <- 0L
  for (index in seq_len(16L)) {
    total <- as.integer(left[[index]]) + as.integer(right[[index]]) + carry
    result[[index]] <- as.raw(total %% 256L)
    carry <- total %/% 256L
  }
  result[[16L]] <- as.raw(bitwAnd(as.integer(result[[16L]]), 127L))
  result
}

.dsvert_dp_count_release_message_v1 <- function(value) {
  charToRaw(paste0(
    .DSVERT_DP_COUNT_RELEASE_SIGNATURE_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value))))
}

.dsvert_dp_count_release_v1 <- function(
    record, value_text, .signer = .dsvert_relay_sign_message) {
  authorization <- record$authorization
  contract <- authorization$contract
  privacy <- contract$semantic$privacy
  mechanism <- privacy$mechanism
  source_pk <- record$execution$role_map$source$identity_pk
  finalizer_pk <- record$execution$role_map$finalizer$identity_pk
  identity <- .get_identity_keypair()
  local_pk <- .dsvert_relay_normalize_identity_pk(identity$identity_pk)
  if (!identical(local_pk, finalizer_pk) || !is.function(.signer)) {
    stop("Only the identity-bound Count evaluator may sign the release.",
         call. = FALSE)
  }
  core <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_COUNT_RELEASE_VERSION,
    artifact_key = authorization$artifact_key,
    contract_sha256 = authorization$contract_sha256,
    analysis_binding_sha256 = authorization$analysis_binding_sha256,
    worker_static_sha256 = record$execution$worker_static_sha256,
    circuit = record$execution$circuit,
    mechanism = list(
      family = mechanism$family,
      version = mechanism$version,
      sampler = mechanism$calibration$sampler,
      epsilon = privacy$epsilon,
      delta = privacy$delta,
      implementation_delta =
        mechanism$calibration$implementation_delta,
      sensitivity_l1 = 1),
    bounds = list(
      lower = "0",
      upper = authorization$worker_static$encoded_upper),
    value = value_text,
    source_identity_pk = source_pk,
    finalizer_identity_pk = finalizer_pk,
    backend = "exact-gc-joint-dp-laplace-ring127-v2",
    postprocessing = "one-joint-noise-draw-and-one-clamp-inside-exact-gc",
    intermediate_values_exposed = FALSE,
    public_openings = 1L))
  release_sha256 <- .dsvert_dp_count_hash_v1(
    .DSVERT_DP_COUNT_RELEASE_DOMAIN, core)
  signed <- .dsvert_dp_canonical_query_value(c(
    core, list(release_sha256 = release_sha256)))
  signature <- .signer(
    .dsvert_dp_count_release_message_v1(signed), identity$identity_sk)
  .dsvert_dp_count_signature_v1(signature)
  .dsvert_dp_canonical_query_value(c(
    signed, list(signature = signature)))
}

.dsvert_dp_count_release_state_v1 <- function(ss) {
  if (!is.environment(ss$.dp_count_releases)) {
    ss$.dp_count_releases <- new.env(parent = emptyenv())
  }
  ss$.dp_count_releases
}

.dsvert_dp_count_release_cleanup_v1 <- function(
    ss, operation_id, record, releases) {
  entry <- releases[[operation_id]]
  if (!is.list(entry) || !is.list(entry$release) ||
      !is.character(entry$encrypted) || length(entry$encrypted) != 1L ||
      is.na(entry$encrypted) || !is.logical(entry$typed_consumed) ||
      length(entry$typed_consumed) != 1L ||
      !is.logical(entry$output_consumed) ||
      length(entry$output_consumed) != 1L) {
    stop("Invalid cached Count release cleanup state.", call. = FALSE)
  }
  context <- .dsvert_dp_count_final_context_v1(record)
  sender <- record$execution$role_map$source$peer_name
  if (!isTRUE(entry$typed_consumed)) {
    consumed <- .dsvert_typed_blob_consume(
      ss, .DSVERT_DP_COUNT_FINAL_CAPABILITY, context,
      sender_name = sender, required = FALSE, consume = TRUE)
    if (!is.null(consumed) && !identical(consumed, entry$encrypted)) {
      stop("The committed Count ciphertext changed during release.",
           call. = FALSE)
    }
    entry$typed_consumed <- TRUE
    releases[[operation_id]] <- entry
  }
  if (!isTRUE(entry$output_consumed)) {
    available <- (ss$.exact_gc_outputs %||% list())[[
      record$execution$output_key]]
    if (!is.null(available)) {
      invisible(.dsvert_dp_count_output_v1(
        ss, record, consume = TRUE))
    }
    entry$output_consumed <- TRUE
    releases[[operation_id]] <- entry
  }
  entry$release
}

.dsvert_dp_count_release_impl_v1 <- function(
    ss, session_id, operation_id, output_key,
    .signer = .dsvert_relay_sign_message) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  output_key <- .exact_gc_validate_key(output_key, output = TRUE)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid Count release session.", call. = FALSE)
  }
  record <- .dsvert_dp_count_execution_record_v1(
    ss, session_id, operation_id, output_key, "evaluator")
  request <- .dsvert_dp_canonical_query_value(list(
    artifact_key = record$authorization$artifact_key,
    contract_sha256 = record$authorization$contract_sha256,
    analysis_binding_sha256 =
      record$authorization$analysis_binding_sha256,
    circuit = record$execution$circuit,
    exact_context_hash = record$exact_state$context_hash,
    operation_id = operation_id,
    output_key = output_key))
  releases <- .dsvert_dp_count_release_state_v1(ss)
  previous <- releases[[operation_id]]
  if (!is.null(previous)) {
    if (!is.list(previous) || !identical(previous$request, request) ||
        !is.list(previous$release)) {
      stop("Conflicting retry for Count release.", call. = FALSE)
    }
    return(.dsvert_dp_count_release_cleanup_v1(
      ss, operation_id, record, releases))
  }
  context <- .dsvert_dp_count_final_context_v1(record)
  sender <- record$execution$role_map$source$peer_name
  encrypted <- .dsvert_typed_blob_consume(
    ss, .DSVERT_DP_COUNT_FINAL_CAPABILITY, context,
    sender_name = sender, consume = FALSE)
  opened <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(encrypted),
    recipient_sk = .key_get("transport_sk", ss)))
  peer_raw <- tryCatch(
    jsonlite::base64_dec(opened$data), error = function(error) NULL)
  if (!is.raw(peer_raw)) {
    stop("The encrypted Count final share could not be opened.",
         call. = FALSE)
  }
  own_output <- .dsvert_dp_count_output_v1(ss, record, consume = FALSE)
  own <- .dsvert_dp_count_final_payload_decode_v1(charToRaw(
    .dsvert_dp_canonical_json(
      .dsvert_dp_count_final_payload_v1(record, own_output))))
  peer <- .dsvert_dp_count_final_payload_decode_v1(peer_raw)
  common <- c(
    "version", "artifact_key", "contract_sha256",
    "analysis_binding_sha256", "worker_static_sha256", "operation_id",
    "output_key", "circuit", "exact_context_hash", "lower_bound",
    "upper_bound", "ring_bits", "vector_len")
  if (!identical(own[common], peer[common]) ||
      !identical(own$artifact_key, record$authorization$artifact_key) ||
      !identical(own$contract_sha256,
                 record$authorization$contract_sha256) ||
      !identical(own$analysis_binding_sha256,
                 record$authorization$analysis_binding_sha256) ||
      !identical(own$worker_static_sha256,
                 record$execution$worker_static_sha256) ||
      !identical(own$exact_context_hash,
                 record$exact_state$context_hash)) {
    stop("The two Count output shares do not match one execution.",
         call. = FALSE)
  }
  validity <- bitwXor(
    as.integer(own$validity_raw[[1L]]),
    as.integer(peer$validity_raw[[1L]]))
  if (!identical(validity, 1L)) {
    stop("The Count exact-gc validity certificate is invalid.",
         call. = FALSE)
  }
  residue <- .dsvert_dp_count_ring127_add_v1(
    own$share_raw, peer$share_raw)
  exact <- openssl::bignum(rev(residue))
  upper <- openssl::bignum(record$authorization$worker_static$encoded_upper)
  if (exact > upper) {
    stop("The Count exact-gc output violates its signed clamp bounds.",
         call. = FALSE)
  }
  release <- .dsvert_dp_count_release_v1(
    record, as.character(exact), .signer = .signer)
  releases[[operation_id]] <- list(
    request = request, release = release, encrypted = encrypted,
    typed_consumed = FALSE, output_consumed = FALSE)
  rm(exact, residue, own, peer, peer_raw, validity)
  .dsvert_dp_count_release_cleanup_v1(
    ss, operation_id, record, releases)
}

.dsvert_dp_count_release_endpoint_v1 <- function(
    session_id, operation_id, output_key) {
  .dsvert_dp_count_release_impl_v1(
    .S(session_id), session_id, operation_id, output_key)
}
