# Server-held authorization for a compiled fixed-domain Frequency artifact.
.DSVERT_DP_FREQUENCY_AUTHORIZATION_VERSION <- "dsvert-dp-frequency-session-authorization-v1"
.DSVERT_DP_FREQUENCY_WORKER_STATIC_VERSION <- "dsvert-dp-frequency-worker-static-v1"
.DSVERT_DP_FREQUENCY_BINDING_DOMAIN <- "dsVert/dp-frequency/analysis-binding/v1|"
.DSVERT_DP_FREQUENCY_WORKER_DOMAIN <- "dsVert/dp-frequency/worker-static/v1|"
.DSVERT_DP_FREQUENCY_RECEIPT_SET_DOMAIN <- "dsVert/dp-frequency/receipt-set/v1|"
.DSVERT_DP_FREQUENCY_CONTRACT_DOMAIN <- "dsVert/dp-frequency/compiled-contract/v1|"
.DSVERT_DP_FREQUENCY_AUTHORIZATION_DOMAIN <- "dsVert/dp-frequency/session-authorization/v1|"
.DSVERT_DP_FREQUENCY_PUBLIC_AUTHORIZATION_VERSION <-
  "dsvert-dp-frequency-public-authorization-v1"
.DSVERT_DP_FREQUENCY_PUBLIC_AUTHORIZATION_SIGNATURE_DOMAIN <-
  "dsVert/dp-frequency/public-authorization-signature/v1|"
.dsvert_dp_frequency_analysis_binding_v1 <- function(contract) {
  contract <- .dsvert_dp_analysis_contract_validate_v1(contract)
  roles <- contract$semantic$noise_authority_roles
  role_names <- unlist(roles$role_order, use.names = FALSE)
  authority_ids <- unlist(roles$authority_ids, use.names = FALSE)
  authority_roles <- stats::setNames(as.list(authority_ids), role_names)
  value <- list(
    version = "dsvert-dp-frequency-analysis-binding-v1",
    artifact_key = contract$artifact_key,
    semantic_contract_sha256 = .dsvert_dp_frequency_hash_v1(
      "dsVert/dp-frequency/semantic-contract/v1|", contract$semantic),
    authority_roles = authority_roles)
  list(value = value, sha256 = .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_BINDING_DOMAIN, value))
}
.dsvert_dp_frequency_worker_static_v1 <- function(contract, config, binding) {
  contract <- .dsvert_dp_analysis_contract_validate_v1(contract)
  config <- .dsvert_dp_frequency_config_validate_v1(config)
  plan <- contract$semantic$analysis$effective_arguments$sampler_plan
  if (!identical(plan, .dsvert_dp_analysis_canonical_value_v1(
      .dsvert_dp_frequency_plan_summary_v1(config)))) stop(
    "Frequency worker contract and configuration disagree.",
    call. = FALSE)
  primitive <- contract$semantic$analysis$primitive
  profile <- .dsvert_dp_analysis_frequency_profile_v1(primitive)
  roles <- binding$value$authority_roles
  tokens <- lapply(roles, .dsvert_relay_peer_id)
  purpose <- if (isTRUE(profile$gaussian)) {
    "dyadic-discrete-gaussian-tv-bounded-v2"
  } else "convolution"
  d <- as.integer(plan$d)
  chunk <- as.integer(plan$chunk_coordinates)
  raw_bound <- list(
    lower = "0", upper = format(
      config$coordinate_upper_bound, scientific = FALSE, trim = TRUE),
    scale = 0L)
  release <- list(
    version = "dsvert-dp-frequency-worker-release-v1",
    artifact_key = contract$artifact_key, primitive = primitive,
    selected_plan_sha256 = plan$full_plan_sha256,
    coordinate_order_sha256 = plan$coordinate_order_sha256,
    d = d, chunk_coordinates = chunk, raw_bound = raw_bound,
    authority_roles = roles)
  release_hash <- .dsvert_dp_frequency_hash_v1(
    "dsVert/dp-frequency/worker-release/v1|", release)
  transcript_hash <- .dsvert_dp_frequency_hash_v1(
    "dsVert/dp-frequency/worker-transcript/v1|", list(
      version = "dsvert-dp-frequency-worker-transcript-v1",
      release_contract_hash = release_hash,
      analysis_binding_sha256 = binding$sha256,
      authority_tokens = tokens))
  contexts <- lapply(tokens, function(token) {
    .dsvert_joint_dp_vector_context(transcript_hash, token, purpose)
  })
  list(
    version = .DSVERT_DP_FREQUENCY_WORKER_STATIC_VERSION,
    selected_primitive = primitive, selected_profile = profile,
    selected_request = config$backend_selection$selected_request,
    selected_plan = config$backend_selection$selected_plan,
    selected_plan_sha256 = plan$full_plan_sha256,
    ring_bits = 128L, frac_bits = 0L,
    output_lattice_bits = as.integer(profile$output_lattice_bits),
    d = d, chunk_coordinates = chunk,
    chunk_count = as.integer(ceiling(d / chunk)), raw_bound = raw_bound,
    authority_roles = roles, authority_tokens = tokens,
    release_contract_hash = release_hash, transcript_hash = transcript_hash,
    commitment_purpose = purpose, commitment_contexts = contexts,
    source_share_policy = list(
      source_owner = "private_frequency_vector_ring128_v1",
      secondary_noise_authority = "zero_vector_ring128_v1"))
}
.dsvert_dp_frequency_local_authority_v1 <- function(config, binding) {
  identity_pk <- tryCatch(.dsvert_dp_frequency_identity_pk_v1(
    .get_identity_keypair()$identity_pk, "local authority"),
    error = function(error) NULL)
  roles <- unlist(binding$value$authority_roles, use.names = TRUE)
  role <- names(roles)[match(identity_pk, unname(roles))]
  peer <- names(config$peer_pins)[match(identity_pk, unname(config$peer_pins))]
  if (is.null(identity_pk) || length(role) != 1L || is.na(role) ||
      length(peer) != 1L || is.na(peer)) {
    stop("The local identity is not a Frequency noise authority.",
         call. = FALSE)
  }
  list(peer_name = unname(peer), identity_pk = identity_pk,
       role = unname(role))
}
.dsvert_dp_frequency_seed_material_v1 <- function(authorization) {
  role <- authorization$local_authority$role
  context <- authorization$worker_static$commitment_contexts[[role]]
  sticky <- .dsvert_dp_sticky_subseed_v1(
    authorization$contract, "final_noise")
  list(role = role, commitment_context = context,
       sha256 = .dsvert_joint_dp_vector_seed_commitment(context, sticky))
}

.dsvert_dp_frequency_public_authorization_message_v1 <- function(value) {
  fields <- sort(c(
    "version", "session_id", "artifact_key", "config_sha256",
    "source_claim_sha256", "receipt_set_sha256", "psi_run_sha256",
    "contract_sha256", "analysis_binding_sha256", "worker_static_sha256",
    "local_authority", "commitment_context", "seed_commitment",
    "authorization_sha256"), method = "radix")
  if (!is.list(value) || !identical(names(value), fields) ||
      !identical(value, .dsvert_dp_analysis_canonical_value_v1(value))) {
    stop("Invalid Frequency public authorization message.", call. = FALSE)
  }
  charToRaw(paste0(
    .DSVERT_DP_FREQUENCY_PUBLIC_AUTHORIZATION_SIGNATURE_DOMAIN,
    .dsvert_dp_canonical_json(value)))
}

.dsvert_dp_frequency_public_authorization_core_v1 <- function(authorization) {
  seed <- .dsvert_dp_frequency_seed_material_v1(authorization)
  .dsvert_dp_analysis_canonical_value_v1(list(
    version = .DSVERT_DP_FREQUENCY_PUBLIC_AUTHORIZATION_VERSION,
    session_id = authorization$session_id,
    artifact_key = authorization$artifact_key,
    config_sha256 = authorization$config_sha256,
    source_claim_sha256 = authorization$source_claim_sha256,
    receipt_set_sha256 = authorization$receipt_set_sha256,
    psi_run_sha256 = authorization$psi_run_sha256,
    contract_sha256 = authorization$contract_sha256,
    analysis_binding_sha256 = authorization$analysis_binding_sha256,
    worker_static_sha256 = authorization$worker_static_sha256,
    local_authority = authorization$local_authority,
    commitment_context = seed$commitment_context,
    seed_commitment = seed$sha256,
    authorization_sha256 = authorization$authorization_sha256))
}

.dsvert_dp_frequency_public_authorization_validate_v1 <- function(
    value, ss, .verifier = .dsvert_relay_verify_message) {
  fields <- sort(c(
    "version", "session_id", "artifact_key", "config_sha256",
    "source_claim_sha256", "receipt_set_sha256", "psi_run_sha256",
    "contract_sha256", "analysis_binding_sha256", "worker_static_sha256",
    "local_authority", "commitment_context", "seed_commitment",
    "authorization_sha256", "signature"), method = "radix")
  if (!is.environment(ss) || !is.function(.verifier) || !is.list(value) ||
      !identical(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_DP_FREQUENCY_PUBLIC_AUTHORIZATION_VERSION)) {
    stop("Invalid Frequency public authorization.", call. = FALSE)
  }
  value$session_id <- .dsvert_relay_validate_session_id(value$session_id)
  for (field in c(
      "artifact_key", "config_sha256", "source_claim_sha256",
      "receipt_set_sha256", "psi_run_sha256", "contract_sha256",
      "analysis_binding_sha256", "worker_static_sha256",
      "commitment_context", "seed_commitment", "authorization_sha256")) {
    value[[field]] <- .dsvert_dp_frequency_hex_v1(
      value[[field]], paste("public authorization", field))
  }
  value$signature <- .dsvert_dp_frequency_signature_v1(value$signature)
  local <- value$local_authority
  local_fields <- sort(c("peer_name", "identity_pk", "role"),
                       method = "radix")
  if (!is.list(local) || !identical(names(local), local_fields) ||
      !is.character(local$role) || length(local$role) != 1L ||
      is.na(local$role) || !local$role %in%
        c("source_owner", "secondary_noise_authority")) {
    stop("Invalid Frequency public authorization.", call. = FALSE)
  }
  local$peer_name <- .dsvert_dp_frequency_peer_name_v1(local$peer_name)
  local$identity_pk <- tryCatch(.dsvert_dp_frequency_identity_pk_v1(
    local$identity_pk, "public authorization identity"),
    error = function(error) stop(
      "Invalid Frequency public authorization.", call. = FALSE))
  value$local_authority <- local
  normalized <- .dsvert_dp_analysis_canonical_value_v1(value)
  if (!identical(value, normalized)) stop(
    "Invalid Frequency public authorization.", call. = FALSE)
  unsigned <- value[setdiff(names(value), "signature")]
  valid <- tryCatch(if (identical(
      .verifier, .dsvert_relay_verify_message)) {
    .verifier(.dsvert_dp_frequency_public_authorization_message_v1(unsigned),
              local$identity_pk, value$signature)
  } else .verifier(
    .dsvert_dp_frequency_public_authorization_message_v1(unsigned),
    local$identity_pk, value$signature, local$peer_name),
    error = function(error) FALSE)
  if (!isTRUE(valid)) stop(
    "Frequency public authorization signature verification failed.",
    call. = FALSE)
  authorization <- tryCatch(
    .dsvert_dp_frequency_session_authorization_validate_v1(
      ss, value$session_id, value$artifact_key),
    error = function(error) stop(
      "Frequency public authorization does not match server state.",
      call. = FALSE))
  if (!identical(unsigned,
      .dsvert_dp_frequency_public_authorization_core_v1(authorization))) {
    stop("Frequency public authorization does not match server state.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_frequency_authorization_hash_v1 <- function(value) {
  value <- value[setdiff(names(value), "authorization_sha256")]
  value$config$peer_pins <- as.list(value$config$peer_pins)
  .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_AUTHORIZATION_DOMAIN, value)
}

.dsvert_dp_frequency_session_authorization_validate_v1 <- function(
    ss, session_id, artifact_key = NULL) {
  if (!is.environment(ss)) stop(
    "Invalid Frequency session authorization state.", call. = FALSE)
  session_id <- .dsvert_relay_validate_session_id(session_id)
  authorization <- ss$.dp_frequency_authorization
  fields <- c(
    "version", "session_id", "artifact_key", "config", "config_sha256",
    "source_claim_sha256", "receipt_peers", "receipt_set_sha256",
    "psi_run_sha256", "contract", "contract_sha256", "analysis_binding",
    "analysis_binding_sha256", "worker_static", "worker_static_sha256",
    "local_authority", "authorization_sha256")
  if (!is.list(authorization) || is.null(names(authorization)) ||
      anyNA(names(authorization)) || anyDuplicated(names(authorization)) ||
      !setequal(names(authorization), fields) ||
      !identical(authorization$version,
                 .DSVERT_DP_FREQUENCY_AUTHORIZATION_VERSION) ||
      !identical(authorization$session_id, session_id)) {
    stop("Invalid Frequency session authorization.", call. = FALSE)
  }
  config <- .dsvert_dp_frequency_config_validate_v1(authorization$config)
  contract <- .dsvert_dp_analysis_contract_validate_v1(authorization$contract)
  binding <- .dsvert_dp_frequency_analysis_binding_v1(contract)
  worker <- .dsvert_dp_frequency_worker_static_v1(contract, config, binding)
  local <- .dsvert_dp_frequency_local_authority_v1(config, binding)
  expected <- authorization
  expected$config <- config
  expected$artifact_key <- contract$artifact_key
  expected$config_sha256 <- .dsvert_dp_frequency_config_hash_v1(config)
  expected$receipt_peers <- as.list(sort(names(config$peer_pins),
                                         method = "radix"))
  expected$contract <- contract
  expected$contract_sha256 <- .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_CONTRACT_DOMAIN, contract)
  expected$analysis_binding <- binding$value
  expected$analysis_binding_sha256 <- binding$sha256
  expected$worker_static <- worker
  expected$worker_static_sha256 <- .dsvert_dp_frequency_hash_v1(
    .DSVERT_DP_FREQUENCY_WORKER_DOMAIN, worker)
  expected$local_authority <- local
  expected$authorization_sha256 <-
    .dsvert_dp_frequency_authorization_hash_v1(expected)
  for (field in c(
      "source_claim_sha256", "receipt_set_sha256", "psi_run_sha256")) {
    .dsvert_dp_frequency_hex_v1(expected[[field]],
                                paste("authorization", field))
  }
  if (!identical(authorization, expected) ||
      !identical(contract$execution$peer_pins, as.list(config$peer_pins)) ||
      (!is.null(artifact_key) && !identical(artifact_key,
                                            contract$artifact_key))) {
    stop("Invalid Frequency session authorization.", call. = FALSE)
  }
  authorization
}

.dsvert_dp_frequency_authorize_session_v1 <- function(
    ss, session_id, config, receipts, source_claim,
    .verifier = .dsvert_relay_verify_message) {
  if (!is.environment(ss)) stop(
    "Invalid Frequency session authorization state.", call. = FALSE)
  session_id <- .dsvert_relay_validate_session_id(session_id)
  config <- .dsvert_dp_frequency_config_validate_v1(config)
  contract <- .dsvert_dp_frequency_compile_v1(
    receipts, config, source_claim, .verifier = .verifier)
  verified <- lapply(
    receipts, .dsvert_dp_frequency_receipt_verify_v1, config = config,
    source_claim = source_claim, .verifier = .verifier)
  names(verified) <- vapply(verified, `[[`, character(1L), "peer_name")
  verified <- verified[sort(names(verified), method = "radix")]
  binding <- .dsvert_dp_frequency_analysis_binding_v1(contract)
  worker <- .dsvert_dp_frequency_worker_static_v1(contract, config, binding)
  local <- .dsvert_dp_frequency_local_authority_v1(config, binding)
  candidate <- list(
    version = .DSVERT_DP_FREQUENCY_AUTHORIZATION_VERSION,
    session_id = session_id, artifact_key = contract$artifact_key,
    config = config,
    config_sha256 = .dsvert_dp_frequency_config_hash_v1(config),
    source_claim_sha256 = verified[[1L]]$source_claim_sha256,
    receipt_peers = as.list(names(verified)),
    receipt_set_sha256 = .dsvert_dp_frequency_hash_v1(
      .DSVERT_DP_FREQUENCY_RECEIPT_SET_DOMAIN, verified),
    psi_run_sha256 = verified[[1L]]$psi_run_sha256, contract = contract,
    contract_sha256 = .dsvert_dp_frequency_hash_v1(
      .DSVERT_DP_FREQUENCY_CONTRACT_DOMAIN, contract),
    analysis_binding = binding$value,
    analysis_binding_sha256 = binding$sha256,
    worker_static = worker,
    worker_static_sha256 = .dsvert_dp_frequency_hash_v1(
      .DSVERT_DP_FREQUENCY_WORKER_DOMAIN, worker),
    local_authority = local)
  candidate$authorization_sha256 <-
    .dsvert_dp_frequency_authorization_hash_v1(candidate)
  if (!is.null(ss$.dp_count_authorization) ||
      !is.null(ss$.exact_gc_peer_binding_digest) ||
      !is.null(ss$.exact_gc_analysis_binding) ||
      !is.null(ss$.typed_blob_peer_binding_digest)) stop(
    "Frequency authorization conflicts with existing session state.",
    call. = FALSE)
  previous <- ss$.dp_frequency_authorization
  if (!is.null(previous)) {
    previous <- .dsvert_dp_frequency_session_authorization_validate_v1(
      ss, session_id)
    if (!identical(previous, candidate)) stop(
      "Conflicting Frequency session authorization.", call. = FALSE)
    return(previous)
  }
  ss$.dp_frequency_authorization <- candidate
  candidate
}

.dsvert_dp_frequency_public_authorization_v1 <- function(
    ss, session_id, config, receipts, source_claim,
    .verifier = .dsvert_relay_verify_message,
    .signer = .dsvert_relay_sign_message) {
  if (!is.environment(ss)) stop(
    "Invalid Frequency public authorization state.", call. = FALSE)
  prior_authorization <- ss$.dp_frequency_authorization
  prior_public <- ss$.dp_frequency_public_authorization
  if (!is.null(prior_public) && is.null(prior_authorization)) stop(
    "Conflicting Frequency public authorization state.", call. = FALSE)
  committed <- FALSE
  on.exit(if (!committed) {
    if (is.null(prior_authorization)) ss$.dp_frequency_authorization <- NULL
    if (is.null(prior_public)) ss$.dp_frequency_public_authorization <- NULL
  }, add = TRUE)
  authorization <- .dsvert_dp_frequency_authorize_session_v1(
    ss, session_id, config, receipts, source_claim,
    .verifier = .verifier)
  if (!is.null(prior_public)) {
    value <- .dsvert_dp_frequency_public_authorization_validate_v1(
      prior_public, ss, .verifier = .verifier)
    committed <- TRUE
    return(value)
  }
  identity <- .get_identity_keypair()
  identity_pk <- tryCatch(.dsvert_dp_frequency_identity_pk_v1(
    identity$identity_pk, "public authorization signer"),
    error = function(error) NULL)
  if (!is.function(.signer) || is.null(identity_pk) ||
      !identical(identity_pk,
                 authorization$local_authority$identity_pk)) stop(
    "The Frequency public authorization signer is not the local authority.",
    call. = FALSE)
  unsigned <- .dsvert_dp_frequency_public_authorization_core_v1(authorization)
  signature <- .signer(
    .dsvert_dp_frequency_public_authorization_message_v1(unsigned),
    identity$identity_sk)
  signature <- .dsvert_dp_frequency_signature_v1(signature)
  value <- .dsvert_dp_analysis_canonical_value_v1(c(
    unsigned, list(signature = signature)))
  value <- .dsvert_dp_frequency_public_authorization_validate_v1(
    value, ss, .verifier = .verifier)
  ss$.dp_frequency_public_authorization <- value
  committed <- TRUE
  value
}
