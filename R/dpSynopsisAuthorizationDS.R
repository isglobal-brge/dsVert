# Server-held authorization for one stateless sticky synopsis.
# This layer exposes no endpoint and creates state only on the two designated
# noise authorities.  Witnesses participate only in the K-wide compilation.

.DSVERT_DP_SYNOPSIS_AUTHORIZATION_VERSION <-
  "dsvert-stateless-catalog-synopsis-authorization-v1"
.DSVERT_DP_SYNOPSIS_AUTHORIZATION_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/authorization/v1|"

.dsvert_dp_synopsis_authorization_state_v1 <- function(
    ss, installing = FALSE) {
  if (!is.environment(ss)) {
    stop("Invalid synopsis session authorization state.", call. = FALSE)
  }
  bindings <- ls(ss, all.names = TRUE)
  if (isTRUE(installing)) {
    allowed <- c(
      ".created_at", ".last_activity", ".session_id",
      ".dsvert_resource_owner", ".dp_synopsis_authorization")
    if (length(setdiff(bindings, allowed))) {
      stop("Synopsis authorization conflicts with existing session state.",
           call. = FALSE)
    }
  } else {
    rival <- grep(
      "^\\.dp_.*_authorization$", bindings, value = TRUE)
    rival <- setdiff(rival, ".dp_synopsis_authorization")
    if (length(rival)) {
      stop("Synopsis authorization conflicts with another DP protocol.",
           call. = FALSE)
    }
  }
  invisible(ss)
}

.dsvert_dp_synopsis_local_authority_v1 <- function(
    semantic, policy, identity = NULL) {
  semantic <- .dsvert_dp_analysis_synopsis_semantic_validate_v1(semantic)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  peer <- .dsvert_dp_analysis_scalar_id(
    policy$peer_name, "local synopsis authority peer")
  if (is.null(identity)) identity <- .get_identity_keypair()
  identity_pk <- if (is.list(identity) && !is.null(identity$identity_pk)) {
    tryCatch(.dsvert_dp_analysis_identity_pk(
      identity$identity_pk, "local synopsis authority identity"),
      error = function(error) NULL)
  } else NULL
  roles <- semantic$noise_authority_roles
  authority_ids <- unlist(roles$authority_ids, use.names = FALSE)
  position <- if (is.null(identity_pk)) integer() else
    which(authority_ids == identity_pk)
  if (length(position) != 1L || !peer %in% names(pins) ||
      !identical(identity_pk, unname(pins[[peer]]))) {
    stop("The local identity is not a synopsis noise authority.",
         call. = FALSE)
  }
  list(
    peer_name = peer, identity_pk = identity_pk,
    role = roles$role_order[[position]])
}

.dsvert_dp_synopsis_compact_artifact_validate_v1 <- function(
    artifact, policy, manifest) {
  fields <- c("semantic", "artifact_key", "physical_plan")
  if (!is.list(artifact) || is.null(names(artifact)) ||
      anyNA(names(artifact)) || anyDuplicated(names(artifact)) ||
      !setequal(names(artifact), fields)) {
    stop("Invalid synopsis authorization artifact.", call. = FALSE)
  }
  semantic <- .dsvert_dp_analysis_synopsis_semantic_validate_v1(
    artifact$semantic)
  physical_plan <- .dsvert_dp_synopsis_physical_plan_validate_v1(
    artifact$physical_plan, policy, manifest,
    semantic$catalog_projection)
  claim_reference <- list(
    projection = semantic$catalog_projection,
    sha256 = semantic$source_claim_set_sha256)
  expected <- .dsvert_dp_synopsis_semantic_v1(
    policy, manifest, claim_reference, physical_plan)
  artifact_key <- .dsvert_dp_synopsis_hex_v1(
    artifact$artifact_key, "authorization artifact key")
  if (!identical(semantic, expected) ||
      !identical(artifact_key,
                 .dsvert_dp_analysis_artifact_key_v1(expected))) {
    stop("Invalid synopsis authorization artifact.", call. = FALSE)
  }
  list(
    semantic = expected, artifact_key = artifact_key,
    physical_plan = physical_plan)
}

.dsvert_dp_synopsis_authorization_hash_v1 <- function(value, secret) {
  if (!is.raw(secret) || length(secret) != 32L) {
    stop("Invalid synopsis authorization secret.", call. = FALSE)
  }
  value <- value[setdiff(names(value), "authorization_sha256")]
  digest::hmac(
    key = secret, object = charToRaw(paste0(
      .DSVERT_DP_SYNOPSIS_AUTHORIZATION_DOMAIN,
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(value)))),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}

.dsvert_dp_synopsis_session_authorization_validate_v1 <- function(
    ss, session_id, .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get) {
  .dsvert_dp_synopsis_authorization_state_v1(ss, installing = FALSE)
  session_id <- .dsvert_relay_validate_session_id(session_id)
  authorization <- ss$.dp_synopsis_authorization
  fields <- c(
    "version", "session_id", "manifest_sha256", "artifact",
    "artifact_key", "source_claim_set_sha256", "receipt_peers",
    "receipt_set_sha256", "local_authority", "authorization_sha256")
  if (!is.list(authorization) || is.null(names(authorization)) ||
      anyNA(names(authorization)) || anyDuplicated(names(authorization)) ||
      !setequal(names(authorization), fields) ||
      !identical(
        authorization$version, .DSVERT_DP_SYNOPSIS_AUTHORIZATION_VERSION) ||
      !identical(authorization$session_id, session_id)) {
    stop("Invalid synopsis session authorization.", call. = FALSE)
  }
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    authorization$manifest_sha256, "authorization manifest hash")
  manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
    manifest_sha256, .policy, .secret, .cache_get)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  artifact <- .dsvert_dp_synopsis_compact_artifact_validate_v1(
    authorization$artifact, .policy, manifest)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(.policy$peer_pinset)
  receipt_peers <- as.list(names(pins))
  receipt_set_sha256 <- .dsvert_dp_synopsis_hex_v1(
    authorization$receipt_set_sha256, "authorization receipt-set hash")
  local_authority <- .dsvert_dp_synopsis_local_authority_v1(
    artifact$semantic, .policy, .identity)
  expected <- list(
    version = .DSVERT_DP_SYNOPSIS_AUTHORIZATION_VERSION,
    session_id = session_id, manifest_sha256 = manifest_sha256,
    artifact = artifact, artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256,
    receipt_peers = receipt_peers,
    receipt_set_sha256 = receipt_set_sha256,
    local_authority = local_authority)
  expected$authorization_sha256 <-
    .dsvert_dp_synopsis_authorization_hash_v1(expected, .secret)
  if (!identical(authorization, expected)) {
    stop("Invalid synopsis session authorization.", call. = FALSE)
  }
  expected
}

.dsvert_dp_synopsis_session_context_v1 <- function(ss, session_id) {
  .dsvert_dp_synopsis_authorization_state_v1(ss, installing = FALSE)
  session_id <- .dsvert_relay_validate_session_id(session_id)
  authorization <- ss$.dp_synopsis_authorization
  fields <- c(
    "version", "session_id", "manifest_sha256", "artifact",
    "artifact_key", "source_claim_set_sha256", "receipt_peers",
    "receipt_set_sha256", "local_authority", "authorization_sha256")
  if (!is.list(authorization) || is.null(names(authorization)) ||
      anyNA(names(authorization)) || anyDuplicated(names(authorization)) ||
      !setequal(names(authorization), fields) || !identical(
        authorization$version, .DSVERT_DP_SYNOPSIS_AUTHORIZATION_VERSION) ||
      !identical(authorization$session_id, session_id)) {
    stop("Invalid synopsis session authorization.", call. = FALSE)
  }
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    authorization$manifest_sha256, "authorization manifest selector")
  secret <- .dsvert_dp_secret()
  policy <- .dsvert_dp_synopsis_policy_for_manifest_v1(
    manifest_sha256, secret)
  cache_get <- .dsvert_dp_synopsis_manifest_cache_get_readonly_v1
  authorization <- .dsvert_dp_synopsis_session_authorization_validate_v1(
    ss, session_id, policy, secret, .cache_get = cache_get)
  list(
    ss = ss, policy = policy, secret = secret,
    cache_get = cache_get, authorization = authorization)
}

.dsvert_dp_synopsis_authorize_session_v1 <- function(
    ss, session_id, manifest_sha256, artifact, claim_set, receipts,
    .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message) {
  prior_exists <- is.environment(ss) && exists(
    ".dp_synopsis_authorization", envir = ss, inherits = FALSE)
  .dsvert_dp_synopsis_authorization_state_v1(
    ss, installing = !prior_exists)
  session_id <- .dsvert_relay_validate_session_id(session_id)
  if (!is.function(.verifier)) {
    stop("Invalid synopsis authorization verifier.", call. = FALSE)
  }
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    manifest_sha256, "authorization manifest selector")
  manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
    manifest_sha256, .policy, .secret, .cache_get)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  compilation <- .dsvert_dp_synopsis_compile_v1(
    receipts, artifact, claim_set, .policy, manifest,
    .verifier = .verifier)
  artifact <- compilation$artifact
  local_authority <- .dsvert_dp_synopsis_local_authority_v1(
    artifact$semantic, .policy, .identity)
  candidate <- list(
    version = .DSVERT_DP_SYNOPSIS_AUTHORIZATION_VERSION,
    session_id = session_id, manifest_sha256 = manifest_sha256,
    artifact = artifact, artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256,
    receipt_peers = as.list(names(compilation$receipts)),
    receipt_set_sha256 = compilation$receipt_set_sha256,
    local_authority = local_authority)
  candidate$authorization_sha256 <-
    .dsvert_dp_synopsis_authorization_hash_v1(candidate, .secret)
  if (prior_exists) {
    previous <- .dsvert_dp_synopsis_session_authorization_validate_v1(
      ss, session_id, .policy, .secret, .identity, .cache_get)
    if (!identical(previous, candidate)) {
      stop("Conflicting synopsis session authorization.", call. = FALSE)
    }
    return(previous)
  }
  committed <- FALSE
  on.exit(if (!committed &&
      identical(ss$.dp_synopsis_authorization, candidate)) {
    rm(".dp_synopsis_authorization", envir = ss)
  }, add = TRUE)
  ss$.dp_synopsis_authorization <- candidate
  installed <- .dsvert_dp_synopsis_session_authorization_validate_v1(
    ss, session_id, .policy, .secret, .identity, .cache_get)
  committed <- TRUE
  installed
}

.dsvert_dp_synopsis_sticky_subseed_v1 <- function(ss, session_id, lane) {
  authorization <-
    .dsvert_dp_synopsis_session_authorization_validate_v1(ss, session_id)
  semantic <- authorization$artifact$semantic
  .dsvert_dp_sticky_subseed_from_artifact_v1(
    authorization$artifact_key,
    semantic$privacy$mechanism$randomness$lanes,
    semantic$noise_authority_roles$authority_ids, lane)
}
