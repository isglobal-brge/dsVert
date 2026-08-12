# Internal execution contract for one stateless sticky synopsis artifact.
#
# It deliberately does not reuse the historical vector release ledger: the
# artifact key, rather than a session, noise root or request counter, is the
# unique sticky-release identity.

.DSVERT_DP_SYNOPSIS_EXECUTION_VERSION <-
  "dsvert-stateless-catalog-synopsis-execution-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_ID_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/execution-id/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_CONTRACT_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/execution-contract/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_ATTEMPT_VERSION <-
  "dsvert-stateless-catalog-synopsis-execution-attempt-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_ATTEMPT_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/execution-attempt/v1|"
.DSVERT_DP_SYNOPSIS_PUBLIC_CHUNK_COORDINATES <- 8192L
.DSVERT_DP_SYNOPSIS_EXACT_CHUNK_COORDINATES <- 64L
.DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_VERSION <-
  "dsvert-stateless-catalog-synopsis-execution-prepare-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/execution-prepare/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_STORE_VERSION <-
  "dsvert-stateless-catalog-synopsis-execution-store-v2"
.DSVERT_DP_SYNOPSIS_EXECUTION_STORE_RECORD_VERSION <-
  "dsvert-stateless-catalog-synopsis-execution-record-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_MAX_BYTES <- 64L * 1024L
.DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_VERSION <-
  "dsvert-stateless-catalog-synopsis-local-chunk-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/local-chunk/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_RECORD_VERSION <-
  "dsvert-stateless-catalog-synopsis-local-record-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_VERSION <-
  "dsvert-stateless-catalog-synopsis-local-result-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/local-result/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_SET_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/prepare-set/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_CHUNK_SET_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/local-chunk-set/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_RECORD_VERSION <-
  "dsvert-stateless-catalog-synopsis-result-record-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_SET_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/result-set/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_SEGMENT_SET_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/final-share-segment-set/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_FINAL_SHARE_PAYLOAD_VERSION <-
  "dsvert-stateless-catalog-synopsis-final-share-payload-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_VERSION <-
  "dsvert-stateless-catalog-synopsis-public-chunk-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/public-chunk/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_VERSION <-
  "dsvert-stateless-catalog-synopsis-release-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/release/v1|"
.DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_RECORD_VERSION <-
  "dsvert-stateless-catalog-synopsis-release-record-v1"
.DSVERT_DP_SYNOPSIS_EXECUTION_STORE_MAX_RECORD_BYTES <- 512L * 1024L
.DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_MAX_RECORD_BYTES <- 2L * 1024L^2

.dsvert_dp_synopsis_execution_hash_v1 <- function(domain, value) {
  digest::digest(charToRaw(paste0(
    domain, .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value)))),
  algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_execution_context_v1 <- function(
    ss, session_id, .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  authorization <-
    .dsvert_dp_synopsis_session_authorization_validate_v1(
      ss, session_id, .policy, .secret, .identity, .cache_get)
  manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
    authorization$manifest_sha256, .policy, .secret, .cache_get)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  artifact <- authorization$artifact
  semantic <- artifact$semantic
  physical <- artifact$physical_plan
  validated <- .dsvert_dp_capsule_materializer_manifest(.policy, manifest)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(validated)
  if (!identical(lattice$transform_sha256,
                 semantic$release$lattice$transform_sha256) ||
      !identical(as.numeric(validated$layout$coordinate_count),
                 as.numeric(semantic$release$lattice$coordinate_count))) {
    stop("The synopsis execution lattice changed after authorization.",
         call. = FALSE)
  }
  source_contract <-
    .dsvert_dp_synopsis_source_contract_from_hashes_v1(
      .policy, manifest, artifact$artifact_key,
      semantic$source_claim_set_sha256)
  profile <- .dsvert_joint_dp_vector_profile(
    physical$profile$mechanism, physical$profile$backend)
  dimension <- as.integer(semantic$release$lattice$coordinate_count)
  execution_chunk_coordinates <- if (isTRUE(profile$exact_gc)) {
    capacity <- as.integer(.dsvert_joint_dp_vector_exact_gc_integer(
      physical$full_plan$maximum_chunk_coordinates,
      "synopsis exact-GC chunk capacity", 1L, 128L))
    required <- min(.DSVERT_DP_SYNOPSIS_EXACT_CHUNK_COORDINATES, dimension)
    if (capacity < required) {
      stop("The synopsis exact-GC plan cannot serve canonical chunks.",
           call. = FALSE)
    }
    required
  } else {
    min(.DSVERT_JOINT_DP_VECTOR_CHUNK_COORDINATES, dimension)
  }
  if (!is.finite(execution_chunk_coordinates) ||
      execution_chunk_coordinates < 1L) {
    stop("Invalid synopsis execution chunk geometry.", call. = FALSE)
  }
  public_chunk_coordinates <- min(
    .DSVERT_DP_SYNOPSIS_PUBLIC_CHUNK_COORDINATES, dimension)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(.policy$peer_pinset)
  authority_ids <- unlist(
    semantic$noise_authority_roles$authority_ids, use.names = FALSE)
  authority_peers <- names(pins)[match(authority_ids, unname(pins))]
  if (length(authority_peers) != 2L || anyNA(authority_peers) ||
      anyDuplicated(authority_peers)) {
    stop("Invalid synopsis execution authorities.", call. = FALSE)
  }
  execution_id <- digest::digest(charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_EXECUTION_ID_DOMAIN, artifact$artifact_key)),
  algo = "sha256", serialize = FALSE)
  ring <- .dsvert_dp_synopsis_ring_certificate_v1(
    lattice, physical$full_plan, profile)
  source_contract_sha256 <- .dsvert_joint_dp_hash(source_contract)
  value <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_VERSION,
    execution_id = execution_id, artifact_key = artifact$artifact_key,
    source_claim_set_sha256 = semantic$source_claim_set_sha256,
    semantic_sha256 = .dsvert_joint_dp_hash(semantic),
    draw_law_sha256 = semantic$release$draw_law_sha256,
    authority_roles = semantic$noise_authority_roles,
    authority_peers = as.list(authority_peers),
    geometry = list(
      coordinate_count = dimension,
      public_chunk_coordinates = public_chunk_coordinates,
      public_chunk_count = as.integer(ceiling(
        dimension / public_chunk_coordinates)),
      coordinate_order_sha256 =
        semantic$release$lattice$coordinate_order_sha256,
      lattice_transform_sha256 = lattice$transform_sha256),
    mechanism = list(
      mechanism = physical$profile$mechanism, backend = profile$backend,
      sampler = profile$sampler,
      release_mechanism = profile$release_mechanism),
    ring = ring))
  contract_sha256 <- .dsvert_dp_synopsis_execution_hash_v1(
    .DSVERT_DP_SYNOPSIS_EXECUTION_CONTRACT_DOMAIN, value)
  attempt_value <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_ATTEMPT_VERSION,
    execution_id = execution_id, artifact_key = artifact$artifact_key,
    manifest_sha256 = authorization$manifest_sha256,
    manifest_capsule_id =
      source_contract$synopsis_binding$manifest_capsule_id,
    source_contract_sha256 = source_contract_sha256,
    full_plan_sha256 = physical$full_plan_sha256,
    execution_geometry = list(
      chunk_coordinates = execution_chunk_coordinates,
      chunk_count = as.integer(ceiling(
        dimension / execution_chunk_coordinates)))))
  attempt_sha256 <- .dsvert_dp_synopsis_execution_hash_v1(
    .DSVERT_DP_SYNOPSIS_EXECUTION_ATTEMPT_DOMAIN, attempt_value)
  release_contract <- list(
    capsule_id = execution_id, release_instance_id = execution_id,
    coordinate_count = dimension,
    chunk_coordinates = public_chunk_coordinates,
    chunk_count = value$geometry$public_chunk_count,
    output_lattice_bits = physical$lattice$output_lattice_bits,
    output_lattice_scale = physical$lattice$output_lattice_scale,
    epsilon = physical$request$epsilon,
    allocated_delta = physical$request$delta,
    sensitivity_steps = if (isTRUE(profile$gaussian)) {
      physical$request$l2_sensitivity_steps
    } else physical$request$sensitivity_steps,
    backend = profile$backend, sampler = profile$sampler,
    mechanism = physical$profile$mechanism)
  vector <- list(
    release_contract = .dsvert_dp_canonical_query_value(release_contract),
    release_contract_hash = contract_sha256,
    transcript_hash = contract_sha256,
    execution_attempt_hash = attempt_sha256,
    plan = physical$full_plan,
    plan_sha256 = physical$full_plan_sha256,
    designated = authority_peers, profile = profile, lattice = lattice,
    source_contract = source_contract, artifact_key = artifact$artifact_key)
  list(
    authorization = authorization, manifest_json = manifest_json,
    source_contract = source_contract, execution_id = execution_id,
    contract = list(value = value, sha256 = contract_sha256),
    attempt = list(value = attempt_value, sha256 = attempt_sha256),
    vector = vector)
}

.dsvert_dp_synopsis_execution_prepare_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_execution_json_v1 <- function(
    value, what, maximum_bytes) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    stop("Invalid synopsis execution ", what, ".", call. = FALSE)
  }
  parsed <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = FALSE), error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(parsed)),
    error = function(error) NULL)
  if (is.null(parsed) || !identical(canonical, value)) {
    stop("Invalid or non-canonical synopsis execution ", what, ".",
         call. = FALSE)
  }
  parsed
}

.dsvert_dp_synopsis_execution_prepare_set_v1 <- function(
    first_prepare, second_prepare, context, policy,
    .verifier = .dsvert_relay_verify_message) {
  if (!is.function(.verifier) || !is.list(context) ||
      !is.list(context$contract) || !is.list(context$attempt) ||
      !is.list(context$authorization)) {
    stop("Invalid synopsis execution PREPARE context.", call. = FALSE)
  }
  fields <- c(
    "version", "execution_id", "artifact_key", "contract_sha256",
    "attempt_sha256", "local_authority", "commitment_context",
    "seed_commitment", "signature")
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  roles <- context$contract$value$authority_roles
  peers <- unlist(context$contract$value$authority_peers,
                  use.names = FALSE)
  identities <- unlist(roles$authority_ids, use.names = FALSE)
  role_names <- unlist(roles$role_order, use.names = FALSE)
  if (length(peers) != 2L || length(identities) != 2L ||
      length(role_names) != 2L) {
    stop("Invalid synopsis execution PREPARE authorities.", call. = FALSE)
  }
  expected_authorities <- lapply(seq_len(2L), function(index) list(
    peer_name = peers[[index]], identity_pk = identities[[index]],
    role = role_names[[index]]))
  names(expected_authorities) <- peers
  expected_common <- list(
    execution_id = context$execution_id,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256)
  verify <- function(encoded) {
    value <- .dsvert_dp_synopsis_execution_json_v1(
      encoded, "PREPARE record",
      .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_MAX_BYTES)
    if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
        anyDuplicated(names(value)) || !setequal(names(value), fields) ||
        !identical(value$version,
                   .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_VERSION)) {
      stop("Invalid synopsis execution PREPARE record.", call. = FALSE)
    }
    authority <- value$local_authority
    if (!is.list(authority) || is.null(names(authority)) ||
        anyNA(names(authority)) || anyDuplicated(names(authority)) ||
        !setequal(names(authority),
                  c("peer_name", "identity_pk", "role"))) {
      stop("Invalid synopsis execution PREPARE authority.", call. = FALSE)
    }
    peer <- tryCatch(.dsvert_dp_analysis_scalar_id(
      authority$peer_name, "PREPARE peer"), error = function(error) "")
    if (!peer %in% peers || !peer %in% names(pins) ||
        !identical(.dsvert_dp_canonical_query_value(authority),
                   .dsvert_dp_canonical_query_value(
                     expected_authorities[[peer]])) ||
        !identical(authority$identity_pk, unname(pins[[peer]]))) {
      stop("Invalid synopsis execution PREPARE authority coverage.",
           call. = FALSE)
    }
    if (!identical(value[names(expected_common)], expected_common)) {
      stop("The synopsis execution PREPARE records do not agree.",
           call. = FALSE)
    }
    expected_context <- .dsvert_joint_dp_vector_context(
      expected_common$contract_sha256, peer,
      context$vector$profile$commitment_purpose)
    for (field in c("commitment_context", "seed_commitment")) {
      value[[field]] <- .dsvert_dp_synopsis_hex_v1(
        value[[field]], paste("PREPARE", field))
    }
    signature <- .dsvert_dp_synopsis_signature_v1(value$signature)
    unsigned <- value[setdiff(fields, "signature")]
    if (!identical(value$commitment_context, expected_context) ||
        !isTRUE(tryCatch(.verifier(
          .dsvert_dp_synopsis_execution_prepare_message_v1(unsigned),
          authority$identity_pk, signature),
        error = function(error) FALSE))) {
      stop("Synopsis execution PREPARE signature verification failed.",
           call. = FALSE)
    }
    c(unsigned, list(signature = signature))
  }
  verified <- lapply(list(first_prepare, second_prepare), verify)
  observed <- vapply(
    verified, function(value) value$local_authority$peer_name,
    character(1L))
  if (anyDuplicated(observed) || !setequal(observed, peers)) {
    stop("Invalid synopsis execution PREPARE authority coverage.",
         call. = FALSE)
  }
  names(verified) <- observed
  verified <- verified[peers]
  local <- context$authorization$local_authority
  if (!identical(
      .dsvert_dp_canonical_query_value(
        verified[[local$peer_name]]$local_authority),
      .dsvert_dp_canonical_query_value(local))) {
    stop("The local synopsis PREPARE authority is missing.",
         call. = FALSE)
  }
  verified
}

.dsvert_dp_synopsis_execution_prepare_v1 <- function(
    ss, session_id, .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get, .signer = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  if (is.null(.signer)) .signer <- .dsvert_relay_sign_message
  if (!is.list(.identity) || is.null(.identity$identity_sk) ||
      !is.function(.signer)) {
    stop("Invalid synopsis execution PREPARE signer.", call. = FALSE)
  }
  context <- .dsvert_dp_synopsis_execution_context_v1(
    ss, session_id, .policy, .secret, .identity, .cache_get)
  authorization <- context$authorization
  semantic <- authorization$artifact$semantic
  seed <- .dsvert_dp_sticky_subseed_material_v1(
    authorization$artifact_key,
    semantic$privacy$mechanism$randomness$lanes,
    semantic$noise_authority_roles$authority_ids, "final_noise",
    authorization$local_authority$identity_pk)
  seed_raw <- .dsvert_joint_dp_backend_hex_raw_v2(
    seed, "synopsis sticky final-noise seed")
  commitment_context <- .dsvert_joint_dp_vector_context(
    context$contract$sha256, authorization$local_authority$peer_name,
    context$vector$profile$commitment_purpose)
  context_raw <- .dsvert_joint_dp_backend_hex_raw_v2(
    commitment_context, "synopsis seed commitment context")
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_VERSION,
    execution_id = context$execution_id,
    artifact_key = authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    local_authority = authorization$local_authority,
    commitment_context = commitment_context,
    seed_commitment = .dsvert_joint_dp_backend_hash_raw_v2(c(
      context_raw, seed_raw)))
  signature <- .dsvert_dp_synopsis_signature_v1(.signer(
    .dsvert_dp_synopsis_execution_prepare_message_v1(unsigned),
    .identity$identity_sk))
  c(unsigned, list(signature = signature))
}

.dsvert_dp_synopsis_execution_store_path_v1 <- function(policy) {
  base <- .dsvert_dp_ledger_path(
    policy$ledger_path, require_private = isTRUE(policy$ledger_private))
  path <- paste0(base, ".synopsis-execution-v1.sqlite")
  .dsvert_dp_assert_private_file(
    path, "synopsis execution store",
    require_private = isTRUE(policy$ledger_private))
  path
}

.dsvert_dp_synopsis_execution_store_mac_v1 <- function(
    secret, table, key, json) {
  if (!is.raw(secret) || length(secret) != 32L ||
      !is.character(table) || length(table) != 1L || is.na(table) ||
      !is.character(key) || length(key) != 1L || is.na(key) ||
      !is.character(json) || length(json) != 1L || is.na(json)) {
    stop("Invalid synopsis execution store authentication input.",
         call. = FALSE)
  }
  digest::hmac(
    key = secret, object = charToRaw(paste0(
      "dsVert/stateless-catalog-synopsis/execution-store/v1|",
      table, "|", key, "|", json)),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}

.dsvert_dp_synopsis_execution_record_json_v1 <- function(value) {
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value))
}

.dsvert_dp_synopsis_execution_record_decode_v1 <- function(
    row, secret, table, key, what,
    maximum_bytes = .DSVERT_DP_SYNOPSIS_EXECUTION_STORE_MAX_RECORD_BYTES) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !all(c("record_json", "row_mac") %in% names(row)) ||
      !is.character(row$record_json[[1L]]) ||
      length(row$record_json[[1L]]) != 1L ||
      is.na(row$record_json[[1L]]) ||
      nchar(row$record_json[[1L]], type = "bytes") >
        maximum_bytes ||
      !.dsvert_joint_dp_dsi_hex_equal(
        row$row_mac[[1L]], .dsvert_dp_synopsis_execution_store_mac_v1(
          secret, table, key, row$record_json[[1L]]))) {
    stop("The synopsis execution ", what,
         " failed private-store authentication.", call. = FALSE)
  }
  value <- tryCatch(jsonlite::fromJSON(
    row$record_json[[1L]], simplifyVector = FALSE),
    error = function(error) NULL)
  if (is.null(value) || !identical(
      .dsvert_dp_synopsis_execution_record_json_v1(value),
      row$record_json[[1L]])) {
    stop("The synopsis execution ", what, " is malformed.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_execution_schema_statements_v1 <- function() c(
  paste(
    "CREATE TABLE synopsis_meta (key TEXT PRIMARY KEY,",
    "value TEXT NOT NULL, row_mac TEXT NOT NULL) WITHOUT ROWID"),
  paste(
    "CREATE TABLE synopsis_artifacts (artifact_key TEXT PRIMARY KEY,",
    "state TEXT NOT NULL CHECK(state = 'STARTED'),",
    "sticky_core_sha256 TEXT NOT NULL, run_binding_sha256 TEXT NOT NULL,",
    "execution_chunk_count INTEGER NOT NULL",
    "CHECK(execution_chunk_count > 0),",
    "public_chunk_count INTEGER NOT NULL CHECK(public_chunk_count > 0),",
    "record_json TEXT NOT NULL, row_mac TEXT NOT NULL) WITHOUT ROWID"),
  paste(
    "CREATE TABLE synopsis_chunks (artifact_key TEXT NOT NULL,",
    "kind TEXT NOT NULL CHECK(kind = 'LOCAL'),",
    "chunk_index INTEGER NOT NULL CHECK(chunk_index >= 0),",
    "payload_chars INTEGER NOT NULL CHECK(payload_chars > 0),",
    "record_json TEXT NOT NULL, row_mac TEXT NOT NULL,",
    "PRIMARY KEY(artifact_key,kind,chunk_index),",
    "FOREIGN KEY(artifact_key) REFERENCES synopsis_artifacts(artifact_key)",
    ") WITHOUT ROWID"),
  paste(
    "CREATE TABLE synopsis_results (artifact_key TEXT PRIMARY KEY,",
    "receipt_sha256 TEXT NOT NULL, record_json TEXT NOT NULL,",
    "row_mac TEXT NOT NULL, FOREIGN KEY(artifact_key)",
    "REFERENCES synopsis_artifacts(artifact_key)) WITHOUT ROWID"),
  paste(
    "CREATE TABLE synopsis_public_chunks (artifact_key TEXT NOT NULL,",
    "public_chunk_index INTEGER NOT NULL CHECK(public_chunk_index >= 0),",
    "chunk_sha256 TEXT NOT NULL, record_json TEXT NOT NULL,",
    "row_mac TEXT NOT NULL, PRIMARY KEY(artifact_key,public_chunk_index),",
    "FOREIGN KEY(artifact_key) REFERENCES synopsis_artifacts(artifact_key)",
    ") WITHOUT ROWID"),
  paste(
    "CREATE TABLE synopsis_releases (artifact_key TEXT PRIMARY KEY,",
    "receipt_sha256 TEXT NOT NULL, result_set_sha256 TEXT NOT NULL,",
    "final_vector_root TEXT NOT NULL, record_json TEXT NOT NULL,",
    "row_mac TEXT NOT NULL, FOREIGN KEY(artifact_key)",
    "REFERENCES synopsis_artifacts(artifact_key)) WITHOUT ROWID"))

.dsvert_dp_synopsis_execution_schema_rows_v1 <- function(connection) {
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT type,name,tbl_name,sql FROM sqlite_master",
    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,tbl_name,name"))
  rows$sql <- vapply(rows$sql, function(value) {
    if (is.na(value)) return(NA_character_)
    gsub("[[:space:]]+", " ", trimws(value), perl = TRUE)
  }, character(1L))
  rownames(rows) <- NULL
  rows
}

.dsvert_dp_synopsis_execution_schema_expected_v1 <- local({
  value <- NULL
  function() {
    if (!is.null(value)) return(value)
    connection <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    for (statement in
         .dsvert_dp_synopsis_execution_schema_statements_v1()) {
      DBI::dbExecute(connection, statement)
    }
    value <<- .dsvert_dp_synopsis_execution_schema_rows_v1(connection)
    value
  }
})

.dsvert_dp_synopsis_execution_transaction_v1 <- function(
    connection, code) {
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  committed <- FALSE
  on.exit(if (!committed) try(
    DBI::dbRollback(connection), silent = TRUE), add = TRUE)
  value <- force(code)
  DBI::dbCommit(connection)
  committed <- TRUE
  value
}

.dsvert_dp_synopsis_execution_store_initialize_v1 <- function(
    connection, policy, secret) {
  binding <- .dsvert_dp_synopsis_execution_record_json_v1(list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_STORE_VERSION,
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_name = policy$peer_name, own_identity_pk = policy$own_identity_pk,
    peer_pinset_sha256 = policy$peer_pinset_sha256))
  mac <- .dsvert_dp_synopsis_execution_store_mac_v1(
    secret, "meta", "policy_binding", binding)
  rows <- .dsvert_dp_synopsis_execution_schema_rows_v1(connection)
  if (!nrow(rows)) {
    .dsvert_dp_synopsis_execution_transaction_v1(connection, {
      for (statement in
           .dsvert_dp_synopsis_execution_schema_statements_v1()) {
        DBI::dbExecute(connection, statement)
      }
      DBI::dbExecute(connection, paste(
        "INSERT INTO synopsis_meta(key,value,row_mac)",
        "VALUES('policy_binding',?,?)"), params = list(binding, mac))
      invisible(TRUE)
    })
  }
  if (!identical(
      .dsvert_dp_synopsis_execution_schema_rows_v1(connection),
      .dsvert_dp_synopsis_execution_schema_expected_v1())) {
    stop("The synopsis execution store schema is invalid.", call. = FALSE)
  }
  observed <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM synopsis_meta",
    "WHERE key='policy_binding'"))
  if (nrow(observed) != 1L ||
      !identical(observed$value[[1L]], binding) ||
      !.dsvert_joint_dp_dsi_hex_equal(observed$row_mac[[1L]], mac)) {
    stop(paste(
      "The synopsis execution store belongs to another policy or failed",
      "authentication."), call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_synopsis_execution_with_store_v1 <- function(
    policy, secret, code) {
  if (!is.raw(secret) || length(secret) != 32L || !is.function(code)) {
    stop("Invalid synopsis execution store dependency.", call. = FALSE)
  }
  path <- .dsvert_dp_synopsis_execution_store_path_v1(policy)
  private <- isTRUE(policy$ledger_private)
  paths <- c(
    store = path, lock = paste0(path, ".lock"),
    wal = paste0(path, "-wal"), shm = paste0(path, "-shm"))
  for (name in names(paths)) .dsvert_dp_assert_private_file(
    paths[[name]], paste("synopsis execution store", name), private)
  previous_umask <- Sys.umask("0077")
  on.exit(Sys.umask(previous_umask), add = TRUE)
  lock <- filelock::lock(
    paths[["lock"]], timeout = policy$lock_timeout_ms %||% 30000)
  if (is.null(lock)) {
    stop("The synopsis execution store is busy.", call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
  .dsvert_dp_synopsis_execution_store_initialize_v1(
    connection, policy, secret)
  DBI::dbExecute(connection, "PRAGMA foreign_keys=ON")
  DBI::dbExecute(connection, "PRAGMA journal_mode=WAL")
  DBI::dbExecute(connection, "PRAGMA synchronous=FULL")
  .dsvert_dp_chmod_private_files(paths)
  for (name in names(paths)) .dsvert_dp_assert_private_file(
    paths[[name]], paste("synopsis execution store", name), private)
  code(connection)
}

.dsvert_dp_synopsis_execution_artifact_load_v1 <- function(
    connection, secret, artifact_key) {
  artifact_key <- .dsvert_dp_synopsis_hex_v1(
    artifact_key, "execution artifact key")
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT artifact_key,state,sticky_core_sha256,run_binding_sha256,",
    "execution_chunk_count,public_chunk_count,record_json,row_mac",
    "FROM synopsis_artifacts",
    "WHERE artifact_key=?"), params = list(artifact_key))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_dp_synopsis_execution_record_decode_v1(
    row, secret, "artifacts", artifact_key, "artifact record")
  value <- .dsvert_dp_canonical_query_value(value)
  fields <- c(
    "version", "artifact_key", "sticky_core_sha256",
    "run_binding_sha256", "execution_chunk_count",
    "public_chunk_count", "state")
  if (!is.list(value) || is.null(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_DP_SYNOPSIS_EXECUTION_STORE_RECORD_VERSION) ||
      !identical(value$artifact_key, artifact_key) ||
      !identical(value$state, row$state[[1L]]) ||
      !identical(value$sticky_core_sha256,
                 row$sticky_core_sha256[[1L]]) ||
      !identical(value$run_binding_sha256,
                 row$run_binding_sha256[[1L]]) ||
      !identical(as.numeric(value$execution_chunk_count),
                 as.numeric(row$execution_chunk_count[[1L]])) ||
      !identical(as.numeric(value$public_chunk_count),
                 as.numeric(row$public_chunk_count[[1L]]))) {
    stop("The synopsis execution artifact record is inconsistent.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_execution_start_claim_v1 <- function(
    connection, artifact_key, sticky_core_sha256,
    run_binding_sha256, execution_chunk_count, public_chunk_count,
    secret) {
  artifact_key <- .dsvert_dp_synopsis_hex_v1(
    artifact_key, "execution artifact key")
  sticky_core_sha256 <- .dsvert_dp_synopsis_hex_v1(
    sticky_core_sha256, "execution sticky contract hash")
  run_binding_sha256 <- .dsvert_dp_synopsis_hex_v1(
    run_binding_sha256, "execution attempt hash")
  counts <- c(execution_chunk_count, public_chunk_count)
  if (!is.numeric(counts) || length(counts) != 2L || anyNA(counts) ||
      any(!is.finite(counts)) || any(counts != floor(counts)) ||
      any(counts < 1L) || any(counts > 1000000L)) {
    stop("Invalid synopsis execution chunk count.", call. = FALSE)
  }
  candidate <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_STORE_RECORD_VERSION,
    artifact_key = artifact_key,
    sticky_core_sha256 = sticky_core_sha256,
    run_binding_sha256 = run_binding_sha256,
    execution_chunk_count = as.integer(execution_chunk_count),
    public_chunk_count = as.integer(public_chunk_count), state = "STARTED"))
  existing <- .dsvert_dp_synopsis_execution_artifact_load_v1(
    connection, secret, artifact_key)
  if (!is.null(existing)) {
    immutable <- setdiff(names(candidate), "state")
    if (!identical(existing[immutable], candidate[immutable])) {
      stop("The synopsis execution artifact was first claimed by a conflicting attempt.",
           call. = FALSE)
    }
    return(existing)
  }
  json <- .dsvert_dp_synopsis_execution_record_json_v1(candidate)
  mac <- .dsvert_dp_synopsis_execution_store_mac_v1(
    secret, "artifacts", artifact_key, json)
  DBI::dbExecute(connection, paste(
    "INSERT INTO synopsis_artifacts(",
    "artifact_key,state,sticky_core_sha256,run_binding_sha256,",
    "execution_chunk_count,public_chunk_count,record_json,row_mac)",
    "VALUES(?,?,?,?,?,?,?,?)"), params = list(
      artifact_key, "STARTED", sticky_core_sha256, run_binding_sha256,
      as.integer(execution_chunk_count), as.integer(public_chunk_count),
      json, mac))
  candidate
}

.dsvert_dp_synopsis_execution_chunk_v1 <- function(context, chunk_index) {
  geometry <- context$attempt$value$execution_geometry
  dimension <- context$contract$value$geometry$coordinate_count
  if (!is.list(geometry) ||
      !.dsvert_dp_synopsis_integer_v1(
        geometry$chunk_coordinates, 1, 1000000) ||
      !.dsvert_dp_synopsis_integer_v1(
        geometry$chunk_count, 1, 1000000) ||
      !.dsvert_dp_synopsis_integer_v1(dimension, 1, 1000000)) {
    stop("Invalid synopsis execution chunk geometry.", call. = FALSE)
  }
  index <- .dsvert_joint_dp_vector_index(
    chunk_index, "synopsis execution chunk index", 0,
    geometry$chunk_count - 1L)
  offset <- index * geometry$chunk_coordinates
  count <- min(geometry$chunk_coordinates, dimension - offset)
  list(index = as.integer(index), offset = as.integer(offset),
       count = as.integer(count))
}

.dsvert_dp_synopsis_execution_local_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_execution_local_validate_v1 <- function(
    receipt, context, prepare, chunk, policy,
    .verifier = .dsvert_relay_verify_message) {
  fields <- c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "local_authority", "chunk_index", "coordinate_offset",
    "coordinate_count", "backend", "sampler", "seed_commitment",
    "local_chunk_sha256", "sampler_contract_sha256",
    "local_chunk_durable", "intermediate_payload_exposed", "signature")
  expected <- list(
    execution_id = context$execution_id,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256)
  expected_seed_commitment <- if (is.null(prepare)) {
    receipt$seed_commitment
  } else prepare$seed_commitment
  valid <- is.function(.verifier) && is.list(receipt) &&
    !is.null(names(receipt)) && !anyNA(names(receipt)) &&
    !anyDuplicated(names(receipt)) && setequal(names(receipt), fields) &&
    identical(receipt$version,
              .DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_VERSION) &&
    identical(receipt$phase, "synopsis_local_chunk_committed") &&
    identical(receipt[names(expected)], expected) &&
    identical(.dsvert_dp_canonical_query_value(receipt$local_authority),
              .dsvert_dp_canonical_query_value(
                context$authorization$local_authority)) &&
    .dsvert_dp_synopsis_integer_v1(receipt$chunk_index, 0, 999999) &&
    .dsvert_dp_synopsis_integer_v1(
      receipt$coordinate_offset, 0, 999999) &&
    .dsvert_dp_synopsis_integer_v1(
      receipt$coordinate_count, 1, 1000000) &&
    identical(as.numeric(receipt$chunk_index), as.numeric(chunk$index)) &&
    identical(as.numeric(receipt$coordinate_offset),
              as.numeric(chunk$offset)) &&
    identical(as.numeric(receipt$coordinate_count),
              as.numeric(chunk$count)) &&
    identical(receipt$backend, context$vector$profile$backend) &&
    identical(receipt$sampler, context$vector$profile$sampler) &&
    identical(receipt$seed_commitment, expected_seed_commitment) &&
    identical(receipt$local_chunk_durable, TRUE) &&
    identical(receipt$intermediate_payload_exposed, FALSE)
  if (!isTRUE(valid)) {
    stop("Invalid durable synopsis LOCAL receipt.", call. = FALSE)
  }
  for (field in c(
      "seed_commitment", "local_chunk_sha256",
      "sampler_contract_sha256")) {
    receipt[[field]] <- .dsvert_dp_synopsis_hex_v1(
      receipt[[field]], paste("LOCAL", field))
  }
  receipt$local_authority <- context$authorization$local_authority
  signature <- .dsvert_dp_synopsis_signature_v1(receipt$signature)
  unsigned <- receipt[setdiff(fields, "signature")]
  identity_pk <- context$authorization$local_authority$identity_pk
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  if (!identical(identity_pk, unname(
        pins[[context$authorization$local_authority$peer_name]])) ||
      !isTRUE(tryCatch(.verifier(
        .dsvert_dp_synopsis_execution_local_message_v1(unsigned),
        identity_pk, signature), error = function(error) FALSE))) {
    stop("Synopsis LOCAL receipt signature verification failed.",
         call. = FALSE)
  }
  c(unsigned, list(signature = signature))
}

.dsvert_dp_synopsis_execution_local_key_v1 <- function(
    artifact_key, chunk_index) {
  paste(artifact_key, "LOCAL", as.integer(chunk_index), sep = "|")
}

.dsvert_dp_synopsis_execution_local_load_v1 <- function(
    connection, secret, context, prepare, chunk, policy, .verifier) {
  artifact_key <- context$authorization$artifact_key
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT kind,payload_chars,record_json,row_mac FROM synopsis_chunks",
    "WHERE artifact_key=? AND kind='LOCAL' AND chunk_index=?"),
  params = list(artifact_key, chunk$index))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_dp_synopsis_execution_record_decode_v1(
    row, secret, "chunks",
    .dsvert_dp_synopsis_execution_local_key_v1(
      artifact_key, chunk$index), "LOCAL chunk record")
  fields <- c(
    "version", "artifact_key", "execution_id", "contract_sha256",
    "attempt_sha256", "source_contract_sha256", "chunk_index",
    "coordinate_offset", "coordinate_count", "noised_share_b64",
    "noised_share_sha256", "sampler_contract_sha256", "payload_chars",
    "receipt")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) &&
    identical(value$version,
              .DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_RECORD_VERSION) &&
    identical(value$artifact_key, artifact_key) &&
    identical(value$execution_id, context$execution_id) &&
    identical(value$contract_sha256, context$contract$sha256) &&
    identical(value$attempt_sha256, context$attempt$sha256) &&
    identical(value$source_contract_sha256,
              context$attempt$value$source_contract_sha256) &&
    .dsvert_dp_synopsis_integer_v1(value$chunk_index, 0, 999999) &&
    .dsvert_dp_synopsis_integer_v1(value$coordinate_offset, 0, 999999) &&
    .dsvert_dp_synopsis_integer_v1(value$coordinate_count, 1, 1000000) &&
    identical(as.numeric(value$chunk_index), as.numeric(chunk$index)) &&
    identical(as.numeric(value$coordinate_offset),
              as.numeric(chunk$offset)) &&
    identical(as.numeric(value$coordinate_count),
              as.numeric(chunk$count)) &&
    identical(row$kind[[1L]], "LOCAL") &&
    .dsvert_dp_synopsis_integer_v1(value$payload_chars, 1, 524288) &&
    identical(as.numeric(value$payload_chars),
              as.numeric(row$payload_chars[[1L]])) &&
    is.character(value$noised_share_b64) &&
    length(value$noised_share_b64) == 1L &&
    !is.na(value$noised_share_b64) &&
    identical(as.numeric(nchar(
      value$noised_share_b64, type = "bytes")),
    as.numeric(value$payload_chars))
  if (!isTRUE(valid)) {
    stop("The synopsis execution LOCAL chunk is inconsistent.",
         call. = FALSE)
  }
  share <- .dsvert_joint_dp_vector_standard_b64(
    value$noised_share_b64, "synopsis LOCAL noised share",
    chunk$count * 16L)
  if (!.dsvert_joint_dp_dsi_hex_equal(
        value$noised_share_sha256,
        digest::digest(share, algo = "sha256", serialize = FALSE))) {
    stop("The synopsis execution LOCAL payload failed authentication.",
         call. = FALSE)
  }
  value$receipt <- .dsvert_dp_synopsis_execution_local_validate_v1(
    value$receipt, context, prepare, chunk, policy, .verifier)
  if (!identical(value$receipt$local_chunk_sha256,
                 value$noised_share_sha256) ||
      !identical(value$receipt$sampler_contract_sha256,
                 value$sampler_contract_sha256)) {
    stop("The synopsis execution LOCAL receipt disagrees with its payload.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_execution_local_put_v1 <- function(
    connection, secret, candidate, context, prepare, chunk, policy,
    .verifier) {
  existing <- .dsvert_dp_synopsis_execution_local_load_v1(
    connection, secret, context, prepare, chunk, policy, .verifier)
  if (!is.null(existing)) {
    left <- existing; right <- candidate
    left$receipt$signature <- NULL; right$receipt$signature <- NULL
    if (!identical(
          .dsvert_dp_synopsis_execution_record_json_v1(left),
          .dsvert_dp_synopsis_execution_record_json_v1(right))) {
      stop("Conflicting durable synopsis LOCAL chunk.", call. = FALSE)
    }
    return(existing)
  }
  json <- .dsvert_dp_synopsis_execution_record_json_v1(candidate)
  key <- .dsvert_dp_synopsis_execution_local_key_v1(
    candidate$artifact_key, candidate$chunk_index)
  mac <- .dsvert_dp_synopsis_execution_store_mac_v1(
    secret, "chunks", key, json)
  DBI::dbExecute(connection, paste(
    "INSERT INTO synopsis_chunks(",
    "artifact_key,kind,chunk_index,payload_chars,record_json,row_mac)",
    "VALUES(?,'LOCAL',?,?,?,?)"), params = list(
      candidate$artifact_key, as.integer(candidate$chunk_index),
      as.integer(candidate$payload_chars), json, mac))
  candidate
}

.dsvert_dp_synopsis_execution_start_v1 <- function(
    ss, session_id, first_prepare, second_prepare, chunk_index,
    .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message, .signer = NULL,
    .source_reader = NULL, .sampler = NULL, .exact_compiler = NULL,
    .exact_start = .dsvert_joint_dp_vector_exact_gc_start,
    .session = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  if (!is.function(.verifier)) {
    stop("Invalid synopsis START dependencies.", call. = FALSE)
  }
  context <- .dsvert_dp_synopsis_execution_context_v1(
    ss, session_id, .policy, .secret, .identity, .cache_get)
  chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, chunk_index)
  prepares <- .dsvert_dp_synopsis_execution_prepare_set_v1(
    first_prepare, second_prepare, context, .policy, .verifier)
  own <- prepares[[context$authorization$local_authority$peer_name]]
  if (isTRUE(context$vector$profile$exact_gc)) {
    stop(paste(
      "Synopsis exact-GC START requires its dedicated initialization and",
      "RESULT adapter."), call. = FALSE)
  }
  if (is.null(.signer)) .signer <- .dsvert_relay_sign_message
  if (!is.list(.identity) || is.null(.identity$identity_sk) ||
      !is.function(.signer)) {
    stop("Invalid synopsis START signer.", call. = FALSE)
  }
  if (is.null(.source_reader)) .source_reader <- function(
      policy, manifest_json, offset, count, secret, source_contract) {
    .dsvert_dp_capsule_source_aggregate_release_range_internal(
      policy, manifest_json, offset, count, secret, source_contract)
  }
  if (is.null(.sampler)) .sampler <- function(command, input) {
    .callMpcTool(command, input)
  }
  if (!is.function(.source_reader) || !is.function(.sampler)) {
    stop("Invalid synopsis START private dependency.", call. = FALSE)
  }
  artifact_key <- context$authorization$artifact_key
  .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) {
      .dsvert_dp_synopsis_execution_transaction_v1(connection, {
        .dsvert_dp_synopsis_execution_start_claim_v1(
          connection, artifact_key, context$contract$sha256,
          context$attempt$sha256,
          context$attempt$value$execution_geometry$chunk_count,
          context$contract$value$geometry$public_chunk_count, .secret)
      })
    })
  existing <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) {
      .dsvert_dp_synopsis_execution_local_load_v1(
        connection, .secret, context, own, chunk, .policy, .verifier)
    })
  if (!is.null(existing)) return(existing$receipt)

  semantic <- context$authorization$artifact$semantic
  seed <- .dsvert_dp_sticky_subseed_material_v1(
    artifact_key, semantic$privacy$mechanism$randomness$lanes,
    semantic$noise_authority_roles$authority_ids, "final_noise",
    context$authorization$local_authority$identity_pk)
  seed_raw <- .dsvert_joint_dp_backend_hex_raw_v2(
    seed, "synopsis sticky final-noise seed")
  expected_commitment <- .dsvert_joint_dp_backend_hash_raw_v2(c(
    .dsvert_joint_dp_backend_hex_raw_v2(
      own$commitment_context, "synopsis seed commitment context"),
    seed_raw))
  if (!.dsvert_joint_dp_dsi_hex_equal(
        expected_commitment, own$seed_commitment)) {
    stop("The sticky synopsis seed no longer matches PREPARE.",
         call. = FALSE)
  }
  source <- .source_reader(
    .policy, context$manifest_json, chunk$offset, chunk$count,
    .secret, context$source_contract)
  if (!is.raw(source) || length(source) != chunk$count * 16L) {
    stop("The synopsis aggregate range has the wrong Ring128 shape.",
         call. = FALSE)
  }
  positions <- seq.int(chunk$offset + 1L, chunk$offset + chunk$count)
  release <- context$vector$release_contract
  input <- c(list(
    version = context$vector$profile$input_version,
    ring_bits = 128L, frac_bits = 0L,
    total_coordinate_count = release$coordinate_count,
    chunk_start = chunk$offset, coordinate_count = chunk$count,
    output_lattice_bits = release$output_lattice_bits,
    epsilon = release$epsilon, allocated_delta = release$allocated_delta),
  if (isTRUE(context$vector$profile$gaussian)) {
    list(l2_sensitivity_steps = release$sensitivity_steps)
  } else list(sensitivity_steps = release$sensitivity_steps), list(
    scale_shifts = as.list(context$vector$lattice$scale_shifts[positions]),
    raw_upper_bounds = as.list(
      context$vector$lattice$raw_upper_bounds[positions]),
    release_contract_hash = context$contract$sha256,
    transcript_hash = context$contract$sha256,
    peer_name = .policy$peer_name,
    commitment_context = own$commitment_context,
    seed_commitment = own$seed_commitment,
    private_seed = seed,
    source_share = gsub("[\r\n]", "", jsonlite::base64_enc(source))))
  output <- .sampler(context$vector$profile$share_command, input)
  input$private_seed <- NULL; input$source_share <- NULL
  if (is.list(output) && is.list(output$plan)) {
    output$plan <- .dsvert_dp_analysis_canonical_value_v1(output$plan)
  }
  checked <- .dsvert_joint_dp_vector_sampler_validate(
    output, context$vector, list(
      peer_name = own$local_authority$peer_name,
      seed_commitment = own$seed_commitment), chunk)
  rm(source, seed, seed_raw)
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_VERSION,
    phase = "synopsis_local_chunk_committed",
    execution_id = context$execution_id, artifact_key = artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256,
    local_authority = context$authorization$local_authority,
    chunk_index = chunk$index, coordinate_offset = chunk$offset,
    coordinate_count = chunk$count,
    backend = context$vector$profile$backend,
    sampler = context$vector$profile$sampler,
    seed_commitment = own$seed_commitment,
    local_chunk_sha256 = checked$share_sha256,
    sampler_contract_sha256 = output$sampler_contract_hash,
    local_chunk_durable = TRUE, intermediate_payload_exposed = FALSE)
  receipt <- c(unsigned, list(signature =
    .dsvert_dp_synopsis_signature_v1(.signer(
      .dsvert_dp_synopsis_execution_local_message_v1(unsigned),
      .identity$identity_sk))))
  .dsvert_dp_synopsis_execution_local_validate_v1(
    receipt, context, own, chunk, .policy, .verifier)
  record <- list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_LOCAL_RECORD_VERSION,
    artifact_key = artifact_key, execution_id = context$execution_id,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256,
    chunk_index = chunk$index, coordinate_offset = chunk$offset,
    coordinate_count = chunk$count,
    noised_share_b64 = output$noised_share,
    noised_share_sha256 = checked$share_sha256,
    sampler_contract_sha256 = output$sampler_contract_hash,
    payload_chars = as.integer(nchar(
      output$noised_share, type = "bytes")), receipt = receipt)
  persisted <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) {
      .dsvert_dp_synopsis_execution_transaction_v1(connection, {
        claim <- .dsvert_dp_synopsis_execution_artifact_load_v1(
          connection, .secret, artifact_key)
        if (is.null(claim) ||
            !identical(claim$sticky_core_sha256,
                       context$contract$sha256) ||
            !identical(claim$run_binding_sha256,
                       context$attempt$sha256)) {
          stop("The synopsis START claim changed before persistence.",
               call. = FALSE)
        }
        .dsvert_dp_synopsis_execution_local_put_v1(
          connection, .secret, record, context, own, chunk,
          .policy, .verifier)
      })
    })
  persisted$receipt
}

.dsvert_dp_synopsis_execution_prepare_set_hash_v1 <- function(prepares) {
  values <- lapply(unname(prepares), function(value) {
    value[setdiff(names(value), "signature")]
  })
  .dsvert_dp_synopsis_execution_hash_v1(
    .DSVERT_DP_SYNOPSIS_EXECUTION_PREPARE_SET_DOMAIN, list(
      version = "dsvert-stateless-catalog-synopsis-prepare-set-v1",
      prepares = values))
}

.dsvert_dp_synopsis_execution_chunk_set_hash_v1 <- function(
    context, authority, commitments) {
  .dsvert_dp_synopsis_execution_hash_v1(
    .DSVERT_DP_SYNOPSIS_EXECUTION_CHUNK_SET_DOMAIN, list(
      version = "dsvert-stateless-catalog-synopsis-local-chunk-set-v1",
      artifact_key = context$authorization$artifact_key,
      contract_sha256 = context$contract$sha256,
      attempt_sha256 = context$attempt$sha256,
      local_authority = authority,
      execution_chunk_count =
        context$attempt$value$execution_geometry$chunk_count,
      public_chunk_count =
        context$contract$value$geometry$public_chunk_count,
      commitments = as.list(commitments)))
}

.dsvert_dp_synopsis_execution_result_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_execution_result_authorities_v1 <- function(
    context, policy) {
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  peers <- unlist(
    context$contract$value$authority_peers, use.names = FALSE)
  identities <- unlist(
    context$contract$value$authority_roles$authority_ids,
    use.names = FALSE)
  roles <- unlist(
    context$contract$value$authority_roles$role_order,
    use.names = FALSE)
  if (length(peers) != 2L || length(identities) != 2L ||
      length(roles) != 2L || anyNA(peers) || anyDuplicated(peers) ||
      !all(peers %in% names(pins)) ||
      !identical(unname(pins[peers]), identities)) {
    stop("Invalid synopsis RESULT authorities.", call. = FALSE)
  }
  values <- lapply(seq_len(2L), function(index) list(
    peer_name = peers[[index]], identity_pk = identities[[index]],
    role = roles[[index]]))
  names(values) <- peers
  values
}

.dsvert_dp_synopsis_execution_result_validate_v1 <- function(
    receipt, context, prepares, policy,
    .verifier = .dsvert_relay_verify_message,
    expected_authority = NULL, expected_prepare_set_sha256 = NULL) {
  fields <- c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "prepare_set_sha256", "local_authority", "execution_chunk_count",
    "public_chunk_count", "local_chunk_commitments",
    "local_chunk_set_root", "local_chunk_set_sha256",
    "all_chunks_durable", "intermediate_payload_exposed", "signature")
  authorities <- .dsvert_dp_synopsis_execution_result_authorities_v1(
    context, policy)
  authority <- expected_authority %||%
    context$authorization$local_authority
  authority_peer <- if (is.list(authority)) authority$peer_name else NULL
  if (!is.character(authority_peer) || length(authority_peer) != 1L ||
      is.na(authority_peer) || is.null(authorities[[authority_peer]]) ||
      !identical(
        .dsvert_dp_canonical_query_value(authority),
        .dsvert_dp_canonical_query_value(authorities[[authority_peer]]))) {
    stop("Invalid synopsis RESULT authority.", call. = FALSE)
  }
  execution_count <-
    context$attempt$value$execution_geometry$chunk_count
  public_count <- context$contract$value$geometry$public_chunk_count
  commitment_values <- receipt$local_chunk_commitments
  canonical_commitments <- is.list(commitment_values) &&
    is.null(names(commitment_values)) &&
    length(commitment_values) == execution_count &&
    all(vapply(commitment_values, function(value) {
      is.character(value) && length(value) == 1L && !is.na(value)
    }, logical(1L)))
  commitments <- if (canonical_commitments) {
    vapply(commitment_values, identity, character(1L))
  } else character()
  expected <- list(
    execution_id = context$execution_id,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256)
  prepare_set_sha256 <- if (!is.null(prepares)) {
    .dsvert_dp_synopsis_execution_prepare_set_hash_v1(prepares)
  } else {
    tryCatch(.dsvert_dp_synopsis_hex_v1(
      expected_prepare_set_sha256, "RESULT PREPARE-set hash"),
    error = function(error) "")
  }
  valid <- is.function(.verifier) && is.list(receipt) &&
    !is.null(names(receipt)) && !anyNA(names(receipt)) &&
    !anyDuplicated(names(receipt)) && setequal(names(receipt), fields) &&
    identical(receipt$version,
              .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_VERSION) &&
    identical(receipt$phase, "synopsis_local_result_committed") &&
    identical(receipt[names(expected)], expected) &&
    identical(.dsvert_dp_canonical_query_value(receipt$local_authority),
              .dsvert_dp_canonical_query_value(authority)) &&
    .dsvert_dp_synopsis_integer_v1(
      receipt$execution_chunk_count, 1, 1000000) &&
    .dsvert_dp_synopsis_integer_v1(
      receipt$public_chunk_count, 1, 1000000) &&
    identical(as.numeric(receipt$execution_chunk_count),
              as.numeric(execution_count)) &&
    identical(as.numeric(receipt$public_chunk_count),
              as.numeric(public_count)) &&
    canonical_commitments && length(commitments) == execution_count &&
    is.character(commitments) && !anyNA(commitments) &&
    all(nchar(commitments, type = "bytes") == 64L) &&
    all(grepl("^[0-9a-f]{64}$", commitments)) &&
    identical(receipt$prepare_set_sha256, prepare_set_sha256) &&
    identical(receipt$local_chunk_set_root,
              .dsvert_joint_dp_vector_merkle_root(commitments)) &&
    identical(receipt$local_chunk_set_sha256,
              .dsvert_dp_synopsis_execution_chunk_set_hash_v1(
                context, authority, commitments)) &&
    identical(receipt$all_chunks_durable, TRUE) &&
    identical(receipt$intermediate_payload_exposed, FALSE)
  if (!isTRUE(valid)) {
    stop("Invalid durable synopsis RESULT receipt.", call. = FALSE)
  }
  for (field in c(
      "prepare_set_sha256", "local_chunk_set_root",
      "local_chunk_set_sha256")) {
    receipt[[field]] <- .dsvert_dp_synopsis_hex_v1(
      receipt[[field]], paste("RESULT", field))
  }
  receipt$local_chunk_commitments <- as.list(commitments)
  receipt$local_authority <- authority
  signature <- .dsvert_dp_synopsis_signature_v1(receipt$signature)
  unsigned <- receipt[setdiff(fields, "signature")]
  identity_pk <- authority$identity_pk
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  if (!identical(identity_pk, unname(pins[[authority$peer_name]])) ||
      !isTRUE(tryCatch(.verifier(
        .dsvert_dp_synopsis_execution_result_message_v1(unsigned),
        identity_pk, signature), error = function(error) FALSE))) {
    stop("Synopsis RESULT receipt signature verification failed.",
         call. = FALSE)
  }
  c(unsigned, list(signature = signature))
}

.dsvert_dp_synopsis_execution_result_load_v1 <- function(
    connection, secret, context, prepares, policy, .verifier,
    expected_prepare_set_sha256 = NULL) {
  artifact_key <- context$authorization$artifact_key
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT receipt_sha256,record_json,row_mac FROM synopsis_results",
    "WHERE artifact_key=?"), params = list(artifact_key))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_dp_synopsis_execution_record_decode_v1(
    row, secret, "results", artifact_key, "RESULT record",
    .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_MAX_RECORD_BYTES)
  fields <- c("version", "artifact_key", "receipt_sha256", "receipt")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) &&
    identical(value$version,
              .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_RECORD_VERSION) &&
    identical(value$artifact_key, artifact_key)
  if (!isTRUE(valid)) {
    stop("The synopsis execution RESULT record is inconsistent.",
         call. = FALSE)
  }
  value$receipt_sha256 <- .dsvert_dp_synopsis_hex_v1(
    value$receipt_sha256, "RESULT receipt hash")
  value$receipt <- .dsvert_dp_synopsis_execution_result_validate_v1(
    value$receipt, context, prepares, policy, .verifier,
    expected_authority = context$authorization$local_authority,
    expected_prepare_set_sha256 = expected_prepare_set_sha256)
  if (!identical(value$receipt_sha256, row$receipt_sha256[[1L]]) ||
      !identical(value$receipt_sha256,
                 .dsvert_joint_dp_hash(value$receipt))) {
    stop("The synopsis execution RESULT record failed authentication.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_execution_result_put_v1 <- function(
    connection, secret, candidate, context, prepares, policy, .verifier) {
  existing <- .dsvert_dp_synopsis_execution_result_load_v1(
    connection, secret, context, prepares, policy, .verifier)
  if (!is.null(existing)) {
    left <- existing; right <- candidate
    left$receipt_sha256 <- NULL; right$receipt_sha256 <- NULL
    left$receipt$signature <- NULL; right$receipt$signature <- NULL
    if (!identical(
          .dsvert_dp_synopsis_execution_record_json_v1(left),
          .dsvert_dp_synopsis_execution_record_json_v1(right))) {
      stop("Conflicting durable synopsis RESULT.", call. = FALSE)
    }
    return(existing)
  }
  json <- .dsvert_dp_synopsis_execution_record_json_v1(candidate)
  artifact_key <- candidate$artifact_key
  mac <- .dsvert_dp_synopsis_execution_store_mac_v1(
    secret, "results", artifact_key, json)
  DBI::dbExecute(connection, paste(
    "INSERT INTO synopsis_results(",
    "artifact_key,receipt_sha256,record_json,row_mac) VALUES(?,?,?,?)"),
  params = list(
    artifact_key, candidate$receipt_sha256, json, mac))
  candidate
}

.dsvert_dp_synopsis_execution_result_v1 <- function(
    ss, session_id, first_prepare, second_prepare,
    .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message, .signer = NULL,
    .exact_compiler = NULL,
    .exact_consume = .dsvert_joint_dp_vector_exact_gc_consume,
    .session = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  if (!is.function(.verifier)) {
    stop("Invalid synopsis RESULT verifier.", call. = FALSE)
  }
  context <- .dsvert_dp_synopsis_execution_context_v1(
    ss, session_id, .policy, .secret, .identity, .cache_get)
  prepares <- .dsvert_dp_synopsis_execution_prepare_set_v1(
    first_prepare, second_prepare, context, .policy, .verifier)
  own <- prepares[[context$authorization$local_authority$peer_name]]
  if (isTRUE(context$vector$profile$exact_gc)) {
    stop(paste(
      "Synopsis exact-GC RESULT requires its dedicated durable-before-",
      "consume adapter."), call. = FALSE)
  }
  durable <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) list(
      claim = .dsvert_dp_synopsis_execution_artifact_load_v1(
        connection, .secret, context$authorization$artifact_key),
      result = .dsvert_dp_synopsis_execution_result_load_v1(
        connection, .secret, context, prepares, .policy, .verifier)))
  claim <- durable$claim
  if (is.null(claim)) stop(.dsvert_phase_not_ready_condition())
  expected_execution_count <-
    context$attempt$value$execution_geometry$chunk_count
  expected_public_count <-
    context$contract$value$geometry$public_chunk_count
  if (!identical(claim$sticky_core_sha256, context$contract$sha256) ||
      !identical(claim$run_binding_sha256, context$attempt$sha256) ||
      !identical(as.numeric(claim$execution_chunk_count),
                 as.numeric(expected_execution_count)) ||
      !identical(as.numeric(claim$public_chunk_count),
                 as.numeric(expected_public_count))) {
    stop("The synopsis RESULT has a conflicting START claim.",
         call. = FALSE)
  }
  if (!is.null(durable$result)) return(durable$result$receipt)
  chunks <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) lapply(
      seq.int(0L, expected_execution_count - 1L), function(index) {
        chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, index)
        .dsvert_dp_synopsis_execution_local_load_v1(
          connection, .secret, context, own, chunk, .policy, .verifier)
      }))
  if (any(vapply(chunks, is.null, logical(1L)))) {
    stop(.dsvert_phase_not_ready_condition())
  }
  if (is.null(.signer)) .signer <- .dsvert_relay_sign_message
  if (!is.list(.identity) || is.null(.identity$identity_sk) ||
      !is.function(.signer)) {
    stop("Invalid synopsis RESULT signer.", call. = FALSE)
  }
  commitments <- vapply(chunks, function(value) {
    value$receipt$local_chunk_sha256
  }, character(1L))
  prepare_set_sha256 <-
    .dsvert_dp_synopsis_execution_prepare_set_hash_v1(prepares)
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_VERSION,
    phase = "synopsis_local_result_committed",
    execution_id = context$execution_id,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256,
    prepare_set_sha256 = prepare_set_sha256,
    local_authority = context$authorization$local_authority,
    execution_chunk_count = as.integer(expected_execution_count),
    public_chunk_count = as.integer(expected_public_count),
    local_chunk_commitments = as.list(commitments),
    local_chunk_set_root =
      .dsvert_joint_dp_vector_merkle_root(commitments),
    local_chunk_set_sha256 =
      .dsvert_dp_synopsis_execution_chunk_set_hash_v1(
        context, context$authorization$local_authority, commitments),
    all_chunks_durable = TRUE, intermediate_payload_exposed = FALSE)
  receipt <- c(unsigned, list(signature =
    .dsvert_dp_synopsis_signature_v1(.signer(
      .dsvert_dp_synopsis_execution_result_message_v1(unsigned),
      .identity$identity_sk))))
  receipt <- .dsvert_dp_synopsis_execution_result_validate_v1(
    receipt, context, prepares, .policy, .verifier)
  record <- list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_RECORD_VERSION,
    artifact_key = context$authorization$artifact_key,
    receipt_sha256 = .dsvert_joint_dp_hash(receipt), receipt = receipt)
  persisted <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) {
      .dsvert_dp_synopsis_execution_transaction_v1(connection, {
        claim <- .dsvert_dp_synopsis_execution_artifact_load_v1(
          connection, .secret, context$authorization$artifact_key)
        if (is.null(claim) ||
            !identical(claim$sticky_core_sha256,
                       context$contract$sha256) ||
            !identical(claim$run_binding_sha256,
                       context$attempt$sha256)) {
          stop("The synopsis RESULT claim changed before persistence.",
               call. = FALSE)
        }
        observed <- lapply(
          seq.int(0L, expected_execution_count - 1L), function(index) {
            chunk <- .dsvert_dp_synopsis_execution_chunk_v1(
              context, index)
            value <- .dsvert_dp_synopsis_execution_local_load_v1(
              connection, .secret, context, own, chunk,
              .policy, .verifier)
            value$receipt$local_chunk_sha256
          })
        if (!identical(unlist(observed, use.names = FALSE), commitments)) {
          stop("The synopsis LOCAL set changed before RESULT.",
               call. = FALSE)
        }
        .dsvert_dp_synopsis_execution_result_put_v1(
          connection, .secret, record, context, prepares,
          .policy, .verifier)
      })
    })
  persisted$receipt
}

.dsvert_dp_synopsis_execution_result_set_hash_v1 <- function(results) {
  unsigned <- unname(lapply(results, function(value) {
    value[setdiff(names(value), "signature")]
  }))
  .dsvert_dp_synopsis_execution_hash_v1(
    .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_SET_DOMAIN, list(
      version = "dsvert-stateless-catalog-synopsis-result-set-v1",
      results = unsigned))
}

.dsvert_dp_synopsis_execution_result_set_v1 <- function(
    first_result, second_result, context, policy,
    .verifier = .dsvert_relay_verify_message) {
  values <- list(first_result, second_result)
  prepare_hashes <- vapply(values, function(value) tryCatch(
    .dsvert_dp_synopsis_hex_v1(
      if (is.list(value)) value$prepare_set_sha256 else NULL,
      "RESULT PREPARE-set hash"), error = function(error) ""),
  character(1L))
  if (length(unique(prepare_hashes)) != 1L || !nzchar(
      prepare_hashes[[1L]])) {
    stop("The synopsis RESULT records do not agree.", call. = FALSE)
  }
  authorities <- .dsvert_dp_synopsis_execution_result_authorities_v1(
    context, policy)
  peers <- vapply(values, function(value) {
    peer <- if (is.list(value) && is.list(value$local_authority)) {
      value$local_authority$peer_name
    } else NULL
    if (!is.character(peer) || length(peer) != 1L || is.na(peer)) ""
    else peer
  }, character(1L))
  if (anyDuplicated(peers) || !setequal(peers, names(authorities))) {
    stop("Invalid synopsis RESULT authority coverage.", call. = FALSE)
  }
  verified <- lapply(seq_along(values), function(index) {
    .dsvert_dp_synopsis_execution_result_validate_v1(
      values[[index]], context, NULL, policy, .verifier,
      expected_authority = authorities[[peers[[index]]]],
      expected_prepare_set_sha256 = prepare_hashes[[1L]])
  })
  names(verified) <- peers
  verified[names(authorities)]
}

.dsvert_dp_synopsis_execution_public_chunk_v1 <- function(
    context, public_chunk_index) {
  geometry <- context$contract$value$geometry
  execution <- context$attempt$value$execution_geometry
  dimension <- geometry$coordinate_count
  public_size <- geometry$public_chunk_coordinates
  public_count <- geometry$public_chunk_count
  execution_size <- execution$chunk_coordinates
  execution_count <- execution$chunk_count
  valid <- .dsvert_dp_synopsis_integer_v1(
      dimension, 1, .DSVERT_DP_MAX_COORDINATES) &&
    .dsvert_dp_synopsis_integer_v1(public_size, 1, 8192) &&
    .dsvert_dp_synopsis_integer_v1(public_count, 1, 1000000) &&
    .dsvert_dp_synopsis_integer_v1(execution_size, 1, 8192) &&
    .dsvert_dp_synopsis_integer_v1(execution_count, 1, 1000000) &&
    identical(as.numeric(public_size),
              as.numeric(min(8192L, dimension))) &&
    identical(as.numeric(public_count),
              as.numeric(ceiling(dimension / public_size))) &&
    identical(as.numeric(execution_count),
              as.numeric(ceiling(dimension / execution_size)))
  if (!isTRUE(valid)) {
    stop("Invalid synopsis public chunk geometry.", call. = FALSE)
  }
  index <- .dsvert_joint_dp_vector_index(
    public_chunk_index, "synopsis public chunk index", 0,
    public_count - 1L)
  offset <- index * public_size
  count <- min(public_size, dimension - offset)
  first <- floor(offset / execution_size)
  last <- floor((offset + count - 1L) / execution_size)
  list(
    index = as.integer(index), offset = as.integer(offset),
    count = as.integer(count),
    first_execution_chunk_index = as.integer(first),
    segment_count = as.integer(last - first + 1L),
    execution_chunk_indices = as.list(as.integer(seq.int(first, last))))
}

.dsvert_dp_synopsis_execution_segment_set_hash_v1 <- function(
    context, result_set_sha256, public_chunk, segments) {
  .dsvert_dp_synopsis_execution_hash_v1(
    .DSVERT_DP_SYNOPSIS_EXECUTION_SEGMENT_SET_DOMAIN, list(
      version = "dsvert-stateless-catalog-synopsis-segment-set-v1",
      artifact_key = context$authorization$artifact_key,
      contract_sha256 = context$contract$sha256,
      attempt_sha256 = context$attempt$sha256,
      result_set_sha256 = result_set_sha256,
      public_chunk_index = public_chunk$index,
      coordinate_offset = public_chunk$offset,
      coordinate_count = public_chunk$count,
      segments = unname(segments)))
}

.dsvert_dp_synopsis_execution_final_share_context_v1 <- function(
    context, result_set_sha256, public_chunk, segment_set_sha256,
    sender, recipient) {
  role_names <- unlist(
    context$contract$value$authority_roles$role_order,
    use.names = FALSE)
  authority_peers <- unlist(
    context$contract$value$authority_peers, use.names = FALSE)
  roles <- as.list(authority_peers)
  names(roles) <- role_names
  value <- list(
    version = .DSVERT_TYPED_BLOB_SYNOPSIS_CONTEXT_VERSION,
    purpose = .DSVERT_TYPED_BLOB_SYNOPSIS_PURPOSE,
    artifact_key = context$authorization$artifact_key,
    execution_id = context$execution_id,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    result_set_sha256 = result_set_sha256, roles = roles,
    sender = sender, recipient = recipient,
    total_coordinate_count = as.character(
      context$contract$value$geometry$coordinate_count),
    public_chunk_index = as.character(public_chunk$index),
    public_chunk_count = as.character(
      context$contract$value$geometry$public_chunk_count),
    coordinate_offset = as.character(public_chunk$offset),
    coordinate_count = as.character(public_chunk$count),
    execution_chunk_coordinates = as.character(
      context$attempt$value$execution_geometry$chunk_coordinates),
    execution_chunk_count = as.character(
      context$attempt$value$execution_geometry$chunk_count),
    first_execution_chunk_index = as.character(
      public_chunk$first_execution_chunk_index),
    segment_count = as.character(public_chunk$segment_count),
    share_format = "ring128-local-chunk-segments-v1",
    segment_set_sha256 = segment_set_sha256,
    ring_bits = "128", frac_bits = "0")
  .dsvert_typed_blob_synopsis_context_v1(value, sender)
}

.dsvert_dp_synopsis_execution_final_share_v1 <- function(
    ss, session_id, first_result, second_result, public_chunk_index,
    .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message, .encryptor = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  if (!is.function(.verifier)) {
    stop("Invalid synopsis FINAL_SHARE verifier.", call. = FALSE)
  }
  context <- .dsvert_dp_synopsis_execution_context_v1(
    ss, session_id, .policy, .secret, .identity, .cache_get)
  if (isTRUE(context$vector$profile$exact_gc)) {
    stop(paste(
      "Synopsis exact-GC FINAL_SHARE requires its dedicated validity and",
      "binding adapter."), call. = FALSE)
  }
  results <- .dsvert_dp_synopsis_execution_result_set_v1(
    first_result, second_result, context, .policy, .verifier)
  result_set_sha256 <-
    .dsvert_dp_synopsis_execution_result_set_hash_v1(results)
  public_chunk <- .dsvert_dp_synopsis_execution_public_chunk_v1(
    context, public_chunk_index)
  sender <- context$authorization$local_authority$peer_name
  recipient <- setdiff(names(results), sender)
  if (length(recipient) != 1L) {
    stop("Invalid synopsis FINAL_SHARE recipient.", call. = FALSE)
  }
  own <- results[[sender]]
  commitments <- unlist(
    own$local_chunk_commitments, use.names = FALSE)
  indices <- unlist(
    public_chunk$execution_chunk_indices, use.names = FALSE)
  descriptors <- lapply(indices, function(index) {
    chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, index)
    list(
      execution_chunk_index = chunk$index,
      coordinate_offset = chunk$offset,
      coordinate_count = chunk$count,
      chunk_commitment_sha256 = commitments[[index + 1L]])
  })
  segment_set_sha256 <-
    .dsvert_dp_synopsis_execution_segment_set_hash_v1(
      context, result_set_sha256, public_chunk, descriptors)
  typed_context <- .dsvert_dp_synopsis_execution_final_share_context_v1(
    context, result_set_sha256, public_chunk, segment_set_sha256,
    sender, recipient)

  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid synopsis FINAL_SHARE session.", call. = FALSE)
  }
  typed <- .dsvert_typed_blob_session_context(ss)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(.policy$peer_pinset)
  expected_peers <- as.list(pins[setdiff(names(pins), sender)])
  transport_pks <- ss$peer_transport_pks %||% list()
  recipient_pk <- transport_pks[[recipient]]
  if (!identical(typed$self_name, sender) ||
      !identical(
        .dsvert_dp_canonical_query_value(typed$peer_identity_pks),
        .dsvert_dp_canonical_query_value(expected_peers)) ||
      is.null(names(transport_pks)) || anyDuplicated(names(transport_pks)) ||
      !setequal(names(transport_pks), names(expected_peers)) ||
      is.null(recipient_pk)) {
    stop("The synopsis FINAL_SHARE recipient is not pinned.",
         call. = FALSE)
  }
  request <- list(
    session_id = session_id,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    result_set_sha256 = result_set_sha256,
    public_chunk_index = public_chunk$index,
    segment_set_sha256 = segment_set_sha256,
    recipient_name = recipient,
    recipient_identity_pk = unname(pins[[recipient]]),
    typed_peer_binding_digest = typed$peer_binding_digest)
  replay <- .dsvert_typed_blob_operation_replay(
    ss, ".dsvert_dp_synopsis_execution_final_share_v1", request)
  if (isTRUE(replay$hit)) return(replay$result)

  durable_result <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) {
      .dsvert_dp_synopsis_execution_result_load_v1(
        connection, .secret, context, NULL, .policy, .verifier,
        expected_prepare_set_sha256 = own$prepare_set_sha256)
    })
  if (is.null(durable_result)) stop(.dsvert_phase_not_ready_condition())
  local_unsigned <- own[setdiff(names(own), "signature")]
  durable_unsigned <- durable_result$receipt[setdiff(
    names(durable_result$receipt), "signature")]
  if (!identical(
      .dsvert_dp_synopsis_execution_record_json_v1(local_unsigned),
      .dsvert_dp_synopsis_execution_record_json_v1(durable_unsigned))) {
    stop("The synopsis FINAL_SHARE is not bound to the durable RESULT.",
         call. = FALSE)
  }
  chunks <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) lapply(indices, function(index) {
      chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, index)
      .dsvert_dp_synopsis_execution_local_load_v1(
        connection, .secret, context, NULL, chunk,
        .policy, .verifier)
    }))
  if (any(vapply(chunks, is.null, logical(1L)))) {
    stop(.dsvert_phase_not_ready_condition())
  }
  segments <- lapply(seq_along(chunks), function(position) {
    value <- chunks[[position]]
    descriptor <- descriptors[[position]]
    if (!identical(
        value$receipt$local_chunk_sha256,
        descriptor$chunk_commitment_sha256)) {
      stop("The durable LOCAL chunk disagrees with RESULT.",
           call. = FALSE)
    }
    c(descriptor[c(
      "execution_chunk_index", "coordinate_offset",
      "coordinate_count")], list(
        noised_share_b64 = value$noised_share_b64,
        noised_share_sha256 = value$noised_share_sha256,
        chunk_commitment_sha256 =
          descriptor$chunk_commitment_sha256))
  })
  covered_offsets <- vapply(segments, `[[`, numeric(1L),
                            "coordinate_offset")
  covered_counts <- vapply(segments, `[[`, numeric(1L),
                           "coordinate_count")
  if (!identical(as.numeric(covered_offsets[[1L]]),
                 as.numeric(public_chunk$offset)) ||
      !identical(as.numeric(sum(covered_counts)),
                 as.numeric(public_chunk$count)) ||
      (length(segments) > 1L && any(
        covered_offsets[-1L] != head(covered_offsets + covered_counts, -1L)))) {
    stop("The synopsis FINAL_SHARE segments do not cover the public chunk.",
         call. = FALSE)
  }
  payload <- list(
    version =
      .DSVERT_DP_SYNOPSIS_EXECUTION_FINAL_SHARE_PAYLOAD_VERSION,
    context = typed_context, segments = segments)
  plaintext <- charToRaw(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(payload)))
  sealed <- if (is.null(.encryptor)) {
    .callMpcTool("transport-encrypt", list(
      data = gsub("[\r\n]", "", jsonlite::base64_enc(plaintext)),
      recipient_pk = recipient_pk))$sealed
  } else {
    if (!is.function(.encryptor)) {
      stop("Invalid synopsis FINAL_SHARE encryptor.", call. = FALSE)
    }
    .encryptor(plaintext, recipient_pk)
  }
  ciphertext <- base64_to_base64url(
    .dsvert_joint_dp_vector_scalar(
      sealed, "encrypted synopsis final share",
      maximum_bytes = 32L * 1024L^2))
  transfer <- .dsvert_typed_blob_mint(
    ss, session_id, .DSVERT_TYPED_BLOB_SYNOPSIS_FINAL_CAPABILITY,
    base64_to_base64url(recipient_pk), ciphertext, typed_context,
    producer = ".dsvert_dp_synopsis_execution_final_share_v1")
  result <- list(
    ciphertext = ciphertext, transfer = transfer,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    result_set_sha256 = result_set_sha256,
    public_chunk_index = public_chunk$index,
    intermediate_payload_exposed = FALSE, capability_available = TRUE)
  .dsvert_typed_blob_operation_commit(
    ss, ".dsvert_dp_synopsis_execution_final_share_v1", request, result)
}

.dsvert_dp_synopsis_execution_public_key_v1 <- function(
    artifact_key, public_chunk_index) {
  paste(artifact_key, "PUBLIC", as.integer(public_chunk_index), sep = "|")
}

.dsvert_dp_synopsis_execution_public_load_v1 <- function(
    connection, secret, context, result_set_sha256, public_chunk) {
  artifact_key <- context$authorization$artifact_key
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT chunk_sha256,record_json,row_mac FROM synopsis_public_chunks",
    "WHERE artifact_key=? AND public_chunk_index=?"), params = list(
      artifact_key, public_chunk$index))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_dp_synopsis_execution_record_decode_v1(
    row, secret, "public_chunks",
    .dsvert_dp_synopsis_execution_public_key_v1(
      artifact_key, public_chunk$index), "PUBLIC chunk record",
    .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_MAX_RECORD_BYTES)
  fields <- c(
    "version", "artifact_key", "execution_id", "contract_sha256",
    "attempt_sha256", "result_set_sha256", "public_chunk_index",
    "coordinate_offset", "coordinate_count", "chunk_sha256",
    "public_chunk")
  public_fields <- c(
    "version", "artifact_key", "execution_id", "contract_sha256",
    "attempt_sha256", "result_set_sha256", "public_chunk_index",
    "public_chunk_count", "coordinate_offset", "coordinate_count",
    "output_lattice_bits", "output_lattice_scale", "scaled_values",
    "value_encoding", "postprocessing", "source_values_exposed",
    "preclamp_values_exposed")
  public <- value$public_chunk
  scaled <- if (is.list(public$scaled_values) &&
      is.null(names(public$scaled_values)) &&
      length(public$scaled_values) == public_chunk$count &&
      all(vapply(public$scaled_values, function(item) {
        is.character(item) && length(item) == 1L && !is.na(item) &&
          grepl("^(0|[1-9][0-9]*)$", item)
      }, logical(1L)))) {
    vapply(public$scaled_values, identity, character(1L))
  } else character()
  expected <- list(
    artifact_key = artifact_key, execution_id = context$execution_id,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    result_set_sha256 = result_set_sha256,
    public_chunk_index = public_chunk$index,
    coordinate_offset = public_chunk$offset,
    coordinate_count = public_chunk$count)
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) &&
    identical(value$version,
              .DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_VERSION) &&
    identical(value[names(expected)], expected) &&
    is.list(public) && !is.null(names(public)) &&
    !anyNA(names(public)) && !anyDuplicated(names(public)) &&
    setequal(names(public), public_fields) &&
    identical(public$version,
              .DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_VERSION) &&
    identical(public[names(expected)], expected) &&
    identical(as.numeric(public$public_chunk_count), as.numeric(
      context$contract$value$geometry$public_chunk_count)) &&
    identical(as.numeric(public$output_lattice_bits), as.numeric(
      context$vector$release_contract$output_lattice_bits)) &&
    identical(as.numeric(public$output_lattice_scale), as.numeric(
      context$vector$release_contract$output_lattice_scale)) &&
    length(scaled) == public_chunk$count &&
    identical(public$value_encoding,
              "nonnegative-decimal-integer-common-lattice-v1") &&
    identical(public$postprocessing,
              context$vector$profile$postprocessing) &&
    identical(public$source_values_exposed, FALSE) &&
    identical(public$preclamp_values_exposed, FALSE)
  positions <- seq.int(
    public_chunk$offset + 1L, public_chunk$offset + public_chunk$count)
  if (isTRUE(valid)) valid <- all(vapply(seq_along(scaled), function(index) {
    upper <- openssl::bignum(
      context$vector$lattice$raw_upper_bounds[[positions[[index]]]]) *
      (openssl::bignum(2) ^ as.integer(
        context$vector$lattice$scale_shifts[[positions[[index]]]]))
    openssl::bignum(scaled[[index]]) <= upper
  }, logical(1L)))
  if (!isTRUE(valid)) {
    stop("The synopsis PUBLIC chunk is inconsistent.", call. = FALSE)
  }
  public$scaled_values <- as.list(scaled)
  expected_hash <- .dsvert_dp_synopsis_execution_hash_v1(
    .DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_DOMAIN, public)
  value$public_chunk <- public
  value$chunk_sha256 <- .dsvert_dp_synopsis_hex_v1(
    value$chunk_sha256, "PUBLIC chunk hash")
  if (!identical(value$chunk_sha256, row$chunk_sha256[[1L]]) ||
      !identical(value$chunk_sha256, expected_hash)) {
    stop("The synopsis PUBLIC chunk failed authentication.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_execution_public_put_v1 <- function(
    connection, secret, candidate, context, result_set_sha256,
    public_chunk) {
  existing <- .dsvert_dp_synopsis_execution_public_load_v1(
    connection, secret, context, result_set_sha256, public_chunk)
  if (!is.null(existing)) {
    if (!identical(
        .dsvert_dp_synopsis_execution_record_json_v1(existing),
        .dsvert_dp_synopsis_execution_record_json_v1(candidate))) {
      stop("Conflicting durable synopsis PUBLIC chunk.", call. = FALSE)
    }
    return(existing)
  }
  json <- .dsvert_dp_synopsis_execution_record_json_v1(candidate)
  key <- .dsvert_dp_synopsis_execution_public_key_v1(
    candidate$artifact_key, candidate$public_chunk_index)
  mac <- .dsvert_dp_synopsis_execution_store_mac_v1(
    secret, "public_chunks", key, json)
  DBI::dbExecute(connection, paste(
    "INSERT INTO synopsis_public_chunks(",
    "artifact_key,public_chunk_index,chunk_sha256,record_json,row_mac)",
    "VALUES(?,?,?,?,?)"), params = list(
      candidate$artifact_key, as.integer(candidate$public_chunk_index),
      candidate$chunk_sha256, json, mac))
  candidate
}

.dsvert_dp_synopsis_execution_release_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_execution_release_validate_v1 <- function(
    receipt, context, result_set_sha256, policy,
    .verifier = .dsvert_relay_verify_message,
    expected_authority = NULL) {
  fields <- c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "result_set_sha256", "local_authority", "public_chunk_count",
    "final_chunk_hashes", "final_vector_root", "output_lattice_bits",
    "output_lattice_scale", "mechanism", "epsilon", "delta",
    "implementation_delta_numerator",
    "implementation_delta_denominator", "delta_aggregation",
    "postprocessing", "all_public_chunks_durable",
    "intermediate_payload_exposed", "durable_replay",
    "capability_available", "signature")
  authorities <- .dsvert_dp_synopsis_execution_result_authorities_v1(
    context, policy)
  authority <- expected_authority %||%
    context$authorization$local_authority
  peer <- if (is.list(authority)) authority$peer_name else NULL
  hashes_value <- receipt$final_chunk_hashes
  canonical_hashes <- is.list(hashes_value) &&
    is.null(names(hashes_value)) && length(hashes_value) ==
      context$contract$value$geometry$public_chunk_count &&
    all(vapply(hashes_value, function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^[0-9a-f]{64}$", value)
    }, logical(1L)))
  hashes <- if (canonical_hashes) {
    vapply(hashes_value, identity, character(1L))
  } else character()
  delta <- .dsvert_joint_dp_vector_implementation_delta(context$vector)
  expected_scale <- as.character(openssl::bignum(2) ^ as.integer(
    context$vector$release_contract$output_lattice_bits))
  expected <- list(
    execution_id = context$execution_id,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256,
    result_set_sha256 = result_set_sha256)
  valid <- is.function(.verifier) && is.list(receipt) &&
    !is.null(names(receipt)) && !anyNA(names(receipt)) &&
    !anyDuplicated(names(receipt)) && setequal(names(receipt), fields) &&
    identical(receipt$version,
              .DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_VERSION) &&
    identical(receipt$phase, "synopsis_released") &&
    identical(receipt[names(expected)], expected) &&
    is.character(peer) && length(peer) == 1L && !is.na(peer) &&
    !is.null(authorities[[peer]]) && identical(
      .dsvert_dp_canonical_query_value(authority),
      .dsvert_dp_canonical_query_value(authorities[[peer]])) &&
    identical(
      .dsvert_dp_canonical_query_value(receipt$local_authority),
      .dsvert_dp_canonical_query_value(authority)) &&
    identical(as.numeric(receipt$public_chunk_count), as.numeric(
      context$contract$value$geometry$public_chunk_count)) &&
    canonical_hashes && identical(
      receipt$final_vector_root,
      .dsvert_joint_dp_vector_merkle_root(hashes)) &&
    identical(as.numeric(receipt$output_lattice_bits), as.numeric(
      context$vector$release_contract$output_lattice_bits)) &&
    identical(receipt$output_lattice_scale, expected_scale) &&
    identical(receipt$mechanism,
              context$vector$profile$release_mechanism) &&
    identical(receipt$epsilon,
              context$vector$release_contract$epsilon) &&
    identical(receipt$delta,
              context$vector$release_contract$allocated_delta) &&
    identical(receipt$implementation_delta_numerator, delta[[1L]]) &&
    identical(receipt$implementation_delta_denominator, delta[[2L]]) &&
    identical(receipt$delta_aggregation,
              context$vector$profile$delta_aggregation) &&
    identical(receipt$postprocessing,
              context$vector$profile$postprocessing) &&
    identical(receipt$all_public_chunks_durable, TRUE) &&
    identical(receipt$intermediate_payload_exposed, FALSE) &&
    identical(receipt$durable_replay, TRUE) &&
    identical(receipt$capability_available, TRUE)
  if (!isTRUE(valid)) {
    stop("Invalid durable synopsis RELEASE receipt.", call. = FALSE)
  }
  receipt$final_chunk_hashes <- as.list(hashes)
  receipt$final_vector_root <- .dsvert_dp_synopsis_hex_v1(
    receipt$final_vector_root, "RELEASE root")
  receipt$local_authority <- authority
  signature <- .dsvert_dp_synopsis_signature_v1(receipt$signature)
  unsigned <- receipt[setdiff(fields, "signature")]
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  if (!identical(authority$identity_pk, unname(pins[[peer]])) ||
      !isTRUE(tryCatch(.verifier(
        .dsvert_dp_synopsis_execution_release_message_v1(unsigned),
        authority$identity_pk, signature),
      error = function(error) FALSE))) {
    stop("Synopsis RELEASE receipt signature verification failed.",
         call. = FALSE)
  }
  c(unsigned, list(signature = signature))
}

.dsvert_dp_synopsis_execution_release_load_v1 <- function(
    connection, secret, context, result_set_sha256, policy, .verifier) {
  artifact_key <- context$authorization$artifact_key
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT receipt_sha256,result_set_sha256,final_vector_root,",
    "record_json,row_mac FROM synopsis_releases WHERE artifact_key=?"),
  params = list(artifact_key))
  if (!nrow(row)) return(NULL)
  value <- .dsvert_dp_synopsis_execution_record_decode_v1(
    row, secret, "releases", artifact_key, "RELEASE record",
    .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_MAX_RECORD_BYTES)
  fields <- c(
    "version", "artifact_key", "execution_id", "contract_sha256",
    "attempt_sha256", "result_set_sha256", "receipt_sha256", "receipt")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) && identical(
      value$version, .DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_RECORD_VERSION) &&
    identical(value$artifact_key, artifact_key) &&
    identical(value$execution_id, context$execution_id) &&
    identical(value$contract_sha256, context$contract$sha256) &&
    identical(value$attempt_sha256, context$attempt$sha256) &&
    identical(value$result_set_sha256, result_set_sha256) &&
    identical(row$result_set_sha256[[1L]], result_set_sha256)
  if (!isTRUE(valid)) {
    stop("The synopsis RELEASE record is inconsistent.", call. = FALSE)
  }
  value$receipt <- .dsvert_dp_synopsis_execution_release_validate_v1(
    value$receipt, context, result_set_sha256, policy, .verifier)
  value$receipt_sha256 <- .dsvert_dp_synopsis_hex_v1(
    value$receipt_sha256, "RELEASE receipt hash")
  if (!identical(value$receipt_sha256, row$receipt_sha256[[1L]]) ||
      !identical(value$receipt$final_vector_root,
                 row$final_vector_root[[1L]]) ||
      !identical(value$receipt_sha256,
                 .dsvert_joint_dp_hash(value$receipt))) {
    stop("The synopsis RELEASE record failed authentication.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_execution_release_put_v1 <- function(
    connection, secret, candidate, context, result_set_sha256,
    policy, .verifier) {
  existing <- .dsvert_dp_synopsis_execution_release_load_v1(
    connection, secret, context, result_set_sha256, policy, .verifier)
  if (!is.null(existing)) {
    left <- existing; right <- candidate
    left$receipt_sha256 <- NULL; right$receipt_sha256 <- NULL
    left$receipt$signature <- NULL; right$receipt$signature <- NULL
    if (!identical(
        .dsvert_dp_synopsis_execution_record_json_v1(left),
        .dsvert_dp_synopsis_execution_record_json_v1(right))) {
      stop("Conflicting durable synopsis RELEASE.", call. = FALSE)
    }
    return(existing)
  }
  json <- .dsvert_dp_synopsis_execution_record_json_v1(candidate)
  artifact_key <- candidate$artifact_key
  mac <- .dsvert_dp_synopsis_execution_store_mac_v1(
    secret, "releases", artifact_key, json)
  DBI::dbExecute(connection, paste(
    "INSERT INTO synopsis_releases(",
    "artifact_key,receipt_sha256,result_set_sha256,final_vector_root,",
    "record_json,row_mac) VALUES(?,?,?,?,?,?)"), params = list(
      artifact_key, candidate$receipt_sha256,
      candidate$result_set_sha256,
      candidate$receipt$final_vector_root, json, mac))
  candidate
}

.dsvert_dp_synopsis_execution_default_peer_reader_v1 <- function(
    session, typed_context, sender, public_chunk, expected_segments) {
  encrypted <- .dsvert_typed_blob_consume(
    session, .DSVERT_TYPED_BLOB_SYNOPSIS_FINAL_CAPABILITY,
    typed_context, sender_name = sender, required = FALSE,
    consume = FALSE)
  if (is.null(encrypted)) stop(.dsvert_phase_not_ready_condition())
  opened <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(encrypted),
    recipient_sk = .key_get("transport_sk", session)))
  plaintext <- tryCatch(
    jsonlite::base64_dec(opened$data), error = function(error) NULL)
  maximum <- 32L * public_chunk$count + 256L * 1024L
  payload <- if (is.raw(plaintext)) {
    .dsvert_dp_synopsis_execution_json_v1(
      rawToChar(plaintext), "FINAL_SHARE payload", maximum)
  } else NULL
  if (!is.list(payload) || is.null(names(payload)) ||
      anyNA(names(payload)) || anyDuplicated(names(payload)) ||
      !setequal(names(payload), c("version", "context", "segments")) ||
      !identical(payload$version,
                 .DSVERT_DP_SYNOPSIS_EXECUTION_FINAL_SHARE_PAYLOAD_VERSION) ||
      !identical(
        .dsvert_dp_canonical_query_value(payload$context),
        .dsvert_dp_canonical_query_value(typed_context)) ||
      !is.list(payload$segments) || !is.null(names(payload$segments)) ||
      length(payload$segments) != length(expected_segments)) {
    stop("Invalid synopsis FINAL_SHARE payload.", call. = FALSE)
  }
  bytes <- lapply(seq_along(expected_segments), function(index) {
    segment <- payload$segments[[index]]
    expected <- expected_segments[[index]]
    fields <- c(
      "execution_chunk_index", "coordinate_offset", "coordinate_count",
      "noised_share_b64", "noised_share_sha256",
      "chunk_commitment_sha256")
    if (!is.list(segment) || is.null(names(segment)) ||
        anyNA(names(segment)) || anyDuplicated(names(segment)) ||
        !setequal(names(segment), fields) || !identical(
          segment[names(expected)], expected)) {
      stop("Invalid synopsis FINAL_SHARE segment.", call. = FALSE)
    }
    raw <- .dsvert_joint_dp_vector_standard_b64(
      segment$noised_share_b64, "synopsis peer noised share",
      segment$coordinate_count * 16L)
    if (!.dsvert_joint_dp_dsi_hex_equal(
        segment$noised_share_sha256,
        digest::digest(raw, algo = "sha256", serialize = FALSE))) {
      stop("The synopsis peer share failed authentication.",
           call. = FALSE)
    }
    raw
  })
  list(
    share_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(do.call(c, bytes))),
    encrypted = encrypted)
}

.dsvert_dp_synopsis_execution_release_v1 <- function(
    ss, session_id, first_result, second_result,
    .policy = NULL, .secret = NULL, .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message, .signer = NULL,
    .peer_share_reader = NULL, .finalizer = NULL, .session = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  if (!is.function(.verifier)) {
    stop("Invalid synopsis RELEASE verifier.", call. = FALSE)
  }
  context <- .dsvert_dp_synopsis_execution_context_v1(
    ss, session_id, .policy, .secret, .identity, .cache_get)
  if (isTRUE(context$vector$profile$exact_gc)) {
    stop(paste(
      "Synopsis exact-GC RELEASE requires its dedicated validity and",
      "binding adapter."), call. = FALSE)
  }
  results <- .dsvert_dp_synopsis_execution_result_set_v1(
    first_result, second_result, context, .policy, .verifier)
  result_set_sha256 <-
    .dsvert_dp_synopsis_execution_result_set_hash_v1(results)
  existing <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) {
      .dsvert_dp_synopsis_execution_release_load_v1(
        connection, .secret, context, result_set_sha256,
        .policy, .verifier)
    })
  if (!is.null(existing)) return(existing$receipt)

  local_peer <- context$authorization$local_authority$peer_name
  peer <- setdiff(names(results), local_peer)
  if (length(peer) != 1L) {
    stop("Invalid synopsis RELEASE peer authority.", call. = FALSE)
  }
  own_result <- results[[local_peer]]
  peer_result <- results[[peer]]
  durable <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) list(
      claim = .dsvert_dp_synopsis_execution_artifact_load_v1(
        connection, .secret, context$authorization$artifact_key),
      result = .dsvert_dp_synopsis_execution_result_load_v1(
        connection, .secret, context, NULL, .policy, .verifier,
        expected_prepare_set_sha256 = own_result$prepare_set_sha256)))
  if (is.null(durable$claim) || is.null(durable$result)) {
    stop(.dsvert_phase_not_ready_condition())
  }
  own_unsigned <- own_result[setdiff(names(own_result), "signature")]
  stored_unsigned <- durable$result$receipt[setdiff(
    names(durable$result$receipt), "signature")]
  expected_execution_count <-
    context$attempt$value$execution_geometry$chunk_count
  expected_public_count <-
    context$contract$value$geometry$public_chunk_count
  if (!identical(
      .dsvert_dp_synopsis_execution_record_json_v1(own_unsigned),
      .dsvert_dp_synopsis_execution_record_json_v1(stored_unsigned)) ||
      !identical(durable$claim$sticky_core_sha256,
                 context$contract$sha256) ||
      !identical(durable$claim$run_binding_sha256,
                 context$attempt$sha256) ||
      !identical(as.numeric(durable$claim$execution_chunk_count),
                 as.numeric(expected_execution_count)) ||
      !identical(as.numeric(durable$claim$public_chunk_count),
                 as.numeric(expected_public_count))) {
    stop("The synopsis RELEASE conflicts with durable execution state.",
         call. = FALSE)
  }
  if (!identical(
      as.numeric(context$attempt$value$execution_geometry$chunk_coordinates),
      as.numeric(context$contract$value$geometry$public_chunk_coordinates)) ||
      !identical(as.numeric(expected_execution_count),
                 as.numeric(expected_public_count))) {
    stop("Non-exact synopsis RELEASE requires canonical public chunks.",
         call. = FALSE)
  }

  default_reader <- is.null(.peer_share_reader)
  if (default_reader) {
    .peer_share_reader <-
      .dsvert_dp_synopsis_execution_default_peer_reader_v1
    if (is.null(.session)) .session <- .S(session_id)
  }
  if (!is.function(.peer_share_reader) ||
      !is.environment(.session)) {
    stop("Invalid synopsis RELEASE peer-share reader.", call. = FALSE)
  }
  if (is.null(.finalizer)) .finalizer <- function(input) {
    .callMpcTool(context$vector$profile$finalizer_command, input)
  }
  if (!is.function(.finalizer)) {
    stop("Invalid synopsis RELEASE finalizer.", call. = FALSE)
  }
  own_commitments <- unlist(
    own_result$local_chunk_commitments, use.names = FALSE)
  peer_commitments <- unlist(
    peer_result$local_chunk_commitments, use.names = FALSE)
  authority_peers <- unlist(
    context$contract$value$authority_peers, use.names = FALSE)

  for (index in seq.int(0L, expected_public_count - 1L)) {
    public_chunk <- .dsvert_dp_synopsis_execution_public_chunk_v1(
      context, index)
    present <- .dsvert_dp_synopsis_execution_with_store_v1(
      .policy, .secret, function(connection) {
        .dsvert_dp_synopsis_execution_public_load_v1(
          connection, .secret, context, result_set_sha256, public_chunk)
      })
    execution_index <- public_chunk$first_execution_chunk_index
    own_descriptor <- list(
      execution_chunk_index = execution_index,
      coordinate_offset = public_chunk$offset,
      coordinate_count = public_chunk$count,
      chunk_commitment_sha256 =
        own_commitments[[execution_index + 1L]])
    peer_descriptor <- list(
      execution_chunk_index = execution_index,
      coordinate_offset = public_chunk$offset,
      coordinate_count = public_chunk$count,
      chunk_commitment_sha256 =
        peer_commitments[[execution_index + 1L]])
    peer_segment_set_sha256 <-
      .dsvert_dp_synopsis_execution_segment_set_hash_v1(
        context, result_set_sha256, public_chunk, list(peer_descriptor))
    typed_context <-
      .dsvert_dp_synopsis_execution_final_share_context_v1(
        context, result_set_sha256, public_chunk,
        peer_segment_set_sha256, peer, local_peer)
    if (!is.null(present)) {
      if (default_reader) .dsvert_typed_blob_consume(
        .session, .DSVERT_TYPED_BLOB_SYNOPSIS_FINAL_CAPABILITY,
        typed_context, sender_name = peer, required = FALSE,
        consume = TRUE)
      next
    }

    execution_chunk <- .dsvert_dp_synopsis_execution_chunk_v1(
      context, execution_index)
    own <- .dsvert_dp_synopsis_execution_with_store_v1(
      .policy, .secret, function(connection) {
        .dsvert_dp_synopsis_execution_local_load_v1(
          connection, .secret, context, NULL, execution_chunk,
          .policy, .verifier)
      })
    if (is.null(own) || !identical(
        own$receipt$local_chunk_sha256,
        own_descriptor$chunk_commitment_sha256)) {
      stop(.dsvert_phase_not_ready_condition())
    }
    peer_share <- .peer_share_reader(
      .session, typed_context, peer, public_chunk,
      list(peer_descriptor))
    if (!is.list(peer_share) || !is.character(peer_share$share_b64) ||
        length(peer_share$share_b64) != 1L ||
        is.na(peer_share$share_b64)) {
      stop("Invalid synopsis RELEASE peer share.", call. = FALSE)
    }
    peer_raw <- .dsvert_joint_dp_vector_standard_b64(
      peer_share$share_b64, "synopsis peer noised share",
      public_chunk$count * 16L)
    if (!.dsvert_joint_dp_dsi_hex_equal(
        digest::digest(peer_raw, algo = "sha256", serialize = FALSE),
        peer_descriptor$chunk_commitment_sha256)) {
      stop("The synopsis peer share disagrees with signed RESULT.",
           call. = FALSE)
    }
    positions <- seq.int(
      public_chunk$offset + 1L,
      public_chunk$offset + public_chunk$count)
    release <- context$vector$release_contract
    input <- c(list(
      version = context$vector$profile$finalizer_input_version,
      ring_bits = 128L, frac_bits = 0L,
      total_coordinate_count = release$coordinate_count,
      chunk_start = public_chunk$offset,
      coordinate_count = public_chunk$count,
      output_lattice_bits = release$output_lattice_bits,
      epsilon = release$epsilon,
      allocated_delta = release$allocated_delta),
    if (isTRUE(context$vector$profile$gaussian)) {
      list(l2_sensitivity_steps = release$sensitivity_steps)
    } else list(sensitivity_steps = release$sensitivity_steps), list(
      scale_shifts = as.list(
        context$vector$lattice$scale_shifts[positions]),
      raw_upper_bounds = as.list(
        context$vector$lattice$raw_upper_bounds[positions]),
      release_contract_hash = context$contract$sha256,
      transcript_hash = context$contract$sha256,
      left_noised_share = if (identical(
        local_peer, authority_peers[[1L]])) {
        own$noised_share_b64
      } else peer_share$share_b64,
      right_noised_share = if (identical(
        local_peer, authority_peers[[1L]])) {
        peer_share$share_b64
      } else own$noised_share_b64))
    output <- .finalizer(input)
    input$left_noised_share <- NULL
    input$right_noised_share <- NULL
    if (is.list(output) && is.list(output$plan)) {
      output$plan <- .dsvert_dp_analysis_canonical_value_v1(output$plan)
    }
    if (!is.list(output) || is.null(names(output)) ||
        anyNA(names(output)) || anyDuplicated(names(output))) {
      stop("The synopsis finalizer returned an invalid certificate.",
           call. = FALSE)
    }
    values <- .dsvert_joint_dp_vector_finalizer_validate(
      output, context$vector, public_chunk,
      context$vector$lattice$raw_upper_bounds[positions],
      context$vector$lattice$scale_shifts[positions])
    public <- list(
      version = .DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_VERSION,
      artifact_key = context$authorization$artifact_key,
      execution_id = context$execution_id,
      contract_sha256 = context$contract$sha256,
      attempt_sha256 = context$attempt$sha256,
      result_set_sha256 = result_set_sha256,
      public_chunk_index = public_chunk$index,
      public_chunk_count = as.integer(expected_public_count),
      coordinate_offset = public_chunk$offset,
      coordinate_count = public_chunk$count,
      output_lattice_bits = release$output_lattice_bits,
      output_lattice_scale = release$output_lattice_scale,
      scaled_values = values,
      value_encoding =
        "nonnegative-decimal-integer-common-lattice-v1",
      postprocessing = context$vector$profile$postprocessing,
      source_values_exposed = FALSE,
      preclamp_values_exposed = FALSE)
    chunk_sha256 <- .dsvert_dp_synopsis_execution_hash_v1(
      .DSVERT_DP_SYNOPSIS_EXECUTION_PUBLIC_DOMAIN, public)
    record <- c(public[c(
      "version", "artifact_key", "execution_id", "contract_sha256",
      "attempt_sha256", "result_set_sha256", "public_chunk_index",
      "coordinate_offset", "coordinate_count")], list(
        chunk_sha256 = chunk_sha256, public_chunk = public))
    .dsvert_dp_synopsis_execution_with_store_v1(
      .policy, .secret, function(connection) {
        .dsvert_dp_synopsis_execution_transaction_v1(connection, {
          claim <- .dsvert_dp_synopsis_execution_artifact_load_v1(
            connection, .secret, context$authorization$artifact_key)
          local <- .dsvert_dp_synopsis_execution_local_load_v1(
            connection, .secret, context, NULL, execution_chunk,
            .policy, .verifier)
          if (is.null(claim) || is.null(local) ||
              !identical(claim$sticky_core_sha256,
                         context$contract$sha256) ||
              !identical(claim$run_binding_sha256,
                         context$attempt$sha256) ||
              !identical(local$receipt$local_chunk_sha256,
                         own_descriptor$chunk_commitment_sha256)) {
            stop("The synopsis RELEASE state changed before persistence.",
                 call. = FALSE)
          }
          .dsvert_dp_synopsis_execution_public_put_v1(
            connection, .secret, record, context,
            result_set_sha256, public_chunk)
        })
      })
    if (default_reader) {
      consumed <- .dsvert_typed_blob_consume(
        .session, .DSVERT_TYPED_BLOB_SYNOPSIS_FINAL_CAPABILITY,
        typed_context, sender_name = peer, required = FALSE,
        consume = TRUE)
      if (!is.null(consumed) && !is.null(peer_share$encrypted) &&
          !identical(consumed, peer_share$encrypted)) {
        stop("The synopsis ciphertext changed before consumption.",
             call. = FALSE)
      }
    }
  }

  final <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) lapply(
      seq.int(0L, expected_public_count - 1L), function(index) {
        chunk <- .dsvert_dp_synopsis_execution_public_chunk_v1(
          context, index)
        .dsvert_dp_synopsis_execution_public_load_v1(
          connection, .secret, context, result_set_sha256, chunk)
      }))
  if (any(vapply(final, is.null, logical(1L)))) {
    stop(.dsvert_phase_not_ready_condition())
  }
  hashes <- vapply(final, `[[`, character(1L), "chunk_sha256")
  root <- .dsvert_joint_dp_vector_merkle_root(hashes)
  if (is.null(.signer)) .signer <- .dsvert_relay_sign_message
  if (!is.list(.identity) || is.null(.identity$identity_sk) ||
      !is.function(.signer)) {
    stop("Invalid synopsis RELEASE signer.", call. = FALSE)
  }
  delta <- .dsvert_joint_dp_vector_implementation_delta(context$vector)
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_VERSION,
    phase = "synopsis_released", execution_id = context$execution_id,
    artifact_key = context$authorization$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256,
    result_set_sha256 = result_set_sha256,
    local_authority = context$authorization$local_authority,
    public_chunk_count = as.integer(expected_public_count),
    final_chunk_hashes = as.list(hashes), final_vector_root = root,
    output_lattice_bits =
      as.integer(context$vector$release_contract$output_lattice_bits),
    output_lattice_scale = as.character(openssl::bignum(2) ^ as.integer(
      context$vector$release_contract$output_lattice_bits)),
    mechanism = context$vector$profile$release_mechanism,
    epsilon = context$vector$release_contract$epsilon,
    delta = context$vector$release_contract$allocated_delta,
    implementation_delta_numerator = delta[[1L]],
    implementation_delta_denominator = delta[[2L]],
    delta_aggregation = context$vector$profile$delta_aggregation,
    postprocessing = context$vector$profile$postprocessing,
    all_public_chunks_durable = TRUE,
    intermediate_payload_exposed = FALSE, durable_replay = TRUE,
    capability_available = TRUE)
  receipt <- c(unsigned, list(signature =
    .dsvert_dp_synopsis_signature_v1(.signer(
      .dsvert_dp_synopsis_execution_release_message_v1(unsigned),
      .identity$identity_sk))))
  receipt <- .dsvert_dp_synopsis_execution_release_validate_v1(
    receipt, context, result_set_sha256, .policy, .verifier)
  candidate <- list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_RELEASE_RECORD_VERSION,
    artifact_key = context$authorization$artifact_key,
    execution_id = context$execution_id,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    result_set_sha256 = result_set_sha256,
    receipt_sha256 = .dsvert_joint_dp_hash(receipt), receipt = receipt)
  persisted <- .dsvert_dp_synopsis_execution_with_store_v1(
    .policy, .secret, function(connection) {
      .dsvert_dp_synopsis_execution_transaction_v1(connection, {
        observed <- lapply(
          seq.int(0L, expected_public_count - 1L), function(index) {
            chunk <- .dsvert_dp_synopsis_execution_public_chunk_v1(
              context, index)
            .dsvert_dp_synopsis_execution_public_load_v1(
              connection, .secret, context, result_set_sha256, chunk)
          })
        observed_hashes <- vapply(
          observed, `[[`, character(1L), "chunk_sha256")
        if (!identical(observed_hashes, hashes)) {
          stop("The synopsis PUBLIC set changed before RELEASE.",
               call. = FALSE)
        }
        .dsvert_dp_synopsis_execution_release_put_v1(
          connection, .secret, candidate, context,
          result_set_sha256, .policy, .verifier)
      })
    })
  persisted$receipt
}
