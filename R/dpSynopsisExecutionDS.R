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
  "dsvert-stateless-catalog-synopsis-execution-store-v1"
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
    identical(receipt$seed_commitment, prepare$seed_commitment) &&
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

.dsvert_dp_synopsis_execution_result_validate_v1 <- function(
    receipt, context, prepares, policy,
    .verifier = .dsvert_relay_verify_message) {
  fields <- c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "prepare_set_sha256", "local_authority", "execution_chunk_count",
    "public_chunk_count", "local_chunk_commitments",
    "local_chunk_set_root", "local_chunk_set_sha256",
    "all_chunks_durable", "intermediate_payload_exposed", "signature")
  authority <- context$authorization$local_authority
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
    identical(receipt$prepare_set_sha256,
              .dsvert_dp_synopsis_execution_prepare_set_hash_v1(prepares)) &&
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
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  identity_pk <- authority$identity_pk
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
    connection, secret, context, prepares, policy, .verifier) {
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
    value$receipt, context, prepares, policy, .verifier)
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
