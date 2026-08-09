# Internal, non-promoted registry for operation-independent DP capsules.
#
# A capsule is charged once when its immutable snapshot/workload identity is
# first registered. Reusing the authenticated capsule record is pure
# post-processing: it performs no ledger access and changes no state.

.DSVERT_CAPSULE_REGISTRY_VERSION <- "dsvert-dp-capsule-registry-v3"
.DSVERT_CAPSULE_IDENTITY_VERSION <- "dsvert-joint-dp-capsule-identity-v3"
.DSVERT_CAPSULE_RECORD_VERSION <- "dsvert-dp-capsule-record-v3"
.DSVERT_CAPSULE_REGISTRY_ALLOCATOR_STATE_VERSION <-
  "dsvert-capsule-registry-allocator-state-v2"
.DSVERT_CAPSULE_REGISTRY_FAST_STATE_VERSION <-
  "dsvert-capsule-registry-fast-state-v3"
.DSVERT_CAPSULE_REGISTRY_PRIVACY_EPOCH_SCOPE <-
  "per_peer_signed_receipts_v1"

.dsvert_capsule_registry_hash <- function(value) {
  value <- .dsvert_dp_canonical_query_value(value)
  digest::digest(
    .dsvert_dp_canonical_json(value), algo = "sha256", serialize = FALSE)
}

.dsvert_capsule_registry_decimal <- function(
    value, what, minimum = 0, open_minimum = FALSE, maximum = Inf) {
  valid <- is.numeric(value) && length(value) == 1L && !is.na(value) &&
    is.finite(value) && value <= maximum &&
    if (isTRUE(open_minimum)) value > minimum else value >= minimum
  if (!isTRUE(valid)) {
    stop("Invalid capsule-registry ", what, ".", call. = FALSE)
  }
  formatted <- format(
    as.numeric(value), digits = 17L, scientific = TRUE, trim = TRUE)
  out_dec <- getOption("OutDec", ".")
  if (!identical(out_dec, ".")) {
    formatted <- sub(out_dec, ".", formatted, fixed = TRUE)
  }
  formatted
}

.dsvert_capsule_registry_hex <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") != 64L ||
      !grepl("^[0-9a-f]+$", value, perl = TRUE)) {
    stop("Invalid capsule-registry ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_capsule_registry_id <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") > 192L ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]*$", value, perl = TRUE)) {
    stop("Invalid capsule-registry ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_capsule_registry_config <- function(
    registry_path, consortium_id, policy_contract,
    peer_pinset_sha256, capsule_epsilon, capsule_delta,
    lifetime_max_distinct_capsules,
    require_private = TRUE, lock_timeout_ms = 30000L) {
  if (!is.character(registry_path) || length(registry_path) != 1L ||
      is.na(registry_path) || !nzchar(registry_path)) {
    stop("Invalid capsule-registry path.", call. = FALSE)
  }
  registry_path <- path.expand(registry_path)
  absolute <- grepl("^/", registry_path) ||
    grepl("^[A-Za-z]:[/\\\\]", registry_path)
  if (!isTRUE(absolute) || !dir.exists(dirname(registry_path)) ||
      !nzchar(basename(registry_path)) || basename(registry_path) %in% c(".", "..")) {
    stop("The capsule-registry path must be an absolute file in an existing directory.",
         call. = FALSE)
  }
  registry_path <- file.path(
    normalizePath(dirname(registry_path), mustWork = TRUE),
    basename(registry_path))
  consortium_id <- .dsvert_capsule_registry_id(
    consortium_id, "consortium id")
  peer_pinset_sha256 <- .dsvert_capsule_registry_hex(
    peer_pinset_sha256, "peer-pinset hash")
  epsilon_text <- .dsvert_capsule_registry_decimal(
    capsule_epsilon, "capsule epsilon", open_minimum = TRUE,
    maximum = 2^40)
  delta_text <- .dsvert_capsule_registry_decimal(
    capsule_delta, "capsule delta", maximum = 1 - .Machine$double.eps)
  lifetime_max_distinct_capsules <-
    .dsvert_joint_dp_release_ledger_count(
      lifetime_max_distinct_capsules,
      "lifetime maximum distinct capsules")
  if (lifetime_max_distinct_capsules < 1) {
    stop("Invalid capsule-registry lifetime maximum distinct capsules.",
         call. = FALSE)
  }
  lifetime_epsilon <- .dsvert_joint_dp_release_ledger_exact_total(
    epsilon_text, lifetime_max_distinct_capsules, "lifetime epsilon")
  lifetime_delta <- .dsvert_joint_dp_release_ledger_exact_total(
    delta_text, lifetime_max_distinct_capsules, "lifetime delta")
  if (.dsvert_joint_dp_release_ledger_exact_compare(
        lifetime_epsilon, "8", "lifetime epsilon") > 0L ||
      .dsvert_joint_dp_release_ledger_exact_compare(
        lifetime_delta, "1", "lifetime delta") >= 0L) {
    stop("The capsule-registry lifetime privacy bound is invalid.",
         call. = FALSE)
  }
  timeout_text <- .dsvert_capsule_registry_decimal(
    lock_timeout_ms, "lock timeout", minimum = 1, maximum = 2^31 - 1)
  if (as.numeric(timeout_text) != floor(as.numeric(timeout_text)) ||
      !is.logical(require_private) || length(require_private) != 1L ||
      is.na(require_private)) {
    stop("Invalid capsule-registry operational configuration.", call. = FALSE)
  }
  policy_contract <- tryCatch(
    .dsvert_dp_canonical_query_value(policy_contract),
    error = function(e) NULL)
  policy_epsilon <- if (is.list(policy_contract)) {
    policy_contract$epsilon_capsule
  } else NULL
  policy_delta <- if (is.list(policy_contract)) {
    policy_contract$delta_capsule
  } else NULL
  if (!is.list(policy_contract) || is.null(names(policy_contract)) ||
      !all(c(
        "epsilon_capsule", "delta_capsule", "peer_pinset_sha256",
        "lifetime_max_distinct_capsules",
        "lifetime_epsilon_upper_bound",
        "lifetime_delta_upper_bound") %in%
           names(policy_contract)) ||
      !is.numeric(policy_epsilon) || length(policy_epsilon) != 1L ||
      !is.numeric(policy_delta) || length(policy_delta) != 1L ||
      !identical(as.numeric(policy_epsilon),
                 as.numeric(capsule_epsilon)) ||
      !identical(as.numeric(policy_delta),
                 as.numeric(capsule_delta)) ||
      !identical(
        as.numeric(policy_contract$lifetime_max_distinct_capsules),
        as.numeric(lifetime_max_distinct_capsules)) ||
      !identical(policy_contract$lifetime_epsilon_upper_bound,
                 lifetime_epsilon) ||
      !identical(policy_contract$lifetime_delta_upper_bound,
                 lifetime_delta) ||
      !identical(policy_contract$peer_pinset_sha256, peer_pinset_sha256)) {
    stop("The capsule-registry policy contract does not bind its lifetime privacy policy and pinset.",
         call. = FALSE)
  }
  policy_contract_hash <- .dsvert_capsule_registry_hash(policy_contract)
  identity <- .dsvert_dp_canonical_query_value(list(
    protocol = .DSVERT_CAPSULE_REGISTRY_VERSION,
    consortium_id = consortium_id,
    policy_contract_hash = policy_contract_hash,
    peer_pinset_sha256 = peer_pinset_sha256,
    capsule_epsilon = as.numeric(capsule_epsilon),
    capsule_delta = as.numeric(capsule_delta),
    lifetime_max_distinct_capsules =
      as.numeric(lifetime_max_distinct_capsules),
    lifetime_epsilon_upper_bound = lifetime_epsilon,
    lifetime_delta_upper_bound = lifetime_delta,
    privacy_epoch_scope =
      .DSVERT_CAPSULE_REGISTRY_PRIVACY_EPOCH_SCOPE))
  list(
    version = .DSVERT_CAPSULE_REGISTRY_VERSION,
    registry_id = .dsvert_capsule_registry_hash(identity),
    registry_path = registry_path,
    consortium_id = consortium_id,
    policy_contract = policy_contract,
    policy_contract_hash = policy_contract_hash,
    peer_pinset_sha256 = peer_pinset_sha256,
    capsule_epsilon = as.numeric(capsule_epsilon),
    capsule_delta = as.numeric(capsule_delta),
    lifetime_max_distinct_capsules =
      as.numeric(lifetime_max_distinct_capsules),
    lifetime_epsilon_upper_bound = lifetime_epsilon,
    lifetime_delta_upper_bound = lifetime_delta,
    privacy_epoch_scope =
      .DSVERT_CAPSULE_REGISTRY_PRIVACY_EPOCH_SCOPE,
    require_private = require_private,
    lock_timeout_ms = as.integer(as.numeric(timeout_text)))
}

.dsvert_capsule_registry_config_from_policy <- function(
    policy, registry_path = NULL) {
  context <- .dsvert_joint_dp_policy_context(
    policy, require_designated = FALSE)
  if (!isTRUE(.dsvert_identity_test_mode())) {
    invisible(.dsvert_privacy_accountant_namespace_enforce(
      policy, context))
  }
  ledger_path <- .dsvert_joint_dp_ledger_path(policy)
  if (is.null(registry_path)) {
    # Leave historical registries untouched as authenticated state. The v3
    # namespace adds a bounded lifetime contract and cannot silently inherit
    # an unbounded registry.
    registry_path <- paste0(ledger_path, ".capsule-registry-v3.sqlite")
  }
  canonical_path <- function(value) {
    value <- path.expand(value)
    file.path(
      normalizePath(dirname(value), mustWork = TRUE), basename(value))
  }
  if (!is.character(registry_path) || length(registry_path) != 1L ||
      is.na(registry_path)) {
    stop("The capsule registry must be separate from every DP ledger.",
         call. = FALSE)
  }
  registry_path <- canonical_path(registry_path)
  ledger_paths <- vapply(
    c(policy$ledger_path, ledger_path), canonical_path, character(1L))
  if (registry_path %in% ledger_paths) {
    stop("The capsule registry must be separate from every DP ledger.",
         call. = FALSE)
  }
  lock_timeout_ms <- policy$lock_timeout_ms
  if (is.null(lock_timeout_ms)) lock_timeout_ms <- 30000L
  .dsvert_capsule_registry_config(
    registry_path = registry_path,
    consortium_id = context$consortium_id,
    policy_contract = context$common,
    peer_pinset_sha256 = context$common$peer_pinset_sha256,
    capsule_epsilon = context$common$epsilon_capsule,
    capsule_delta = context$common$delta_capsule,
    lifetime_max_distinct_capsules =
      context$common$lifetime_max_distinct_capsules,
    require_private = isTRUE(policy$ledger_private),
    lock_timeout_ms = lock_timeout_ms)
}

.dsvert_capsule_registry_validate_config <- function(config) {
  required <- c(
    "version", "registry_id", "registry_path", "consortium_id",
    "policy_contract", "policy_contract_hash", "peer_pinset_sha256",
    "capsule_epsilon", "capsule_delta",
    "lifetime_max_distinct_capsules",
    "lifetime_epsilon_upper_bound", "lifetime_delta_upper_bound",
    "privacy_epoch_scope",
    "require_private",
    "lock_timeout_ms")
  if (!is.list(config) || is.null(names(config)) || anyNA(names(config)) ||
      anyDuplicated(names(config)) || !setequal(names(config), required) ||
      !identical(config$version, .DSVERT_CAPSULE_REGISTRY_VERSION)) {
    stop("Invalid capsule-registry configuration.", call. = FALSE)
  }
  expected <- .dsvert_capsule_registry_config(
    config$registry_path, config$consortium_id, config$policy_contract,
    config$peer_pinset_sha256, config$capsule_epsilon,
    config$capsule_delta, config$lifetime_max_distinct_capsules,
    config$require_private, config$lock_timeout_ms)
  if (!identical(config, expected)) {
    stop("The capsule-registry configuration is not canonical.", call. = FALSE)
  }
  config
}

.dsvert_capsule_registry_component <- function(value, what) {
  forbidden <- c(
    "method", "methods", "argument", "arguments", "operation",
    "operation_id", "query", "query_id", "capsule_id",
    "capsule_release_id")
  inspect <- function(current) {
    if (!is.list(current)) return(invisible(TRUE))
    fields <- names(current)
    if (!is.null(fields) &&
        (anyNA(fields) || any(!nzchar(fields)) || anyDuplicated(fields) ||
         any(tolower(fields) %in% forbidden))) {
      stop("Invalid operation-independent capsule ", what, ".",
           call. = FALSE)
    }
    lapply(current, inspect)
    invisible(TRUE)
  }
  if (!is.list(value) || !length(value) || is.null(names(value))) {
    stop("Invalid operation-independent capsule ", what, ".",
         call. = FALSE)
  }
  inspect(value)
  tryCatch(
    .dsvert_dp_canonical_query_value(value),
    error = function(e) stop(
      "Invalid operation-independent capsule ", what, ".", call. = FALSE))
}

.dsvert_capsule_registry_identity <- function(
    config, logical_snapshot, capsule_schema, admission, bounds, workload) {
  config <- .dsvert_capsule_registry_validate_config(config)
  snapshot_fields <- c(
    "logical_snapshot_id", "version", "alignment_protocol_version")
  if (!is.list(logical_snapshot) || is.null(names(logical_snapshot)) ||
      anyNA(names(logical_snapshot)) || anyDuplicated(names(logical_snapshot)) ||
      !setequal(names(logical_snapshot), snapshot_fields) ||
      !is.character(logical_snapshot$logical_snapshot_id) ||
      length(logical_snapshot$logical_snapshot_id) != 1L ||
      is.na(logical_snapshot$logical_snapshot_id) ||
      nchar(logical_snapshot$logical_snapshot_id, type = "bytes") > 128L ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]*$",
             logical_snapshot$logical_snapshot_id, perl = TRUE) ||
      !is.character(logical_snapshot$version) ||
      length(logical_snapshot$version) != 1L ||
      is.na(logical_snapshot$version) ||
      nchar(logical_snapshot$version, type = "bytes") > 128L ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]*$",
             logical_snapshot$version, perl = TRUE) ||
      !is.numeric(logical_snapshot$alignment_protocol_version) ||
      length(logical_snapshot$alignment_protocol_version) != 1L ||
      is.na(logical_snapshot$alignment_protocol_version) ||
      !is.finite(logical_snapshot$alignment_protocol_version) ||
      logical_snapshot$alignment_protocol_version < 1 ||
      logical_snapshot$alignment_protocol_version !=
        floor(logical_snapshot$alignment_protocol_version) ||
      !is.character(capsule_schema) || length(capsule_schema) != 1L ||
      is.na(capsule_schema) ||
      nchar(capsule_schema, type = "bytes") > 128L ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:/-]*$", capsule_schema,
             perl = TRUE)) {
    stop("Invalid capsule-registry identity inputs.", call. = FALSE)
  }
  contract <- .dsvert_dp_canonical_query_value(list(
    protocol = .DSVERT_CAPSULE_IDENTITY_VERSION,
    consortium_id = config$consortium_id,
    policy_contract_hash = config$policy_contract_hash,
    peer_pinset_sha256 = config$peer_pinset_sha256,
    logical_snapshot = logical_snapshot,
    capsule_schema = capsule_schema,
    admission = .dsvert_capsule_registry_component(
      admission, "admission contract"),
    bounds = .dsvert_capsule_registry_component(bounds, "bounds contract"),
    workload = .dsvert_capsule_registry_component(
      workload, "workload contract"),
    privacy_epoch_scope = config$privacy_epoch_scope))
  list(
    capsule_id = .dsvert_capsule_registry_hash(contract),
    contract = contract)
}

.dsvert_capsule_registry_validate_identity <- function(config, identity) {
  required <- c("capsule_id", "contract")
  fields <- c(
    "protocol", "consortium_id", "policy_contract_hash",
    "peer_pinset_sha256", "logical_snapshot", "capsule_schema",
    "admission", "bounds", "workload", "privacy_epoch_scope")
  if (!is.list(identity) || is.null(names(identity)) || anyNA(names(identity)) ||
      anyDuplicated(names(identity)) || !setequal(names(identity), required) ||
      !is.list(identity$contract) || is.null(names(identity$contract)) ||
      anyNA(names(identity$contract)) ||
      anyDuplicated(names(identity$contract)) ||
      !setequal(names(identity$contract), fields) ||
      !identical(identity$contract$protocol,
                 .DSVERT_CAPSULE_IDENTITY_VERSION) ||
      !identical(identity$contract$privacy_epoch_scope,
                 .DSVERT_CAPSULE_REGISTRY_PRIVACY_EPOCH_SCOPE)) {
    stop("Invalid capsule-registry identity.", call. = FALSE)
  }
  identity$capsule_id <- .dsvert_capsule_registry_hex(
    identity$capsule_id, "capsule id")
  expected <- .dsvert_capsule_registry_identity(
    config, identity$contract$logical_snapshot,
    identity$contract$capsule_schema, identity$contract$admission,
    identity$contract$bounds, identity$contract$workload)
  identity <- .dsvert_dp_canonical_query_value(identity)
  if (!identical(identity, expected)) {
    stop("The capsule id does not match its immutable contract.",
         call. = FALSE)
  }
  identity
}

.dsvert_capsule_registry_hmac <- function(secret, family, value) {
  if (!is.raw(secret) || length(secret) != 32L ||
      !is.character(family) || length(family) != 1L || is.na(family)) {
    stop("Invalid capsule-registry authentication context.", call. = FALSE)
  }
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/capsule-registry/", family, "/v1|",
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(value)))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_capsule_registry_reuse_key <- function(secret, registry_id) {
  registry_id <- .dsvert_capsule_registry_hex(registry_id, "registry id")
  if (!is.raw(secret) || length(secret) != 32L) {
    stop("Invalid capsule-registry authentication context.", call. = FALSE)
  }
  derived <- digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/capsule-registry/reusable-record-key/v1|", registry_id)),
    algo = "sha256", serialize = FALSE)
  starts <- seq.int(1L, 63L, by = 2L)
  as.raw(strtoi(substring(derived, starts, starts + 1L), base = 16L))
}

.dsvert_capsule_registry_record_mac <- function(
    secret, registry_id, value) {
  key <- .dsvert_capsule_registry_reuse_key(secret, registry_id)
  payload <- serialize(list(
    domain = "dsVert/capsule-registry/reusable-record/v1",
    value = value), connection = NULL, version = 3L)
  digest::hmac(
    key = key, object = payload, algo = "sha256", serialize = FALSE)
}

.dsvert_capsule_registry_meta <- function(
    config, secret, fast_state = TRUE) {
  values <- list(
    version = config$version,
    registry_id = config$registry_id,
    consortium_id = config$consortium_id,
    policy_contract_hash = config$policy_contract_hash,
    peer_pinset_sha256 = config$peer_pinset_sha256,
    capsule_epsilon = .dsvert_capsule_registry_decimal(
      config$capsule_epsilon, "capsule epsilon", open_minimum = TRUE),
    capsule_delta = .dsvert_capsule_registry_decimal(
      config$capsule_delta, "capsule delta"),
    privacy_epoch_scope = config$privacy_epoch_scope)
  if (isTRUE(fast_state)) {
    values$fast_state_version <- .DSVERT_CAPSULE_REGISTRY_FAST_STATE_VERSION
  }
  values$registry_auth <- .dsvert_capsule_registry_hmac(
    secret, "meta", values)
  unlist(values, use.names = TRUE)
}

.dsvert_capsule_registry_initialize <- function(connection, config, secret) {
  expected <- .dsvert_capsule_registry_meta(config, secret)
  legacy <- .dsvert_capsule_registry_meta(
    config, secret, fast_state = FALSE)
  observed <- DBI::dbGetQuery(
    connection, "SELECT key, value FROM capsule_registry_meta ORDER BY key")
  if (!nrow(observed)) {
    tables <- c(
      "capsule_registry_records", "capsule_registry_allocator_bindings",
      "capsule_registry_allocator_state", "capsule_registry_state")
    nonempty <- vapply(tables, function(table) {
      nrow(DBI::dbGetQuery(
        connection, paste0("SELECT 1 FROM ", table, " LIMIT 1"))) > 0L
    }, logical(1L))
    if (any(nonempty)) {
      stop("The capsule registry is missing immutable metadata.",
           call. = FALSE)
    }
    DBI::dbExecute(connection, "BEGIN IMMEDIATE")
    committed <- FALSE
    on.exit(if (!committed) try(
      DBI::dbExecute(connection, "ROLLBACK"), silent = TRUE), add = TRUE)
    # The fast-state marker is written only after both authenticated
    # singleton states exist.  A crash before promotion therefore resumes as
    # a one-time legacy bootstrap rather than accepting a missing current
    # state.
    for (key in names(legacy)) {
      DBI::dbExecute(connection,
        "INSERT INTO capsule_registry_meta(key, value) VALUES(?, ?)",
        params = list(key, unname(legacy[[key]])))
    }
    DBI::dbExecute(connection, "COMMIT")
    committed <- TRUE
    return("new")
  }
  matches <- function(value) {
    nrow(observed) == length(value) &&
      setequal(observed$key, names(value)) &&
      identical(
        unname(stats::setNames(observed$value, observed$key)[names(value)]),
        unname(value))
  }
  if (matches(expected)) return("current")
  if (matches(legacy)) return("legacy")
  if (!setequal(observed$key, names(expected)) &&
      !setequal(observed$key, names(legacy))) {
    stop("The capsule registry has invalid immutable metadata.", call. = FALSE)
  }
  stop("The capsule registry failed its policy or authentication check.",
       call. = FALSE)
}

.dsvert_capsule_registry_promote_fast_state <- function(
    connection, config, secret) {
  expected <- .dsvert_capsule_registry_meta(config, secret)
  changed_marker <- DBI::dbExecute(connection, paste(
    "INSERT INTO capsule_registry_meta(key, value) VALUES(?, ?)",
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value"), params = list(
      "fast_state_version", .DSVERT_CAPSULE_REGISTRY_FAST_STATE_VERSION))
  changed_auth <- DBI::dbExecute(connection, paste(
    "UPDATE capsule_registry_meta SET value = ? WHERE key = 'registry_auth'"),
    params = list(unname(expected[["registry_auth"]])))
  if (!identical(as.integer(changed_marker), 1L) ||
      !identical(as.integer(changed_auth), 1L)) {
    stop("The capsule registry fast-state marker could not be persisted.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_capsule_registry_with <- function(config, secret, code) {
  config <- .dsvert_capsule_registry_validate_config(config)
  if (!is.raw(secret) || length(secret) != 32L || !is.function(code)) {
    stop("Invalid capsule-registry execution context.", call. = FALSE)
  }
  paths <- c(
    registry = config$registry_path,
    lock = paste0(config$registry_path, ".lock"),
    wal = paste0(config$registry_path, "-wal"),
    shm = paste0(config$registry_path, "-shm"))
  for (label in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[label]], paste0("capsule registry ", label),
      config$require_private)
  }
  previous_umask <- Sys.umask("0077")
  lock <- NULL
  connection <- NULL
  on.exit({
    if (!is.null(connection)) {
      try(DBI::dbExecute(connection, "PRAGMA wal_checkpoint(TRUNCATE)"),
          silent = TRUE)
      try(DBI::dbDisconnect(connection), silent = TRUE)
    }
    try(.dsvert_dp_chmod_private_files(paths), silent = TRUE)
    if (!is.null(lock)) try(filelock::unlock(lock), silent = TRUE)
    try(Sys.umask(previous_umask), silent = TRUE)
  }, add = TRUE)
  lock <- filelock::lock(
    paths[["lock"]], timeout = config$lock_timeout_ms)
  if (is.null(lock)) {
    stop("The capsule registry is busy.", call. = FALSE)
  }
  for (label in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[label]], paste0("capsule registry ", label),
      config$require_private)
  }
  connection <- DBI::dbConnect(RSQLite::SQLite(), config$registry_path)
  DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
  DBI::dbExecute(connection, "PRAGMA journal_mode=WAL")
  DBI::dbExecute(connection, "PRAGMA synchronous=FULL")
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS capsule_registry_meta (",
    "key TEXT PRIMARY KEY, value TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS capsule_registry_records (",
    "capsule_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL UNIQUE,",
    "identity_json TEXT NOT NULL, capsule_epsilon TEXT NOT NULL,",
    "capsule_delta TEXT NOT NULL, previous_chain TEXT NOT NULL,",
    "chain_hash TEXT NOT NULL UNIQUE, row_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS capsule_registry_allocator_bindings (",
    "capsule_id TEXT PRIMARY KEY, binding_json TEXT NOT NULL,",
    "binding_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS capsule_registry_allocator_state (",
    "singleton INTEGER PRIMARY KEY CHECK(singleton = 1),",
    "binding_count INTEGER NOT NULL, head_chain TEXT NOT NULL,",
    "state_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE IF NOT EXISTS capsule_registry_state (",
    "singleton INTEGER PRIMARY KEY CHECK(singleton = 1),",
    "capsule_count INTEGER NOT NULL, head_chain TEXT NOT NULL,",
    "state_mac TEXT NOT NULL)"))
  .dsvert_dp_chmod_private_files(paths)
  for (label in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[label]], paste0("capsule registry ", label),
      config$require_private)
  }
  metadata_state <- .dsvert_capsule_registry_initialize(
    connection, config, secret)
  allow_bootstrap <- !identical(metadata_state, "current")
  .dsvert_capsule_registry_initialize_state(
    connection, config, secret, allow_initialize = allow_bootstrap)
  .dsvert_capsule_registry_initialize_allocator_state(
    connection, config, secret, allow_migration = allow_bootstrap,
    force_audit = identical(metadata_state, "legacy"))
  if (isTRUE(allow_bootstrap)) {
    .dsvert_capsule_registry_transaction(connection, {
      .dsvert_capsule_registry_promote_fast_state(
        connection, config, secret)
    })
  }
  code(connection, config, secret)
}

.dsvert_capsule_registry_state_material <- function(config, count, head) {
  count_text <- .dsvert_capsule_registry_decimal(
    count, "capsule count", minimum = 0, maximum = 2^53 - 1)
  if (as.numeric(count_text) != floor(as.numeric(count_text)) ||
      !is.character(head) || length(head) != 1L || is.na(head) ||
      !(identical(head, "GENESIS") ||
        identical(.dsvert_capsule_registry_hex(head, "chain head"), head)) ||
      (as.numeric(count_text) == 0 && !identical(head, "GENESIS")) ||
      (as.numeric(count_text) > 0 && identical(head, "GENESIS"))) {
    stop("Invalid capsule-registry authenticated state.", call. = FALSE)
  }
  list(
    version = .DSVERT_CAPSULE_REGISTRY_VERSION,
    registry_id = config$registry_id,
    capsule_count = as.numeric(count_text),
    head_chain = head)
}

.dsvert_capsule_registry_initialize_state <- function(
    connection, config, secret, allow_initialize = TRUE) {
  state <- DBI::dbGetQuery(
    connection,
    paste("SELECT capsule_count, head_chain, state_mac",
          "FROM capsule_registry_state WHERE singleton = 1"))
  if (!nrow(state)) {
    if (!isTRUE(allow_initialize)) {
      stop("The capsule registry is missing authenticated state.",
           call. = FALSE)
    }
    has_record <- nrow(DBI::dbGetQuery(
      connection,
      "SELECT 1 FROM capsule_registry_records LIMIT 1")) > 0L
    if (isTRUE(has_record)) {
      stop("The capsule registry is missing authenticated state.",
           call. = FALSE)
    }
    material <- .dsvert_capsule_registry_state_material(
      config, 0, "GENESIS")
    state_mac <- .dsvert_capsule_registry_hmac(
      secret, "state", material)
    DBI::dbExecute(connection, paste(
      "INSERT INTO capsule_registry_state(",
      "singleton, capsule_count, head_chain, state_mac)",
      "VALUES(1, ?, ?, ?)"), params = list(
        material$capsule_count, material$head_chain, state_mac))
    return(invisible(TRUE))
  }
  if (nrow(state) != 1L) {
    stop("The capsule registry has invalid authenticated state.",
         call. = FALSE)
  }
  invisible(.dsvert_capsule_registry_read_state(
    connection, config, secret))
}

.dsvert_capsule_registry_read_state <- function(connection, config, secret) {
  state <- DBI::dbGetQuery(
    connection,
    paste("SELECT capsule_count, head_chain, state_mac",
          "FROM capsule_registry_state WHERE singleton = 1"))
  material <- tryCatch({
    if (nrow(state) != 1L) stop("invalid")
    value <- .dsvert_capsule_registry_state_material(
      config, as.numeric(state$capsule_count[[1L]]),
      state$head_chain[[1L]])
    supplied_mac <- .dsvert_capsule_registry_hex(
      state$state_mac[[1L]], "state MAC")
    expected_mac <- .dsvert_capsule_registry_hmac(
      secret, "state", value)
    if (!identical(supplied_mac, expected_mac)) stop("invalid")
    value
  }, error = function(error) NULL)
  if (is.null(material)) {
    stop("The capsule registry failed its state authentication check.",
         call. = FALSE)
  }
  material
}

.dsvert_capsule_registry_write_state <- function(
    connection, config, secret, count, head) {
  material <- .dsvert_capsule_registry_state_material(config, count, head)
  state_mac <- .dsvert_capsule_registry_hmac(secret, "state", material)
  changed <- DBI::dbExecute(connection, paste(
    "UPDATE capsule_registry_state SET capsule_count = ?,",
    "head_chain = ?, state_mac = ? WHERE singleton = 1"),
    params = list(material$capsule_count, material$head_chain, state_mac))
  if (!identical(as.integer(changed), 1L)) {
    stop("The capsule registry could not persist authenticated state.",
         call. = FALSE)
  }
  material
}

.dsvert_capsule_registry_allocator_state_material <- function(
    config, count, head) {
  count_text <- .dsvert_capsule_registry_decimal(
    count, "allocator-binding count", minimum = 0, maximum = 2^53 - 1)
  if (as.numeric(count_text) != floor(as.numeric(count_text)) ||
      as.numeric(count_text) > config$lifetime_max_distinct_capsules ||
      !is.character(head) || length(head) != 1L || is.na(head) ||
      !(identical(head, "GENESIS") ||
        identical(.dsvert_capsule_registry_hex(
          head, "allocator-binding chain head"), head)) ||
      (as.numeric(count_text) == 0 && !identical(head, "GENESIS")) ||
      (as.numeric(count_text) > 0 && identical(head, "GENESIS"))) {
    stop("Invalid authenticated allocator-binding state.", call. = FALSE)
  }
  list(
    version = .DSVERT_CAPSULE_REGISTRY_ALLOCATOR_STATE_VERSION,
    registry_id = config$registry_id,
    binding_count = as.numeric(count_text),
    head_chain = head,
    operation_accounting = "one_per_distinct_capsule_allocator_commit",
    operation_limit = TRUE,
    history_can_deny_operation = TRUE)
}

.dsvert_capsule_registry_read_allocator_state <- function(
    connection, config, secret, allow_missing = FALSE) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT binding_count, head_chain, state_mac",
    "FROM capsule_registry_allocator_state WHERE singleton = 1"))
  if (!nrow(row) && isTRUE(allow_missing)) return(NULL)
  material <- tryCatch({
    if (nrow(row) != 1L) stop("invalid")
    value <- .dsvert_capsule_registry_allocator_state_material(
      config, as.numeric(row$binding_count[[1L]]), row$head_chain[[1L]])
    supplied_mac <- .dsvert_capsule_registry_hex(
      row$state_mac[[1L]], "allocator-binding state MAC")
    expected_mac <- .dsvert_capsule_registry_hmac(
      secret, "allocator-state", value)
    if (!identical(supplied_mac, expected_mac)) stop("invalid")
    value
  }, error = function(error) NULL)
  if (is.null(material)) {
    stop("The capsule registry failed its allocator-state authentication check.",
         call. = FALSE)
  }
  material
}

.dsvert_capsule_registry_write_allocator_state <- function(
    connection, config, secret, count, head, insert = FALSE) {
  material <- .dsvert_capsule_registry_allocator_state_material(
    config, count, head)
  state_mac <- .dsvert_capsule_registry_hmac(
    secret, "allocator-state", material)
  if (isTRUE(insert)) {
    changed <- DBI::dbExecute(connection, paste(
      "INSERT INTO capsule_registry_allocator_state(",
      "singleton, binding_count, head_chain, state_mac)",
      "VALUES(1, ?, ?, ?)"), params = list(
        material$binding_count, material$head_chain, state_mac))
  } else {
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE capsule_registry_allocator_state SET binding_count = ?,",
      "head_chain = ?, state_mac = ? WHERE singleton = 1"), params = list(
        material$binding_count, material$head_chain, state_mac))
  }
  if (!identical(as.integer(changed), 1L)) {
    stop("The capsule registry could not persist allocator state.",
         call. = FALSE)
  }
  material
}

.dsvert_capsule_registry_row_material <- function(
    config, capsule_id, sequence, identity_json, previous_chain) {
  list(
    version = .DSVERT_CAPSULE_RECORD_VERSION,
    registry_id = config$registry_id,
    capsule_id = capsule_id,
    sequence = as.numeric(sequence),
    identity_json = identity_json,
    capsule_epsilon = .dsvert_capsule_registry_decimal(
      config$capsule_epsilon, "capsule epsilon", open_minimum = TRUE),
    capsule_delta = .dsvert_capsule_registry_decimal(
      config$capsule_delta, "capsule delta"),
    previous_chain = previous_chain)
}

.dsvert_capsule_registry_record <- function(config, row, identity, secret) {
  record <- list(
    version = .DSVERT_CAPSULE_RECORD_VERSION,
    registry_id = config$registry_id,
    capsule_id = row$capsule_id[[1L]],
    sequence = as.numeric(row$sequence[[1L]]),
    identity = identity,
    capsule_epsilon = config$capsule_epsilon,
    capsule_delta = config$capsule_delta,
    operation_accounting = "none",
    capability_available = FALSE)
  record$record_mac <- .dsvert_capsule_registry_record_mac(
    secret, config$registry_id, record)
  record
}

.dsvert_capsule_registry_validate_row <- function(
    config, row, secret) {
  required <- c(
    "capsule_id", "sequence", "identity_json", "capsule_epsilon",
    "capsule_delta", "previous_chain", "chain_hash", "row_mac")
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !setequal(names(row), required)) {
    stop("The capsule registry contains an invalid row.", call. = FALSE)
  }
  identity_contract <- tryCatch(
    jsonlite::fromJSON(row$identity_json[[1L]], simplifyVector = FALSE),
    error = function(error) NULL)
  identity <- if (is.list(identity_contract)) list(
    capsule_id = row$capsule_id[[1L]], contract = identity_contract) else NULL
  identity <- tryCatch(
    .dsvert_capsule_registry_validate_identity(config, identity),
    error = function(error) NULL)
  if (is.null(identity) ||
      !identical(row$identity_json[[1L]],
                 .dsvert_dp_canonical_json(identity$contract))) {
    stop("The capsule registry contains an invalid identity.", call. = FALSE)
  }
  material <- tryCatch(
    .dsvert_capsule_registry_row_material(
      config, row$capsule_id[[1L]], as.numeric(row$sequence[[1L]]),
      row$identity_json[[1L]], row$previous_chain[[1L]]),
    error = function(error) NULL)
  if (is.null(material) || material$sequence < 0 ||
      material$sequence != floor(material$sequence)) {
    stop("The capsule registry contains an invalid row.", call. = FALSE)
  }
  chain_hash <- .dsvert_capsule_registry_hash(material)
  row_mac <- .dsvert_capsule_registry_hmac(
    secret, "row", c(material, list(chain_hash = chain_hash)))
  if (!identical(row$capsule_epsilon[[1L]], material$capsule_epsilon) ||
      !identical(row$capsule_delta[[1L]], material$capsule_delta) ||
      !identical(row$chain_hash[[1L]], chain_hash) ||
      !identical(row$row_mac[[1L]], row_mac)) {
    stop("The capsule registry failed its row integrity check.",
         call. = FALSE)
  }
  list(
    row = row,
    identity = identity,
    chain_hash = chain_hash,
    record = .dsvert_capsule_registry_record(
      config, row, identity, secret))
}

.dsvert_capsule_registry_validate_head <- function(
    connection, config, secret, state = NULL, return_tail = FALSE) {
  if (is.null(state)) {
    state <- .dsvert_capsule_registry_read_state(
      connection, config, secret)
  }
  tail <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM capsule_registry_records",
    "ORDER BY sequence DESC LIMIT 1"))
  if (state$capsule_count == 0) {
    if (nrow(tail)) {
      stop("The empty capsule registry has an unexpected row.",
           call. = FALSE)
    }
    if (isTRUE(return_tail)) {
      return(list(state = state, tail = NULL))
    }
    return(state)
  }
  if (nrow(tail) != 1L ||
      !identical(as.numeric(tail$sequence[[1L]]),
                 state$capsule_count - 1)) {
    stop("The capsule registry tail does not match authenticated state.",
         call. = FALSE)
  }
  verified_tail <- .dsvert_capsule_registry_validate_row(
    config, tail, secret)
  if (!identical(verified_tail$chain_hash, state$head_chain)) {
    stop("The capsule registry tail does not match authenticated state.",
         call. = FALSE)
  }
  if (isTRUE(return_tail)) {
    return(list(state = state, tail = verified_tail))
  }
  state
}

.dsvert_capsule_registry_audit <- function(connection, config, secret) {
  state <- .dsvert_capsule_registry_read_state(connection, config, secret)
  rows <- DBI::dbGetQuery(
    connection,
    "SELECT * FROM capsule_registry_records ORDER BY sequence")
  if (!identical(as.numeric(nrow(rows)), state$capsule_count)) {
    stop("The capsule registry count does not match its authenticated state.",
         call. = FALSE)
  }
  previous <- "GENESIS"
  records <- vector("list", nrow(rows))
  if (nrow(rows)) for (index in seq_len(nrow(rows))) {
    row <- rows[index, , drop = FALSE]
    if (!identical(as.numeric(row$sequence[[1L]]), as.numeric(index - 1L)) ||
        !identical(row$previous_chain[[1L]], previous)) {
      stop("The capsule registry chain is discontinuous.", call. = FALSE)
    }
    verified <- .dsvert_capsule_registry_validate_row(
      config, row, secret)
    previous <- verified$chain_hash
    records[[index]] <- verified$record
  }
  if (!identical(previous, state$head_chain)) {
    stop("The capsule registry head does not match its authenticated state.",
         call. = FALSE)
  }
  list(rows = rows, records = records, head = previous, state = state)
}

.dsvert_capsule_registry_summary <- function(config, count) {
  count <- .dsvert_joint_dp_release_ledger_count(
    count, "capsule-registry count")
  if (count > config$lifetime_max_distinct_capsules) {
    stop("The capsule registry exceeds its lifetime privacy bound.",
         call. = FALSE)
  }
  cumulative_epsilon_text <-
    .dsvert_joint_dp_release_ledger_exact_total(
      config$capsule_epsilon, count, "cumulative epsilon")
  cumulative_delta_text <-
    .dsvert_joint_dp_release_ledger_exact_total(
      config$capsule_delta, count, "cumulative delta")
  cumulative_epsilon <-
    .dsvert_joint_dp_release_ledger_upper_numeric(
      cumulative_epsilon_text, "cumulative epsilon")
  cumulative_delta <-
    .dsvert_joint_dp_release_ledger_upper_numeric(
      cumulative_delta_text, "cumulative delta")
  list(
    version = .DSVERT_CAPSULE_REGISTRY_VERSION,
    registry_id = config$registry_id,
    capsule_count = as.numeric(count),
    lifetime_max_distinct_capsules =
      config$lifetime_max_distinct_capsules,
    remaining_distinct_capsules =
      config$lifetime_max_distinct_capsules - as.numeric(count),
    capsule_epsilon = config$capsule_epsilon,
    capsule_delta = config$capsule_delta,
    cumulative_epsilon = cumulative_epsilon,
    cumulative_delta = cumulative_delta,
    cumulative_delta_vacuous = FALSE,
    composition_role = "basic_composition_authenticated_lifetime_bound",
    registration_policy =
      "allocator_admitted_distinct_capsules_up_to_lifetime_limit",
    operation_accounting = "one_per_distinct_capsule_allocator_commit",
    operation_limit = TRUE,
    history_can_deny_operation = TRUE,
    capability_available = FALSE)
}

.dsvert_capsule_registry_transaction <- function(connection, code) {
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  committed <- FALSE
  on.exit(if (!committed) try(
    DBI::dbExecute(connection, "ROLLBACK"), silent = TRUE), add = TRUE)
  value <- force(code)
  DBI::dbExecute(connection, "COMMIT")
  committed <- TRUE
  value
}

.dsvert_capsule_registry_register_connection <- function(
    connection, config, identity, secret) {
  state <- .dsvert_capsule_registry_read_state(
    connection, config, secret)
  state <- .dsvert_capsule_registry_validate_head(
    connection, config, secret, state)
  existing <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM capsule_registry_records WHERE capsule_id = ?"),
    params = list(identity$capsule_id))
  if (nrow(existing)) {
    verified_existing <- .dsvert_capsule_registry_validate_row(
      config, existing, secret)
    if (verified_existing$record$sequence >= state$capsule_count) {
      stop("The capsule registry contains an invalid memoized capsule.",
           call. = FALSE)
    }
    return(list(
      record = verified_existing$record, created = FALSE,
      binding = list(
        sequence = verified_existing$record$sequence,
        chain_hash = verified_existing$chain_hash,
        head_chain = state$head_chain),
      summary = .dsvert_capsule_registry_summary(
        config, state$capsule_count)))
  }
  if (state$capsule_count >= config$lifetime_max_distinct_capsules) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  identity_json <- .dsvert_dp_canonical_json(identity$contract)
  sequence <- state$capsule_count
  material <- .dsvert_capsule_registry_row_material(
    config, identity$capsule_id, sequence, identity_json,
    state$head_chain)
  chain_hash <- .dsvert_capsule_registry_hash(material)
  row_mac <- .dsvert_capsule_registry_hmac(
    secret, "row", c(material, list(chain_hash = chain_hash)))
  DBI::dbExecute(connection, paste(
    "INSERT INTO capsule_registry_records(",
    "capsule_id, sequence, identity_json, capsule_epsilon,",
    "capsule_delta, previous_chain, chain_hash, row_mac)",
    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)"), params = list(
      identity$capsule_id, sequence, identity_json,
      material$capsule_epsilon, material$capsule_delta,
      state$head_chain, chain_hash, row_mac))
  inserted <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM capsule_registry_records WHERE capsule_id = ?"),
    params = list(identity$capsule_id))
  verified <- .dsvert_capsule_registry_validate_row(
    config, inserted, secret)
  next_state <- .dsvert_capsule_registry_write_state(
    connection, config, secret, sequence + 1, chain_hash)
  list(
    record = verified$record,
    created = TRUE,
    binding = list(
      sequence = verified$record$sequence,
      chain_hash = verified$chain_hash,
      head_chain = next_state$head_chain),
    summary = .dsvert_capsule_registry_summary(
      config, next_state$capsule_count))
}

.dsvert_capsule_registry_register <- function(config, identity, secret) {
  config <- .dsvert_capsule_registry_validate_config(config)
  identity <- .dsvert_capsule_registry_validate_identity(config, identity)
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    .dsvert_capsule_registry_transaction(connection,
      .dsvert_capsule_registry_register_connection(
        connection, config, identity, secret))
  })
}

.dsvert_capsule_registry_allocator_admission <- function(
    config, identity, allocator_sequence, joint_record_hash,
    prepare_set_hash, own_commit_hash, secret) {
  config <- .dsvert_capsule_registry_validate_config(config)
  identity <- .dsvert_capsule_registry_validate_identity(config, identity)
  allocator_sequence <- .dsvert_capsule_registry_decimal(
    allocator_sequence, "allocator sequence", minimum = 0,
    maximum = 2^53 - 1)
  hashes <- c(joint_record_hash, prepare_set_hash, own_commit_hash)
  if (as.numeric(allocator_sequence) !=
        floor(as.numeric(allocator_sequence)) ||
      as.numeric(allocator_sequence) >=
        config$lifetime_max_distinct_capsules ||
      !is.character(hashes) || length(hashes) != 3L || anyNA(hashes) ||
      any(!grepl("^[0-9a-f]{64}$", hashes))) {
    stop("Invalid cross-signed allocator admission.", call. = FALSE)
  }
  material <- .dsvert_dp_canonical_query_value(list(
    protocol = "dsvert-capsule-registry-allocator-admission-v2",
    registry_id = config$registry_id,
    consortium_id = config$consortium_id,
    capsule_id = identity$capsule_id,
    identity_hash = .dsvert_capsule_registry_hash(identity$contract),
    allocator_sequence = as.character(as.numeric(allocator_sequence)),
    joint_record_hash = joint_record_hash,
    prepare_set_hash = prepare_set_hash,
    own_commit_hash = own_commit_hash,
    reservation_evidence =
      "two_signed_prepares_plus_own_signed_commit",
    operation_accounting = "one_per_distinct_capsule_allocator_commit",
    operation_limit = TRUE,
    history_can_deny_operation = TRUE,
    capability_available = FALSE))
  list(
    material = material,
    admission_mac = .dsvert_capsule_registry_hmac(
      secret, "allocator-admission", material))
}

.dsvert_capsule_registry_allocator_admission_validate <- function(
    config, identity, admission, secret) {
  valid <- is.list(admission) && !is.null(names(admission)) &&
    !anyDuplicated(names(admission)) &&
    setequal(names(admission), c("material", "admission_mac")) &&
    is.list(admission$material) &&
    is.character(admission$admission_mac) &&
    length(admission$admission_mac) == 1L &&
    grepl("^[0-9a-f]{64}$", admission$admission_mac)
  if (!isTRUE(valid)) {
    stop("Invalid cross-signed allocator admission.", call. = FALSE)
  }
  expected <- .dsvert_capsule_registry_allocator_admission(
    config, identity, suppressWarnings(as.numeric(
      admission$material$allocator_sequence)),
    admission$material$joint_record_hash,
    admission$material$prepare_set_hash,
    admission$material$own_commit_hash, secret)
  if (!identical(admission, expected)) {
    stop("The capsule-registry allocator admission failed authentication.",
         call. = FALSE)
  }
  admission
}

.dsvert_capsule_registry_allocator_binding_decode <- function(
    row, config, identity, secret) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !setequal(names(row), c(
        "capsule_id", "binding_json", "binding_mac"))) {
    stop("Invalid capsule-registry allocator binding.", call. = FALSE)
  }
  material <- tryCatch(
    jsonlite::fromJSON(row$binding_json[[1L]], simplifyVector = FALSE),
    error = function(error) NULL)
  admission <- list(
    material = material, admission_mac = row$binding_mac[[1L]])
  admission <- tryCatch(
    .dsvert_capsule_registry_allocator_admission_validate(
      config, identity, admission, secret),
    error = function(error) NULL)
  if (is.null(admission) ||
      !identical(row$capsule_id[[1L]], identity$capsule_id) ||
      !identical(row$binding_json[[1L]],
                 .dsvert_dp_canonical_json(admission$material))) {
    stop("The capsule-registry allocator binding failed authentication.",
         call. = FALSE)
  }
  admission
}

.dsvert_capsule_registry_rebuild_allocator_state <- function(
    connection, config, secret, existing_state = NULL) {
  audit <- .dsvert_capsule_registry_audit(connection, config, secret)
  bindings <- DBI::dbGetQuery(connection, paste(
    "SELECT capsule_id, binding_json, binding_mac",
    "FROM capsule_registry_allocator_bindings ORDER BY capsule_id"))
  if (nrow(bindings) != length(audit$records) ||
      !setequal(bindings$capsule_id, vapply(
        audit$records, `[[`, character(1L), "capsule_id"))) {
    stop("The capsule registry contains an unbound allocator entry.",
         call. = FALSE)
  }
  if (length(audit$records)) for (record in audit$records) {
    position <- match(record$capsule_id, bindings$capsule_id)
    .dsvert_capsule_registry_allocator_binding_decode(
      bindings[position, , drop = FALSE], config, record$identity, secret)
  }
  expected <- .dsvert_capsule_registry_allocator_state_material(
    config, length(audit$records), audit$head)
  if (!is.null(existing_state)) {
    if (!identical(existing_state, expected)) {
      stop("The capsule registry authenticated allocator state is inconsistent.",
           call. = FALSE)
    }
    return(existing_state)
  }
  .dsvert_capsule_registry_write_allocator_state(
    connection, config, secret, expected$binding_count,
    expected$head_chain, insert = TRUE)
}

.dsvert_capsule_registry_initialize_allocator_state <- function(
    connection, config, secret, allow_migration = TRUE,
    force_audit = FALSE) {
  state <- .dsvert_capsule_registry_read_allocator_state(
    connection, config, secret, allow_missing = TRUE)
  if (!is.null(state)) {
    if (isTRUE(force_audit)) {
      return(invisible(.dsvert_capsule_registry_rebuild_allocator_state(
        connection, config, secret, existing_state = state)))
    }
    return(invisible(state))
  }
  if (!isTRUE(allow_migration)) {
    stop("The capsule registry is missing authenticated allocator state.",
         call. = FALSE)
  }
  has_binding <- nrow(DBI::dbGetQuery(connection, paste(
    "SELECT 1 FROM capsule_registry_allocator_bindings LIMIT 1"))) > 0L
  if (isTRUE(has_binding)) {
    return(invisible(.dsvert_capsule_registry_rebuild_allocator_state(
      connection, config, secret)))
  }
  invisible(.dsvert_capsule_registry_write_allocator_state(
    connection, config, secret, 0, "GENESIS", insert = TRUE))
}

.dsvert_capsule_registry_validate_bound_state <- function(
    connection, config, secret) {
  head <- .dsvert_capsule_registry_validate_head(
    connection, config, secret, return_tail = TRUE)
  state <- head$state
  allocator_state <- .dsvert_capsule_registry_read_allocator_state(
    connection, config, secret)
  if (!identical(state$capsule_count, allocator_state$binding_count) ||
      !identical(state$head_chain, allocator_state$head_chain)) {
    stop("The capsule registry contains an unbound allocator entry.",
         call. = FALSE)
  }
  if (state$capsule_count > 0) {
    tail_binding <- DBI::dbGetQuery(connection, paste(
      "SELECT * FROM capsule_registry_allocator_bindings",
      "WHERE capsule_id = ?"),
      params = list(head$tail$record$capsule_id))
    .dsvert_capsule_registry_allocator_binding_decode(
      tail_binding, config, head$tail$identity, secret)
  }
  list(registry = state, allocator = allocator_state)
}

.dsvert_capsule_registry_register_bound <- function(
    config, identity, admission, secret) {
  config <- .dsvert_capsule_registry_validate_config(config)
  identity <- .dsvert_capsule_registry_validate_identity(config, identity)
  admission <- .dsvert_capsule_registry_allocator_admission_validate(
    config, identity, admission, secret)
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    .dsvert_capsule_registry_transaction(connection, {
      bound_state <- .dsvert_capsule_registry_validate_bound_state(
        connection, config, secret)
      existing_record <- DBI::dbGetQuery(connection, paste(
        "SELECT * FROM capsule_registry_records WHERE capsule_id = ?"),
        params = list(identity$capsule_id))
      existing_binding <- DBI::dbGetQuery(connection, paste(
        "SELECT * FROM capsule_registry_allocator_bindings",
        "WHERE capsule_id = ?"), params = list(identity$capsule_id))
      if (nrow(existing_record) && !nrow(existing_binding)) {
        stop("A pre-existing capsule lacks cross-signed allocator admission.",
             call. = FALSE)
      }
      if (!nrow(existing_record) && nrow(existing_binding)) {
        stop("The capsule registry contains an orphan allocator binding.",
             call. = FALSE)
      }
      if (!nrow(existing_record) &&
          !identical(
            as.numeric(admission$material$allocator_sequence),
            as.numeric(bound_state$allocator$binding_count))) {
        stop("The allocator admission is not the next registry sequence.",
             call. = FALSE)
      }
      if (nrow(existing_binding)) {
        observed <- .dsvert_capsule_registry_allocator_binding_decode(
          existing_binding, config, identity, secret)
        if (!identical(observed, admission)) {
          stop("Conflicting cross-signed allocator admission replay.",
               call. = FALSE)
        }
      }
      result <- .dsvert_capsule_registry_register_connection(
        connection, config, identity, secret)
      if (!identical(
            as.numeric(result$record$sequence),
            as.numeric(admission$material$allocator_sequence))) {
        stop("The allocator admission sequence does not match the registry.",
             call. = FALSE)
      }
      if (isTRUE(result$created)) {
        DBI::dbExecute(connection, paste(
          "INSERT INTO capsule_registry_allocator_bindings(",
          "capsule_id, binding_json, binding_mac) VALUES(?, ?, ?)"),
          params = list(
            identity$capsule_id,
            .dsvert_dp_canonical_json(admission$material),
            admission$admission_mac))
        .dsvert_capsule_registry_write_allocator_state(
          connection, config, secret, result$summary$capsule_count,
          result$binding$head_chain)
      } else if (result$summary$capsule_count !=
          bound_state$allocator$binding_count ||
          !identical(result$binding$head_chain,
                     bound_state$allocator$head_chain)) {
        stop("The capsule registry allocator state changed during replay.",
             call. = FALSE)
      }
      result$allocator_admission <- admission
      result
    })
  })
}

.dsvert_capsule_registry_bound_integrity_state <- function(config, secret) {
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    bound_state <- .dsvert_capsule_registry_validate_bound_state(
      connection, config, secret)
    state <- bound_state$registry
    list(
      summary = .dsvert_capsule_registry_summary(
        config, state$capsule_count),
      head_chain = state$head_chain)
  })
}

.dsvert_capsule_registry_bound_entry <- function(
    config, capsule_id, secret) {
  capsule_id <- .dsvert_capsule_registry_hex(capsule_id, "capsule id")
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    state <- .dsvert_capsule_registry_validate_bound_state(
      connection, config, secret)$registry
    row <- DBI::dbGetQuery(connection, paste(
      "SELECT * FROM capsule_registry_records WHERE capsule_id = ?"),
      params = list(capsule_id))
    if (!nrow(row)) return(NULL)
    verified <- .dsvert_capsule_registry_validate_row(
      config, row, secret)
    binding <- DBI::dbGetQuery(connection, paste(
      "SELECT * FROM capsule_registry_allocator_bindings",
      "WHERE capsule_id = ?"), params = list(capsule_id))
    admission <- .dsvert_capsule_registry_allocator_binding_decode(
      binding, config, verified$identity, secret)
    list(
      record = verified$record,
      created = FALSE,
      binding = list(
        sequence = verified$record$sequence,
        chain_hash = verified$chain_hash,
        head_chain = state$head_chain),
      summary = .dsvert_capsule_registry_summary(
        config, state$capsule_count),
      allocator_admission = admission)
  })
}

.dsvert_capsule_registry_bound_sequence <- function(
    config, sequence, secret) {
  sequence <- as.numeric(.dsvert_capsule_registry_decimal(
    sequence, "registry sequence", minimum = 0, maximum = 2^53 - 1))
  if (sequence != floor(sequence)) {
    stop("Invalid capsule-registry sequence.", call. = FALSE)
  }
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    state <- .dsvert_capsule_registry_validate_bound_state(
      connection, config, secret)$registry
    row <- DBI::dbGetQuery(connection, paste(
      "SELECT * FROM capsule_registry_records WHERE sequence = ?"),
      params = list(sequence))
    if (!nrow(row)) return(NULL)
    verified <- .dsvert_capsule_registry_validate_row(
      config, row, secret)
    binding <- DBI::dbGetQuery(connection, paste(
      "SELECT * FROM capsule_registry_allocator_bindings",
      "WHERE capsule_id = ?"), params = list(verified$record$capsule_id))
    admission <- .dsvert_capsule_registry_allocator_binding_decode(
      binding, config, verified$identity, secret)
    list(
      record = verified$record,
      created = FALSE,
      binding = list(
        sequence = verified$record$sequence,
        chain_hash = verified$chain_hash,
        head_chain = state$head_chain),
      summary = .dsvert_capsule_registry_summary(
        config, state$capsule_count),
      allocator_admission = admission)
  })
}

.dsvert_capsule_registry_bound_state_entry <- function(
    config, secret, capsule_id = NULL) {
  if (!is.null(capsule_id)) {
    capsule_id <- .dsvert_capsule_registry_hex(capsule_id, "capsule id")
  }
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    state <- .dsvert_capsule_registry_validate_bound_state(
      connection, config, secret)$registry
    entry <- NULL
    if (!is.null(capsule_id)) {
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT * FROM capsule_registry_records WHERE capsule_id = ?"),
        params = list(capsule_id))
      if (nrow(row)) {
        verified <- .dsvert_capsule_registry_validate_row(
          config, row, secret)
        binding <- DBI::dbGetQuery(connection, paste(
          "SELECT * FROM capsule_registry_allocator_bindings",
          "WHERE capsule_id = ?"), params = list(capsule_id))
        admission <- .dsvert_capsule_registry_allocator_binding_decode(
          binding, config, verified$identity, secret)
        entry <- list(
          record = verified$record,
          created = FALSE,
          binding = list(
            sequence = verified$record$sequence,
            chain_hash = verified$chain_hash,
            head_chain = state$head_chain),
          summary = .dsvert_capsule_registry_summary(
            config, state$capsule_count),
          allocator_admission = admission)
      }
    }
    list(
      summary = .dsvert_capsule_registry_summary(
        config, state$capsule_count),
      head_chain = state$head_chain,
      entry = entry)
  })
}

.dsvert_capsule_registry_integrity_state <- function(config, secret) {
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    state <- .dsvert_capsule_registry_validate_head(
      connection, config, secret)
    list(
      summary = .dsvert_capsule_registry_summary(
        config, state$capsule_count),
      head_chain = state$head_chain)
  })
}

.dsvert_capsule_registry_entry <- function(config, capsule_id, secret) {
  capsule_id <- .dsvert_capsule_registry_hex(capsule_id, "capsule id")
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    state <- .dsvert_capsule_registry_validate_head(
      connection, config, secret)
    row <- DBI::dbGetQuery(connection, paste(
      "SELECT * FROM capsule_registry_records WHERE capsule_id = ?"),
      params = list(capsule_id))
    if (!nrow(row)) return(NULL)
    verified <- .dsvert_capsule_registry_validate_row(
      config, row, secret)
    list(
      record = verified$record,
      created = FALSE,
      binding = list(
        sequence = verified$record$sequence,
        chain_hash = verified$chain_hash,
        head_chain = state$head_chain),
      summary = .dsvert_capsule_registry_summary(
        config, state$capsule_count))
  })
}

.dsvert_capsule_registry_snapshot <- function(config, secret) {
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    audit <- .dsvert_capsule_registry_audit(connection, config, secret)
    list(
      summary = .dsvert_capsule_registry_summary(
        config, length(audit$records)),
      records = audit$records)
  })
}

.dsvert_capsule_registry_status <- function(config, secret) {
  .dsvert_capsule_registry_with(config, secret, function(
      connection, config, secret) {
    state <- .dsvert_capsule_registry_validate_head(
      connection, config, secret)
    .dsvert_capsule_registry_summary(config, state$capsule_count)
  })
}

.dsvert_capsule_registry_lookup <- function(config, capsule_id, secret) {
  entry <- .dsvert_capsule_registry_entry(config, capsule_id, secret)
  if (is.null(entry)) NULL else entry$record
}

.dsvert_capsule_registry_reuse <- function(
    record, secret, expected_registry_id) {
  expected_registry_id <- .dsvert_capsule_registry_hex(
    expected_registry_id, "expected registry id")
  required <- c(
    "version", "registry_id", "capsule_id", "sequence", "identity",
    "capsule_epsilon", "capsule_delta", "operation_accounting",
    "capability_available", "record_mac")
  valid <- is.list(record) && !is.null(names(record)) && !anyNA(names(record)) &&
    !anyDuplicated(names(record)) && setequal(names(record), required) &&
    identical(record$version, .DSVERT_CAPSULE_RECORD_VERSION) &&
    identical(record$operation_accounting, "none") &&
    identical(record$capability_available, FALSE) &&
    is.numeric(record$sequence) && length(record$sequence) == 1L &&
    !is.na(record$sequence) && is.finite(record$sequence) &&
    record$sequence >= 0 && record$sequence == floor(record$sequence) &&
    is.numeric(record$capsule_epsilon) &&
    length(record$capsule_epsilon) == 1L && record$capsule_epsilon > 0 &&
    is.numeric(record$capsule_delta) &&
    length(record$capsule_delta) == 1L && record$capsule_delta >= 0 &&
    record$capsule_delta < 1 &&
    identical(.dsvert_capsule_registry_hex(
      record$registry_id, "registry id"), record$registry_id) &&
    identical(.dsvert_capsule_registry_hex(
      record$capsule_id, "capsule id"), record$capsule_id) &&
    identical(.dsvert_capsule_registry_hex(
      record$record_mac, "record MAC"), record$record_mac) &&
    is.list(record$identity)
  if (!isTRUE(valid)) {
    stop("Invalid authenticated capsule record for reuse.", call. = FALSE)
  }
  if (!identical(record$registry_id, expected_registry_id)) {
    stop("The capsule record does not match the expected registry context.",
         call. = FALSE)
  }
  if (!is.raw(secret) || length(secret) != 32L) {
    stop("Invalid capsule-registry reuse secret.", call. = FALSE)
  }
  supplied_mac <- record$record_mac
  material <- record[setdiff(names(record), "record_mac")]
  expected_mac <- .dsvert_capsule_registry_record_mac(
    secret, expected_registry_id, material)
  if (!identical(supplied_mac, expected_mac)) {
    stop("The capsule record failed authentication before reuse.",
         call. = FALSE)
  }
  record
}
