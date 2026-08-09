# Authenticated crash journal linking the cross-signed joint-DP allocator to
# the separate operation-independent capsule registry.  This remains internal:
# it authorizes no public capability. It mirrors the allocator's authenticated
# lifetime reservation boundary; it is not a request or session quota.

.DSVERT_JOINT_DP_REGISTRY_JOURNAL_VERSION <-
  "dsvert-joint-dp-capsule-registry-journal-v3"
.DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION <- "3"
.DSVERT_JOINT_DP_REGISTRY_STATE_VERSION <-
  "dsvert-joint-dp-capsule-registry-state-v3"
.DSVERT_JOINT_DP_REGISTRY_STATE_META_KEY <-
  "capsule_registry_state_version"

.dsvert_joint_dp_registry_meta_snapshot <- function(connection) {
  keys <- c(
    "capsule_registry_integration_version",
    .DSVERT_JOINT_DP_REGISTRY_STATE_META_KEY)
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT key, value FROM joint_meta WHERE key IN (?, ?)"),
    params = as.list(keys))
  if (anyDuplicated(rows$key) || any(!rows$key %in% keys)) {
    stop("The joint-DP capsule-registry metadata is invalid.",
         call. = FALSE)
  }
  stats::setNames(as.list(rows$value), rows$key)
}

.dsvert_joint_dp_registry_state_savepoint <- function(connection, code) {
  name <- "dsvert_registry_state_migration"
  DBI::dbExecute(connection, paste("SAVEPOINT", name))
  open <- TRUE
  on.exit(if (open) {
    try(DBI::dbExecute(
      connection, paste("ROLLBACK TO SAVEPOINT", name)), silent = TRUE)
    try(DBI::dbExecute(
      connection, paste("RELEASE SAVEPOINT", name)), silent = TRUE)
  }, add = TRUE)
  value <- force(code)
  DBI::dbExecute(connection, paste("RELEASE SAVEPOINT", name))
  open <- FALSE
  value
}

.dsvert_joint_dp_registry_journal_mac <- function(secret, value) {
  if (!is.raw(secret) || length(secret) != 32L) {
    stop("Invalid joint-DP capsule-registry journal secret.", call. = FALSE)
  }
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/joint-dp/capsule-registry-journal/v3|",
      .dsvert_dp_canonical_json(value))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_registry_state_material <- function(
    config, journal_count, registered_count, registry_head_chain) {
  journal_count <- .dsvert_joint_dp_index(
    journal_count, "capsule-registry journal count")
  registered_count <- .dsvert_joint_dp_index(
    registered_count, "registered capsule count")
  valid_head <- is.character(registry_head_chain) &&
    length(registry_head_chain) == 1L && !is.na(registry_head_chain) &&
    (identical(registry_head_chain, "GENESIS") ||
     grepl("^[0-9a-f]{64}$", registry_head_chain))
  if (journal_count > config$lifetime_max_distinct_capsules ||
      registered_count > journal_count || !isTRUE(valid_head) ||
      (registered_count == 0 &&
       !identical(registry_head_chain, "GENESIS")) ||
      (registered_count > 0 &&
       identical(registry_head_chain, "GENESIS"))) {
    stop("Invalid authenticated capsule-registry journal state.",
         call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_REGISTRY_STATE_VERSION,
    registry_id = config$registry_id,
    consortium_id = config$consortium_id,
    journal_count = as.numeric(journal_count),
    registered_count = as.numeric(registered_count),
    registry_head_chain = registry_head_chain,
    operation_accounting = "one_per_distinct_capsule_allocator_commit",
    operation_limit = TRUE,
    history_can_deny_operation = TRUE,
    capability_available = FALSE))
}

.dsvert_joint_dp_registry_state_mac <- function(secret, value) {
  if (!is.raw(secret) || length(secret) != 32L) {
    stop("Invalid joint-DP capsule-registry state secret.", call. = FALSE)
  }
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/joint-dp/capsule-registry-state/v3|",
      .dsvert_dp_canonical_json(value))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_registry_state_read <- function(
    connection, config, secret, allow_missing = FALSE) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT journal_count, registered_count, registry_head_chain, state_mac",
    "FROM joint_capsule_registry_state WHERE singleton = 1"))
  if (!nrow(row) && isTRUE(allow_missing)) return(NULL)
  material <- tryCatch({
    if (nrow(row) != 1L) stop("invalid")
    value <- .dsvert_joint_dp_registry_state_material(
      config, as.numeric(row$journal_count[[1L]]),
      as.numeric(row$registered_count[[1L]]),
      row$registry_head_chain[[1L]])
    supplied_mac <- row$state_mac[[1L]]
    if (!is.character(supplied_mac) || length(supplied_mac) != 1L ||
        !grepl("^[0-9a-f]{64}$", supplied_mac) ||
        !identical(supplied_mac,
                   .dsvert_joint_dp_registry_state_mac(secret, value))) {
      stop("invalid")
    }
    value
  }, error = function(error) NULL)
  if (is.null(material)) {
    stop("The joint-DP capsule-registry state failed its integrity check.",
         call. = FALSE)
  }
  material
}

.dsvert_joint_dp_registry_state_write <- function(
    connection, config, secret, journal_count, registered_count,
    registry_head_chain, insert = FALSE) {
  material <- .dsvert_joint_dp_registry_state_material(
    config, journal_count, registered_count, registry_head_chain)
  state_mac <- .dsvert_joint_dp_registry_state_mac(secret, material)
  if (isTRUE(insert)) {
    changed <- DBI::dbExecute(connection, paste(
      "INSERT INTO joint_capsule_registry_state(",
      "singleton, journal_count, registered_count, registry_head_chain,",
      "state_mac) VALUES(1, ?, ?, ?, ?)"), params = list(
        material$journal_count, material$registered_count,
        material$registry_head_chain, state_mac))
  } else {
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE joint_capsule_registry_state SET journal_count = ?,",
      "registered_count = ?, registry_head_chain = ?, state_mac = ?",
      "WHERE singleton = 1"), params = list(
        material$journal_count, material$registered_count,
        material$registry_head_chain, state_mac))
  }
  if (!identical(as.integer(changed), 1L)) {
    stop("The joint-DP capsule-registry state could not be persisted.",
         call. = FALSE)
  }
  material
}

.dsvert_joint_dp_registry_journal_material <- function(
    config, record, state = "pending", registry_chain_hash = NULL,
    registry_record_mac = NULL) {
  prepares <- if (is.list(record)) {
    list(record$own_prepare, record$peer_prepare)
  } else {
    list()
  }
  prepare_names <- if (length(prepares) == 2L &&
      all(vapply(prepares, is.list, logical(1L)))) {
    vapply(prepares, function(value) {
      if (is.character(value$peer_name) && length(value$peer_name) == 1L &&
          !is.na(value$peer_name) && nzchar(value$peer_name)) {
        value$peer_name
      } else {
        NA_character_
      }
    }, character(1L))
  } else {
    character()
  }
  valid_prepare_set <- length(prepare_names) == 2L &&
    !anyNA(prepare_names) && !anyDuplicated(prepare_names)
  if (isTRUE(valid_prepare_set)) {
    names(prepares) <- prepare_names
    prepares <- prepares[order(names(prepares), method = "radix")]
  }
  prepare_set_hash <- if (isTRUE(valid_prepare_set)) {
    .dsvert_joint_dp_hash(prepares)
  } else {
    NULL
  }
  own_commit <- if (is.list(record)) record$own_commit else NULL
  valid_commit <- is.list(own_commit) &&
    identical(own_commit$version, .DSVERT_JOINT_DP_COMMIT_VERSION) &&
    identical(own_commit$phase, "committed") &&
    identical(own_commit$capsule_id, record$query_id) &&
    identical(own_commit$query_id, record$query_id) &&
    identical(own_commit$allocation_index, record$allocation_index) &&
    identical(own_commit$previous_chain, record$previous_chain) &&
    identical(own_commit$new_chain, record$new_chain) &&
    identical(own_commit$joint_record_hash, record$joint_record_hash) &&
    identical(own_commit$prepare_set_hash, prepare_set_hash) &&
    identical(own_commit$seed_commitment,
              record$own_prepare$seed_commitment) &&
    identical(own_commit$peer_name, record$own_prepare$peer_name) &&
    is.character(own_commit$signature) &&
    length(own_commit$signature) == 1L && !is.na(own_commit$signature) &&
    nzchar(own_commit$signature)
  if (!is.list(record) ||
      !record$state %in% c(
        "locally_committed", "committed", "authorized", "open_authorized") ||
      !isTRUE(valid_prepare_set) || !isTRUE(valid_commit) ||
      !is.character(prepare_set_hash) ||
      !grepl("^[0-9a-f]{64}$", prepare_set_hash) ||
      !is.character(record$joint_record_hash) ||
      length(record$joint_record_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", record$joint_record_hash) ||
      !is.list(record$common_query$capsule_identity) ||
      !identical(record$query_id,
                 .dsvert_joint_dp_hash(
                   record$common_query$capsule_identity)) ||
      !state %in% c("pending", "registered")) {
    stop("Only a cross-signed joint-DP capsule can enter the registry journal.",
         call. = FALSE)
  }
  allocation_index <- .dsvert_joint_dp_index(record$allocation_index)
  if (allocation_index >= config$lifetime_max_distinct_capsules) {
    stop("The cross-signed allocator record exceeds its lifetime bound.",
         call. = FALSE)
  }
  if (identical(state, "pending")) {
    if (!all(vapply(
      list(registry_chain_hash, registry_record_mac), is.null, logical(1L)))) {
      stop("A pending capsule-registry journal row contains final state.",
           call. = FALSE)
    }
  } else {
    hashes <- c(registry_chain_hash, registry_record_mac)
    if (!is.character(hashes) || length(hashes) != 2L || anyNA(hashes) ||
        any(!grepl("^[0-9a-f]{64}$", hashes))) {
      stop("Invalid committed capsule-registry binding.", call. = FALSE)
    }
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_REGISTRY_JOURNAL_VERSION,
    registry_id = config$registry_id,
    consortium_id = config$consortium_id,
    capsule_id = record$query_id,
    query_id = record$query_id,
    identity_hash = .dsvert_joint_dp_hash(
      record$common_query$capsule_identity),
    allocator_sequence = as.character(allocation_index),
    registry_sequence = as.character(allocation_index),
    joint_record_hash = record$joint_record_hash,
    prepare_set_hash = prepare_set_hash,
    own_commit_hash = .dsvert_joint_dp_hash(own_commit),
    reservation_evidence =
      "two_signed_prepares_plus_own_signed_commit",
    state = state,
    registry_chain_hash = registry_chain_hash,
    registry_record_mac = registry_record_mac,
    operation_accounting = "one_per_distinct_capsule_allocator_commit",
    operation_limit = TRUE,
    history_can_deny_operation = TRUE,
    capability_available = FALSE))
}

.dsvert_joint_dp_registry_journal_decode <- function(
    row, config, record, secret) {
  required <- c(
    "query_id", "allocator_sequence", "state", "registry_sequence",
    "journal_json", "row_mac")
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !setequal(names(row), required)) {
    stop("The joint-DP capsule-registry journal row is invalid.",
         call. = FALSE)
  }
  value <- tryCatch(
    jsonlite::fromJSON(row$journal_json[[1L]], simplifyVector = FALSE),
    error = function(error) NULL)
  if (!is.list(value) || is.null(names(value)) || anyDuplicated(names(value)) ||
      !identical(row$journal_json[[1L]],
                 .dsvert_dp_canonical_json(value)) ||
      !identical(row$row_mac[[1L]],
                 .dsvert_joint_dp_registry_journal_mac(secret, value)) ||
      !identical(value$query_id, row$query_id[[1L]]) ||
      !identical(value$state, row$state[[1L]]) ||
      !identical(as.numeric(value$allocator_sequence),
                 as.numeric(row$allocator_sequence[[1L]])) ||
      !identical(
        if (is.null(value$registry_sequence)) NA_real_ else
          as.numeric(value$registry_sequence),
        if (is.na(row$registry_sequence[[1L]])) NA_real_ else
          as.numeric(row$registry_sequence[[1L]]))) {
    stop("The joint-DP capsule-registry journal failed authentication.",
         call. = FALSE)
  }
  expected <- .dsvert_joint_dp_registry_journal_material(
    config, record, value$state, value$registry_chain_hash,
    value$registry_record_mac)
  if (!identical(value, expected)) {
    stop("The joint-DP allocator and capsule-registry journal diverged.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_registry_journal_ensure <- function(
    connection, policy, context, record, secret) {
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  state <- .dsvert_joint_dp_registry_state_ensure(
    connection, policy, context, secret)
  pending <- .dsvert_joint_dp_registry_journal_material(config, record)
  existing <- DBI::dbGetQuery(connection, paste(
    "SELECT query_id, allocator_sequence, state, registry_sequence,",
    "journal_json, row_mac FROM joint_capsule_registry",
    "WHERE query_id = ?"), params = list(record$query_id))
  if (nrow(existing)) {
    observed <- .dsvert_joint_dp_registry_journal_decode(
      existing, config, record, secret)
    immutable <- c(
      "version", "registry_id", "consortium_id", "capsule_id",
      "query_id", "identity_hash", "allocator_sequence", "joint_record_hash",
      "registry_sequence", "prepare_set_hash", "own_commit_hash",
      "reservation_evidence", "operation_accounting", "operation_limit",
      "history_can_deny_operation", "capability_available")
    if (!identical(observed[immutable], pending[immutable])) {
      stop("Conflicting joint-DP capsule-registry journal replay.",
           call. = FALSE)
    }
    if (as.numeric(observed$allocator_sequence) >= state$journal_count) {
      stop("The allocator reservation journal is out of order.",
           call. = FALSE)
    }
    return(invisible(observed))
  }
  if (!identical(as.numeric(pending$allocator_sequence),
                 state$journal_count)) {
    stop("The allocator reservation journal is out of order.",
         call. = FALSE)
  }
  json <- .dsvert_dp_canonical_json(pending)
  changed <- DBI::dbExecute(connection, paste(
    "INSERT INTO joint_capsule_registry(",
    "query_id, allocator_sequence, state, registry_sequence,",
    "journal_json, row_mac) VALUES(?, ?, ?, ?, ?, ?)"), params = list(
      pending$query_id, as.numeric(pending$allocator_sequence),
      pending$state, as.numeric(pending$registry_sequence), json,
      .dsvert_joint_dp_registry_journal_mac(secret, pending)))
  if (!identical(as.integer(changed), 1L)) {
    stop("The allocator reservation journal could not be persisted.",
         call. = FALSE)
  }
  .dsvert_joint_dp_registry_state_write(
    connection, config, secret, state$journal_count + 1,
    state$registered_count, state$registry_head_chain)
  invisible(pending)
}

.dsvert_joint_dp_registry_journal_migrate <- function(
    connection, policy, context, secret) {
  metadata <- .dsvert_joint_dp_registry_meta_snapshot(connection)
  version <- metadata[["capsule_registry_integration_version"]]
  state_marker <- metadata[[.DSVERT_JOINT_DP_REGISTRY_STATE_META_KEY]]
  if (!is.null(state_marker) &&
      !identical(version,
                 .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)) {
    stop("The joint-DP capsule-registry integration is incomplete.",
         call. = FALSE)
  }
  if (!is.null(version) &&
      !identical(version,
                 .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)) {
    stop("Unsupported joint-DP capsule-registry integration version.",
         call. = FALSE)
  }
  if (identical(version,
                .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)) {
    .dsvert_joint_dp_registry_state_ensure(
      connection, policy, context, secret, version, state_marker)
    return(invisible(TRUE))
  }
  .dsvert_joint_dp_registry_state_ensure(
    connection, policy, context, secret)
  rows <- DBI::dbGetQuery(
    connection, "SELECT * FROM joint_records ORDER BY sequence")
  if (nrow(rows)) for (index in seq_len(nrow(rows))) {
    record <- .dsvert_joint_dp_record_decode(
      rows[index, , drop = FALSE], secret)
    if (!identical(record$state, "prepared")) {
      .dsvert_joint_dp_registry_journal_ensure(
        connection, policy, context, record, secret)
    }
  }
  if (is.null(version)) {
    .dsvert_joint_dp_meta_set(
      connection, "capsule_registry_integration_version",
      .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)
  }
  .dsvert_joint_dp_registry_journal_audit(
    connection, policy, context, secret, require_enabled = TRUE)
  .dsvert_joint_dp_meta_set(
    connection, .DSVERT_JOINT_DP_REGISTRY_STATE_META_KEY,
    .DSVERT_JOINT_DP_REGISTRY_STATE_VERSION)
  invisible(TRUE)
}

.dsvert_joint_dp_registry_journal_audit <- function(
    connection, policy, context, secret, require_enabled = FALSE) {
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  version <- .dsvert_joint_dp_meta_get(
    connection, "capsule_registry_integration_version")
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT query_id, allocator_sequence, state, registry_sequence,",
    "journal_json, row_mac FROM joint_capsule_registry",
    "ORDER BY allocator_sequence"))
  if (is.null(version)) {
    persisted_state <- .dsvert_joint_dp_registry_state_read(
      connection, config, secret, allow_missing = TRUE)
    if (nrow(rows) || !is.null(persisted_state) || isTRUE(require_enabled)) {
      stop("The joint-DP capsule-registry integration is incomplete.",
           call. = FALSE)
    }
    return(list(
      config = config, journals = list(), records = list(),
      state = .dsvert_joint_dp_registry_state_material(
        config, 0, 0, "GENESIS")))
  }
  if (!identical(version,
                 .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)) {
    stop("Unsupported joint-DP capsule-registry integration version.",
         call. = FALSE)
  }
  eligible_rows <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM joint_records WHERE state <> 'prepared'",
    "ORDER BY sequence"))
  eligible <- list()
  if (nrow(eligible_rows)) for (index in seq_len(nrow(eligible_rows))) {
    record <- .dsvert_joint_dp_record_decode(
      eligible_rows[index, , drop = FALSE], secret)
    eligible[[record$query_id]] <- record
  }
  if (!setequal(rows$query_id, names(eligible)) ||
      nrow(rows) != length(eligible)) {
    stop("The cross-signed allocator and capsule-registry journal are incomplete.",
         call. = FALSE)
  }
  journals <- vector("list", nrow(rows))
  names(journals) <- rows$query_id
  if (nrow(rows)) for (index in seq_len(nrow(rows))) {
    query_id <- rows$query_id[[index]]
    journals[[query_id]] <- .dsvert_joint_dp_registry_journal_decode(
      rows[index, , drop = FALSE], config, eligible[[query_id]], secret)
  }
  sequences <- if (length(journals)) {
    unname(vapply(journals, function(value) {
      as.numeric(value$allocator_sequence)
    }, numeric(1L)))
  } else {
    numeric()
  }
  registry_sequences <- if (length(journals)) {
    unname(vapply(journals, function(value) {
      as.numeric(value$registry_sequence)
    }, numeric(1L)))
  } else {
    numeric()
  }
  expected_sequences <- if (length(journals)) {
    as.numeric(seq.int(0L, length(journals) - 1L))
  } else {
    numeric()
  }
  if (!identical(sequences, expected_sequences) ||
      !identical(registry_sequences, expected_sequences)) {
    stop("The authenticated allocator reservation sequence is discontinuous.",
         call. = FALSE)
  }
  registered <- Filter(
    function(value) identical(value$state, "registered"), journals)
  registered_sequences <- if (length(registered)) unname(sort(vapply(
    registered, function(value) as.numeric(value$registry_sequence),
    numeric(1L)))) else numeric()
  if (length(registered_sequences) &&
      !identical(registered_sequences, as.numeric(seq.int(
        0L, length(registered_sequences) - 1L)))) {
    stop("The authenticated capsule-registry sequence is discontinuous.",
         call. = FALSE)
  }
  registered <- if (length(registered)) registered[order(vapply(
    registered, function(value) as.numeric(value$registry_sequence),
    numeric(1L)))] else list()
  head <- if (length(registered)) {
    registered[[length(registered)]]$registry_chain_hash
  } else {
    "GENESIS"
  }
  derived_state <- .dsvert_joint_dp_registry_state_material(
    config, length(journals), length(registered), head)
  persisted_state <- .dsvert_joint_dp_registry_state_read(
    connection, config, secret, allow_missing = TRUE)
  if (!is.null(persisted_state) &&
      !identical(persisted_state, derived_state)) {
    stop("The authenticated capsule-registry journal state is inconsistent.",
         call. = FALSE)
  }
  list(
    config = config, journals = journals, records = eligible,
    state = derived_state)
}

.dsvert_joint_dp_registry_state_ensure <- function(
    connection, policy, context, secret, version = NULL,
    state_marker = NULL) {
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  if (is.null(version) && is.null(state_marker)) {
    metadata <- .dsvert_joint_dp_registry_meta_snapshot(connection)
    version <- metadata[["capsule_registry_integration_version"]]
    state_marker <- metadata[[.DSVERT_JOINT_DP_REGISTRY_STATE_META_KEY]]
  }
  if (!is.null(state_marker) &&
      !identical(state_marker, .DSVERT_JOINT_DP_REGISTRY_STATE_VERSION)) {
    stop("Unsupported joint-DP capsule-registry state version.",
         call. = FALSE)
  }
  if (!is.null(state_marker) &&
      !identical(version,
                 .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)) {
    stop("The joint-DP capsule-registry integration is incomplete.",
         call. = FALSE)
  }
  state <- .dsvert_joint_dp_registry_state_read(
    connection, config, secret, allow_missing = TRUE)
  if (identical(state_marker, .DSVERT_JOINT_DP_REGISTRY_STATE_VERSION)) {
    if (is.null(state)) {
      stop("The authenticated joint-DP capsule-registry state is missing.",
           call. = FALSE)
    }
    return(state)
  }
  if (identical(version,
                .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)) {
    return(.dsvert_joint_dp_registry_state_savepoint(connection, {
      audit <- .dsvert_joint_dp_registry_journal_audit(
        connection, policy, context, secret, require_enabled = TRUE)
      if (is.null(state)) {
        state <- .dsvert_joint_dp_registry_state_write(
          connection, config, secret, audit$state$journal_count,
          audit$state$registered_count, audit$state$registry_head_chain,
          insert = TRUE)
      }
      .dsvert_joint_dp_meta_set(
        connection, .DSVERT_JOINT_DP_REGISTRY_STATE_META_KEY,
        .DSVERT_JOINT_DP_REGISTRY_STATE_VERSION)
      state
    }))
  }
  if (!is.null(version)) {
    stop("Unsupported joint-DP capsule-registry integration version.",
         call. = FALSE)
  }
  if (!is.null(state)) return(state)
  has_journal <- nrow(DBI::dbGetQuery(
    connection, "SELECT 1 FROM joint_capsule_registry LIMIT 1")) > 0L
  if (isTRUE(has_journal)) {
    stop("The joint-DP capsule-registry integration is incomplete.",
         call. = FALSE)
  }
  .dsvert_joint_dp_registry_state_write(
    connection, config, secret, 0, 0, "GENESIS", insert = TRUE)
}

.dsvert_joint_dp_registry_journal_validate_local <- function(
    connection, policy, context, secret, expected_journal_count = NULL) {
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  metadata <- .dsvert_joint_dp_registry_meta_snapshot(connection)
  version <- metadata[["capsule_registry_integration_version"]]
  state_marker <- metadata[[.DSVERT_JOINT_DP_REGISTRY_STATE_META_KEY]]
  if (is.null(version)) {
    has_journal <- nrow(DBI::dbGetQuery(
      connection, "SELECT 1 FROM joint_capsule_registry LIMIT 1")) > 0L
    state <- .dsvert_joint_dp_registry_state_read(
      connection, config, secret, allow_missing = TRUE)
    expected <- if (is.null(expected_journal_count)) 0 else
      .dsvert_joint_dp_index(
        expected_journal_count, "expected reservation journal count")
    if (isTRUE(has_journal) || !is.null(state) || !is.null(state_marker) ||
        expected != 0) {
      stop("The joint-DP capsule-registry integration is incomplete.",
           call. = FALSE)
    }
    return(invisible(TRUE))
  }
  if (!identical(version,
                 .DSVERT_JOINT_DP_REGISTRY_INTEGRATION_VERSION)) {
    stop("Unsupported joint-DP capsule-registry integration version.",
         call. = FALSE)
  }
  state <- .dsvert_joint_dp_registry_state_ensure(
    connection, policy, context, secret, version, state_marker)
  if (!is.null(expected_journal_count) &&
      !identical(state$journal_count,
                 .dsvert_joint_dp_index(
                   expected_journal_count,
                   "eligible capsule-registry journal count"))) {
    stop("The cross-signed allocator and capsule-registry journal are incomplete.",
         call. = FALSE)
  }
  invisible(state)
}

.dsvert_joint_dp_registry_registration_validate <- function(
    registration, journal, record) {
  valid <- is.list(registration) && is.list(registration$record) &&
    is.list(registration$binding) && is.list(registration$summary) &&
    is.list(registration$allocator_admission) &&
    identical(registration$record$capsule_id, journal$capsule_id) &&
    identical(
      .dsvert_dp_canonical_json(registration$record$identity$contract),
      .dsvert_dp_canonical_json(record$common_query$capsule_identity)) &&
    identical(registration$record$registry_id, journal$registry_id) &&
    identical(registration$record$operation_accounting, "none") &&
    identical(registration$record$capability_available, FALSE) &&
    identical(registration$summary$operation_limit, TRUE) &&
    identical(registration$summary$history_can_deny_operation, TRUE) &&
    identical(
      registration$summary$operation_accounting,
      "one_per_distinct_capsule_allocator_commit") &&
    identical(
      registration$allocator_admission$material$allocator_sequence,
      journal$allocator_sequence) &&
    identical(
      registration$allocator_admission$material$joint_record_hash,
      journal$joint_record_hash) &&
    identical(
      registration$allocator_admission$material$prepare_set_hash,
      journal$prepare_set_hash) &&
    identical(
      registration$allocator_admission$material$own_commit_hash,
      journal$own_commit_hash) &&
    identical(
      registration$allocator_admission$material$reservation_evidence,
      journal$reservation_evidence) &&
    identical(
      registration$allocator_admission$material$operation_limit, TRUE) &&
    identical(
      registration$allocator_admission$material$history_can_deny_operation,
      TRUE) &&
    identical(as.numeric(registration$binding$sequence),
              as.numeric(registration$record$sequence)) &&
    identical(as.numeric(registration$binding$sequence),
              as.numeric(journal$registry_sequence)) &&
    identical(as.numeric(journal$registry_sequence),
              as.numeric(journal$allocator_sequence)) &&
    is.character(registration$binding$chain_hash) &&
    grepl("^[0-9a-f]{64}$", registration$binding$chain_hash) &&
    is.character(registration$record$record_mac) &&
    grepl("^[0-9a-f]{64}$", registration$record$record_mac)
  if (!isTRUE(valid)) {
    stop("The capsule registry returned an invalid allocator binding.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_joint_dp_registry_admission <- function(
    config, journal, record, secret) {
  .dsvert_capsule_registry_allocator_admission(
    config,
    list(capsule_id = journal$capsule_id,
         contract = record$common_query$capsule_identity),
    as.numeric(journal$allocator_sequence), journal$joint_record_hash,
    journal$prepare_set_hash, journal$own_commit_hash, secret)
}

.dsvert_joint_dp_registry_journal_commit <- function(
    connection, policy, context, query_id, registration, secret) {
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  state <- .dsvert_joint_dp_registry_state_ensure(
    connection, policy, context, secret)
  record <- .dsvert_joint_dp_load(connection, query_id, secret)
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT query_id, allocator_sequence, state, registry_sequence,",
    "journal_json, row_mac FROM joint_capsule_registry WHERE query_id = ?"),
    params = list(query_id))
  if (is.null(record) || nrow(row) != 1L) {
    stop("The cross-signed capsule has no allocator journal entry.",
         call. = FALSE)
  }
  journal <- .dsvert_joint_dp_registry_journal_decode(
    row, config, record, secret)
  .dsvert_joint_dp_registry_registration_validate(
    registration, journal, record)
  committed <- .dsvert_joint_dp_registry_journal_material(
    config, record, "registered",
    registration$binding$chain_hash,
    registration$record$record_mac)
  if (identical(journal$state, "registered")) {
    if (!identical(journal, committed) ||
        as.numeric(journal$registry_sequence) >= state$registered_count) {
      stop("The allocator-registry binding changed after commit.",
           call. = FALSE)
    }
    return(invisible(journal))
  }
  if (!identical(as.numeric(committed$registry_sequence),
                 state$registered_count) ||
      state$registered_count >= state$journal_count) {
    stop("The allocator-registry journal transition is out of order.",
         call. = FALSE)
  }
  json <- .dsvert_dp_canonical_json(committed)
  changed <- DBI::dbExecute(connection, paste(
    "UPDATE joint_capsule_registry SET state = ?, registry_sequence = ?,",
    "journal_json = ?, row_mac = ? WHERE query_id = ? AND state = 'pending'"),
    params = list(
      committed$state, as.numeric(committed$registry_sequence), json,
      .dsvert_joint_dp_registry_journal_mac(secret, committed), query_id))
  if (!identical(as.integer(changed), 1L)) {
    stop("The allocator-registry journal lost its pending transition.",
         call. = FALSE)
  }
  .dsvert_joint_dp_registry_state_write(
    connection, config, secret, state$journal_count,
    state$registered_count + 1, committed$registry_chain_hash)
  invisible(committed)
}

.dsvert_joint_dp_registry_journal_entry <- function(
    connection, config, query_id, secret, row = NULL) {
  if (is.null(row)) {
    row <- DBI::dbGetQuery(connection, paste(
      "SELECT query_id, allocator_sequence, state, registry_sequence,",
      "journal_json, row_mac FROM joint_capsule_registry WHERE query_id = ?"),
      params = list(query_id))
  }
  record <- .dsvert_joint_dp_load(connection, query_id, secret)
  if (is.null(record) || nrow(row) != 1L) return(NULL)
  list(
    journal = .dsvert_joint_dp_registry_journal_decode(
      row, config, record, secret),
    record = record)
}

.dsvert_joint_dp_registry_journal_sequence_entry <- function(
    connection, config, registry_sequence, secret) {
  registry_sequence <- .dsvert_joint_dp_index(
    registry_sequence, "capsule-registry sequence")
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT query_id, allocator_sequence, state, registry_sequence,",
    "journal_json, row_mac FROM joint_capsule_registry",
    "WHERE state = 'registered' AND registry_sequence = ?"),
    params = list(registry_sequence))
  if (nrow(row) != 1L) return(NULL)
  .dsvert_joint_dp_registry_journal_entry(
    connection, config, row$query_id[[1L]], secret, row)
}

.dsvert_joint_dp_registry_target_validate <- function(
    registry_target, local_target) {
  if (is.null(registry_target) || is.null(local_target) ||
      !identical(local_target$journal$state, "registered")) {
    stop("The requested allocator-registry binding is inconsistent.",
         call. = FALSE)
  }
  journal <- local_target$journal
  .dsvert_joint_dp_registry_registration_validate(
    registry_target, journal, local_target$record)
  if (!identical(as.numeric(registry_target$record$sequence),
                 as.numeric(journal$registry_sequence)) ||
      !identical(registry_target$binding$chain_hash,
                 journal$registry_chain_hash) ||
      !identical(registry_target$record$record_mac,
                 journal$registry_record_mac)) {
    stop("The requested allocator-registry binding is inconsistent.",
         call. = FALSE)
  }
  invisible(journal)
}

.dsvert_joint_dp_capsule_registry_reconcile <- function(
    connection, policy, context, secret, query_id = NULL,
    phase_hook = NULL, verifier = NULL) {
  local <- .dsvert_joint_dp_transaction(connection, {
    .dsvert_joint_dp_registry_journal_migrate(
      connection, policy, context, secret)
    config <- .dsvert_capsule_registry_config_from_policy(policy)
    state <- .dsvert_joint_dp_registry_state_ensure(
      connection, policy, context, secret)
    target <- if (is.null(query_id)) NULL else
      .dsvert_joint_dp_registry_journal_entry(
        connection, config, query_id, secret)
    list(config = config, state = state, target = target)
  })
  if (!is.null(query_id) && is.null(local$target)) {
    stop("The requested capsule is not cross-signed in the allocator journal.",
         call. = FALSE)
  }
  registry_view <- .dsvert_capsule_registry_bound_state_entry(
    local$config, secret, query_id)
  registry_state <- registry_view[c("summary", "head_chain")]
  registry_count <- registry_state$summary$capsule_count
  if (registry_count > local$state$journal_count) {
    stop("The capsule registry contains an entry without a cross-signed allocator journal.",
         call. = FALSE)
  }
  if (identical(registry_count, local$state$registered_count) &&
      identical(local$state$journal_count,
                local$state$registered_count) &&
      identical(registry_state$head_chain,
                local$state$registry_head_chain) &&
      identical(registry_state$summary$operation_limit, TRUE) &&
      identical(registry_state$summary$history_can_deny_operation, TRUE)) {
    binding <- NULL
    if (!is.null(query_id)) {
      binding <- .dsvert_joint_dp_registry_target_validate(
        registry_view$entry, local$target)
    }
    .dsvert_joint_dp_phase(phase_hook, "after_capsule_registry_reconcile")
    return(list(
      binding = binding,
      summary = registry_state$summary,
      operation_limit = TRUE,
      history_can_deny_operation = TRUE,
      capability_available = FALSE))
  }
  if (registry_count < local$state$registered_count) {
    expected_boundary <- if (registry_count == 0) {
      "GENESIS"
    } else {
      boundary <- .dsvert_joint_dp_registry_journal_sequence_entry(
        connection, local$config, registry_count - 1, secret)
      if (is.null(boundary)) {
        stop("The allocator lacks its authenticated registry boundary.",
             call. = FALSE)
      }
      boundary$journal$registry_chain_hash
    }
    if (!identical(registry_state$head_chain, expected_boundary)) {
      stop("The capsule registry rollback does not match the authenticated allocator boundary.",
           call. = FALSE)
    }
    suffix <- DBI::dbGetQuery(connection, paste(
      "SELECT query_id, allocator_sequence, state, registry_sequence,",
      "journal_json, row_mac FROM joint_capsule_registry",
      "WHERE state = 'registered' AND registry_sequence >= ?",
      "ORDER BY registry_sequence"), params = list(registry_count))
    expected_suffix <- local$state$registered_count - registry_count
    if (!identical(as.numeric(nrow(suffix)), expected_suffix)) {
      stop("The allocator registry-recovery suffix is incomplete.",
           call. = FALSE)
    }
    if (nrow(suffix)) for (position in seq_len(nrow(suffix))) {
      entry <- .dsvert_joint_dp_registry_journal_entry(
        connection, local$config, suffix$query_id[[position]], secret,
        suffix[position, , drop = FALSE])
      if (is.null(entry)) {
        stop("The allocator registry-recovery suffix is incomplete.",
             call. = FALSE)
      }
      journal <- entry$journal
      record <- entry$record
      registration <- .dsvert_capsule_registry_register_bound(
        local$config,
        list(capsule_id = journal$capsule_id,
             contract = record$common_query$capsule_identity),
        .dsvert_joint_dp_registry_admission(
          local$config, journal, record, secret),
        secret)
      .dsvert_joint_dp_registry_registration_validate(
        registration, journal, record)
      if (!identical(as.numeric(registration$record$sequence),
                     as.numeric(journal$registry_sequence)) ||
          !identical(registration$binding$chain_hash,
                     journal$registry_chain_hash) ||
          !identical(registration$record$record_mac,
                     journal$registry_record_mac)) {
        stop("The capsule registry could not recover its authenticated suffix.",
             call. = FALSE)
      }
    }
    registry_state <- .dsvert_capsule_registry_bound_integrity_state(
      local$config, secret)
    registry_count <- registry_state$summary$capsule_count
  }

  while (registry_count > local$state$registered_count) {
    registration <- .dsvert_capsule_registry_bound_sequence(
      local$config, local$state$registered_count, secret)
    if (is.null(registration)) {
      stop("The capsule registry and pending allocator journal diverged.",
           call. = FALSE)
    }
    entry <- .dsvert_joint_dp_registry_journal_entry(
      connection, local$config, registration$record$capsule_id, secret)
    if (is.null(entry) || !identical(entry$journal$state, "pending")) {
      stop("The capsule registry and pending allocator journal diverged.",
           call. = FALSE)
    }
    journal <- entry$journal
    record <- entry$record
    .dsvert_joint_dp_registry_registration_validate(
      registration, journal, record)
    .dsvert_joint_dp_phase(phase_hook, "after_capsule_registry_register")
    local$state <- .dsvert_joint_dp_transaction(connection, {
      .dsvert_joint_dp_registry_journal_commit(
        connection, policy, context, journal$capsule_id,
        registration, secret)
      .dsvert_joint_dp_registry_state_read(
        connection, local$config, secret)
    })
    .dsvert_joint_dp_phase(
      phase_hook, "after_capsule_registry_binding_commit")
  }

  if (registry_count != local$state$registered_count ||
      !identical(registry_state$head_chain,
                 local$state$registry_head_chain)) {
    stop("The allocator and capsule registry have divergent authenticated heads.",
         call. = FALSE)
  }

  pending <- DBI::dbGetQuery(connection, paste(
    "SELECT query_id, allocator_sequence, state, registry_sequence,",
    "journal_json, row_mac FROM joint_capsule_registry",
    "WHERE state = 'pending' ORDER BY allocator_sequence"))
  if (nrow(pending)) for (position in seq_len(nrow(pending))) {
    entry <- .dsvert_joint_dp_registry_journal_entry(
      connection, local$config, pending$query_id[[position]], secret,
      pending[position, , drop = FALSE])
    if (is.null(entry)) {
      stop("The pending capsule-registry journal is incomplete.",
           call. = FALSE)
    }
    journal <- entry$journal
    record <- entry$record
    registration <- .dsvert_capsule_registry_register_bound(
      local$config,
      list(capsule_id = journal$capsule_id,
           contract = record$common_query$capsule_identity),
      .dsvert_joint_dp_registry_admission(
        local$config, journal, record, secret),
      secret)
    .dsvert_joint_dp_registry_registration_validate(
      registration, journal, record)
    .dsvert_joint_dp_phase(phase_hook, "after_capsule_registry_register")
    local$state <- .dsvert_joint_dp_transaction(connection, {
      .dsvert_joint_dp_registry_journal_commit(
        connection, policy, context, journal$capsule_id,
        registration, secret)
      .dsvert_joint_dp_registry_state_read(
        connection, local$config, secret)
    })
    .dsvert_joint_dp_phase(
      phase_hook, "after_capsule_registry_binding_commit")
  }

  local$state <- .dsvert_joint_dp_registry_state_read(
    connection, local$config, secret)
  final_state <- .dsvert_capsule_registry_bound_integrity_state(
    local$config, secret)
  if (!identical(local$state$journal_count,
                 local$state$registered_count) ||
      !identical(final_state$summary$capsule_count,
                 local$state$registered_count) ||
      !identical(final_state$head_chain,
                 local$state$registry_head_chain) ||
      !identical(final_state$summary$operation_limit, TRUE) ||
      !identical(final_state$summary$history_can_deny_operation, TRUE)) {
    stop("The allocator and capsule registry failed final reconciliation.",
         call. = FALSE)
  }
  if (!is.null(query_id)) {
    target <- .dsvert_capsule_registry_bound_entry(
      local$config, query_id, secret)
    local_target <- .dsvert_joint_dp_registry_journal_entry(
      connection, local$config, query_id, secret)
    journal <- .dsvert_joint_dp_registry_target_validate(
      target, local_target)
  }
  .dsvert_joint_dp_phase(phase_hook, "after_capsule_registry_reconcile")
  binding <- if (is.null(query_id)) NULL else journal
  list(
    binding = binding,
    summary = final_state$summary,
    operation_limit = TRUE,
    history_can_deny_operation = TRUE,
    capability_available = FALSE)
}
