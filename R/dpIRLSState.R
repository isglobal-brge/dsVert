# Internal B1 public-only state machine. No source reads, MPC or remote method.
# Each authority has its own pre-provisioned store and independently runs Go.

.dsvert_dp_irls_state_json <- function(value) {
  .dsvert_dp_canonical_json(.dsvert_dp_analysis_canonical_value_v1(value))
}

.dsvert_dp_irls_state_decode <- function(bytes) {
  if (!is.character(bytes) || length(bytes) != 1L || is.na(bytes) ||
      nchar(bytes, type = "bytes") > 16L * 1024L^2)
    stop("Invalid IRLS canonical record.", call. = FALSE)
  value <- jsonlite::fromJSON(bytes, simplifyVector = FALSE)
  if (!identical(.dsvert_dp_irls_state_json(value), bytes))
    stop("Noncanonical IRLS record.", call. = FALSE)
  value
}

.dsvert_dp_irls_stage_message <- function(body) {
  charToRaw(paste0("dsvert-v3-irls-successor-v1|",
                  .dsvert_dp_irls_state_json(body)))
}

.dsvert_dp_irls_stage_signatures <- function(stage, contract, complete = TRUE) {
  if (!is.list(stage) || !setequal(names(stage), c("body", "signatures")) ||
      anyDuplicated(names(stage)) || !is.list(stage$signatures) ||
      is.null(names(stage$signatures)) || anyDuplicated(names(stage$signatures)))
    stop("Invalid IRLS stage envelope.", call. = FALSE)
  pair <- unlist(contract$privacy_source$computation_peers, use.names = FALSE)
  pins <- contract$privacy_source$peer_pins
  peers <- names(stage$signatures)
  if ((!length(peers)) || !all(peers %in% pair) ||
      (complete && !setequal(peers, pair)))
    stop("IRLS stage requires designated authority signatures.", call. = FALSE)
  message <- .dsvert_dp_irls_stage_message(stage$body)
  for (peer in peers) {
    if (!isTRUE(.dsvert_relay_verify_message(message, pins[[peer]],
                                            stage$signatures[[peer]])))
      stop("Invalid IRLS stage signature or pin.", call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_irls_go_update <- function(request) {
  binary <- Sys.getenv("DS_VERT_MPC")
  if (!nzchar(binary) || !file.exists(binary))
    stop("The pinned IRLS arithmetic binary is unavailable.", call. = FALSE)
  input_file <- tempfile("irls-public-update-", tmpdir = tempdir())
  on.exit(unlink(input_file), add = TRUE)
  writeBin(charToRaw(.dsvert_dp_irls_state_json(request)), input_file)
  run <- processx::run(binary, "dp-irls-update", stdin = input_file,
                      timeout = 60000L, error_on_status = FALSE)
  if (run$status != 0L)
    stop("IRLS exact update rejected: ", trimws(run$stderr), call. = FALSE)
  .dsvert_dp_irls_state_decode(run$stdout)
}

.dsvert_dp_irls_stage_body <- function(contract, t, predecessor, payload,
                                      chain, candidate_beta = NULL,
                                      update = .dsvert_dp_irls_go_update) {
  id <- .dsvert_dp_irls_stage_id(contract, t, predecessor)
  index <- as.integer(t)
  if (length(chain) != index)
    stop("IRLS predecessor chain length mismatch.", call. = FALSE)
  expected_predecessor <- if (index == 0L) {
    .dsvert_dp_irls_start_digest(contract)
  } else chain[[index]]$body$payload_digest
  if (!identical(predecessor, expected_predecessor))
    stop("Alternate IRLS predecessor rejected.", call. = FALSE)
  beta <- if (index == 0L) contract$path$start$beta else
    chain[[index]]$body$update_result$beta
  if (!is.null(candidate_beta) && !identical(
      .dsvert_dp_irls_state_json(beta), .dsvert_dp_irls_state_json(candidate_beta)))
    stop("Alternate IRLS beta rejected.", call. = FALSE)
  payload_digest <- .dsvert_dp_irls_payload_digest(contract, t, payload)
  H <- payload[["H"]]
  if (is.null(H)) {
    ref <- payload[["H_reference"]]
    matches <- which(vapply(chain, function(stage) {
      identical(stage$body$stage_id, ref$stage_id) &&
        identical(stage$body$payload_digest, ref$payload_digest) &&
        !is.null(stage$body$payload[["H"]])
    }, logical(1L)))
    # The refresh schedule identifies the most recent signed curvature release.
    refreshed <- which(vapply(chain, function(stage)
      !is.null(stage$body$payload[["H"]]), logical(1L)))
    if (length(matches) != 1L || !length(refreshed) ||
        matches != tail(refreshed, 1L))
      stop("Invalid IRLS signed prior-H reference.", call. = FALSE)
    H <- chain[[matches]]$body$payload[["H"]]
  }
  purpose <- if (index == as.integer(contract$path$T))
    "terminal-audit" else "optimizer"
  input <- result <- NULL
  if (purpose == "optimizer") {
    numeric <- contract$numeric
    path <- contract$path
    input <- list(beta = beta, box_lower = path$box$lower,
      box_upper = path$box$upper, damping = path$damping[[index + 1L]],
      floor = path$floor, floor_quantum = path$floor_quantum,
      g = payload$g, g_translation = numeric$translation$g,
      g_unit = numeric$lattice$g, h = H,
      h_translation = numeric$translation$H, h_unit = numeric$lattice$H,
      lattice = numeric$lattice$beta, limits = numeric$certificate,
      ridge = path$ridge, trust = path$trust[[index + 1L]],
      version = path$update_version)
    result <- update(input)
  }
  list(root = .dsvert_dp_irls_root(contract), t = t, purpose = purpose,
    stage_id = id, predecessor = predecessor, payload = payload,
    payload_digest = payload_digest, beta = beta, update_input = input,
    update_result = result, update_version_digest = .dsvert_dp_irls_hash(
      "dsvert-v3-irls-update-version-v1", contract$path$update_version))
}

.dsvert_dp_irls_store_open <- function(path, code) {
  # Opening a missing store must never silently create a new reservation space.
  if (!is.character(path) || length(path) != 1L || !file.exists(path) ||
      dir.exists(path) || nzchar(Sys.readlink(path)))
    stop("IRLS reservation store missing or invalid; recovery required.", call. = FALSE)
  .dsvert_dp_assert_private_file(path, "IRLS reservation store", TRUE)
  lock <- filelock::lock(paste0(path, ".lock"), timeout = 30000L)
  if (is.null(lock)) stop("IRLS reservation store busy.", call. = FALSE)
  on.exit(filelock::unlock(lock), add = TRUE)
  db <- DBI::dbConnect(RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RW)
  on.exit(DBI::dbDisconnect(db), add = TRUE)
  DBI::dbExecute(db, "PRAGMA synchronous=FULL")
  DBI::dbExecute(db, "PRAGMA busy_timeout=30000")
  if (!identical(DBI::dbGetQuery(db, "PRAGMA quick_check")[[1L]], "ok"))
    stop("Corrupt IRLS reservation store; recovery required.", call. = FALSE)
  code(db)
}

.dsvert_dp_irls_store_create <- function(path, signed_contract, trusted_pins,
                                        authority) {
  contract <- .dsvert_dp_irls_contract_validate(signed_contract, trusted_pins)
  if (!authority %in% unlist(contract$privacy_source$computation_peers, use.names = FALSE))
    stop("Invalid IRLS authority.", call. = FALSE)
  # Validate the signed arithmetic certificate for every damping/trust setting
  # before reserving any path. These public zero-decoded probes never draw noise.
  probes <- list()
  for (i in seq_len(as.integer(contract$path$T)) - 1L) {
    payload <- list(g = contract$numeric$translation$g)
    if (contract$path$refresh_mask[[i + 1L]] == "1") {
      payload[["H"]] <- contract$numeric$translation$H
    } else {
      previous_h <- tail(which(vapply(probes, function(x)
        !is.null(x$body$payload[["H"]]), logical(1L))), 1L)
      payload[["H_reference"]] <- probes[[previous_h]]$body[c("stage_id", "payload_digest")]
    }
    predecessor <- if (i == 0L) .dsvert_dp_irls_start_digest(contract) else
      probes[[i]]$body$payload_digest
    probes[[i + 1L]] <- list(body = .dsvert_dp_irls_stage_body(contract,
      as.character(i), predecessor, payload, probes))
  }
  # Explicit one-time provisioning. A persistent directory tombstone prevents
  # recreation after deleting only the database; backups must restore it.
  parent <- dirname(path)
  if (dir.exists(parent) || file.exists(parent))
    stop("IRLS store directory already provisioned; recover retained state.", call. = FALSE)
  old <- Sys.umask("0077")
  on.exit(Sys.umask(old), add = TRUE)
  if (!dir.create(parent, recursive = FALSE, mode = "0700"))
    stop("Cannot provision IRLS store.", call. = FALSE)
  db <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(db), add = TRUE)
  DBI::dbExecute(db, "PRAGMA journal_mode=DELETE")
  DBI::dbExecute(db, "PRAGMA synchronous=FULL")
  DBI::dbWithTransaction(db, {
    DBI::dbExecute(db, paste("CREATE TABLE context (root TEXT PRIMARY KEY,",
      "authority TEXT NOT NULL, contract TEXT NOT NULL, history_hash TEXT NOT NULL)"))
    DBI::dbExecute(db, paste("CREATE TABLE successors (root TEXT NOT NULL,",
      "t TEXT NOT NULL, prepared TEXT NOT NULL, committed TEXT,",
      "PRIMARY KEY (root,t))"))
    DBI::dbExecute(db, "INSERT INTO context VALUES (?,?,?,?)", params = list(
      .dsvert_dp_irls_root(contract), authority,
      .dsvert_dp_irls_state_json(signed_contract), .dsvert_dp_irls_store_hash(db)))
  })
  Sys.chmod(path, "0600")
  invisible(path)
}

.dsvert_dp_irls_store_hash <- function(db) {
  rows <- DBI::dbGetQuery(db, "SELECT * FROM successors ORDER BY root,t")
  records <- lapply(seq_len(nrow(rows)), function(i) {
    list(root = rows$root[[i]], t = rows$t[[i]], prepared = rows$prepared[[i]],
         committed = if (is.na(rows$committed[[i]])) NULL else rows$committed[[i]])
  })
  digest::digest(.dsvert_dp_irls_state_json(records), algo = "sha256",
                 serialize = FALSE)
}

.dsvert_dp_irls_store_seal <- function(db) {
  DBI::dbExecute(db, "UPDATE context SET history_hash=?",
                 params = list(.dsvert_dp_irls_store_hash(db)))
}

.dsvert_dp_irls_store_context <- function(db, signed_contract, trusted_pins) {
  contract <- .dsvert_dp_irls_contract_validate(signed_contract, trusted_pins)
  context <- DBI::dbGetQuery(db, "SELECT * FROM context")
  if (nrow(context) != 1L ||
      !identical(context$root, .dsvert_dp_irls_root(contract)) ||
      !identical(context$contract, .dsvert_dp_irls_state_json(signed_contract)) ||
      !identical(context$history_hash, .dsvert_dp_irls_store_hash(db)))
    stop("IRLS contract or frozen epoch splice rejected.", call. = FALSE)
  list(contract = contract, root = context$root, authority = context$authority)
}

.dsvert_dp_irls_store_chain <- function(db, context, before) {
  rows <- DBI::dbGetQuery(db, "SELECT * FROM successors WHERE root=?",
                         params = list(context$root))
  chain <- list()
  if (before > 0L) for (i in seq_len(before) - 1L) {
    row <- rows[rows$t == as.character(i), , drop = FALSE]
    if (nrow(row) != 1L || is.na(row$committed))
      stop("Prior IRLS stage is not durably dual-committed.", call. = FALSE)
    stage <- .dsvert_dp_irls_state_decode(row$committed)
    .dsvert_dp_irls_stage_signatures(stage, context$contract)
    expected <- .dsvert_dp_irls_stage_body(context$contract, as.character(i),
      stage$body$predecessor, stage$body$payload, chain,
      candidate_beta = stage$body$beta)
    if (!identical(.dsvert_dp_irls_state_json(expected),
                   .dsvert_dp_irls_state_json(stage$body)))
      stop("Corrupt IRLS predecessor chain.", call. = FALSE)
    chain[[length(chain) + 1L]] <- stage
  }
  chain
}

.dsvert_dp_irls_successor_prepare <- function(path, signed_contract, trusted_pins,
    t, predecessor, payload, identity_sk, candidate_beta = NULL,
    crash_after_prepare = FALSE) {
  .dsvert_dp_irls_store_open(path, function(db) {
    context <- .dsvert_dp_irls_store_context(db, signed_contract, trusted_pins)
    # stage_id validates the integer and signed purpose/schedule before coercion.
    .dsvert_dp_irls_stage_id(context$contract, t, predecessor)
    chain <- .dsvert_dp_irls_store_chain(db, context, as.integer(t))
    body <- .dsvert_dp_irls_stage_body(context$contract, t, predecessor,
                                     payload, chain, candidate_beta)
    existing <- DBI::dbGetQuery(db,
      "SELECT prepared,committed FROM successors WHERE root=? AND t=?",
      params = list(context$root, t))
    if (nrow(existing)) {
      retained <- .dsvert_dp_irls_state_decode(existing$prepared)
      .dsvert_dp_irls_stage_signatures(retained, context$contract, FALSE)
      if (!identical(.dsvert_dp_irls_state_json(retained$body),
                     .dsvert_dp_irls_state_json(body)))
        stop("IRLS single-successor reservation rejects a fork.", call. = FALSE)
      return(retained)
    }
    signature <- .dsvert_relay_sign_message(
      .dsvert_dp_irls_stage_message(body), identity_sk)
    stage <- list(body = body, signatures = stats::setNames(
      list(signature), context$authority))
    .dsvert_dp_irls_stage_signatures(stage, context$contract, FALSE)
    DBI::dbWithTransaction(db, {
      DBI::dbExecute(db,
      "INSERT INTO successors(root,t,prepared,committed) VALUES (?,?,?,NULL)",
      params = list(context$root, t, .dsvert_dp_irls_state_json(stage)))
      .dsvert_dp_irls_store_seal(db)
    })
    if (isTRUE(crash_after_prepare))
      stop("Simulated crash after durable IRLS PREPARE.", call. = FALSE)
    stage
  })
}

.dsvert_dp_irls_successor_commit <- function(path, signed_contract, trusted_pins,
                                            stages, crash_after_commit = FALSE) {
  .dsvert_dp_irls_store_open(path, function(db) {
    context <- .dsvert_dp_irls_store_context(db, signed_contract, trusted_pins)
    if (!is.list(stages) || length(stages) != 2L)
      stop("Two matching IRLS authority records required.", call. = FALSE)
    body <- .dsvert_dp_irls_state_json(stages[[1L]]$body)
    if (!identical(body, .dsvert_dp_irls_state_json(stages[[2L]]$body)))
      stop("IRLS authorities disagree on successor bytes.", call. = FALSE)
    signatures <- c(stages[[1L]]$signatures, stages[[2L]]$signatures)
    stage <- list(body = stages[[1L]]$body, signatures = signatures)
    .dsvert_dp_irls_stage_signatures(stage, context$contract)
    if (!identical(stage$body$root, context$root))
      stop("IRLS commit root mismatch.", call. = FALSE)
    existing <- DBI::dbGetQuery(db,
      "SELECT prepared,committed FROM successors WHERE root=? AND t=?",
      params = list(context$root, stage$body$t))
    if (nrow(existing) != 1L)
      stop("No durable IRLS reservation for commit.", call. = FALSE)
    retained <- .dsvert_dp_irls_state_decode(existing$prepared)
    .dsvert_dp_irls_stage_signatures(retained, context$contract, FALSE)
    if (!identical(body, .dsvert_dp_irls_state_json(retained$body)))
      stop("IRLS commit conflicts with reserved successor.", call. = FALSE)
    bytes <- .dsvert_dp_irls_state_json(stage)
    if (!is.na(existing$committed)) {
      if (!identical(existing$committed, bytes))
        stop("IRLS commit conflicts with retained bytes.", call. = FALSE)
      return(.dsvert_dp_irls_state_decode(existing$committed))
    }
    DBI::dbWithTransaction(db, {
      DBI::dbExecute(db,
      "UPDATE successors SET committed=? WHERE root=? AND t=?",
      params = list(bytes, context$root, stage$body$t))
      .dsvert_dp_irls_store_seal(db)
    })
    if (isTRUE(crash_after_commit))
      stop("Simulated crash after durable IRLS COMMIT.", call. = FALSE)
    .dsvert_dp_irls_state_decode(bytes)
  })
}

.dsvert_dp_irls_successor_accounting <- function(path, signed_contract,
                                               trusted_pins) {
  .dsvert_dp_irls_store_open(path, function(db) {
    context <- .dsvert_dp_irls_store_context(db, signed_contract, trusted_pins)
    rows <- DBI::dbGetQuery(db, "SELECT * FROM successors WHERE root=?",
                           params = list(context$root))
    observed <- lapply(seq_len(nrow(rows)), function(i) {
      stage <- .dsvert_dp_irls_state_decode(rows$prepared[[i]])
      .dsvert_dp_irls_stage_signatures(stage, context$contract, FALSE)
      list(t = stage$body$t, lanes = if (is.null(stage$body$payload[["H"]]))
        list("g") else list("g", "H"))
    })
    # A locally prepared payload could already be observable to an authority.
    # Count its lanes even when the parent never completes; retries add nothing.
    .dsvert_dp_irls_accounting(context$contract, observed)
  })
}
