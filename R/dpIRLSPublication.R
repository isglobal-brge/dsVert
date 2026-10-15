# Private B3 publication barrier. Child records are relay messages, not a
# publication API. Only a parent with both authorities' durable commit receipts
# can be read. B1 remains the authority for the successor and public arithmetic.

.dsvert_dp_irls_publication_hash <- function(db) {
  rows <- DBI::dbGetQuery(db, "SELECT key,value FROM records ORDER BY key")
  .dsvert_dp_irls_hash("dsvert-v3-irls-publication-store-v1", lapply(
    seq_len(nrow(rows)), function(i) as.list(rows[i, , drop = FALSE])))
}

.dsvert_dp_irls_publication_create <- function(path, signed_contract, trusted_pins, authority) {
  contract <- .dsvert_dp_irls_profile_admit(signed_contract, trusted_pins)$contract
  .dsvert_dp_irls_choice(authority, unlist(contract$privacy_source$computation_peers))
  parent <- dirname(path)
  if (file.exists(parent)) stop("Publication directory already provisioned; recover retained state.", call. = FALSE)
  old <- Sys.umask("0077"); on.exit(Sys.umask(old), add = TRUE)
  if (!dir.create(parent, mode = "0700")) stop("Cannot provision publication store.", call. = FALSE)
  db <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(db), add = TRUE)
  DBI::dbExecute(db, "PRAGMA journal_mode=DELETE")
  DBI::dbExecute(db, "PRAGMA synchronous=FULL")
  DBI::dbWithTransaction(db, {
    DBI::dbExecute(db, "CREATE TABLE context (root TEXT, authority TEXT, contract TEXT, history_hash TEXT)")
    DBI::dbExecute(db, "CREATE TABLE records (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    DBI::dbExecute(db, "INSERT INTO context VALUES (?,?,?,?)", params = list(
      .dsvert_dp_irls_root(contract), authority, .dsvert_dp_irls_state_json(signed_contract),
      .dsvert_dp_irls_publication_hash(db)))
  })
  Sys.chmod(path, "0600")
  invisible(path)
}

.dsvert_dp_irls_publication_open <- function(path, signed_contract, trusted_pins, code) {
  .dsvert_dp_irls_store_open(path, function(db) {
    contract <- .dsvert_dp_irls_profile_admit(signed_contract, trusted_pins)$contract
    context <- DBI::dbGetQuery(db, "SELECT * FROM context")
    if (nrow(context) != 1L || !identical(context$root, .dsvert_dp_irls_root(contract)) ||
        !identical(context$contract, .dsvert_dp_irls_state_json(signed_contract)) ||
        !identical(context$history_hash, .dsvert_dp_irls_publication_hash(db)))
      stop("Publication state corrupt or frozen epoch splice rejected.", call. = FALSE)
    .dsvert_dp_irls_choice(context$authority, unlist(contract$privacy_source$computation_peers))
    code(db, list(contract = contract, root = context$root, authority = context$authority))
  })
}

.dsvert_dp_irls_publication_get <- function(db, key, required = TRUE) {
  row <- DBI::dbGetQuery(db, "SELECT value FROM records WHERE key=?", params = list(key))
  if (!nrow(row)) {
    if (required) stop("Publication durable boundary not reached.", call. = FALSE)
    return(NULL)
  }
  .dsvert_dp_irls_state_decode(row$value)
}

.dsvert_dp_irls_publication_put <- function(db, key, value) {
  bytes <- .dsvert_dp_irls_state_json(value)
  old <- .dsvert_dp_irls_publication_get(db, key, FALSE)
  if (!is.null(old)) {
    if (!identical(.dsvert_dp_irls_state_json(old), bytes))
      stop("Publication replay conflicts with retained bytes.", call. = FALSE)
    return(old)
  }
  DBI::dbWithTransaction(db, {
    DBI::dbExecute(db, "INSERT INTO records VALUES (?,?)", params = list(key, bytes))
    DBI::dbExecute(db, "UPDATE context SET history_hash=?",
      params = list(.dsvert_dp_irls_publication_hash(db)))
  })
  .dsvert_dp_irls_state_decode(bytes)
}

.dsvert_dp_irls_receipt_message <- function(body) charToRaw(paste0(
  "dsvert-v3-irls-durable-receipt-v1|", .dsvert_dp_irls_state_json(body)))

.dsvert_dp_irls_receipt_check <- function(receipt, contract, complete = FALSE) {
  .dsvert_dp_irls_fields(receipt, c("body", "signatures"))
  pins <- contract$privacy_source$peer_pins
  peers <- names(receipt$signatures)
  if (!is.list(receipt$signatures) || !length(peers) || anyDuplicated(peers) ||
      !all(peers %in% names(pins)) ||
      (complete && !setequal(peers, unlist(contract$privacy_source$computation_peers))))
    stop("Invalid durable receipt authorities.", call. = FALSE)
  if (!identical(receipt$body$root, .dsvert_dp_irls_root(contract)) ||
      !identical(receipt$body$stage_id, .dsvert_dp_irls_stage_id(contract,
        receipt$body$t, receipt$body$predecessor)))
    stop("Durable receipt purpose mismatch.", call. = FALSE)
  for (peer in peers) if (!isTRUE(.dsvert_relay_verify_message(
      .dsvert_dp_irls_receipt_message(receipt$body), pins[[peer]], receipt$signatures[[peer]])))
    stop("Invalid durable receipt signature.", call. = FALSE)
  invisible(TRUE)
}

.dsvert_dp_irls_receipt_sign <- function(body, context, identity_sk) {
  receipt <- list(body = body, signatures = stats::setNames(list(
    .dsvert_relay_sign_message(.dsvert_dp_irls_receipt_message(body), identity_sk)), context$authority))
  .dsvert_dp_irls_receipt_check(receipt, context$contract)
  receipt
}

.dsvert_dp_irls_receipt_pair <- function(receipts, contract, kind) {
  if (!is.list(receipts) || length(receipts) != 2L)
    stop("Two durable authority receipts required.", call. = FALSE)
  for (r in receipts) {
    .dsvert_dp_irls_receipt_check(r, contract)
    if (!identical(r$body$kind, kind)) stop("Wrong durable receipt boundary.", call. = FALSE)
  }
  if (!identical(.dsvert_dp_irls_state_json(receipts[[1L]]$body),
      .dsvert_dp_irls_state_json(receipts[[2L]]$body)))
    stop("Authorities disagree on durable bytes.", call. = FALSE)
  r <- list(body = receipts[[1L]]$body,
    signatures = c(receipts[[1L]]$signatures, receipts[[2L]]$signatures))
  .dsvert_dp_irls_receipt_check(r, contract, TRUE)
  .dsvert_dp_irls_state_decode(.dsvert_dp_irls_state_json(r))
}

.dsvert_dp_irls_boundary_body <- function(context, t, predecessor, kind) list(
  version = "dsvert-dp-irls-durable-receipt-v1", kind = kind, root = context$root,
  t = t, predecessor = predecessor,
  stage_id = .dsvert_dp_irls_stage_id(context$contract, t, predecessor))

.dsvert_dp_irls_lane_prepare <- function(path, signed_contract, trusted_pins,
    t, predecessor, lane, values, identity_sk, crash_after = FALSE) {
  .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    .dsvert_dp_irls_choice(lane, c("g", "H"))
    contract <- ctx$contract
    if (!.dsvert_dp_irls_stage(contract, t)$refresh)
      stop("B3 publication requires both budgeted lanes.", call. = FALSE)
    values <- .dsvert_dp_irls_array(values, length(contract$numeric$upper_limits[[lane]]))
    for (i in seq_along(values)) .dsvert_dp_irls_int(values[[i]], "0", contract$numeric$upper_limits[[lane]][[i]])
    a <- contract$accounting$stages[[as.integer(t) + 1L]]
    body <- c(.dsvert_dp_irls_boundary_body(ctx, t, predecessor, "lane-prepared"), list(
      lane = lane, lane_id = .dsvert_dp_irls_lane_id(.dsvert_dp_irls_stage_id(contract, t, predecessor), lane),
      values = values, epsilon = a[[lane]], sensitivity = contract$accounting$sensitivity[[lane]],
      alpha = a[[paste0("alpha_", lane)]], translation = contract$numeric$translation[[lane]],
      lattice = contract$numeric$lattice[[lane]], sampler = contract$numeric$sampler_version))
    receipt <- .dsvert_dp_irls_receipt_sign(body, ctx, identity_sk)
    retained <- .dsvert_dp_irls_publication_put(db, paste("lane", t, lane, "prepare", sep = "/"), receipt)
    if (isTRUE(crash_after)) stop("Simulated crash after durable lane PREPARE.", call. = FALSE)
    retained
  })
}

.dsvert_dp_irls_lane_commit <- function(path, signed_contract, trusted_pins,
    receipts, identity_sk, crash_after = FALSE) {
  .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    pair <- .dsvert_dp_irls_receipt_pair(receipts, ctx$contract, "lane-prepared")
    b <- pair$body
    key <- paste("lane", b$t, b$lane, sep = "/")
    own <- .dsvert_dp_irls_publication_get(db, paste0(key, "/prepare"))
    if (!identical(.dsvert_dp_irls_state_json(own$body), .dsvert_dp_irls_state_json(b)))
      stop("Lane commit conflicts with local durable value.", call. = FALSE)
    body <- b; body$kind <- "lane-committed"
    body$prepared_digest <- .dsvert_dp_irls_hash("dsvert-v3-irls-lane-prepared-v1", pair)
    receipt <- .dsvert_dp_irls_receipt_sign(body, ctx, identity_sk)
    retained <- .dsvert_dp_irls_publication_put(db, paste0(key, "/commit"),
      list(prepared = pair, receipt = receipt))
    if (isTRUE(crash_after)) stop("Simulated crash after durable lane COMMIT.", call. = FALSE)
    retained$receipt
  })
}

.dsvert_dp_irls_parent_prepare <- function(path, state_path, signed_contract, trusted_pins,
    t, predecessor, lane_receipts, identity_sk, crash_after = FALSE) {
  payload <- .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    .dsvert_dp_irls_fields(lane_receipts, c("g", "H"))
    barrier <- lapply(c("g", "H"), function(lane) {
      pair <- .dsvert_dp_irls_receipt_pair(lane_receipts[[lane]], ctx$contract, "lane-committed")
      if (pair$body$lane != lane || pair$body$t != t || pair$body$predecessor != predecessor)
        stop("Lane barrier stage mismatch.", call. = FALSE)
      own <- .dsvert_dp_irls_publication_get(db, paste("lane", t, lane, "commit", sep = "/"))$receipt
      if (!identical(.dsvert_dp_irls_state_json(own$body), .dsvert_dp_irls_state_json(pair$body)))
        stop("Lane barrier conflicts with durable state.", call. = FALSE)
      pair
    })
    names(barrier) <- c("g", "H")
    .dsvert_dp_irls_publication_put(db, paste0("barrier/", t), barrier)
    lapply(barrier, function(x) x$body$values)
  })
  if (identical(crash_after, "barrier")) stop("Simulated crash after durable lane BARRIER.", call. = FALSE)
  .dsvert_dp_irls_successor_prepare(state_path, signed_contract, trusted_pins,
    t, predecessor, payload, identity_sk, crash_after_prepare = crash_after)
}

.dsvert_dp_irls_parent_commit <- function(path, state_path, signed_contract, trusted_pins,
    stages, identity_sk, crash_after = FALSE) {
  # Authenticate the local child barrier before advancing the B1 chain.
  .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    barrier <- .dsvert_dp_irls_publication_get(db, paste0("barrier/", stages[[1L]]$body$t))
    payload <- lapply(barrier, function(x) x$body$values)
    if (!identical(.dsvert_dp_irls_state_json(payload),
        .dsvert_dp_irls_state_json(stages[[1L]]$body$payload)))
      stop("Parent payload differs from durable lanes.", call. = FALSE)
  })
  stage <- .dsvert_dp_irls_successor_commit(state_path, signed_contract, trusted_pins, stages)
  if (identical(crash_after, "successor-commit")) stop("Simulated crash after durable successor COMMIT.", call. = FALSE)
  .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    b <- stage$body
    body <- c(.dsvert_dp_irls_boundary_body(ctx, b$t, b$predecessor, "parent-committed"),
      list(artifact_digest = .dsvert_dp_irls_hash("dsvert-v3-irls-parent-artifact-v1", stage)))
    receipt <- .dsvert_dp_irls_receipt_sign(body, ctx, identity_sk)
    retained <- .dsvert_dp_irls_publication_put(db, paste0("parent/", b$t), list(stage = stage, receipt = receipt))
    if (isTRUE(crash_after)) stop("Simulated crash after durable parent COMMIT.", call. = FALSE)
    retained$receipt
  })
}

.dsvert_dp_irls_parent_publish <- function(path, signed_contract, trusted_pins,
    receipts, crash_after = FALSE) {
  .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    pair <- .dsvert_dp_irls_receipt_pair(receipts, ctx$contract, "parent-committed")
    parent <- .dsvert_dp_irls_publication_get(db, paste0("parent/", pair$body$t))
    if (!identical(.dsvert_dp_irls_state_json(parent$receipt$body), .dsvert_dp_irls_state_json(pair$body)))
      stop("Parent publication conflicts with durable bytes.", call. = FALSE)
    retained <- .dsvert_dp_irls_publication_put(db, paste0("public/", pair$body$t),
      list(stage = parent$stage, durable_receipts = pair))
    if (isTRUE(crash_after)) stop("Simulated crash after durable PUBLICATION.", call. = FALSE)
    retained$stage
  })
}

.dsvert_dp_irls_publication_read <- function(path, signed_contract, trusted_pins) {
  .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    chain <- list()
    for (i in seq_len(as.integer(ctx$contract$path$T) + as.integer(ctx$contract$path$terminal_audit)) - 1L) {
      record <- .dsvert_dp_irls_publication_get(db, paste0("public/", i), FALSE)
      if (is.null(record)) break
      .dsvert_dp_irls_receipt_check(record$durable_receipts, ctx$contract, TRUE)
      .dsvert_dp_irls_stage_signatures(record$stage, ctx$contract)
      if (!identical(record$durable_receipts$body$artifact_digest,
          .dsvert_dp_irls_hash("dsvert-v3-irls-parent-artifact-v1", record$stage)))
        stop("Corrupt parent artifact.", call. = FALSE)
      chain[[length(chain) + 1L]] <- record$stage
    }
    chain
  })
}

.dsvert_dp_irls_publication_accounting <- function(path, signed_contract, trusted_pins) {
  .dsvert_dp_irls_publication_open(path, signed_contract, trusted_pins, function(db, ctx) {
    observed <- list()
    for (i in seq_along(ctx$contract$accounting$stages) - 1L) {
      lanes <- Filter(function(lane) !is.null(.dsvert_dp_irls_publication_get(db,
        paste("lane", i, lane, "prepare", sep = "/"), FALSE)), c("g", "H"))
      if (length(lanes)) observed[[length(observed) + 1L]] <- list(t = as.character(i), lanes = as.list(lanes))
    }
    .dsvert_dp_irls_accounting(ctx$contract, observed)
  })
}

# Public post-processing of DP bytes only, including the terminal audit.
.dsvert_dp_irls_decode_payload <- function(contract, t, payload) {
  payload <- .dsvert_dp_irls_payload_validate(contract, t, payload)
  decoded <- list(); endpoints <- list()
  for (lane in c("g", "H")) if (!is.null(payload[[lane]])) {
    A <- contract$numeric$translation[[lane]]; U <- contract$numeric$upper_limits[[lane]]
    decoded[[lane]] <- lapply(seq_along(A), function(i) .dsvert_dp_irls_rational(
      (gmp::as.bigz(payload[[lane]][[i]]) - gmp::as.bigz(A[[i]])) *
        .dsvert_dp_irls_bigq(contract$numeric$lattice[[lane]])))
    endpoints[[lane]] <- lapply(seq_along(A), function(i)
      payload[[lane]][[i]] == "0" || payload[[lane]][[i]] == U[[i]])
  }
  list(values = decoded, endpoint_hits = endpoints,
    inference_refused = any(unlist(endpoints, use.names = FALSE)))
}
