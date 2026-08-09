# Purpose-bound, producer-minted transport for legacy MPC blobs.
#
# The analyst is an opaque relay.  It cannot choose a session-storage key or
# mint a transfer: a server-side producer signs a one-shot ticket that binds the
# payload digest to the session, the pinned sender/recipient names, the complete
# peer manifest and one allowlisted capability.  The recipient derives the
# legacy consumer slot exclusively from that signed capability/context.

.DSVERT_TYPED_BLOB_VERSION <- "dsvert-typed-blob-v1"
.DSVERT_TYPED_BLOB_TICKET_VERSION <- "dsvert-typed-blob-ticket-v1"
.DSVERT_TYPED_BLOB_DOMAIN <- "dsVert/typed-blob/ticket/v1|"
.DSVERT_TYPED_BLOB_RECEIPT_VERSION <- "dsvert-typed-blob-receipt-v1"
.DSVERT_TYPED_BLOB_RECEIPT_DOMAIN <- "dsVert/typed-blob/receipt/v1|"
.DSVERT_TYPED_BLOB_REJECTION_VERSION <- "dsvert-typed-blob-rejection-v1"
.DSVERT_TYPED_BLOB_TRANSFER_RE <- "^tb_[0-9a-f]{32}$"
.DSVERT_TYPED_BLOB_MAX_TICKET_BYTES <- 32L * 1024L
.DSVERT_TYPED_BLOB_MAX_CONTEXT_BYTES <- 8L * 1024L
.DSVERT_TYPED_BLOB_MAX_FRAME_BYTES <- 8L * 1024L^2
.DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS <- 512 * 1024^2
.DSVERT_TYPED_BLOB_MAX_FRAMES <- 4096L
.DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS <- 24L * 60L * 60L
.DSVERT_TYPED_BLOB_CLOCK_SKEW_SECONDS <- 5L * 60L
.DSVERT_TYPED_BLOB_SOURCE_DESCRIPTOR_VERSION <-
  "dsvert-typed-source-descriptor-v1"
.DSVERT_TYPED_BLOB_SWEEP_MAX_RECORDS <- 256L

.dsvert_typed_blob_spool_max_bytes <- function() {
  value <- getOption("dsvert.typed_blob.spool_max_bytes", 1024^3)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < 1024^2 ||
      value > 64 * 1024^3) {
    stop("Invalid typed-blob spool capacity policy.", call. = FALSE)
  }
  as.numeric(value)
}

# Reserve the signed final length of every admitted transfer, rather than only
# bytes received so far.  This makes backpressure effective before an attacker
# can open many sparse partial transfers. Completed and legacy disk blobs are
# charged at their actual retained size until consumed. The authenticated
# in-memory head makes the normal admission path O(1); a directory identity
# change, missing head or invalid MAC triggers a complete reconciliation.
.dsvert_typed_blob_accounting_secret <- function(ss) {
  secret <- tryCatch(.key_get("transport_sk", ss), error = function(e) NULL)
  if (is.null(secret) || !length(secret)) NULL else secret
}

.dsvert_typed_blob_directory_stamp <- function(path) {
  if (!dir.exists(path)) return(list(exists = FALSE))
  if (nzchar(Sys.readlink(path))) {
    stop("Typed-blob spool directory cannot be a symbolic link.",
         call. = FALSE)
  }
  info <- tryCatch(fs::file_info(path), error = function(e) NULL)
  if (is.null(info) || nrow(info) != 1L || is.na(info$type) ||
      !identical(as.character(info$type), "directory") ||
      anyNA(c(info$device_id, info$inode, info$modification_time,
              info$change_time))) {
    stop("Typed-blob spool directory metadata is invalid.", call. = FALSE)
  }
  list(
    exists = TRUE, device_id = as.numeric(info$device_id),
    inode = as.numeric(info$inode),
    modification_time = as.numeric(info$modification_time),
    change_time = as.numeric(info$change_time))
}

.dsvert_typed_blob_accounting_stamps <- function(ss) {
  if (is.null(ss$.session_dir)) {
    absent <- list(exists = FALSE)
    return(list(blobs = absent, typed = absent, typed_source = absent))
  }
  .assert_session_dir(ss)
  list(
    blobs = .dsvert_typed_blob_directory_stamp(
      file.path(ss$.session_dir, "blobs")),
    typed = .dsvert_typed_blob_directory_stamp(
      file.path(ss$.session_dir, "typed")),
    typed_source = .dsvert_typed_blob_directory_stamp(
      file.path(ss$.session_dir, "typed_source")))
}

.dsvert_typed_blob_accounting_mac <- function(secret, material) {
  digest::hmac(
    secret, serialize(material, NULL, version = 3L),
    algo = "sha256", serialize = FALSE)
}

.dsvert_typed_blob_accounting_material <- function(cache) {
  cache[c("version", "total", "active_count", "stamps",
          "next_orphan_expiry")]
}

.dsvert_typed_blob_accounting_authentic <- function(ss, cache) {
  secret <- .dsvert_typed_blob_accounting_secret(ss)
  required <- c("version", "total", "active_count", "stamps",
                "next_orphan_expiry", "mac")
  !is.null(secret) && is.list(cache) && !is.null(names(cache)) &&
    !anyDuplicated(names(cache)) &&
    identical(sort(names(cache)), sort(required)) &&
    identical(cache$version, "dsvert-typed-blob-accounting-v1") &&
    is.numeric(cache$total) && length(cache$total) == 1L &&
    !is.na(cache$total) && is.finite(cache$total) && cache$total >= 0 &&
    cache$total <= 2^53 - 1 &&
    is.numeric(cache$active_count) && length(cache$active_count) == 1L &&
    !is.na(cache$active_count) && is.finite(cache$active_count) &&
    cache$active_count >= 0 && cache$active_count == floor(cache$active_count) &&
    is.numeric(cache$next_orphan_expiry) &&
    length(cache$next_orphan_expiry) == 1L &&
    !is.na(cache$next_orphan_expiry) &&
    is.character(cache$mac) && length(cache$mac) == 1L &&
    identical(
      .dsvert_typed_blob_accounting_mac(
        secret, .dsvert_typed_blob_accounting_material(cache)),
      cache$mac)
}

.dsvert_typed_blob_accounting_store <- function(
    ss, total, next_orphan_expiry = Inf) {
  secret <- .dsvert_typed_blob_accounting_secret(ss)
  if (is.null(secret)) {
    ss$.typed_blob_retained_head <- NULL
    return(invisible(NULL))
  }
  material <- list(
    version = "dsvert-typed-blob-accounting-v1",
    total = as.numeric(total),
    active_count = as.numeric(length(ss$.typed_blob_transfers %||% list())),
    stamps = .dsvert_typed_blob_accounting_stamps(ss),
    next_orphan_expiry = as.numeric(next_orphan_expiry))
  material$mac <- .dsvert_typed_blob_accounting_mac(secret, material)
  ss$.typed_blob_retained_head <- material
  invisible(material)
}

.dsvert_typed_blob_accounting_invalidate <- function(ss) {
  ss$.typed_blob_retained_head <- NULL
  invisible(NULL)
}

.dsvert_typed_blob_accounting_adjust <- function(ss, prior, delta) {
  if (!.dsvert_typed_blob_accounting_authentic(ss, prior) ||
      !identical(ss$.typed_blob_retained_head, prior) ||
      !is.numeric(delta) || length(delta) != 1L || is.na(delta) ||
      !is.finite(delta)) {
    .dsvert_typed_blob_accounting_invalidate(ss)
    return(invisible(NULL))
  }
  total <- prior$total + delta
  if (!is.finite(total) || total < 0 || total > 2^53 - 1) {
    .dsvert_typed_blob_accounting_invalidate(ss)
    return(invisible(NULL))
  }
  .dsvert_typed_blob_accounting_store(
    ss, total, next_orphan_expiry = prior$next_orphan_expiry)
}

.dsvert_typed_blob_sweep_keys <- function(records, cursor, maximum) {
  count <- length(records)
  if (!count) {
    return(list(keys = character(), indices = integer(), cursor = 1L))
  }
  keys <- names(records)
  if (is.null(keys) || anyNA(keys) || any(!nzchar(keys)) ||
      anyDuplicated(keys)) {
    stop("Typed-blob transfer state is malformed.", call. = FALSE)
  }
  cursor <- suppressWarnings(as.integer(cursor))
  if (length(cursor) != 1L || is.na(cursor) || cursor < 1L ||
      cursor > count) cursor <- 1L
  take <- min(as.integer(maximum), count)
  indices <- ((cursor - 1L + seq_len(take) - 1L) %% count) + 1L
  list(keys = keys[indices], indices = indices,
       cursor = (indices[[take]] %% count) + 1L)
}

.dsvert_typed_blob_sweep_expired <- function(
    ss, now = .dsvert_typed_blob_now(),
    maximum = .DSVERT_TYPED_BLOB_SWEEP_MAX_RECORDS) {
  if (!is.environment(ss) || !is.numeric(now) || length(now) != 1L ||
      is.na(now) || !is.finite(now) || now < 0 ||
      !is.numeric(maximum) || length(maximum) != 1L || is.na(maximum) ||
      maximum < 1 || maximum != floor(maximum)) {
    stop("Invalid typed-blob expiry sweep.", call. = FALSE)
  }
  changed <- FALSE
  active <- ss$.typed_blob_transfers %||% list()
  selected <- .dsvert_typed_blob_sweep_keys(
    active, ss$.typed_blob_receive_sweep_cursor %||% 1L, maximum)
  ss$.typed_blob_receive_sweep_cursor <- selected$cursor
  expired_ids <- character()
  for (selected_index in seq_along(selected$keys)) {
    transfer_id <- selected$keys[[selected_index]]
    state <- active[[selected$indices[[selected_index]]]]
    if (!is.list(state) || !is.numeric(state$last_activity) ||
        length(state$last_activity) != 1L || is.na(state$last_activity) ||
        !is.finite(state$last_activity) ||
        !is.character(state$path) || length(state$path) != 1L ||
        is.na(state$path) || !nzchar(state$path) ||
        !is.character(state$ticket_digest) ||
        length(state$ticket_digest) != 1L || is.na(state$ticket_digest) ||
        !grepl("^[0-9a-f]{64}$", state$ticket_digest)) {
      stop("Typed-blob transfer state is malformed.", call. = FALSE)
    }
    if (now - state$last_activity <= .SESSION_TTL_SECONDS) next
    root <- file.path(.ensure_session_dir(ss), "typed")
    if (file.exists(state$path)) {
      if (nzchar(Sys.readlink(state$path)) ||
          !identical(normalizePath(dirname(state$path), mustWork = TRUE),
                     normalizePath(root, mustWork = TRUE)) ||
          !identical(basename(state$path), transfer_id)) {
        stop("Typed-blob inactivity cleanup found an invalid spool.",
             call. = FALSE)
      }
      unlink(state$path)
      if (file.exists(state$path)) {
        stop("Could not release an inactive typed-blob spool.",
             call. = FALSE)
      }
    }
    expired_ids <- c(expired_ids, transfer_id)
    changed <- TRUE
  }
  if (length(expired_ids)) {
    ss$.typed_blob_transfers <- active[
      !names(active) %in% expired_ids]
    ticket_index <- ss$.typed_blob_ticket_index %||% list()
    if (length(ticket_index)) {
      ss$.typed_blob_ticket_index <- ticket_index[
        !unlist(ticket_index, use.names = FALSE) %in% expired_ids]
    }
  }

  outbound <- ss$.typed_blob_outbound %||% list()
  selected <- .dsvert_typed_blob_sweep_keys(
    outbound, ss$.typed_blob_source_sweep_cursor %||% 1L, maximum)
  ss$.typed_blob_source_sweep_cursor <- selected$cursor
  for (selected_index in seq_along(selected$keys)) {
    state <- outbound[[selected$indices[[selected_index]]]]
    if (is.null(state$source_path)) next
    expired <- if (is.null(state$source_admitted_at)) {
      if (!is.numeric(state$expires_at) || length(state$expires_at) != 1L ||
          is.na(state$expires_at) || !is.finite(state$expires_at)) {
        stop("Typed-source outbound state is malformed.", call. = FALSE)
      }
      now > state$expires_at
    } else {
      if (!is.numeric(state$source_last_activity) ||
          length(state$source_last_activity) != 1L ||
          is.na(state$source_last_activity) ||
          !is.finite(state$source_last_activity)) {
        stop("Typed-source outbound state is malformed.", call. = FALSE)
      }
      now - state$source_last_activity > .SESSION_TTL_SECONDS
    }
    if (!isTRUE(expired)) next
    .dsvert_typed_blob_expire_outbound_operation(ss, state)
    changed <- TRUE
  }
  if (changed) .dsvert_typed_blob_accounting_invalidate(ss)
  invisible(changed)
}

.dsvert_typed_blob_file_inventory <- function(path, what) {
  if (!dir.exists(path)) return(list(paths = character(), info = NULL))
  paths <- list.files(path, all.files = TRUE, full.names = TRUE, no.. = TRUE)
  if (!length(paths)) return(list(paths = character(), info = NULL))
  info <- file.info(paths)
  if (anyNA(info$size) || any(info$isdir) ||
      any(nzchar(Sys.readlink(paths)))) {
    stop(what, " spool contents are invalid.", call. = FALSE)
  }
  list(paths = paths, info = info)
}

.dsvert_typed_blob_reconcile_retained_bytes <- function(ss, now) {
  active <- ss$.typed_blob_transfers %||% list()
  if (!is.list(active)) {
    stop("Typed-blob transfer state is malformed.", call. = FALSE)
  }
  active_paths <- character(length(active))
  active_reserved <- 0
  if (length(active)) {
    for (index in seq_along(active)) {
      state <- active[[index]]
      if (!is.list(state) || !is.numeric(state$payload_chars) ||
          length(state$payload_chars) != 1L || is.na(state$payload_chars) ||
          !is.finite(state$payload_chars) || state$payload_chars < 1 ||
          state$payload_chars != floor(state$payload_chars) ||
          !is.character(state$path) || length(state$path) != 1L ||
          is.na(state$path) || !nzchar(state$path)) {
        stop("Typed-blob transfer state is malformed.", call. = FALSE)
      }
      active_reserved <- active_reserved + state$payload_chars
      active_paths[[index]] <- normalizePath(state$path, mustWork = FALSE)
    }
  }
  disk_retained <- 0
  source_retained <- 0
  next_orphan_expiry <- Inf
  cleanup_left <- .DSVERT_TYPED_BLOB_SWEEP_MAX_RECORDS
  if (!is.null(ss$.session_dir)) {
    .assert_session_dir(ss)
    blob_inventory <- .dsvert_typed_blob_file_inventory(
      file.path(ss$.session_dir, "blobs"), "Typed-blob")
    if (length(blob_inventory$paths)) {
      disk_retained <- sum(as.numeric(blob_inventory$info$size))
    }

    typed_inventory <- .dsvert_typed_blob_file_inventory(
      file.path(ss$.session_dir, "typed"), "Typed-blob")
    if (length(typed_inventory$paths)) {
      canonical <- normalizePath(typed_inventory$paths, mustWork = FALSE)
      orphan <- !canonical %in% active_paths
      if (any(orphan)) {
        orphan_paths <- typed_inventory$paths[orphan]
        orphan_info <- typed_inventory$info[orphan, , drop = FALSE]
        if (any(!grepl("^tb_[0-9a-f]{32}$", basename(orphan_paths)))) {
          stop("Typed-blob spool contents are invalid.", call. = FALSE)
        }
        expiry <- as.numeric(orphan_info$mtime) + .SESSION_TTL_SECONDS
        expired <- expiry < now
        remove <- which(expired)[seq_len(min(sum(expired), cleanup_left))]
        if (length(remove)) {
          unlink(orphan_paths[remove])
          if (any(file.exists(orphan_paths[remove]))) {
            stop("Could not release crashed typed-blob spools.",
                 call. = FALSE)
          }
          keep <- setdiff(seq_along(orphan_paths), remove)
          cleanup_left <- cleanup_left - length(remove)
          orphan_paths <- orphan_paths[keep]
          orphan_info <- orphan_info[keep, , drop = FALSE]
          expiry <- expiry[keep]
        }
        if (length(orphan_paths)) {
          disk_retained <- disk_retained +
            sum(as.numeric(orphan_info$size))
          next_orphan_expiry <- min(next_orphan_expiry, expiry)
        }
      }
    }

    source_inventory <- .dsvert_typed_blob_file_inventory(
      file.path(ss$.session_dir, "typed_source"), "Typed-source")
    if (length(source_inventory$paths)) {
      source_ids <- sub("\\.b64$", "", basename(source_inventory$paths))
      valid_names <- grepl(
        "^(stage_[0-9a-f]{32}|tb_[0-9a-f]{32})\\.b64$",
        basename(source_inventory$paths))
      if (any(!valid_names)) {
        stop("Typed-source spool contents are invalid.", call. = FALSE)
      }
      outbound <- ss$.typed_blob_outbound %||% list()
      outbound_index <- match(source_ids, names(outbound))
      referenced <- vapply(seq_along(source_ids), function(index) {
        if (!grepl(.DSVERT_TYPED_BLOB_TRANSFER_RE, source_ids[[index]]) ||
            is.na(outbound_index[[index]])) {
          return(FALSE)
        }
        record <- outbound[[outbound_index[[index]]]]
        !is.null(record) && identical(
          normalizePath(record$source_path, mustWork = FALSE),
          normalizePath(source_inventory$paths[[index]], mustWork = FALSE))
      }, logical(1L))
      orphan <- !referenced
      if (any(orphan)) {
        expiry <- as.numeric(source_inventory$info$mtime[orphan]) +
          .SESSION_TTL_SECONDS
        orphan_indices <- which(orphan)
        expired_indices <- orphan_indices[expiry < now]
        remove <- expired_indices[seq_len(min(
          length(expired_indices), cleanup_left))]
        if (length(remove)) {
          unlink(source_inventory$paths[remove])
          if (any(file.exists(source_inventory$paths[remove]))) {
            stop("Could not release crashed typed-source spools.",
                 call. = FALSE)
          }
          cleanup_left <- cleanup_left - length(remove)
          keep <- setdiff(seq_along(source_ids), remove)
          source_inventory$paths <- source_inventory$paths[keep]
          source_inventory$info <- source_inventory$info[keep, , drop = FALSE]
          referenced <- referenced[keep]
          expiry <- as.numeric(source_inventory$info$mtime[!referenced]) +
            .SESSION_TTL_SECONDS
        }
        if (length(expiry)) {
          next_orphan_expiry <- min(next_orphan_expiry, expiry)
        }
      }
      source_retained <- sum(as.numeric(source_inventory$info$size))
    }
  }
  total <- active_reserved + disk_retained + source_retained
  if (!is.finite(total) || total < 0 || total > 2^53 - 1) {
    stop("Typed-blob retained-byte accounting overflowed.", call. = FALSE)
  }
  .dsvert_typed_blob_accounting_store(
    ss, total, next_orphan_expiry = next_orphan_expiry)
  as.numeric(total)
}

.dsvert_typed_blob_retained_bytes <- function(
    ss, now = .dsvert_typed_blob_now()) {
  if (!is.environment(ss) || !is.numeric(now) || length(now) != 1L ||
      is.na(now) || !is.finite(now) || now < 0) {
    stop("Invalid typed-blob retained-byte accounting request.",
         call. = FALSE)
  }
  cache <- ss$.typed_blob_retained_head
  active <- ss$.typed_blob_transfers %||% list()
  if (.dsvert_typed_blob_accounting_authentic(ss, cache) &&
      identical(cache$active_count, as.numeric(length(active))) &&
      identical(cache$stamps,
                .dsvert_typed_blob_accounting_stamps(ss)) &&
      now <= cache$next_orphan_expiry) {
    return(as.numeric(cache$total))
  }
  .dsvert_typed_blob_reconcile_retained_bytes(ss, now)
}

.dsvert_typed_blob_integer_string <- function(value, what, minimum = 1,
                                               maximum = 2^31 - 1) {
  if (is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && value == floor(value)) {
    value <- format(value, scientific = FALSE, trim = TRUE)
  }
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^(0|[1-9][0-9]*)$", value)) {
    stop("Invalid typed-blob ", what, ".", call. = FALSE)
  }
  numeric <- suppressWarnings(as.numeric(value))
  if (!is.finite(numeric) || numeric < minimum || numeric > maximum) {
    stop("Invalid typed-blob ", what, ".", call. = FALSE)
  }
  format(numeric, scientific = FALSE, trim = TRUE)
}

.dsvert_typed_blob_ring <- function(value) {
  value <- .dsvert_typed_blob_integer_string(
    value, "ring", minimum = 63, maximum = 127)
  if (!value %in% c("63", "127")) {
    stop("Invalid typed-blob ring.", call. = FALSE)
  }
  value
}

.dsvert_typed_blob_context_fields <- function(context, required) {
  if (!is.list(context) || is.null(names(context)) ||
      anyDuplicated(names(context)) ||
      !identical(sort(names(context)), sort(required))) {
    stop("Invalid typed-blob producer context.", call. = FALSE)
  }
  context[required]
}

.dsvert_typed_blob_storage_name <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop("Invalid typed-blob ", what, ".", call. = FALSE)
  }
  .validate_storage_component(value, what)
  value
}

# Resolve a producer-owned operation label to a private storage suffix.  The
# label remains signed in the ticket context, but never becomes a caller-chosen
# path component.
.dsvert_typed_blob_operation_tag <- function(value, what = "operation") {
  value <- .dsvert_typed_blob_storage_name(value, what)
  substr(digest::digest(
    paste0("dsVert/typed-blob/operation/v1|", value),
    algo = "sha256", serialize = FALSE), 1L, 24L)
}

.dsvert_typed_blob_count_string <- function(value, what) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < 1 ||
      value > 2^53 - 1) {
    stop("Invalid typed-blob ", what, ".", call. = FALSE)
  }
  format(value, scientific = FALSE, trim = TRUE)
}

.dsvert_typed_blob_metadata <- function(capability_id, slot, context,
                                         family, producer, consumer, phase,
                                         shape, count) {
  .validate_storage_component(slot, "typed-blob destination")
  list(
    slot = slot,
    context = context,
    family = family,
    producer = producer,
    consumer = consumer,
    phase = phase,
    ring = context$ring,
    shape = shape,
    count = .dsvert_typed_blob_count_string(count, "element count"))
}

.dsvert_typed_blob_now <- function() floor(as.numeric(Sys.time()))

.dsvert_typed_blob_rejection <- function(operation) {
  list(
    version = .DSVERT_TYPED_BLOB_REJECTION_VERSION,
    operation = operation, rejected = TRUE)
}

.dsvert_typed_blob_stream_key <- function(capability_id, peer_name) {
  paste(capability_id, peer_name, sep = "|")
}

.dsvert_typed_blob_request_key <- function(producer, request) {
  if (!is.character(producer) || length(producer) != 1L ||
      is.na(producer) || !nzchar(producer) || !is.list(request)) {
    stop("Invalid typed-blob producer request cache key.", call. = FALSE)
  }
  paste0(producer, "|", digest::digest(
    list(version = "dsvert-typed-blob-operation-v1", request = request),
    algo = "sha256", serialize = TRUE))
}

# A DataSHIELD aggregate request may be executed successfully even when its
# response is lost. Producers call this before any random sharing/encryption or
# session mutation. While peer receipts are pending, an exact re-execution gets
# the byte-identical prior result rather than generating a second protocol
# phase.
.dsvert_typed_blob_operation_replay <- function(ss, producer, request) {
  if (!is.environment(ss)) stop("Invalid typed-blob session.", call. = FALSE)
  key <- .dsvert_typed_blob_request_key(producer, request)
  record <- (ss$.typed_blob_pending_operations %||% list())[[key]]
  if (is.null(record)) return(list(hit = FALSE, key = key))
  if (!is.list(record) || !identical(record$producer, producer) ||
      !identical(record$request, request) || is.null(record$result) ||
      !is.character(record$transfer_ids) || !length(record$transfer_ids)) {
    stop("Typed-blob pending producer result is malformed; abort the session.",
         call. = FALSE)
  }
  list(hit = TRUE, key = key, result = record$result)
}

.dsvert_typed_blob_result_transfer_ids <- function(value) {
  found <- character()
  walk <- function(node) {
    if (!is.list(node)) return(invisible(NULL))
    required <- c("ticket", "transfer_id", "capability_id", "sender_name",
                  "recipient_name", "payload_chars", "payload_sha256")
    if (!is.null(names(node)) && all(required %in% names(node)) &&
        is.character(node$transfer_id) && length(node$transfer_id) == 1L &&
        grepl(.DSVERT_TYPED_BLOB_TRANSFER_RE, node$transfer_id)) {
      found <<- c(found, node$transfer_id)
      return(invisible(NULL))
    }
    lapply(node, walk)
    invisible(NULL)
  }
  walk(value)
  unique(found)
}

.dsvert_typed_blob_operation_commit <- function(
    ss, producer, request, result) {
  key <- .dsvert_typed_blob_request_key(producer, request)
  transfer_ids <- .dsvert_typed_blob_result_transfer_ids(result)
  if (!length(transfer_ids)) {
    stop("Typed-blob producer result contains no transfer contract.",
         call. = FALSE)
  }
  outbound <- ss$.typed_blob_outbound %||% list()
  if (any(!transfer_ids %in% names(outbound))) {
    stop("Typed-blob producer result references an unknown transfer.",
         call. = FALSE)
  }
  if (is.null(ss$.typed_blob_pending_operations)) {
    ss$.typed_blob_pending_operations <- list()
  }
  prior <- ss$.typed_blob_pending_operations[[key]]
  if (!is.null(prior)) {
    if (!identical(prior$result, result)) {
      stop("Conflicting typed-blob result for one producer request.",
           call. = FALSE)
    }
    return(prior$result)
  }
  for (transfer_id in transfer_ids) {
    outbound[[transfer_id]]$operation_key <- key
  }
  ss$.typed_blob_outbound <- outbound
  ss$.typed_blob_pending_operations[[key]] <- list(
    producer = producer, request = request, result = result,
    transfer_ids = transfer_ids)
  result
}

# Complete active-first capability registry. Adding an entry requires both a
# fixed server producer and a consumer-side provenance check. The remotely
# callable store cannot add capabilities, choose destinations, or mint tickets.
.dsvert_typed_blob_destination <- function(capability_id, sender_name,
                                            context) {
  capability_id <- .dsvert_relay_validate_capability_id(capability_id)
  sender_name <- .dsvert_validate_logical_peer_name(sender_name)
  fixed <- list(
    "blob.input.peer-x.v1" = list(
      slot = "k2_peer_x_share", required = c("n", "p", "ring"),
      family = "input", producer = "k2ShareInputDS",
      consumer = "k2ReceiveShareDS", phase = "input.peer-x",
      shape = "row-major-matrix"),
    "blob.input.peer-y.v1" = list(
      slot = "k2_peer_y_share", required = c("n", "ring"),
      family = "input", producer = "k2ShareInputDS",
      consumer = "k2ReceiveShareDS", phase = "input.peer-y",
      shape = "vector"),
    "blob.gradient.peer-r1.v1" = list(
      slot = "k2_grad_peer_r1", required = c("n", "p", "ring"),
      family = "gradient", producer = "k2GradientR1DS",
      consumer = "k2GradientR2DS", phase = "gradient.round-1",
      shape = "masked-matrix-vector-tuple"),
    "blob.beaver.vecmul-masked.v1" = list(
      slot = "k2_beaver_vecmul_peer_masked",
      required = c("n", "ring"), family = "beaver",
      producer = "k2BeaverVecmulR1DS", consumer = "k2BeaverVecmulR2DS",
      phase = "beaver.vecmul.round-1", shape = "masked-vector-pair"),
    "blob.glm.weight-share.v1" = list(
      slot = "k2_peer_weight_share",
      required = c("n", "ring", "numeric_family"), family = "glm",
      producer = "k2ShareWeightsDS", consumer = "k2ReceiveWeightSharesDS",
      phase = "glm.weights", shape = "vector"),
    "blob.glm.sqrt-weight-share.v1" = list(
      slot = "k2_peer_sqrt_weight_share",
      required = c("n", "ring", "numeric_family"), family = "glm",
      producer = "k2ShareWeightsDS", consumer = "k2ReceiveWeightSharesDS",
      phase = "glm.sqrt-weights", shape = "vector"))
  if (capability_id %in% names(fixed)) {
    spec <- fixed[[capability_id]]
    required <- spec$required
    context <- .dsvert_typed_blob_context_fields(context, required)
    context$n <- .dsvert_typed_blob_integer_string(context$n, "row count")
    if ("p" %in% required) {
      context$p <- .dsvert_typed_blob_integer_string(
        context$p, "column count")
    }
    context$ring <- .dsvert_typed_blob_ring(context$ring)
    if ("numeric_family" %in% required) {
      if (!is.character(context$numeric_family) ||
          length(context$numeric_family) != 1L ||
          is.na(context$numeric_family) ||
          !context$numeric_family %in% c("gaussian", "binomial", "poisson")) {
        stop("Invalid typed-blob numeric family.", call. = FALSE)
      }
    }
    count <- as.numeric(context$n)
    if ("p" %in% required) count <- count * as.numeric(context$p)
    if (identical(capability_id, "blob.gradient.peer-r1.v1")) {
      count <- count + as.numeric(context$n)
    } else if (identical(
      capability_id, "blob.beaver.vecmul-masked.v1")) {
      count <- 2 * count
    }
    return(.dsvert_typed_blob_metadata(
      capability_id, spec$slot, context, spec$family, spec$producer,
      spec$consumer, spec$phase, spec$shape, count))
  }
  if (identical(capability_id, "blob.transport.source-probe.v1")) {
    context <- .dsvert_typed_blob_context_fields(
      context, c("raw_bytes", "ring"))
    context$raw_bytes <- .dsvert_typed_blob_integer_string(
      context$raw_bytes, "source-probe byte count",
      maximum = floor(.DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS * 3 / 4))
    context$ring <- .dsvert_typed_blob_ring(context$ring)
    if (!identical(context$ring, "63")) {
      stop("Typed source probe has an invalid fixed context.", call. = FALSE)
    }
    return(.dsvert_typed_blob_metadata(
      capability_id, "typed_source_probe", context, "transport",
      "mpcTypedSourceProbeDS", "transportSourceProbeOnly",
      "transport.source-probe", "opaque-base64url-stream",
      as.numeric(context$raw_bytes)))
  }
  if (identical(capability_id, "blob.joint-dp.count-source.v1")) {
    required <- c(
      "query_id", "capsule_release_id", "allocation_index", "source_contract_hash",
      "purpose_hash", "ring")
    context <- .dsvert_typed_blob_context_fields(context, required)
    hashes <- context[c(
      "query_id", "capsule_release_id", "source_contract_hash",
      "purpose_hash")]
    if (any(!vapply(hashes, function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^[0-9a-f]{64}$", value)
    }, logical(1L)))) {
      stop("Invalid typed-blob joint-DP count context.", call. = FALSE)
    }
    context$allocation_index <- .dsvert_typed_blob_integer_string(
      context$allocation_index, "joint-DP allocation index",
      minimum = 0, maximum = 2^53 - 1)
    if (!is.character(context$ring) || length(context$ring) != 1L ||
        !identical(context$ring, "128")) {
      stop("Joint-DP count source shares require Ring128.", call. = FALSE)
    }
    tag <- substr(digest::digest(
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(context)),
      algo = "sha256", serialize = FALSE), 1L, 24L)
    slot <- paste0("joint_dp_count_source_", tag)
    .validate_storage_component(slot, "typed-blob destination")
    return(.dsvert_typed_blob_metadata(
      capability_id, slot, context, "joint-dp",
      ".dsvert_joint_dp_count_mint_transfer",
      ".dsvert_joint_dp_count_receive_transfer",
      "joint-dp.count-source", "encrypted-ring128-scalar-share", 1))
  }
  if (identical(capability_id, "blob.joint-dp.count-final-share.v1")) {
    required <- c(
      "query_id", "capsule_release_id", "allocation_index",
      "source_contract_hash", "purpose_hash", "ring",
      "result_contract_hash", "result_set_hash",
      "delivery_commit_set_hash")
    context <- .dsvert_typed_blob_context_fields(context, required)
    hashes <- context[setdiff(required, c("allocation_index", "ring"))]
    if (any(!vapply(hashes, function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^[0-9a-f]{64}$", value)
    }, logical(1L)))) {
      stop("Invalid typed-blob joint-DP Count final context.", call. = FALSE)
    }
    context$allocation_index <- .dsvert_typed_blob_integer_string(
      context$allocation_index, "joint-DP allocation index",
      minimum = 0, maximum = 2^53 - 1)
    if (!is.character(context$ring) || length(context$ring) != 1L ||
        !identical(context$ring, "127")) {
      stop("Joint-DP Count final shares require Ring127.", call. = FALSE)
    }
    tag <- substr(digest::digest(
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(context)),
      algo = "sha256", serialize = FALSE), 1L, 24L)
    slot <- paste0("joint_dp_count_final_", tag)
    .validate_storage_component(slot, "typed-blob destination")
    return(.dsvert_typed_blob_metadata(
      capability_id, slot, context, "joint-dp",
      ".dsvert_joint_dp_count_mint_final_transfer",
      ".dsvert_joint_dp_count_release",
      "joint-dp.count-final-share", "encrypted-post-clamp-ring127-share", 1))
  }
  if (identical(capability_id, "blob.joint-dp.vector-final-share.v3")) {
    required <- c(
      "capsule_id", "release_contract_hash", "result_set_hash",
      "chunk_index", "chunk_count", "coordinate_count", "ring",
      "noised_share_sha256")
    context <- .dsvert_typed_blob_context_fields(context, required)
    hashes <- context[c(
      "capsule_id", "release_contract_hash", "result_set_hash",
      "noised_share_sha256")]
    if (any(!vapply(hashes, function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^[0-9a-f]{64}$", value)
    }, logical(1L)))) {
      stop("Invalid typed-blob joint-DP vector context.", call. = FALSE)
    }
    context$chunk_index <- .dsvert_typed_blob_integer_string(
      context$chunk_index, "joint-DP vector chunk index",
      minimum = 0, maximum = 2^31 - 1)
    context$chunk_count <- .dsvert_typed_blob_integer_string(
      context$chunk_count, "joint-DP vector chunk count",
      minimum = 1, maximum = 2^31 - 1)
    context$coordinate_count <- .dsvert_typed_blob_integer_string(
      context$coordinate_count, "joint-DP vector coordinate count",
      minimum = 1, maximum = 8192)
    if (as.numeric(context$chunk_index) >=
        as.numeric(context$chunk_count) ||
        !is.character(context$ring) || length(context$ring) != 1L ||
        !identical(context$ring, "128")) {
      stop("Joint-DP vector final shares require a valid Ring128 chunk.",
           call. = FALSE)
    }
    tag <- substr(digest::digest(
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(context)),
      algo = "sha256", serialize = FALSE), 1L, 24L)
    slot <- paste0("joint_dp_vector_final_", tag)
    .validate_storage_component(slot, "typed-blob destination")
    return(.dsvert_typed_blob_metadata(
      capability_id, slot, context, "joint-dp",
      ".dsvert_joint_dp_vector_final_share_impl",
      ".dsvert_joint_dp_vector_release_impl",
      "joint-dp.vector-final-share",
      "encrypted-ring128-noised-vector-chunk",
      as.numeric(context$coordinate_count)))
  }
  if (identical(capability_id, "blob.input.extra-x.v1")) {
    context <- .dsvert_typed_blob_context_fields(
      context, c("n", "p", "ring"))
    context$n <- .dsvert_typed_blob_integer_string(context$n, "row count")
    context$p <- .dsvert_typed_blob_integer_string(
      context$p, "column count")
    context$ring <- .dsvert_typed_blob_ring(context$ring)
    source <- .dsvert_typed_blob_storage_name(sender_name, "source peer")
    slot <- paste0("k2_extra_x_share_", source)
    .validate_storage_component(slot, "typed-blob destination")
    return(.dsvert_typed_blob_metadata(
      capability_id, slot, context, "input",
      c("glmRing63ShareExtraInputDS", "glmRing63ExportOwnShareDS"),
      "glmRing63ReceiveExtraShareDS",
      "input.extra-x", "row-major-matrix",
      as.numeric(context$n) * as.numeric(context$p)))
  }
  if (identical(capability_id, "blob.beaver.vector-share.v1")) {
    context <- .dsvert_typed_blob_context_fields(
      context, c("variable", "n", "levels", "ring"))
    variable <- .dsvert_typed_blob_storage_name(
      context$variable, "one-hot variable")
    context$n <- .dsvert_typed_blob_integer_string(context$n, "row count")
    context$levels <- .dsvert_typed_blob_integer_string(
      context$levels, "level count")
    context$ring <- .dsvert_typed_blob_ring(context$ring)
    slot <- paste0("bshr_", variable)
    .validate_storage_component(slot, "typed-blob destination")
    return(.dsvert_typed_blob_metadata(
      capability_id, slot, context, "beaver",
      "k2BeaverShareVectorDS", "k2BeaverReceiveVectorDS",
      "beaver.vector-share", "row-major-one-hot",
      as.numeric(context$n) * as.numeric(context$levels)))
  }
  iknp <- c(
    "blob.iknp.base-points.v1" = "base_points",
    "blob.iknp.base-ciphertexts.v1" = "base_ciphertexts",
    "blob.iknp.u-matrix.v1" = "u_matrix",
    "blob.iknp.ciphertexts.v1" = "ciphertexts")
  if (capability_id %in% names(iknp)) {
    context <- .dsvert_typed_blob_context_fields(
      context, c("operation", "n", "ring"))
    operation <- .dsvert_typed_blob_operation_tag(
      context$operation, "IKNP operation")
    context$n <- .dsvert_typed_blob_integer_string(
      context$n, "IKNP element count")
    context$ring <- .dsvert_typed_blob_ring(context$ring)
    stage <- unname(iknp[[capability_id]])
    slot <- paste0("tb_iknp_", operation, "_", stage)
    producers <- c(
      base_points = "k2IknpBaseSenderChoicesDS",
      base_ciphertexts = "k2IknpBaseReceiverEncryptDS",
      u_matrix = "k2IknpReceiverExtendDS",
      ciphertexts = "k2IknpSenderEncryptDS")
    consumers <- c(
      base_points = "k2IknpBaseReceiverEncryptDS",
      base_ciphertexts = "k2IknpBaseSenderFinalizeDS",
      u_matrix = "k2IknpSenderEncryptDS",
      ciphertexts = "k2IknpReceiverDecryptDS")
    return(.dsvert_typed_blob_metadata(
      capability_id, slot, context, "iknp", unname(producers[[stage]]),
      unname(consumers[[stage]]), paste0("iknp.", gsub("_", "-", stage)),
      if (stage == "u_matrix") "iknp-u-matrix" else "iknp-batch",
      as.numeric(context$n)))
  }
  stop("Typed-blob capability is not present in the server registry.",
       call. = FALSE)
}

.dsvert_typed_blob_random_transfer_id <- function() {
  bytes <- .dsvert_secure_random_bytes(16L)
  value <- paste0("tb_", paste(sprintf("%02x", as.integer(bytes)),
                                collapse = ""))
  if (!grepl(.DSVERT_TYPED_BLOB_TRANSFER_RE, value)) {
    stop("Could not mint a typed-blob transfer identifier.", call. = FALSE)
  }
  value
}

.dsvert_typed_blob_peer_binding <- function(
    identity_info, transport_keys, parent_binding_digest = NULL) {
  if (!is.list(identity_info) || !length(identity_info) ||
      is.null(names(identity_info)) || anyDuplicated(names(identity_info))) {
    stop("Typed-blob transport requires a name-bound peer manifest.",
         call. = FALSE)
  }
  if (!is.list(transport_keys) || !length(transport_keys) ||
      is.null(names(transport_keys)) || anyDuplicated(names(transport_keys)) ||
      !setequal(names(transport_keys), names(identity_info))) {
    stop("Typed-blob transport and identity manifests must match.",
         call. = FALSE)
  }
  names_sorted <- sort(names(identity_info))
  fields <- vapply(names_sorted, function(name) {
    info <- identity_info[[name]]
    if (!is.list(info) || is.null(info$identity_pk)) {
      stop("Typed-blob peer manifest is malformed.", call. = FALSE)
    }
    identity <- .dsvert_normalize_crypto_b64(
      info$identity_pk, 32L,
      paste0("identity public key for '", name, "'"))
    transport <- .dsvert_normalize_crypto_b64(
      transport_keys[[name]], 32L,
      paste0("transport public key for '", name, "'"))
    paste0(nchar(name, type = "bytes"), ":", name,
           nchar(identity, type = "bytes"), ":", identity,
           nchar(transport, type = "bytes"), ":", transport)
  }, character(1L), USE.NAMES = FALSE)
  peer_manifest_digest <- digest::digest(
    charToRaw(paste0("dsVert/typed-blob/peers/v1|",
                     paste0(fields, collapse = ""))),
    algo = "sha256", serialize = FALSE)
  if (is.null(parent_binding_digest)) return(peer_manifest_digest)
  if (!is.character(parent_binding_digest) ||
      length(parent_binding_digest) != 1L ||
      is.na(parent_binding_digest) ||
      !grepl("^[0-9a-f]{64}$", parent_binding_digest)) {
    stop("Invalid typed-blob parent peer binding.", call. = FALSE)
  }
  digest::digest(
    .dsvert_dp_canonical_json(list(
      version = "dsvert-typed-blob-parent-binding-v2",
      peer_manifest_sha256 = peer_manifest_digest,
      parent_binding_sha256 = parent_binding_digest)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_typed_blob_install_peer_manifest <- function(
    ss, identity_info, transport_keys, parent_binding_digest = NULL) {
  if (!is.environment(ss)) stop("Invalid typed-blob session.", call. = FALSE)
  configured_own_name <- .dsvert_require_configured_local_peer_name()
  own <- .dsvert_normalize_crypto_b64(
    .key_get("identity_pk", ss), 32L, "own identity public key")
  normalized <- vapply(names(identity_info), function(name) {
    .dsvert_normalize_crypto_b64(
      identity_info[[name]]$identity_pk, 32L,
      paste0("identity public key for '", name, "'"))
  }, character(1L), USE.NAMES = TRUE)
  own_names <- names(normalized)[normalized == own]
  if (length(own_names) != 1L) {
    stop("Typed-blob peer manifest must bind this server exactly once.",
         call. = FALSE)
  }
  if (!identical(own_names[[1L]], configured_own_name)) {
    stop("Typed-blob peer manifest relabels this server: the own identity ",
         "must be bound to configured dsvert.peer_name '",
         configured_own_name, "'.", call. = FALSE)
  }
  peers <- normalized[names(normalized) != own_names[[1L]]]
  if (!length(peers)) {
    stop("Typed-blob transport requires at least one pinned peer.",
         call. = FALSE)
  }
  binding <- .dsvert_typed_blob_peer_binding(
    identity_info, transport_keys,
    parent_binding_digest = parent_binding_digest)
  if (!is.null(ss$.typed_blob_peer_binding_digest) &&
      !identical(ss$.typed_blob_peer_binding_digest, binding)) {
    stop("Conflicting retry for typed-blob peer binding.", call. = FALSE)
  }
  ss$.typed_blob_self_name <- own_names[[1L]]
  ss$.typed_blob_peer_identity_pks <- as.list(peers)
  ss$.typed_blob_parent_binding_digest <- parent_binding_digest
  ss$.typed_blob_peer_binding_digest <- binding
  invisible(TRUE)
}

.dsvert_typed_blob_session_context <- function(ss) {
  self_name <- ss$.typed_blob_self_name
  peers <- ss$.typed_blob_peer_identity_pks
  binding <- ss$.typed_blob_peer_binding_digest
  if (!is.character(self_name) || length(self_name) != 1L ||
      is.na(self_name) || !nzchar(self_name) || !is.list(peers) ||
      !length(peers) || is.null(names(peers)) || anyDuplicated(names(peers)) ||
      !is.character(binding) || length(binding) != 1L ||
      !grepl("^[0-9a-f]{64}$", binding)) {
    stop("Typed-blob transport requires an authenticated pinned-peer setup.",
         call. = FALSE)
  }
  list(self_name = self_name, peer_identity_pks = peers,
       peer_binding_digest = binding)
}

.dsvert_typed_blob_recipient_name <- function(ss, recipient_pk) {
  session <- .dsvert_typed_blob_session_context(ss)
  .dsvert_validate_peer_pk(recipient_pk, ss, "typed-blob recipient")
  normalized <- .dsvert_normalize_crypto_b64(
    recipient_pk, 32L, "typed-blob recipient transport public key")
  peer_pks <- ss$peer_transport_pks
  hits <- names(peer_pks)[vapply(peer_pks, function(value) {
    identical(.dsvert_normalize_crypto_b64(
      value, 32L, "pinned transport public key"), normalized)
  }, logical(1L))]
  if (length(hits) != 1L ||
      is.null(session$peer_identity_pks[[hits[[1L]]]])) {
    stop("Typed-blob recipient is not uniquely bound to a pinned peer.",
         call. = FALSE)
  }
  hits[[1L]]
}

.dsvert_typed_blob_context_token <- function(context) {
  encoded <- charToRaw(as.character(jsonlite::toJSON(
    context, auto_unbox = TRUE, null = "null", digits = NA)))
  if (!length(encoded)) {
    stop("Typed-blob producer context is empty.", call. = FALSE)
  }
  if (length(encoded) > .DSVERT_TYPED_BLOB_MAX_CONTEXT_BYTES) {
    .dsvert_resource_oversize(
      length(encoded), .DSVERT_TYPED_BLOB_MAX_CONTEXT_BYTES,
      "typed-blob producer context")
  }
  .dsvert_relay_b64url_encode(encoded)
}

.dsvert_typed_blob_body_token <- function(body) {
  .dsvert_relay_b64url_encode(charToRaw(as.character(jsonlite::toJSON(
    body, auto_unbox = TRUE, null = "null", digits = NA))))
}

.dsvert_typed_blob_signature_message <- function(body_token) {
  body <- .dsvert_relay_b64url_decode(
    body_token, "typed-blob signature body")
  gsub("[\r\n]", "", jsonlite::base64_enc(c(
    charToRaw(.DSVERT_TYPED_BLOB_DOMAIN), body)))
}

.dsvert_typed_blob_receipt_signature_message <- function(body_token) {
  body <- .dsvert_relay_b64url_decode(
    body_token, "typed-blob receipt signature body")
  gsub("[\r\n]", "", jsonlite::base64_enc(c(
    charToRaw(.DSVERT_TYPED_BLOB_RECEIPT_DOMAIN), body)))
}

# Producer spools are created only below the session directory.  The runtime
# receives a fresh non-existent staging path; neither the analyst nor a DSI
# endpoint can provide a path or filename.
.dsvert_typed_blob_source_root <- function(ss, create = FALSE) {
  if (!is.environment(ss)) stop("Invalid typed-source session.", call. = FALSE)
  root <- file.path(.ensure_session_dir(ss), "typed_source")
  if (isTRUE(create) && !dir.exists(root) &&
      !dir.create(root, mode = "0700", showWarnings = FALSE)) {
    stop("Could not create the private typed-source spool.", call. = FALSE)
  }
  if (dir.exists(root)) {
    Sys.chmod(root, mode = "0700")
    root <- normalizePath(root, mustWork = TRUE)
  }
  root
}

.dsvert_typed_blob_source_stage_path <- function(ss) {
  root <- .dsvert_typed_blob_source_root(ss, create = TRUE)
  token <- paste(sprintf("%02x", as.integer(
    .dsvert_secure_random_bytes(16L))), collapse = "")
  file.path(root, paste0("stage_", token, ".b64"))
}

.dsvert_typed_blob_source_identity <- function(path) {
  info <- tryCatch(fs::file_info(path), error = function(e) NULL)
  if (is.null(info) || nrow(info) != 1L || is.na(info$type) ||
      !identical(as.character(info$type), "file") || is.na(info$size) ||
      !is.finite(as.numeric(info$size)) ||
      anyNA(c(info$device_id, info$inode, info$hard_links,
              info$modification_time, info$change_time))) {
    stop("Invalid private typed-source spool metadata.", call. = FALSE)
  }
  list(
    device_id = as.numeric(info$device_id), inode = as.numeric(info$inode),
    size = as.numeric(info$size), hard_links = as.numeric(info$hard_links),
    permissions = as.character(info$permissions),
    modification_time = as.numeric(info$modification_time),
    change_time = as.numeric(info$change_time))
}

.dsvert_typed_blob_source_stable_identity <- function(identity) {
  identity[c("device_id", "inode", "size", "hard_links", "permissions",
             "modification_time")]
}

.dsvert_typed_blob_source_descriptor_mac <- function(ss, descriptor) {
  secret <- .key_get("transport_sk", ss)
  if (is.null(secret) || !length(secret)) {
    stop("Typed-source descriptor has no session authentication key.",
         call. = FALSE)
  }
  digest::hmac(
    secret,
    serialize(descriptor, NULL, version = 3L),
    algo = "sha256", serialize = FALSE)
}

.dsvert_typed_blob_source_validate_stream <- function(path) {
  con <- file(path, "rb")
  on.exit(close(con), add = TRUE)
  repeat {
    value <- readBin(con, "raw", n = 1024L * 1024L)
    if (!length(value)) break
    bytes <- as.integer(value)
    valid <- (bytes >= 48L & bytes <= 57L) |
      (bytes >= 65L & bytes <= 90L) |
      (bytes >= 97L & bytes <= 122L) | bytes %in% c(45L, 95L)
    if (!all(valid)) {
      stop("Typed-source spool is not canonical Base64url text.",
           call. = FALSE)
    }
  }
  invisible(TRUE)
}

.dsvert_typed_blob_source_hash_file <- function(path) {
  digest::digest(file = path, algo = "sha256", serialize = FALSE)
}

.dsvert_typed_blob_source_file_metadata <- function(ss, path) {
  root <- .dsvert_typed_blob_source_root(ss, create = FALSE)
  if (!dir.exists(root) || !is.character(path) || length(path) != 1L ||
      is.na(path) || !nzchar(path) || !file.exists(path) ||
      nzchar(Sys.readlink(path)) ||
      !identical(normalizePath(dirname(path), mustWork = TRUE), root) ||
      !grepl("^(stage_[0-9a-f]{32}|tb_[0-9a-f]{32})\\.b64$",
             basename(path))) {
    stop("Invalid private typed-source spool file.", call. = FALSE)
  }
  identity <- .dsvert_typed_blob_source_identity(path)
  if (identity$size < 1 || (.Platform$OS.type != "windows" &&
       (!identical(identity$hard_links, 1) ||
        !identical(identity$permissions, "rw-------")))) {
    stop("Invalid private typed-source spool metadata.", call. = FALSE)
  }
  if (identity$size > .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS) {
    .dsvert_resource_oversize(
      identity$size, .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS,
      "typed-source payload")
  }
  .dsvert_typed_blob_source_validate_stream(path)
  payload_sha256 <- .dsvert_typed_blob_source_hash_file(path)
  final_identity <- .dsvert_typed_blob_source_identity(path)
  if (!identical(final_identity, identity)) {
    stop("Typed-source spool changed while it was being verified.",
         call. = FALSE)
  }
  if (identity$size %% 4L == 1L) {
    stop("Typed-source spool is not canonical Base64url text.",
         call. = FALSE)
  }
  unsigned <- list(
    version = .DSVERT_TYPED_BLOB_SOURCE_DESCRIPTOR_VERSION,
    source_path = normalizePath(path, mustWork = TRUE),
    identity = identity, payload_chars = identity$size,
    payload_sha256 = payload_sha256)
  c(unsigned, list(
    descriptor_mac = .dsvert_typed_blob_source_descriptor_mac(ss, unsigned)))
}

.dsvert_typed_blob_source_descriptor <- function(ss, descriptor,
                                                   source_path) {
  required <- c("version", "source_path", "identity", "payload_chars",
                "payload_sha256", "descriptor_mac")
  if (!is.list(descriptor) || is.null(names(descriptor)) ||
      anyDuplicated(names(descriptor)) ||
      !identical(sort(names(descriptor)), sort(required)) ||
      !identical(descriptor$version,
                 .DSVERT_TYPED_BLOB_SOURCE_DESCRIPTOR_VERSION) ||
      !is.character(descriptor$source_path) ||
      length(descriptor$source_path) != 1L || is.na(descriptor$source_path) ||
      !is.list(descriptor$identity) ||
      !is.numeric(descriptor$payload_chars) ||
      length(descriptor$payload_chars) != 1L ||
      !is.character(descriptor$payload_sha256) ||
      length(descriptor$payload_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", descriptor$payload_sha256) ||
      !is.character(descriptor$descriptor_mac) ||
      length(descriptor$descriptor_mac) != 1L) {
    stop("Invalid authenticated typed-source descriptor.", call. = FALSE)
  }
  unsigned <- descriptor[setdiff(names(descriptor), "descriptor_mac")]
  if (!identical(
      .dsvert_typed_blob_source_descriptor_mac(ss, unsigned),
      descriptor$descriptor_mac) ||
      !identical(normalizePath(source_path, mustWork = TRUE),
                 descriptor$source_path) ||
      !identical(.dsvert_typed_blob_source_identity(source_path),
                 descriptor$identity)) {
    stop("Typed-source descriptor no longer matches its private spool.",
         call. = FALSE)
  }
  descriptor
}

# Common ticket mint. In-memory producers pass only a descriptor; the single
# source-stream pilot additionally supplies a validated private spool path.
.dsvert_typed_blob_mint_descriptor <- function(
    ss, session_id, capability_id, recipient_pk, payload_chars,
    payload_sha256, context, producer = NULL, source_path = NULL,
    source_descriptor = NULL) {
  .dsvert_relay_validate_session_id(session_id)
  if (!is.environment(ss) || !identical(ss, .S(session_id))) {
    stop("Invalid typed-blob producer session.", call. = FALSE)
  }
  session <- .dsvert_typed_blob_session_context(ss)
  recipient_name <- .dsvert_typed_blob_recipient_name(ss, recipient_pk)
  resolved <- .dsvert_typed_blob_destination(
    capability_id, session$self_name, context)
  allowed_producers <- resolved$producer
  if (is.null(producer) && length(allowed_producers) == 1L) {
    producer <- allowed_producers[[1L]]
  }
  if (!is.character(producer) || length(producer) != 1L ||
      is.na(producer) || !producer %in% allowed_producers) {
    stop("Typed-blob producer does not own this capability.", call. = FALSE)
  }
  if (!is.numeric(payload_chars) || length(payload_chars) != 1L ||
      is.na(payload_chars) || !is.finite(payload_chars) ||
      payload_chars != floor(payload_chars) || payload_chars < 1 ||
      !is.character(payload_sha256) || length(payload_sha256) != 1L ||
      is.na(payload_sha256) ||
      !grepl("^[0-9a-f]{64}$", payload_sha256)) {
    stop("Invalid typed-blob payload descriptor.", call. = FALSE)
  }
  if (payload_chars > .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS) {
    .dsvert_resource_oversize(
      payload_chars, .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS,
      "typed-blob payload object")
  }
  if (xor(is.null(source_path), is.null(source_descriptor))) {
    stop("Typed-source spool and descriptor must be supplied together.",
         call. = FALSE)
  }
  if (!is.null(source_path)) {
    source_descriptor <- .dsvert_typed_blob_source_descriptor(
      ss, source_descriptor, source_path)
    if (!identical(source_descriptor$payload_chars,
                   as.numeric(payload_chars)) ||
        !identical(source_descriptor$payload_sha256, payload_sha256)) {
      stop("Typed-source spool conflicts with its payload descriptor.",
           call. = FALSE)
    }
  }
  if (is.null(ss$.typed_blob_send_sequence)) {
    ss$.typed_blob_send_sequence <- list()
  }
  stream_key <- .dsvert_typed_blob_stream_key(capability_id, recipient_name)
  outbound <- ss$.typed_blob_outbound %||% list()
  stream_pending <- vapply(outbound, function(record) {
    identical(record$stream_key, stream_key)
  }, logical(1L))
  if (any(stream_pending)) {
    stop("Typed-blob producer stream awaits a signed peer receipt.",
         call. = FALSE)
  }
  previous_sequence <- ss$.typed_blob_send_sequence[[stream_key]] %||% 0
  sequence <- previous_sequence + 1
  if (!is.numeric(sequence) || !is.finite(sequence) ||
      sequence != floor(sequence) || sequence > 2^53 - 1) {
    stop("Typed-blob send sequence is exhausted.", call. = FALSE)
  }
  issued_at <- .dsvert_typed_blob_now()
  expires_at <- issued_at + .DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS
  transfer_id <- .dsvert_typed_blob_random_transfer_id()
  body <- list(
    version = .DSVERT_TYPED_BLOB_TICKET_VERSION,
    session_id = session_id,
    transfer_id = transfer_id,
    replay_id = transfer_id,
    capability_id = capability_id,
    family = resolved$family,
    producer = producer,
    consumer = resolved$consumer,
    phase = resolved$phase,
    ring = resolved$ring,
    shape = resolved$shape,
    count = resolved$count,
    destination = resolved$slot,
    sender_name = session$self_name,
    recipient_name = recipient_name,
    peer_binding_digest = session$peer_binding_digest,
    sequence = .dsvert_typed_blob_count_string(sequence, "send sequence"),
    issued_at = .dsvert_typed_blob_count_string(issued_at, "issue time"),
    expires_at = .dsvert_typed_blob_count_string(expires_at, "expiry time"),
    context = .dsvert_typed_blob_context_token(resolved$context),
    payload_chars = as.numeric(payload_chars),
    payload_sha256 = payload_sha256)
  body_token <- .dsvert_typed_blob_body_token(body)
  identity <- .get_identity_keypair()
  own_identity <- .dsvert_normalize_crypto_b64(
    identity$identity_pk, 32L, "runtime identity public key")
  stored_identity <- .dsvert_normalize_crypto_b64(
    .key_get("identity_pk", ss), 32L, "session identity public key")
  if (!identical(own_identity, stored_identity)) {
    stop("Typed-blob runtime identity changed after session setup.",
         call. = FALSE)
  }
  signature <- base64_to_base64url(.sign_transport_pk(
    .dsvert_typed_blob_signature_message(body_token), identity$identity_sk))
  ticket <- .dsvert_relay_b64url_encode(charToRaw(as.character(
    jsonlite::toJSON(list(body = body_token, signature = signature),
                     auto_unbox = TRUE, null = "null", digits = NA))))
  if (nchar(ticket, type = "bytes") > .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES) {
    .dsvert_resource_oversize(
      nchar(ticket, type = "bytes"), .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES,
      "typed-blob ticket")
  }
  committed_source <- NULL
  committed_source_identity <- NULL
  committed <- FALSE
  on.exit(if (!committed && !is.null(committed_source) &&
             file.exists(committed_source)) unlink(committed_source), add = TRUE)
  if (!is.null(source_path)) {
    committed_source <- file.path(
      .dsvert_typed_blob_source_root(ss, create = TRUE),
      paste0(body$transfer_id, ".b64"))
    if (file.exists(committed_source) ||
        !file.rename(source_path, committed_source)) {
      stop("Could not commit the private typed-source spool atomically.",
           call. = FALSE)
    }
    Sys.chmod(committed_source, mode = "0600")
    committed_source_identity <-
      .dsvert_typed_blob_source_identity(committed_source)
    if (!identical(
        .dsvert_typed_blob_source_stable_identity(
          committed_source_identity),
        .dsvert_typed_blob_source_stable_identity(
          source_descriptor$identity))) {
      stop("Typed-source spool identity changed during atomic commit.",
           call. = FALSE)
    }
  }
  ss$.typed_blob_send_sequence[[stream_key]] <- sequence
  transfer <- list(
    ticket = ticket, transfer_id = body$transfer_id,
    capability_id = capability_id, sender_name = session$self_name,
    recipient_name = recipient_name,
    payload_chars = as.numeric(payload_chars),
    payload_sha256 = body$payload_sha256)
  if (is.null(ss$.typed_blob_outbound)) ss$.typed_blob_outbound <- list()
  ticket_digest <- digest::digest(
    ticket, algo = "sha256", serialize = FALSE)
  ss$.typed_blob_outbound[[body$transfer_id]] <- list(
    stream_key = stream_key, ticket_digest = digest::digest(
      ticket, algo = "sha256", serialize = FALSE),
    ticket = ticket,
    transfer_id = body$transfer_id, capability_id = capability_id,
    producer = producer, sender_name = session$self_name,
    recipient_name = recipient_name, sequence = sequence,
    peer_binding_digest = session$peer_binding_digest,
    payload_chars = as.numeric(payload_chars),
    payload_sha256 = body$payload_sha256, operation_key = NULL,
    issued_at = issued_at, expires_at = expires_at,
    source_path = committed_source,
    source_identity = committed_source_identity,
    source_frame_chars = NULL,
    source_high_water = 0, source_admitted_at = NULL,
    source_last_activity = NULL)
  if (is.null(ss$.typed_blob_outbound_ticket_index)) {
    ss$.typed_blob_outbound_ticket_index <- list()
  }
  ss$.typed_blob_outbound_ticket_index[[ticket_digest]] <- body$transfer_id
  committed <- TRUE
  transfer
}

# Internal only. A purpose-specific server producer calls this with a fixed
# capability after creating the complete in-memory opaque payload.
.dsvert_typed_blob_mint <- function(ss, session_id, capability_id,
                                    recipient_pk, payload, context,
                                    producer = NULL) {
  if (!is.character(payload) || length(payload) != 1L || is.na(payload) ||
      !nzchar(payload) ||
      !grepl("^[A-Za-z0-9_-]+$", payload,
             perl = TRUE, useBytes = TRUE) || nchar(payload) %% 4L == 1L) {
    stop("Typed-blob producer emitted a non-canonical opaque payload.",
         call. = FALSE)
  }
  .dsvert_typed_blob_mint_descriptor(
    ss, session_id, capability_id, recipient_pk,
    nchar(payload, type = "bytes"),
    digest::digest(payload, algo = "sha256", serialize = FALSE),
    context, producer = producer)
}

.dsvert_typed_blob_mint_file <- function(
    ss, session_id, capability_id, recipient_pk, source_path, context,
    producer = NULL, source_descriptor = NULL) {
  if (is.null(source_descriptor)) {
    source_descriptor <- .dsvert_typed_blob_source_file_metadata(
      ss, source_path)
  }
  .dsvert_typed_blob_mint_descriptor(
    ss, session_id, capability_id, recipient_pk,
    source_descriptor$payload_chars, source_descriptor$payload_sha256,
    context, producer = producer, source_path = source_path,
    source_descriptor = source_descriptor)
}

#' Create one data-free source-stream diagnostic payload (AGGREGATE)
#'
#' This pilot never reads protected data. The packaged runtime writes random
#' Base64url bytes directly to a private bounded spool and returns only length
#' and SHA-256 metadata. It exists to exercise the source-stream transport;
#' it is not a statistical method or evidence that legacy producers stream.
#'
#' @param recipient_pk Pinned recipient transport public key.
#' @param payload_bytes Public raw diagnostic payload size.
#' @param session_id Active pinned-peer MPC session identifier.
#' @return A producer-minted typed transfer contract, without payload bytes.
mpcTypedSourceProbeDS <- function(recipient_pk, payload_bytes, session_id) {
  tryCatch(
    .mpcTypedSourceProbeDS_impl(recipient_pk, payload_bytes, session_id),
    interrupt = function(e) stop(e),
    error = function(e) {
      if (inherits(e, "dsvert_resource_backpressure") ||
          inherits(e, "dsvert_resource_oversize")) stop(e)
      .dsvert_typed_blob_rejection("source-probe")
    })
}

.mpcTypedSourceProbeDS_impl <- function(
    recipient_pk, payload_bytes, session_id) {
  .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  payload_bytes <- .dsvert_typed_blob_uint(
    payload_bytes, "source-probe byte count", 1,
    floor(.DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS * 3 / 4))
  request <- list(
    recipient_pk = recipient_pk,
    payload_bytes = as.numeric(payload_bytes), session_id = session_id)
  replay <- .dsvert_typed_blob_operation_replay(
    ss, "mpcTypedSourceProbeDS", request)
  if (isTRUE(replay$hit)) return(replay$result)

  expected_chars <- ceiling(4 * payload_bytes / 3)
  capacity <- .dsvert_typed_blob_spool_max_bytes()
  .dsvert_typed_blob_sweep_expired(ss)
  retained <- .dsvert_typed_blob_retained_bytes(ss)
  if (expected_chars > capacity) {
    .dsvert_resource_oversize(
      expected_chars, capacity, "typed-source session spool")
  }
  if (retained > capacity - expected_chars) {
    .dsvert_resource_backpressure(
      retained, expected_chars, capacity, "typed-source session spool")
  }
  .dsvert_resource_admit(ss, expected_chars)
  accounting_head <- ss$.typed_blob_retained_head
  .dsvert_mpc_require_capabilities("typed_source_stream")
  stage_path <- .dsvert_typed_blob_source_stage_path(ss)
  committed <- FALSE
  on.exit(if (!committed && file.exists(stage_path)) unlink(stage_path),
          add = TRUE)
  generated <- .callMpcTool("typed-source-stream-probe", list(
    output_path = stage_path, raw_bytes = as.numeric(payload_bytes)))
  required <- c("version", "payload_chars", "payload_sha256")
  if (!is.list(generated) || is.null(names(generated)) ||
      anyDuplicated(names(generated)) ||
      !identical(sort(names(generated)), sort(required)) ||
      !identical(generated$version, "dsvert-typed-source-stream-v1") ||
      !identical(as.numeric(generated$payload_chars),
                 as.numeric(expected_chars)) ||
      !is.character(generated$payload_sha256) ||
      length(generated$payload_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", generated$payload_sha256)) {
    stop("Typed-source runtime returned invalid metadata.", call. = FALSE)
  }
  metadata <- .dsvert_typed_blob_source_file_metadata(ss, stage_path)
  if (!identical(metadata$payload_chars, as.numeric(expected_chars)) ||
      !identical(metadata$payload_sha256, generated$payload_sha256)) {
    stop("Typed-source runtime output failed its integrity check.",
         call. = FALSE)
  }
  transfer <- .dsvert_typed_blob_mint_file(
    ss, session_id, "blob.transport.source-probe.v1", recipient_pk,
    stage_path,
    list(raw_bytes = format(
      payload_bytes, scientific = FALSE, trim = TRUE), ring = "63"),
    producer = "mpcTypedSourceProbeDS", source_descriptor = metadata)
  .dsvert_typed_blob_accounting_adjust(
    ss, accounting_head, as.numeric(expected_chars))
  committed <- TRUE
  .dsvert_typed_blob_operation_commit(
    ss, "mpcTypedSourceProbeDS", request,
    list(source_transfer = transfer))
}

.dsvert_typed_blob_source_ack <- function(
    transfer_id, offset, chunk, total, payload_sha256) {
  chunk_chars <- nchar(chunk, type = "bytes")
  list(
    version = "dsvert-typed-blob-source-v1",
    transfer_id = transfer_id, offset = as.numeric(offset), chunk = chunk,
    chunk_chars = as.numeric(chunk_chars),
    chunk_sha256 = digest::digest(
      chunk, algo = "sha256", serialize = FALSE),
    total_chars = as.numeric(total), payload_sha256 = payload_sha256,
    final = identical(as.numeric(offset + chunk_chars), as.numeric(total)))
}

.dsvert_typed_blob_expire_outbound_operation <- function(ss, outbound) {
  accounting_head <- ss$.typed_blob_retained_head
  operation_key <- outbound$operation_key
  operation <- if (is.character(operation_key) &&
      length(operation_key) == 1L && !is.na(operation_key) &&
      nzchar(operation_key)) {
    (ss$.typed_blob_pending_operations %||% list())[[operation_key]]
  } else {
    NULL
  }
  transfer_ids <- if (is.list(operation) &&
      is.character(operation$transfer_ids) &&
      outbound$transfer_id %in% operation$transfer_ids) {
    operation$transfer_ids
  } else {
    outbound$transfer_id
  }
  records <- (ss$.typed_blob_outbound %||% list())[transfer_ids]
  source_records <- Filter(function(record) {
    is.list(record) && !is.null(record$source_path)
  }, records)
  released_bytes <- 0
  if (length(source_records)) {
    root <- .dsvert_typed_blob_source_root(ss, create = FALSE)
    paths <- character()
    for (record in source_records) {
      path <- record$source_path
      safe_path <- dir.exists(root) && is.character(path) &&
        length(path) == 1L && !is.na(path) && nzchar(path) &&
        identical(normalizePath(dirname(path), mustWork = TRUE), root) &&
        grepl("^tb_[0-9a-f]{32}\\.b64$", basename(path))
      if (!isTRUE(safe_path)) {
        stop("Typed-source inactivity cleanup found an invalid producer spool.",
             call. = FALSE)
      }
      if (!file.exists(path)) next
      if (nzchar(Sys.readlink(path)) ||
          !identical(.dsvert_typed_blob_source_identity(path),
                     record$source_identity)) {
        stop("Typed-source inactivity cleanup found an invalid producer spool.",
             call. = FALSE)
      }
      paths <- c(paths, path)
      released_bytes <- released_bytes + as.numeric(file.size(path))
    }
    if (length(paths)) unlink(paths)
    if (length(paths) && any(file.exists(paths))) {
      stop("Could not release an inactive typed-source spool.",
           call. = FALSE)
    }
  }
  for (transfer_id in transfer_ids) {
    record <- (ss$.typed_blob_outbound %||% list())[[transfer_id]]
    if (!is.null(record) && !is.null(ss$.typed_blob_outbound_ticket_index)) {
      ss$.typed_blob_outbound_ticket_index[[record$ticket_digest]] <- NULL
    }
    ss$.typed_blob_outbound[[transfer_id]] <- NULL
  }
  if (!is.null(operation)) {
    ss$.typed_blob_pending_operations[[operation_key]] <- NULL
  }
  if (released_bytes > 0) {
    .dsvert_typed_blob_accounting_adjust(
      ss, accounting_head, -released_bytes)
  }
  invisible(TRUE)
}

#' Read one fixed source-stream frame from its producer (AGGREGATE)
#'
#' The signed ticket is the only selector. The endpoint accepts no path, key,
#' purpose or recipient and permits only fixed-geometry absolute-offset reads.
#' Exact replay is idempotent and does not extend the source lifetime.
#'
#' @param ticket Producer-minted signed transfer ticket.
#' @param offset Absolute zero-based character offset.
#' @param max_chars Immutable frame geometry selected before the first read.
#' @param session_id Active MPC session identifier.
#' @return One typed Base64url frame with length and SHA-256 commitments.
mpcTypedBlobReadDS <- function(ticket, offset, max_chars, session_id) {
  tryCatch(
    .mpcTypedBlobReadDS_impl(ticket, offset, max_chars, session_id),
    interrupt = function(e) stop(e),
    error = function(e) {
      if (inherits(e, "dsvert_resource_backpressure") ||
          inherits(e, "dsvert_resource_oversize")) stop(e)
      .dsvert_typed_blob_rejection("read")
    })
}

.mpcTypedBlobReadDS_impl <- function(ticket, offset, max_chars, session_id) {
  .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  if (!is.character(ticket) || length(ticket) != 1L || is.na(ticket) ||
      !nzchar(ticket) ||
      !grepl("^[A-Za-z0-9_-]+$", ticket, perl = TRUE, useBytes = TRUE)) {
    stop("Invalid typed-source ticket.", call. = FALSE)
  }
  if (nchar(ticket, type = "bytes") > .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES) {
    .dsvert_resource_oversize(
      nchar(ticket, type = "bytes"), .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES,
      "typed-source ticket")
  }
  ticket_digest <- digest::digest(
    ticket, algo = "sha256", serialize = FALSE)
  transfer_id <- (ss$.typed_blob_outbound_ticket_index %||%
                    list())[[ticket_digest]]
  outbound <- (ss$.typed_blob_outbound %||% list())[[transfer_id]]
  if (is.null(outbound) || !identical(outbound$ticket, ticket) ||
      !identical(outbound$ticket_digest, ticket_digest) ||
      !is.character(outbound$source_path) ||
      length(outbound$source_path) != 1L || is.na(outbound$source_path)) {
    stop("Typed-source ticket has no pending producer spool.", call. = FALSE)
  }
  total <- .dsvert_typed_blob_uint(
    outbound$payload_chars, "source length", 1,
    .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS)
  offset <- .dsvert_typed_blob_uint(
    offset, "source offset", 0, total - 1)
  max_chars <- .dsvert_typed_blob_uint(
    max_chars, "source frame geometry", 1,
    .DSVERT_TYPED_BLOB_MAX_FRAME_BYTES)
  now <- .dsvert_typed_blob_now()
  if (is.null(outbound$source_admitted_at)) {
    if (!identical(offset, 0) || now > outbound$expires_at) {
      stop("Typed-source transfer is expired or did not start at zero.",
           call. = FALSE)
    }
    outbound$source_admitted_at <- now
    outbound$source_last_activity <- now
    outbound$source_frame_chars <- max_chars
  } else if (!identical(outbound$source_frame_chars, max_chars)) {
    stop("Typed-source geometry is invalid.", call. = FALSE)
  } else if (!is.numeric(outbound$source_last_activity) ||
             length(outbound$source_last_activity) != 1L ||
             is.na(outbound$source_last_activity) ||
             now - outbound$source_last_activity > .SESSION_TTL_SECONDS) {
    .dsvert_typed_blob_expire_outbound_operation(ss, outbound)
    stop("Typed-source admitted transfer exceeded its inactivity lease.",
         call. = FALSE)
  }
  high_water <- .dsvert_typed_blob_uint(
    outbound$source_high_water, "source high-water mark", 0, total)
  if (offset > high_water || offset %% max_chars != 0) {
    stop("Typed-source read is out of order.", call. = FALSE)
  }
  path <- outbound$source_path
  root <- .dsvert_typed_blob_source_root(ss, create = FALSE)
  if (!dir.exists(root) || !file.exists(path) || nzchar(Sys.readlink(path)) ||
      !identical(normalizePath(dirname(path), mustWork = TRUE), root) ||
      !grepl("^tb_[0-9a-f]{32}\\.b64$", basename(path)) ||
      !identical(.dsvert_typed_blob_source_identity(path),
                 outbound$source_identity) ||
      !identical(outbound$source_identity$size, as.numeric(total))) {
    stop("Typed-source spool integrity changed.", call. = FALSE)
  }
  count <- min(max_chars, total - offset)
  con <- file(path, "rb")
  on.exit(close(con), add = TRUE)
  seek(con, where = offset, origin = "start")
  bytes <- readBin(con, "raw", n = count)
  if (length(bytes) != count) {
    stop("Typed-source frame was truncated.", call. = FALSE)
  }
  if (!identical(.dsvert_typed_blob_source_identity(path),
                 outbound$source_identity)) {
    stop("Typed-source spool changed during frame read.", call. = FALSE)
  }
  chunk <- rawToChar(bytes)
  if (identical(offset, high_water)) {
    outbound$source_high_water <- as.numeric(offset + count)
    outbound$source_last_activity <- now
    ss$.typed_blob_outbound[[transfer_id]] <- outbound
    .session_progress(ss, now)
  }
  .dsvert_typed_blob_source_ack(
    transfer_id, offset, chunk, total, outbound$payload_sha256)
}

.dsvert_typed_blob_parse_ticket <- function(ticket, ss, session_id) {
  if (!is.character(ticket) || length(ticket) != 1L || is.na(ticket)) {
    stop("Invalid typed-blob ticket.", call. = FALSE)
  }
  if (nchar(ticket, type = "bytes") > .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES) {
    .dsvert_resource_oversize(
      nchar(ticket, type = "bytes"), .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES,
      "typed-blob ticket")
  }
  ticket_raw <- .dsvert_relay_b64url_decode(ticket, "typed-blob ticket")
  envelope <- tryCatch(jsonlite::fromJSON(
    rawToChar(ticket_raw), simplifyVector = FALSE), error = function(e) NULL)
  if (!is.list(envelope) ||
      !identical(sort(names(envelope)), c("body", "signature"))) {
    stop("Invalid typed-blob ticket envelope.", call. = FALSE)
  }
  body_raw <- .dsvert_relay_b64url_decode(
    envelope$body, "typed-blob ticket body")
  body <- tryCatch(jsonlite::fromJSON(
    rawToChar(body_raw), simplifyVector = FALSE), error = function(e) NULL)
  required <- c(
    "version", "session_id", "transfer_id", "replay_id", "capability_id",
    "family", "producer", "consumer", "phase", "ring", "shape", "count",
    "destination", "sender_name", "recipient_name", "peer_binding_digest",
    "sequence", "issued_at", "expires_at", "context", "payload_chars",
    "payload_sha256")
  if (!is.list(body) ||
      !identical(sort(names(body)), sort(required)) ||
      !identical(body$version, .DSVERT_TYPED_BLOB_TICKET_VERSION) ||
      !identical(body$session_id, session_id) ||
      !is.character(body$transfer_id) ||
      !grepl(.DSVERT_TYPED_BLOB_TRANSFER_RE, body$transfer_id) ||
      !identical(body$replay_id, body$transfer_id) ||
      !is.character(body$payload_sha256) ||
      !grepl("^[0-9a-f]{64}$", body$payload_sha256)) {
    stop("Invalid typed-blob ticket body.", call. = FALSE)
  }
  session <- .dsvert_typed_blob_session_context(ss)
  sender <- .dsvert_validate_logical_peer_name(body$sender_name)
  recipient <- .dsvert_validate_logical_peer_name(body$recipient_name)
  if (!identical(recipient, session$self_name) ||
      identical(sender, recipient) ||
      is.null(session$peer_identity_pks[[sender]]) ||
      !identical(body$peer_binding_digest, session$peer_binding_digest)) {
    stop("Typed-blob ticket is not bound to this pinned-peer session.",
         call. = FALSE)
  }
  signature_raw <- .dsvert_relay_b64url_decode(
    envelope$signature, "typed-blob ticket signature")
  if (length(signature_raw) != 64L ||
      !.verify_peer_identity(
        .dsvert_typed_blob_signature_message(envelope$body),
        session$peer_identity_pks[[sender]],
        .base64url_to_base64(envelope$signature))) {
    stop("Typed-blob producer signature is invalid.", call. = FALSE)
  }
  payload_chars <- suppressWarnings(as.numeric(body$payload_chars))
  if (length(payload_chars) != 1L || is.na(payload_chars) ||
      !is.finite(payload_chars) || payload_chars != floor(payload_chars) ||
      payload_chars < 1) {
    stop("Invalid typed-blob payload length.", call. = FALSE)
  }
  if (payload_chars > .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS) {
    .dsvert_resource_oversize(
      payload_chars, .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS,
      "typed-blob signed payload")
  }
  context_raw <- .dsvert_relay_b64url_decode(
    body$context, "typed-blob producer context")
  if (length(context_raw) > .DSVERT_TYPED_BLOB_MAX_CONTEXT_BYTES) {
    .dsvert_resource_oversize(
      length(context_raw), .DSVERT_TYPED_BLOB_MAX_CONTEXT_BYTES,
      "typed-blob producer context")
  }
  context <- tryCatch(jsonlite::fromJSON(
    rawToChar(context_raw), simplifyVector = FALSE),
    error = function(e) NULL)
  resolved <- .dsvert_typed_blob_destination(
    body$capability_id, sender, context)
  metadata_valid <-
    identical(body$family, resolved$family) &&
    is.character(body$producer) && length(body$producer) == 1L &&
    body$producer %in% resolved$producer &&
    identical(body$consumer, resolved$consumer) &&
    identical(body$phase, resolved$phase) &&
    identical(body$ring, resolved$ring) &&
    identical(body$shape, resolved$shape) &&
    identical(body$count, resolved$count) &&
    identical(body$destination, resolved$slot)
  if (!metadata_valid) {
    stop("Typed-blob ticket metadata conflicts with its capability.",
         call. = FALSE)
  }
  sequence <- .dsvert_typed_blob_integer_string(
    body$sequence, "receive sequence", maximum = 2^53 - 1)
  issued_at <- .dsvert_typed_blob_integer_string(
    body$issued_at, "issue time", maximum = 2^53 - 1)
  expires_at <- .dsvert_typed_blob_integer_string(
    body$expires_at, "expiry time", maximum = 2^53 - 1)
  now <- .dsvert_typed_blob_now()
  ticket_digest <- digest::digest(
    ticket, algo = "sha256", serialize = FALSE)
  admitted_state <- (ss$.typed_blob_transfers %||% list())[[body$transfer_id]]
  completed_state <- (ss$.typed_blob_receipts %||% list())[[body$transfer_id]]
  previously_admitted <-
    (!is.null(admitted_state) &&
     identical(admitted_state$ticket_digest, ticket_digest)) ||
    (!is.null(completed_state) &&
     identical(completed_state$ticket_digest, ticket_digest))
  if (as.numeric(issued_at) > now + .DSVERT_TYPED_BLOB_CLOCK_SKEW_SECONDS ||
      (as.numeric(expires_at) < now && !previously_admitted) ||
      as.numeric(expires_at) - as.numeric(issued_at) !=
        .DSVERT_TYPED_BLOB_TICKET_TTL_SECONDS) {
    stop("Typed-blob ticket is expired or has an invalid lifetime.",
         call. = FALSE)
  }
  list(
    ticket_digest = ticket_digest,
    session_id = body$session_id,
    transfer_id = body$transfer_id,
    capability_id = body$capability_id,
    family = body$family, producer = body$producer,
    consumer = body$consumer, phase = body$phase,
    ring = body$ring, shape = body$shape, count = body$count,
    context = resolved$context,
    sender_name = sender, recipient_name = recipient,
    destination = resolved$slot,
    sequence = as.numeric(sequence), issued_at = as.numeric(issued_at),
    expires_at = as.numeric(expires_at),
    payload_chars = as.numeric(payload_chars),
    payload_sha256 = body$payload_sha256)
}

# After the first authenticated frame, cache the verified plan by the ticket's
# SHA-256 digest. Subsequent frames still bind to the exact ticket bytes but do
# not repeat JSON decoding and Ed25519 verification for every DSI chunk.
.dsvert_typed_blob_plan <- function(ticket, ss, session_id) {
  if (is.character(ticket) && length(ticket) == 1L && !is.na(ticket)) {
    ticket_digest <- digest::digest(
      ticket, algo = "sha256", serialize = FALSE)
    transfer_id <- (ss$.typed_blob_ticket_index %||% list())[[ticket_digest]]
    if (!is.null(transfer_id)) {
      state <- (ss$.typed_blob_transfers %||% list())[[transfer_id]]
      if (!is.null(state$verified_plan) &&
          identical(state$ticket_digest, ticket_digest) &&
          identical(state$session_id, session_id)) return(state$verified_plan)
      receipt <- (ss$.typed_blob_receipts %||% list())[[transfer_id]]
      if (!is.null(receipt$plan) &&
          identical(receipt$plan$ticket_digest, ticket_digest) &&
          identical(receipt$plan$session_id, session_id)) return(receipt$plan)
      ss$.typed_blob_ticket_index[[ticket_digest]] <- NULL
    }
  }
  .dsvert_typed_blob_parse_ticket(ticket, ss, session_id)
}

.dsvert_typed_blob_destination_present <- function(ss, destination) {
  in_memory <- !is.null(ss$blobs[[destination]])
  path <- if (is.null(ss$.session_dir)) NULL else
    file.path(ss$.session_dir, "blobs", destination)
  isTRUE(in_memory) || (!is.null(path) && file.exists(path))
}

# Consume only a blob whose committed destination carries producer-signed
# provenance for the exact capability/context expected by this consumer. A
# legacy mpcStoreBlobDS write has no such provenance and is therefore rejected.
.dsvert_typed_blob_consume <- function(ss, capability_id, context,
                                       sender_name = NULL,
                                       required = TRUE, consume = TRUE) {
  if (!is.environment(ss)) stop("Invalid typed-blob session.", call. = FALSE)
  if (!is.logical(consume) || length(consume) != 1L || is.na(consume)) {
    stop("Invalid typed-blob consumption mode.", call. = FALSE)
  }
  if (!is.null(sender_name)) {
    sender_name <- .dsvert_validate_logical_peer_name(sender_name)
    resolved <- .dsvert_typed_blob_destination(
      capability_id, sender_name, context)
    candidates <- resolved$slot
  } else {
    records <- ss$.typed_blob_destinations %||% list()
    candidates <- names(records)[vapply(records, function(record) {
      identical(record$capability_id, capability_id)
    }, logical(1L))]
    if (length(candidates) == 1L) {
      sender_name <- records[[candidates]]$sender_name
      resolved <- .dsvert_typed_blob_destination(
        capability_id, sender_name, context)
      if (!identical(resolved$slot, candidates)) candidates <- character()
    }
  }
  if (length(candidates) != 1L) {
    if (!isTRUE(required) && !length(candidates)) return(NULL)
    stop("Typed-blob consumer could not resolve one exact producer transfer.",
         call. = FALSE)
  }
  destination <- candidates[[1L]]
  record <- (ss$.typed_blob_destinations %||% list())[[destination]]
  if (is.null(record)) {
    if (.dsvert_typed_blob_destination_present(ss, destination)) {
      stop("Typed-blob consumer rejected a legacy or unprovenanced blob.",
           call. = FALSE)
    }
    if (!isTRUE(required)) return(NULL)
    stop("Required typed-blob transfer is not committed.", call. = FALSE)
  }
  expected <- .dsvert_typed_blob_destination(
    capability_id, record$sender_name, context)
  valid <- identical(record$capability_id, capability_id) &&
    identical(record$sender_name, sender_name) &&
    identical(record$recipient_name,
              .dsvert_typed_blob_session_context(ss)$self_name) &&
    identical(record$destination, expected$slot) &&
    identical(record$family, expected$family) &&
    record$producer %in% expected$producer &&
    identical(record$consumer, expected$consumer) &&
    identical(record$phase, expected$phase) &&
    identical(record$ring, expected$ring) &&
    identical(record$shape, expected$shape) &&
    identical(record$count, expected$count) &&
    identical(record$context, expected$context)
  if (!valid) {
    stop("Typed-blob consumer provenance/shape contract mismatch.",
         call. = FALSE)
  }
  if (!.dsvert_typed_blob_destination_present(ss, destination)) {
    stop("Typed-blob provenance exists without a committed payload.",
         call. = FALSE)
  }
  accounting_head <- ss$.typed_blob_retained_head
  destination_path <- if (is.null(ss$.session_dir)) NULL else
    file.path(ss$.session_dir, "blobs", destination)
  retained_size <- if (isTRUE(consume) && !is.null(destination_path) &&
      file.exists(destination_path) && !nzchar(Sys.readlink(destination_path))) {
    as.numeric(file.size(destination_path))
  } else {
    0
  }
  payload <- if (isTRUE(consume)) {
    value <- .blob_consume(
      destination, ss, invalidate_accounting = FALSE)
    if (retained_size > 0) {
      if (file.exists(destination_path)) {
        stop("Could not release the consumed typed-blob spool.",
             call. = FALSE)
      }
      .dsvert_typed_blob_accounting_adjust(
        ss, accounting_head, -retained_size)
    }
    value
  } else {
    .blob_read(destination, ss)
  }
  if (isTRUE(consume)) ss$.typed_blob_destinations[[destination]] <- NULL
  if (is.null(payload) || !identical(
      digest::digest(payload, algo = "sha256", serialize = FALSE),
      record$payload_sha256)) {
    stop("Typed-blob committed payload failed its final digest check.",
         call. = FALSE)
  }
  if (isTRUE(consume)) {
    .dsvert_typed_blob_compact_consumed_receipt(ss, record$transfer_id)
  }
  payload
}

.dsvert_typed_blob_uint <- function(value, what, minimum, maximum) {
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value != floor(value) || value < minimum) {
    stop("Invalid typed-blob ", what, ".", call. = FALSE)
  }
  if (value > maximum) {
    .dsvert_resource_oversize(
      value, maximum, paste("typed-blob", what))
  }
  value
}

.dsvert_typed_blob_spool_path <- function(ss, transfer_id) {
  if (!grepl(.DSVERT_TYPED_BLOB_TRANSFER_RE, transfer_id)) {
    stop("Invalid typed-blob transfer identifier.", call. = FALSE)
  }
  root <- file.path(.ensure_session_dir(ss), "typed")
  if (!dir.exists(root) &&
      !dir.create(root, mode = "0700", showWarnings = FALSE)) {
    stop("Could not create the private typed-blob spool.", call. = FALSE)
  }
  Sys.chmod(root, mode = "0700")
  file.path(root, transfer_id)
}

.dsvert_typed_blob_mint_receipt <- function(plan, ss) {
  session <- .dsvert_typed_blob_session_context(ss)
  if (!identical(plan$recipient_name, session$self_name)) {
    stop("Typed-blob receipt recipient does not own this session.",
         call. = FALSE)
  }
  body <- list(
    version = .DSVERT_TYPED_BLOB_RECEIPT_VERSION,
    session_id = plan$session_id,
    transfer_id = plan$transfer_id,
    capability_id = plan$capability_id,
    sender_name = plan$sender_name,
    recipient_name = plan$recipient_name,
    peer_binding_digest = session$peer_binding_digest,
    sequence = .dsvert_typed_blob_count_string(
      plan$sequence, "receipt sequence"),
    ticket_digest = plan$ticket_digest,
    payload_chars = as.numeric(plan$payload_chars),
    payload_sha256 = plan$payload_sha256)
  body_token <- .dsvert_typed_blob_body_token(body)
  identity <- .get_identity_keypair()
  own_identity <- .dsvert_normalize_crypto_b64(
    identity$identity_pk, 32L, "runtime identity public key")
  stored_identity <- .dsvert_normalize_crypto_b64(
    .key_get("identity_pk", ss), 32L, "session identity public key")
  if (!identical(own_identity, stored_identity)) {
    stop("Typed-blob runtime identity changed before receipt signing.",
         call. = FALSE)
  }
  signature <- base64_to_base64url(.sign_transport_pk(
    .dsvert_typed_blob_receipt_signature_message(body_token),
    identity$identity_sk))
  .dsvert_relay_b64url_encode(charToRaw(as.character(jsonlite::toJSON(
    list(body = body_token, signature = signature), auto_unbox = TRUE,
    null = "null", digits = NA))))
}

.dsvert_typed_blob_parse_receipt <- function(receipt, ss, session_id) {
  if (!is.character(receipt) || length(receipt) != 1L || is.na(receipt) ||
      !nzchar(receipt)) {
    stop("Invalid typed-blob receipt.", call. = FALSE)
  }
  if (nchar(receipt, type = "bytes") >
      .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES) {
    .dsvert_resource_oversize(
      nchar(receipt, type = "bytes"), .DSVERT_TYPED_BLOB_MAX_TICKET_BYTES,
      "typed-blob receipt")
  }
  envelope_raw <- .dsvert_relay_b64url_decode(
    receipt, "typed-blob receipt")
  envelope <- tryCatch(jsonlite::fromJSON(
    rawToChar(envelope_raw), simplifyVector = FALSE),
    error = function(e) NULL)
  if (!is.list(envelope) ||
      !identical(sort(names(envelope)), c("body", "signature"))) {
    stop("Invalid typed-blob receipt envelope.", call. = FALSE)
  }
  body_raw <- .dsvert_relay_b64url_decode(
    envelope$body, "typed-blob receipt body")
  body <- tryCatch(jsonlite::fromJSON(
    rawToChar(body_raw), simplifyVector = FALSE), error = function(e) NULL)
  required <- c(
    "version", "session_id", "transfer_id", "capability_id",
    "sender_name", "recipient_name", "peer_binding_digest", "sequence",
    "ticket_digest", "payload_chars", "payload_sha256")
  if (!is.list(body) ||
      !identical(sort(names(body)), sort(required)) ||
      !identical(body$version, .DSVERT_TYPED_BLOB_RECEIPT_VERSION) ||
      !identical(body$session_id, session_id) ||
      !is.character(body$transfer_id) ||
      !grepl(.DSVERT_TYPED_BLOB_TRANSFER_RE, body$transfer_id) ||
      !is.character(body$ticket_digest) ||
      !grepl("^[0-9a-f]{64}$", body$ticket_digest) ||
      !is.character(body$payload_sha256) ||
      !grepl("^[0-9a-f]{64}$", body$payload_sha256)) {
    stop("Invalid typed-blob receipt body.", call. = FALSE)
  }
  session <- .dsvert_typed_blob_session_context(ss)
  sender <- .dsvert_validate_logical_peer_name(body$sender_name)
  recipient <- .dsvert_validate_logical_peer_name(body$recipient_name)
  if (!identical(sender, session$self_name) || identical(sender, recipient) ||
      is.null(session$peer_identity_pks[[recipient]]) ||
      !identical(body$peer_binding_digest, session$peer_binding_digest)) {
    stop("Typed-blob receipt is not bound to this pinned-peer session.",
         call. = FALSE)
  }
  signature_raw <- .dsvert_relay_b64url_decode(
    envelope$signature, "typed-blob receipt signature")
  if (length(signature_raw) != 64L ||
      !.verify_peer_identity(
        .dsvert_typed_blob_receipt_signature_message(envelope$body),
        session$peer_identity_pks[[recipient]],
        .base64url_to_base64(envelope$signature))) {
    stop("Typed-blob peer receipt signature is invalid.", call. = FALSE)
  }
  sequence <- as.numeric(.dsvert_typed_blob_integer_string(
    body$sequence, "receipt sequence", maximum = 2^53 - 1))
  payload_chars <- as.numeric(.dsvert_typed_blob_integer_string(
    body$payload_chars, "receipt payload length",
    maximum = .DSVERT_TYPED_BLOB_MAX_PAYLOAD_CHARS))
  list(
    receipt_digest = digest::digest(
      receipt, algo = "sha256", serialize = FALSE),
    transfer_id = body$transfer_id,
    capability_id = body$capability_id,
    sender_name = sender, recipient_name = recipient,
    peer_binding_digest = body$peer_binding_digest,
    sequence = sequence, ticket_digest = body$ticket_digest,
    payload_chars = payload_chars,
    payload_sha256 = body$payload_sha256)
}

.dsvert_typed_blob_receipt_ack <- function(transfer_id) {
  list(version = .DSVERT_TYPED_BLOB_RECEIPT_VERSION,
       transfer_id = transfer_id, confirmed = TRUE)
}

# Keep exactly one terminal acknowledgement per purpose-bound peer stream.  A
# lost DSI response can only require replay of the current terminal phase: a
# later sequence on the same stream proves that the earlier acknowledgement was
# observed.  This bounds receipt memory independently of the number of
# successful transfers in a long-lived session.
.dsvert_typed_blob_record_latest <- function(ss, records_name, latest_name,
                                             stream_key, transfer_id, record) {
  records <- ss[[records_name]] %||% list()
  latest <- ss[[latest_name]] %||% list()
  previous <- latest[[stream_key]]
  if (is.character(previous) && length(previous) == 1L &&
      !is.na(previous) && nzchar(previous) &&
      !identical(previous, transfer_id)) {
    old <- records[[previous]]
    if (!is.null(old$ticket_digest) &&
        !is.null(ss$.typed_blob_ticket_index)) {
      ss$.typed_blob_ticket_index[[old$ticket_digest]] <- NULL
    }
    records[[previous]] <- NULL
  }
  records[[transfer_id]] <- record
  latest[[stream_key]] <- transfer_id
  ss[[records_name]] <- records
  ss[[latest_name]] <- latest
  invisible(record)
}

# After one-shot consumption only the final request can still be ambiguous to
# a sender that lost its terminal acknowledgement.  Keep that exact replay and
# discard all earlier frame boundaries so completed metadata is constant-size.
.dsvert_typed_blob_compact_consumed_receipt <- function(ss, transfer_id) {
  receipts <- ss$.typed_blob_receipts %||% list()
  receipt <- receipts[[transfer_id]]
  if (is.null(receipt)) return(invisible(FALSE))
  receipt$frame_offsets <- as.numeric(receipt$final_offset)
  receipt$frame_chars <- as.numeric(receipt$final_chars)
  receipts[[transfer_id]] <- receipt
  ss$.typed_blob_receipts <- receipts
  invisible(TRUE)
}

.dsvert_typed_blob_completed_frame_matches <- function(
    ss, receipt, offset, chunk, chunk_chars, frame_hash) {
  if (!is.list(receipt) || !is.numeric(receipt$frame_offsets) ||
      !is.numeric(receipt$frame_chars) ||
      length(receipt$frame_offsets) != length(receipt$frame_chars)) {
    return(FALSE)
  }
  index <- match(as.numeric(offset), receipt$frame_offsets)
  if (is.na(index) ||
      !identical(as.numeric(chunk_chars), receipt$frame_chars[[index]])) {
    return(FALSE)
  }
  if (identical(as.numeric(offset), receipt$final_offset)) {
    return(identical(receipt$final_hash, frame_hash))
  }

  # Before one-shot consumption, compare a bounded slice of the committed
  # destination instead of retaining one R list/hash object per frame.  After
  # consumption only the terminal frame remains replayable, which is the sole
  # response that can still be ambiguous in the sequential absolute-offset
  # protocol.
  destination <- receipt$plan$destination
  if (!is.character(destination) || length(destination) != 1L ||
      is.na(destination) || !nzchar(destination) ||
      !.dsvert_typed_blob_destination_present(ss, destination)) {
    return(FALSE)
  }
  expected <- NULL
  memory <- ss$blobs[[destination]]
  if (!is.null(memory)) {
    expected <- substr(memory, offset + 1, offset + chunk_chars)
  } else {
    path <- file.path(.assert_session_dir(ss), "blobs", destination)
    if (!file.exists(path) || nzchar(Sys.readlink(path))) return(FALSE)
    con <- file(path, "rb")
    on.exit(close(con), add = TRUE)
    seek(con, where = offset, origin = "start")
    value <- readBin(con, "raw", n = chunk_chars)
    if (length(value) != chunk_chars) return(FALSE)
    expected <- rawToChar(value)
  }
  identical(
    digest::digest(expected, algo = "sha256", serialize = FALSE),
    frame_hash) && identical(expected, chunk)
}

#' Confirm receipt of one producer-minted typed blob (AGGREGATE)
#'
#' The receipt is signed by the pinned recipient and is accepted only for the
#' exact outbound transfer awaiting it. Exact replay is idempotent. Confirming
#' all transfers from one producer invocation releases its cached response so
#' the next logical protocol phase may proceed.
#'
#' @param receipt Recipient-signed receipt returned by
#'   \code{mpcTypedBlobStoreDS} after atomic commit.
#' @param session_id Active MPC session identifier.
#' @return A purpose-bound confirmation acknowledgement.
#' @export
mpcTypedBlobReceiptDS <- function(receipt, session_id) {
  tryCatch(
    .mpcTypedBlobReceiptDS_impl(receipt, session_id),
    interrupt = function(e) stop(e),
    error = function(e) {
      if (inherits(e, "dsvert_resource_backpressure") ||
          inherits(e, "dsvert_resource_oversize")) stop(e)
      .dsvert_typed_blob_rejection("receipt")
    })
}

.mpcTypedBlobReceiptDS_impl <- function(receipt, session_id) {
  .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  parsed <- .dsvert_typed_blob_parse_receipt(receipt, ss, session_id)
  if (is.null(ss$.typed_blob_outbound_receipts)) {
    ss$.typed_blob_outbound_receipts <- list()
  }
  prior <- ss$.typed_blob_outbound_receipts[[parsed$transfer_id]]
  if (!is.null(prior)) {
    if (!identical(prior$receipt_digest, parsed$receipt_digest)) {
      stop("Conflicting typed-blob peer receipt replay.", call. = FALSE)
    }
    return(.dsvert_typed_blob_receipt_ack(parsed$transfer_id))
  }
  outbound <- (ss$.typed_blob_outbound %||% list())[[parsed$transfer_id]]
  if (is.null(outbound)) {
    stop("Typed-blob receipt does not match a pending outbound transfer.",
         call. = FALSE)
  }
  valid <- identical(outbound$transfer_id, parsed$transfer_id) &&
    identical(outbound$capability_id, parsed$capability_id) &&
    identical(outbound$sender_name, parsed$sender_name) &&
    identical(outbound$recipient_name, parsed$recipient_name) &&
    identical(outbound$peer_binding_digest, parsed$peer_binding_digest) &&
    identical(as.numeric(outbound$sequence), parsed$sequence) &&
    identical(outbound$ticket_digest, parsed$ticket_digest) &&
    identical(as.numeric(outbound$payload_chars), parsed$payload_chars) &&
    identical(outbound$payload_sha256, parsed$payload_sha256)
  if (!valid) {
    stop("Typed-blob receipt conflicts with the pending outbound transfer.",
         call. = FALSE)
  }
  operation_key <- outbound$operation_key
  if (!is.character(operation_key) || length(operation_key) != 1L ||
      is.na(operation_key) || !nzchar(operation_key)) {
    stop("Typed-blob receipt arrived before producer result commit.",
         call. = FALSE)
  }
  operation <- (ss$.typed_blob_pending_operations %||% list())[[operation_key]]
  if (is.null(operation) ||
      !parsed$transfer_id %in% operation$transfer_ids) {
    stop("Typed-blob receipt has no matching producer invocation.",
         call. = FALSE)
  }
  receipt_record <- list(
    receipt_digest = parsed$receipt_digest,
    stream_key = outbound$stream_key,
    sequence = outbound$sequence)
  .dsvert_typed_blob_record_latest(
    ss, ".typed_blob_outbound_receipts",
    ".typed_blob_outbound_receipt_latest", outbound$stream_key,
    parsed$transfer_id, receipt_record)
  accounting_head <- ss$.typed_blob_retained_head
  released_bytes <- 0
  if (!is.null(outbound$source_path)) {
    root <- .dsvert_typed_blob_source_root(ss, create = FALSE)
    if (!is.character(outbound$source_path) ||
        length(outbound$source_path) != 1L ||
        !file.exists(outbound$source_path) ||
        nzchar(Sys.readlink(outbound$source_path)) ||
        !identical(normalizePath(dirname(outbound$source_path),
                                 mustWork = TRUE), root) ||
        !identical(.dsvert_typed_blob_source_identity(outbound$source_path),
                   outbound$source_identity)) {
      stop("Typed-source receipt found an invalid producer spool.",
           call. = FALSE)
    }
    released_bytes <- as.numeric(file.size(outbound$source_path))
    unlink(outbound$source_path)
    if (file.exists(outbound$source_path)) {
      stop("Could not release the completed typed-source spool.",
           call. = FALSE)
    }
  }
  if (!is.null(ss$.typed_blob_outbound_ticket_index)) {
    ss$.typed_blob_outbound_ticket_index[[outbound$ticket_digest]] <- NULL
  }
  ss$.typed_blob_outbound[[parsed$transfer_id]] <- NULL
  confirmed <- operation$transfer_ids %in%
    names(ss$.typed_blob_outbound_receipts)
  if (all(confirmed)) {
    ss$.typed_blob_pending_operations[[operation_key]] <- NULL
  }
  if (released_bytes > 0) {
    .dsvert_typed_blob_accounting_adjust(
      ss, accounting_head, -released_bytes)
  }
  .dsvert_typed_blob_receipt_ack(parsed$transfer_id)
}

.dsvert_typed_blob_ack <- function(transfer_id, committed, total, sealed,
                                    receipt = NULL) {
  list(
    version = .DSVERT_TYPED_BLOB_VERSION,
    transfer_id = transfer_id,
    committed_chars = as.numeric(committed),
    total_chars = as.numeric(total),
    sealed = isTRUE(sealed), receipt = receipt)
}

#' Store one producer-minted, purpose-bound opaque MPC frame (AGGREGATE)
#'
#' The endpoint has no key, filename, purpose or recipient argument.  Those are
#' derived from a signed one-shot producer ticket.  Absolute offsets make an
#' ambiguous DSI replay idempotent; conflicting retries fail closed.  Resource
#' bounds and backpressure are byte limits, not request-count or rate quotas.
#'
#' @param ticket Producer-minted signed ticket.
#' @param chunk Non-empty slice of the opaque Base64url payload.
#' @param offset Absolute zero-based character offset.
#' @param session_id Active MPC session identifier.
#' @return A typed acknowledgement with the committed absolute offset.
#' @export
mpcTypedBlobStoreDS <- function(ticket, chunk, offset, session_id) {
  tryCatch(
    .mpcTypedBlobStoreDS_impl(ticket, chunk, offset, session_id),
    interrupt = function(e) stop(e),
    error = function(e) {
      if (inherits(e, "dsvert_resource_backpressure") ||
          inherits(e, "dsvert_resource_oversize")) stop(e)
      .dsvert_typed_blob_rejection("store")
    })
}

.mpcTypedBlobStoreDS_impl <- function(ticket, chunk, offset, session_id) {
  .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  plan <- .dsvert_typed_blob_plan(ticket, ss, session_id)
  if (!is.character(chunk) || length(chunk) != 1L || is.na(chunk) ||
      !nzchar(chunk) ||
      !grepl("^[A-Za-z0-9_-]+$", chunk, perl = TRUE, useBytes = TRUE)) {
    stop("Typed-blob frame must be non-empty Base64url text.", call. = FALSE)
  }
  chunk_chars <- nchar(chunk, type = "bytes")
  if (chunk_chars > .DSVERT_TYPED_BLOB_MAX_FRAME_BYTES) {
    .dsvert_resource_oversize(
      chunk_chars, .DSVERT_TYPED_BLOB_MAX_FRAME_BYTES,
      "typed-blob frame")
  }
  offset <- .dsvert_typed_blob_uint(
    offset, "absolute offset", 0, plan$payload_chars - 1)
  if (offset + chunk_chars > plan$payload_chars) {
    stop("Typed-blob frame exceeds the signed payload length.",
         call. = FALSE)
  }
  if (is.null(ss$.typed_blob_transfers)) ss$.typed_blob_transfers <- list()
  if (is.null(ss$.typed_blob_receipts)) ss$.typed_blob_receipts <- list()
  receipt <- ss$.typed_blob_receipts[[plan$transfer_id]]
  frame_hash <- digest::digest(chunk, algo = "sha256", serialize = FALSE)
  if (!is.null(receipt)) {
    if (!is.numeric(receipt$completed_at) ||
        .dsvert_typed_blob_now() - receipt$completed_at >
          .SESSION_TTL_SECONDS) {
      ss$.typed_blob_receipts[[plan$transfer_id]] <- NULL
      ss$.typed_blob_ticket_index[[plan$ticket_digest]] <- NULL
      stop("Completed typed-blob receipt exceeded the session lifetime.",
           call. = FALSE)
    }
    exact_frame_replay <-
      identical(receipt$ticket_digest, plan$ticket_digest) &&
      identical(receipt$payload_sha256, plan$payload_sha256) &&
      .dsvert_typed_blob_completed_frame_matches(
        ss, receipt, offset, chunk, chunk_chars, frame_hash)
    if (!exact_frame_replay) {
      stop("Conflicting replay for a completed typed-blob transfer.",
           call. = FALSE)
    }
    return(.dsvert_typed_blob_ack(
      plan$transfer_id, plan$payload_chars, plan$payload_chars, TRUE,
      receipt = receipt$signed_receipt))
  }
  state <- ss$.typed_blob_transfers[[plan$transfer_id]]
  new_transfer <- is.null(state)
  accounting_head <- ss$.typed_blob_retained_head
  if (is.null(state)) {
    if (offset != 0) {
      stop("Typed-blob transfer must start at absolute offset zero.",
           call. = FALSE)
    }
    if (is.null(ss$.typed_blob_receive_sequence)) {
      ss$.typed_blob_receive_sequence <- list()
    }
    stream_key <- .dsvert_typed_blob_stream_key(
      plan$capability_id, plan$sender_name)
    expected_sequence <-
      (ss$.typed_blob_receive_sequence[[stream_key]] %||% 0) + 1
    if (!identical(plan$sequence, as.numeric(expected_sequence))) {
      stop("Typed-blob transfer is reordered or skips a protocol phase.",
           call. = FALSE)
    }
    .dsvert_typed_blob_sweep_expired(ss)
    retained <- .dsvert_typed_blob_retained_bytes(ss)
    accounting_head <- ss$.typed_blob_retained_head
    capacity <- .dsvert_typed_blob_spool_max_bytes()
    if (plan$payload_chars > capacity) {
      .dsvert_resource_oversize(
        plan$payload_chars, capacity, "typed-blob session spool")
    }
    if (retained > capacity - plan$payload_chars) {
      .dsvert_resource_backpressure(
        retained, plan$payload_chars, capacity, "typed-blob session spool")
    }
    .dsvert_resource_admit(ss, plan$payload_chars)
    path <- .dsvert_typed_blob_spool_path(ss, plan$transfer_id)
    if (file.exists(path)) {
      stop("Typed-blob spool path is already in use.", call. = FALSE)
    }
    con <- file(path, "wb")
    close(con)
    Sys.chmod(path, mode = "0600")
    state <- c(plan, list(
      path = path, committed_chars = 0, frame_count = 0L,
      frames = list(), poisoned = FALSE,
      verified_plan = plan,
      admitted_at = .dsvert_typed_blob_now(),
      last_activity = .dsvert_typed_blob_now()))
    if (is.null(ss$.typed_blob_ticket_index)) {
      ss$.typed_blob_ticket_index <- list()
    }
    ss$.typed_blob_ticket_index[[plan$ticket_digest]] <- plan$transfer_id
  }
  now <- .dsvert_typed_blob_now()
  if (!is.numeric(state$admitted_at) || !is.numeric(state$last_activity) ||
      now - state$last_activity > .SESSION_TTL_SECONDS) {
    if (!is.null(state$path) && file.exists(state$path)) unlink(state$path)
    ss$.typed_blob_transfers[[plan$transfer_id]] <- NULL
    ss$.typed_blob_ticket_index[[plan$ticket_digest]] <- NULL
    stop("Typed-blob admitted transfer exceeded its inactivity lease.",
         call. = FALSE)
  }
  if (isTRUE(state$poisoned)) {
    stop("Typed-blob transfer is poisoned; abort the session.",
         call. = FALSE)
  }
  invariant <- identical(state$ticket_digest, plan$ticket_digest) &&
    identical(state$destination, plan$destination) &&
    identical(state$sequence, plan$sequence) &&
    identical(state$phase, plan$phase) &&
    identical(state$context, plan$context) &&
    identical(state$payload_chars, plan$payload_chars) &&
    identical(state$payload_sha256, plan$payload_sha256)
  if (!invariant) {
    stop("Typed-blob ticket conflicts with in-progress transfer state.",
         call. = FALSE)
  }
  offset_key <- format(offset, scientific = FALSE, trim = TRUE)
  previous <- state$frames[[offset_key]]
  if (!is.null(previous)) {
    if (!identical(previous$chars, as.numeric(chunk_chars)) ||
        !identical(previous$hash, frame_hash)) {
      stop("Conflicting typed-blob frame replay.", call. = FALSE)
    }
    return(.dsvert_typed_blob_ack(
      plan$transfer_id, state$committed_chars, plan$payload_chars, FALSE))
  }
  if (!identical(offset, state$committed_chars)) {
    stop("Typed-blob frame offset does not match committed data.",
         call. = FALSE)
  }
  if (state$frame_count >= .DSVERT_TYPED_BLOB_MAX_FRAMES) {
    .dsvert_resource_oversize(
      state$frame_count + 1, .DSVERT_TYPED_BLOB_MAX_FRAMES,
      "typed-blob frame metadata")
  }
  start_size <- file.size(state$path)
  if (length(start_size) != 1L || is.na(start_size) ||
      !identical(as.numeric(start_size), state$committed_chars)) {
    stop("Typed-blob spool does not match committed state.", call. = FALSE)
  }
  prior_state <- state
  rollback <- TRUE
  on.exit(if (rollback) {
    .dsvert_typed_blob_accounting_invalidate(ss)
    if (isTRUE(new_transfer)) {
      if (file.exists(prior_state$path)) unlink(prior_state$path)
      ss$.typed_blob_transfers[[plan$transfer_id]] <- NULL
      ss$.typed_blob_ticket_index[[plan$ticket_digest]] <- NULL
    } else {
      if (file.exists(prior_state$path)) {
        tryCatch(.dsvert_relay_truncate(
          prior_state$path, prior_state$committed_chars),
          error = function(e) NULL)
      }
      ss$.typed_blob_transfers[[plan$transfer_id]] <- prior_state
    }
  }, add = TRUE)
  .dsvert_relay_append(state$path, charToRaw(chunk), state$committed_chars)
  state$frames[[offset_key]] <- list(
    chars = as.numeric(chunk_chars), hash = frame_hash)
  state$frame_count <- state$frame_count + 1L
  state$committed_chars <- state$committed_chars + chunk_chars
  state$last_activity <- now
  if (state$committed_chars < plan$payload_chars) {
    ss$.typed_blob_transfers[[plan$transfer_id]] <- state
    if (isTRUE(new_transfer)) {
      .dsvert_typed_blob_accounting_adjust(
        ss, accounting_head, plan$payload_chars)
    }
    .session_progress(ss, now)
    rollback <- FALSE
    return(.dsvert_typed_blob_ack(
      plan$transfer_id, state$committed_chars, plan$payload_chars, FALSE))
  }
  payload_hash <- digest::digest(
    file = state$path, algo = "sha256", serialize = FALSE)
  if (!identical(payload_hash, plan$payload_sha256)) {
    state$poisoned <- TRUE
    ss$.typed_blob_transfers[[plan$transfer_id]] <- state
    unlink(state$path)
    .dsvert_typed_blob_accounting_adjust(ss, accounting_head,
                                         if (isTRUE(new_transfer)) {
                                           plan$payload_chars
                                         } else 0)
    rollback <- FALSE
    stop("Typed-blob payload hash does not match its producer ticket.",
         call. = FALSE)
  }
  signed_receipt <- .dsvert_typed_blob_mint_receipt(plan, ss)
  existing_memory <- !is.null(ss$blobs[[plan$destination]])
  destination_path <- file.path(
    .ensure_session_dir(ss), "blobs", plan$destination)
  existing_provenance <-
    !is.null((ss$.typed_blob_destinations %||% list())[[plan$destination]])
  if (existing_memory || file.exists(destination_path) || existing_provenance) {
    state$poisoned <- TRUE
    ss$.typed_blob_transfers[[plan$transfer_id]] <- state
    unlink(state$path)
    .dsvert_typed_blob_accounting_adjust(ss, accounting_head,
                                         if (isTRUE(new_transfer)) {
                                           plan$payload_chars
                                         } else 0)
    rollback <- FALSE
    stop("Typed-blob destination is already populated.", call. = FALSE)
  }
  if (!file.rename(state$path, destination_path)) {
    stop("Could not commit typed-blob payload atomically.", call. = FALSE)
  }
  Sys.chmod(destination_path, mode = "0600")
  final_offset <- offset
  final_chars <- as.numeric(chunk_chars)
  ss$.typed_blob_transfers[[plan$transfer_id]] <- NULL
  if (is.null(ss$.typed_blob_destinations)) {
    ss$.typed_blob_destinations <- list()
  }
  ss$.typed_blob_destinations[[plan$destination]] <- plan[c(
    "transfer_id", "capability_id", "family", "producer", "consumer",
    "phase", "ring", "shape", "count", "context", "sender_name",
    "recipient_name", "destination", "sequence", "payload_chars",
    "payload_sha256")]
  stream_key <- .dsvert_typed_blob_stream_key(
    plan$capability_id, plan$sender_name)
  ss$.typed_blob_receive_sequence[[stream_key]] <- plan$sequence
  frame_offsets <- suppressWarnings(as.numeric(names(state$frames)))
  frame_chars <- vapply(state$frames, `[[`, numeric(1L), "chars")
  if (anyNA(frame_offsets) || anyDuplicated(frame_offsets) ||
      length(frame_offsets) != state$frame_count) {
    stop("Typed-blob terminal frame index is invalid.", call. = FALSE)
  }
  receipt_record <- list(
    ticket_digest = plan$ticket_digest,
    payload_sha256 = plan$payload_sha256,
    final_offset = final_offset, final_chars = final_chars,
    final_hash = frame_hash,
    frame_offsets = frame_offsets, frame_chars = frame_chars,
    signed_receipt = signed_receipt,
    completed_at = now, plan = plan)
  .dsvert_typed_blob_record_latest(
    ss, ".typed_blob_receipts", ".typed_blob_receipt_latest",
    stream_key, plan$transfer_id, receipt_record)
  .dsvert_typed_blob_accounting_adjust(ss, accounting_head,
                                       if (isTRUE(new_transfer)) {
                                         plan$payload_chars
                                       } else 0)
  .session_progress(ss, now)
  rollback <- FALSE
  .dsvert_typed_blob_ack(
    plan$transfer_id, plan$payload_chars, plan$payload_chars, TRUE,
    receipt = signed_receipt)
}
