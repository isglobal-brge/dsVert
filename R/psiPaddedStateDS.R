# Crash-durable private journal for the padded PSI state. Patient identifiers,
# permutations, membership shares and transport secrets are never written in
# plaintext. The journal key is domain-separated from the persistent Ed25519
# identity seed and the file is atomically replaced under an owner-only lock.

.DSVERT_PSI_PADDED_JOURNAL_MAGIC <- charToRaw("DSVPSIJ3")
.DSVERT_PSI_PADDED_JOURNAL_MAX_BYTES <- 1024^3
.DSVERT_PSI_PADDED_JOURNAL_STATE_VERSION <- 1L
.psi_padded_journal_swept <- new.env(parent = emptyenv())

.psi_padded_journal_enabled <- function() {
  !isTRUE(.dsvert_identity_test_mode()) ||
    isTRUE(getOption("dsvert.psi.padded.persist_in_tests", FALSE))
}

.psi_padded_journal_keys <- function() {
  seed <- jsonlite::base64_dec(.dsvert_normalize_crypto_b64(
    .get_identity_seed(), 32L, "padded PSI journal identity seed"))
  derive <- function(label) digest::hmac(
    key = seed,
    object = charToRaw(paste0(
      "dsVert/padded-psi/private-journal/v4|", label)),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  keys <- list(encryption = derive("aes-256-ctr"),
               authentication = derive("hmac-sha256"))
  seed <- NULL
  keys
}

.psi_padded_journal_path <- function(session_id, peer_id,
                                     allow_test_path = FALSE) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  peer_id <- .dsvert_relay_validate_peer_id(peer_id)
  candidate <- file.path(
    .dsvert_state_root(), "psi-padded-v5", peer_id,
    paste0(session_id, ".state"))
  .dsvert_dp_noise_private_directory(
    candidate, .allow_test_path = allow_test_path)
}

.psi_padded_journal_context <- function(peer_id, session_id, iv,
                                        ciphertext) {
  c(
    .DSVERT_PSI_PADDED_JOURNAL_MAGIC,
    charToRaw(paste0(
      "|", nchar(peer_id, type = "bytes"), ":", peer_id,
      "|", nchar(session_id, type = "bytes"), ":", session_id,
      "|", format(length(ciphertext), scientific = FALSE, trim = TRUE),
      "|")),
    iv, ciphertext)
}

.psi_padded_journal_freeze <- function(state) {
  if (!is.list(state) ||
      !identical(state$protocol, .DSVERT_PSI_PADDED_PROTOCOL)) {
    stop("Invalid padded PSI state journal payload.", call. = FALSE)
  }
  frozen <- state
  replay <- frozen$replay_cache
  if (is.environment(replay)) {
    frozen$replay_cache <- as.list(replay, all.names = TRUE)
  } else if (is.null(replay)) {
    if (!identical(frozen$phase, "attested")) {
      frozen$replay_cache <- list()
    }
  } else if (!is.list(replay)) {
    stop("Invalid padded PSI replay journal.", call. = FALSE)
  }
  assert_plain <- function(value, depth = 0L) {
    if (depth > 64L || is.environment(value) || is.function(value) ||
        typeof(value) %in% c("externalptr", "weakref", "closure",
                             "builtin", "special", "language", "promise")) {
      stop("Padded PSI journal contains non-serializable runtime state.",
           call. = FALSE)
    }
    if (is.list(value)) for (item in value) assert_plain(item, depth + 1L)
    invisible(TRUE)
  }
  assert_plain(frozen)
  frozen
}

.psi_padded_journal_thaw <- function(state) {
  state <- .psi_padded_journal_freeze(state)
  if ("replay_cache" %in% names(state)) {
    replay <- new.env(parent = emptyenv())
    if (length(state$replay_cache)) {
      list2env(state$replay_cache, envir = replay)
    }
    state$replay_cache <- replay
  }
  state
}

.psi_padded_journal_limit <- function() {
  value <- getOption(
    "dsvert.psi.padded.journal_max_bytes",
    .DSVERT_PSI_PADDED_JOURNAL_MAX_BYTES)
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value < 1024^2 || value > 2^31 - 1 || value != floor(value)) {
    stop("Invalid padded PSI private-journal size policy.", call. = FALSE)
  }
  value
}

.psi_padded_journal_ttl_seconds <- function() {
  value <- getOption(
    "dsvert.psi.padded.journal_ttl_seconds", .SESSION_TTL_SECONDS)
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value < 10 || value > 7 * 86400 || value != floor(value)) {
    stop("Invalid padded PSI private-journal inactivity lease.",
         call. = FALSE)
  }
  value
}

.psi_padded_journal_resource_owner <- function(path) {
  # Admission is deliberately byte-only. There is no session, request or
  # query counter: any number of journals may coexist while their authenticated
  # physical bytes fit the shared transport capacity.
  .dsvert_resource_external_owner("psi-padded-journal", path)
}

.psi_padded_journal_file_size <- function(path, absent_ok = TRUE) {
  if (!file.exists(path) && !.dsvert_dp_path_is_link(path)) {
    if (isTRUE(absent_ok)) return(0)
    stop("Padded PSI private journal is unavailable.", call. = FALSE)
  }
  if (.dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("Padded PSI journal is not an owner-only regular file.",
         call. = FALSE)
  }
  info <- file.info(path)
  size <- suppressWarnings(as.numeric(info$size))
  maximum <- .psi_padded_journal_limit() + 56L
  if (nrow(info) != 1L || length(size) != 1L || is.na(size) ||
      !is.finite(size) || size < 57L || size > maximum ||
      size != floor(size)) {
    stop("Padded PSI private journal has an invalid size.", call. = FALSE)
  }
  size
}

.psi_padded_journal_timestamp <- function(state) {
  if (!is.list(state) ||
      !identical(state$journal_state_version,
                 .DSVERT_PSI_PADDED_JOURNAL_STATE_VERSION)) {
    return(NULL)
  }
  created <- suppressWarnings(as.numeric(state$journal_created_at))
  progress <- suppressWarnings(as.numeric(state$journal_last_progress_at))
  if (length(created) != 1L || is.na(created) || !is.finite(created) ||
      created < 0 || length(progress) != 1L || is.na(progress) ||
      !is.finite(progress) || progress < created) {
    return(NULL)
  }
  progress
}

.psi_padded_journal_stamp <- function(state, now = .session_now()) {
  if (!is.list(state)) {
    stop("Invalid padded PSI state journal payload.", call. = FALSE)
  }
  now <- suppressWarnings(as.numeric(now))
  if (length(now) != 1L || is.na(now) || !is.finite(now) || now < 0) {
    stop("Invalid padded PSI journal progress timestamp.", call. = FALSE)
  }
  created <- suppressWarnings(as.numeric(state$journal_created_at))
  if (length(created) != 1L || is.na(created) || !is.finite(created) ||
      created < 0 || created > now) {
    created <- now
  }
  previous <- suppressWarnings(as.numeric(state$journal_last_progress_at))
  if (length(previous) == 1L && !is.na(previous) && is.finite(previous) &&
      previous >= created) {
    now <- max(previous, now)
  }
  state$journal_state_version <-
    .DSVERT_PSI_PADDED_JOURNAL_STATE_VERSION
  state$journal_created_at <- created
  state$journal_last_progress_at <- now
  state
}

.psi_padded_journal_with_lock <- function(path, code) {
  lock_path <- paste0(path, ".lock")
  if (.dsvert_dp_path_is_link(lock_path)) {
    stop("Padded PSI journal lock must not be a symbolic link.",
         call. = FALSE)
  }
  lock <- filelock::lock(lock_path, timeout = 30000)
  if (is.null(lock)) stop("Could not lock the padded PSI private journal.",
                          call. = FALSE)
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  Sys.chmod(lock_path, mode = "0600")
  if (.dsvert_dp_path_is_link(lock_path) ||
      !.dsvert_dp_private_mode(lock_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(lock_path), 1)) {
    stop("Padded PSI journal lock is not an owner-only regular file.",
         call. = FALSE)
  }
  force(code)
}

.psi_padded_journal_write <- function(
    state, allow_test_path = FALSE,
    .progress_at = .session_now()) {
  frozen <- .psi_padded_journal_freeze(
    .psi_padded_journal_stamp(state, .progress_at))
  session_id <- .dsvert_relay_validate_session_id(frozen$session_id)
  peer_id <- .dsvert_relay_validate_peer_id(frozen$self_peer_id)
  .psi_padded_journal_sweep(
    peer_id, allow_test_path = allow_test_path)
  path <- .psi_padded_journal_path(
    session_id, peer_id, allow_test_path = allow_test_path)
  .psi_padded_journal_with_lock(path, {
    plaintext <- serialize(frozen, NULL, ascii = FALSE, version = 3L)
    if (!is.raw(plaintext) || length(plaintext) > .psi_padded_journal_limit()) {
      stop("Padded PSI private journal exceeds its storage policy.",
           call. = FALSE)
    }
    keys <- .psi_padded_journal_keys()
    iv <- .dsvert_secure_random_bytes(16L)
    ciphertext <- openssl::aes_ctr_encrypt(
      plaintext, keys$encryption, iv = iv)
    mac <- digest::hmac(
      key = keys$authentication,
      object = .psi_padded_journal_context(
        peer_id, session_id, iv, ciphertext),
      algo = "sha256", serialize = FALSE, raw = TRUE)
    encoded <- c(.DSVERT_PSI_PADDED_JOURNAL_MAGIC, iv, mac, ciphertext)
    previous_bytes <- .psi_padded_journal_file_size(path)
    next_bytes <- as.numeric(length(encoded))
    owner <- .psi_padded_journal_resource_owner(path)
    .dsvert_resource_admit_external(
      owner, previous_bytes, next_bytes,
      "psi-padded-journal")
    temporary <- tempfile(
      pattern = ".psi-padded-state-", tmpdir = dirname(path))
    on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
            add = TRUE)
    connection <- file(temporary, open = "wb")
    on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
            add = TRUE)
    writeBin(encoded, connection)
    flush(connection)
    close(connection)
    Sys.chmod(temporary, mode = "0600")
    .dsvert_identity_require_sync(temporary, "padded PSI private journal")
    if (!file.rename(temporary, path)) {
      stop("Could not atomically commit the padded PSI private journal.",
           call. = FALSE)
    }
    Sys.chmod(path, mode = "0600")
    .dsvert_resource_external_reconcile(
      owner, next_bytes, "psi-padded-journal")
    .dsvert_identity_require_sync(path, "padded PSI private journal")
    .dsvert_identity_require_sync(dirname(path),
                                  "padded PSI journal directory")
    plaintext <- keys <- NULL
    invisible(path)
  })
}

.psi_padded_journal_read_locked <- function(path, session_id, peer_id,
                                            keys = NULL) {
  if (.dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("Padded PSI journal is not an owner-only regular file.",
         call. = FALSE)
  }
  info <- file.info(path)
  maximum <- .psi_padded_journal_limit() + 56L
  if (nrow(info) != 1L || is.na(info$size) || info$size < 57L ||
      info$size > maximum) {
    stop("Padded PSI private journal has an invalid size.", call. = FALSE)
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded <- readBin(path, "raw", n = info$size + 1L)
  after_info <- file.info(path)
  after <- unname(after_info[c("size", "mtime", "ctime")])
  if (!identical(before, after) || length(encoded) != info$size ||
      !identical(encoded[1:8], .DSVERT_PSI_PADDED_JOURNAL_MAGIC)) {
    stop("Padded PSI private journal changed while being read.",
         call. = FALSE)
  }
  iv <- encoded[9:24]
  mac <- encoded[25:56]
  ciphertext <- encoded[57:length(encoded)]
  if (is.null(keys)) keys <- .psi_padded_journal_keys()
  expected <- digest::hmac(
    key = keys$authentication,
    object = .psi_padded_journal_context(
      peer_id, session_id, iv, ciphertext),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  authenticated <- length(mac) == 32L && length(expected) == 32L &&
    identical(sum(bitwXor(as.integer(mac), as.integer(expected))), 0L)
  if (!isTRUE(authenticated)) {
    stop("Padded PSI private journal authentication failed.",
         call. = FALSE)
  }
  plaintext <- tryCatch(openssl::aes_ctr_decrypt(
    ciphertext, keys$encryption, iv = iv), error = function(e) NULL)
  state <- if (is.raw(plaintext)) tryCatch(
    unserialize(plaintext), error = function(e) NULL) else NULL
  if (!is.list(state) ||
      !identical(state$protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !identical(state$session_id, session_id) ||
      !identical(state$self_peer_id, peer_id)) {
    stop("Padded PSI private journal plaintext is invalid.",
         call. = FALSE)
  }
  owner <- .psi_padded_journal_resource_owner(path)
  .dsvert_resource_external_reconcile(
    owner, as.numeric(info$size), "psi-padded-journal")
  plaintext <- keys <- NULL
  .psi_padded_journal_thaw(state)
}

.psi_padded_journal_read <- function(session_id, peer_id,
                                     allow_test_path = FALSE) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  peer_id <- .dsvert_relay_validate_peer_id(peer_id)
  path <- .psi_padded_journal_path(
    session_id, peer_id, allow_test_path = allow_test_path)
  if (!file.exists(path) && !.dsvert_dp_path_is_link(path)) return(NULL)
  .psi_padded_journal_with_lock(path, {
    if (!file.exists(path) && !.dsvert_dp_path_is_link(path)) {
      NULL
    } else {
      .psi_padded_journal_read_locked(path, session_id, peer_id)
    }
  })
}

.psi_padded_journal_unlink_locked <- function(path, owner) {
  if (.dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("Refusing to remove an invalid padded PSI journal.", call. = FALSE)
  }
  if (!identical(unlink(path, force = TRUE), 0L) || file.exists(path) ||
      .dsvert_dp_path_is_link(path)) {
    stop("Could not remove the padded PSI private journal.",
         call. = FALSE)
  }
  .dsvert_resource_external_unregister(owner)
  .dsvert_identity_require_sync(dirname(path),
                                "padded PSI journal deletion")
  invisible(TRUE)
}

.psi_padded_journal_sweep <- function(
    peer_id, now = .session_now(), force = FALSE,
    allow_test_path = isTRUE(.dsvert_identity_test_mode())) {
  peer_id <- .dsvert_relay_validate_peer_id(peer_id)
  now <- suppressWarnings(as.numeric(now))
  if (length(now) != 1L || is.na(now) || !is.finite(now) || now < 0) {
    stop("Invalid padded PSI journal sweep timestamp.", call. = FALSE)
  }
  probe <- .psi_padded_journal_path(
    "00000000-0000-4000-8000-000000000000", peer_id,
    allow_test_path = allow_test_path)
  root <- dirname(probe)
  marker <- digest::digest(
    paste(root, peer_id, sep = "|"), algo = "sha256", serialize = FALSE)
  if (!isTRUE(force) && isTRUE(.psi_padded_journal_swept[[marker]])) {
    return(invisible(list(
      scanned = 0L, expired = 0L, retired = 0L, invalid = 0L)))
  }
  ttl <- .psi_padded_journal_ttl_seconds()
  journal_base <- dirname(root)
  if (.dsvert_dp_path_is_link(journal_base) ||
      !.dsvert_dp_private_mode(journal_base, directory = TRUE)) {
    stop("Padded PSI journal root is not an owner-only directory.",
         call. = FALSE)
  }
  result <- .psi_padded_journal_with_lock(
    file.path(journal_base, ".sweep"), {
    # One state root has exactly one persistent service identity.  A peer
    # namespace different from the active identity can only contain
    # non-resumable pre-rotation journals.  Retire those encrypted journals so
    # a legitimate identity recovery cannot leave stale byte reservations
    # blocking new work.  Directory and file symlinks are never traversed.
    candidates <- list.files(
      journal_base, all.files = TRUE, no.. = TRUE, full.names = TRUE,
      recursive = FALSE)
    journal_roots <- candidates[vapply(candidates, function(candidate) {
      !.dsvert_dp_path_is_link(candidate) && dir.exists(candidate) &&
        grepl(.DSVERT_RELAY_PEER_RE, basename(candidate)) &&
        isTRUE(tryCatch(
          .dsvert_dp_private_mode(candidate, directory = TRUE),
          error = function(e) FALSE))
    }, logical(1L))]
    if (!root %in% journal_roots) journal_roots <- c(root, journal_roots)
    paths <- unlist(lapply(journal_roots, function(journal_root) {
      list.files(
        journal_root, pattern = "\\.state$", all.files = TRUE, no.. = TRUE,
        full.names = TRUE, recursive = FALSE)
    }), use.names = FALSE)
    keys <- if (length(paths)) .psi_padded_journal_keys() else NULL
    scanned <- expired <- retired <- invalid <- 0L
    for (path in paths) {
      session_id <- sub("\\.state$", "", basename(path))
      if (!grepl(.DSVERT_RELAY_SESSION_RE, session_id) ||
          .dsvert_dp_path_is_link(path)) {
        invalid <- invalid + 1L
        next
      }
      scanned <- scanned + 1L
      path_peer_id <- basename(dirname(path))
      stale_identity <- !identical(path_peer_id, peer_id)
      outcome <- .psi_padded_journal_with_lock(path, {
        state <- if (isTRUE(stale_identity)) NULL else tryCatch(
          .psi_padded_journal_read_locked(
            path, session_id, path_peer_id, keys = keys),
          error = function(e) NULL)
        if (is.null(state)) {
          # An owner-only encrypted journal that no longer authenticates is
          # not resumable.  Retaining it would make corruption or a legitimate
          # identity rotation consume the global byte cap indefinitely.
          size <- tryCatch(
            .psi_padded_journal_file_size(path, absent_ok = FALSE),
            error = function(e) NULL)
          if (!is.null(size)) {
            owner <- .psi_padded_journal_resource_owner(path)
            .psi_padded_journal_unlink_locked(path, owner)
            "retired"
          } else {
            "invalid"
          }
        } else {
          progress <- .psi_padded_journal_timestamp(state)
          if (is.null(progress) || now - progress > ttl) {
            owner <- .psi_padded_journal_resource_owner(path)
            .psi_padded_journal_unlink_locked(path, owner)
            "expired"
          } else {
            "active"
          }
        }
      })
      if (identical(outcome, "expired")) {
        expired <- expired + 1L
      } else if (identical(outcome, "retired")) {
        retired <- retired + 1L
      } else if (identical(outcome, "invalid")) {
        invalid <- invalid + 1L
      }
    }
    list(scanned = scanned, expired = expired, retired = retired,
         invalid = invalid)
  })
  .psi_padded_journal_swept[[marker]] <- TRUE
  invisible(result)
}

.psi_padded_state_commit <- function(ss) {
  if (!.psi_padded_journal_enabled() || !is.environment(ss) ||
      !is.list(ss$.psi_padded_state)) return(invisible(FALSE))
  now <- .session_now()
  ss$.psi_padded_state <- .psi_padded_journal_stamp(
    ss$.psi_padded_state, now)
  .session_progress(ss, now)
  .psi_padded_journal_write(
    ss$.psi_padded_state,
    allow_test_path = isTRUE(.dsvert_identity_test_mode()),
    .progress_at = now)
  invisible(TRUE)
}

.psi_padded_state_restore <- function(ss, session_id) {
  if (!.psi_padded_journal_enabled() || !is.environment(ss)) return(FALSE)
  if (is.list(ss$.psi_padded_state)) return(TRUE)
  identity <- .get_identity_keypair()
  peer_id <- .dsvert_relay_peer_id(identity$identity_pk)
  .psi_padded_journal_sweep(
    peer_id, allow_test_path = isTRUE(.dsvert_identity_test_mode()))
  state <- .psi_padded_journal_read(
    session_id, peer_id,
    allow_test_path = isTRUE(.dsvert_identity_test_mode()))
  if (is.null(state)) return(FALSE)
  if (!identical(state$identity_pk, identity$identity_pk)) {
    stop("Padded PSI journal belongs to a different persistent identity.",
         call. = FALSE)
  }
  ss$.psi_padded_state <- state
  TRUE
}

.psi_padded_state_delete <- function(state) {
  if (!is.list(state) ||
      !identical(state$protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !is.character(state$session_id) ||
      !is.character(state$self_peer_id)) return(invisible(FALSE))
  path <- tryCatch(.psi_padded_journal_path(
    state$session_id, state$self_peer_id,
    allow_test_path = isTRUE(.dsvert_identity_test_mode())),
    error = function(e) NULL)
  if (is.null(path)) return(invisible(FALSE))
  owner <- .psi_padded_journal_resource_owner(path)
  if (!file.exists(path) && !.dsvert_dp_path_is_link(path)) {
    .dsvert_resource_external_unregister(owner)
    return(invisible(FALSE))
  }
  .psi_padded_journal_with_lock(path, {
    .psi_padded_journal_unlink_locked(path, owner)
  })
  invisible(TRUE)
}
