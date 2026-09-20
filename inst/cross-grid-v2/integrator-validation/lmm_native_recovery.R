# Synthetic validation only. No production worker or protocol hook is changed.
# The relay pauses between fanout cycles, before returning pending envelopes.
# Native processes are stopped only to confirm the on-disk state pair.
# This tests process interruption on the surviving filesystem, not power loss;
# no harness write or fsync changes durability. Local MACs/values stay private.
structured_lmm_native_probe <- function(session_id, operation_id,
                                        action = "inspect", label = "") {
  fixture <- get0(".grid_lifecycle_fixture", .GlobalEnv)
  if (is.null(fixture) || !identical(fixture$stage$operation_id, operation_id)) return(NULL)
  sf <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
  manifest <- sf(".dsvert_dp_capsule_source_manifest")(fixture$manifest_json)
  artifact <- sf(".dsvert_dp_lmm_cross_artifacts")(manifest)[[1L]]
  kind <- sf(".dsvert_dp_staged_grouped_kind")(artifact$family)
  stage_prefix <- if (kind == "gee-fixed-rho") "gee" else kind
  if (action %in% c("pause", "resume", "terminate")) {
    # The synthetic trace retains the session privately during the authorized
    # start. Calling .S here would correctly reject an out-of-entrypoint read.
    captured <- get0(".grid_native_recovery_session", .GlobalEnv)
    stopifnot(is.list(captured), is.environment(captured$session),
      identical(captured$session_id, session_id),
      identical(captured$operation_id, operation_id))
    worker <- sf(".exact_gc_operation_state")(captured$session, operation_id)
    stopifnot(identical(worker$operation, paste0("grouped-", kind, "-staged-v1")),
      identical(worker$session_id, session_id),
      identical(worker$operation_id, operation_id))
    stopifnot(inherits(worker$process, "process"))
    if (worker$process$is_alive()) {
      if (action == "terminate") {
        worker$process$kill()
        worker$process$wait(timeout = 5000)
      } else stopifnot(tools::pskill(worker$process$get_pid(),
        signal = if (action == "pause") 19L else 18L))
    }
    return(TRUE)
  }
  semantic <- sf(".dsvert_dp_glm_grid_cross_key")(manifest, artifact, fixture$source_contract)
  directory <- file.path(dirname(sf(".dsvert_dp_capsule_source_store_path")(fixture$policy)),
    paste0(kind, "-staged-v1"), semantic)
  key <- sf(".dsvert_dp_capsule_source_hex_raw")(sf(".dsvert_dp_capsule_source_mac")(
    fixture$secret, paste0("grouped-", kind, "-stage-store-key-v1"), semantic), "synthetic stage MAC key")
  cached <- get0(".grid_native_recovery_path", .GlobalEnv)
  files <- if (is.list(cached) && identical(cached$semantic, semantic)) cached$path else
    list.files(directory, pattern = "\\.stage$", full.names = TRUE)
  selected <- NULL
  for (path in files) {
    info <- file.info(path)
    stopifnot(!sf(".dsvert_dp_path_is_link")(path),
      sf(".dsvert_dp_private_mode")(path, directory = FALSE),
      !info$isdir, info$size >= 32, info$size <= 128*1024^2)
    connection <- file(path, "rb")
    bytes <- tryCatch({
      seek(connection, where = 0, origin = "end")
      size <- seek(connection)
      stopifnot(size >= 32, size <= 128*1024^2)
      seek(connection, where = 0, origin = "start")
      readBin(connection, "raw", n = size)
    }, finally = close(connection))
    payload <- bytes[-seq_len(32L)]
    mac <- digest::hmac(key, c(charToRaw("dsvert/staged-grid/v1/private-record"),
      as.raw(0), payload), algo = "sha256", serialize = FALSE, raw = TRUE)
    stopifnot(identical(mac, bytes[seq_len(32L)]))
    record <- jsonlite::fromJSON(rawToChar(payload), simplifyVector = FALSE)
    if (!identical(record$StageID, paste0(stage_prefix, ".source.numeric"))) next
    hex <- function(value) paste(sprintf("%02x", as.integer(unlist(value))), collapse = "")
    expected_role <- if (identical(fixture$policy$peer_name,
      sf(".dsvert_dp_glm_grid_cross_embedded_contract")(artifact)$spec$grouping$owner_peer)) 0 else 1
    stopifnot(identical(record$Version, "cross-grid-stage-record-v1"),
      identical(record$Session, paste0(kind, "-staged-", semantic)),
      identical(record$ABI$ID, record$StageID),
      identical(hex(record$PlanDigest), fixture$stage$stage_plan_digest),
      identical(as.numeric(record$Role), expected_role),
      record$State %in% c("ABORTED", "RUNNING", "PREPARE", "COMMIT"),
      record$Generation >= 1)
    selected <- record
    assign(".grid_native_recovery_path", list(semantic = semantic, path = path), .GlobalEnv)
    break
  }
  if (is.null(selected)) return(NULL)
  retained <- get0(".grid_native_recovery_records", .GlobalEnv)
  if (is.null(retained)) retained <- list()
  if (action == "remember") {
    stopifnot(label %in% c("bilateral_prepare", "unilateral_commit"),
      selected$State %in% c("PREPARE", "COMMIT"))
    if (label == "unilateral_commit") {
      before <- retained$bilateral_prepare
      stopifnot(!is.null(before), selected$Generation > before$Generation,
        !identical(selected$AttemptNonce, before$AttemptNonce),
        !identical(selected$OutputMaskDomainTag, before$OutputMaskDomainTag))
    }
    retained[[label]] <- selected
    assign(".grid_native_recovery_records", retained, .GlobalEnv)
  }
  if (action == "verify_replay") {
    before <- retained$unilateral_commit
    stopifnot(!is.null(before), identical(selected$State, "COMMIT"))
    before$State <- "COMMIT"
    # Includes the exact private share, validity, MAC, nonce, generation and
    # predecessor/receipt identities. Only this equality bit leaves the peer.
    stopifnot(identical(selected, before))
    return(TRUE)
  }
  list(stage_id = selected$StageID, state = selected$State,
    role = as.numeric(selected$Role), authenticated = TRUE)
}

structured_lmm_native_recovery <- function(peers, kind = "lmm") {
  stopifnot(identical(names(peers), c("site_a", "site_b")))
  stopifnot(kind %in% c("lmm", "glmm", "gee-fixed-rho"))
  marker <- paste0("DSLITE_", toupper(kind))
  state <- new.env(parent = emptyenv())
  state$mode <- "none"
  state$fired <- FALSE
  state$session <- state$operation <- NULL
  state$proved <- character()
  state$last_states <- NULL
  state$installed <- TRUE
  probe <- function(session, operation, action = "inspect", label = "") {
    lapply(peers, function(peer) peer$worker$run(structured_lmm_native_probe,
      args = list(session, operation, action, label)))
  }
  barrier <- function(operation, expressions, cycle) {
    if (identical(state$mode, "none") ||
        !identical(operation, "exact MPC byte exchange") ||
        !identical(cycle$state, "ok")) return(invisible(NULL))
    request <- as.list(expressions[[1L]])
    session <- request$session_id
    id <- request$operation_id
    # A signed staged operation is identified by its bound public operation ID,
    # not by inspecting or substituting an encrypted relay payload.
    records <- probe(session, id)
    if (any(vapply(records, is.null, logical(1L)))) return(invisible(NULL))
    expected <- if (state$mode == "bilateral_prepare") c("PREPARE", "PREPARE") else
      c("PREPARE", "COMMIT")
    states <- vapply(records, `[[`, character(1L), "state")
    if (!identical(states, state$last_states)) {
      cat(paste0(marker, "_NATIVE_RECOVERY_STATE"), state$mode, unname(states), "\n")
      state$last_states <- states
    }
    if (state$mode == "bilateral_prepare" && identical(states[[1L]], "PREPARE")) {
      # G has received E's output commitment, so E can finish its own save
      # without another delivery. Hold G's pending prepared envelope here.
      deadline <- proc.time()[["elapsed"]] + 5
      while (states[[2L]] %in% c("ABORTED", "RUNNING") &&
          proc.time()[["elapsed"]] < deadline) {
        Sys.sleep(.01)
        records <- probe(session, id)
        states <- vapply(records, `[[`, character(1L), "state")
      }
    }
    if (!identical(unname(states), expected)) return(invisible(NULL))
    terminated <- FALSE
    on.exit(if (!terminated) try(probe(session, id, "resume"), silent = TRUE), add = TRUE)
    probe(session, id, "pause")
    records <- probe(session, id)
    states <- vapply(records, `[[`, character(1L), "state")
    if (!identical(unname(states), expected)) return(invisible(NULL))
    stopifnot(identical(records[[1L]]$stage_id, records[[2L]]$stage_id),
      identical(vapply(records, `[[`, numeric(1L), "role"), c(site_a = 0, site_b = 1)),
      all(vapply(records, `[[`, logical(1L), "authenticated")))
    probe(session, id, "remember", state$mode)
    probe(session, id, "terminate")
    terminated <- TRUE
    state$fired <- TRUE
    state$proved <- c(state$proved, state$mode)
    state$session <- session
    state$operation <- id
    state$mode <- "none"
    stop("Synthetic interruption at authenticated native staged boundary", call. = FALSE)
  }
  assign(".grid_lmm_native_barrier", barrier, .GlobalEnv)
  trace(".dsvert_fanout_cycle", where = asNamespace("dsVertClient"), print = FALSE,
    exit = quote(get(".grid_lmm_native_barrier", .GlobalEnv)(operation, expressions, returnValue())))
  list(begin = function(mode) {
    stopifnot(mode %in% c("bilateral_prepare", "unilateral_commit"))
    state$mode <- mode
    state$fired <- FALSE
    state$last_states <- NULL
  }, interrupted = function() isTRUE(state$fired),
  verify = function() {
    stopifnot(identical(state$proved, c("bilateral_prepare", "unilateral_commit")),
      all(unlist(probe(state$session, state$operation, "verify_replay"))))
    TRUE
  }, stop = function() {
    state$mode <- "none"
    if (state$installed) untrace(".dsvert_fanout_cycle", where = asNamespace("dsVertClient"))
    state$installed <- FALSE
    invisible(TRUE)
  })
}
