# PUBLIC SYNTHETIC EVALUATIONS ONLY. Never source this capture hook in a server
# profile: it intentionally retains test noise seeds and synthetic source shares.
grid_synthetic_capture_native <- function(original) {
  force(original)
  function(command, input_data, simplify_output = TRUE) {
    capture <- grepl("^joint-dp-vector-(convolution|gaussian)-(share|finalize)-v[0-9]+$", command)
    # Preserve JSON array shape even for one-coordinate chunks. An exit trace
    # cannot be used here: .callMpcTool replaces on.exit() for private cleanup.
    output <- original(command, input_data, if (capture) FALSE else simplify_output)
    if (capture) {
      calls <- get(".grid_synthetic_native_calls", .GlobalEnv)
      calls[[length(calls) + 1L]] <- list(command = command,
        input = input_data, output = output)
      assign(".grid_synthetic_native_calls", calls, .GlobalEnv)
      path <- get(".grid_synthetic_native_path", .GlobalEnv)
      saveRDS(calls, path)
      Sys.chmod(path, "0600")
      if (simplify_output) output <- jsonlite::fromJSON(jsonlite::toJSON(
        output, auto_unbox = TRUE, digits = 17, null = "null"))
    }
    output
  }
}

grid_synthetic_replay_boot <- function(boot) {
  force(boot)
  function(spec, server_dir, pins = NULL, raw = NULL, policy = NULL) {
    stopifnot(identical(spec$dataset_id, "cross-grid-synthetic"),
      is.data.frame(raw), is.character(raw$patient_id),
      all(grepl("^synthetic-[0-9]+$", raw$patient_id)))
    peer <- boot(spec, server_dir, pins, raw, policy)
    peer$worker$run(function(path, capture) {
      assign(".grid_synthetic_native_calls", if (file.exists(path)) readRDS(path) else list(), .GlobalEnv)
      assign(".grid_synthetic_native_path", path, .GlobalEnv)
      namespace <- asNamespace("dsVert")
      wrapped <- capture(get(".callMpcTool", namespace, inherits = FALSE))
      unlockBinding(".callMpcTool", namespace)
      assign(".callMpcTool", wrapped, namespace)
      lockBinding(".callMpcTool", namespace)
      TRUE
    }, args = list(file.path(spec$state_dir, "synthetic-native-calls.rds"),
      grid_synthetic_capture_native))
    peer
  }
}

grid_synthetic_native_calls <- function(peers, planned = NULL) {
  calls <- unlist(lapply(peers, function(peer) peer$worker$run(function()
    get0(".grid_synthetic_native_calls", .GlobalEnv, ifnotfound = list()))), recursive = FALSE)
  if (!length(calls)) calls <- planned$native_calls
  if (is.null(calls)) return(list())
  encoded <- vapply(calls, function(call) as.character(jsonlite::toJSON(
    call, auto_unbox = TRUE, digits = 17, null = "null")), character(1L))
  calls[!duplicated(encoded)]
}

grid_synthetic_native_reset <- function(peers) {
  for (peer in peers) peer$worker$run(function() {
    assign(".grid_synthetic_native_calls", list(), .GlobalEnv)
    saveRDS(list(), get(".grid_synthetic_native_path", .GlobalEnv))
    TRUE
  })
  invisible(NULL)
}

grid_synthetic_source_commits <- function(server_dir, client_dir) {
  setNames(lapply(c(server_dir, client_dir), function(path)
    trimws(processx::run("git", c("-C", path, "rev-parse", "HEAD"))$stdout)),
    c("dsVert", "dsVertClient"))
}

grid_synthetic_replay_record <- function(workload, contract, schema, policy,
    exact, released, criterion_indices, draws, native_calls, certificate = NULL,
    source_commits = NULL) {
  integers <- function(value) {
    stopifnot(is.character(value), length(value) > 0L,
      all(grepl("^(0|-?[1-9][0-9]*)$", value)))
    as.list(unname(value))
  }
  stopifnot(is.list(contract$spec), length(contract$signatures) >= 2L,
    length(schema$signatures) >= 2L, length(exact) == length(released),
    length(criterion_indices) > 0L, !anyDuplicated(criterion_indices),
    all(criterion_indices >= 2L), all(criterion_indices <= length(exact)),
    length(draws) > 0L || length(native_calls) > 0L)
  bytes <- charToRaw(paste0(paste(exact, collapse = "\n"), "\n"))
  list(version = "dsvert-public-synthetic-release-replay-v1",
    data_classification = "public-synthetic-test-fixture",
    seed_scope = "test-harness-only-never-production-secrets",
    integer_encoding = "canonical-base10-strings",
    coordinate_order = "capsule-layout-count-first-then-signed-grid-coordinates",
    criterion_index_base = 1L, criterion_indices = as.list(criterion_indices),
    signed_workload = workload, signed_contract = contract,
    signed_schema = schema, public_policy = policy,
    source_commits = source_commits,
    exact_coordinates = integers(exact),
    exact_candidate_criterion_integers = integers(exact[criterion_indices]),
    exact_coordinates_sha256 = digest::digest(bytes, algo = "sha256", serialize = FALSE),
    exact_hash_encoding = "UTF-8 decimal coordinates separated and terminated by LF",
    released_coordinates = integers(released),
    peer_draws = draws, native_calls = native_calls,
    public_certificate = certificate)
}
