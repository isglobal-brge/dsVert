#!/usr/bin/env Rscript
# Signed public-API integration harness for grouped/Cox routes.
# Success markers require a real authenticated release; a fail-closed API is a failure.
# Synthetic-only custodian harness. Analyst work uses the exported client API;
# provisioning/signing runs inside the existing isolated DSLite peer processes.
args <- commandArgs(trailingOnly = TRUE)
root <- normalizePath(if (length(args)) args[[1]] else "..")
n <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_N", "4"))
family <- Sys.getenv("DSVERT_GRID_VALIDATION_FAMILY")
cox <- identical(family, "cox")
gee <- grepl("_gee$", family)
staged <- family %in% c("lmm", "binomial_glmm", "poisson_glmm", "cox") || gee
staged_kind <- if (cox) "cox" else if (family == "lmm") "lmm" else if (gee) "gee-fixed-rho" else "glmm"
staged_marker <- paste0("DSLITE_", toupper(staged_kind))
epsilon <- as.numeric(Sys.getenv("DSVERT_GRID_VALIDATION_EPSILON", "4"))
instance <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_INSTANCE", "1"))
instance_count <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_INSTANCE_COUNT", "1"))
oracle_only <- identical(Sys.getenv("DSVERT_GRID_VALIDATION_ORACLE_ONLY"), "1")
first_instance <- instance
real_count <- if (oracle_only) 0L else as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_REAL_COUNT", "2"))
predictors <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_P", if (gee || staged) "3" else "6"))
grid_size <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_GRID", "2"))
owner_count <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_OWNERS", "2"))
gee_correlation <- Sys.getenv("DSVERT_GEE_CORRELATION", "exchangeable")
gee_rho <- as.numeric(Sys.getenv("DSVERT_GEE_RHO", "0.25"))
if (gee) stopifnot(gee_correlation %in% c("independence", "exchangeable", "ar1"),
  gee_rho %in% c(0, .25, .5), gee_correlation != "independence" || gee_rho == 0,
  predictors <= 3L, grid_size <= 4L)
stopifnot(n > 0, family %in% c("lmm", "binomial_glmm", "poisson_glmm",
  "binomial_gee", "poisson_gee", "cox"), epsilon %in% c(1, 4, 8),
  owner_count %in% c(2L, 3L, 5L), predictors >= 1L, predictors <= 16L,
  grid_size >= 2L, grid_size <= 50L, instance_count == 1L,
  oracle_only || real_count >= 1L,
  identical(Sys.getenv("DSVERT_GRID_VALIDATION_COLD"), "1"),
  Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT") %in%
    if (staged) c("0", "1") else "1")
if (cox) stopifnot(n >= 2L, n <= 400L)
server_dir <- file.path(root, "dsVert")
client_dir <- file.path(root, "dsVertClient")
if (cox) {
  oracle_binary <- file.path(server_dir, "inst/cross-grid-v2/build/cross-grid-oracle.test")
  registered <- processx::run(oracle_binary,
    "-test.list=^TestStructuredGridNoiseOracle$", error_on_status = FALSE)
  stopifnot(registered$status == 0L,
    "TestStructuredGridNoiseOracle" %in% strsplit(registered$stdout, "\n", fixed = TRUE)[[1L]])
}
source(file.path(client_dir, "inst/validation/v1.2.0/worked_example_custodian.R"))
source(file.path(server_dir, "inst/cross-grid-v2/integrator-validation/synthetic_replay_record.R"))
we_boot_peer <- grid_synthetic_replay_boot(we_boot_peer)
# Custodian-side release policy, applied to every fresh/cold isolated peer.
# This changes execution leases only; the release driver's 256GB/8h capacity
# gate remains independent. Unset variables preserve the server defaults.
structured_transport_policy <- list()
for (setting in c("ttl_seconds", "max_runtime_seconds")) {
  value <- Sys.getenv(paste0("DSVERT_RELEASE_", toupper(setting)))
  if (nzchar(value)) {
    parsed <- suppressWarnings(as.numeric(value))
    stopifnot(length(parsed) == 1L, is.finite(parsed), parsed == floor(parsed))
    structured_transport_policy[[paste0("dsvert.exact_gc.", setting)]] <- parsed
  }
}
structured_boot_peer <- we_boot_peer
we_boot_peer <- function(...) {
  peer <- structured_boot_peer(...)
  tryCatch({
    effective <- peer$worker$run(function(policy) {
      do.call(options, policy)
      ttl <- dsVert:::.exact_gc_ttl_seconds()
      list(ttl_seconds = ttl,
        max_runtime_seconds = dsVert:::.exact_gc_max_runtime_seconds(ttl),
        pid = Sys.getpid())
    }, args = list(structured_transport_policy))
    cat("DSLITE_ISOLATED_PEER_LEASE", jsonlite::toJSON(effective, auto_unbox = TRUE), "\n")
    peer
  }, error = function(error) {
    try(peer$worker$close(), silent = TRUE)
    stop(error)
  })
}
pkgload::load_all(client_dir, quiet = TRUE)
cf <- function(name) get(name, asNamespace("dsVertClient"), inherits = FALSE)
trace("stop", where = baseenv(), print = FALSE, tracer = quote({
  functions <- vapply(sys.calls(), function(call)
    if (is.symbol(call[[1L]])) as.character(call[[1L]]) else "<call>", character(1L))
  history <- get0(".grid_client_stop_history", .GlobalEnv)
  assign(".grid_client_stop_history", utils::tail(c(history, list(functions)), 20L), .GlobalEnv)
}))
trace(".dsvert_dp_glm_grid_cross_transcript_stop", where = asNamespace("dsVertClient"),
  print = FALSE, tracer = quote({
    entry <- list(message = substr(conditionMessage(error), 1L, 1000L),
      functions = vapply(sys.calls(), function(call)
        if (is.symbol(call[[1L]])) as.character(call[[1L]]) else "<call>", character(1L)))
    history <- get0(".grid_client_failure_history", .GlobalEnv)
    assign(".grid_client_failure_history", utils::tail(c(history, list(entry)), 20L), .GlobalEnv)
  }))
structured_client_diagnostics <- function() print(list(
  client_failure_history = get0(".grid_client_failure_history", .GlobalEnv),
  client_stop_history = get0(".grid_client_stop_history", .GlobalEnv)))
# Synthetic fixture diagnostics preserve errors and the connector's lifecycle.
structured_traffic <- new.env(parent = emptyenv())
structured_traffic$requests <- structured_traffic$responses <- 0
structured_traffic$submitted_calls <- structured_traffic$fetched_calls <- 0
structured_traffic$failed_calls <- list()
structured_traffic$completed_functions <- character()
structured_progress <- identical(Sys.getenv("DSVERT_GRID_VALIDATION_PROGRESS", if (n <= 4L) "1" else "0"), "1")
structured_rpc_name <- function(expr) {
  if (is.call(expr) && is.symbol(expr[[1L]])) return(as.character(expr[[1L]]))
  if (is.character(expr) && length(expr) == 1L) {
    match <- regexpr("^[[:space:]]*[[:alnum:]_.]+(?=[[:space:]]*\\()", expr, perl = TRUE)
    if (match[[1L]] > 0L) return(trimws(regmatches(expr, match)))
  }
  class(expr)[[1L]]
}
structured_fetch <- methods::selectMethod("dsFetch", "DSVertE2EProcessResult")
methods::setMethod("dsFetch", "DSVertE2EProcessResult", function(res) {
  tryCatch({
    value <- structured_fetch(res)
    structured_traffic$responses <- structured_traffic$responses + length(serialize(value, NULL, version = 3))
    structured_traffic$fetched_calls <- structured_traffic$fetched_calls + 1
    function_name <- res@consumed$grid_function
    if (structured_progress && is.character(function_name) && length(function_name) == 1L &&
        !function_name %in% structured_traffic$completed_functions) {
      structured_traffic$completed_functions <- c(structured_traffic$completed_functions, function_name)
      cat("DSLITE_RPC_COMPLETE", function_name, "\n")
    }
    value
  }, error = function(error) {
    failure <- list(peer = res@conn@name, function_name = res@consumed$grid_function,
      message = substr(conditionMessage(error), 1L, 1000L))
    structured_traffic$failed_calls <- tail(c(structured_traffic$failed_calls, list(failure)), 20L)
    cat("SYNTHETIC_DSI_FETCH_ERROR", failure$function_name, conditionMessage(error), "\n")
    stop(error)
  })
})
structured_aggregate <- methods::selectMethod("dsAggregate", "DSVertE2EProcessConnection")
methods::setMethod("dsAggregate", "DSVertE2EProcessConnection", function(conn, expr, async = TRUE) {
  tryCatch({
    structured_traffic$requests <- structured_traffic$requests + length(serialize(expr, NULL, version = 3))
    structured_traffic$submitted_calls <- structured_traffic$submitted_calls + 1
    structured_traffic$last_submitted <- list(peer = conn@name,
      function_name = structured_rpc_name(expr))
    result <- structured_aggregate(conn, expr, async)
    result@consumed$grid_function <- structured_traffic$last_submitted$function_name
    result
  }, error = function(error) {
    cat("SYNTHETIC_DSI_SUBMIT_ERROR", conditionMessage(error), "\n")
    stop(error)
  })
})
structured_poll <- methods::selectMethod("dsIsCompleted", "DSVertE2EProcessResult")
methods::setMethod("dsIsCompleted", "DSVertE2EProcessResult", function(res) {
  tryCatch(structured_poll(res), error = function(error) {
    cat("SYNTHETIC_DSI_POLL_ERROR", conditionMessage(error), "\n")
    stop(error)
  })
})
state_parent <- Sys.getenv("DSVERT_GRID_VALIDATION_STATE_PARENT",
  file.path(path.expand("~"), ".dsvert-structured-validation"))
dir.create(state_parent, recursive = TRUE, showWarnings = FALSE, mode = "0700")
state <- tempfile("cross-grid-dslite-", tmpdir = state_parent)
replay_only <- identical(Sys.getenv("DSVERT_GRID_VALIDATION_REPLAY_ONLY"), "1")
if (replay_only) {
  state <- normalizePath(Sys.getenv("DSVERT_GRID_VALIDATION_EXISTING_STATE"), mustWork = TRUE)
  stopifnot(staged, identical(Sys.getenv("DSVERT_GRID_VALIDATION_KEEP_STATE"), "1"),
    identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "0"))
}
dir.create(state, recursive = TRUE, mode = "0700", showWarnings = FALSE)
trace(if (cox) ".dsvert_dp_cox_cross_public_evidence_set" else
  ".dsvert_dp_lmm_cross_public_evidence_set", where = asNamespace("dsVertClient"),
  print = FALSE, tracer = quote({
    path <- file.path(state, "synthetic-public-evidence.rds")
    saveRDS(list(responses = responses,
      context = context[setdiff(names(context), c("conns", "all_conns"))],
      manifest = manifest, analysis_id = analysis_id, release = release, compiled = compiled), path)
    Sys.chmod(path, "0600")
  }))
trace(".dsvert_dp_gaussian_synopsis_certificate_validate", where = asNamespace("dsVertClient"),
  print = FALSE, tracer = quote(if (certificate$descriptor$version %in%
      c("bounded-lmm-cross-grid-v1", "bounded-binomial-glmm-cross-grid-v1", "bounded-poisson-glmm-cross-grid-v1",
        "bounded-binomial-gee-cross-grid-v1", "bounded-poisson-gee-cross-grid-v1", "bounded-cox-breslow-observed-cross-grid-v1")) {
    path <- file.path(state, "synthetic-public-certificate.rds")
    saveRDS(list(object = object, certificate = certificate), path)
    Sys.chmod(path, "0600")
  }))
peers <- list()
# Executed inside a synthetic custodian; the copied database and MAC key stay
# in that custodian and its fresh child. Return only pass/fail evidence.
structured_lmm_cold_lifecycle <- function(server_dir, contract, schema) {
  fixture <- get(".grid_lifecycle_fixture", .GlobalEnv)
  callr::r(function(server_dir, fixture, contract, schema) {
    pkgload::load_all(server_dir, quiet = TRUE)
    sf <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
    sf(".dsvert_dp_glm_grid_profile_admit")(contract, fixture$policy, schema)
    manifest <- sf(".dsvert_dp_capsule_source_manifest")(fixture$manifest_json)
    source <- DBI::dbConnect(RSQLite::SQLite(), fixture$record_database)
    on.exit(DBI::dbDisconnect(source), add = TRUE)
    scratch <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
    on.exit(DBI::dbDisconnect(scratch), add = TRUE)
    RSQLite::sqliteCopyDatabase(source, scratch)
    cox <- identical(contract$spec$family, "cox")
    artifact <- sf(if (cox) ".dsvert_dp_cox_cross_artifacts" else
      ".dsvert_dp_lmm_cross_artifacts")(manifest)[[1L]]
    read <- function(source_contract = fixture$source_contract, stage = fixture$stage) {
      sf(".dsvert_dp_lmm_cross_record")(scratch, fixture$secret, manifest,
        artifact, source_contract, stage = stage)
    }
    rejected <- function(code) {
      condition <- tryCatch(sf(".dsvert_dp_synopsis_remote_public_v1")(force(code)), error = identity)
      inherits(condition, "dsvert_dp_public_failure") &&
        identical(conditionMessage(condition), sf(".DSVERT_DP_PUBLIC_FAILURE_MESSAGE"))
    }
    record <- read()
    stopifnot(!is.null(record))
    block <- sf(".dsvert_dp_capsule_coordinate_layout")(manifest)$blocks[["gaussian_models::grid"]]
    base <- as.raw(rep(7, 16 * block$length))
    chunk <- list(offset = block$start - 1, count = block$length)
    inject <- function() {
      if (cox) sf(".dsvert_dp_cox_cross_inject")(scratch, fixture$secret,
        manifest, fixture$source_contract, chunk, base, fixture$policy, schema) else
      sf(".dsvert_dp_lmm_cross_inject")(scratch, fixture$secret,
        manifest, fixture$source_contract, chunk, base, fixture$policy)
    }
    first <- inject()
    expected <- sf(".dsvert_dp_capsule_source_add_ring128")(base,
      sf(".exact_gc_standard_b64_raw")(record$share, length(base), "synthetic LMM result"))
    stopifnot(identical(as.raw(first), expected), identical(inject(), first),
      identical(attr(first, "dsvert_staged_source")$validity_share, record$validity_share))
    changed_source <- fixture$source_contract
    changed_source$source_context_hash <- strrep("0", 64)
    source_swap <- rejected(read(source_contract = changed_source))
    changed_stage <- fixture$stage
    changed_stage$stage_plan_digest <- strrep("1", 64)
    stage_swap <- rejected(read(stage = changed_stage))
    changed_stage <- fixture$stage
    changed_stage$purpose <- if (cox) paste0("cox-loss-staged-v1/", strrep("2", 64)) else
      paste0("grouped-", sf(".dsvert_dp_staged_grouped_kind")(artifact$family),
        "-staged-v1/", strrep("2", 64))
    stage_purpose <- rejected(read(stage = changed_stage))
    row <- DBI::dbGetQuery(scratch, paste("SELECT chunk_index FROM source_aggregate_chunks",
      "WHERE capsule_id=? ORDER BY chunk_index LIMIT 1"), params = list(fixture$source_contract$capsule_id))
    stopifnot(nrow(row) == 1L)
    loaded <- sf(".dsvert_dp_capsule_source_aggregate_load")(scratch,
      fixture$source_contract$capsule_id, row$chunk_index[[1L]], fixture$secret)
    stopifnot(!is.null(loaded))
    DBI::dbExecute(scratch, "UPDATE source_aggregate_chunks SET row_mac='tampered'")
    source_tamper <- rejected(sf(".dsvert_dp_capsule_source_aggregate_load")(scratch,
      fixture$source_contract$capsule_id, row$chunk_index[[1L]], fixture$secret))
    DBI::dbExecute(scratch, "UPDATE source_cross_grid_records SET row_mac='tampered' WHERE batch_index=0")
    stage_tamper <- rejected(inject())
    checks <- c(cold_authenticated_admission = TRUE, original_injection = TRUE,
      identical_replay = TRUE, swapped_source_rejected = source_swap,
      swapped_stage_rejected = stage_swap, swapped_stage_purpose_rejected = stage_purpose,
      source_tamper_rejected = source_tamper, stage_tamper_rejected = stage_tamper)
    stopifnot(all(checks))
    as.list(checks)
  }, args = list(server_dir, fixture, contract, schema))
}

run <- function() {
  end_to_end_started <- proc.time()[["elapsed"]]
  on.exit({
    we_close_peers(peers)
    if (!identical(Sys.getenv("DSVERT_GRID_VALIDATION_KEEP_STATE"), "1")) unlink(state, recursive = TRUE)
  }, add = TRUE)
  set.seed(20260918 + instance)
  # Dyadic synthetic inputs preserve exact independent integer encoding.
  x <- matrix(sample(0:16, n * predictors, replace = TRUE) / 16, n, predictors)
  truth <- c(0, rep(1 / 32, predictors))
  eta <- drop(cbind(1, x) %*% truth)
  maximum <- if (startsWith(family, "poisson")) 4 else 1
  y <- if (family == "lmm") sample(0:16, n, replace = TRUE) / 16 else
    if (startsWith(family, "poisson")) pmin(maximum, rpois(n, exp(eta))) else
      rbinom(n, 1, plogis(eta))
  cluster_size <- 4L
  cluster_count <- ceiling(n / cluster_size)
  cluster <- sprintf("cluster-%05d", ceiling(seq_len(n) / cluster_size))
  cluster_levels <- sprintf("cluster-%05d", seq_len(cluster_count))
  time <- sample(seq(0.25, 20, by = .25), n, replace = TRUE)
  event <- rbinom(n, 1, .7)
  ids <- sprintf("synthetic-%06d", seq_len(n))
  owner_names <- paste0("site_", letters[seq_len(owner_count)])
  if (cox) {
    stopifnot(predictors >= owner_count)
    allocation <- pmin(owner_count, 1L + floor((seq_len(predictors)-1L) * owner_count / predictors))
  } else {
    # The first owner supplies private routing; the second supplies outcomes.
    # K2 collapses covariates onto the routing owner, K3 onto owner C, and K5
    # partitions covariates over C..E, giving every pinned owner a source role.
    covariate_owners <- if (owner_count == 2L) 1L else seq.int(3L, owner_count)
    stopifnot(predictors >= length(covariate_owners))
    allocation <- covariate_owners[1L + floor((seq_len(predictors)-1L) *
      length(covariate_owners) / predictors)]
  }
  variable_names <- if (predictors == 10L) sprintf("x%02d", seq_len(predictors)) else paste0("x", seq_len(predictors))
  predictor_order <- paste0(owner_names[allocation], "$", variable_names)
  stopifnot(identical(predictor_order, sort(predictor_order, method = "radix")))
  raw <- stats::setNames(lapply(seq_len(owner_count), function(owner) {
    result <- data.frame(patient_id = ids)
    if (owner == 1L) {
      if (cox) { result$time <- time; result$event <- event } else {
        result$cluster <- factor(cluster, levels = cluster_levels)
      }
    }
    if (!cox && owner == 2L) result$y <- y
    for (j in which(allocation == owner)) result[[variable_names[[j]]]] <- x[, j]
    result
  }), owner_names)
  specs <- lapply(owner_names, function(peer) {
    home <- file.path(state, peer)
    dir.create(home, mode = "0700", showWarnings = FALSE)
    list(name = peer, state_dir = home, dslite_home = file.path(home, "dslite"),
      # Resolve and checksum the loaded package's native platform runtime.
      mpc_binary = "",
      dataset_id = "cross-grid-synthetic", dataset_version = "v1")
  })
  names(specs) <- names(raw)
  policies <- lapply(names(raw), function(peer) {
    variables <- setdiff(names(raw[[peer]]), "patient_id")
    numeric_variables <- setdiff(variables, "cluster")
    bounds <- stats::setNames(lapply(numeric_variables, function(v)
      c(0, if (v == "y") maximum else if (v == "time") 20 else 1)), numeric_variables)
    list(total_epsilon = epsilon, total_delta = 2^-100, domain = "cross-grid-v2-validation",
      cohort_id = "cross-grid-synthetic", adjacency = "add_remove_patient",
      patient_column = "patient_id", unit_capacity = n, numeric_grid_bits = 16L,
      max_records_per_unit = 1L, fixed_cohort_size = NULL, overflow_policy = "reject_snapshot",
      datasets = list(DA = list(id = specs[[peer]]$dataset_id, version = "v1")),
      workload_scope = list(mode = "catalog_v1", numeric_moments = character(),
        categorical_marginals = character(), categorical_pairs = list(), correlations = list()),
      designated_noise_peers = owner_names[1:2], numeric_bounds = bounds,
      categorical_levels = if ("cluster" %in% variables) list(cluster = cluster_levels) else NULL,
      capsule_dataset_mapping = list(DA = variables), gaussian_specs = list(),
      synopsis_state_path = file.path(specs[[peer]]$state_dir, "dp-synopsis"))
  })
  names(policies) <- names(raw)
  boot <- function(pins = NULL) stats::setNames(lapply(names(raw), function(peer)
    we_boot_peer(specs[[peer]], server_dir, if (is.null(pins)) NULL else pins[[peer]],
      raw[[peer]], policies[[peer]])), names(raw))
  cat("DSLITE_BOOT_INITIAL_START\n")
  peers <<- boot()
  cat("DSLITE_BOOT_INITIAL_COMPLETE\n")
  identities <- tryCatch(ds.getIdentityPks(we_connections(peers)), error = function(error) {
    for (peer in peers) {
      print(peer$worker$run(function() {
        tryCatch(get(".dsvert_e2e_server", .GlobalEnv)$aggregate(
          get(".dsvert_e2e_sid", .GlobalEnv), quote(dsvertIdentityPkDS())),
          error = function(error) substr(conditionMessage(error), 1, 400))
      }))
    }
    stop(error)
  })
  # Assign the synthetic authorities before any pinset or contract is signed.
  # The grouping or Cox time/event owner keeps its raw data; only unused bootstrap state homes
  # are assigned to owner names so A is the actual transport garbler.
  if (staged) {
    identity_ids <- vapply(peers[owner_names[1:2]], function(peer) peer$worker$run(function() {
      dsVert:::.dsvert_relay_peer_id(dsVert:::.get_identity_keypair()$identity_pk)
    }), character(1L))
    we_close_peers(peers)
    if (order(identity_ids, method = "radix")[[1L]] != 1L) {
      homes <- lapply(specs[1:2], function(spec) spec[c("state_dir", "dslite_home")])
      for (j in 1:2) {
        specs[[j]][c("state_dir", "dslite_home")] <- homes[[3L-j]]
        policies[[j]]$synopsis_state_path <- file.path(specs[[j]]$state_dir, "dp-synopsis")
      }
      identities[1:2] <- identities[2:1]
      identity_ids <- identity_ids[2:1]
    }
    stopifnot(order(identity_ids, method = "radix")[[1L]] == 1L)
    cat(paste0(staged_marker, if (cox) "_TIME_EVENT_OWNER_PINNED_GARBLER\n" else
      "_GROUPING_OWNER_PINNED_GARBLER\n"))
  }
  pins <- stats::setNames(lapply(names(raw), function(peer) {
    other <- setdiff(names(raw), peer)
    stats::setNames(unname(unlist(identities[other])), other)
  }), names(raw))
  we_close_peers(peers)
  cat("DSLITE_BOOT_PINNED_START\n")
  peers <<- boot(pins)
  cat("DSLITE_BOOT_PINNED_COMPLETE\n")
  conns <- we_connections(peers)
  for (peer in peers) peer$worker$run(function(n, gee) {
    options(dsvert.psi.max_input_ids = as.integer(2^ceiling(log2(max(64, n)))))
    trace(".exact_gc_record_private_error", where = asNamespace("dsVert"), print = FALSE,
      tracer = substitute({
        captured <- list(operation = state$operation, message = message,
          # Synthetic fixture only: preserve startup errors before spool cleanup.
          worker_log = if (!is.null(state$spool) && file.exists(file.path(state$spool, "worker-private.log")))
            readLines(file.path(state$spool, "worker-private.log"), n = 12L, warn = FALSE)
            else character())
        if (GEE) captured$worker_exit_status <- tryCatch(
          state$process$get_exit_status(), error = function(error) NA_integer_)
        assign(".grid_early_worker_error", captured, .GlobalEnv)
      }, list(GEE = gee)))
    TRUE
  }, args = list(n, gee))
  cat("DSLITE_ALIGNMENT_START\n")
  tryCatch(ds.psiAlign("D", "patient_id", "DA", datasources = conns, verbose = FALSE),
    error = function(error) {
      for (peer in peers) print(peer$worker$run(function()
        get0(".grid_early_worker_error", .GlobalEnv)))
      stop(error)
    })
  cat("DSLITE_ALIGNMENT_COMPLETE\n")
  for (peer in peers) peer$worker$run(function() {
    trace(".dsvert_dp_transcript_stop", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(if (!inherits(error, "dsvert_dp_public_failure"))
        assign(".grid_bootstrap_failure", list(message = conditionMessage(error),
          call = if (is.null(conditionCall(error))) "" else as.character(conditionCall(error)[[1]])),
          envir = .GlobalEnv)))
    TRUE
  })
  for (instance in seq.int(instance, length.out = instance_count)) {
  grid_synthetic_native_reset(peers)
  bootstrap <- tryCatch(cf(".dsvert_dp_synopsis_bootstrap_build_v1")(conns),
    error = function(error) {
      for (peer in peers) print(peer$worker$run(function()
        get0(".grid_bootstrap_failure", .GlobalEnv)))
      stop(error)
    })
  schema <- jsonlite::fromJSON(bootstrap$manifest_bundle$schema_json, simplifyVector = FALSE)
  cat("DSLITE_INITIAL_BOOTSTRAP_COMPLETE\n")
  schema$datasets <- lapply(schema$datasets, function(dataset) {
    dataset$columns <- lapply(dataset$columns, function(column) {
      if (identical(column$kind, "categorical"))
        column$levels <- unlist(column$levels, use.names = FALSE)
      column
    })
    dataset
  })
  all_pins <- stats::setNames(unname(unlist(identities)), names(raw))
  policy <- list(peer_pinset = all_pins,
    peer_pinset_sha256 = cf(".dsvert_dp_capsule_source_hash")(as.list(all_pins)),
    designated_noise_peers = owner_names[1:2], unit_capacity = n, numeric_grid_bits = 16,
    adjacency = "add_remove_patient")
  offsets <- if (grid_size == 2L) c(0, 0.25) else seq(-0.25, 0.25, length.out = grid_size)
  beta <- lapply(offsets, function(offset)
    truth + c(offset / 2 + (instance - 1) / 1024, rep(0, predictors)))
  if (cox) beta <- lapply(seq_along(beta), function(j)
    beta[[j]][-1L] + c((j-1L)/64, rep(0, predictors-1L)))
  beta <- beta[order(vapply(beta, function(b) cf(".dsvert_joint_dp_client_json")(as.list(b)), character(1)), method = "radix")]
  make_contract <- function(schema) {
    authenticated <- cf(".dsvert_dp_glm_grid_cross_schema_validate")(
      policy, schema$logical_snapshot, schema, cf(".dsvert_dp_glm_grid_cross_verify"))
    alignment <- list(version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "cross-grid-synthetic",
      public_alignment_contract_sha256 = cf(".dsvert_dp_capsule_source_hash")(list(
        logical_snapshot = schema$logical_snapshot, alignment_group = "cross-grid-synthetic",
        method = "pinned_psi_ordered_manifest_v1")), public_patient_dependent_hash = FALSE)
    prefix <- if (cox) ".dsvert_dp_cox_grid_cross_" else ".dsvert_dp_grouped_grid_cross_"
    raw_spec <- list(version = paste0(family, "_grid_cross_v1"), analysis_id = "grid",
      dataset = "DA", predictor_order = predictor_order, beta_grid = beta, alignment = alignment)
    if (cox) {
      raw_spec$time <- "site_a$time"; raw_spec$event <- "site_a$event"
    } else {
      raw_spec$outcome <- "site_b$y"; raw_spec$max_outcome <- maximum
      raw_spec$grouping <- list(reference = "site_a$cluster", cluster_capacity = cluster_count,
        max_patients_per_cluster = cluster_size, patient_rule = "one_analysis_row_per_patient_v1",
        ordering = "stable_signed_slots_preserve_gaps_v1")
      raw_spec$parameters <- if (family == "lmm")
        list(objective = "ml", variance_grid = list(
          list(residual_variance = .5, random_intercept_variance = .25),
          list(residual_variance = 1, random_intercept_variance = .25))) else if (family %in% c("binomial_glmm", "poisson_glmm"))
        list(variance_grid = list(0, .25), quadrature = "gh5_fixed_v1") else if (gee)
        list(correlation = gee_correlation, rho = gee_rho, score_clip = 1,
          composition = "staged_fixed_rho_v1") else
        list(random_intercept_variance = .25, quadrature = "gh5_fixed_v1")
    }
    spec <- cf(paste0(prefix, "spec"))(raw_spec, policy, authenticated)
    artifact <- cf(paste0(prefix, "artifact"))(spec)
    list(version = if (cox) "dsvert-cox-cross-owner-grid-signed-contract-v1" else
      "dsvert-grouped-cross-signed-contract-v1", spec = spec, artifact = artifact,
      source_contract = cf(paste0(prefix, "source_contract"))(spec, artifact))
  }
  contract <- make_contract(schema)
  cat("DSLITE_STRUCTURED_SPEC_COMPLETE\n")
  workload <- list(version = "dsvert-biomedical-capsule-workload-contract-v2",
    describe = list(), survival = list(), vertical_cross = list(),
    gaussian = list(grid = list(owner_peer = contract$spec$owner_peer, spec = list(
      version = contract$spec$version, dataset = "DA", contract = contract))))
  # Compute the schema fixed point before asking custodians to sign it.
  schema$signatures <- NULL
  snapshot_context <- list(servers = "site_a", status = list(site_a = list(policy = list(
    domain = "cross-grid-v2-validation", cohort_id = "cross-grid-synthetic",
    peer_pinset_sha256 = policy$peer_pinset_sha256))))
  schema$logical_snapshot <- cf(".dsvert_dp_capsule_manifest_expected_snapshot")(
    snapshot_context, schema$datasets, schema$logical_snapshot$alignment_protocol_version, workload)
  schema$signatures <- lapply(peers, function(peer) peer$worker$run(function(schema) {
    identity <- dsVert:::.get_identity_keypair()
    dsVert:::.dsvert_relay_sign_message(dsVert:::.dsvert_dp_capsule_schema_message(schema), identity$identity_sk)
  }, args = list(schema)))
  contract <- make_contract(schema)
  contract$signatures <- lapply(peers, function(peer) peer$worker$run(function(contract) {
    identity <- dsVert:::.get_identity_keypair()
    dsVert:::.dsvert_relay_sign_message(get(if (contract$spec$family == "cox") ".dsvert_dp_cox_grid_cross_message" else
      ".dsvert_dp_grouped_cross_message", asNamespace("dsVert"))(contract), identity$identity_sk)
  }, args = list(contract)))
  cf(if (cox) ".dsvert_dp_cox_grid_cross_contract_validate" else
    ".dsvert_dp_grouped_grid_cross_contract_validate")(contract, policy, schema)
  workload$gaussian$grid$spec$contract <- contract
  stopifnot(identical(cf(".dsvert_dp_capsule_manifest_expected_snapshot")(
    snapshot_context,schema$datasets,schema$logical_snapshot$alignment_protocol_version,workload),schema$logical_snapshot))

  peers[[contract$spec$owner_peer]]$worker$run(function(contract) {
    options(dsvert.dp.gaussian_specs = list(grid = list(version = contract$spec$version,
      dataset = "DA", contract = dsVert:::.dsvert_dp_canonical_json(
        dsVert:::.dsvert_dp_canonical_query_value(contract)))))
    TRUE
  }, args = list(contract))
  for (peer in peers) peer$worker$run(function(server_dir) {
    trace("stop", where = baseenv(), print = FALSE, tracer = quote({
      functions <- vapply(sys.calls(), function(call)
        if (is.symbol(call[[1L]])) as.character(call[[1L]]) else "<call>", character(1L))
      history <- get0(".grid_stop_history", .GlobalEnv)
      assign(".grid_stop_history", utils::tail(c(history, list(functions)), 20L), .GlobalEnv)
      for (frame in sys.frames()) {
        if (exists("stderr_file", frame, inherits = FALSE) &&
            exists("command", frame, inherits = FALSE)) {
          command_name <- get("command", frame, inherits = FALSE)
          stderr_path <- get("stderr_file", frame, inherits = FALSE)
          if (is.character(command_name) && length(command_name) == 1L &&
              grepl("^[a-z0-9][a-z0-9-]{0,63}$", command_name)) {
            entry <- list(command = command_name,
              status = if (exists("status", frame, inherits = FALSE)) get("status", frame, inherits = FALSE) else NULL,
              stderr = if (file.exists(stderr_path)) substr(paste(readLines(stderr_path,
                n = 12L, warn = FALSE), collapse = "\n"), 1L, 1000L) else "")
            history <- get0(".grid_native_error_history", .GlobalEnv)
            assign(".grid_native_error_history", utils::tail(c(history, list(entry)), 20L), .GlobalEnv)
          }
        }
      }
    }))
    trace(".dsvert_dp_capsule_mechanism_selection", where = asNamespace("dsVert"), print = FALSE,
      exit = quote(assign(".grid_public_mechanism_selection", returnValue(), .GlobalEnv)))
    namespace <- asNamespace("dsVert")
    native_call <- local({
      original <- get(".callMpcTool", namespace, inherits = FALSE)
      function(command, input_data, simplify_output = TRUE) {
        tryCatch(original(command, input_data, simplify_output), error = function(error) {
          entry <- list(command = command, message = substr(conditionMessage(error), 1L, 1000L))
          history <- get0(".grid_native_error_history", .GlobalEnv)
          assign(".grid_native_error_history", utils::tail(c(history, list(entry)), 20L), .GlobalEnv)
          stop(error)
        })
      }
    })
    unlockBinding(".callMpcTool", namespace)
    assign(".callMpcTool", native_call, namespace)
    lockBinding(".callMpcTool", namespace)
    trace(".dsvert_dp_transcript_stop", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote({
        entry <- list(message = substr(conditionMessage(error), 1L, 1000L),
          call = if (is.null(conditionCall(error))) "" else as.character(conditionCall(error)[[1L]]),
          functions = vapply(sys.calls(), function(call)
            if (is.symbol(call[[1L]])) as.character(call[[1L]]) else "<call>", character(1L)))
        assign(".grid_synthetic_failure", entry, .GlobalEnv)
        history <- get0(".grid_synthetic_failure_history", .GlobalEnv)
        assign(".grid_synthetic_failure_history", tail(c(history, list(entry)), 20L), .GlobalEnv)
      }))
    trace(".dsvert_dp_glm_grid_cross_spec", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(assign(".grid_public_spec", list(raw=raw,schema=schema),.GlobalEnv)))
    trace(".dsvert_dp_capsule_manifest_expected_snapshot", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(assign(".grid_public_snapshot", list(datasets = datasets,
        workload = .dsvert_dp_glm_grid_cross_snapshot_workload(workload_contract),
        policy=policy[c("domain","cohort_id","peer_pinset_sha256")]), .GlobalEnv)))
    trace(".dsvert_dp_glm_grid_cross_fail", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(assign(".grid_grouped_failure", vapply(sys.calls(), function(call)
        if (is.symbol(call[[1L]])) as.character(call[[1L]]) else "<call>", character(1L)), .GlobalEnv)))
    assign(".grid_synthetic_noise", list(), .GlobalEnv)
    traffic <- new.env(parent = emptyenv())
    traffic$exact_gc_max_offsets <- numeric()
    traffic$exact_gc_offered_bytes <- traffic$source_ciphertext_delivered_bytes <- 0
    assign(".grid_protocol_traffic", traffic, .GlobalEnv)
    trace(".exact_gc_exchange_impl", where = asNamespace("dsVert"), print = FALSE,
      exit = quote({
        offered <- returnValue()$outbound
        if (!is.null(offered)) {
          traffic <- get(".grid_protocol_traffic", .GlobalEnv)
          key <- paste(offered$session_id, offered$operation_id, offered$sender_peer_id, sep = "/")
          previous <- traffic$exact_gc_max_offsets[key]
          if (is.na(previous)) previous <- 0
          traffic$exact_gc_max_offsets[key] <- max(previous, offered$offset + offered$chunk_bytes)
          traffic$exact_gc_offered_bytes <- traffic$exact_gc_offered_bytes + offered$chunk_bytes
        }
      }))
    trace(".dsvert_dp_capsule_source_accept_impl", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote({
        envelope <- jsonlite::fromJSON(envelope_json, simplifyVector = FALSE)
        if (is.numeric(envelope$ciphertext_bytes) && length(envelope$ciphertext_bytes) == 1L) {
          traffic <- get(".grid_protocol_traffic", .GlobalEnv)
          traffic$source_ciphertext_delivered_bytes <-
            traffic$source_ciphertext_delivered_bytes + envelope$ciphertext_bytes
        }
      }))
    trace(".dsvert_dp_glm_grid_cross_bind", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(assign(".grid_lifecycle_fixture", list(policy = policy,
        secret = secret, manifest_json = manifest_json,
        source_contract = source_contract), .GlobalEnv)))
    if (Sys.getenv("DSVERT_GRID_VALIDATION_FAMILY") %in% c("lmm", "binomial_glmm", "poisson_glmm",
        "cox", "binomial_gee", "poisson_gee")) {
      source(file.path(server_dir, "inst/cross-grid-v2/validate_cold_lifecycle.R"))
      assign(".grid_interrupt_mode", "none", .GlobalEnv)
      assign(".grid_interrupted", FALSE, .GlobalEnv)
      trace(if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_FAMILY"), "cox"))
        ".dsvert_dp_cox_cross_bind" else ".dsvert_dp_lmm_cross_bind",
        where = asNamespace("dsVert"), print = FALSE,
        exit = quote(assign(".grid_lifecycle_fixture", list(policy = policy, secret = secret,
          manifest_json = .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(manifest)),
          source_contract = source_contract,
          stage = .dsvert_dp_lmm_cross_binding(ss, analysis_id)$stage), .GlobalEnv)))
      trace(".dsvert_dp_lmm_cross_prepare", where = asNamespace("dsVert"), print = FALSE,
        exit = quote({
          if (identical(get(".grid_interrupt_mode", .GlobalEnv), "prepared")) {
            assign(".grid_interrupted", TRUE, .GlobalEnv)
            stop("Synthetic interruption after staged prepared receipt", call. = FALSE)
          }
        }))
      trace(".dsvert_dp_lmm_cross_start", where = asNamespace("dsVert"), print = FALSE,
        exit = quote(assign(".grid_native_recovery_session", list(
          session_id = session_id, operation_id = stage$operation_id,
          session = ss), .GlobalEnv)))
      trace(".dsvert_dp_lmm_cross_store", where = asNamespace("dsVert"), print = FALSE,
        tracer = quote({
          mode <- get(".grid_interrupt_mode", .GlobalEnv)
          if (identical(mode, "committed") ||
              (identical(mode, "unilateral") && identical(policy$peer_name, "site_b"))) {
            assign(".grid_interrupted", TRUE, .GlobalEnv)
            stop("Synthetic interruption after native terminal COMMIT before R persistence", call. = FALSE)
          }
        }))
      trace(".dsvert_dp_lmm_cross_finalize", where = asNamespace("dsVert"), print = FALSE,
        exit = quote(get("grid_snapshot_lifecycle", .GlobalEnv)()))
    } else if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_COLD"), "1") ||
        identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "1")) {
      source(file.path(server_dir, "inst/cross-grid-v2/validate_cold_lifecycle.R"))
      assign(".grid_interrupted", FALSE, .GlobalEnv)
      trace(".dsvert_dp_glm_grid_cross_finalize", where = asNamespace("dsVert"),
        print = FALSE, tracer = quote({
          if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "1") &&
              !isTRUE(get(".grid_interrupted", .GlobalEnv))) {
            assign(".grid_interrupted", TRUE, .GlobalEnv)
            stop("Synthetic interruption after durable grid batches", call. = FALSE)
          }
        }), exit = quote({
          if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_COLD"), "1"))
            get("grid_snapshot_lifecycle", .GlobalEnv)()
        }))
    }
    trace(".private_write_lines", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote({
        if (identical(basename(path), "worker-config.json")) {
          cfg <- jsonlite::fromJSON(value, simplifyVector = FALSE)
          if (cfg$operation %in% c("joint-dp-vector-laplace-v3", "joint-dp-vector-gaussian-one-draw-v1")) {
            # Synthetic validation only: retain the noise policy/seed, never
            # the source share, transport key, or kernel private inputs.
            keep <- cfg[c("operation", "purpose", "garbler_id", "evaluator_id", "role",
              "joint_dp_vector", "joint_dp_gaussian_one_draw", "private_seed")]
            records <- get(".grid_synthetic_noise", .GlobalEnv)
            records[[length(records)+1L]] <- keep
            assign(".grid_synthetic_noise", records, .GlobalEnv)
          }
        }
      }))
    trace(".dsvert_dp_glm_grid_cross_equal", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote({
        canonical <- function(x) .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(x))
        if (!identical(canonical(value), canonical(expected))) {
          fields <- union(names(value), names(expected))
          unequal <- fields[!vapply(fields, function(k) identical(canonical(value[[k]]), canonical(expected[[k]])), logical(1))]
          assign(".grid_public_mismatch", list(fields = unequal,
            functions = vapply(sys.calls(), function(x) if (is.symbol(x[[1]])) as.character(x[[1]]) else "<call>", character(1))), .GlobalEnv)
        }
      }))
    TRUE
  }, args = list(server_dir))
  cat("DSLITE_CUSTODIAN_SIGNATURES_COMPLETE\n")
  tryCatch(cf(".dsvert_dp_synopsis_bootstrap_build_v1")(conns), error = function(error) {
    for (peer in peers) print(peer$worker$run(function() list(
      failure = get0(".grid_synthetic_failure", .GlobalEnv),
      mismatch = get0(".grid_public_mismatch", .GlobalEnv))))
    actual <- peers$site_a$worker$run(function() get0(".grid_public_snapshot", .GlobalEnv))
    expected <- list(datasets=schema$datasets,workload=cf(".dsvert_dp_glm_grid_cross_snapshot_workload")(workload),
      policy=snapshot_context$status$site_a$policy)
    actual_spec <- peers$site_a$worker$run(function() get0(".grid_public_spec",.GlobalEnv))
    saveRDS(list(actual=actual,expected=expected,actual_spec=actual_spec,contract=contract,schema=schema,policy=policy),
      file.path(state, "public-admission-debug.rds"))
    Sys.chmod(file.path(state, "public-admission-debug.rds"), "0600")
    differences <- function(a,b,path="") {
      if (identical(cf(".dsvert_joint_dp_client_json")(cf(".dsvert_joint_dp_client_canonical")(a)),
                    cf(".dsvert_joint_dp_client_json")(cf(".dsvert_joint_dp_client_canonical")(b)))) return(character())
      if (!is.list(a)||!is.list(b)||is.null(names(a))||is.null(names(b))) return(path)
      unlist(lapply(union(names(a),names(b)),function(k) differences(a[[k]],b[[k]],paste(path,k,sep="/"))))
    }
    print(differences(actual,expected))
    stop(error)
  })
  cat("DSLITE_PUBLIC_ADMISSION_COMPLETE\n")
  for (name in names(peers)) {
    selection <- peers[[name]]$worker$run(function()
      get0(".grid_public_mechanism_selection", .GlobalEnv))
    cat("DSLITE_PUBLIC_MECHANISM_SELECTION", name,
      jsonlite::toJSON(selection, auto_unbox = TRUE, digits = NA), "\n")
  }
  if (staged) {
    replay_fixture <- file.path(state, "synthetic-public-replay-fixture.rds")
    saveRDS(list(synthetic_fixture_seed = 20260918 + instance,
      n = n, predictors = predictors, owners = owner_count,
      specs = specs, policies = policies, pins = pins,
      contract = contract, policy = policy, schema = schema, predictor_order = predictor_order), replay_fixture)
    Sys.chmod(replay_fixture, "0600")
  }
  if (replay_only) for (peer in peers) peer$worker$run(function() {
    for (name in c(".dsvert_dp_capsule_source_prepare_impl",
        ".dsvert_dp_lmm_cross_prepare_worker", ".dsvert_dp_cox_cross_prepare_worker",
        ".dsvert_dp_synopsis_local_claim_v1", ".dsvert_dp_synopsis_execution_start_v1")) {
      trace(name, where = asNamespace("dsVert"), print = FALSE,
        tracer = quote(stop("Synthetic published replay forbids a new producer", call. = FALSE)))
    }
    TRUE
  })
  real_release <- instance < first_instance + real_count
  if (!staged || oracle_only) {
    source(file.path(server_dir, "inst/cross-grid-v2/prepare_oracle_noise.R"))
    planned <- tryCatch(grid_oracle_noise(peers, conns,
      cf(".dsvert_dp_synopsis_bootstrap_build_v1")(conns),
      synthetic_staged = staged && oracle_only), error = function(error) {
        for (peer in peers) print(peer$worker$run(function()
          get0(".grid_synthetic_failure", .GlobalEnv)))
        stop(error)
      })
    captures <- planned$captures
    elapsed <- NA_real_
  }
  if (real_release) {
  formula <- stats::as.formula(paste(if (cox) "Surv(site_a$time, site_a$event)" else
    "site_b$y", "~", paste(predictor_order, collapse = " + ")))
  invoke <- function() {
    if (cox) getExportedValue("dsVertClient", "dp_cox_grid")(formula, data = "DA", analysis_id = "grid", datasources = conns) else {
      entry <- if (family == "lmm") "dp_lmm_grid" else if (gee) "dp_gee_grid" else "dp_glmm_grid"
      getExportedValue("dsVertClient", entry)(
        "site_b$y", predictor_order, contract, policy, schema, datasources = conns)
    }
  }
  release_started <- proc.time()[["elapsed"]]
  protocol_before <- c(requests = structured_traffic$requests, responses = structured_traffic$responses)
  recovery_exercised <- identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "1")
  native_verified <- FALSE
  if (staged && recovery_exercised) {
    source(file.path(root, "integrator-validation/lmm_native_recovery.R"))
    native_recovery <- structured_lmm_native_recovery(peers[owner_names[1:2]], kind = staged_kind)
    on.exit(native_recovery$stop(), add = TRUE)
    for (mode in c("prepared", "bilateral_prepare", "unilateral_commit", "committed", "unilateral")) {
      cat(paste0(staged_marker, "_RECOVERY_BEGIN"), mode, "\n")
      native_mode <- mode %in% c("bilateral_prepare", "unilateral_commit")
      if (native_mode) native_recovery$begin(mode)
      for (peer in peers[owner_names[1:2]]) peer$worker$run(function(mode) {
        assign(".grid_interrupt_mode", mode, .GlobalEnv)
        assign(".grid_interrupted", FALSE, .GlobalEnv)
        TRUE
      }, args = list(if (native_mode) "none" else mode))
      interrupted <- tryCatch(invoke(), error = identity)
      flags <- vapply(peers[owner_names[1:2]], function(peer) peer$worker$run(function()
        isTRUE(get(".grid_interrupted", .GlobalEnv))), logical(1L))
      expected_flags <- if (native_mode) c(FALSE, FALSE) else
        if (mode == "unilateral") c(FALSE, TRUE) else c(TRUE, TRUE)
      native_fired <- !native_mode || native_recovery$interrupted()
      if (!inherits(interrupted, "error") || !identical(unname(flags), expected_flags) || !native_fired) {
        cat(paste0(staged_marker, "_UNEXPECTED_RECOVERY_RESULT"), mode,
          if (inherits(interrupted, "error")) conditionMessage(interrupted) else "release returned", "\n")
        print(structured_traffic$last_submitted)
        print(structured_traffic$failed_calls)
        structured_client_diagnostics()
        for (peer in peers) print(peer$worker$run(function() list(
          failure = get0(".grid_synthetic_failure", .GlobalEnv),
          history = get0(".grid_synthetic_failure_history", .GlobalEnv),
          stop_history = get0(".grid_stop_history", .GlobalEnv),
          worker_error = get0(".grid_early_worker_error", .GlobalEnv),
          mechanism_selection = get0(".grid_public_mechanism_selection", .GlobalEnv),
          native_errors = get0(".grid_native_error_history", .GlobalEnv),
          grouped_failure = get0(".grid_grouped_failure", .GlobalEnv),
          mismatch = get0(".grid_public_mismatch", .GlobalEnv))))
        if (gee) for (peer in peers) print(peer$worker$run(function() list(
          gee_worker_error = get0(".grid_early_worker_error", .GlobalEnv))))
      }
      stopifnot(inherits(interrupted, "error"), identical(unname(flags), expected_flags), native_fired)
      persisted <- vapply(peers[owner_names[1:2]], function(peer) peer$worker$run(function() {
        fixture <- get(".grid_lifecycle_fixture", .GlobalEnv)
        dsVert:::.dsvert_dp_capsule_source_with_store(fixture$policy, fixture$secret, function(con) {
          !is.null(dsVert:::.dsvert_dp_glm_grid_cross_load(con, fixture$secret,
            fixture$source_contract$capsule_id, "grid", 1L))
        })
      }), logical(1L))
      stopifnot(identical(unname(persisted),
        if (mode == "unilateral") c(TRUE, FALSE) else c(FALSE, FALSE)))
      if (mode == "committed") {
        native_verified <- native_recovery$verify()
        native_recovery$stop()
        cat(paste0(staged_marker, "_NATIVE_PREPARE_REMASK_AND_UNILATERAL_COMMIT_EXACT_REPLAY_VERIFIED\n"))
      }
      cat(paste0(staged_marker, "_RECOVERY_BOUNDARY"), mode, "OBSERVED\n")
    }
    for (peer in peers[owner_names[1:2]]) peer$worker$run(function() {
      assign(".grid_interrupt_mode", "none", .GlobalEnv)
      TRUE
    })
  } else if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "1")) {
    interrupted <- tryCatch(invoke(), error = identity)
    stopifnot(inherits(interrupted, "error"), all(unlist(lapply(
      peers[owner_names[1:2]], function(peer) peer$worker$run(function()
        get(".grid_interrupted", .GlobalEnv))))))
    cat("DSLITE_INTERRUPTED_AFTER_DURABLE_BATCHES\n")
  }
  elapsed <- system.time(fit <- tryCatch(invoke(), error = function(error) {
      print(structured_traffic$last_submitted)
      print(structured_traffic$failed_calls)
      structured_client_diagnostics()
      for (peer in peers) print(peer$worker$run(function() list(
        failure = get0(".grid_synthetic_failure", .GlobalEnv),
        history = get0(".grid_synthetic_failure_history", .GlobalEnv),
        stop_history = get0(".grid_stop_history", .GlobalEnv),
        worker_error = get0(".grid_early_worker_error", .GlobalEnv),
        mechanism_selection = get0(".grid_public_mechanism_selection", .GlobalEnv),
        native_errors = get0(".grid_native_error_history", .GlobalEnv),
        grouped_failure = get0(".grid_grouped_failure", .GlobalEnv))))
      if (gee) for (peer in peers) print(peer$worker$run(function() list(
        gee_worker_error = get0(".grid_early_worker_error", .GlobalEnv))))
      stop(error)
    }))[["elapsed"]]
  if (replay_only) {
    checked <- ds.validateDPGaussianCertificate(fit$provenance_certificate)
    stopifnot(identical(checked$integrity_valid, TRUE),
      identical(checked$authenticity, "session_transport_anchored"))
    fit_path <- file.path(state, "synthetic-public-replayed-fit.rds")
    saveRDS(fit, fit_path)
    Sys.chmod(fit_path, "0600")
    cat(paste0(staged_marker, "_RETAINED_PUBLISHED_REPLAY_AUTHENTICATED\n"))
    return(invisible(fit))
  }
  end_to_end_release_elapsed <- proc.time()[["elapsed"]] - end_to_end_started
  end_to_end_serialized_rpc_bytes <- structured_traffic$requests + structured_traffic$responses
  successful_call_elapsed <- elapsed
  if (staged) elapsed <- proc.time()[["elapsed"]] - release_started
  release_protocol_bytes <- sum(c(requests = structured_traffic$requests,
    responses = structured_traffic$responses) - protocol_before)
  protocol_payload <- lapply(peers, function(peer) peer$worker$run(function() {
    traffic <- get(".grid_protocol_traffic", .GlobalEnv)
    list(exact_gc_unique_payload_bytes = sum(traffic$exact_gc_max_offsets),
      exact_gc_offered_payload_bytes = traffic$exact_gc_offered_bytes,
      source_ciphertext_delivered_bytes = traffic$source_ciphertext_delivered_bytes)
  }))
  protocol_payload <- as.list(Reduce(`+`, lapply(protocol_payload, unlist)))
  stopifnot(identical(fit$implementation_state, "cross_owner_exact_gc_materialized"))
  actual_captures <- unlist(lapply(peers, function(peer) peer$worker$run(function()
    get(".grid_synthetic_noise", .GlobalEnv))), recursive = FALSE)
  capture_identity <- function(records) {
    fields <- c("operation", "purpose", "garbler_id", "evaluator_id", "role",
      "joint_dp_vector", "private_seed")
    sort(unique(vapply(records, function(record) cf(".dsvert_joint_dp_client_json")(
      cf(".dsvert_joint_dp_client_canonical")(record[fields])), character(1))), method = "radix")
  }
  if (staged) {
    captures <- actual_captures
    planned <- list(artifact_key = fit$provenance_certificate$artifact_key)
  } else if (!length(grid_synthetic_native_calls(peers, planned)))
    stopifnot(identical(capture_identity(actual_captures), capture_identity(captures)))
  }
  native_calls <- grid_synthetic_native_calls(peers, planned)
  if (length(native_calls)) captures <- list()
  stopifnot(length(captures) >= 2L || length(native_calls) >= 2L)
  purposes <- unique(vapply(captures, `[[`, character(1), "purpose"))
  draws <- lapply(purposes, function(purpose) {
    pair <- captures[vapply(captures, function(z) identical(z$purpose,purpose),logical(1))]
    g <- pair[[which(vapply(pair,function(z)identical(z$role,"garbler"),logical(1)))[[1]]]]
    e <- pair[[which(vapply(pair,function(z)identical(z$role,"evaluator"),logical(1)))[[1]]]]
    draw <- g[setdiff(names(g),c("role","private_seed"))]
    draw$garbler_seed <- g$private_seed
    draw$evaluator_seed <- e$private_seed
    draw
  })
  spec <- contract$spec
  source(file.path(root, "integrator-validation/structured_integer_oracle.R"))
  exact <- structured_integer_oracle(server_dir, client_dir, spec, x, y, cluster, time, event)
  # Commitment to deterministic exact integers, independent of random authority
  # keys and sticky DP seeds. Same bytes in oracle-only and real-release modes.
  exact_text <- paste0(paste(c(as.character(n), exact), collapse = "\n"), "\n")
  exact_hash <- digest::digest(charToRaw(exact_text), algo = "sha256", serialize = FALSE)
  expected_hash <- Sys.getenv("DSVERT_GRID_VALIDATION_EXPECTED_ORACLE_SHA256")
  if (nzchar(expected_hash)) stopifnot(identical(exact_hash, expected_hash))
  input <- file.path(state, "synthetic-oracle-input.json")
  output <- file.path(state, "synthetic-oracle-output.json")
  fixture <- list(Exact = as.list(c(as.character(n), exact)), Draws = draws,
    NativeCalls = native_calls, Output = output)
  writeLines(jsonlite::toJSON(fixture,auto_unbox=TRUE,digits=17,null="null"),input)
  oracle_run <- processx::run(file.path(server_dir,"inst/cross-grid-v2/build/cross-grid-oracle.test"),
    "-test.run=^TestStructuredGridNoiseOracle$",env=c(DSVERT_STRUCTURED_ORACLE_FIXTURE=input),
    error_on_status = FALSE)
  if (oracle_run$status != 0) cat(oracle_run$stdout, oracle_run$stderr)
  stopifnot(oracle_run$status==0)
  oracle <- jsonlite::fromJSON(output)
  candidate_count <- if (staged && !cox && !gee) length(spec$candidate_grid) else length(spec$beta_grid)
  width <- length(exact) / candidate_count
  loss_indices <- seq.int(1L, length(exact), by = width)
  released_losses <- as.numeric(oracle$Released[-1])[loss_indices]
  exact_losses <- as.numeric(exact)[loss_indices]
  replay_record <- grid_synthetic_replay_record(workload, contract, schema, policy,
    c(as.character(n), unname(exact)), unname(oracle$Released), loss_indices + 1L,
    draws, jsonlite::fromJSON(output, simplifyVector = FALSE)$NativeCalls,
    if (real_release) fit$provenance_certificate else NULL,
    source_commits = grid_synthetic_source_commits(server_dir, client_dir))
  if (oracle_only) {
    source_commits <- if (file.exists(file.path(root, "frozen-source-manifest.json"))) {
      jsonlite::fromJSON(file.path(root, "frozen-source-manifest.json"))$repositories
    } else setNames(lapply(c(server_dir, client_dir), function(repo)
      processx::run("git", c("-C", repo, "rev-parse", "HEAD"))$stdout |>
        trimws()), c("dsVert", "dsVertClient"))
    summary <- list(source_commits = source_commits, recomputation = replay_record,
      family = family, n = n, p = predictors, grid = grid_size,
      candidates = candidate_count, clusters = cluster_count, slots = cluster_size,
      owners = owner_count, epsilon = epsilon, instance = instance,
      oracle_only = TRUE, real_authenticated_release = FALSE,
      expected_oracle_sha256 = exact_hash,
      oracle_hash_scope = "UTF-8 count then exact integer coordinates, LF terminated",
      selected_candidate = which.min(released_losses), exact_best = which.min(exact_losses),
      loss_gap = (exact_losses[which.min(released_losses)] - min(exact_losses)) / 2^16)
    summary_json <- jsonlite::toJSON(summary, auto_unbox = TRUE, digits = 17)
    metrics_path <- Sys.getenv("DSVERT_GRID_VALIDATION_METRICS_PATH")
    if (nzchar(metrics_path)) writeLines(summary_json, metrics_path)
    cat("STRUCTURED_SELECTION_ORACLE_ONLY", summary_json, "\n")
    return(invisible(summary))
  }
  if (real_release) {
  # Compare authenticated integers before converting the DP block to doubles.
  trace(".dsvert_dp_synopsis_client_replay", where = asNamespace("dsVertClient"),
    print = FALSE, exit = quote(assign(".grid_public_replay", returnValue(), .GlobalEnv)))
  checked <- ds.validateDPGaussianCertificate(fit$provenance_certificate)
  stopifnot(identical(checked$integrity_valid, TRUE),
    identical(checked$authenticity, "session_transport_anchored"))
  if (gee) stopifnot(length(checked$coordinates) == length(exact),
    identical(unname(checked$sufficient_statistics_dp$candidate_negative_log_likelihoods),
      unname(checked$coordinates[loss_indices])))
  untrace(".dsvert_dp_synopsis_client_replay", where = asNamespace("dsVertClient"))
  observed <- get(".grid_public_replay", .GlobalEnv)$scaled
  if (!identical(unname(observed), unname(oracle$Released))) {
    saveRDS(list(observed = observed, oracle_released = oracle$Released,
      certificate = fit$provenance_certificate),
      file.path(state, "public-release-mismatch.rds"))
    Sys.chmod(file.path(state, "public-release-mismatch.rds"), "0600")
  }
  stopifnot(identical(unname(observed), unname(oracle$Released)))
  stopifnot(fit$selected_candidate == which.min(released_losses))
  replay <- invoke()
  stopifnot(identical(replay$coefficients, fit$coefficients),
    identical(replay$provenance_certificate, fit$provenance_certificate))
  tampered <- contract
  tampered$spec$beta_grid[[1L]][[1L]] <- tampered$spec$beta_grid[[1L]][[1L]] + 1/16
  rejected <- tryCatch(cf(if (cox) ".dsvert_dp_cox_grid_cross_contract_validate" else
    ".dsvert_dp_grouped_grid_cross_contract_validate")(tampered, policy, schema), error = identity)
  stopifnot(inherits(rejected, "dsvert_dp_public_failure"))
  cat("DSLITE_ORACLE_BITWISE_EQUAL_STICKY_TAMPER_REJECTED", family, "\n")
  if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_COLD"), "1")) {
    cold <- if (staged) lapply(peers[owner_names[1:2]], function(peer)
      peer$worker$run(structured_lmm_cold_lifecycle, args = list(server_dir, contract, schema))) else
      lapply(peers[owner_names[1:2]], function(peer) peer$worker$run(
      function(server_dir, contract, schema) {
        source(file.path(server_dir, "inst/cross-grid-v2/validate_cold_lifecycle.R"))
        grid_cold_lifecycle(server_dir, contract, schema)
      }, args = list(server_dir, contract, schema)))
    stopifnot(all(unlist(cold)))
    cat("DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED\n")
    if (staged) {
      policies[[contract$spec$owner_peer]]$gaussian_specs <- list(grid = list(
        version = contract$spec$version, dataset = "DA", contract =
          cf(".dsvert_joint_dp_client_json")(cf(".dsvert_joint_dp_client_canonical")(contract))))
      we_close_peers(peers)
      peers <<- boot(pins)
      conns <- we_connections(peers)
      for (peer in peers) peer$worker$run(function(n) {
        options(dsvert.psi.max_input_ids = as.integer(2^ceiling(log2(max(64, n)))))
        for (name in c(".dsvert_dp_capsule_source_prepare_impl",
            ".dsvert_dp_lmm_cross_prepare_worker", ".dsvert_dp_cox_cross_prepare_worker",
            ".dsvert_dp_synopsis_local_claim_v1", ".dsvert_dp_synopsis_execution_start_v1")) {
          trace(name, where = asNamespace("dsVert"), print = FALSE,
            tracer = quote(stop("Synthetic cold replay forbids a new producer", call. = FALSE)))
        }
        TRUE
      }, args = list(n))
      ds.psiAlign("D", "patient_id", "DA", datasources = conns, verbose = FALSE)
      cold_fit <- invoke()
      stopifnot(identical(cold_fit$coefficients, fit$coefficients),
        identical(cold_fit$provenance_certificate, fit$provenance_certificate))
      cold_checked <- ds.validateDPGaussianCertificate(cold_fit$provenance_certificate)
      stopifnot(identical(cold_checked$integrity_valid, TRUE),
        identical(cold_checked$authenticity, "session_transport_anchored"))
      cat(paste0(staged_marker, "_COLD_EXPORTED_API_EQUAL_AUTHENTICATED\n"))
    }
  }
  }

  summary <- list(family = family, recomputation = replay_record, n = n, p = predictors, grid = grid_size,
    candidates = candidate_count, clusters = cluster_count, slots = cluster_size, owners = owner_count,
    working_correlation = if (gee) list(mode = "fixed_analyst_specified",
      correlation = spec$parameters$correlation, rho = spec$parameters$rho,
      score_clip = spec$parameters$score_clip, composition = spec$parameters$composition) else NULL,
    epsilon = epsilon, instance = instance,
    elapsed = elapsed, successful_call_elapsed = successful_call_elapsed,
    uninterrupted_baseline_elapsed = if (!recovery_exercised) successful_call_elapsed else NULL,
    recovery = if (recovery_exercised) "exercised" else "not_exercised",
    native_recovery = if (native_verified) "prepare_remask_and_unilateral_commit_exact_replay" else "not_exercised",
    end_to_end_release_elapsed = end_to_end_release_elapsed,
    end_to_end_serialized_rpc_bytes = end_to_end_serialized_rpc_bytes,
    end_to_end_scope = paste0("fixture-bootstrap-PSI-signing-source-staged-",
      if (family == "lmm") "LMM" else family,
      "-and-DP-through-first-successful-release-including-retries-before-oracle-and-replay"),
    release_serialized_rpc_bytes = release_protocol_bytes,
    serialized_rpc_scope = "R-v3-serialized-DSI-request-response-objects-including-retries-excluding-IPC-framing",
    protocol_payload = protocol_payload,
    protocol_payload_scope = "public-release-exactGC-and-source-transport-before-replay-no-bootstrap-PSI",
    expected_oracle_sha256 = exact_hash,
    oracle_only = !real_release,
    selected_candidate = which.min(released_losses), exact_best = which.min(exact_losses),
    loss_gap = (exact_losses[which.min(released_losses)] - min(exact_losses)) / 2^16,
    artifact_key = planned$artifact_key,
    certificate_sha256 = if (real_release) fit$certificate_sha256 else NULL)
  summary_json <- jsonlite::toJSON(summary, auto_unbox = TRUE, null = "null", digits = 17)
  metrics_path <- Sys.getenv("DSVERT_GRID_VALIDATION_METRICS_PATH")
  if (nzchar(metrics_path)) writeLines(summary_json, metrics_path)
  cat(summary_json, "\n")
  }
}
run()
