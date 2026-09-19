#!/usr/bin/env Rscript
# Integration harness: six grouped/Cox routes still require producer wiring.
# Success markers require a real authenticated release; a fail-closed API is a failure.
# Synthetic-only custodian harness. Analyst work uses the exported client API;
# provisioning/signing runs inside the existing isolated DSLite peer processes.
args <- commandArgs(trailingOnly = TRUE)
root <- normalizePath(if (length(args)) args[[1]] else "..")
n <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_N", "4"))
family <- Sys.getenv("DSVERT_GRID_VALIDATION_FAMILY")
cox <- identical(family, "cox")
gee <- grepl("_gee$", family)
epsilon <- as.numeric(Sys.getenv("DSVERT_GRID_VALIDATION_EPSILON", "4"))
instance <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_INSTANCE", "1"))
instance_count <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_INSTANCE_COUNT", "1"))
oracle_only <- identical(Sys.getenv("DSVERT_GRID_VALIDATION_ORACLE_ONLY"), "1")
first_instance <- instance
real_count <- if (oracle_only) 0L else as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_REAL_COUNT", "2"))
predictors <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_P", if (gee) "3" else "6"))
grid_size <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_GRID", "2"))
owner_count <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_OWNERS", "2"))
stopifnot(n > 0, family %in% c("lmm", "binomial_glmm", "poisson_glmm",
  "binomial_gee", "poisson_gee", "cox"), epsilon %in% c(1, 4, 8),
  owner_count %in% c(2L, 3L, 5L), predictors >= 1L, predictors <= 16L,
  grid_size >= 2L, grid_size <= 50L, !oracle_only, instance_count == 1L, real_count >= 1L,
  identical(Sys.getenv("DSVERT_GRID_VALIDATION_COLD"), "1"),
  identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "1"))
server_dir <- file.path(root, "dsVert")
client_dir <- file.path(root, "dsVertClient")
source(file.path(client_dir, "inst/validation/v1.2.0/worked_example_custodian.R"))
pkgload::load_all(client_dir, quiet = TRUE)
cf <- function(name) get(name, asNamespace("dsVertClient"), inherits = FALSE)
# Synthetic fixture diagnostics preserve errors and the connector's lifecycle.
structured_fetch <- methods::selectMethod("dsFetch", "DSVertE2EProcessResult")
methods::setMethod("dsFetch", "DSVertE2EProcessResult", function(res) {
  tryCatch(structured_fetch(res), error = function(error) {
    cat("SYNTHETIC_DSI_FETCH_ERROR", conditionMessage(error), "\n")
    stop(error)
  })
})
structured_aggregate <- methods::selectMethod("dsAggregate", "DSVertE2EProcessConnection")
methods::setMethod("dsAggregate", "DSVertE2EProcessConnection", function(conn, expr, async = TRUE) {
  tryCatch(structured_aggregate(conn, expr, async), error = function(error) {
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
  file.path(client_dir, "inst/cross-grid-v2/build"))
dir.create(state_parent, recursive = TRUE, showWarnings = FALSE, mode = "0700")
state <- tempfile("cross-grid-dslite-", tmpdir = state_parent)
dir.create(state, recursive = TRUE, mode = "0700")
peers <- list()
run <- function() {
  on.exit({we_close_peers(peers); unlink(state, recursive = TRUE)}, add = TRUE)
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
  allocation <- pmin(owner_count, 1L + floor((seq_len(predictors)-1L) * owner_count / predictors))
  variable_names <- if (predictors == 10L) sprintf("x%02d", seq_len(predictors)) else paste0("x", seq_len(predictors))
  predictor_order <- paste0(owner_names[allocation], "$", variable_names)
  stopifnot(identical(predictor_order, sort(predictor_order, method = "radix")))
  raw <- stats::setNames(lapply(seq_len(owner_count), function(owner) {
    result <- data.frame(patient_id = ids)
    if (owner == 1L) {
      if (cox) { result$time <- time; result$event <- event } else {
        result$y <- y; result$cluster <- cluster
      }
    }
    for (j in which(allocation == owner)) result[[variable_names[[j]]]] <- x[, j]
    result
  }), owner_names)
  specs <- lapply(owner_names, function(peer) {
    home <- file.path(state, peer)
    dir.create(home, mode = "0700")
    list(name = peer, state_dir = home, dslite_home = file.path(home, "dslite"),
      mpc_binary = file.path(server_dir, "inst/bin/linux-amd64/dsvert-mpc"),
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
  pins <- stats::setNames(lapply(names(raw), function(peer) {
    other <- setdiff(names(raw), peer)
    stats::setNames(unname(unlist(identities[other])), other)
  }), names(raw))
  we_close_peers(peers)
  cat("DSLITE_BOOT_PINNED_START\n")
  peers <<- boot(pins)
  cat("DSLITE_BOOT_PINNED_COMPLETE\n")
  conns <- we_connections(peers)
  for (peer in peers) peer$worker$run(function(n) {
    options(dsvert.psi.max_input_ids = as.integer(2^ceiling(log2(max(64, n)))))
    TRUE
  }, args = list(n))
  cat("DSLITE_ALIGNMENT_START\n")
  ds.psiAlign("D", "patient_id", "DA", datasources = conns, verbose = FALSE)
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
      raw_spec$outcome <- "site_a$y"; raw_spec$max_outcome <- maximum
      raw_spec$grouping <- list(reference = "site_a$cluster", cluster_capacity = cluster_count,
        max_patients_per_cluster = cluster_size, patient_rule = "one_analysis_row_per_patient_v1",
        ordering = "stable_signed_slots_preserve_gaps_v1")
      raw_spec$parameters <- if (family == "lmm")
        list(residual_variance = 1, random_intercept_variance = .25) else if (gee)
        list(correlation = "exchangeable", rho = .25, score_clip = 1) else
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
    gaussian = list(grid = list(owner_peer = "site_a", spec = list(
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

  peers$site_a$worker$run(function(contract) {
    options(dsvert.dp.gaussian_specs = list(grid = list(version = contract$spec$version,
      dataset = "DA", contract = dsVert:::.dsvert_dp_canonical_json(
        dsVert:::.dsvert_dp_canonical_query_value(contract)))))
    TRUE
  }, args = list(contract))
  for (peer in peers) peer$worker$run(function(server_dir) {
    trace(".dsvert_dp_transcript_stop", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(if (!inherits(error, "dsvert_dp_public_failure")) assign(".grid_synthetic_failure", list(message = conditionMessage(error),
        call = if (is.null(conditionCall(error))) "" else as.character(conditionCall(error)[[1]])),
        envir = .GlobalEnv)))
    trace(".dsvert_dp_glm_grid_cross_spec", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(assign(".grid_public_spec", list(raw=raw,schema=schema),.GlobalEnv)))
    trace(".dsvert_dp_capsule_manifest_expected_snapshot", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(assign(".grid_public_snapshot", list(datasets = datasets,
        workload = .dsvert_dp_glm_grid_cross_snapshot_workload(workload_contract),
        policy=policy[c("domain","cohort_id","peer_pinset_sha256")]), .GlobalEnv)))
    assign(".grid_synthetic_noise", list(), .GlobalEnv)
    trace(".dsvert_dp_glm_grid_cross_bind", where = asNamespace("dsVert"), print = FALSE,
      tracer = quote(assign(".grid_lifecycle_fixture", list(policy = policy,
        secret = secret, manifest_json = manifest_json,
        source_contract = source_contract), .GlobalEnv)))
    if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_COLD"), "1") ||
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
      file.path(server_dir,"inst/cross-grid-v2/build/public-admission-debug.rds"))
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
  real_release <- instance < first_instance + real_count
  {
    source(file.path(server_dir, "inst/cross-grid-v2/prepare_oracle_noise.R"))
    planned <- tryCatch(grid_oracle_noise(peers, conns,
      cf(".dsvert_dp_synopsis_bootstrap_build_v1")(conns)), error = function(error) {
        for (peer in peers) print(peer$worker$run(function()
          get0(".grid_synthetic_failure", .GlobalEnv)))
        stop(error)
      })
    captures <- planned$captures
    elapsed <- NA_real_
  }
  if (real_release) {
  formula <- stats::as.formula(paste(if (cox) "Surv(site_a$time, site_a$event)" else
    "site_a$y", "~", paste(predictor_order, collapse = " + ")))
  invoke <- function() {
    if (cox) cf("dp_cox_grid")(formula, data = "DA", analysis_id = "grid", datasources = conns) else {
      entry <- if (family == "lmm") "dp_lmm_grid" else if (gee) "dp_gee_grid" else "dp_glmm_grid"
      cf(entry)("site_a$y", predictor_order, contract, policy, schema, datasources = conns)
    }
  }
  if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "1")) {
    interrupted <- tryCatch(invoke(), error = identity)
    stopifnot(inherits(interrupted, "error"), all(unlist(lapply(
      peers[owner_names[1:2]], function(peer) peer$worker$run(function()
        get(".grid_interrupted", .GlobalEnv))))))
    cat("DSLITE_INTERRUPTED_AFTER_DURABLE_BATCHES\n")
  }
  elapsed <- system.time(fit <- tryCatch(invoke(), error = function(error) {
      for (peer in peers) print(peer$worker$run(function() {
        get0(".grid_synthetic_failure", .GlobalEnv)
      }))
      stop(error)
    }))[["elapsed"]]
  stopifnot(identical(fit$implementation_state, "cross_owner_exact_gc_materialized"))
  actual_captures <- unlist(lapply(peers, function(peer) peer$worker$run(function()
    get(".grid_synthetic_noise", .GlobalEnv))), recursive = FALSE)
  capture_identity <- function(records) {
    fields <- c("operation", "purpose", "garbler_id", "evaluator_id", "role",
      "joint_dp_vector", "private_seed")
    sort(unique(vapply(records, function(record) cf(".dsvert_joint_dp_client_json")(
      cf(".dsvert_joint_dp_client_canonical")(record[fields])), character(1))), method = "radix")
  }
  stopifnot(identical(capture_identity(actual_captures), capture_identity(captures)))
  }
  stopifnot(length(captures) >= 2L)
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
  input <- file.path(state, "synthetic-oracle-input.json")
  output <- file.path(state, "synthetic-oracle-output.json")
  fixture <- list(Exact = as.list(c(as.character(n), exact)), Draws = draws, Output = output)
  writeLines(jsonlite::toJSON(fixture,auto_unbox=TRUE,digits=NA,null="null"),input)
  oracle_run <- processx::run(file.path(server_dir,"inst/cross-grid-v2/build/cross-grid-oracle.test"),
    "-test.run=^TestStructuredGridNoiseOracle$",env=c(DSVERT_STRUCTURED_ORACLE_FIXTURE=input),
    error_on_status = FALSE)
  if (oracle_run$status != 0) cat(oracle_run$stdout, oracle_run$stderr)
  stopifnot(oracle_run$status==0)
  oracle <- jsonlite::fromJSON(output)
  if (real_release) {
  # Compare authenticated integers before converting the DP block to doubles.
  trace(".dsvert_dp_synopsis_client_replay", where = asNamespace("dsVertClient"),
    print = FALSE, exit = quote(assign(".grid_public_replay", returnValue(), .GlobalEnv)))
  checked <- ds.validateDPGaussianCertificate(fit$provenance_certificate)
  stopifnot(identical(checked$integrity_valid, TRUE),
    identical(checked$authenticity, "session_transport_anchored"))
  untrace(".dsvert_dp_synopsis_client_replay", where = asNamespace("dsVertClient"))
  observed <- get(".grid_public_replay", .GlobalEnv)$scaled
  if (!identical(unname(observed), unname(oracle$Released))) {
    saveRDS(list(observed = observed, oracle_released = oracle$Released,
      certificate = fit$provenance_certificate),
      file.path(server_dir, "inst/cross-grid-v2/build/public-release-mismatch.rds"))
  }
  stopifnot(identical(unname(observed), unname(oracle$Released)))
  width <- length(exact) / length(spec$beta_grid)
  loss_indices <- seq.int(1L, length(exact), by = width)
  released_losses <- as.numeric(oracle$Released[-1])[loss_indices]
  exact_losses <- as.numeric(exact)[loss_indices]
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
    cold <- lapply(peers[owner_names[1:2]], function(peer) peer$worker$run(
      function(server_dir, contract, schema) {
        source(file.path(server_dir, "inst/cross-grid-v2/validate_cold_lifecycle.R"))
        grid_cold_lifecycle(server_dir, contract, schema)
      }, args = list(server_dir, contract, schema)))
    stopifnot(all(unlist(cold)))
    cat("DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED\n")
  }
  }

  cat(jsonlite::toJSON(list(family = family, n = n, p = predictors, grid = grid_size, owners = owner_count,
    epsilon = epsilon, instance = instance,
    elapsed = elapsed, oracle_only = !real_release,
    selected_candidate = which.min(released_losses), exact_best = which.min(exact_losses),
    loss_gap = (exact_losses[which.min(released_losses)] - min(exact_losses)) / 2^16,
    artifact_key = planned$artifact_key,
    certificate_sha256 = if (real_release) fit$certificate_sha256 else NULL), auto_unbox = TRUE), "\n")
  }
}
run()
