#!/usr/bin/env Rscript
# Synthetic-only custodian harness. Analyst work uses the exported client API;
# provisioning/signing runs inside the existing isolated DSLite peer processes.
args <- commandArgs(trailingOnly = TRUE)
root <- normalizePath(if (length(args)) args[[1]] else "..")
n <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_N", "4"))
family <- Sys.getenv("DSVERT_GRID_VALIDATION_FAMILY", "binomial")
epsilon <- as.numeric(Sys.getenv("DSVERT_GRID_VALIDATION_EPSILON", "4"))
instance <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_INSTANCE", "1"))
instance_count <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_INSTANCE_COUNT", "1"))
oracle_only <- identical(Sys.getenv("DSVERT_GRID_VALIDATION_ORACLE_ONLY"), "1")
first_instance <- instance
real_count <- if (oracle_only) 0L else as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_REAL_COUNT", "2"))
predictors <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_P", "6"))
grid_size <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_GRID", "2"))
owner_count <- as.integer(Sys.getenv("DSVERT_GRID_VALIDATION_OWNERS", "2"))
stopifnot(n > 0, family %in% c("binomial", "poisson"), epsilon %in% c(1, 4, 8),
  owner_count %in% c(2L, 3L, 5L), predictors %in% c(6L, 10L),
  grid_size >= 2L, grid_size <= 50L)
server_dir <- file.path(root, "dsVert")
client_dir <- file.path(root, "dsVertClient")
source(file.path(client_dir, "inst/validation/v1.2.0/worked_example_custodian.R"))
pkgload::load_all(client_dir, quiet = TRUE)
cf <- function(name) get(name, asNamespace("dsVertClient"), inherits = FALSE)
state_parent <- file.path(client_dir, "inst/cross-grid-v2/build")
dir.create(state_parent, recursive = TRUE, showWarnings = FALSE, mode = "0700")
state <- tempfile("cross-grid-dslite-", tmpdir = state_parent)
dir.create(state, recursive = TRUE, mode = "0700")
peers <- list()
run <- function() {
  on.exit({we_close_peers(peers); unlink(state, recursive = TRUE)}, add = TRUE)
  set.seed(20260918 + instance)
  x <- matrix(runif(n * predictors), n, predictors)
  truth <- c(-0.5, 0.5, -0.25, 0.25, 0.5, -0.25, 0.25,
    rep(c(-0.25, 0.25), length.out = predictors - 6L))
  eta <- drop(cbind(1, x) %*% truth)
  maximum <- if (family == "binomial") 1 else 16
  y <- if (family == "binomial") rbinom(n, 1, plogis(eta)) else pmin(maximum, rpois(n, exp(eta)))
  ids <- sprintf("synthetic-%06d", seq_len(n))
  owner_names <- paste0("site_", letters[seq_len(owner_count)])
  allocation <- as.integer(cut(seq_len(predictors), breaks = owner_count, labels = FALSE))
  predictor_order <- paste0(owner_names[allocation], "$x", seq_len(predictors))
  raw <- stats::setNames(lapply(seq_len(owner_count), function(owner) {
    result <- data.frame(patient_id = ids)
    if (owner == 1L) result$y <- y
    for (j in which(allocation == owner)) result[[paste0("x", j)]] <- x[, j]
    result
  }), owner_names)
  specs <- lapply(owner_names, function(peer) {
    home <- file.path(state, peer)
    dir.create(home, mode = "0700")
    list(name = peer, state_dir = home, dslite_home = file.path(home, "dslite"),
      mpc_binary = file.path(server_dir, "inst/cross-grid-v2/build/dsvert-mpc"),
      dataset_id = "cross-grid-synthetic", dataset_version = "v1")
  })
  names(specs) <- names(raw)
  policies <- lapply(names(raw), function(peer) {
    variables <- setdiff(names(raw[[peer]]), "patient_id")
    bounds <- stats::setNames(lapply(variables, function(v) c(0, if (v == "y") maximum else 1)), variables)
    list(total_epsilon = epsilon, total_delta = 2^-100, domain = "cross-grid-v2-validation",
      cohort_id = "cross-grid-synthetic", adjacency = "add_remove_patient",
      patient_column = "patient_id", unit_capacity = n, numeric_grid_bits = 16L,
      max_records_per_unit = 1L, fixed_cohort_size = NULL, overflow_policy = "reject_snapshot",
      datasets = list(DA = list(id = specs[[peer]]$dataset_id, version = "v1")),
      workload_scope = list(mode = "catalog_v1", numeric_moments = character(),
        categorical_marginals = character(), categorical_pairs = list(), correlations = list()),
      designated_noise_peers = owner_names[1:2], numeric_bounds = bounds,
      capsule_dataset_mapping = list(DA = variables), gaussian_specs = list(),
      synopsis_state_path = file.path(specs[[peer]]$state_dir, "dp-synopsis"))
  })
  names(policies) <- names(raw)
  boot <- function(pins = NULL) stats::setNames(lapply(names(raw), function(peer)
    we_boot_peer(specs[[peer]], server_dir, if (is.null(pins)) NULL else pins[[peer]],
      raw[[peer]], policies[[peer]])), names(raw))
  peers <<- boot()
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
  peers <<- boot(pins)
  conns <- we_connections(peers)
  for (peer in peers) peer$worker$run(function(n) {
    options(dsvert.psi.max_input_ids = as.integer(2^ceiling(log2(max(64, n)))))
    TRUE
  }, args = list(n))
  ds.psiAlign("D", "patient_id", "DA", datasources = conns, verbose = FALSE)
  cat("DSLITE_ALIGNMENT_COMPLETE\n")
  for (instance in seq.int(instance, length.out = instance_count)) {
  bootstrap <- cf(".dsvert_dp_synopsis_bootstrap_build_v1")(conns)
  schema <- jsonlite::fromJSON(bootstrap$manifest_bundle$schema_json, simplifyVector = FALSE)
  all_pins <- stats::setNames(unname(unlist(identities)), names(raw))
  policy <- list(peer_pinset = all_pins,
    peer_pinset_sha256 = cf(".dsvert_dp_capsule_source_hash")(as.list(all_pins)),
    designated_noise_peers = owner_names[1:2], unit_capacity = n, numeric_grid_bits = 16,
    adjacency = "add_remove_patient")
  offsets <- if (grid_size == 2L) c(0, 0.25) else seq(-0.25, 0.25, length.out = grid_size)
  beta <- lapply(offsets, function(offset)
    truth + c(offset + (instance - 1) / 1024, rep(0, predictors)))
  beta <- beta[order(vapply(beta, function(b) cf(".dsvert_joint_dp_client_json")(as.list(b)), character(1)), method = "radix")]
  make_contract <- function(schema) {
    authenticated <- cf(".dsvert_dp_glm_grid_cross_schema_validate")(
      policy, schema$logical_snapshot, schema, cf(".dsvert_dp_glm_grid_cross_verify"))
    alignment <- list(version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "cross-grid-synthetic",
      public_alignment_contract_sha256 = cf(".dsvert_dp_capsule_source_hash")(list(
        logical_snapshot = schema$logical_snapshot, alignment_group = "cross-grid-synthetic",
        method = "pinned_psi_ordered_manifest_v1")), public_patient_dependent_hash = FALSE)
    raw_spec <- list(version = paste0(family, "_grid_cross_v1"), analysis_id = "grid",
      dataset = "DA", outcome = "site_a$y", predictor_order = predictor_order,
      beta_grid = beta, max_outcome = maximum, alignment = alignment)
    spec <- cf(".dsvert_dp_glm_grid_cross_spec")(raw_spec, policy, authenticated, "piecewise_v2")
    artifact <- cf(".dsvert_dp_glm_grid_cross_artifact")(spec)
    list(version = "dsvert-cross-owner-grid-signed-contract-v1", spec = spec,
      artifact = artifact, source_contract = cf(".dsvert_dp_glm_grid_cross_source_contract")(spec, artifact))
  }
  contract <- make_contract(schema)
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
    dsVert:::.dsvert_relay_sign_message(dsVert:::.dsvert_dp_glm_grid_cross_message(contract), identity$identity_sk)
  }, args = list(contract)))
  cf(".dsvert_dp_glm_grid_profile_admit")(contract, policy, schema)
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
  formula <- stats::as.formula(paste("site_a$y ~", paste(predictor_order, collapse = " + ")))
  invoke <- function() ds.vertGLM(formula, data = "DA", family = family,
    analysis_id = "grid", datasources = conns, verbose = FALSE)
  if (identical(Sys.getenv("DSVERT_GRID_VALIDATION_INTERRUPT"), "1")) {
    interrupted <- tryCatch(invoke(), error = identity)
    stopifnot(inherits(interrupted, "error"), all(unlist(lapply(
      peers[owner_names[1:2]], function(peer) peer$worker$run(function()
        get(".grid_interrupted", .GlobalEnv))))))
    cat("DSLITE_INTERRUPTED_AFTER_DURABLE_BATCHES\n")
  }
  elapsed <- system.time(fit <- tryCatch(ds.vertGLM(formula, data = "DA", family = family,
    analysis_id = "grid", datasources = conns, verbose = FALSE), error = function(error) {
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
  plan <- list(Family=family,Rows=min(32,n),Predictors=predictors,Owners=owner_count,
    A=spec$numeric_contract$profile_envelope,GridBits=16,MaxOutcome=maximum,
    Beta=spec$beta_encoded,Caps=lapply(spec$sensitivity$candidate_bounds,`[[`,"per_patient_cap"))
  input <- file.path(state,"synthetic-oracle-input.json")
  output <- file.path(state,"synthetic-oracle-output.json")
  values <- cbind(round(x*2^50),y)
  fixture <- list(Plan=plan,Rows=lapply(seq_len(n),function(i)as.list(sprintf("%.0f",values[i,]))),
    Draws=draws,Output=output)
  writeLines(jsonlite::toJSON(fixture,auto_unbox=TRUE,digits=NA,null="null"),input)
  oracle_run <- processx::run(file.path(server_dir,"inst/cross-grid-v2/build/cross-grid-oracle.test"),
    "-test.run=^TestCrossGridLayeredOracle$",env=c(DSVERT_CROSS_ORACLE_FIXTURE=input),
    error_on_status = FALSE)
  if (oracle_run$status != 0) cat(oracle_run$stdout, oracle_run$stderr)
  stopifnot(oracle_run$status==0)
  oracle <- jsonlite::fromJSON(output)
  if (real_release) {
  # Compare authenticated integers before converting the DP block to doubles.
  trace(".dsvert_dp_synopsis_client_replay", where = asNamespace("dsVertClient"),
    print = FALSE, exit = quote(assign(".grid_public_replay", returnValue(), .GlobalEnv)))
  checked <- ds.validateDPGaussianCertificate(fit$provenance_certificate)
  untrace(".dsvert_dp_synopsis_client_replay", where = asNamespace("dsVertClient"))
  observed <- get(".grid_public_replay", .GlobalEnv)$scaled
  if (!identical(unname(observed), unname(oracle$Released))) {
    saveRDS(list(observed = observed, oracle_released = oracle$Released,
      certificate = fit$provenance_certificate),
      file.path(server_dir, "inst/cross-grid-v2/build/public-release-mismatch.rds"))
  }
  stopifnot(identical(unname(observed), unname(oracle$Released)))
  stopifnot(fit$selected_candidate == which.min(as.numeric(oracle$Released[-1])))
  cat("DSLITE_ORACLE_BITWISE_EQUAL\n")
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
    selected_candidate = which.min(as.numeric(oracle$Released[-1])),
    exact_best = which.min(as.numeric(oracle$Exact)),
    loss_gap = (as.numeric(oracle$Exact[which.min(as.numeric(oracle$Released[-1]))]) -
      min(as.numeric(oracle$Exact))) / 2^16,
    artifact_key = planned$artifact_key,
    certificate_sha256 = if (real_release) fit$certificate_sha256 else NULL), auto_unbox = TRUE), "\n")
  }
}
run()
