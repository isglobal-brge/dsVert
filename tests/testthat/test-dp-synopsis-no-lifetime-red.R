.synopsis_no_lifetime_public_abi <- list(
  dsvertDPSynopsisBootstrapDS = NULL,
  dsvertDPSynopsisBindDS = "bootstrap_set_json",
  dsvertDPSynopsisPublicationDS = "manifest_sha256",
  dsvertDPSynopsisPublishedReplayDS = c(
    "artifact_key", "first_release_json", "second_release_json",
    "public_chunk_index"),
  dsvertDPSynopsisFinalizeAckDS = c(
    "manifest_sha256", "first_release_json", "second_release_json"))

.synopsis_no_lifetime_internal <- c(
  ".dsvert_dp_synopsis_policy_v1",
  ".dsvert_dp_synopsis_bootstrap_v1",
  ".dsvert_dp_synopsis_manifest_build_v1",
  ".dsvert_dp_synopsis_bind_v1",
  ".dsvert_dp_synopsis_publication_v1",
  ".dsvert_dp_synopsis_publication_replay_v1",
  ".dsvert_dp_synopsis_finalize_ack_v1")

.synopsis_no_lifetime_available <- function() {
  namespace <- asNamespace("dsVert")
  all(vapply(c(
    names(.synopsis_no_lifetime_public_abi),
    .synopsis_no_lifetime_internal), exists, logical(1L),
    envir = namespace, mode = "function", inherits = FALSE))
}

.synopsis_description_option_names <- function() {
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  values <- trimws(strsplit(
    description[1L, "Options"], ",", fixed = TRUE)[[1L]])
  sub("=.*$", "", values)
}

test_that("the installed profile does not advertise retired DP defaults", {
  options <- .synopsis_description_option_names()
  retired <- c(
    "default.dsvert.dp.epsilon", "default.dsvert.dp.delta",
    "default.dsvert.dp.implementation_delta",
    "default.dsvert.dp.total_epsilon",
    "default.dsvert.dp.total_delta",
    "default.dsvert.dp.ledger_path",
    "default.dsvert.dp.anchor_provider",
    "default.nfilter.glm", "default.nfilter.subset")
  expect_length(intersect(options, retired), 0L)
  expect_false(any(grepl(
    "^default\\.dsvert\\.dp\\.(noise|lifetime|ledger|anchor|quota|rate|catalog)",
    options, perl = TRUE)))
  expect_true(all(c(
    "datashield.privacyLevel", "default.nfilter.tab") %in% options))
})

test_that("retired profile defaults retain explicit safe fallbacks", {
  withr::local_options(list(
    dsvert.dp.epsilon = NULL,
    default.dsvert.dp.epsilon = NULL,
    dsvert.dp.delta = NULL,
    default.dsvert.dp.delta = NULL,
    dsvert.dp.implementation_delta = NULL,
    default.dsvert.dp.implementation_delta = NULL,
    dsvert.dp.frequency.epsilon = NULL,
    default.dsvert.dp.frequency.epsilon = NULL,
    dsvert.dp.frequency.delta = NULL,
    default.dsvert.dp.frequency.delta = NULL,
    dsvert.dp.frequency.implementation_delta = NULL,
    default.dsvert.dp.frequency.implementation_delta = NULL,
    nfilter.tab = NULL,
    default.nfilter.tab = NULL,
    nfilter.glm = NULL,
    default.nfilter.glm = NULL,
    nfilter.subset = NULL,
    default.nfilter.subset = NULL))

  expect_identical(.dsvert_dp_count_option_v1("epsilon", 1), 1)
  expect_identical(.dsvert_dp_count_option_v1("delta", 1e-6), 1e-6)
  expect_identical(
    .dsvert_dp_count_option_v1("implementation_delta", 1e-9), 1e-9)
  expect_identical(.dsvert_dp_frequency_surface_option_v1(
    "epsilon", 1), 1)
  expect_identical(.dsvert_dp_frequency_surface_option_v1(
    "delta", 1e-6), 1e-6)
  expect_identical(.dsvert_dp_frequency_surface_option_v1(
    "implementation_delta", 1e-9), 1e-9)
  expect_identical(.dsvert_dp_option("total_epsilon", 1), 1)
  expect_identical(.dsvert_dp_option(
    "total_delta", .DSVERT_DP_DEFAULT_CAPSULE_DELTA),
    .DSVERT_DP_DEFAULT_CAPSULE_DELTA)
  expect_identical(.dsvert_disclosure_settings(), list(
    nfilter.tab = 3, nfilter.glm = 0.33, nfilter.subset = 3,
    privacyLevel = 5))
})

.synopsis_no_lifetime_b64url <- function(value) {
  chartr("+/", "-_", gsub("=", "", gsub(
    "[\r\n]", "", jsonlite::base64_enc(value))))
}

.synopsis_no_lifetime_signer <- function(message, key) {
  .synopsis_no_lifetime_b64url(openssl::sha512(c(
    charToRaw(key), message)))
}

.synopsis_no_lifetime_verifier <- function(message, key, signature) {
  identical(signature, .synopsis_no_lifetime_signer(message, key))
}

.synopsis_no_lifetime_policies <- function(k) {
  peers <- paste0("peer_", letters[seq_len(k)])
  pins <- stats::setNames(vapply(seq_len(k), function(index) {
    .synopsis_no_lifetime_b64url(as.raw(
      ((seq_len(32L) + 41L * index) %% 256L)))
  }, character(1L)), peers)
  common <- list(
    schema_version = 1L,
    mechanism_version = "dsvert-dp-v7-contingency-unit-aggregation-1",
    policy_contract = .DSVERT_DP_SYNOPSIS_POLICY_CONTRACT,
    domain = "synopsis-test", cohort_id = "cohort-v1",
    logical_peers = peers,
    peer_pinset = pins,
    peer_pinset_sha256 = .dsvert_dp_synopsis_pinset_hash_v1(pins),
    peer_count = as.integer(k), designated_noise_peers = peers[1:2],
    global_total_epsilon = 1, global_total_delta = 1e-6,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 10L, fixed_cohort_size = NULL,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = 8L,
    noise_selection = list(version = "test-noise-selection-v1"),
    transcript_privacy = "test-only",
    snapshot_binding = "internal_test_bypass",
    alignment_binding = "internal_test_bypass",
    require_snapshot_digest = FALSE,
    require_alignment_manifest = FALSE,
    datasets = list(), categorical_levels = list(), numeric_bounds = list(),
    capsule_dataset_mapping = NULL,
    capsule_workload_scope = list(mode = "all_schema"),
    capsule_workload_specs = list(
      describe = list(), survival = list(), gaussian = list(),
      vertical_cross = list()),
    lock_timeout_ms = 30000L,
    state_private = TRUE)
  stats::setNames(lapply(peers, function(peer) c(common, list(
    peer_name = peer, own_identity_pk = unname(pins[[peer]]),
    synopsis_state_path = tempfile(paste0("synopsis-state-", peer, "-"))))),
  peers)
}

.synopsis_no_lifetime_json <- function(value) {
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value))
}

.synopsis_no_lifetime_noise_selector <- function(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
    objective) {
  list(
    selector = .DSVERT_DP_NOISE_SELECTOR,
    objective = objective,
    coordinate_count = as.integer(coordinate_count),
    winner = "laplace",
    laplace = list(available = TRUE, simultaneous_95_abs = 100),
    gaussian = list(available = FALSE, simultaneous_95_abs = 100))
}

test_that("K=2/3/5 local categorical selectors bind signed catalog metadata", {
  logical_snapshot <- list(
    logical_snapshot_id = "cohort-v1", version = "schema-v1-catalog",
    alignment_protocol_version = 1L)
  for (k in c(2L, 3L, 5L)) {
    policies <- .synopsis_no_lifetime_policies(k)
    policy <- policies[[1L]]
    policy$capsule_workload_scope <- list(
      mode = "catalog_v1", numeric_moments = character(),
      categorical_marginals = character(),
      categorical_pairs = list(c("disease", "exposure")),
      correlations = list())
    schema <- list(
      schema = list(
        version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
        logical_snapshot = logical_snapshot,
        peer_pinset_sha256 = policy$peer_pinset_sha256,
        datasets = list(cohort = list(
          dataset_id = "cohort", dataset_version = "v1",
          schema_version = "schema-v1", alignment_group = "cohort-v1",
          patient_keys = list(peer_a = "patient_id"),
          columns = list(
            disease = list(
              kind = "categorical", owner_peer = "peer_a",
              levels = c("no", "yes")),
            exposure = list(
              kind = "categorical", owner_peer = "peer_a",
              levels = c("no", "yes")))))),
      schema_sha256 = strrep("1", 64L),
      workload = list(version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION),
      workload_sha256 = strrep("2", 64L),
      logical_snapshot = logical_snapshot)
    request <- list(
      version = .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_REQUEST_VERSION,
      family = "categorical_pairs", dataset = "cohort",
      columns = c("exposure", "disease"), owner_peer = NULL)
    selected <- .dsvert_dp_synopsis_local_pair_resolve_v1(
      request, schema, policy)
    projected <- .dsvert_dp_synopsis_local_pair_project_v1(
      schema, selected, policy)
    expect_identical(names(projected$schema$datasets), "cohort")
    expect_identical(
      names(projected$schema$datasets$cohort$columns),
      c("disease", "exposure"))
    expect_identical(
      names(projected$schema$datasets$cohort$patient_keys), "peer_a")
    expect_identical(projected$workload,
      .dsvert_dp_canonical_query_value(c(
      list(version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION),
      stats::setNames(rep(list(list()), 4L),
                      c("describe", "survival", "gaussian",
                        "vertical_cross")))))
    reversed <- request
    reversed$columns <- rev(request$columns)
    expect_identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(reversed, schema, policy),
      selected, info = paste("K =", k))
    expect_identical(
      .dsvert_dp_synopsis_local_pair_selector_validate_v1(
        selected, schema, policy), selected)
    expect_identical(
      .dsvert_dp_synopsis_local_pair_scope_v1(selected)$categorical_pairs,
      list(c("disease", "exposure")))
    projected_context <- .dsvert_dp_synopsis_policy_context_v1(
      policy, .primitive_scope =
        .dsvert_dp_synopsis_local_pair_scope_v1(selected))
    expect_identical(selected$parent$policy_sha256,
                     .dsvert_joint_dp_hash(projected_context$common))
    expect_identical(selected$parent$schema_sha256,
                     projected$schema_sha256)
    expect_identical(selected$parent$workload_contract_sha256,
                     projected$workload_sha256)
    expect_identical(selected$parent$logical_snapshot,
                     projected$logical_snapshot)

    unrelated <- schema
    unrelated$schema$datasets$cohort$columns$stage <- list(
      kind = "categorical", owner_peer = "peer_a",
      levels = c("early", "late"))
    unrelated$schema$logical_snapshot$version <- "schema-v1-unrelated"
    unrelated$schema_sha256 <- strrep("3", 64L)
    unrelated$workload <- c(unrelated$workload, list(
      gaussian = list(unrelated = list(owner_peer = "peer_a"))))
    unrelated$workload_sha256 <- strrep("4", 64L)
    unrelated_policy <- policy
    unrelated_policy$capsule_workload_scope$categorical_pairs <- list(
      c("disease", "exposure"), c("disease", "stage"))
    unrelated_selected <- .dsvert_dp_synopsis_local_pair_resolve_v1(
      request, unrelated, unrelated_policy)
    expect_identical(unrelated_selected, selected,
                     info = paste("unrelated metadata K =", k))
    expect_identical(
      .dsvert_dp_synopsis_local_pair_project_v1(
        unrelated, unrelated_selected, unrelated_policy),
      projected, info = paste("unrelated projection K =", k))

    changed_levels <- schema
    changed_levels$schema$datasets$cohort$columns$disease$levels <-
      c("maybe", "no", "yes")
    expect_false(identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(
        request, changed_levels, policy), selected),
      info = paste("selected levels K =", k))
    changed_dp <- policy
    changed_dp$global_total_epsilon <- 2
    expect_false(identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(
        request, schema, changed_dp), selected),
      info = paste("DP policy K =", k))
    changed_snapshot <- schema
    changed_snapshot$schema$datasets$cohort$dataset_version <- "v2"
    expect_false(identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(
        request, changed_snapshot, policy), selected),
      info = paste("snapshot K =", k))
    changed_logical_snapshot <- schema
    changed_logical_snapshot$schema$logical_snapshot$
      alignment_protocol_version <- 2L
    expect_false(identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(
        request, changed_logical_snapshot, policy), selected),
      info = paste("logical snapshot K =", k))
    changed_pin_policy <- policy
    replacement_pin <- .synopsis_no_lifetime_b64url(as.raw(
      (seq_len(32L) + 173L + k) %% 256L))
    changed_peer <- names(changed_pin_policy$peer_pinset)[[k]]
    changed_pin_policy$peer_pinset[[changed_peer]] <- replacement_pin
    changed_pin_policy$peer_pinset_sha256 <-
      .dsvert_dp_synopsis_pinset_hash_v1(
        changed_pin_policy$peer_pinset)
    if (identical(changed_pin_policy$peer_name, changed_peer)) {
      changed_pin_policy$own_identity_pk <- replacement_pin
    }
    changed_pin_schema <- schema
    changed_pin_schema$schema$peer_pinset_sha256 <-
      changed_pin_policy$peer_pinset_sha256
    expect_false(identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(
        request, changed_pin_schema, changed_pin_policy), selected),
      info = paste("pinset K =", k))
    changed_owner <- schema
    changed_owner$schema$datasets$cohort$patient_keys <- list(
      peer_b = "patient_id")
    changed_owner$schema$datasets$cohort$columns$disease$owner_peer <-
      "peer_b"
    changed_owner$schema$datasets$cohort$columns$exposure$owner_peer <-
      "peer_b"
    expect_false(identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(
        request, changed_owner, policy), selected),
      info = paste("owner K =", k))
    changed_dataset <- schema
    names(changed_dataset$schema$datasets) <- "cohort2"
    changed_request <- request
    changed_request$dataset <- "cohort2"
    expect_false(identical(
      .dsvert_dp_synopsis_local_pair_resolve_v1(
        changed_request, changed_dataset, policy), selected),
      info = paste("dataset K =", k))

    unauthorized <- policy
    unauthorized$capsule_workload_scope$categorical_pairs <- list()
    expect_error(.dsvert_dp_synopsis_local_pair_resolve_v1(
      request, schema, unauthorized), "not in the signed catalog")
    cross <- schema
    cross$schema$datasets$cohort$patient_keys$peer_b <- "patient_id"
    cross$schema$datasets$cohort$columns$exposure$owner_peer <- "peer_b"
    expect_error(.dsvert_dp_synopsis_local_pair_resolve_v1(
      request, cross, policy), "missing or ambiguous")
    tampered <- selected
    tampered$parent$schema_sha256 <- strrep("9", 64L)
    expect_error(.dsvert_dp_synopsis_local_pair_selector_validate_v1(
      tampered, schema, policy), "detached")
  }
})

test_that(paste(
  "K=2/3/5 projected manifest cache ignores unrelated signed metadata"), {
  for (k in c(2L, 3L, 5L)) {
    policies <- .synopsis_no_lifetime_policies(k)
    peers <- names(policies)
    policy <- policies[[1L]]
    policy$global_total_delta <- 0
    policy$datasets <- list(cohort = list(
      id = "cohort", version = "v1",
      snapshot_sha256 = NULL, alignment_manifest_hash = NULL,
      alignment_manifest_version = 1L))
    policy$categorical_levels <- list(
      disease = c("no", "yes"), exposure = c("no", "yes"))
    policy$numeric_bounds <- list()
    policy$capsule_workload_scope <- list(
      mode = "catalog_v1", numeric_moments = character(),
      categorical_marginals = character(),
      categorical_pairs = list(c("disease", "exposure")),
      correlations = list())

    source_schema <- function(
        unrelated = FALSE, selected_levels = c("no", "yes"),
        owner = "peer_a", dataset = "cohort", dataset_id = dataset,
        dataset_version = "v1", alignment_version = 1L,
        pinset_sha256 = policy$peer_pinset_sha256) {
      columns <- list(
        disease = list(
          kind = "categorical", owner_peer = owner,
          levels = selected_levels),
        exposure = list(
          kind = "categorical", owner_peer = owner,
          levels = selected_levels))
      gaussian <- list()
      if (isTRUE(unrelated)) {
        columns$stage <- list(
          kind = "categorical", owner_peer = owner,
          levels = c("early", "late"))
        columns$gaussian_x <- list(
          kind = "numeric", owner_peer = owner, lower = 0, upper = 1)
        columns$gaussian_y <- list(
          kind = "numeric", owner_peer = owner, lower = 0, upper = 1)
        gaussian <- list(unrelated = list(
          owner_peer = owner, spec = list(
            version = "v1", dataset = dataset, outcome = "gaussian_y",
            predictors = c("gaussian_x"), intercept = TRUE)))
      }
      schema_value <- .dsvert_dp_canonical_query_value(list(
        version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
        logical_snapshot = list(
          logical_snapshot_id = "cohort-v1",
          version = if (isTRUE(unrelated)) {
            "schema-v1-with-unrelated-metadata"
          } else "schema-v1-selected-only",
          alignment_protocol_version = as.integer(alignment_version)),
        peer_pinset_sha256 = pinset_sha256,
        datasets = stats::setNames(list(list(
          dataset_id = dataset_id, dataset_version = dataset_version,
          schema_version = "schema-v1", alignment_group = "cohort-v1",
          patient_keys = stats::setNames(list("patient_id"), owner),
          columns = columns)), dataset)))
      workload <- .dsvert_dp_canonical_query_value(list(
        version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION,
        describe = list(), survival = list(), gaussian = gaussian,
        vertical_cross = list()))
      list(
        schema = schema_value,
        schema_sha256 = .dsvert_joint_dp_hash(schema_value),
        workload = workload,
        workload_sha256 = .dsvert_joint_dp_hash(workload),
        logical_snapshot = schema_value$logical_snapshot)
    }
    request <- list(
      version = .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_REQUEST_VERSION,
      family = "categorical_pairs", dataset = "cohort",
      columns = c("disease", "exposure"), owner_peer = NULL)
    build <- function(schema, current_policy, current_request = request) {
      selector <- .dsvert_dp_synopsis_local_pair_resolve_v1(
        current_request, schema, current_policy)
      projected <- .dsvert_dp_synopsis_local_pair_project_v1(
        schema, selector, current_policy)
      message <- .dsvert_dp_capsule_schema_message(projected$schema)
      signatures <- stats::setNames(lapply(peers, function(peer) {
        .synopsis_no_lifetime_signer(
          message, unname(current_policy$peer_pinset[[peer]]))
      }), peers)
      .dsvert_dp_synopsis_manifest_build_v1(
        c(projected$schema, list(signatures = signatures)),
        projected$workload, current_policy, as.raw(rep(91L, 32L)),
        local_projection = selector,
        .verifier = .synopsis_no_lifetime_verifier)
    }
    baseline <- testthat::with_mocked_bindings(
      build(source_schema(FALSE), policy),
      .dsvert_dp_noise_selection = .synopsis_no_lifetime_noise_selector,
      .package = "dsVert")

    unrelated_policy <- policy
    unrelated_policy$categorical_levels$stage <- c("early", "late")
    unrelated_policy$numeric_bounds$gaussian_x <- c(0, 1)
    unrelated_policy$numeric_bounds$gaussian_y <- c(0, 1)
    unrelated_policy$capsule_workload_scope$categorical_pairs <- list(
      c("disease", "exposure"), c("disease", "stage"))
    unrelated_policy$capsule_workload_specs$gaussian <- list(
      unrelated = list(
        version = "v1", dataset = "cohort", outcome = "gaussian_y",
        predictors = c("gaussian_x"), intercept = TRUE))
    unrelated <- testthat::with_mocked_bindings(
      build(source_schema(TRUE), unrelated_policy),
      .dsvert_dp_noise_selection = .synopsis_no_lifetime_noise_selector,
      .package = "dsVert")

    expect_identical(unrelated$record$cache_key,
                     baseline$record$cache_key, info = paste("K =", k))
    expect_identical(unrelated$record$manifest_sha256,
                     baseline$record$manifest_sha256,
                     info = paste("manifest K =", k))
    expect_identical(unrelated$record$public_capsule_key,
                     baseline$record$public_capsule_key,
                     info = paste("public capsule K =", k))
    expect_identical(unrelated$manifest$capsule_identity$capsule_id,
                     baseline$manifest$capsule_identity$capsule_id,
                     info = paste("artifact identity K =", k))
    expect_identical(unrelated$artifact_index,
                     baseline$artifact_index,
                     info = paste("artifact commitments K =", k))

    reverse_path <- tempfile(paste0("synopsis-projection-reverse-k", k, "-"))
    reverse_unrelated_policy <- unrelated_policy
    reverse_unrelated_policy$synopsis_state_path <- reverse_path
    reverse_baseline_policy <- policy
    reverse_baseline_policy$synopsis_state_path <- reverse_path
    reverse_unrelated <- testthat::with_mocked_bindings(
      build(source_schema(TRUE), reverse_unrelated_policy),
      .dsvert_dp_noise_selection = .synopsis_no_lifetime_noise_selector,
      .package = "dsVert")
    reverse_baseline <- testthat::with_mocked_bindings(
      build(source_schema(FALSE), reverse_baseline_policy),
      .dsvert_dp_noise_selection = .synopsis_no_lifetime_noise_selector,
      .package = "dsVert")
    expect_identical(reverse_baseline$record$manifest_sha256,
                     reverse_unrelated$record$manifest_sha256,
                     info = paste("removed metadata manifest K =", k))
    expect_identical(reverse_baseline$record$public_capsule_key,
                     reverse_unrelated$record$public_capsule_key,
                     info = paste("removed metadata artifact K =", k))
    expect_identical(reverse_baseline$artifact_index,
                     reverse_unrelated$artifact_index,
                     info = paste("removed metadata release K =", k))

    build_fresh <- function(schema, current_policy,
                            current_request = request) {
      current_policy$synopsis_state_path <- tempfile(paste0(
        "synopsis-projection-divergence-k", k, "-"))
      testthat::with_mocked_bindings(
        build(schema, current_policy, current_request),
        .dsvert_dp_noise_selection = .synopsis_no_lifetime_noise_selector,
        .package = "dsVert")
    }
    expect_divergent_release <- function(candidate, label) {
      expect_false(identical(
        candidate$record$manifest_sha256,
        baseline$record$manifest_sha256),
        info = paste(label, "manifest K =", k))
      expect_false(identical(
        candidate$record$public_capsule_key,
        baseline$record$public_capsule_key),
        info = paste(label, "artifact K =", k))
      expect_false(identical(
        candidate$artifact_index$root,
        baseline$artifact_index$root),
        info = paste(label, "release K =", k))
    }

    level_policy <- policy
    level_policy$categorical_levels$disease <- c("maybe", "no", "yes")
    level_policy$categorical_levels$exposure <- c("maybe", "no", "yes")
    expect_divergent_release(build_fresh(
      source_schema(selected_levels = c("maybe", "no", "yes")),
      level_policy), "selected levels")

    dp_policy <- policy
    dp_policy$global_total_epsilon <- 2
    expect_divergent_release(build_fresh(
      source_schema(), dp_policy), "DP")

    snapshot_policy <- policy
    snapshot_policy$datasets$cohort$alignment_manifest_version <- 2L
    expect_divergent_release(build_fresh(
      source_schema(alignment_version = 2L),
      snapshot_policy), "logical snapshot")

    expect_divergent_release(build_fresh(
      source_schema(owner = "peer_b"), policy), "selected owner")

    dataset_policy <- policy
    names(dataset_policy$datasets) <- "cohort2"
    dataset_policy$datasets$cohort2$id <- "cohort2"
    dataset_request <- request
    dataset_request$dataset <- "cohort2"
    expect_divergent_release(build_fresh(
      source_schema(dataset = "cohort2", dataset_id = "cohort2"),
      dataset_policy, dataset_request), "selected dataset")

    pin_policy <- policy
    changed_peer <- peers[[k]]
    pin_policy$peer_pinset[[changed_peer]] <-
      .synopsis_no_lifetime_b64url(as.raw(
        (seq_len(32L) + 211L + k) %% 256L))
    pin_policy$peer_pinset_sha256 <-
      .dsvert_dp_synopsis_pinset_hash_v1(pin_policy$peer_pinset)
    if (identical(pin_policy$peer_name, changed_peer)) {
      pin_policy$own_identity_pk <- unname(
        pin_policy$peer_pinset[[changed_peer]])
    }
    expect_divergent_release(build_fresh(
      source_schema(pinset_sha256 = pin_policy$peer_pinset_sha256),
      pin_policy), "trusted pins")
  }
})

test_that("the synopsis no-lifetime surface has one closed ABI", {
  namespace <- asNamespace("dsVert")
  expected <- c(
    stats::setNames(.synopsis_no_lifetime_public_abi,
                    names(.synopsis_no_lifetime_public_abi)),
    stats::setNames(rep(list("<internal>"),
                        length(.synopsis_no_lifetime_internal)),
                    .synopsis_no_lifetime_internal))
  observed <- lapply(names(expected), function(name) {
    if (!exists(name, namespace, mode = "function", inherits = FALSE)) {
      return("<missing>")
    }
    if (identical(expected[[name]], "<internal>")) return("<internal>")
    names(formals(get(name, namespace, inherits = FALSE)))
  })
  names(observed) <- names(expected)
  expect_identical(observed, expected)
})

test_that("bootstrap and binding are independent of lifetime machinery", {
  skip_if_not(.synopsis_no_lifetime_available(),
              "RED: dedicated synopsis lifecycle is absent")
  namespace <- asNamespace("dsVert")
  functions <- lapply(c(
    "dsvertDPSynopsisBootstrapDS", "dsvertDPSynopsisBindDS",
    ".dsvert_dp_policy_core_v1", ".dsvert_dp_synopsis_policy_v1",
    ".dsvert_dp_synopsis_bootstrap_v1",
    ".dsvert_dp_synopsis_manifest_build_v1",
    ".dsvert_dp_synopsis_bind_v1"), get, envir = namespace, inherits = FALSE)
  globals <- unique(unlist(lapply(functions, function(value) {
    codetools::findGlobals(value, merge = FALSE)$functions
  }), use.names = FALSE))
  body_text <- paste(vapply(functions, function(value) {
    paste(deparse(body(value)), collapse = "\n")
  }, character(1L)), collapse = "\n")
  forbidden <- c(
    ".dsvert_dp_policy", ".dsvert_dp_policy_build",
    ".dsvert_joint_dp_open_ledger", ".dsvert_capsule_registry_with",
    ".dsvert_dp_capsule_manifest_cache_with",
    ".dsvert_dp_capsule_manifest_build_impl",
    ".dsvert_joint_dp_allocator_full_audit",
    ".dsvert_dp_resolve_snapshot", ".resolveData",
    ".dsvert_dp_dataset_binding", ".dsvert_dp_admit_units",
    ".dsvert_dp_synopsis_source_vector_claim_v1")
  expect_length(intersect(globals, forbidden), 0L)
  expect_false(grepl(
    "lifetime_max_distinct|lifetime_(epsilon|delta)|history_can_deny",
    body_text, perl = TRUE))
  bootstrap <- get(
    ".dsvert_dp_synopsis_bootstrap_v1", namespace, inherits = FALSE)
  bind <- get(".dsvert_dp_synopsis_bind_v1", namespace, inherits = FALSE)
  expect_identical(formals(bootstrap)$.signer,
                   quote(.dsvert_relay_sign_message))
  expect_identical(formals(bind)$.verifier,
                   quote(.dsvert_relay_verify_message))
  expect_identical(formals(bind)$.signer,
                   quote(.dsvert_relay_sign_message))
})

test_that("K=2/3/5 bootstrap and Bind require the pinned exact-K set", {
  for (k in c(2L, 3L, 5L)) {
    policies <- .synopsis_no_lifetime_policies(k)
    peers <- names(policies)
    pins <- policies[[1L]]$peer_pinset
    schema <- list(
      schema = list(version = "test-schema-v1"),
      schema_sha256 = strrep("1", 64L),
      workload = list(version = "test-workload-v1"),
      workload_sha256 = strrep("2", 64L),
      logical_snapshot = list(
        logical_snapshot_id = "snapshot", version = "v1",
        alignment_protocol_version = 1L))
    built <- list(
      record = list(manifest_sha256 = strrep("3", 64L),
                    manifest_json = "{}"),
      manifest = list(capsule_identity = list(
        capsule_id = strrep("4", 64L))),
      artifact_index = list(
        count = 0, root = strrep("5", 64L),
        value = list(version = "empty-index-v1")))
    testthat::with_mocked_bindings({
      bootstraps <- lapply(peers, function(peer) {
        policy <- policies[[peer]]
        .dsvert_dp_synopsis_bootstrap_v1(
          .policy = policy,
          .identity = list(
            identity_pk = unname(pins[[peer]]),
            identity_sk = unname(pins[[peer]])),
          .signer = .synopsis_no_lifetime_signer)
      })
      names(bootstraps) <- peers
      expect_named(.dsvert_dp_synopsis_bootstrap_set_v1(
        bootstraps, policies[[1L]], .synopsis_no_lifetime_verifier),
        peers, ignore.order = FALSE)
      expect_error(.dsvert_dp_synopsis_bootstrap_set_v1(
        bootstraps[-k], policies[[1L]],
        .synopsis_no_lifetime_verifier), "coverage")

      signature_request <- .synopsis_no_lifetime_json(list(
        version = .DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION,
        phase = "schema_signature", bootstraps = bootstraps,
        schema_signatures = NULL))
      local <- policies[[1L]]
      identity <- list(
        identity_pk = unname(pins[[1L]]),
        identity_sk = unname(pins[[1L]]))
      signed_schema <- .dsvert_dp_synopsis_bind_v1(
        signature_request, .policy = local, .secret = as.raw(rep(1L, 32L)),
        .identity = identity, .signer = .synopsis_no_lifetime_signer,
        .verifier = .synopsis_no_lifetime_verifier)
      expect_identical(signed_schema$phase, "global_schema_verified")

      message <- .dsvert_dp_capsule_schema_message(schema$schema)
      signatures <- stats::setNames(lapply(peers, function(peer) {
        .synopsis_no_lifetime_signer(message, unname(pins[[peer]]))
      }), peers)
      manifest_request <- function(value) .synopsis_no_lifetime_json(list(
        version = .DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION,
        phase = "manifest_build", bootstraps = bootstraps,
        schema_signatures = value))
      bound <- .dsvert_dp_synopsis_bind_v1(
        manifest_request(signatures), .policy = local,
        .secret = as.raw(rep(1L, 32L)), .identity = identity,
        .signer = .synopsis_no_lifetime_signer,
        .verifier = .synopsis_no_lifetime_verifier)
      expect_identical(bound$manifest_sha256, strrep("3", 64L))
      expect_identical(bound$privacy_scope,
                       "per_canonical_artifact_v1")
      expect_identical(bound$global_composition_claim, FALSE)
      expect_error(.dsvert_dp_synopsis_bind_v1(
        manifest_request(signatures[-k]), .policy = local,
        .secret = as.raw(rep(1L, 32L)), .identity = identity,
        .signer = .synopsis_no_lifetime_signer,
        .verifier = .synopsis_no_lifetime_verifier), "one schema signature")
      tampered <- signatures
      tampered[[k]] <- .synopsis_no_lifetime_signer(
        charToRaw("different schema"), unname(pins[[k]]))
      expect_error(.dsvert_dp_synopsis_bind_v1(
        manifest_request(tampered), .policy = local,
        .secret = as.raw(rep(1L, 32L)), .identity = identity,
        .signer = .synopsis_no_lifetime_signer,
        .verifier = .synopsis_no_lifetime_verifier), "signatures are invalid")
    },
    .dsvert_dp_capsule_manifest_draft_unsigned = function(...) {
      list(version = "custodian-test-draft-v1")
    },
    .dsvert_dp_synopsis_manifest_schema_v1 = function(...) schema,
    .dsvert_dp_synopsis_manifest_build_v1 = function(...) built,
    .package = "dsVert")
  }
})

test_that("K=2/3/5 bootstrap and Bind survive restart with real Ed25519", {
  schema <- list(
    schema = list(version = "real-ed25519-schema-v1"),
    schema_sha256 = strrep("1", 64L),
    workload = list(version = "real-ed25519-workload-v1"),
    workload_sha256 = strrep("2", 64L),
    logical_snapshot = list(
      logical_snapshot_id = "real-ed25519-snapshot", version = "v1",
      alignment_protocol_version = 1L))
  built <- list(
    record = list(manifest_sha256 = strrep("3", 64L),
                  manifest_json = "{}"),
    manifest = list(capsule_identity = list(capsule_id = strrep("4", 64L))),
    artifact_index = list(
      count = 0, root = strrep("5", 64L),
      value = list(version = "empty-index-v1")))

  for (k in c(2L, 3L, 5L)) {
    policies <- .synopsis_no_lifetime_policies(k)
    peers <- names(policies)
    identities <- stats::setNames(lapply(seq_len(k), function(index) {
      .callMpcTool("derive-identity", list(seed = jsonlite::base64_enc(
        as.raw((seq_len(32L) + 61L * index + k) %% 256L))))
    }), peers)
    pins <- stats::setNames(vapply(identities, function(identity) {
      .dsvert_relay_normalize_identity_pk(identity$identity_pk)
    }, character(1L)), peers)
    pinset_sha256 <- .dsvert_dp_synopsis_pinset_hash_v1(pins)
    policies <- stats::setNames(lapply(peers, function(peer) {
      policy <- policies[[peer]]
      policy$peer_pinset <- pins
      policy$peer_pinset_sha256 <- pinset_sha256
      policy$own_identity_pk <- unname(pins[[peer]])
      policy
    }), peers)

    testthat::with_mocked_bindings({
      bootstraps <- stats::setNames(lapply(peers, function(peer) {
        .dsvert_dp_synopsis_bootstrap_v1(
          .policy = policies[[peer]], .identity = identities[[peer]])
      }), peers)
      bootstraps <- jsonlite::fromJSON(
        .synopsis_no_lifetime_json(bootstraps), simplifyVector = FALSE)
      expect_named(.dsvert_dp_synopsis_bootstrap_set_v1(
        bootstraps, policies[[1L]]), peers, ignore.order = FALSE)

      tampered <- bootstraps
      tampered[[k]]$policy$artifact_epsilon <- 2
      expect_error(.dsvert_dp_synopsis_bootstrap_set_v1(
        tampered, policies[[1L]]), "bootstrap")

      schema_message <- .dsvert_dp_capsule_schema_message(schema$schema)
      schema_signatures <- stats::setNames(lapply(peers, function(peer) {
        .dsvert_relay_sign_message(
          schema_message, identities[[peer]]$identity_sk)
      }), peers)
      request <- .synopsis_no_lifetime_json(list(
        version = .DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION,
        phase = "manifest_build", bootstraps = bootstraps,
        schema_signatures = schema_signatures))
      bound <- .dsvert_dp_synopsis_bind_v1(
        request, .policy = policies[[1L]],
        .secret = as.raw(rep(1L, 32L)), .identity = identities[[1L]])
      expect_identical(bound$manifest_sha256, strrep("3", 64L))
      expect_true(.dsvert_relay_verify_message(
        .dsvert_dp_synopsis_bind_message_v1(bound),
        identities[[1L]]$identity_pk, bound$signature))

      changed <- schema_signatures
      changed[[k]] <- .dsvert_relay_sign_message(
        charToRaw("different schema"), identities[[k]]$identity_sk)
      changed_request <- .synopsis_no_lifetime_json(list(
        version = .DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION,
        phase = "manifest_build", bootstraps = bootstraps,
        schema_signatures = changed))
      expect_error(.dsvert_dp_synopsis_bind_v1(
        changed_request, .policy = policies[[1L]],
        .secret = as.raw(rep(1L, 32L)), .identity = identities[[1L]]),
        "signatures are invalid")
    },
    .dsvert_dp_capsule_manifest_draft_unsigned = function(...) {
      list(version = "custodian-test-draft-v1")
    },
    .dsvert_dp_synopsis_manifest_schema_v1 = function(...) schema,
    .dsvert_dp_synopsis_manifest_build_v1 = function(...) built,
    .package = "dsVert")
  }
})

test_that("real Ed25519 categorical Bind is wire-safe for K=2/3/5", {
  draft <- function(policy) {
    peer <- policy$peer_name
    data_name <- paste0("data_", peer)
    column_name <- paste0("group_", peer)
    datasets <- stats::setNames(list(list(
      dataset_id = data_name, dataset_version = "v1",
      schema_version = .DSVERT_DP_CAPSULE_MANIFEST_SCHEMA_VERSION,
      alignment_group = policy$cohort_id,
      alignment_protocol_version = 1L,
      patient_column = policy$patient_column,
      columns = stats::setNames(list(list(
        kind = "categorical", owner_peer = peer,
        levels = c("case", "control"))), column_name))), data_name)
    list(
      version = .DSVERT_DP_CAPSULE_MANIFEST_DRAFT_VERSION,
      phase = "custodian_policy_draft", peer_name = peer,
      peer_identity_pk = unname(policy$peer_pinset[[peer]]),
      peer_pinset_sha256 = policy$peer_pinset_sha256,
      domain = policy$domain, cohort_id = policy$cohort_id,
      dataset_mapping_mode = "automatic_single_local_dataset",
      datasets = datasets,
      workload_fragments = list(
        describe = list(), survival = list(), gaussian = list(),
        vertical_cross = list()),
      data_access = FALSE, patient_derived_metadata = FALSE,
      operation_limit = FALSE, request_limit = FALSE,
      history_can_deny_operation = FALSE)
  }
  built <- list(
    record = list(manifest_sha256 = strrep("3", 64L),
                  manifest_json = "{}"),
    manifest = list(capsule_identity = list(capsule_id = strrep("4", 64L))),
    artifact_index = list(
      count = 0, root = strrep("5", 64L),
      value = list(version = "empty-index-v1")))

  for (k in c(2L, 3L, 5L)) {
    policies <- .synopsis_no_lifetime_policies(k)
    peers <- names(policies)
    identities <- stats::setNames(lapply(seq_len(k), function(index) {
      .callMpcTool("derive-identity", list(seed = jsonlite::base64_enc(
        as.raw((seq_len(32L) + 71L * index + k) %% 256L))))
    }), peers)
    pins <- stats::setNames(vapply(identities, function(identity) {
      .dsvert_relay_normalize_identity_pk(identity$identity_pk)
    }, character(1L)), peers)
    pinset_sha256 <- .dsvert_dp_synopsis_pinset_hash_v1(pins)
    policies <- stats::setNames(lapply(peers, function(peer) {
      policy <- policies[[peer]]
      policy$logical_peers <- peers
      policy$peer_pinset <- pins
      policy$peer_pinset_sha256 <- pinset_sha256
      policy$own_identity_pk <- unname(pins[[peer]])
      policy$datasets <- list(
        local = list(alignment_manifest_version = 1L))
      policy
    }), peers)

    testthat::with_mocked_bindings({
      bootstraps <- stats::setNames(lapply(peers, function(peer) {
        .dsvert_dp_synopsis_bootstrap_v1(
          .policy = policies[[peer]], .identity = identities[[peer]])
      }), peers)
      bootstraps <- jsonlite::fromJSON(
        .synopsis_no_lifetime_json(bootstraps), simplifyVector = FALSE)
      verified <- .dsvert_dp_synopsis_bootstrap_set_v1(
        bootstraps, policies[[1L]])
      schema <- .dsvert_dp_synopsis_manifest_schema_v1(
        verified, policies[[1L]])
      columns <- unlist(lapply(schema$schema$datasets, function(dataset) {
        dataset$columns
      }), recursive = FALSE)
      expect_true(all(vapply(columns, function(column) {
        identical(column$levels, c("case", "control"))
      }, logical(1L))), info = paste("categorical wire K", k))

      signature_request <- .synopsis_no_lifetime_json(list(
        version = .DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION,
        phase = "schema_signature", bootstraps = bootstraps,
        schema_signatures = NULL))
      signed <- .dsvert_dp_synopsis_bind_v1(
        signature_request, .policy = policies[[1L]],
        .secret = as.raw(rep(1L, 32L)), .identity = identities[[1L]])
      expect_identical(signed$schema_sha256, schema$schema_sha256)
      expect_true(.dsvert_relay_verify_message(
        .dsvert_dp_synopsis_bind_message_v1(signed),
        identities[[1L]]$identity_pk, signed$signature))

      schema_message <- .dsvert_dp_capsule_schema_message(schema$schema)
      schema_signatures <- stats::setNames(lapply(peers, function(peer) {
        .dsvert_relay_sign_message(
          schema_message, identities[[peer]]$identity_sk)
      }), peers)
      manifest_request <- .synopsis_no_lifetime_json(list(
        version = .DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION,
        phase = "manifest_build", bootstraps = bootstraps,
        schema_signatures = schema_signatures))
      bound <- .dsvert_dp_synopsis_bind_v1(
        manifest_request, .policy = policies[[1L]],
        .secret = as.raw(rep(1L, 32L)), .identity = identities[[1L]])
      expect_identical(bound$manifest_sha256, strrep("3", 64L))

      malformed <- verified
      dataset_name <- names(malformed[[k]]$draft$datasets)[[1L]]
      column_name <- names(
        malformed[[k]]$draft$datasets[[dataset_name]]$columns)[[1L]]
      malformed[[k]]$draft$datasets[[dataset_name]]$columns[[
        column_name]]$levels <- list("case", list("control"))
      expect_error(.dsvert_dp_synopsis_manifest_schema_v1(
        malformed, policies[[1L]]), "categorical domain")
      duplicated <- verified
      duplicated[[k]]$draft$datasets[[dataset_name]]$columns[[
        column_name]]$levels <- list("case", "case")
      expect_error(.dsvert_dp_synopsis_manifest_schema_v1(
        duplicated, policies[[1L]]), "categorical domain")
    }, .dsvert_dp_capsule_manifest_draft_unsigned = draft,
    .dsvert_dp_synopsis_manifest_build_v1 = function(...) built,
    .package = "dsVert")
  }
})

test_that("PUBLICATION and published REPLAY are durable-only and session-free", {
  skip_if_not(.synopsis_no_lifetime_available(),
              "RED: dedicated synopsis lifecycle is absent")
  namespace <- asNamespace("dsVert")
  functions <- lapply(c(
    "dsvertDPSynopsisPublicationDS", "dsvertDPSynopsisPublishedReplayDS",
    ".dsvert_dp_synopsis_publication_v1",
    ".dsvert_dp_synopsis_publication_replay_v1"),
    get, envir = namespace, inherits = FALSE)
  globals <- unique(unlist(lapply(functions, function(value) {
    codetools::findGlobals(value, merge = FALSE)$functions
  }), use.names = FALSE))
  forbidden <- c(
    ".S", ".session_storage", ".dsvert_dp_resolve_snapshot",
    ".dsvert_dp_synopsis_local_claim_v1",
    ".dsvert_dp_synopsis_local_compile_v1",
    ".dsvert_dp_synopsis_source_transport_ticket_v1",
    ".dsvert_dp_synopsis_source_transport_prepare_v1",
    ".dsvert_dp_synopsis_source_transport_chunk_v1",
    ".dsvert_dp_capsule_source_reserve", ".dsvert_resource_backpressure")
  expect_length(intersect(globals, forbidden), 0L)
  expect_false(any(vapply(functions, function(value) {
    "session_id" %in% names(formals(value))
  }, logical(1L))))
})

test_that("one manifest has one immutable compiled artifact", {
  policy <- .synopsis_no_lifetime_policies(3L)[[1L]]
  secret <- as.raw(rep(31L, 32L))
  path <- paste0(policy$synopsis_state_path, ".manifest-v1.sqlite")
  withr::defer(unlink(c(
    path, paste0(path, ".lock"), paste0(path, "-wal"),
    paste0(path, "-shm")), force = TRUE))
  manifest_sha256 <- strrep("a", 64L)
  first <- list(artifact_key = strrep("b", 64L), payload = "first")
  replay <- .dsvert_dp_synopsis_compilation_register_v1(
    manifest_sha256, first, list(peer = "peer_a"), policy, secret)
  expect_identical(.dsvert_dp_synopsis_compilation_register_v1(
    manifest_sha256, first, list(peer = "peer_a"), policy, secret),
    replay)
  second <- list(artifact_key = strrep("c", 64L), payload = "second")
  expect_error(.dsvert_dp_synopsis_compilation_register_v1(
    manifest_sha256, second, list(peer = "peer_a"), policy, secret),
    "rotate its custodian snapshot version")
})

test_that("Synopsis artifact indexes declare sticky per-artifact privacy", {
  policy <- .synopsis_no_lifetime_policies(3L)[[1L]]
  manifest <- list(
    capsule_identity = list(
      capsule_id = strrep("1", 64L),
      contract = list(
        consortium_id = "dpsc1_test",
        policy_contract_hash = strrep("2", 64L))),
    logical_snapshot = list(version = "v1"),
    capsule_schema = "synopsis-test-v1",
    admission = list(version = "admission-v1"),
    bounds = list(version = "bounds-v1"),
    workload = list(
      release_lattice = list(version = "release-lattice-v1"),
      capsule_mechanism = list(version = "mechanism-v1"),
      mechanism_selection = list(version = "selection-v1")))
  build <- function(value) testthat::with_mocked_bindings(
    .dsvert_dp_capsule_artifact_commitment_index(
      manifest, value, strrep("3", 64L)),
    .dsvert_dp_capsule_coordinate_layout = function(...) list(
      version = "empty-layout-v1", coordinate_count = 0,
      sha256 = strrep("4", 64L), blocks = list()),
    .package = "dsVert")

  synopsis <- build(policy)
  expect_identical(
    synopsis$value$context$privacy_epoch_scope,
    "per_canonical_artifact_sticky_v1")
  legacy <- policy
  legacy$policy_contract <- "biomedical_dp_policy_v1"
  expect_identical(
    build(legacy)$value$context$privacy_epoch_scope,
    "per_peer_signed_receipts_v1")
})

test_that("warm replay loads its authenticated policy snapshot, not config", {
  policy <- .synopsis_no_lifetime_policies(3L)[[2L]]
  secret <- as.raw(rep(43L, 32L))
  path <- paste0(policy$synopsis_state_path, ".manifest-v1.sqlite")
  withr::defer(unlink(c(
    path, paste0(path, ".lock"), paste0(path, "-wal"),
    paste0(path, "-shm")), force = TRUE))
  manifest_json <- .synopsis_no_lifetime_json(list(version = "test-v1"))
  manifest_sha256 <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  draft <- function(policy) list(peer_name = policy$peer_name)
  record <- testthat::with_mocked_bindings({
    local <- .dsvert_dp_synopsis_manifest_local_authority_v1(
      policy, secret)
    .dsvert_dp_synopsis_manifest_cache_put_v1(
      policy, secret, list(
        version = .DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION,
        cache_key = strrep("1", 64L),
        public_capsule_key = strrep("2", 64L),
        local_authority_sha256 = local,
        schema_sha256 = strrep("3", 64L),
        workload_contract_sha256 = strrep("4", 64L),
        manifest_sha256 = manifest_sha256,
        manifest_json = manifest_json,
        policy_snapshot = .dsvert_dp_synopsis_policy_snapshot_v1(policy)))
  }, .dsvert_dp_capsule_manifest_draft_unsigned = draft,
  .package = "dsVert")
  decoded_snapshot <- .dsvert_dp_synopsis_policy_snapshot_validate_v1(
    record$policy_snapshot, policy$synopsis_state_path)
  expect_identical(decoded_snapshot$policy$peer_name, "peer_b")
  restored <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_policy_for_manifest_v1(
      manifest_sha256, secret, state_path = policy$synopsis_state_path),
    .dsvert_dp_capsule_manifest_draft_unsigned = draft,
    .dsvert_dp_policy_core_v1 = function(...) {
      stop("current policy reached", call. = FALSE)
    },
    .dsvert_dp_alignment_registry_resolve_templates = function(...) {
      stop("current alignment registry reached", call. = FALSE)
    }, .package = "dsVert")
  expect_identical(
    .dsvert_dp_canonical_json(
      .dsvert_dp_synopsis_policy_snapshot_v1(restored)),
    .dsvert_dp_canonical_json(
      .dsvert_dp_synopsis_policy_snapshot_v1(policy)))
  expect_identical(testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_cached_manifest_v1(
      manifest_sha256, restored, secret),
    .dsvert_dp_capsule_manifest_draft_unsigned = draft,
    .package = "dsVert"), manifest_json)
  expect_length(intersect(names(restored), c(
    "lifetime_max_distinct_capsules", "ledger_path", "noise_root")), 0L)

  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "UPDATE synopsis_manifest_meta SET row_mac=?",
    "WHERE key='schema_version'"), params = list(strrep("0", 64L)))
  DBI::dbDisconnect(connection)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_policy_for_manifest_v1(
      manifest_sha256, secret, state_path = policy$synopsis_state_path),
    .dsvert_dp_capsule_manifest_draft_unsigned = draft,
    .package = "dsVert"), "metadata failed authentication")
})

test_that("public synopsis stores are absent without read-side creation", {
  policy <- .synopsis_no_lifetime_policies(2L)[[1L]]
  secret <- as.raw(rep(59L, 32L))
  manifest <- paste0(policy$synopsis_state_path, ".manifest-v1.sqlite")
  execution <- paste0(
    policy$synopsis_state_path, ".synopsis-execution-v1.sqlite")
  paths <- unlist(lapply(c(manifest, execution), function(path) c(
    path, paste0(path, ".lock"), paste0(path, "-wal"),
    paste0(path, "-shm"), paste0(path, "-journal"))))
  withr::defer(unlink(paths, force = TRUE))

  policy_miss <- tryCatch(
    .dsvert_dp_synopsis_policy_for_manifest_v1(
      strrep("a", 64L), secret,
      state_path = policy$synopsis_state_path),
    error = identity)
  expect_s3_class(policy_miss, "dsvert_phase_not_ready")
  publication_miss <- tryCatch(
    .dsvert_dp_synopsis_publication_v1(
      strrep("a", 64L), .policy = policy, .secret = secret),
    error = identity)
  expect_s3_class(publication_miss, "dsvert_phase_not_ready")
  execution_miss <- tryCatch(
    .dsvert_dp_synopsis_execution_with_store_readonly_v1(
      policy, secret, function(connection) TRUE),
    error = identity)
  expect_s3_class(execution_miss, "dsvert_phase_not_ready")
  expect_false(any(file.exists(paths)))

  expect_true(file.create(paste0(manifest, ".lock")))
  Sys.chmod(paste0(manifest, ".lock"), mode = "0600")
  orphan <- tryCatch(
    .dsvert_dp_synopsis_policy_for_manifest_v1(
      strrep("a", 64L), secret,
      state_path = policy$synopsis_state_path),
    error = identity)
  expect_false(inherits(orphan, "dsvert_phase_not_ready"))
  expect_match(conditionMessage(orphan), "orphaned SQLite sidecars")
  expect_false(file.exists(manifest))
})

test_that("public synopsis reads ignore writer file locks and do not mutate stores", {
  policy <- .synopsis_no_lifetime_policies(2L)[[1L]]
  secret <- as.raw(rep(61L, 32L))
  manifest_path <- paste0(
    policy$synopsis_state_path, ".manifest-v1.sqlite")
  execution_path <- paste0(
    policy$synopsis_state_path, ".synopsis-execution-v1.sqlite")
  paths <- unlist(lapply(c(manifest_path, execution_path), function(path) c(
    path, paste0(path, ".lock"), paste0(path, "-wal"),
    paste0(path, "-shm"), paste0(path, "-journal"))))
  withr::defer(unlink(paths, force = TRUE))
  manifest_json <- .synopsis_no_lifetime_json(list(version = "test-v1"))
  manifest_sha256 <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  draft <- function(policy) list(peer_name = policy$peer_name)
  record <- testthat::with_mocked_bindings({
    local <- .dsvert_dp_synopsis_manifest_local_authority_v1(
      policy, secret)
    .dsvert_dp_synopsis_manifest_cache_put_v1(
      policy, secret, list(
        version = .DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION,
        cache_key = strrep("1", 64L),
        public_capsule_key = strrep("2", 64L),
        local_authority_sha256 = local,
        schema_sha256 = strrep("3", 64L),
        workload_contract_sha256 = strrep("4", 64L),
        manifest_sha256 = manifest_sha256,
        manifest_json = manifest_json,
        policy_snapshot = .dsvert_dp_synopsis_policy_snapshot_v1(policy)))
  }, .dsvert_dp_capsule_manifest_draft_unsigned = draft,
  .package = "dsVert")
  expect_identical(record$manifest_sha256, manifest_sha256)
  expect_true(.dsvert_dp_synopsis_execution_with_store_v1(
    policy, secret, function(connection) TRUE))

  connect_writer <- function(path) DBI::dbConnect(
    RSQLite::SQLite(), path, synchronous = NULL,
    loadable.extensions = FALSE, default.extensions = FALSE)
  manifest_writer <- connect_writer(manifest_path)
  execution_writer <- connect_writer(execution_path)
  withr::defer(DBI::dbDisconnect(manifest_writer))
  withr::defer(DBI::dbDisconnect(execution_writer))
  DBI::dbExecute(manifest_writer, "BEGIN IMMEDIATE")
  DBI::dbExecute(execution_writer, "BEGIN IMMEDIATE")
  withr::defer(try(DBI::dbRollback(manifest_writer), silent = TRUE))
  withr::defer(try(DBI::dbRollback(execution_writer), silent = TRUE))
  manifest_lock <- filelock::lock(
    paste0(manifest_path, ".lock"), timeout = 0)
  execution_lock <- filelock::lock(
    paste0(execution_path, ".lock"), timeout = 0)
  expect_false(is.null(manifest_lock))
  expect_false(is.null(execution_lock))
  withr::defer(filelock::unlock(manifest_lock))
  withr::defer(filelock::unlock(execution_lock))

  immutable_paths <- c(
    manifest_path, paste0(manifest_path, "-wal"),
    paste0(manifest_path, ".lock"), execution_path,
    paste0(execution_path, "-wal"), paste0(execution_path, ".lock"))
  immutable_paths <- immutable_paths[file.exists(immutable_paths)]
  stamp <- function(value) {
    info <- file.info(value)
    list(
      paths = value, size = unname(info$size),
      mtime = unname(as.numeric(info$mtime)),
      sha256 = unname(vapply(value, function(path) digest::digest(
        path, algo = "sha256", serialize = FALSE, file = TRUE),
        character(1L))))
  }
  before <- stamp(immutable_paths)
  existing_before <- file.exists(paths)
  observed <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_manifest_cache_get_readonly_v1(
      policy, secret, manifest_sha256 = manifest_sha256),
    .dsvert_dp_capsule_manifest_draft_unsigned = draft,
    .package = "dsVert")
  expect_identical(observed$manifest_sha256, manifest_sha256)
  restored <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_policy_for_manifest_v1(
      manifest_sha256, secret,
      state_path = policy$synopsis_state_path),
    .dsvert_dp_capsule_manifest_draft_unsigned = draft,
    .package = "dsVert")
  expect_identical(restored$peer_name, policy$peer_name)
  meta_rows <- .dsvert_dp_synopsis_execution_with_store_readonly_v1(
    policy, secret, function(connection) DBI::dbGetQuery(
      connection, "SELECT COUNT(*) AS count FROM synopsis_meta")$count[[1L]])
  expect_identical(as.integer(meta_rows), 1L)
  expect_identical(stamp(immutable_paths), before)
  expect_identical(file.exists(paths), existing_before)

  publication_globals <- codetools::findGlobals(
    .dsvert_dp_synopsis_publication_v1, merge = FALSE)$functions
  replay_globals <- codetools::findGlobals(
    .dsvert_dp_synopsis_publication_replay_v1, merge = FALSE)$functions
  expect_true(all(c(
    ".dsvert_dp_synopsis_compilation_get_readonly_v1",
    ".dsvert_dp_synopsis_execution_with_store_readonly_v1") %in%
    publication_globals))
  expect_true(
    ".dsvert_dp_synopsis_execution_with_store_readonly_v1" %in%
      replay_globals)
  expect_false(any(c(
    ".dsvert_dp_synopsis_manifest_store_with_v1",
    ".dsvert_dp_synopsis_execution_with_store_v1") %in%
    c(publication_globals, replay_globals)))
  expect_identical(
    formals(.dsvert_dp_synopsis_publication_context_v1)$.cache_get,
    quote(.dsvert_dp_synopsis_manifest_cache_get_readonly_v1))
})

test_that("read-only store validation and rows share one WAL snapshot", {
  path <- tempfile("synopsis-read-snapshot-", fileext = ".sqlite")
  paths <- c(path, paste0(path, ".lock"), paste0(path, "-wal"),
             paste0(path, "-shm"), paste0(path, "-journal"))
  withr::defer(unlink(paths, force = TRUE))
  previous_umask <- Sys.umask("0077")
  withr::defer(Sys.umask(previous_umask))
  writer <- DBI::dbConnect(
    RSQLite::SQLite(), path, synchronous = NULL,
    loadable.extensions = FALSE, default.extensions = FALSE)
  withr::defer(DBI::dbDisconnect(writer))
  expect_identical(
    DBI::dbGetQuery(writer, "PRAGMA journal_mode=WAL")[[1L]], "wal")
  DBI::dbExecute(writer, "CREATE TABLE snapshot_test(value INTEGER NOT NULL)")
  DBI::dbExecute(writer, "INSERT INTO snapshot_test(value) VALUES(1)")
  first <- NULL
  second <- .dsvert_dp_synopsis_store_readonly_with_v1(
    path, "snapshot test store", TRUE,
    function(connection) {
      first <<- DBI::dbGetQuery(
        connection, "SELECT value FROM snapshot_test")$value[[1L]]
      DBI::dbExecute(writer, "UPDATE snapshot_test SET value=2")
      invisible(TRUE)
    }, function(connection) DBI::dbGetQuery(
      connection, "SELECT value FROM snapshot_test")$value[[1L]])
  expect_identical(as.integer(first), 1L)
  expect_identical(as.integer(second), 1L)
  expect_identical(as.integer(DBI::dbGetQuery(
    writer, "SELECT value FROM snapshot_test")$value[[1L]]), 2L)
})

test_that("read-only execution lookup neither migrates nor accepts bad metadata", {
  policy <- .synopsis_no_lifetime_policies(2L)[[1L]]
  secret <- as.raw(rep(67L, 32L))
  path <- paste0(
    policy$synopsis_state_path, ".synopsis-execution-v1.sqlite")
  paths <- c(path, paste0(path, ".lock"), paste0(path, "-wal"),
             paste0(path, "-shm"), paste0(path, "-journal"))
  withr::defer(unlink(paths, force = TRUE))
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  for (statement in
       .dsvert_dp_synopsis_execution_schema_statements_v1(FALSE)) {
    DBI::dbExecute(connection, statement)
  }
  binding <- .dsvert_dp_synopsis_execution_store_binding_v1(
    policy, "dsvert-stateless-catalog-synopsis-execution-store-v2")
  DBI::dbExecute(connection, paste(
    "INSERT INTO synopsis_meta(key,value,row_mac)",
    "VALUES('policy_binding',?,?)"), params = list(
      binding, .dsvert_dp_synopsis_execution_store_mac_v1(
        secret, "meta", "policy_binding", binding)))
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")
  legacy <- tryCatch(
    .dsvert_dp_synopsis_execution_with_store_readonly_v1(
      policy, secret, function(connection) TRUE),
    error = identity)
  expect_match(conditionMessage(legacy), "execution store schema is invalid")
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RO,
    synchronous = NULL, loadable.extensions = FALSE,
    default.extensions = FALSE)
  expect_identical(as.integer(DBI::dbGetQuery(connection, paste(
    "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='table'",
    "AND name='synopsis_exact_starts'"))$n[[1L]]), 0L)
  DBI::dbDisconnect(connection)

  unlink(paths, force = TRUE)
  expect_true(.dsvert_dp_synopsis_execution_with_store_v1(
    policy, secret, function(connection) TRUE))
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "UPDATE synopsis_meta SET row_mac=? WHERE key='policy_binding'"),
    params = list(strrep("0", 64L)))
  DBI::dbDisconnect(connection)
  tamper <- tryCatch(
    .dsvert_dp_synopsis_execution_with_store_readonly_v1(
      policy, secret, function(connection) TRUE),
    error = identity)
  expect_false(inherits(tamper, "dsvert_resource_backpressure"))
  expect_match(conditionMessage(tamper), "failed authentication")
})

test_that("synopsis state roots are private service directories", {
  directory <- tempfile("synopsis-public-root-")
  dir.create(directory, mode = "0755")
  withr::defer(unlink(directory, recursive = TRUE, force = TRUE))
  withr::local_options(list(
    dsvert.dp.synopsis_state_path = file.path(directory, "state")))
  if (!identical(.Platform$OS.type, "unix")) {
    expect_error(
      .dsvert_dp_synopsis_state_path_v1(), "POSIX owner-only")
    return(invisible(NULL))
  }
  Sys.chmod(directory, mode = "0755")
  expect_error(
    .dsvert_dp_synopsis_state_path_v1(), "mode 0700")
  Sys.chmod(directory, mode = "0700")
  expect_identical(
    .dsvert_dp_synopsis_state_path_v1(),
    file.path(normalizePath(directory, winslash = "/"), "state"))
})

test_that("durable policy snapshots reject unversioned fields and weak state", {
  policy <- .synopsis_no_lifetime_policies(2L)[[1L]]
  snapshot <- .dsvert_dp_synopsis_policy_snapshot_v1(policy)
  expect_silent(.dsvert_dp_synopsis_policy_snapshot_validate_v1(snapshot))
  embedded <- .dsvert_dp_canonical_query_value(list(
    policy_snapshot = snapshot))$policy_snapshot
  expect_silent(.dsvert_dp_synopsis_policy_snapshot_validate_v1(embedded))
  roundtrip <- jsonlite::fromJSON(
    .dsvert_dp_canonical_json(embedded), simplifyVector = FALSE)
  expect_silent(.dsvert_dp_synopsis_policy_snapshot_validate_v1(roundtrip))
  extended <- policy
  extended$future_field <- "requires-a-new-snapshot-version"
  expect_error(
    .dsvert_dp_synopsis_policy_snapshot_v1(extended),
    "Invalid durable synopsis policy snapshot")
  nonprivate <- policy
  nonprivate$state_private <- FALSE
  expect_error(
    .dsvert_dp_synopsis_policy_snapshot_v1(nonprivate),
    "Invalid durable synopsis policy snapshot")
})

test_that("pre-freeze manifest stores require an explicit migration", {
  policy <- .synopsis_no_lifetime_policies(2L)[[1L]]
  secret <- as.raw(rep(47L, 32L))
  path <- paste0(policy$synopsis_state_path, ".manifest-v1.sqlite")
  withr::defer(unlink(c(
    path, paste0(path, ".lock"), paste0(path, "-wal"),
    paste0(path, "-shm")), force = TRUE))
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "CREATE TABLE synopsis_manifests (cache_key TEXT PRIMARY KEY,",
    "manifest_sha256 TEXT, record_json TEXT, row_mac TEXT)"))
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")
  expect_error(.dsvert_dp_synopsis_manifest_cache_get_v1(
    policy, secret, manifest_sha256 = strrep("a", 64L)),
    "explicit authenticated migration")
})

test_that("manifest store rejects lookalike schemas and crash rolls back", {
  policy <- .synopsis_no_lifetime_policies(2L)[[1L]]
  secret <- as.raw(rep(53L, 32L))
  path <- paste0(policy$synopsis_state_path, ".manifest-v1.sqlite")
  cleanup <- function() unlink(c(
    path, paste0(path, ".lock"), paste0(path, "-wal"),
    paste0(path, "-shm")), force = TRUE)
  withr::defer(cleanup())
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "CREATE TABLE synopsis_manifest_meta (key TEXT PRIMARY KEY,",
    "value TEXT NOT NULL, row_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE synopsis_manifests (cache_key TEXT PRIMARY KEY,",
    "manifest_sha256 TEXT NOT NULL UNIQUE, record_json TEXT NOT NULL,",
    "row_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE synopsis_compilations (manifest_sha256 TEXT PRIMARY KEY,",
    "artifact_key TEXT NOT NULL UNIQUE, complete INTEGER NOT NULL,",
    "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, paste(
    "CREATE TRIGGER leak_trigger AFTER INSERT ON synopsis_manifests",
    "BEGIN DELETE FROM synopsis_manifests; END"))
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")
  expect_error(.dsvert_dp_synopsis_manifest_cache_get_v1(
    policy, secret, manifest_sha256 = strrep("a", 64L)),
    "explicit authenticated migration")
  cleanup()

  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  calls <- 0L
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_manifest_store_schema_v1(connection, secret),
    .dsvert_dp_synopsis_manifest_mac_v1 = function(...) {
      calls <<- calls + 1L
      if (calls == 2L) stop("simulated bootstrap crash", call. = FALSE)
      strrep("a", 64L)
    }, .package = "dsVert"), "simulated bootstrap crash")
  expect_equal(nrow(
    .dsvert_dp_synopsis_manifest_schema_rows_v1(connection)), 0L)
  DBI::dbDisconnect(connection)
})

test_that("only transient durable-store contention is typed backpressure", {
  locked <- simpleError("database is locked")
  pressure <- tryCatch(
    .dsvert_dp_synopsis_store_busy_v1(locked, "synopsis manifest store"),
    error = identity)
  expect_s3_class(pressure, "dsvert_resource_backpressure")
  expect_identical(pressure$code, "resource_backpressure")
  expect_identical(pressure$parent, locked)

  tamper <- simpleError(
    "The synopsis manifest-store metadata failed authentication.")
  observed <- tryCatch(
    .dsvert_dp_synopsis_store_busy_v1(tamper, "synopsis manifest store"),
    error = identity)
  expect_false(inherits(observed, "dsvert_resource_backpressure"))
  expect_identical(observed, tamper)
})

test_that("K=2 real durable publication replays and finalizes after restart", {
  helpers <- local({
    environment <- new.env(parent = asNamespace("dsVert"))
    for (expression in parse(testthat::test_path(
        "test-dp-synopsis-replay.R"))) {
      if (is.call(expression) && identical(
          as.character(expression[[1L]]), "test_that")) break
      eval(expression, envir = environment)
    }
    environment
  })
  release <- helpers$.synopsis_replay_helpers
  result <- release$.synopsis_release_helpers$.synopsis_result_helpers
  start <- result$.synopsis_result_helpers
  planner <- function(input) .callMpcTool(
    "joint-dp-vector-convolution-plan-v3", input)

  fixture <- start$.synopsis_start_convolution_fixture(2L, planner)
  start$.synopsis_start_cleanup(fixture)
  peers <- fixture$peers
  identities <- stats::setNames(lapply(seq_along(peers), function(index) {
    .callMpcTool("derive-identity", list(seed = jsonlite::base64_enc(
      as.raw((seq_len(32L) + 83L * index) %% 256L))))
  }), peers)
  pins <- stats::setNames(vapply(identities, function(identity) {
    .dsvert_relay_normalize_identity_pk(identity$identity_pk)
  }, character(1L)), peers)
  pinset_sha256 <- .dsvert_dp_synopsis_pinset_hash_v1(pins)
  inherited <- c(
    "domain", "cohort_id", "global_total_epsilon",
    "global_total_delta", "adjacency", "patient_column",
    "unit_capacity", "fixed_cohort_size", "max_records_per_unit",
    "overflow_policy", "contingency_unit_aggregation_policy",
    "numeric_grid_bits", "numeric_bounds", "categorical_levels",
    "capsule_workload_scope", "datasets")
  policies <- stats::setNames(lapply(peers, function(peer) {
    old <- fixture$input$policies[[peer]]
    policy <- .synopsis_no_lifetime_policies(2L)[[peer]]
    policy[inherited] <- old[inherited]
    policy$logical_peers <- peers
    policy$peer_pinset <- pins
    policy$peer_pinset_sha256 <- pinset_sha256
    policy$peer_count <- 2L
    policy$designated_noise_peers <- peers
    policy$peer_name <- peer
    policy$own_identity_pk <- unname(pins[[peer]])
    policy$synopsis_state_path <- file.path(normalizePath(
      dirname(old$ledger_path), winslash = "/", mustWork = TRUE),
      basename(old$ledger_path))
    policy
  }), peers)
  state_paths <- vapply(
    policies, `[[`, character(1L), "synopsis_state_path")
  store_paths <- unique(unlist(lapply(state_paths, function(path) {
    bases <- c(
      paste0(path, ".manifest-v1.sqlite"),
      paste0(path, ".synopsis-execution-v1.sqlite"))
    unlist(lapply(bases, function(base) c(
      base, paste0(base, ".lock"), paste0(base, "-wal"),
      paste0(base, "-shm"), paste0(base, "-journal"))))
  })))
  unlink(store_paths, force = TRUE)
  withr::defer(unlink(store_paths, force = TRUE))

  manifest <- fixture$input$fixture$manifest
  manifest$capsule_identity <- .dsvert_dp_synopsis_capsule_identity_v1(
    policies[[1L]], manifest$logical_snapshot, manifest$capsule_schema,
    manifest$admission, manifest$bounds, manifest$workload)
  expect_silent(.dsvert_dp_capsule_materializer_manifest(
    policies[[1L]], manifest))
  manifest_json <- .synopsis_no_lifetime_json(manifest)
  manifest_sha256 <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  secrets <- fixture$input$secrets
  cache_records <- stats::setNames(lapply(peers, function(peer) {
    policy <- policies[[peer]]
    secret <- secrets[[peer]]
    record <- list(
      version = .DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION,
      cache_key = digest::digest(
        paste0(peer, "|", manifest_sha256),
        algo = "sha256", serialize = FALSE),
      public_capsule_key = .dsvert_joint_dp_hash(
        list(version = "real-publication-integration-v1",
             manifest = manifest)),
      local_authority_sha256 =
        .dsvert_dp_synopsis_manifest_local_authority_v1(policy, secret),
      schema_sha256 = .dsvert_joint_dp_hash(manifest$capsule_schema),
      workload_contract_sha256 = .dsvert_joint_dp_hash(manifest$workload),
      manifest_sha256 = manifest_sha256,
      manifest_json = manifest_json,
      policy_snapshot = .dsvert_dp_synopsis_policy_snapshot_v1(policy))
    .dsvert_dp_synopsis_manifest_cache_put_v1(policy, secret, record)
  }), peers)
  expect_true(all(vapply(cache_records, function(record) {
    identical(record$manifest_sha256, manifest_sha256)
  }, logical(1L))))

  projection <- .dsvert_dp_synopsis_catalog_projection_v1(
    policies[[1L]], manifest)
  source_contract <- .dsvert_dp_capsule_source_contract(
    policies[[1L]], manifest)
  source_peers <- .dsvert_dp_capsule_source_names(
    source_contract$source_peers, "real publication source peers")
  claims <- lapply(source_peers, function(peer) {
    unsigned <- list(
      version = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_VERSION,
      source_peer_name = peer,
      source_identity_pk = unname(pins[[peer]]),
      catalog_sha256 = projection$sha256,
      source_vector_commitment = digest::digest(
        paste0("real-source-vector|", peer),
        algo = "sha256", serialize = FALSE))
    c(unsigned, list(signature = .dsvert_relay_sign_message(
      .dsvert_dp_synopsis_source_vector_claim_message_v1(unsigned),
      identities[[peer]]$identity_sk)))
  })
  claim_set <- .dsvert_dp_synopsis_source_claim_set_v1(
    policies[[1L]], manifest, claims)
  local <- stats::setNames(lapply(peers, function(peer) {
    .dsvert_dp_synopsis_local_compile_v1(
      manifest_sha256, claim_set, policies[[peer]], secrets[[peer]],
      identities[[peer]], .dsvert_dp_synopsis_manifest_cache_get_v1,
      planner)
  }), peers)
  expect_true(all(vapply(local[-1L], function(value) {
    identical(value$artifact, local[[1L]]$artifact)
  }, logical(1L))))
  compilation <- .dsvert_dp_synopsis_compile_v1(
    lapply(local, `[[`, "receipt"), local[[1L]]$artifact,
    claim_set, policies[[1L]], manifest)
  compiled_records <- stats::setNames(lapply(peers, function(peer) {
    .dsvert_dp_synopsis_compilation_register_v1(
      manifest_sha256, compilation$artifact,
      compilation$receipts[[peer]], policies[[peer]], secrets[[peer]],
      receipts = compilation$receipts,
      receipt_set_sha256 = compilation$receipt_set_sha256)
  }), peers)
  expect_true(all(vapply(
    compiled_records, `[[`, logical(1L), "complete")))

  signer <- function(message, key) {
    normalized <- .dsvert_relay_normalize_identity_pk(key)
    peer <- names(pins)[match(normalized, unname(pins))]
    if (length(peer) != 1L || is.na(peer)) {
      stop("The integration signer key is not pinned.", call. = FALSE)
    }
    .dsvert_relay_sign_message(message, identities[[peer]]$identity_sk)
  }
  fixture$input$policies <- policies
  fixture$input$fixture <- list(
    policy = policies[[1L]], manifest = manifest, pins = pins)
  fixture$input$claim_set <- claim_set
  fixture$input$manifest_json <- manifest_json
  fixture$input$manifest_sha256 <- manifest_sha256
  fixture$input$cache_get <- .dsvert_dp_synopsis_manifest_cache_get_v1
  fixture$input$planner <- planner
  fixture$input$signer <- signer
  fixture$input$verifier <- .dsvert_relay_verify_message
  fixture$artifact <- compilation$artifact
  fixture$receipts <- unname(compilation$receipts)

  setup <- start$.synopsis_start_setup(fixture)
  authority <- setup$authorities[[1L]]
  remote_storage <- new.env(parent = emptyenv())
  remote_storage[[setup$session_id]] <- setup$authorized[[authority]]$state
  legacy_reached <- FALSE
  forbidden_legacy <- function(...) {
    legacy_reached <<- TRUE
    stop("legacy policy reached", call. = FALSE)
  }
  missing_local <- tryCatch(withr::with_options(
    stats::setNames(
      list(policies[[authority]]$synopsis_state_path),
      "dsvert.dp.synopsis_state_path"),
    testthat::with_mocked_bindings(
      dsvertDPSynopsisResultDS(
        setup$session_id,
        .dsvert_dsi_text_encode(setup$encoded[[1L]]),
        .dsvert_dsi_text_encode(setup$encoded[[2L]])),
      .session_storage = function() remote_storage,
      .dsvert_dp_secret = function() secrets[[authority]],
      .get_identity_keypair = function() identities[[authority]],
      .dsvert_dp_policy = forbidden_legacy,
      .dsvert_dp_synopsis_policy_v1 = forbidden_legacy,
      .package = "dsVert")), error = identity)
  expect_s3_class(missing_local, "dsvert_phase_not_ready")
  expect_false(legacy_reached)
  exact_transports <- stats::setNames(lapply(
    setup$authorities, function(peer) .callMpcTool(
      "transport-keygen", list())), setup$authorities)
  exact_transport_keys <- stats::setNames(lapply(
    setup$authorities, function(peer) base64_to_base64url(
      exact_transports[[peer]]$public_key)), setup$authorities)
  exact_identities <- stats::setNames(lapply(setup$authorities, function(peer) {
    list(
      identity_pk = base64_to_base64url(identities[[peer]]$identity_pk),
      signature = base64_to_base64url(.sign_transport_pk(
        exact_transports[[peer]]$public_key,
        identities[[peer]]$identity_sk)))
  }), setup$authorities)
  encode_exact_map <- function(value) .exact_gc_b64url_encode(charToRaw(
    as.character(jsonlite::toJSON(
      value, auto_unbox = TRUE, null = "null", digits = NA))))
  for (peer in setup$authorities) {
    exact_ss <- new.env(parent = emptyenv())
    exact_ss$.session_id <- setup$session_id
    exact_ss$.dp_synopsis_authorization <-
      setup$authorized[[peer]]$state$.dp_synopsis_authorization
    .key_put("transport_sk", exact_transports[[peer]]$secret_key, exact_ss)
    .key_put("transport_pk", exact_transports[[peer]]$public_key, exact_ss)
    .key_put("identity_pk", identities[[peer]]$identity_pk, exact_ss)
    exact_ss$.exact_gc_transport_initialized <- TRUE
    bind <- function() withr::with_options(
      stats::setNames(
        list(policies[[peer]]$synopsis_state_path),
        "dsvert.dp.synopsis_state_path"),
      testthat::with_mocked_bindings(
        exactGCBindPeersDS(
          encode_exact_map(exact_transport_keys),
          encode_exact_map(exact_identities), setup$session_id),
        .S = function(...) exact_ss,
        .dsvert_dp_secret = function() secrets[[peer]],
        .get_identity_keypair = function() identities[[peer]],
        .dsvert_dp_policy = forbidden_legacy,
        .dsvert_dp_synopsis_policy_v1 = forbidden_legacy,
        .dsvert_require_configured_local_peer_name = forbidden_legacy,
        .package = "dsVert"))
    first_bind <- bind()
    expect_true(first_bind$bound)
    expect_identical(bind(), first_bind)
    expect_identical(
      withr::with_options(
        stats::setNames(
          list(policies[[peer]]$synopsis_state_path),
          "dsvert.dp.synopsis_state_path"),
        testthat::with_mocked_bindings(
          .exact_gc_validate_bound_peer_context(exact_ss, setup$session_id),
          .dsvert_dp_secret = function() secrets[[peer]],
          .get_identity_keypair = function() identities[[peer]],
          .dsvert_dp_policy = forbidden_legacy,
          .dsvert_dp_synopsis_policy_v1 = forbidden_legacy,
          .dsvert_require_configured_local_peer_name = forbidden_legacy,
          .package = "dsVert")),
      exact_ss$.exact_gc_peer_binding_digest)
  }
  expect_false(legacy_reached)
  results <- stats::setNames(lapply(setup$authorities, function(peer) {
    context <- start$.synopsis_start_context(fixture, setup, peer)
    start$.synopsis_start_call(
      fixture, setup, peer, start$.synopsis_start_zero_source,
      start$.synopsis_start_sampler(context))
    result$.synopsis_result_call(fixture, setup, peer)
  }), setup$authorities)
  built <- list(fixture = fixture, setup = setup, results = results)
  releases <- stats::setNames(lapply(setup$authorities, function(peer) {
    release$.synopsis_release_call(built, peer)
  }), setup$authorities)
  expect_identical(
    releases[[1L]]$final_vector_root,
    releases[[2L]]$final_vector_root)
  expect_identical(
    releases[[1L]]$result_set_sha256,
    releases[[2L]]$result_set_sha256)

  durable_paths <- unique(unlist(lapply(peers, function(peer) {
    state <- policies[[peer]]$synopsis_state_path
    c(paste0(state, ".manifest-v1.sqlite"),
      paste0(state, ".manifest-v1.sqlite-wal"),
      paste0(state, ".synopsis-execution-v1.sqlite"),
      paste0(state, ".synopsis-execution-v1.sqlite-wal"))
  })))
  stamp <- function(paths) {
    present <- file.exists(paths)
    existing <- paths[present]
    info <- file.info(existing)
    list(
      present = stats::setNames(present, paths),
      size = stats::setNames(unname(info$size), existing),
      mtime = stats::setNames(unname(as.numeric(info$mtime)), existing),
      sha256 = stats::setNames(vapply(existing, function(path) {
        digest::digest(path, algo = "sha256", serialize = FALSE, file = TRUE)
      }, character(1L)), existing))
  }
  warm <- function(path, code) withr::with_options(
    stats::setNames(list(path), "dsvert.dp.synopsis_state_path"),
    force(code))
  # A first SQLite read may create SHM and an empty WAL for coordination.
  # Warm both stores, then prove that no durable sidecar was created.
  before_warm <- file.exists(store_paths)
  invisible(lapply(peers, function(peer) {
    warm(policies[[peer]]$synopsis_state_path,
         .dsvert_dp_synopsis_policy_for_manifest_v1(
           manifest_sha256, secrets[[peer]]))
    .dsvert_dp_synopsis_execution_with_store_readonly_v1(
      policies[[peer]], secrets[[peer]], function(connection) TRUE)
  }))
  newly_created <- store_paths[!before_warm & file.exists(store_paths)]
  expect_true(all(grepl("-(shm|wal)$", newly_created)))
  new_wal <- newly_created[grepl("-wal$", newly_created)]
  expect_true(all(file.info(new_wal)$size == 0))
  before_public <- stamp(durable_paths)
  sidecars_before <- file.exists(store_paths)
  publications <- stats::setNames(lapply(peers, function(peer) {
    warm(policies[[peer]]$synopsis_state_path,
         .dsvert_dp_synopsis_publication_v1(
           manifest_sha256, .policy = NULL, .secret = secrets[[peer]]))
  }), peers)
  publication_json <- lapply(publications, .synopsis_no_lifetime_json)
  replays <- stats::setNames(lapply(peers, function(peer) {
    warm(policies[[peer]]$synopsis_state_path,
         .dsvert_dp_synopsis_publication_replay_v1(
           compilation$artifact$artifact_key,
           publication_json[[1L]], publication_json[[2L]], 0L,
           .policy = NULL, .secret = secrets[[peer]]))
  }), peers)
  expect_true(all(vapply(replays, function(replay) {
    identical(replay$phase, "synopsis_public_chunk_replayed") &&
      identical(replay$durable_replay, TRUE) &&
      identical(replay$chunk_sha256,
                releases[[1L]]$final_chunk_hashes[[1L]])
  }, logical(1L))))
  expect_identical(stamp(durable_paths), before_public)
  expect_identical(file.exists(store_paths), sidecars_before)

  compactions <- character()
  compactor <- function(
      policy, manifest_json, authorization, secret, source_contract) {
    parsed <- .dsvert_dp_capsule_source_contract_json(
      policy, manifest_json, source_contract)
    expect_identical(parsed$contract_hash,
                     .dsvert_joint_dp_hash(source_contract))
    authorization <-
      .dsvert_dp_capsule_source_compaction_authorization_validate(
        authorization, source_contract, secret)
    compactions <<- c(compactions, policy$peer_name)
    .dsvert_dp_canonical_query_value(list(
      version = "real-publication-integration-compactor-v1",
      peer_name = policy$peer_name,
      source_contract_sha256 = .dsvert_joint_dp_hash(source_contract),
      authorization_sha256 = .dsvert_joint_dp_hash(authorization),
      compacted = TRUE))
  }
  acknowledgements <- stats::setNames(lapply(peers, function(peer) {
    held <- NULL
    if (identical(peer, peers[[1L]])) {
      held <- filelock::lock(paste0(
        policies[[peer]]$synopsis_state_path,
        ".synopsis-execution-v1.sqlite.lock"), timeout = 0)
      expect_false(is.null(held))
      on.exit(if (!is.null(held)) filelock::unlock(held), add = TRUE)
    }
    call <- function() warm(
      policies[[peer]]$synopsis_state_path,
      .dsvert_dp_synopsis_finalize_ack_v1(
        manifest_sha256, publication_json[[1L]], publication_json[[2L]],
        .policy = NULL, .secret = secrets[[peer]],
        .identity = identities[[peer]], .source_compactor = compactor))
    first <- call()
    if (!is.null(held)) {
      filelock::unlock(held)
      held <- NULL
    }
    expect_identical(call(), first)
    expect_true(.dsvert_relay_verify_message(
      .dsvert_dp_synopsis_finalize_ack_message_v1(first),
      pins[[peer]], first$signature))
    first
  }), peers)
  expect_identical(names(acknowledgements), peers)
  expect_identical(sort(unique(compactions), method = "radix"), peers)
  expect_true(all(vapply(peers, function(peer) {
    record <- .dsvert_dp_synopsis_compilation_get_v1(
      policies[[peer]], secrets[[peer]],
      manifest_sha256 = manifest_sha256)
    isTRUE(record$complete) &&
      identical(record$artifact_key, compilation$artifact$artifact_key)
  }, logical(1L))))
})

test_that("publication pairs carry the artifact and exact-K compilation", {
  policy <- .synopsis_no_lifetime_policies(3L)[[3L]]
  peers <- names(policy$peer_pinset)
  artifact_key <- strrep("a", 64L)
  manifest_sha256 <- strrep("b", 64L)
  receipts <- stats::setNames(lapply(peers, function(peer) {
    list(peer_name = peer, proof = paste0("compile-", peer))
  }), peers)
  envelope <- function(peer) list(
    version = .DSVERT_DP_SYNOPSIS_PUBLICATION_VERSION,
    published = TRUE, manifest_sha256 = manifest_sha256,
    artifact = list(artifact_key = artifact_key),
    artifact_key = artifact_key, compile_receipts = receipts,
    receipt_set_sha256 = strrep("c", 64L), public_chunk_count = 2L,
    release_receipt = list(peer_name = peer),
    durable_publication = TRUE, session_required = FALSE,
    source_store_read = FALSE, request_limit = FALSE,
    rate_limit = FALSE, catalog_limit = FALSE)
  pair <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_publication_pair_v1(
      .synopsis_no_lifetime_json(envelope(peers[[1L]])),
      .synopsis_no_lifetime_json(envelope(peers[[2L]])),
      policy, as.raw(rep(1L, 32L)),
      expected_manifest_sha256 = manifest_sha256,
      expected_artifact_key = artifact_key),
    .dsvert_dp_synopsis_publication_context_v1 = function(
        record, policy, secret) list(
      record = record, artifact = record$artifact,
      receipts = record$receipts,
      context = list(contract = list(value = list(
        geometry = list(public_chunk_count = 2L))))),
    .dsvert_dp_synopsis_execution_release_set_v1 = function(...) {
      stats::setNames(list(list(peer = peers[[1L]]),
                           list(peer = peers[[2L]])), peers[1:2])
    },
    .dsvert_dp_synopsis_compilation_register_v1 = function(...) {
      stop("published replay attempted a compilation write", call. = FALSE)
    }, .package = "dsVert")
  expect_identical(names(pair$publication$receipts), peers)
  expect_identical(length(pair$record$receipts), 3L)
  expect_identical(pair$record$local_receipt$peer_name, peers[[3L]])
  expect_false(".dsvert_dp_synopsis_compilation_register_v1" %in%
    codetools::findGlobals(
      .dsvert_dp_synopsis_publication_pair_v1,
      merge = FALSE)$functions)
  expect_error(.dsvert_dp_synopsis_publication_pair_v1(
    .synopsis_no_lifetime_json(list(peer_name = peers[[1L]])),
    .synopsis_no_lifetime_json(envelope(peers[[2L]])),
    policy, as.raw(rep(1L, 32L))), "publication envelope")
  changed <- envelope(peers[[2L]])
  changed$artifact_key <- strrep("d", 64L)
  expect_error(.dsvert_dp_synopsis_publication_pair_v1(
    .synopsis_no_lifetime_json(envelope(peers[[1L]])),
    .synopsis_no_lifetime_json(changed),
    policy, as.raw(rep(1L, 32L))), "do not agree")
})

test_that("FinalizeAck reuses the durable source compactor without a session", {
  skip_if_not(.synopsis_no_lifetime_available(),
              "RED: dedicated synopsis lifecycle is absent")
  namespace <- asNamespace("dsVert")
  finalize <- get(
    ".dsvert_dp_synopsis_finalize_ack_v1", namespace, inherits = FALSE)
  globals <- codetools::findGlobals(finalize, merge = FALSE)$functions
  expect_identical(
    formals(finalize)$.source_compactor,
    quote(.dsvert_dp_capsule_source_compact_after_vector_release_internal))
  expect_false(any(c(".S", ".session_storage") %in% globals))
  expect_false("session_id" %in% names(formals(finalize)))
  expect_true(
    ".dsvert_dp_synopsis_execution_with_store_readonly_v1" %in% globals)
  expect_false(
    ".dsvert_dp_synopsis_execution_with_store_v1" %in% globals)
})

test_that("FinalizeAck authenticates its signer before durable mutation", {
  policy <- .synopsis_no_lifetime_policies(2L)[[1L]]
  touched <- FALSE
  publication <- list(
    artifact = list(artifact_key = strrep("a", 64L)),
    context = list(), manifest_json = "{}")
  compilation <- list(
    manifest_sha256 = strrep("b", 64L),
    artifact = publication$artifact,
    local_receipt = list(peer_name = policy$peer_name),
    receipts = list(), receipt_set_sha256 = strrep("c", 64L))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_finalize_ack_v1(
      compilation$manifest_sha256, "first", "second",
      .policy = policy, .secret = as.raw(rep(71L, 32L)),
      .identity = list(
        identity_pk = unname(policy$peer_pinset[[2L]]),
        identity_sk = unname(policy$peer_pinset[[2L]])),
      .signer = .synopsis_no_lifetime_signer,
      .source_compactor = function(...) {
        touched <<- TRUE
        stop("source compactor reached", call. = FALSE)
      }),
    .dsvert_dp_synopsis_publication_pair_v1 = function(...) list(
      record = compilation, publication = publication, releases = list()),
    .dsvert_dp_synopsis_compilation_register_v1 = function(...) {
      touched <<- TRUE
      stop("compilation registration reached", call. = FALSE)
    },
    .dsvert_dp_synopsis_execution_with_store_v1 = function(...) {
      touched <<- TRUE
      stop("execution store reached", call. = FALSE)
    }, .package = "dsVert"), "identity is not pinned")
  expect_false(touched)
})

test_that("FinalizeAck is idempotent and K-wide for K=2/3/5", {
  for (k in c(2L, 3L, 5L)) {
    policies <- .synopsis_no_lifetime_policies(k)
    peers <- names(policies)
    artifact <- list(artifact_key = strrep("a", 64L))
    source_contract <- list(capsule_id = strrep("b", 64L))
    root <- strrep("c", 64L)
    result <- strrep("d", 64L)
    chunk <- strrep("e", 64L)
    releases <- stats::setNames(lapply(peers[1:2], function(peer) list(
      local_authority = list(peer_name = peer),
      final_vector_root = root, result_set_sha256 = result,
      final_chunk_hashes = list(chunk))), peers[1:2])
    durable_reads <- character()
    compactions <- character()
    registrations <- character()
    acknowledgements <- lapply(peers, function(peer) {
      policy <- policies[[peer]]
      local_authority <- if (peer %in% peers[1:2]) peer else peers[[1L]]
      context <- list(
        execution_id = strrep("f", 64L),
        contract = list(sha256 = strrep("1", 64L)),
        source_contract = source_contract,
        authorization = list(local_authority = list(
          peer_name = local_authority)))
      publication <- list(
        artifact = artifact, manifest_json = "{}", context = context)
      compilation <- list(
        manifest_sha256 = strrep("2", 64L), artifact = artifact,
        local_receipt = list(peer_name = peer),
        receipts = stats::setNames(lapply(peers, function(value) {
          list(peer_name = value)
        }), peers), receipt_set_sha256 = strrep("6", 64L))
      call <- function() testthat::with_mocked_bindings(
        .dsvert_dp_synopsis_finalize_ack_v1(
          strrep("2", 64L), "first-publication", "second-publication",
          .policy = policy, .secret = as.raw(rep(7L, 32L)),
          .identity = list(
            identity_pk = unname(policy$peer_pinset[[peer]]),
            identity_sk = unname(policy$peer_pinset[[peer]])),
          .signer = .synopsis_no_lifetime_signer,
          .source_compactor = function(
              policy, manifest_json, authorization, secret,
              source_contract) {
            compactions <<- c(compactions, policy$peer_name)
            expect_identical(source_contract, publication$context$source_contract)
            list(version = "compaction-test-v1", peer = policy$peer_name,
                 authorization = authorization)
          }),
        .dsvert_dp_synopsis_publication_pair_v1 = function(...) list(
          record = compilation, publication = publication,
          releases = releases),
        .dsvert_dp_synopsis_compilation_register_v1 = function(...) {
          registrations <<- c(registrations, policy$peer_name)
          compilation
        },
        .dsvert_dp_synopsis_execution_with_store_readonly_v1 = function(
            policy, secret, code) {
          durable_reads <<- c(durable_reads, policy$peer_name)
          list(receipt = releases[[policy$peer_name]])
        }, .package = "dsVert")
      first <- call()
      expect_identical(call(), first)
      expect_true(.synopsis_no_lifetime_verifier(
        .dsvert_dp_synopsis_finalize_ack_message_v1(first),
        unname(policy$peer_pinset[[peer]]), first$signature))
      first
    })
    names(acknowledgements) <- peers
    expect_identical(unname(vapply(
      acknowledgements, `[[`, character(1L), "peer_name")), peers)
    expect_identical(sort(unique(compactions), method = "radix"), peers)
    expect_identical(sort(unique(registrations), method = "radix"), peers)
    expect_identical(sort(unique(durable_reads), method = "radix"),
                     peers[1:2])
  }
})
