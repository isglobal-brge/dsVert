.capsule_manifest_test_b64url <- function(value) {
  sub("=+$", "", chartr(
    "+/", "-_", gsub("[\r\n]", "", jsonlite::base64_enc(value))),
    perl = TRUE)
}

.capsule_manifest_test_signature <- function(message, pin) {
  pin_raw <- .dsvert_relay_b64url_decode(pin, "manifest test pin")
  .capsule_manifest_test_b64url(openssl::sha512(c(message, pin_raw)))
}

.capsule_manifest_test_signer <- function(message, peer_name, pin) {
  .capsule_manifest_test_signature(message, pin)
}

.capsule_manifest_test_verifier <- function(message, pin, signature) {
  identical(signature, .capsule_manifest_test_signature(message, pin))
}

.capsule_manifest_test_is_canonical <- function(value) {
  decoded <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = FALSE), error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(decoded)),
    error = function(error) NULL)
  identical(canonical, value)
}

.capsule_manifest_test_fixture <- function(k = 2L) {
  stopifnot(k %in% 2:5)
  root <- tempfile("capsule-manifest-bootstrap-")
  dir.create(root)
  peers <- paste0("peer_", letters[seq_len(k)])
  pins <- vapply(seq_along(peers), function(index) {
    .capsule_manifest_test_b64url(as.raw(
      (seq_len(32L) + 41L * index) %% 256L))
  }, character(1L))
  names(pins) <- peers
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  policies <- stats::setNames(lapply(seq_along(peers), function(index) {
    peer <- peers[[index]]
    data_name <- paste0("data_", peer)
    variable <- paste0("x_", peer)
    numeric_bounds <- stats::setNames(list(c(0, 10)), variable)
    categories <- if (index == 1L) {
      stats::setNames(list(c("control", "treated")), "arm")
    } else if (index == 2L) {
      stats::setNames(list(c("0", "1")), paste0("status_", peer))
    } else {
      list()
    }
    if (index == 2L) {
      numeric_bounds[[paste0("time_", peer)]] <- c(0, 10)
    }
    workload <- list(describe = list(), survival = list(),
                     gaussian = list(), vertical_cross = list())
    if (index == 1L) {
      workload$describe$owner_a_describe <- list(
        version = "v1", dataset = data_name, variables = variable,
        histogram_grids = stats::setNames(list(c(5, 10)), variable),
        allocation = c(
          count = 0.25, sum = 0.25, sumsq = 0.25,
          histogram = 0.25))
      workload$vertical_cross$owner_a_cross <- list(
        version = "v1", left_dataset = "data_peer_a",
        right_dataset = "data_peer_b", left = "x_peer_a",
        right = "time_peer_b", family = "numeric_cross_moment")
    }
    if (index == 2L) {
      workload$survival$owner_b_survival <- list(
        version = "v1", dataset = data_name,
        time = paste0("time_", peer), event = paste0("status_", peer),
        censor = "0", time_grid = c(5, 10), entry = NULL)
    }
    list(
      schema_version = 7L,
      mechanism_version = "dsvert-dp-v7-contingency-unit-aggregation-1",
      policy_contract = "single_safe_policy_v4_global_allocator",
      domain = "capsule-manifest-study", cohort_id = "aligned-cohort-v1",
      peer_name = peer, own_identity_pk = unname(pins[[peer]]),
      logical_peers = peers, peer_pinset = pins,
      peer_pinset_sha256 = pin_hash, peer_count = as.integer(k),
      designated_noise_peers = peers[1:2],
      lifetime_max_distinct_capsules = 8,
      global_total_epsilon = 1, global_total_delta = 2^-100,
      allocation_total_epsilon = 1, allocation_total_delta = 2^-100,
      decay = 0.5, adjacency = "add_remove_patient",
      patient_column = "patient_id", unit_capacity = 100L,
      fixed_cohort_size = NULL, max_records_per_unit = 2L,
      overflow_policy = "reject_snapshot",
      contingency_unit_aggregation_policy =
        "consistent_cell_else_exclude_v1",
      numeric_grid_bits = 8L,
      numeric_bounds = numeric_bounds,
      categorical_levels = categories,
      capsule_dataset_mapping = NULL,
      capsule_workload_specs = workload,
      datasets = stats::setNames(list(list(
        id = paste0("cohort-", peer), version = "v1",
        snapshot_sha256 = strrep(as.character(index), 64L),
        alignment_manifest_hash = strrep(
          letters[[index]], 64L),
        alignment_manifest_version = 1L)), data_name),
      noise_root = list(
        epoch = as.integer(index),
        key_id = paste0("manifest-test-root-", index)),
      ledger_path = file.path(root, paste0(peer, ".sqlite")),
      ledger_private = FALSE, lock_timeout_ms = 30000L,
      rollback_protection = list(mode = "test"))
  }), peers)
  secrets <- stats::setNames(lapply(seq_along(peers), function(index) {
    as.raw(rep(100L + index, 32L))
  }), peers)
  list(root = root, peers = peers, pins = pins, policies = policies,
       secrets = secrets)
}

.capsule_manifest_test_schema <- function(fixture) {
  draft_json <- stats::setNames(lapply(fixture$peers, function(peer) {
    .dsvert_dp_capsule_manifest_draft_impl(
      .policy = fixture$policies[[peer]],
      .signer = .capsule_manifest_test_signer)
  }), fixture$peers)
  stopifnot(all(vapply(
    draft_json, .capsule_manifest_test_is_canonical, logical(1L))))
  drafts <- lapply(draft_json, function(value) {
    jsonlite::fromJSON(value,
      simplifyVector = TRUE, simplifyDataFrame = FALSE,
      simplifyMatrix = FALSE)
  })
  datasets <- list()
  versions <- numeric()
  workload <- list(describe = list(), survival = list(),
                   gaussian = list(), vertical_cross = list())
  for (peer in fixture$peers) {
    for (data_name in names(drafts[[peer]]$datasets)) {
      local <- drafts[[peer]]$datasets[[data_name]]
      versions <- c(versions, local$alignment_protocol_version)
      datasets[[data_name]] <- list(
        dataset_id = local$dataset_id,
        dataset_version = local$dataset_version,
        schema_version = local$schema_version,
        alignment_group = local$alignment_group,
        patient_keys = stats::setNames(list(local$patient_column), peer),
        columns = local$columns)
    }
    for (family in names(workload)) {
      fragments <- drafts[[peer]]$workload_fragments[[family]]
      stopifnot(!length(intersect(names(workload[[family]]),
                                  names(fragments))))
      for (analysis_id in names(fragments)) {
        workload[[family]][[analysis_id]] <- list(
          owner_peer = peer, spec = fragments[[analysis_id]])
      }
    }
  }
  datasets <- datasets[order(names(datasets), method = "radix")]
  workload <- lapply(workload, function(value) {
    if (!length(value)) return(list())
    value[order(names(value), method = "radix")]
  })
  workload <- .dsvert_dp_canonical_query_value(c(
    list(version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION),
    workload))
  workload_json <- .dsvert_dp_canonical_json(workload)
  snapshot <- .dsvert_dp_capsule_manifest_expected_snapshot(
    fixture$policies[[1L]], datasets, unique(versions), workload)
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = snapshot,
    peer_pinset_sha256 = fixture$policies[[1L]]$peer_pinset_sha256,
    datasets = datasets))
  unsigned_json <- .dsvert_dp_canonical_json(unsigned)
  signatures <- stats::setNames(lapply(fixture$peers, function(peer) {
    response_json <- .dsvert_dp_capsule_manifest_sign_impl(
        unsigned_json, workload_json,
        .policy = fixture$policies[[peer]],
        .signer = .capsule_manifest_test_signer)
    stopifnot(.capsule_manifest_test_is_canonical(response_json))
    response <- jsonlite::fromJSON(
      response_json,
      simplifyVector = TRUE, simplifyDataFrame = FALSE,
      simplifyMatrix = FALSE)
    response$schema_signature
  }), fixture$peers)
  signed <- .dsvert_dp_canonical_query_value(
    c(unsigned, list(signatures = signatures)))
  list(
    drafts = drafts, unsigned = unsigned,
    unsigned_json = unsigned_json,
    signed = signed, signed_json = .dsvert_dp_canonical_json(signed),
    workload = workload, workload_json = workload_json)
}

.capsule_manifest_test_memory_cache <- function() {
  values <- new.env(parent = emptyenv())
  get <- function(policy, secret, cache_key = NULL,
                  manifest_sha256 = NULL) {
    keys <- ls(values, all.names = TRUE)
    if (!is.null(cache_key)) {
      if (!exists(cache_key, values, inherits = FALSE)) return(NULL)
      return(base::get(cache_key, values, inherits = FALSE))
    }
    for (key in keys) {
      value <- base::get(key, values, inherits = FALSE)
      if (identical(value$manifest_sha256, manifest_sha256)) return(value)
    }
    NULL
  }
  put <- function(policy, secret, record) {
    if (exists(record$cache_key, values, inherits = FALSE)) {
      prior <- base::get(record$cache_key, values, inherits = FALSE)
      if (!identical(prior, record)) stop("cache conflict")
      return(prior)
    }
    assign(record$cache_key, record, values)
    record
  }
  list(get = get, put = put, values = values)
}

.capsule_manifest_test_recursive_names <- function(value) {
  if (!is.list(value)) return(character())
  c(names(value), unlist(lapply(
    value, .capsule_manifest_test_recursive_names), use.names = FALSE))
}

test_that("K=2 through K=5 derive one byte-identical server-authoritative manifest", {
  for (k in 2:5) {
    fixture <- .capsule_manifest_test_fixture(k)
    schema <- testthat::with_mocked_bindings(
      .capsule_manifest_test_schema(fixture),
      .dsvert_dp_resolve_snapshot = function(...) {
        stop("protected snapshot accessed")
      },
      .dsvert_dp_snapshot_digest = function(...) {
        stop("protected snapshot hashed")
      },
      .psi_validate_alignment_manifest = function(...) {
        stop("protected alignment accessed")
      },
      .package = "dsVert")
    expect_identical(names(schema$signed$signatures), fixture$peers)

    responses <- stats::setNames(lapply(fixture$peers, function(peer) {
      cache <- .capsule_manifest_test_memory_cache()
      .dsvert_dp_capsule_manifest_build_impl(
        schema$signed_json, schema$workload_json,
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = .capsule_manifest_test_signer,
        .verifier = .capsule_manifest_test_verifier,
        .cache_get = cache$get, .cache_put = cache$put)
    }), fixture$peers)
    expect_true(all(vapply(
      responses, .capsule_manifest_test_is_canonical, logical(1L))))
    decoded <- lapply(responses, function(value) jsonlite::fromJSON(
      value, simplifyVector = TRUE, simplifyDataFrame = FALSE,
      simplifyMatrix = FALSE))
    manifests <- vapply(decoded, `[[`, character(1L), "manifest_json")
    expect_length(unique(manifests), 1L)
    expect_length(unique(vapply(
      decoded, `[[`, character(1L), "artifact_commitments_root")), 1L)
    indices <- lapply(decoded, `[[`, "artifact_commitments")
    expect_true(all(vapply(indices, function(index) {
      identical(index$context$privacy_epoch_scope,
                "per_peer_signed_receipts_v1") &&
        !"privacy_epoch" %in% names(index$context)
    }, logical(1L))))
    expect_identical(
      unname(vapply(decoded, `[[`, numeric(1L), "privacy_epoch")),
      as.numeric(seq_len(k)))
    manifest <- jsonlite::fromJSON(
      manifests[[1L]], simplifyVector = TRUE,
      simplifyDataFrame = FALSE, simplifyMatrix = FALSE)
    expect_identical(
      names(manifest$workload$families$describe_artifacts),
      "owner_a_describe")
    expect_identical(
      manifest$workload$families$describe_artifacts$
        owner_a_describe$owner_peer,
      "peer_a")
    expect_identical(
      names(manifest$workload$families$survival_artifacts),
      "owner_b_survival")
    expect_identical(
      manifest$workload$families$survival_artifacts$
        owner_b_survival$owner_peer,
      "peer_b")
    expect_identical(
      manifest$workload$vertical_crosses$configured_crosses$
        owner_a_cross$left_owner,
      "peer_a")
    expect_identical(
      manifest$workload$vertical_crosses$configured_crosses$
        owner_a_cross$right_owner,
      "peer_b")
    expect_setequal(
      names(manifest$workload$schema_attestation$signatures),
      fixture$peers)
    expect_identical(
      manifest$workload$schema_attestation$signatures,
      schema$signed$signatures)
    expect_length(unique(vapply(
      decoded, `[[`, character(1L), "capsule_id")), 1L)
    expect_true(all(vapply(decoded, `[[`, logical(1L),
                           "durable_memoization")))
    expect_true(all(vapply(decoded, function(value) {
      identical(value$operation_limit, FALSE) &&
        identical(value$request_limit, FALSE) &&
        identical(value$history_can_deny_operation, FALSE)
    }, logical(1L))))
  }
})

test_that("K>=3 catalog consensus rejects one divergent peer before source access", {
  fixture <- .capsule_manifest_test_fixture(3L)
  catalog <- list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list())
  for (peer in fixture$peers) {
    fixture$policies[[peer]]$capsule_workload_scope <- catalog
  }
  protected_access <- 0L
  schema <- testthat::with_mocked_bindings(
    .capsule_manifest_test_schema(fixture),
    .dsvert_dp_resolve_snapshot = function(...) {
      protected_access <<- protected_access + 1L
      stop("protected snapshot accessed", call. = FALSE)
    },
    .package = "dsVert")

  build <- function(current) {
    caches <- stats::setNames(lapply(
      current$peers, function(peer) .capsule_manifest_test_memory_cache()),
      current$peers)
    responses <- stats::setNames(lapply(current$peers, function(peer) {
      .dsvert_dp_capsule_manifest_build_impl(
        schema$signed_json, schema$workload_json,
        .policy = current$policies[[peer]],
        .secret = current$secrets[[peer]],
        .signer = .capsule_manifest_test_signer,
        .verifier = .capsule_manifest_test_verifier,
        .cache_get = caches[[peer]]$get, .cache_put = caches[[peer]]$put)
    }), current$peers)
    decoded <- lapply(responses, function(value) jsonlite::fromJSON(
      value, simplifyVector = TRUE, simplifyDataFrame = FALSE,
      simplifyMatrix = FALSE))
    list(decoded = decoded, caches = caches)
  }

  agreed <- build(fixture)
  expect_length(unique(vapply(
    agreed$decoded, `[[`, character(1L), "manifest_sha256")), 1L)
  manifest <- jsonlite::fromJSON(
    agreed$decoded[[1L]]$manifest_json,
    simplifyVector = TRUE, simplifyDataFrame = FALSE,
    simplifyMatrix = FALSE)
  expect_identical(manifest$workload$primitive_scope$mode, "catalog_v1")

  divergent <- fixture
  divergent$policies$peer_c$capsule_workload_scope$numeric_moments <-
    "x_peer_c"
  split <- build(divergent)
  hashes <- vapply(
    split$decoded, `[[`, character(1L), "manifest_sha256")
  expect_identical(length(unique(hashes)), 2L)
  expect_error(
    .dsvert_dp_capsule_manifest_require_built(
      divergent$policies$peer_c,
      split$decoded$peer_a$manifest_json,
      secret = divergent$secrets$peer_c,
      .cache_get = split$caches$peer_c$get),
    class = "dsvert_capsule_manifest_rejected")
  expect_identical(protected_access, 0L)
})

test_that("draft and signing phases never access protected data or expose protected hashes", {
  fixture <- .capsule_manifest_test_fixture(2L)
  schema <- testthat::with_mocked_bindings(
    .capsule_manifest_test_schema(fixture),
    .dsvert_dp_resolve_snapshot = function(...) stop("data access"),
    .dsvert_dp_snapshot_digest = function(...) stop("snapshot access"),
    .psi_validate_alignment_manifest = function(...) stop("alignment access"),
    .package = "dsVert")
  fields <- unlist(lapply(
    schema$drafts, .capsule_manifest_test_recursive_names),
    use.names = FALSE)
  expect_false(any(c(
    "snapshot_sha256", "alignment_manifest_hash", "row_count",
    "patient_hash", "patient_digest", "alignment_hash") %in% fields))
  expect_true(all(vapply(schema$drafts, function(value) {
    identical(value$data_access, FALSE) &&
      identical(value$patient_derived_metadata, FALSE)
  }, logical(1L))))
})

test_that("Gaussian workload fragments are custodian-owned and signed", {
  fixture <- .capsule_manifest_test_fixture(2L)
  policy <- fixture$policies$peer_a
  policy$numeric_bounds$y_peer_a <- c(10, 20)
  policy$capsule_workload_specs$gaussian$gaussian_primary <- list(
    version = "v1", dataset = "data_peer_a", outcome = "y_peer_a",
    predictors = "x_peer_a", intercept = TRUE)
  json <- .dsvert_dp_capsule_manifest_draft_impl(
    .policy = policy, .signer = .capsule_manifest_test_signer)
  draft <- jsonlite::fromJSON(
    json, simplifyVector = FALSE, simplifyDataFrame = FALSE,
    simplifyMatrix = FALSE)
  spec <- draft$workload_fragments$gaussian$gaussian_primary
  expect_identical(spec$dataset, "data_peer_a")
  expect_identical(spec$outcome, "y_peer_a")
  expect_identical(unlist(spec$predictors, use.names = FALSE), "x_peer_a")
  expect_true(spec$intercept)
  expect_true(.capsule_manifest_test_verifier(
    .dsvert_dp_capsule_manifest_message(
      "draft", draft[setdiff(names(draft), "signature")]),
    policy$own_identity_pk, draft$signature))

  unsafe <- policy
  unsafe$capsule_workload_specs$gaussian$gaussian_primary$predictors <-
    "time_peer_b"
  expect_error(
    .dsvert_dp_capsule_manifest_draft_impl(
      .policy = unsafe, .signer = .capsule_manifest_test_signer),
    "not locally owned")
})

test_that("ambiguous multi-dataset policy rejects unless custodian mapping is exact", {
  fixture <- .capsule_manifest_test_fixture(2L)
  policy <- fixture$policies$peer_a
  policy$datasets$data_extra <- policy$datasets$data_peer_a
  policy$datasets$data_extra$id <- "cohort-extra"
  policy$numeric_bounds$x_extra <- c(-1, 1)
  expect_error(
    .dsvert_dp_capsule_manifest_draft_impl(
      .policy = policy, .signer = .capsule_manifest_test_signer),
    class = "dsvert_capsule_manifest_rejected")

  policy$capsule_dataset_mapping <- list(
    data_peer_a = c("arm", "x_peer_a"), data_extra = "x_extra")
  draft <- jsonlite::fromJSON(
    .dsvert_dp_capsule_manifest_draft_impl(
      .policy = policy, .signer = .capsule_manifest_test_signer),
    simplifyVector = TRUE, simplifyDataFrame = FALSE,
    simplifyMatrix = FALSE)
  expect_identical(
    draft$dataset_mapping_mode,
    "custodian_explicit_dataset_mapping_v1")
  expect_setequal(names(draft$datasets), names(policy$datasets))

  policy$capsule_dataset_mapping$data_extra <- "x_peer_a"
  expect_error(
    .dsvert_dp_capsule_manifest_draft_impl(
      .policy = policy, .signer = .capsule_manifest_test_signer),
    class = "dsvert_capsule_manifest_rejected")
})

test_that("schema tampering, invented snapshots and incomplete signatures fail typed", {
  fixture <- .capsule_manifest_test_fixture(3L)
  schema <- .capsule_manifest_test_schema(fixture)
  changed <- schema$unsigned
  changed$datasets$data_peer_a$columns$x_peer_a$upper <- 11
  expect_error(
    .dsvert_dp_capsule_manifest_sign_impl(
      .dsvert_dp_canonical_json(changed), schema$workload_json,
      .policy = fixture$policies$peer_a,
      .signer = .capsule_manifest_test_signer),
    class = "dsvert_capsule_manifest_rejected")

  changed_workload <- schema$workload
  changed_workload$describe$owner_a_describe$spec$
    histogram_grids$x_peer_a[[1L]] <- 6
  expect_error(
    .dsvert_dp_capsule_manifest_sign_impl(
      schema$unsigned_json,
      .dsvert_dp_canonical_json(changed_workload),
      .policy = fixture$policies$peer_a,
      .signer = .capsule_manifest_test_signer),
    class = "dsvert_capsule_manifest_rejected")

  changed_owner <- schema$workload
  changed_owner$describe$owner_a_describe$owner_peer <- "peer_b"
  expect_error(
    .dsvert_dp_capsule_manifest_sign_impl(
      schema$unsigned_json,
      .dsvert_dp_canonical_json(changed_owner),
      .policy = fixture$policies$peer_a,
      .signer = .capsule_manifest_test_signer),
    class = "dsvert_capsule_manifest_rejected")

  changed <- schema$unsigned
  changed$logical_snapshot$version <- "analyst-reroll"
  expect_error(
    .dsvert_dp_capsule_manifest_sign_impl(
      .dsvert_dp_canonical_json(changed), schema$workload_json,
      .policy = fixture$policies$peer_a,
      .signer = .capsule_manifest_test_signer),
    class = "dsvert_capsule_manifest_rejected")

  incomplete <- schema$signed
  incomplete$signatures$peer_c <- NULL
  cache <- .capsule_manifest_test_memory_cache()
  expect_error(
    .dsvert_dp_capsule_manifest_build_impl(
      .dsvert_dp_canonical_json(incomplete), schema$workload_json,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .signer = .capsule_manifest_test_signer,
      .verifier = .capsule_manifest_test_verifier,
      .cache_get = cache$get, .cache_put = cache$put),
    class = "dsvert_capsule_manifest_rejected")
})

test_that("durable memoization replays exact bytes and gates arbitrary manifests", {
  fixture <- .capsule_manifest_test_fixture(2L)
  schema <- .capsule_manifest_test_schema(fixture)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  first <- .dsvert_dp_capsule_manifest_build_impl(
    schema$signed_json, schema$workload_json,
    .policy = policy, .secret = secret,
    .signer = .capsule_manifest_test_signer,
    .verifier = .capsule_manifest_test_verifier)
  second <- testthat::with_mocked_bindings(
    .dsvert_dp_capsule_manifest_build_impl(
      schema$signed_json, schema$workload_json,
      .policy = policy, .secret = secret,
      .signer = .capsule_manifest_test_signer,
      .verifier = .capsule_manifest_test_verifier),
    .dsvert_dp_capsule_workload_manifest = function(...) {
      stop("memoized manifest was rebuilt")
    },
    .package = "dsVert")
  expect_identical(second, first)
  decoded <- jsonlite::fromJSON(
    first, simplifyVector = TRUE, simplifyDataFrame = FALSE,
    simplifyMatrix = FALSE)
  expect_silent(.dsvert_dp_capsule_manifest_require_built(
    policy, decoded$manifest_json, secret))

  changed_private_snapshot <- policy
  changed_private_snapshot$datasets$data_peer_a$snapshot_sha256 <-
    strrep("f", 64L)
  expect_error(
    .dsvert_dp_capsule_manifest_require_built(
      changed_private_snapshot, decoded$manifest_json, secret),
    class = "dsvert_capsule_manifest_rejected")
  expect_error(
    .dsvert_dp_capsule_manifest_build_impl(
      schema$signed_json, schema$workload_json,
      .policy = changed_private_snapshot, .secret = secret,
      .signer = .capsule_manifest_test_signer,
      .verifier = .capsule_manifest_test_verifier),
    class = "dsvert_capsule_manifest_rejected")

  arbitrary <- sub(
    paste0('"execution_state":"',
           'registered_lifecycle_available_requires_runtime_preflight"'),
    '"execution_state":"unregistered"',
    decoded$manifest_json, fixed = TRUE)
  expect_error(
    .dsvert_dp_capsule_manifest_require_built(policy, arbitrary, secret),
    class = "dsvert_capsule_manifest_rejected")
})

test_that("authenticated v4 cache rows remain readable for historical replay", {
  secret <- as.raw(rep(73L, 32L))
  manifest_json <- '{"version":"historical-v5-release"}'
  record <- .dsvert_dp_canonical_query_value(list(
    version = "dsvert-biomedical-capsule-manifest-cache-v4",
    cache_key = strrep("1", 64L),
    public_capsule_key = strrep("2", 64L),
    local_authority_sha256 = strrep("3", 64L),
    schema_sha256 = strrep("4", 64L),
    workload_contract_sha256 = strrep("5", 64L),
    manifest_sha256 = digest::digest(
      manifest_json, algo = "sha256", serialize = FALSE),
    manifest_json = manifest_json))
  json <- .dsvert_dp_canonical_json(record)
  row <- data.frame(
    cache_key = record$cache_key,
    public_capsule_key = record$public_capsule_key,
    manifest_sha256 = record$manifest_sha256,
    record_json = json,
    row_mac = .dsvert_capsule_registry_hmac(
      secret, "manifest-authority-cache", json),
    stringsAsFactors = FALSE)
  expect_identical(
    .dsvert_dp_capsule_manifest_cache_decode(row, secret), record)

  unsupported <- record
  unsupported$version <- "dsvert-biomedical-capsule-manifest-cache-v3"
  row$record_json <- .dsvert_dp_canonical_json(unsupported)
  row$row_mac <- .dsvert_capsule_registry_hmac(
    secret, "manifest-authority-cache", row$record_json)
  expect_error(
    .dsvert_dp_capsule_manifest_cache_decode(row, secret),
    class = "dsvert_capsule_manifest_rejected")
})
