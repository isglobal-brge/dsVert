.synopsis_test_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.synopsis_test_fixture <- function(
    data = data.frame(
      patient_id = c("u1", "u2", "u3"), x = c(1, 5, 9),
      stringsAsFactors = FALSE), lifetime = 8L, grid_bits = 8L,
    epsilon = 1, aligned = FALSE, k = 2L, auxiliary_data = NULL,
    reverse_resolved = FALSE) {
  stopifnot(k %in% 2:5)
  peer_names <- paste0("peer_", letters[seq_len(k)])
  pins <- stats::setNames(vapply(seq_len(k), function(index) {
    .synopsis_test_b64url(as.raw(
      32L * (index - 1L) + seq_len(32L)))
  }, character(1L)), peer_names)
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  descriptor <- list(
    id = "synopsis-cohort", version = "v1", snapshot_sha256 = NULL,
    alignment_manifest_hash = NULL, alignment_manifest_version = 1L)
  if (isTRUE(aligned)) {
    padded <- .dsvert_test_padded_dp_binding(
      data, "patient_id", descriptor$id, descriptor$version, pins)
    data <- padded$data
    descriptor <- padded$descriptor
  }
  policy <- list(
    domain = "synopsis-study", cohort_id = "cohort-v1",
    peer_name = "peer_a", peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = as.integer(k),
    designated_noise_peers = peer_names[1:2],
    lifetime_max_distinct_capsules = as.numeric(lifetime),
    global_total_epsilon = epsilon, global_total_delta = 1e-6,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 10L, fixed_cohort_size = NULL,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = as.integer(grid_bits),
    numeric_bounds = c(
      list(x = c(0, 10)),
      if (is.null(auxiliary_data)) list() else list(y = c(-5, 5))),
    categorical_levels = list(),
    capsule_workload_scope = list(
      mode = "catalog_v1", numeric_moments = "x",
      categorical_marginals = character(), categorical_pairs = list(),
      correlations = list()),
    datasets = c(
      list(protected = descriptor),
      if (is.null(auxiliary_data)) list() else list(auxiliary = list(
        id = "synopsis-auxiliary", version = "v1",
        snapshot_sha256 = NULL, alignment_manifest_hash = NULL,
        alignment_manifest_version = 1L))),
    noise_root = list(epoch = 1, key_id = "synopsis-test-root"),
    ledger_path = tempfile("synopsis-ledger-"))
  logical_snapshot <- list(
    logical_snapshot_id = "synopsis-aligned-cohort", version = "v1",
    alignment_protocol_version = 1L)
  schema_datasets <- list(protected = list(
    dataset_id = "synopsis-cohort", dataset_version = "v1",
    schema_version = "schema-v1", alignment_group = "aligned-main",
    patient_keys = list(peer_a = "patient_id"),
    columns = list(x = list(
      kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 10))))
  if (!is.null(auxiliary_data)) {
    schema_datasets$auxiliary <- list(
      dataset_id = "synopsis-auxiliary", dataset_version = "v1",
      schema_version = "schema-v1", alignment_group = "aligned-main",
      patient_keys = list(peer_a = "patient_id"),
      columns = list(y = list(
        kind = "numeric", owner_peer = "peer_a", lower = -5, upper = 5)))
  }
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash,
    datasets = schema_datasets,
    signatures = stats::setNames(lapply(seq_len(k), function(index) {
      strrep(LETTERS[[index]], 86L)
    }), peer_names))
  describe <- list(primary = list(
    version = "v1", dataset = "protected", variables = "x",
    histogram_grids = list(x = c(5, 10)),
    allocation = c(
      count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2)))
  manifest <- .dsvert_dp_capsule_workload_manifest(
    policy, logical_snapshot, schema, describe_specs = describe,
    survival_specs = list(), gaussian_specs = list(),
    .noise_selector = function(
        coordinate_count, laplace_epsilons, laplace_sensitivities,
        gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
        objective) {
      list(
        selector = .DSVERT_DP_NOISE_SELECTOR, objective = objective,
        coordinate_count = as.integer(coordinate_count), winner = "laplace",
        laplace = list(available = TRUE, simultaneous_95_abs = 10),
        gaussian = list(available = FALSE, simultaneous_95_abs = NULL))
    },
    .signature_verifier = function(...) TRUE,
    .gaussian_planner = function(...) stop("Gaussian unavailable"))
  binding <- .dsvert_dp_dataset_binding(
    policy, "protected", data, as.raw(seq_len(32L)))
  resolved <- list(protected = list(data = data, dataset = binding))
  if (!is.null(auxiliary_data)) {
    auxiliary_binding <- .dsvert_dp_dataset_binding(
      policy, "auxiliary", auxiliary_data, as.raw(seq_len(32L)))
    resolved$auxiliary <- list(
      data = auxiliary_data, dataset = auxiliary_binding)
  }
  if (isTRUE(reverse_resolved)) resolved <- rev(resolved)
  list(policy = policy, manifest = manifest, data = data,
       resolved = resolved, pins = pins, auxiliary_data = auxiliary_data)
}

.synopsis_test_names <- function(value) {
  if (!is.list(value)) return(character())
  c(names(value), unlist(lapply(value, .synopsis_test_names),
                         use.names = FALSE))
}

test_that("source-vector Claim binds only the effective local release", {
  fixture <- .synopsis_test_fixture()
  projection <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_catalog_projection_v1(
      fixture$policy, fixture$manifest),
    .dsvert_dp_resolve_snapshot = function(...) {
      stop("catalog projection resolved protected data")
    },
    .dsvert_dp_admit_units = function(...) {
      stop("catalog projection inspected protected units")
    },
    .package = "dsVert")

  expect_named(projection, c("version", "sha256", "catalog"))
  expect_identical(projection$catalog$primitive_scope$mode, "catalog_v1")
  expect_match(projection$sha256, "^[0-9a-f]{64}$")
  expect_false(any(.synopsis_test_names(projection) %in% c(
    "analysis_id", "method", "probs", "session_id", "operation_id",
    "lifetime_max_distinct_capsules", "privacy_epoch", "noise_key_id",
    "registered_release_lifecycle", "reuse_and_composition",
    "execution_state")))

  different_lifetime <- .synopsis_test_fixture(lifetime = 4L)
  expect_identical(
    .dsvert_dp_synopsis_catalog_projection_v1(
      different_lifetime$policy, different_lifetime$manifest),
    projection)
  different_grid <- .synopsis_test_fixture(grid_bits = 9L)
  different_grid_projection <- .dsvert_dp_synopsis_catalog_projection_v1(
    different_grid$policy, different_grid$manifest)
  expect_false(identical(
    different_grid_projection$sha256,
    projection$sha256))
  # This is intentionally only the catalog-and-layout projection.  The final
  # compiler must add calibration, draw-law/backend and authority roles.
  different_epsilon <- .synopsis_test_fixture(epsilon = 0.5)
  expect_identical(
    .dsvert_dp_synopsis_catalog_projection_v1(
      different_epsilon$policy, different_epsilon$manifest),
    projection)

  mint <- function(input) {
    state <- new.env(parent = emptyenv())
    state$message <- NULL
    signature <- .synopsis_test_b64url(as.raw(rep(83L, 64L)))
    signer <- function(message, identity_sk) {
      state$message <- message; signature
    }
    verifier <- function(message, identity_pk, signed) {
      identical(message, state$message) &&
        identical(identity_pk, unname(input$pins[["peer_a"]])) &&
        identical(signed, signature)
    }
    claim <- testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_source_vector_claim_v1(
        input$policy, input$manifest, input$resolved,
        list(
          identity_pk = input$pins[["peer_a"]],
          identity_sk = "test-secret"),
        .signer = signer, .verifier = verifier),
      .dsvert_dp_analysis_snapshot_key_v1 = function() as.raw(seq_len(32L)),
      .package = "dsVert")
    expect_identical(
      .dsvert_dp_synopsis_source_vector_claim_validate_v1(
        claim, .dsvert_dp_synopsis_catalog_projection_v1(
          input$policy, input$manifest), input$pins,
        .verifier = verifier),
      claim)
    claim
  }

  expect_named(claim <- mint(fixture), c(
    "version", "source_peer_name", "source_identity_pk",
    "catalog_sha256", "source_vector_commitment", "signature"))
  expect_false(any(.synopsis_test_names(claim) %in% c(
    "datasets", "fingerprint", "protected_fingerprint",
    "snapshot_binding_sha256", "capsule_id", "source_context_hash",
    "release_blocks", "cross_blocks", "block_hashes", "values_sha256",
    "values")))

  ignored <- fixture$data
  ignored$unused <- c("changed", "but", "irrelevant")
  ignored_fixture <- .synopsis_test_fixture(data = ignored)
  expect_identical(
    mint(ignored_fixture)$source_vector_commitment,
    claim$source_vector_commitment)

  auxiliary <- data.frame(
    patient_id = c("u1", "u2", "u3"), y = c(-2, 0, 2),
    stringsAsFactors = FALSE)
  multi <- .synopsis_test_fixture(
    auxiliary_data = auxiliary, reverse_resolved = TRUE)
  multi_commitment <- mint(multi)$source_vector_commitment
  ordered <- .synopsis_test_fixture(auxiliary_data = auxiliary)
  expect_identical(names(multi$resolved), rev(names(ordered$resolved)))
  expect_identical(
    mint(ordered)$source_vector_commitment,
    multi_commitment)
  auxiliary$y[[2L]] <- 1
  unused_changed <- .synopsis_test_fixture(
    auxiliary_data = auxiliary, reverse_resolved = TRUE)
  expect_false(identical(
    multi$resolved$auxiliary$dataset$fingerprint,
    unused_changed$resolved$auxiliary$dataset$fingerprint))
  expect_identical(
    mint(unused_changed)$source_vector_commitment,
    multi_commitment)

  changed <- fixture$data
  changed$x[[1L]] <- changed$x[[1L]] + 1
  changed_claim <- mint(.synopsis_test_fixture(data = changed))
  expect_false(identical(changed_claim$source_vector_commitment,
    claim$source_vector_commitment))

  for (k in c(2L, 3L, 5L)) {
    input <- .synopsis_test_fixture(k = k)
    source_claim <- mint(input)
    claim_set <- .dsvert_dp_synopsis_source_claim_set_v1(
      input$policy, input$manifest, list(source_claim),
      .verifier = function(...) TRUE)
    expect_named(claim_set, c(
      "version", "sha256", "projection", "claims"))
    expect_named(claim_set$claims, "peer_a")
    expect_match(claim_set$sha256, "^[0-9a-f]{64}$")
    expect_identical(
      .dsvert_dp_synopsis_source_claim_set_validate_v1(
        claim_set, input$policy, input$manifest,
        .verifier = function(...) TRUE),
      claim_set)
    if (k == 2L) {
      tampered_set <- claim_set
      tampered_set$sha256 <- strrep("f", 64L)
      expect_error(
        .dsvert_dp_synopsis_source_claim_set_validate_v1(
          tampered_set, input$policy, input$manifest,
          .verifier = function(...) TRUE),
        "hash")
    }
  }

  bad_signature <- claim
  bad_signature$signature <- .synopsis_test_b64url(as.raw(rep(84L, 64L)))
  expect_error(
    .dsvert_dp_synopsis_source_vector_claim_validate_v1(
      bad_signature, projection, fixture$pins,
      .verifier = function(...) FALSE),
    "signature")
  expect_error(
    .dsvert_dp_synopsis_source_vector_claim_validate_v1(
      claim, different_grid_projection, fixture$pins,
      .verifier = function(...) TRUE),
    "catalog")
})

test_that("source-vector evidence borrows its producer without owning it", {
  fixture <- .synopsis_test_fixture()
  identity <- list(
    identity_pk = fixture$pins[["peer_a"]], identity_sk = "test-secret")
  signature <- .synopsis_test_b64url(as.raw(rep(83L, 64L)))
  claim <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_source_vector_claim_v1(
      fixture$policy, fixture$manifest, fixture$resolved, identity,
      .signer = function(...) signature,
      .verifier = function(...) TRUE),
    .dsvert_dp_analysis_snapshot_key_v1 = function() as.raw(seq_len(32L)),
    .package = "dsVert")

  producer <- .dsvert_dp_gaussian_cross_source_producer(
    fixture$policy, fixture$manifest, fixture$resolved,
    compute_commitment = FALSE, include_release = TRUE)
  reset_count <- 0L
  borrowed <- producer
  borrowed$reset <- function() {
    reset_count <<- reset_count + 1L
    producer$reset()
  }
  unsigned <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_source_vector_unsigned_from_producer_v1(
      fixture$policy, fixture$manifest, borrowed,
      fixture$pins[["peer_a"]]),
    .dsvert_dp_analysis_snapshot_key_v1 = function() as.raw(seq_len(32L)),
    .package = "dsVert")
  expect_identical(unsigned, claim[setdiff(names(claim), "signature")])
  expect_identical(reset_count, 0L)

  wrong_layout <- borrowed
  wrong_layout$coordinate_order_sha256 <- strrep("f", 64L)
  expect_error(
    .dsvert_dp_synopsis_source_vector_unsigned_from_producer_v1(
      fixture$policy, fixture$manifest, wrong_layout,
      fixture$pins[["peer_a"]]),
    "layout")
  expect_identical(reset_count, 0L)
  producer$reset()

  invalid_projection <- .dsvert_dp_synopsis_catalog_projection_v1(
    fixture$policy, fixture$manifest)
  invalid_projection$catalog$coordinate_count <-
    invalid_projection$catalog$coordinate_count + 1L
  events <- character()
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_source_vector_claim_v1(
      fixture$policy, fixture$manifest, fixture$resolved, identity,
      .signer = function(...) signature,
      .verifier = function(...) TRUE),
    .dsvert_dp_synopsis_catalog_projection_v1 = function(...) {
      events <<- c(events, "catalog_validation")
      invalid_projection
    },
    .dsvert_dp_gaussian_cross_source_producer = function(...) {
      events <<- c(events, "producer_materialization")
      list(reset = function() {
        events <<- c(events, "producer_reset")
      })
    },
    .package = "dsVert"), "release layout")
  expect_identical(events, "catalog_validation")
})

test_that("catalog projection namespaces signed catalog analysis IDs", {
  fixture <- .synopsis_test_fixture()
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  project <- function(entry_id) {
    manifest <- fixture$manifest
    manifest$workload$families$gaussian_models$artifacts$cross_probe <- list(
      analysis_id = entry_id)
    manifest$workload$vertical_crosses$cross_probe <- list(
      analysis_id = entry_id)
    testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_catalog_projection_v1(fixture$policy, manifest),
      .dsvert_dp_capsule_materializer_manifest = function(...) {
        list(manifest = manifest, layout = layout)
      },
      .package = "dsVert")
  }

  first <- project("cross_a")
  second <- project("cross_b")
  expect_false("analysis_id" %in% .synopsis_test_names(first$catalog))
  expect_true("catalog_entry_id" %in% .synopsis_test_names(first$catalog))
  expect_false(identical(first$sha256, second$sha256))
  expect_error(.dsvert_dp_synopsis_catalog_ids_v1(list(
    analysis_id = "a", catalog_entry_id = "b")), "collision")
  raw <- first
  probe <- raw$catalog$families$gaussian_models$artifacts$cross_probe
  probe$analysis_id <- probe$catalog_entry_id
  probe$catalog_entry_id <- NULL
  raw$catalog$families$gaussian_models$artifacts$cross_probe <- probe
  raw$sha256 <- .dsvert_dp_synopsis_catalog_hash_v1(raw$catalog)
  expect_error(.dsvert_dp_synopsis_catalog_projection_validate_v1(raw),
               "Operational request fields")
})

test_that("source-vector HMAC selects semantic blocks, not transport shape", {
  fixture <- .synopsis_test_fixture()
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(
    fixture$policy, fixture$manifest)
  release <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  identity <- list(identity_pk = fixture$pins[["peer_a"]],
                   identity_sk = "test-secret")
  signature <- .synopsis_test_b64url(as.raw(rep(83L, 64L)))

  mint <- function(shift = 0L, local_delta = 0, release_delta = 0,
                   remote_delta = 0, owns_release = TRUE) {
    semantic_release <- release
    if (!isTRUE(owns_release)) {
      semantic_release$blocks <- lapply(semantic_release$blocks,
        function(block) { block$owner_peer <- "peer_b"; block })
    }
    local_one_hot <- "categorical::analysis::left::one_hot"
    local_validity <- "categorical::analysis::left::validity"
    remote_validity <- "categorical::analysis::right::validity"
    private <- list(
      categorical..analysis..right..validity = list(
        start = release$coordinate_count + shift + 7L, length = 2L,
        owner_peer = "peer_b"), categorical..analysis..left..validity = list(
        start = release$coordinate_count + shift + 5L, length = 2L,
        owner_peer = "peer_a"), categorical..analysis..left..one_hot = list(
        start = release$coordinate_count + shift + 3L, length = 2L,
        owner_peer = "peer_a"))
    names(private) <- c(remote_validity, local_validity, local_one_hot)
    cross <- list(
      release_coordinate_count = release$coordinate_count,
      release_coordinate_order_sha256 = release$sha256,
      transport_coordinate_count = max(vapply(
        private, function(block) block$start + block$length - 1L,
        numeric(1L))),
      transport_coordinate_order_sha256 = strrep("9", 64L),
      padding_coordinates = shift + 2L, blocks = private)
    block_values <- c(
      stats::setNames(lapply(names(semantic_release$blocks), function(key) {
        values <- rep(match(key, sort(names(release$blocks))),
                      semantic_release$blocks[[key]]$length)
        if (identical(key, sort(names(release$blocks))[[1L]])) {
          values[[1L]] <- values[[1L]] + release_delta
        }
        values
      }), names(release$blocks)),
      stats::setNames(list(
        c(11 + local_delta, 12), c(21, 22),
        c(31 + remote_delta, 32)),
        c(local_one_hot, local_validity, remote_validity)))
    calls <- character()
    include_release_seen <- NULL
    producer <- function(
        policy, manifest, resolved_snapshots, compute_commitment,
        include_release) {
      include_release_seen <<- include_release
      release_values <- numeric(semantic_release$coordinate_count)
      for (key in names(semantic_release$blocks)) {
        block <- semantic_release$blocks[[key]]
        release_values[block$start:block$end] <- block_values[[key]]
      }
      list(
        coordinate_count = cross$transport_coordinate_count,
        coordinate_order_sha256 = cross$transport_coordinate_order_sha256,
        read_range = function(start, count) {
          if (start <= semantic_release$coordinate_count) {
            if (!isTRUE(include_release) ||
                start + count - 1L > semantic_release$coordinate_count) {
              stop("unexpected source-vector release range")
            }
            calls <<- c(calls, paste(
              "release", start, count, sep = ":"))
            return(release_values[seq.int(start, length.out = count)])
          }
          key <- names(private)[vapply(private, function(block) {
            identical(as.numeric(block$start), as.numeric(start)) &&
              identical(as.numeric(block$length), as.numeric(count))
          }, logical(1L))]
          if (length(key) != 1L) stop("unexpected source-vector range")
          calls <<- c(calls, key)
          block_values[[key]]
        },
        reset = function() invisible(NULL))
    }
    claim <- testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_source_vector_claim_v1(
        fixture$policy, fixture$manifest, fixture$resolved, identity,
        .signer = function(...) signature,
        .verifier = function(...) TRUE),
      .dsvert_dp_synopsis_catalog_projection_v1 = function(...) projection,
      .dsvert_dp_capsule_coordinate_layout = function(...) semantic_release,
      .dsvert_dp_gaussian_cross_layout = function(...) cross,
      .dsvert_dp_gaussian_cross_source_producer = producer,
      .dsvert_dp_analysis_snapshot_key_v1 = function() as.raw(seq_len(32L)),
      .package = "dsVert")
    list(claim = claim, calls = calls,
         include_release = include_release_seen)
  }

  baseline <- mint()
  expect_identical(baseline$calls, c(paste(
    "release", 1L, release$coordinate_count, sep = ":"),
    "categorical::analysis::left::one_hot",
    "categorical::analysis::left::validity"))
  expect_identical(
    mint(shift = 19L, remote_delta = 100)$claim$source_vector_commitment,
    baseline$claim$source_vector_commitment)
  expect_false(identical(
    mint(local_delta = 1)$claim$source_vector_commitment,
    baseline$claim$source_vector_commitment))
  expect_false(identical(
    mint(release_delta = 1)$claim$source_vector_commitment,
    baseline$claim$source_vector_commitment))

  cross_only <- mint(owns_release = FALSE)
  expect_false(cross_only$include_release)
  expect_false(any(names(release$blocks) %in% cross_only$calls))
  expect_identical(
    mint(owns_release = FALSE, release_delta = 100)$claim$
      source_vector_commitment,
    cross_only$claim$source_vector_commitment)

  ranges <- matrix(numeric(), ncol = 2L)
  large <- .dsvert_dp_synopsis_source_vector_blocks_v1(
    list(read_range = function(start, count) {
      ranges <<- rbind(ranges, c(start, count))
      rep(7, count)
    }),
    list(large = list(start = 17L, length = 65539L)), "large")
  expect_equal(ranges, rbind(c(17, 65536), c(65553, 3)))
  expect_length(large$large$block_hashes, 2L)
  different_transport_block <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_source_vector_blocks_v1(list(
      read_range = function(start, count) rep(7, count)), list(
        large = list(start = 17L, length = 65539L)), "large"),
    .DSVERT_DP_CAPSULE_VALUE_BLOCK = 2L,
    .package = "dsVert")
  expect_identical(different_transport_block, large)
})

test_that("local synopsis Claim authorizes the manifest before source access", {
  fixture <- .synopsis_test_fixture()
  manifest_json <- .dsvert_dp_canonical_json(fixture$manifest)
  manifest_sha256 <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  secret <- as.raw(seq_len(32L))
  events <- character()
  cache_get <- function(
      policy, secret, cache_key = NULL, manifest_sha256 = NULL) {
    events <<- c(events, "manifest_authorized")
    .dsvert_dp_capsule_manifest_cache_record(
      cache_key = strrep("1", 64L),
      public_capsule_key = strrep("2", 64L),
      local_authority_sha256 =
        .dsvert_dp_capsule_manifest_local_authority(policy, secret),
      schema_sha256 = strrep("3", 64L),
      workload_contract_sha256 = strrep("4", 64L),
      manifest_json = manifest_json)
  }
  resolver <- function(policy, data_name, envir, secret) {
    events <<- c(events, paste0("resolved:", data_name))
    fixture$resolved[[data_name]]
  }
  state <- new.env(parent = emptyenv())
  state$message <- NULL
  signature <- .synopsis_test_b64url(as.raw(rep(83L, 64L)))
  signer <- function(message, identity_sk) {
    state$message <- message
    signature
  }
  verifier <- function(message, identity_pk, signed) {
    identical(message, state$message) &&
      identical(identity_pk, unname(fixture$pins[["peer_a"]])) &&
      identical(signed, signature)
  }
  identity <- list(
    identity_pk = fixture$pins[["peer_a"]], identity_sk = "test-secret")

  result <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_local_claim_v1(
      manifest_sha256, .policy = fixture$policy,
      .secret = secret, .envir = environment(),
      .identity = identity, .cache_get = cache_get,
      .resolver = resolver, .signer = signer, .verifier = verifier),
    .dsvert_dp_analysis_snapshot_key_v1 = function() {
      as.raw(seq_len(32L))
    },
    .dsvert_dp_capsule_manifest_local_authority = function(...) {
      strrep("a", 64L)
    },
    .package = "dsVert")
  expect_named(result, c("version", "projection", "claim"))
  expect_identical(events, c("manifest_authorized", "resolved:protected"))
  expect_identical(result$claim$catalog_sha256, result$projection$sha256)

  events <- character()
  expect_error(
    .dsvert_dp_synopsis_local_claim_v1(
      manifest_sha256, .policy = fixture$policy,
      .secret = secret, .envir = environment(),
      .identity = identity,
      .cache_get = function(...) {
        events <<- c(events, "manifest_rejected")
        NULL
      },
      .resolver = function(...) {
        events <<- c(events, "source_accessed")
        stop("source accessed")
      },
      .signer = signer, .verifier = verifier),
    "not emitted|not server authorized")
  expect_identical(events, "manifest_rejected")

  events <- character()
  expect_error(
    testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_local_claim_v1(
        manifest_sha256, .policy = fixture$policy,
        .secret = secret, .envir = environment(),
        .identity = list(
          identity_pk = fixture$pins[["peer_b"]],
          identity_sk = "wrong-source-secret"),
        .cache_get = cache_get,
        .resolver = function(...) {
          events <<- c(events, "source_accessed")
          stop("source accessed")
        },
        .signer = signer, .verifier = verifier),
      .dsvert_dp_capsule_manifest_local_authority = function(...) {
        strrep("a", 64L)
      },
      .package = "dsVert"),
    "not pinned")
  expect_identical(events, "manifest_authorized")

  events <- character()
  expect_error(
    testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_local_claim_v1(
        manifest_sha256, .policy = fixture$policy,
        .secret = secret, .envir = environment(),
        .identity = identity,
        .cache_get = function(...) {
          record <- cache_get(...)
          record$version <- rep(record$version, 2L)
          record
        },
        .resolver = function(...) {
          events <<- c(events, "source_accessed")
          stop("source accessed")
        },
        .signer = signer, .verifier = verifier),
      .dsvert_dp_capsule_manifest_local_authority = function(...) {
        strrep("a", 64L)
      },
      .package = "dsVert"),
    "not emitted|not server authorized")
  expect_identical(events, "manifest_authorized")

  oversized_policy <- fixture$policy
  oversized_policy$datasets <- stats::setNames(
    rep(list(fixture$policy$datasets$protected), 4097L),
    sprintf("dataset_%04d", seq_len(4097L)))
  events <- character()
  expect_error(
    testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_local_claim_v1(
        manifest_sha256, .policy = oversized_policy,
        .secret = secret, .envir = environment(),
        .identity = identity, .cache_get = cache_get,
        .resolver = function(...) {
          events <<- c(events, "source_accessed")
          stop("source accessed")
        },
        .signer = signer, .verifier = verifier),
      .dsvert_dp_capsule_manifest_local_authority = function(...) {
        strrep("a", 64L)
      },
      .dsvert_dp_synopsis_catalog_projection_v1 = function(...) {
        result$projection
      },
      .dsvert_dp_capsule_source_contract = function(...) {
        list(source_peers = list("peer_a"))
      },
      .package = "dsVert"),
    "dataset registry")
  expect_identical(events, "manifest_authorized")
  expect_false(any(c("manifest_json", "resolved_snapshots") %in%
                     names(formals(.dsvert_dp_synopsis_local_claim_v1))))
})
