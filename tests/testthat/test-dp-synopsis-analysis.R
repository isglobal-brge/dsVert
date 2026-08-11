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

test_that("stateless synopsis Claim binds one catalog to the real snapshot", {
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
  # artifact compiler must add calibration, sampler plan and authority roles.
  different_epsilon <- .synopsis_test_fixture(epsilon = 0.5)
  expect_identical(
    .dsvert_dp_synopsis_catalog_projection_v1(
      different_epsilon$policy, different_epsilon$manifest),
    projection)

  signed_message <- NULL
  test_signature <- .synopsis_test_b64url(as.raw(rep(83L, 64L)))
  signer <- function(message, identity_sk) {
    signed_message <<- message
    test_signature
  }
  verifier <- function(message, identity_pk, signature) {
      identical(message, signed_message) &&
      identical(identity_pk, unname(fixture$pins[["peer_a"]])) &&
      identical(signature, test_signature)
  }
  identity <- list(
    identity_pk = fixture$pins[["peer_a"]], identity_sk = "test-secret")
  claim <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_snapshot_claim_v1(
      fixture$policy, fixture$manifest, fixture$resolved, identity,
      .signer = signer, .verifier = verifier),
    .dsvert_dp_analysis_snapshot_key_v1 = function() {
      as.raw(seq_len(32L))
    },
    .dsvert_dp_admit_units = function(...) {
      stop("snapshot Claim materialized protected coordinates")
    },
    .package = "dsVert")
  expect_identical(
    .dsvert_dp_synopsis_snapshot_claim_validate_v1(
      claim, projection, fixture$pins, .verifier = verifier),
    claim)
  expect_named(claim, c(
    "version", "source_peer_name", "source_identity_pk",
    "peer_pinset_sha256", "catalog_sha256", "datasets",
    "snapshot_set_commitment", "signature"))
  expect_named(claim$datasets$protected, c(
    "dataset_key", "dataset_id", "dataset_version",
    "alignment_attested", "alignment_protocol_version"))
  expect_false(any(.synopsis_test_names(claim) %in% c(
    "fingerprint", "protected_fingerprint", "snapshot_sha256",
    "alignment_manifest_hash", "values")))

  bad_signature <- claim
  bad_signature$signature <- .synopsis_test_b64url(as.raw(rep(84L, 64L)))
  expect_error(
    .dsvert_dp_synopsis_snapshot_claim_validate_v1(
      bad_signature, projection, fixture$pins, .verifier = verifier),
    "signature")
  expect_error(
    .dsvert_dp_synopsis_snapshot_claim_validate_v1(
      claim, different_grid_projection, fixture$pins,
      .verifier = verifier),
    "catalog")

  aligned <- .synopsis_test_fixture(aligned = TRUE)
  alignment_sentinel <-
    aligned$policy$datasets$protected$alignment_manifest_hash
  signed_message <- NULL
  aligned_claim <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_snapshot_claim_v1(
      aligned$policy, aligned$manifest, aligned$resolved, identity,
      .signer = signer, .verifier = verifier),
    .dsvert_dp_analysis_snapshot_key_v1 = function() {
      as.raw(seq_len(32L))
    },
    .package = "dsVert")
  expect_true(aligned_claim$datasets$protected$alignment_attested)
  expect_false(grepl(
    alignment_sentinel, .dsvert_dp_canonical_json(aligned_claim),
    fixed = TRUE))

  changed <- fixture$data
  changed$x[[1L]] <- changed$x[[1L]] + 1
  changed_fixture <- .synopsis_test_fixture(data = changed)
  signed_message <- NULL
  changed_claim <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_snapshot_claim_v1(
      changed_fixture$policy, changed_fixture$manifest,
      changed_fixture$resolved, identity,
      .signer = signer, .verifier = verifier),
    .dsvert_dp_analysis_snapshot_key_v1 = function() {
      as.raw(seq_len(32L))
    },
    .package = "dsVert")
  expect_identical(changed_claim$catalog_sha256, claim$catalog_sha256)
  expect_false(identical(
    changed_claim$snapshot_set_commitment,
    claim$snapshot_set_commitment))

  tampered <- claim
  tampered$catalog_sha256 <- strrep("f", 64L)
  expect_error(
    .dsvert_dp_synopsis_snapshot_claim_validate_v1(
      tampered, projection, fixture$pins, .verifier = verifier),
    "catalog")
  wrong_pins <- fixture$pins
  wrong_pins[["peer_a"]] <- fixture$pins[["peer_b"]]
  expect_error(
    .dsvert_dp_synopsis_snapshot_claim_validate_v1(
      claim, projection, wrong_pins, .verifier = verifier),
    "pinned|pinset")
})

test_that("synopsis Claims canonicalize K peers and multiple local datasets", {
  mint <- function(fixture) {
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
    projection <- .dsvert_dp_synopsis_catalog_projection_v1(
      fixture$policy, fixture$manifest)
    claim <- testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_snapshot_claim_v1(
        fixture$policy, fixture$manifest, fixture$resolved,
        list(
          identity_pk = fixture$pins[["peer_a"]],
          identity_sk = "test-secret"),
        .signer = signer, .verifier = verifier),
      .dsvert_dp_analysis_snapshot_key_v1 = function() {
        as.raw(seq_len(32L))
      },
      .package = "dsVert")
    expect_identical(
      .dsvert_dp_synopsis_snapshot_claim_validate_v1(
        claim, projection, fixture$pins, .verifier = verifier),
      claim)
    claim
  }

  for (k in c(3L, 5L)) {
    fixture <- .synopsis_test_fixture(k = k)
    claim <- mint(fixture)
    expect_identical(
      claim$peer_pinset_sha256,
      .dsvert_dp_synopsis_pinset_hash_v1(fixture$pins))
  }

  auxiliary <- data.frame(
    patient_id = c("u1", "u2", "u3"), y = c(-2, 0, 2),
    stringsAsFactors = FALSE)
  multi <- .synopsis_test_fixture(
    auxiliary_data = auxiliary, reverse_resolved = TRUE)
  first <- mint(multi)
  expect_identical(names(first$datasets), c("auxiliary", "protected"))

  auxiliary$y[[2L]] <- 1
  changed <- .synopsis_test_fixture(
    auxiliary_data = auxiliary, reverse_resolved = TRUE)
  second <- mint(changed)
  expect_identical(first$catalog_sha256, second$catalog_sha256)
  expect_false(identical(
    first$snapshot_set_commitment, second$snapshot_set_commitment))
  expect_false(any(.synopsis_test_names(first) %in% c(
    "fingerprint", "protected_fingerprint", "snapshot_sha256",
    "alignment_manifest_hash", "values")))
})
