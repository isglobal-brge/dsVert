.analysis_contract_identity_pk <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.analysis_contract_fixture <- function(k = 2L) {
  owners <- paste0("site_", seq_len(k))
  pins <- setNames(vapply(
    seq_along(owners), .analysis_contract_identity_pk, character(1L)),
    owners)
  snapshots <- setNames(lapply(seq_along(owners), function(index) {
    list(
      version = "dsvert-analysis-snapshot-v1",
      dataset_id = "cohort_table",
      dataset_version = "v1",
      snapshot_commitment = strrep(sprintf("%x", index), 64L)
    )
  }), unname(pins))
  list(
    semantic = list(
      version = "dsvert-analysis-semantic-v1",
      domain = "study-domain",
      cohort_id = "cohort-v1",
      owner_snapshots = snapshots,
      noise_authorities = unname(pins[seq_len(2L)]),
      analysis = list(
        primitive = "glm-binomial-logit-v1",
        formula = list(
          response = "outcome", intercept = TRUE,
          terms = list("age", "treatment")),
        effective_arguments = list(
          link = "logit", missing = "complete_case")),
      privacy = list(
        version = "dsvert-per-analysis-dp-v1",
        adjacency = "add_remove_patient",
        privacy_unit = "patient",
        contribution = list(
          version = "dsvert-contribution-policy-v1",
          max_records_per_unit = 1,
          overflow_policy = "reject_operation",
          constraints = list(
            version = "dsvert-contribution-constraints-v1",
            policy_sha256 = strrep("c", 64L))),
        mechanism = list(
          family = "gaussian",
          version = "gaussian-output-perturbation-v1",
          sensitivity = list(
            version = "dsvert-sensitivity-v1",
            norm = "l2",
            value = 1),
          calibration = list(
            version = "dsvert-calibration-v1",
            noise_scale = 5,
            sampler = "gaussian-one-draw-v1",
            implementation_delta = 1e-9),
          randomness = list(
            version = "dsvert-randomness-plan-v1",
            lanes = list(
              final_noise = list(
                version = "dsvert-randomness-lane-v1",
                purpose = "privatize_final_vector",
                primitive = "gaussian-one-draw-v1",
                coordinates = 3)))),
        epsilon = 1,
        delta = 1e-6),
      numeric = list(
        version = "dsvert-numeric-semantics-v1",
        value_bits = 120,
        fractional_bits = 32,
        rounding = "nearest_even",
        overflow = "reject",
        sampler_encoding = "chacha20_absolute_coordinate_v1",
        output_encoding = "fixed_point_v1"),
      public_shape = list(coefficients = 3, covariance = c(3, 3))),
    execution = list(
      version = "dsvert-analysis-execution-v1",
      peer_pins = as.list(pins),
      backend = list(
        kernel = "glm-binomial-logit-v1",
        ring = "ring127",
        build_sha256 = strrep("a", 64L)),
      transport = list(chunk_coordinates = 4096)))
}

.analysis_count_contract_fixture <- function(k = 2L) {
  fixture <- .analysis_contract_fixture(k)
  fixture$semantic$analysis$primitive <- "joint-dp-laplace-v2"
  fixture$semantic$analysis["formula"] <- list(NULL)
  fixture$semantic$analysis$effective_arguments <- list(
    statistic = "admitted_privacy_unit_count")
  fixture$semantic$privacy$mechanism <- list(
    family = "discrete_laplace",
    version = "discrete-laplace-output-perturbation-tv-v2",
    sensitivity = list(
      version = "dsvert-sensitivity-v1", norm = "l1", value = 1),
    calibration = list(
      version = "dsvert-calibration-v1",
      noise_scale = 1,
      sampler = "hkdf-sha256-aes128ctr-two-geometric-tv-v2",
      implementation_delta = 1e-9),
    randomness = list(
      version = "dsvert-randomness-plan-v1",
      lanes = list(
        final_noise = list(
          version = "dsvert-randomness-lane-v1",
          purpose = "privatize_final_vector",
          primitive = "hkdf-sha256-aes128ctr-two-geometric-tv-v2",
          coordinates = 1))))
  fixture$semantic$privacy$epsilon <- 1
  fixture$semantic$privacy$delta <- 1e-6
  fixture$semantic$numeric <- list(
    version = "dsvert-numeric-semantics-v1",
    value_bits = 127,
    fractional_bits = 0,
    rounding = "toward_zero",
    overflow = "reject",
    sampler_encoding = "aes128ctr_integer_coordinate_v2",
    output_encoding = "twos_complement_integer_v1")
  fixture$semantic$public_shape <- list(count = 1)
  fixture$execution$backend$kernel <- "joint-dp-laplace-v2"
  fixture$execution$backend$ring <- "ring127"
  fixture
}

test_that("Count TV contracts are canonical and fail closed for K=2,3,5", {
  contracts <- lapply(c(2L, 3L, 5L), function(k) {
    fixture <- .analysis_count_contract_fixture(k)
    .dsvert_dp_analysis_contract_v1(fixture$semantic, fixture$execution)
  })
  expect_true(all(vapply(contracts, function(contract) {
    identical(contract$semantic$numeric$fractional_bits, 0) &&
      identical(contract$semantic$numeric$value_bits, 127) &&
      identical(contract$semantic$numeric$overflow, "reject") &&
      identical(contract,
                .dsvert_dp_analysis_contract_validate_v1(contract))
  }, logical(1L))))
  calibration <- contracts[[1L]]$semantic$privacy$mechanism$calibration
  expect_lt(calibration$implementation_delta,
            contracts[[1L]]$semantic$privacy$delta)

  fixture <- .analysis_count_contract_fixture(3L)
  original <- .dsvert_dp_analysis_contract_v1(
    fixture$semantic, fixture$execution)
  expect_identical(
    original$artifact_key,
    "f930efe30f04bd6c2d118c4c69ae82a43cd15f62703b91b43ae99d464133e6b0")
  expect_identical(
    .dsvert_dp_analysis_contract_v1(
      fixture$semantic[rev(names(fixture$semantic))],
      fixture$execution[rev(names(fixture$execution))]),
    original)

  invalid <- list(
    sampler = function(x) {
      x$semantic$privacy$mechanism$calibration$sampler <-
        "discrete-laplace-one-draw-v1"
      x$semantic$privacy$mechanism$randomness$lanes$final_noise$primitive <-
        "discrete-laplace-one-draw-v1"
      x
    },
    mechanism = function(x) {
      x$semantic$privacy$mechanism$version <-
        "discrete-laplace-output-perturbation-v1"
      x
    },
    legacy_pair = function(x) {
      x$semantic$privacy$mechanism$version <-
        "discrete-laplace-output-perturbation-v1"
      x$semantic$privacy$mechanism$calibration$sampler <-
        "discrete-laplace-one-draw-v1"
      x$semantic$privacy$mechanism$calibration$implementation_delta <- 0
      x$semantic$privacy$mechanism$randomness$lanes$final_noise$primitive <-
        "discrete-laplace-one-draw-v1"
      x
    },
    zero_implementation_delta = function(x) {
      x$semantic$privacy$mechanism$calibration$implementation_delta <- 0
      x
    },
    zero_delta = function(x) {
      x$semantic$privacy$delta <- 0
      x$semantic$privacy$mechanism$calibration$implementation_delta <- 0
      x
    },
    excessive_implementation_delta = function(x) {
      x$semantic$privacy$mechanism$calibration$implementation_delta <- 2e-6
      x
    },
    insufficient_scale = function(x) {
      x$semantic$privacy$mechanism$calibration$noise_scale <- 1 - 1e-12
      x
    },
    overflowing_scale = function(x) {
      x$semantic$privacy$mechanism$sensitivity$value <- 1e308
      x$semantic$privacy$mechanism$calibration$noise_scale <- 1e308
      x$semantic$privacy$epsilon <- 1e-308
      x
    },
    nonnumeric_certificate = function(x) {
      x$semantic$privacy$mechanism$calibration$implementation_delta <- "1e-9"
      x
    },
    saturating_overflow = function(x) {
      x$semantic$numeric$overflow <- "saturate"
      x
    },
    vector_noise = function(x) {
      x$semantic$privacy$mechanism$randomness$lanes$final_noise$coordinates <-
        2
      x
    },
    nonunit_sensitivity = function(x) {
      x$semantic$privacy$mechanism$sensitivity$value <- 2
      x$semantic$privacy$mechanism$calibration$noise_scale <- 2
      x
    },
    extra_lane = function(x) {
      x$semantic$privacy$mechanism$randomness$lanes$internal <- list(
        version = "dsvert-randomness-lane-v1",
        purpose = "confidential_internal_randomness",
        primitive = "aes128ctr-internal-v1",
        coordinates = 1)
      x
    },
    non_count_primitive = function(x) {
      x$semantic$analysis$primitive <- "other-analysis-v1"
      x$execution$backend$kernel <- "other-analysis-v1"
      x
    },
    unsupported_ring = function(x) {
      x$execution$backend$ring <- "ring128"
      x
    },
    narrow_value_bits = function(x) {
      x$semantic$numeric$value_bits <- 126
      x
    },
    wrong_rounding = function(x) {
      x$semantic$numeric$rounding <- "nearest_even"
      x
    },
    wrong_sampler_encoding = function(x) {
      x$semantic$numeric$sampler_encoding <- "other_encoding_v1"
      x
    },
    wrong_output_encoding = function(x) {
      x$semantic$numeric$output_encoding <- "other_encoding_v1"
      x
    },
    wrong_shape = function(x) {
      x$semantic$public_shape <- list(value = 1)
      x
    },
    negative_fractional_bits = function(x) {
      x$semantic$numeric$fractional_bits <- -1
      x
    },
    full_width_fractional_bits = function(x) {
      x$semantic$numeric$fractional_bits <- 127
      x
    })
  for (mutate in invalid) {
    bad <- mutate(fixture)
    expect_error(.dsvert_dp_analysis_contract_v1(
      bad$semantic, bad$execution))
  }

  generic_zero <- .analysis_contract_fixture()
  generic_zero$semantic$numeric$fractional_bits <- 0
  validated_zero <- .dsvert_dp_analysis_contract_v1(
    generic_zero$semantic, generic_zero$execution)
  expect_identical(validated_zero$semantic$numeric$fractional_bits, 0)
  bad_lane <- generic_zero
  bad_lane$semantic$privacy$mechanism$randomness$lanes$final_noise$coordinates <-
    0
  expect_error(.dsvert_dp_analysis_contract_v1(
    bad_lane$semantic, bad_lane$execution))
})

test_that("analysis artifact identity is semantic and K-generic", {
  contracts <- lapply(c(2L, 3L, 5L), function(k) {
    fixture <- .analysis_contract_fixture(k)
    .dsvert_dp_analysis_contract_v1(
      fixture$semantic, fixture$execution)
  })
  expect_true(all(vapply(contracts, function(contract) {
    identical(contract,
              .dsvert_dp_analysis_contract_validate_v1(contract)) &&
      grepl("^[0-9a-f]{64}$", contract$artifact_key)
  }, logical(1L))))
  expect_identical(length(unique(vapply(
    contracts, `[[`, character(1L), "artifact_key"))), 3L)

  fixture <- .analysis_contract_fixture(3L)
  original <- .dsvert_dp_analysis_contract_v1(
    fixture$semantic, fixture$execution)
  expect_identical(
    original$artifact_key,
    "051e83176ab341f6d9461d71c97b9c14bb765fdb4e7f0220fd8a1d3579de4709")

  reordered_semantic <- fixture$semantic[
    rev(names(fixture$semantic))]
  reordered_semantic$owner_snapshots <-
    reordered_semantic$owner_snapshots[
      rev(names(reordered_semantic$owner_snapshots))]
  reordered_semantic$analysis$effective_arguments <-
    reordered_semantic$analysis$effective_arguments[
      rev(names(reordered_semantic$analysis$effective_arguments))]
  reordered_execution <- fixture$execution[rev(names(fixture$execution))]
  reordered_execution$peer_pins <- reordered_execution$peer_pins[
    rev(names(reordered_execution$peer_pins))]
  reordered_semantic$noise_authorities <-
    rev(reordered_semantic$noise_authorities)
  reordered <- .dsvert_dp_analysis_contract_v1(
    reordered_semantic, reordered_execution)
  expect_identical(reordered, original)

  vector_arguments <- fixture$semantic
  vector_arguments$analysis$effective_arguments$opaque <- c(1, 2)
  list_arguments <- fixture$semantic
  list_arguments$analysis$effective_arguments$opaque <- list(1, 2)
  expect_identical(
    .dsvert_dp_analysis_contract_v1(
      vector_arguments, fixture$execution),
    .dsvert_dp_analysis_contract_v1(
      list_arguments, fixture$execution))
  vector_terms <- fixture$semantic
  vector_terms$analysis$formula$terms <- c("age", "treatment")
  expect_identical(
    .dsvert_dp_analysis_contract_v1(
      vector_terms, fixture$execution),
    original)

  no_formula <- fixture$semantic
  no_formula$analysis["formula"] <- list(NULL)
  expect_null(.dsvert_dp_analysis_contract_v1(
    no_formula, fixture$execution)$semantic$analysis$formula)

  for (ambiguous in list(
      stats::setNames(c(1, 2), c("age", "treatment")),
      matrix(1:4, nrow = 2L),
      structure(list(1, 2), dim = c(1L, 2L)))) {
    bad <- fixture$semantic
    bad$analysis$effective_arguments$ambiguous <- ambiguous
    expect_error(
      .dsvert_dp_analysis_contract_v1(bad, fixture$execution),
      "Attributed")
  }
  empty_atomic <- fixture$semantic
  empty_atomic$analysis$effective_arguments$ambiguous <- numeric()
  expect_error(
    .dsvert_dp_analysis_contract_v1(empty_atomic, fixture$execution),
    "Empty atomic")

  normalized_numeric <- fixture$semantic
  normalized_numeric$privacy$epsilon <- 1L
  normalized_numeric$privacy$mechanism$sensitivity$value <- 1L
  normalized_numeric$numeric$fractional_bits <- 32L
  normalized_numeric$numeric$value_bits <- 120L
  expect_identical(
    .dsvert_dp_analysis_contract_v1(
      normalized_numeric, fixture$execution)$artifact_key,
    original$artifact_key)

  operational <- fixture$execution
  operational$backend$build_sha256 <- strrep("b", 64L)
  operational$backend$ring <- "ring128"
  operational$transport$chunk_coordinates <- 8192
  names(operational$peer_pins) <- paste0(
    "connection_", seq_along(operational$peer_pins))
  changed_execution <- .dsvert_dp_analysis_contract_v1(
    fixture$semantic, operational)
  expect_identical(changed_execution$artifact_key, original$artifact_key)
  expect_false(identical(changed_execution$execution, original$execution))

  changes <- list(
    method = function(x) {
      x$analysis$primitive <- "glm-poisson-log-v1"; x
    },
    argument = function(x) {
      x$analysis$effective_arguments$link <- "probit"; x
    },
    snapshot = function(x) {
      x$owner_snapshots[[1L]]$snapshot_commitment <- strrep("f", 64L); x
    },
    bounds = function(x) {
      x$privacy$contribution$constraints$policy_sha256 <- strrep("d", 64L); x
    },
    epsilon = function(x) {
      x$privacy$epsilon <- 2; x
    },
    mechanism = function(x) {
      x$privacy$mechanism$family <- "laplace"
      x$privacy$mechanism$version <- "laplace-output-perturbation-v1"
      x$privacy$mechanism$sensitivity$norm <- "l1"
      x$privacy$mechanism$calibration$noise_scale <- 1
      x$privacy$mechanism$calibration$sampler <- "laplace-one-draw-v1"
      x$privacy$mechanism$calibration$implementation_delta <- 0
      x$privacy$mechanism$randomness$lanes$final_noise$primitive <-
        "laplace-one-draw-v1"
      x
    },
    numeric = function(x) {
      x$numeric$fractional_bits <- 40; x
    },
    randomness = function(x) {
      x$privacy$mechanism$randomness$lanes$imputation <- list(
        version = "dsvert-randomness-lane-v1",
        purpose = "confidential_internal_randomness",
        primitive = "mi-fixed-chacha20-v1",
        coordinates = 4)
      x
    },
    shape = function(x) {
      x$public_shape$coefficients <- 4; x
    })
  changed_keys <- vapply(changes, function(change) {
    .dsvert_dp_analysis_artifact_key_v1(change(fixture$semantic))
  }, character(1L))
  expect_true(all(changed_keys != original$artifact_key))
  expect_true(all(!duplicated(changed_keys)))

  changed_authorities <- fixture$semantic
  changed_authorities$noise_authorities <- unname(
    names(changed_authorities$owner_snapshots)[2:3])
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(changed_authorities),
    "noise authorities")

  edge <- .analysis_contract_fixture(2L)
  edge_pk <- .analysis_contract_identity_pk(255L)
  names(edge$semantic$owner_snapshots)[1L] <- edge_pk
  edge$execution$peer_pins[[1L]] <- edge_pk
  edge$semantic$noise_authorities <- unname(sort(
    names(edge$semantic$owner_snapshots), method = "radix"))
  edge_contract <- .dsvert_dp_analysis_contract_v1(
    edge$semantic, edge$execution)
  expect_identical(
    sort(names(edge_contract$semantic$owner_snapshots), method = "radix"),
    sort(names(edge$semantic$owner_snapshots), method = "radix"))

  malformed <- .analysis_contract_fixture(2L)
  original_pk <- names(malformed$semantic$owner_snapshots)[1L]
  malformed_pk <- paste0(
    substr(original_pk, 1L, 10L), "=",
    substr(original_pk, 11L, nchar(original_pk)))
  names(malformed$semantic$owner_snapshots)[1L] <- malformed_pk
  malformed$execution$peer_pins[[1L]] <- malformed_pk
  malformed$semantic$noise_authorities[[1L]] <- malformed_pk
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      malformed$semantic, malformed$execution),
    "owner identity")

  aliased <- .analysis_contract_fixture(2L)
  canonical_pk <- .analysis_contract_identity_pk(255L)
  alias_pk <- paste0(" \n", chartr("-_", "+/", canonical_pk), "=\t")
  names(aliased$semantic$owner_snapshots)[1L] <- alias_pk
  aliased$execution$peer_pins[[1L]] <- alias_pk
  aliased$semantic$noise_authorities[[1L]] <- alias_pk
  expect_true(canonical_pk %in% names(
    .dsvert_dp_analysis_contract_v1(
      aliased$semantic, aliased$execution)$semantic$owner_snapshots))

  overpadded <- aliased
  overpadded_pk <- paste0(chartr("-_", "+/", canonical_pk), "==")
  names(overpadded$semantic$owner_snapshots)[1L] <- overpadded_pk
  overpadded$execution$peer_pins[[1L]] <- overpadded_pk
  overpadded$semantic$noise_authorities[[1L]] <- overpadded_pk
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      overpadded$semantic, overpadded$execution),
    "owner identity")
})

test_that("snapshot commitments are opaque and ignore R symbol names", {
  seed <- as.raw(seq_len(32L))
  owner <- .analysis_contract_identity_pk(1L)
  descriptor <- list(
    domain = "study-domain",
    cohort_id = "cohort-v1",
    owner_identity_pk = owner,
    dataset_id = "cohort_table",
    dataset_version = "v1",
    snapshot_sha256 = strrep("a", 64L),
    alignment_version = "dsvert-alignment-v3",
    alignment_sha256 = strrep("b", 64L))
  testthat::local_mocked_bindings(
    .get_identity_seed = function() jsonlite::base64_enc(seed),
    .get_identity_keypair = function() list(identity_pk = owner),
    .package = "dsVert")
  first <- .dsvert_dp_analysis_snapshot_commitment_v1(descriptor)
  expect_identical(
    first,
    "6707da1db58a698c2cb65294ffc0f940bac8a0cb4632fbc747f17dc2fe430f1c")
  expect_identical(
    first,
    .dsvert_dp_analysis_snapshot_commitment_v1(
      descriptor[rev(names(descriptor))]))
  expect_false(grepl(descriptor$snapshot_sha256, first, fixed = TRUE))

  changed <- descriptor
  changed$snapshot_sha256 <- strrep("c", 64L)
  expect_false(identical(
    first,
    .dsvert_dp_analysis_snapshot_commitment_v1(changed)))

  wrong_owner <- descriptor
  wrong_owner$owner_identity_pk <- .analysis_contract_identity_pk(2L)
  expect_error(
    .dsvert_dp_analysis_snapshot_commitment_v1(wrong_owner),
    "not the local identity")

  # The API deliberately has no data_name/R-symbol argument. Renaming the
  # protected binding therefore cannot mint a different artifact.
  expect_false("data_name" %in% names(formals(
    .dsvert_dp_analysis_snapshot_commitment_v1)))
  expect_false("secret" %in% names(formals(
    .dsvert_dp_analysis_snapshot_commitment_v1)))
  expect_false(".dsvert_dp_analysis_snapshot_commitment_v1" %in%
                 getNamespaceExports("dsVert"))
})

test_that("sticky subseeds derive only from identity.seed and declared lanes", {
  fixture <- .analysis_contract_fixture(3L)
  contract <- .dsvert_dp_analysis_contract_v1(
    fixture$semantic, fixture$execution)
  authorities <- contract$semantic$noise_authorities
  derive <- function(seed, identity, lane = "final_noise") {
    testthat::with_mocked_bindings(
      .dsvert_dp_sticky_subseed_v1(contract, lane),
      .get_identity_seed = function() jsonlite::base64_enc(seed),
      .get_identity_keypair = function() list(identity_pk = identity),
      .package = "dsVert")
  }
  first <- derive(as.raw(rep(1L, 32L)), authorities[[1L]])
  expect_identical(
    first, derive(as.raw(rep(1L, 32L)), authorities[[1L]]))
  expect_identical(
    first,
    "d047b7b612f1b9533388a07026ac295bc02a636bedd29faa5fa8fa4cf0095a89")
  expect_false(identical(
    first, derive(as.raw(rep(2L, 32L)), authorities[[1L]])))
  expect_false(identical(
    first, derive(as.raw(rep(2L, 32L)), authorities[[2L]])))
  expect_error(
    derive(as.raw(rep(1L, 32L)), authorities[[1L]], "undeclared"),
    "not declared")
  expect_error(
    derive(as.raw(rep(3L, 32L)),
           .analysis_contract_identity_pk(3L)),
    "not a designated")

  seed <- as.raw(seq_len(32L))
  testthat::with_mocked_bindings({
    expect_identical(
      paste(format(.dsvert_dp_analysis_snapshot_key_v1()), collapse = ""),
      "c185c330d6eb8350d07daad900693ef1f645e0cf73b71756db869cf8eab46d63")
    expect_identical(
      paste(format(.dsvert_dp_sticky_noise_key_v1()), collapse = ""),
      "3a5bf6893871ea61bb5a4bfc338c221a21d43f4a6044b1f04e824b4c42086ed0")
    expect_false(identical(
      .dsvert_dp_analysis_snapshot_key_v1(),
      .dsvert_dp_sticky_noise_key_v1()))
  }, .get_identity_seed = function() jsonlite::base64_enc(seed),
  .package = "dsVert")
  expect_identical(
    names(formals(.dsvert_dp_sticky_subseed_v1)), c("contract", "lane"))
})

test_that("analysis contracts reject ambiguous and operational fields", {
  fixture <- .analysis_contract_fixture()
  bad <- fixture$semantic
  bad$session_id <- "session-1"
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      bad, fixture$execution),
    "semantic contract")
  bad <- fixture$semantic
  bad$analysis$effective_arguments$value <- Inf
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      bad, fixture$execution),
    "canonical|finite")
  bad <- fixture$semantic
  bad$analysis$effective_arguments$session_id <- "session-1"
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      bad, fixture$execution),
    "Operational request fields")
  for (field in c(
      "data_name", "peer_name", "frontdoor", "route", "ledger_path",
      "lifetime_limit", "privacy_epoch", "noise_epoch", "noise_key_id",
      "connection_order", "format", "postprocessing")) {
    bad <- fixture$semantic
    bad$analysis$effective_arguments[[field]] <- "operational"
    expect_error(
      .dsvert_dp_analysis_contract_v1(bad, fixture$execution),
      "Operational request fields")
  }
  bad <- fixture$semantic
  bad$privacy$contribution <- list(unrelated = "accepted")
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      bad, fixture$execution),
    "contribution policy")
  bad <- fixture$semantic
  bad$privacy$contribution$constraints <- list(irrelevant = "accepted")
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      bad, fixture$execution),
    "contribution constraints")
  bad <- fixture$semantic
  bad$privacy$mechanism$calibration$sampler <- "gaussian-evil-v1"
  bad$privacy$mechanism$randomness$lanes$final_noise$primitive <-
    "gaussian-evil-v1"
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      bad, fixture$execution),
    "audited pair")
  bad <- fixture$semantic
  bad$privacy$mechanism$calibration$noise_scale <- .Machine$double.xmin
  expect_error(
    .dsvert_dp_analysis_contract_v1(bad, fixture$execution),
    "does not prove")
  bad <- fixture$semantic
  bad$privacy$delta <- 0
  bad$privacy$mechanism$calibration$implementation_delta <- 0
  expect_error(
    .dsvert_dp_analysis_contract_v1(bad, fixture$execution),
    "does not prove")
  bad <- fixture$semantic
  bad$privacy$mechanism$family <- "laplace"
  bad$privacy$mechanism$version <- "laplace-output-perturbation-v1"
  bad$privacy$mechanism$sensitivity$norm <- "l1"
  bad$privacy$mechanism$sensitivity$value <- 1e308
  bad$privacy$mechanism$calibration$noise_scale <- 1
  bad$privacy$mechanism$calibration$sampler <- "laplace-one-draw-v1"
  bad$privacy$mechanism$calibration$implementation_delta <- 0
  bad$privacy$mechanism$randomness$lanes$final_noise$primitive <-
    "laplace-one-draw-v1"
  bad$privacy$epsilon <- 1e-308
  expect_error(
    .dsvert_dp_analysis_contract_v1(bad, fixture$execution),
    "does not prove")
  bad <- fixture$semantic
  bad$privacy$mechanism$sensitivity$value <- 1e308
  bad$privacy$mechanism$calibration$noise_scale <- 1e308
  bad$privacy$mechanism$calibration$implementation_delta <- 1e-9
  bad$privacy$epsilon <- 1e-308
  bad$privacy$delta <- 0.1
  expect_error(
    .dsvert_dp_analysis_contract_v1(bad, fixture$execution),
    "does not prove")
  bad <- fixture$semantic
  bad$numeric$irrelevant <- "accepted"
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      bad, fixture$execution),
    "numeric semantics")
  bad_execution <- fixture$execution
  bad_execution$peer_pins[[2L]] <- bad_execution$peer_pins[[1L]]
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      fixture$semantic, bad_execution),
    "peer pins")
  bad_execution <- fixture$execution
  bad_execution$noise_authorities <- fixture$semantic$noise_authorities
  expect_error(
    .dsvert_dp_analysis_contract_v1(
      fixture$semantic, bad_execution),
    "execution contract")
  wide <- fixture$semantic
  wide$numeric$value_bits <- 128
  expect_error(
    .dsvert_dp_analysis_contract_v1(wide, fixture$execution),
    "ring is too small")
  bad <- fixture$semantic
  bad$privacy$mechanism$randomness$lanes$final_noise$primitive <-
    "laplace-one-draw-v1"
  expect_error(
    .dsvert_dp_analysis_contract_v1(bad, fixture$execution),
    "does not match")
})
