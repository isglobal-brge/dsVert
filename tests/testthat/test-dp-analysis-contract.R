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

.analysis_frequency_selection_fixture <- function(
    dimension, winner = c("convolution", "gaussian"),
    adjacency = "add_remove_patient", epsilon = 1,
    implementation_delta = 0.001, maximum_noise_per_peer = "100") {
  winner <- match.arg(winner)
  privacy <- list(epsilon = epsilon, adjacency = adjacency)
  calibration <- list(implementation_delta = implementation_delta)
  requests <- .dsvert_dp_analysis_frequency_candidate_requests_v2(
    privacy, calibration, dimension)
  request_hash <- function(kind) {
    profile <- .dsvert_dp_analysis_frequency_profile_v1(if (kind ==
        "convolution") {
      "independent_full_global_draw_convolution_ring128_v3"
    } else paste0("independent_full_global_dyadic_discrete_gaussian_",
                  "tv_bounded_ring128_v2"))
    .dsvert_dp_analysis_frequency_hash_v1(
      profile$request_domain, requests[[kind]])
  }
  plan_hashes <- list(
    convolution = digest::digest("Frequency convolution plan", "sha256",
                                 serialize = FALSE),
    gaussian = digest::digest("Frequency Gaussian plan", "sha256",
                              serialize = FALSE))
  radii <- if (winner == "convolution") {
    list(convolution = "5", gaussian = "16")
  } else list(convolution = "16", gaussian = "5")
  candidates <- lapply(c("convolution", "gaussian"), function(kind) list(
    planner_request_sha256 = request_hash(kind),
    full_plan_sha256 = plan_hashes[[kind]],
    accuracy_certificate_sha256 = digest::digest(
      paste("Frequency", kind, "accuracy"), "sha256", serialize = FALSE),
    simultaneous_95_abs = radii[[kind]],
    absolute_support = as.character(
      2 * openssl::bignum(maximum_noise_per_peer))))
  names(candidates) <- c("convolution", "gaussian")
  primitive <- if (winner == "convolution") {
    "independent_full_global_draw_convolution_ring128_v3"
  } else paste0("independent_full_global_dyadic_discrete_gaussian_",
                "tv_bounded_ring128_v2")
  selection_certificate <- list(
    version = "dsvert-joint-dp-frequency-backend-selection-certificate-v1",
    policy = "minimum_certified_simultaneous_95_abs_convolution_tie_v1",
    objective = "minimum_certified_simultaneous_95_abs",
    selected_primitive = primitive,
    selected_plan_sha256 = plan_hashes[[winner]],
    selected_simultaneous_95_abs = radii[[winner]],
    tie_break = "convolution_laplace_v3_on_equal_certified_radius",
    input_scope = paste0("public_adjacency_planner_requests_and_coordinate_",
                         "upper_bound_only"),
    source_material_consulted = FALSE,
    private_randomness_consulted = FALSE,
    runtime_failure_consulted = FALSE,
    automatic_fallback = FALSE,
    utility_optimality_claimed = FALSE)
  list(
    version = "dsvert-frequency-backend-selection-v2",
    policy_sha256 = .dsvert_dp_analysis_frequency_policy_sha256_v2(),
    selection_certificate_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
      "dsVert/frequency/backend-selection/certificate/v1|",
      selection_certificate),
    objective = "minimum_certified_simultaneous_95_abs",
    tie_break = "convolution_laplace_v3_on_equal_certified_radius",
    candidates = candidates,
    selected_primitive = primitive,
    selected_simultaneous_95_abs = radii[[winner]])
}


.analysis_frequency_contract_fixture <- function(
    k = 2L, profile = c("convolution", "gaussian"),
    levels = c("control", "caf\u00e9", "case"),
    chunk_coordinates = min(8192L, length(levels))) {
  profile <- match.arg(profile)
  levels <- sort(levels, method = "radix")
  fixture <- .analysis_contract_fixture(k)
  owner_ids <- sort(names(fixture$semantic$owner_snapshots), method = "radix")
  source_owner <- owner_ids[[min(2L, length(owner_ids))]]
  secondary <- sort(setdiff(owner_ids, source_owner), method = "radix")[[1L]]
  dimension <- length(levels)
  convolution <- identical(profile, "convolution")
  primitive <- if (convolution) {
    "independent_full_global_draw_convolution_ring128_v3"
  } else {
    paste0("independent_full_global_dyadic_discrete_gaussian_",
           "tv_bounded_ring128_v2")
  }
  registry <- .dsvert_dp_analysis_frequency_profile_v1(primitive)
  plan_version <- registry$plan
  sampler <- registry$sampler
  mechanism_version <- if (convolution) {
    "two-independent-complete-vector-discrete-laplace-draws-v3"
  } else {
    paste0("two-independent-complete-vector-dyadic-discrete-gaussian-",
           "tv-bounded-draws-v2")
  }
  selection <- .analysis_frequency_selection_fixture(
    dimension, profile, maximum_noise_per_peer = "100")
  candidate <- selection$candidates[[profile]]
  planner_request <- .dsvert_dp_analysis_frequency_candidate_requests_v2(
    list(epsilon = 1, adjacency = "add_remove_patient"),
    list(implementation_delta = 0.001), dimension)[[profile]]
  allocated <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(
    planner_request$delta)
  allocated_delta <- list(
    numerator = as.character(allocated$numerator),
    denominator = as.character(allocated$denominator))
  no_wrap_sha256 <- .dsvert_dp_analysis_frequency_hash_v1(
    "dsVert/frequency/ring128-no-wrap/v1|", list(
      version = "dsvert-frequency-ring128-no-wrap-v1",
      coordinate_upper_bound = "1000",
      maximum_noise_per_peer = "100",
      maximum_noise_release = "200"))
  fixture$semantic$version <-
    "dsvert-analysis-semantic-fixed-categorical-vector-v2"
  fixture$semantic$noise_authorities <- NULL
  fixture$semantic$noise_authority_roles <- list(
    version = "dsvert-frequency-noise-authority-roles-v1",
    role_order = list("source_owner", "secondary_noise_authority"),
    authority_ids = list(source_owner, secondary))
  fixture$semantic$analysis <- list(
    primitive = primitive,
    formula = NULL,
    effective_arguments = list(
      version = "dsvert-fixed-domain-categorical-frequency-v2",
      statistic = "aligned_fixed_domain_categorical_frequency",
      source_owner = source_owner,
      dataset_id = "cohort_table",
      dataset_version = "v1",
      variable_id = "status",
      levels = as.list(levels),
      dimension = dimension,
      repeated_record_policy =
        "psi_v4_first_eligible_source_record_per_privacy_unit_v1",
      missingness_policy = "missing_or_out_of_domain_rows_are_ignored",
      coordinate_bounds = list(lower = 0, upper = 1000),
      sampler_plan = list(
        version = "dsvert-frequency-plan-summary-v1",
        physical_plan_version = plan_version,
        full_plan_sha256 = candidate$full_plan_sha256,
        planner_request_sha256 = candidate$planner_request_sha256,
        coordinate_order_sha256 =
          .dsvert_dp_analysis_frequency_coordinate_order_sha256_v1(
            as.list(levels)),
        d = dimension,
        chunk_coordinates = chunk_coordinates,
        implementation_delta = list(
          numerator = "1", denominator = "1000000"),
        allocated_delta = allocated_delta,
        core_delta = list(
          numerator = if (convolution) "0" else "1",
          denominator = if (convolution) "1" else "2000"),
        maximum_noise_per_peer = "100",
        no_wrap_sha256 = no_wrap_sha256,
        profile_sha256 = .dsvert_dp_analysis_frequency_hash_v1(
          "dsVert/frequency/physical-profile/v1|", registry),
        backend_selection = selection)))
  fixture$semantic$privacy$adjacency <- "add_remove_patient"
  fixture$semantic$privacy$contribution$overflow_policy <-
    "clip_to_psi_v4_first_eligible_source_record_v1"
  fixture$semantic$privacy$contribution$constraints$policy_sha256 <-
    .dsvert_dp_analysis_frequency_hash_v1(
      "dsVert/dp-frequency/contribution/v1|", list(
        alignment_protocol = "dsvert-pinned-padded-psi-v4",
        duplicate_policy = "first",
        repeated_record_policy =
          "psi_v4_first_eligible_source_record_per_privacy_unit_v1",
        max_records_per_unit = 1,
        overflow_policy =
          "clip_to_psi_v4_first_eligible_source_record_v1"))
  fixture$semantic$privacy$mechanism <- list(
    family = if (convolution) "discrete_laplace" else "gaussian",
    version = mechanism_version,
    sensitivity = list(
      version = "dsvert-sensitivity-v1",
      norm = if (convolution) "l1" else "l2",
      value = 1),
    calibration = list(
      version = "dsvert-calibration-v1",
      sampler = sampler,
      implementation_delta = 0.001),
    randomness = list(
      version = "dsvert-randomness-plan-v1",
      lanes = list(final_noise = list(
        version = "dsvert-randomness-lane-v1",
        purpose = "privatize_final_vector",
        primitive = sampler,
        coordinates = dimension))))
  fixture$semantic$privacy$epsilon <- 1
  fixture$semantic$privacy$delta <- 0.01
  fixture$semantic$numeric <- list(
    version = "dsvert-numeric-semantics-v1",
    value_bits = 128,
    fractional_bits = 0,
    rounding = "toward_zero",
    overflow = "reject",
    output_encoding = "twos_complement_integer_v1")
  fixture$semantic$public_shape <- list(counts = dimension)
  fixture$execution$backend$kernel <- primitive
  fixture$execution$backend$ring <- "ring128"
  fixture$execution$transport$chunk_coordinates <- chunk_coordinates
  fixture
}

test_that("Frequency contracts are fixed categorical vectors for K=2,3,5", {
  ks <- c(2L, 3L, 5L)
  contracts <- lapply(ks, function(k) {
    fixture <- .analysis_frequency_contract_fixture(k)
    .dsvert_dp_analysis_contract_v1(fixture$semantic, fixture$execution)
  })
  gaussian_contracts <- lapply(ks, function(k) {
    fixture <- .analysis_frequency_contract_fixture(k, "gaussian")
    .dsvert_dp_analysis_contract_v1(fixture$semantic, fixture$execution)
  })
  expect_true(all(vapply(contracts, function(contract) {
    arguments <- contract$semantic$analysis$effective_arguments
    identical(arguments$dimension, 3) &&
      identical(arguments$source_owner,
                contract$semantic$noise_authority_roles$authority_ids[[1L]]) &&
      identical(contract$semantic$privacy$mechanism$randomness$lanes$
                  final_noise$coordinates, 3)
  }, logical(1L))))
  expect_identical(c(
    stats::setNames(vapply(contracts, `[[`, character(1L), "artifact_key"),
                    paste0("convolution_k", ks)),
    stats::setNames(vapply(gaussian_contracts, `[[`, character(1L),
                           "artifact_key"), paste0("gaussian_k", ks))), c(
      convolution_k2 =
        "7e7931ccc08c7803483d6ad0ce6b78250b68cf365408badc58bf62509cd48d41",
      convolution_k3 =
        "dd2f7e4b69426ba27210ef0c9adc3fe33768ac39495d785e6fa9d947ed070150",
      convolution_k5 =
        "bf4fe8d228deeee2d7236a7f0fbc1b635cda3d312b1ab01d2cc04ef5049c795d",
      gaussian_k2 =
        "2248ade285d4125d1a27989296c72595a34cad3eb7d0b79825996f48abb3d019",
      gaussian_k3 =
        "15c906ce50e29adeb6e7356533538f83cc92932f00e193afa57a7ec561697609",
      gaussian_k5 =
        "e9d02fca22487596f22e72f1dc060cd8e94f180436aa290c865182ba16bd50e5"))

  singleton <- .analysis_frequency_contract_fixture(
    3L, levels = "only", chunk_coordinates = 1L)
  singleton <- .dsvert_dp_analysis_contract_v1(
    singleton$semantic, singleton$execution)
  expect_identical(singleton$semantic$public_shape, list(counts = 1))
  expect_identical(singleton$semantic$analysis$primitive,
                   "independent_full_global_draw_convolution_ring128_v3")
  expect_identical(
    singleton$semantic$analysis$effective_arguments$sampler_plan$allocated_delta,
    list(denominator = "1000", numerator = "1"))
  gaussian_singleton <- .analysis_frequency_contract_fixture(
    3L, "gaussian", levels = "only", chunk_coordinates = 1L)
  expect_silent(.dsvert_dp_analysis_contract_v1(
    gaussian_singleton$semantic, gaussian_singleton$execution))

  convolution_profile <- .dsvert_dp_analysis_frequency_profile_v1(
    singleton$semantic$analysis$primitive)
  expect_identical(convolution_profile$chunk_partition_version,
                   "contiguous_full_chunks_except_last_v1")
  expect_identical(
    .dsvert_dp_analysis_frequency_planner_request_v1(
      convolution_profile, list(epsilon = 1),
      list(implementation_delta = 0.001), list(value = 1), 1),
    list(
      epsilon = .dsvert_joint_dp_decimal(1, "Frequency epsilon"),
      delta = .dsvert_joint_dp_decimal(0.001, "Frequency delta"),
      sensitivity_steps = "1", total_coordinate_count = 1L))

  gaussian <- gaussian_contracts[[3L]]
  expect_identical(
    gaussian$semantic$privacy$mechanism$calibration$sampler,
    paste0("cks-target-outward-rational-dyadic-cdf-hkdf-sha256-",
           "chacha20-coordinate-domain-v2"))
  expect_identical(
    gaussian$semantic$analysis$effective_arguments$sampler_plan$allocated_delta,
    list(denominator = "100000000000000000000",
         numerator = "99999999999997161"))
  expect_identical(
    .dsvert_dp_analysis_frequency_planner_request_v1(
      .dsvert_dp_analysis_frequency_profile_v1(
        gaussian$semantic$analysis$primitive),
      list(epsilon = 1), list(implementation_delta = 0.001),
      list(value = 1), 3),
    .dsvert_dp_capsule_exact_gaussian_request(1, 0.001, 1, 3))

  original <- contracts[[2L]]
  source <- original$semantic$analysis$effective_arguments$source_owner
  expect_false(identical(
    source, sort(names(original$semantic$owner_snapshots),
                 method = "radix")[[1L]]))
  expect_identical(original$semantic$noise_authority_roles$role_order,
                   list("source_owner", "secondary_noise_authority"))

  for (kind in c("convolution", "gaussian")) {
    replace_one <- .analysis_frequency_contract_fixture(3L, kind)
    replace_one$semantic$privacy$adjacency <- "replace_one_fixed_cohort"
    sensitivity <- replace_one$semantic$privacy$mechanism$sensitivity
    sensitivity$value <- if (identical(kind, "gaussian")) sqrt(2) else 2
    replace_one$semantic$privacy$mechanism$sensitivity <- sensitivity
    plan <- replace_one$semantic$analysis$effective_arguments$sampler_plan
    plan$backend_selection <- .analysis_frequency_selection_fixture(
      3L, kind, adjacency = "replace_one_fixed_cohort")
    candidate <- plan$backend_selection$candidates[[kind]]
    plan$planner_request_sha256 <- candidate$planner_request_sha256
    plan$full_plan_sha256 <- candidate$full_plan_sha256
    replace_one$semantic$analysis$effective_arguments$sampler_plan <- plan
    expect_silent(.dsvert_dp_analysis_contract_v1(
      replace_one$semantic, replace_one$execution))
  }

  for (kind in c("convolution", "gaussian")) {
    under <- .analysis_frequency_contract_fixture(3L, kind)
    sensitivity <- under$semantic$privacy$mechanism$sensitivity
    sensitivity$value <- 1 - 512 * .Machine$double.eps
    under$semantic$privacy$mechanism$sensitivity <- sensitivity
    registry <- .dsvert_dp_analysis_frequency_profile_v1(
      under$semantic$analysis$primitive)
    request <- .dsvert_dp_analysis_frequency_planner_request_v1(
      registry, under$semantic$privacy,
      under$semantic$privacy$mechanism$calibration, sensitivity, 3)
    under$semantic$analysis$effective_arguments$sampler_plan$
      planner_request_sha256 <- .dsvert_dp_analysis_frequency_hash_v1(
        registry$request_domain, request)
    expect_error(.dsvert_dp_analysis_contract_v1(
      under$semantic, under$execution), "Frequency", info = kind)
  }
  sticky_contract <- contracts[[2L]]
  sticky_authority <- sticky_contract$semantic$noise_authority_roles$
    authority_ids[[1L]]
  sticky <- testthat::with_mocked_bindings(
    .dsvert_dp_sticky_subseed_v1(sticky_contract, "final_noise"),
    .get_identity_keypair = function() list(identity_pk = sticky_authority),
    .get_identity_seed = function() jsonlite::base64_enc(as.raw(rep(91L, 32L))),
    .package = "dsVert")
  expect_match(sticky, "^[0-9a-f]{64}$")
  expect_identical(sticky, testthat::with_mocked_bindings(
    .dsvert_dp_sticky_subseed_v1(sticky_contract, "final_noise"),
    .get_identity_keypair = function() list(identity_pk = sticky_authority),
    .get_identity_seed = function() jsonlite::base64_enc(as.raw(rep(91L, 32L))),
    .package = "dsVert"))
})

test_that("Frequency v2 is radix-canonical and v1 remains fail-closed", {
  fixture <- .analysis_frequency_contract_fixture(3L)
  contract <- .dsvert_dp_analysis_contract_v1(
    fixture$semantic, fixture$execution)
  arguments <- contract$semantic$analysis$effective_arguments
  expect_identical(arguments$levels,
    as.list(sort(unlist(arguments$levels, use.names = FALSE), method = "radix")))
  expect_identical(
    arguments$repeated_record_policy,
    "psi_v4_first_eligible_source_record_per_privacy_unit_v1")
  expect_identical(
    contract$semantic$privacy$contribution$overflow_policy,
    "clip_to_psi_v4_first_eligible_source_record_v1")

  legacy <- fixture
  legacy$semantic$version <-
    "dsvert-analysis-semantic-fixed-categorical-vector-v1"
  legacy$semantic$analysis$effective_arguments$version <-
    "dsvert-fixed-domain-categorical-frequency-v1"
  expect_error(.dsvert_dp_analysis_contract_v1(
    legacy$semantic, legacy$execution), "semantic")

  permuted <- fixture
  permuted$semantic$analysis$effective_arguments$levels <-
    rev(permuted$semantic$analysis$effective_arguments$levels)
  expect_error(.dsvert_dp_analysis_contract_v1(
    permuted$semantic, permuted$execution), "Frequency")

  old_policy <- fixture
  old_policy$semantic$analysis$effective_arguments$repeated_record_policy <-
    "consistent_level_else_exclude_v1"
  old_policy$semantic$privacy$contribution$overflow_policy <-
    "reject_operation"
  expect_error(.dsvert_dp_analysis_contract_v1(
    old_policy$semantic, old_policy$execution), "Frequency")

  tampered_policy <- fixture
  tampered_policy$semantic$privacy$contribution$constraints$policy_sha256 <-
    strrep("f", 64L)
  expect_error(.dsvert_dp_analysis_contract_v1(
    tampered_policy$semantic, tampered_policy$execution), "Frequency")
})

test_that("Frequency caps categorical levels and bytes before sorting", {
  fixture <- .analysis_frequency_contract_fixture(3L)
  original_sort <- base::sort
  expect_pre_cap <- function(max_levels, max_bytes) {
    sorted <- FALSE
    expect_error(testthat::with_mocked_bindings(
      testthat::with_mocked_bindings(
        .dsvert_dp_analysis_frequency_semantic_validate_v1(fixture$semantic),
        sort = function(...) {
          sorted <<- TRUE
          original_sort(...)
        },
        .package = "base"),
      .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS = max_levels,
      .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES = max_bytes,
      .package = "dsVert"), "Frequency")
    expect_false(sorted)
  }
  expect_pre_cap(2L, 16L * 1024L * 1024L)
  expect_pre_cap(3L, 2L)
})

test_that("Frequency backend selector wrapper binds public preimages", {
  result <- .dsvert_dp_analysis_frequency_backend_selection_v2(
    privacy = list(epsilon = 1, adjacency = "add_remove_patient"),
    calibration = list(implementation_delta = 0.001),
    dimension = 3L, coordinate_upper_bound = 1000,
    .selector = function(request) .analysis_frequency_oracle_fixture(request))
  expect_setequal(names(result), c(
    "summary", "selected_request", "selected_plan",
    "selected_accuracy_certificate", "selection_certificate"))
  expect_identical(result$summary$selected_primitive,
    "independent_full_global_draw_convolution_ring128_v3")
  expect_identical(result$summary$selected_simultaneous_95_abs, "5")
  expect_identical(result$summary$candidates$convolution$absolute_support,
                   "200")
  expect_identical(result$selected_request$sensitivity_steps, "1")
  expect_identical(result$selected_plan$bernoulli_thresholds, list("1"))
  gaussian <- .dsvert_dp_analysis_frequency_backend_selection_v2(
    privacy = list(epsilon = 1, adjacency = "add_remove_patient"),
    calibration = list(implementation_delta = 0.001),
    dimension = 3L, coordinate_upper_bound = 1000,
    .selector = function(request) {
      .analysis_frequency_oracle_fixture(request, "gaussian")
    })
  expect_identical(gaussian$summary$selected_primitive,
    paste0("independent_full_global_dyadic_discrete_gaussian_",
           "tv_bounded_ring128_v2"))
  tie <- .dsvert_dp_analysis_frequency_backend_selection_v2(
    privacy = list(epsilon = 1, adjacency = "add_remove_patient"),
    calibration = list(implementation_delta = 0.001),
    dimension = 3L, coordinate_upper_bound = 1000,
    .selector = function(request) {
      .analysis_frequency_oracle_fixture(request, "tie")
    })
  expect_identical(tie$summary$selected_primitive,
                   "independent_full_global_draw_convolution_ring128_v3")

  invalid <- list(
    echo = function(x) { x$request$adjacency <- "replace_one_fixed_cohort"; x },
    plan = function(x) { x$convolution_plan$maximum_noise_magnitude <- "101"; x },
    convolution_missing = function(x) {
      x$convolution_plan$privacy_argument <- NULL; x
    },
    convolution_extra = function(x) {
      x$convolution_plan$schema_drift <- FALSE; x
    },
    convolution_scalar_array = function(x) {
      x$convolution_plan$bernoulli_thresholds <- "1"
      hash <- .dsvert_dp_analysis_frequency_hash_v1(
        "dsVert/frequency/full-plan/v1|", x$convolution_plan)
      x$convolution_certificate$plan_sha256 <- hash
      x$selection_certificate$selected_plan_sha256 <- hash
      x
    },
    convolution_array_length = function(x) {
      x$convolution_plan$bernoulli_thresholds <- list("1", "2")
      hash <- .dsvert_dp_analysis_frequency_hash_v1(
        "dsVert/frequency/full-plan/v1|", x$convolution_plan)
      x$convolution_certificate$plan_sha256 <- hash
      x$selection_certificate$selected_plan_sha256 <- hash
      x
    },
    convolution_named_array = function(x) {
      x$convolution_plan$bernoulli_thresholds <- list(value = "1")
      hash <- .dsvert_dp_analysis_frequency_hash_v1(
        "dsVert/frequency/full-plan/v1|", x$convolution_plan)
      x$convolution_certificate$plan_sha256 <- hash
      x$selection_certificate$selected_plan_sha256 <- hash
      x
    },
    convolution_non_string_array = function(x) {
      x$convolution_plan$bernoulli_thresholds <- list(1)
      hash <- .dsvert_dp_analysis_frequency_hash_v1(
        "dsVert/frequency/full-plan/v1|", x$convolution_plan)
      x$convolution_certificate$plan_sha256 <- hash
      x$selection_certificate$selected_plan_sha256 <- hash
      x
    },
    gaussian_missing = function(x) {
      x$gaussian_plan$unavailable_reason <- NULL; x
    },
    gaussian_extra = function(x) {
      x$gaussian_plan$schema_drift <- FALSE; x
    },
    tv = function(x) {
      x$convolution_certificate$release_tv_upper_numerator <- "2"; x
    },
    support = function(x) {
      x$convolution_certificate$absolute_support <- "199"; x
    },
    finite_radius = function(x) {
      x$convolution_certificate$method <- "finite_support_v1"; x
    },
    exhausted_exact_tail = function(x) {
      x$convolution_plan$one_geometric_tv_denominator <- "240"
      x$convolution_certificate$plan_sha256 <-
        .dsvert_dp_analysis_frequency_hash_v1(
          "dsVert/frequency/full-plan/v1|", x$convolution_plan)
      x$convolution_certificate$release_tv_upper_numerator <- "1"
      x$convolution_certificate$release_tv_upper_denominator <- "20"
      x
    },
    nonfinite_support_radius = function(x) {
      x$convolution_certificate$simultaneous_95_abs <- "200"; x
    },
    winner = function(x) {
      x$selection_certificate$selected_primitive <-
        x$gaussian_certificate$primitive; x
    },
    private = function(x) {
      x$selection_certificate$private_randomness_consulted <- TRUE; x
    },
    extra = function(x) { x$source <- "forbidden"; x })
  for (mutate in invalid) {
    expect_error(.dsvert_dp_analysis_frequency_backend_selection_v2(
      privacy = list(epsilon = 1, adjacency = "add_remove_patient"),
      calibration = list(implementation_delta = 0.001),
      dimension = 3L, coordinate_upper_bound = 1000,
      .selector = function(request) mutate(
        .analysis_frequency_oracle_fixture(request))), "Frequency")
  }
})

test_that("Frequency backend selector requests shape-preserving Go JSON", {
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, input_data, simplify_output) {
      expect_identical(command, "joint-dp-frequency-backend-select-v1")
      expect_identical(simplify_output, FALSE)
      .analysis_frequency_oracle_fixture(input_data)
    },
    .package = "dsVert")
  result <- .dsvert_dp_analysis_frequency_backend_selection_v2(
    privacy = list(epsilon = 1, adjacency = "add_remove_patient"),
    calibration = list(implementation_delta = 0.001),
    dimension = 3L, coordinate_upper_bound = 1000)
  expect_identical(result$selected_plan$bernoulli_thresholds, list("1"))
})

test_that("Frequency artifact identity is canonical and fully semantic", {
  fixture <- .analysis_frequency_contract_fixture(3L)
  original <- .dsvert_dp_analysis_contract_v1(
    fixture$semantic, fixture$execution)

  aliased <- fixture
  source <- aliased$semantic$analysis$effective_arguments$source_owner
  alias <- paste0(" \n", chartr("-_", "+/", source), "=\t")
  source_index <- match(source, names(aliased$semantic$owner_snapshots))
  names(aliased$semantic$owner_snapshots)[[source_index]] <- alias
  aliased$semantic$analysis$effective_arguments$source_owner <- alias
  aliased$semantic$noise_authority_roles$authority_ids[[1L]] <- alias
  pin_index <- which(vapply(
    aliased$execution$peer_pins, identical, logical(1L), source))
  aliased$execution$peer_pins[[pin_index]] <- alias
  aliased <- .dsvert_dp_analysis_contract_v1(
    aliased$semantic, aliased$execution)
  expect_identical(aliased$artifact_key, original$artifact_key)

  operational <- fixture$execution
  operational$backend$build_sha256 <- strrep("b", 64L)
  names(operational$peer_pins) <- paste0(
    "connection_", seq_along(operational$peer_pins))
  changed_execution <- .dsvert_dp_analysis_contract_v1(
    fixture$semantic, operational)
  expect_identical(changed_execution$artifact_key, original$artifact_key)

  rechunked <- .analysis_frequency_contract_fixture(
    3L, chunk_coordinates = 1L)
  expect_error(.dsvert_dp_analysis_contract_v1(
    rechunked$semantic, rechunked$execution), "Frequency")
  gaussian_rechunked <- .analysis_frequency_contract_fixture(
    3L, "gaussian", chunk_coordinates = 2L)
  expect_error(.dsvert_dp_analysis_contract_v1(
    gaussian_rechunked$semantic, gaussian_rechunked$execution), "Frequency")

  replanned <- fixture
  replanned_plan <-
    replanned$semantic$analysis$effective_arguments$sampler_plan
  replanned_plan$full_plan_sha256 <- strrep("e", 64L)
  replanned_plan$backend_selection$candidates$convolution$full_plan_sha256 <-
    strrep("e", 64L)
  replanned_plan$backend_selection$selection_certificate_sha256 <-
    strrep("e", 64L)
  replanned$semantic$analysis$effective_arguments$sampler_plan <-
    replanned_plan
  replanned <- .dsvert_dp_analysis_contract_v1(
    replanned$semantic, replanned$execution)
  expect_false(identical(replanned$artifact_key, original$artifact_key))

  looser_total_delta <- fixture
  looser_total_delta$semantic$privacy$delta <- 0.02
  looser_total_delta <- .dsvert_dp_analysis_contract_v1(
    looser_total_delta$semantic, looser_total_delta$execution)
  expect_false(identical(
    looser_total_delta$artifact_key, original$artifact_key))

  nfc <- .analysis_frequency_contract_fixture(
    3L, levels = c("\u00e9", "x"), chunk_coordinates = 2L)
  nfd <- .analysis_frequency_contract_fixture(
    3L, levels = c("e\u0301", "x"), chunk_coordinates = 2L)
  nfc <- .dsvert_dp_analysis_contract_v1(nfc$semantic, nfc$execution)
  nfd <- .dsvert_dp_analysis_contract_v1(nfd$semantic, nfd$execution)
  expect_false(identical(nfc$artifact_key, nfd$artifact_key))

  latin1_label <- iconv("caf\u00e9", from = "UTF-8", to = "latin1")
  Encoding(latin1_label) <- "latin1"
  non_utf8 <- .analysis_frequency_contract_fixture(
    3L, levels = c(latin1_label, "x"), chunk_coordinates = 2L)
  expect_error(.dsvert_dp_analysis_contract_v1(
    non_utf8$semantic, non_utf8$execution), "Frequency")

  large <- fixture
  large$semantic$analysis$effective_arguments$sampler_plan$
    implementation_delta <- list(
      numerator = "9007199254740993",
      denominator = "9007199254740993000000001")
  expect_silent(.dsvert_dp_analysis_contract_v1(
    large$semantic, large$execution))

  boundary <- fixture
  boundary_plan <- boundary$semantic$analysis$effective_arguments$sampler_plan
  boundary_plan$maximum_noise_per_peer <-
    "85070591730234615865843651857942052363"
  boundary_plan$backend_selection$candidates$convolution$absolute_support <-
    "170141183460469231731687303715884104726"
  boundary_plan$no_wrap_sha256 <- .dsvert_dp_analysis_frequency_hash_v1(
    "dsVert/frequency/ring128-no-wrap/v1|", list(
      version = "dsvert-frequency-ring128-no-wrap-v1",
      coordinate_upper_bound = "1000",
      maximum_noise_per_peer =
        "85070591730234615865843651857942052363",
      maximum_noise_release =
        "170141183460469231731687303715884104726"))
  boundary$semantic$analysis$effective_arguments$sampler_plan <- boundary_plan
  expect_silent(.dsvert_dp_analysis_contract_v1(
    boundary$semantic, boundary$execution))

  million_bound <- fixture
  million_plan <-
    million_bound$semantic$analysis$effective_arguments$sampler_plan
  million_bound$semantic$analysis$effective_arguments$coordinate_bounds$upper <-
    1000000
  million_plan$no_wrap_sha256 <- .dsvert_dp_analysis_frequency_hash_v1(
    "dsVert/frequency/ring128-no-wrap/v1|", list(
      version = "dsvert-frequency-ring128-no-wrap-v1",
      coordinate_upper_bound = "1000000",
      maximum_noise_per_peer = "100", maximum_noise_release = "200"))
  million_bound$semantic$analysis$effective_arguments$sampler_plan <-
    million_plan
  expect_silent(.dsvert_dp_analysis_contract_v1(
    million_bound$semantic, million_bound$execution))

  overflow <- boundary
  overflow_plan <- overflow$semantic$analysis$effective_arguments$sampler_plan
  overflow_plan$maximum_noise_per_peer <-
    "85070591730234615865843651857942052364"
  overflow_plan$no_wrap_sha256 <- .dsvert_dp_analysis_frequency_hash_v1(
    "dsVert/frequency/ring128-no-wrap/v1|", list(
      version = "dsvert-frequency-ring128-no-wrap-v1",
      coordinate_upper_bound = "1000",
      maximum_noise_per_peer =
        "85070591730234615865843651857942052364",
      maximum_noise_release =
        "170141183460469231731687303715884104728"))
  overflow$semantic$analysis$effective_arguments$sampler_plan <- overflow_plan
  expect_error(.dsvert_dp_analysis_contract_v1(
    overflow$semantic, overflow$execution))
})

test_that("Frequency contracts fail closed on every bound dimension", {
  fixture <- .analysis_frequency_contract_fixture(3L)
  invalid_semantic <- list(
    roles = function(x) {
      x$noise_authority_roles$role_order <-
        list("secondary_noise_authority", "source_owner"); x
    },
    role_identity = function(x) {
      x$noise_authority_roles$authority_ids <-
        rev(x$noise_authority_roles$authority_ids); x
    },
    source = function(x) {
      x$analysis$effective_arguments$source_owner <-
        .analysis_contract_identity_pk(99L); x
    },
    source_dataset = function(x) {
      x$analysis$effective_arguments$dataset_version <- "v2"; x
    },
    dimension = function(x) {
      x$analysis$effective_arguments$dimension <- 2; x
    },
    duplicate_level = function(x) {
      x$analysis$effective_arguments$levels[[2L]] <-
        x$analysis$effective_arguments$levels[[1L]]; x
    },
    oversized_level = function(x) {
      x$analysis$effective_arguments$levels[[1L]] <- strrep("x", 1025L); x
    },
    lane = function(x) {
      x$privacy$mechanism$randomness$lanes$final_noise$coordinates <- 2; x
    },
    shape = function(x) { x$public_shape$counts <- 2; x },
    primitive = function(x) {
      x$analysis$primitive <- "exact_gc_one_joint_discrete_laplace_draw_ring128_v3"; x
    },
    numeric_primitive = function(x) { x$analysis$primitive <- 1; x },
    mechanism = function(x) {
      x$privacy$mechanism$version <-
        "discrete-laplace-output-perturbation-v1"; x
    },
    sampler = function(x) {
      x$privacy$mechanism$calibration$sampler <-
        "discrete-laplace-one-draw-v1"; x
    },
    legacy_noise_scale = function(x) {
      x$privacy$mechanism$calibration$noise_scale <- 1; x
    },
    plan_dimension = function(x) {
      x$analysis$effective_arguments$sampler_plan$d <- 2; x
    },
    physical_plan = function(x) {
      x$analysis$effective_arguments$sampler_plan$physical_plan_version <-
        "dsvert-joint-dp-vector-laplace-plan-v3"; x
    },
    planner_request = function(x) {
      x$analysis$effective_arguments$sampler_plan$planner_request_sha256 <-
        strrep("f", 64L); x
    },
    profile = function(x) {
      x$analysis$effective_arguments$sampler_plan$profile_sha256 <-
        strrep("f", 64L); x
    },
    order = function(x) {
      x$analysis$effective_arguments$sampler_plan$coordinate_order_sha256 <-
        strrep("f", 64L); x
    },
    derived_lattice = function(x) {
      x$analysis$effective_arguments$sampler_plan$output_lattice_bits <- 2; x
    },
    raw_bound = function(x) {
      x$analysis$effective_arguments$coordinate_bounds$upper <- 999; x
    },
    partition = function(x) {
      x$analysis$effective_arguments$sampler_plan$chunk_coordinates <- 1; x
    },
    stream = function(x) {
      x$analysis$effective_arguments$sampler_plan$stream_binding <-
        list(mode = "absolute_coordinate_per_peer"); x
    },
    stream_role = function(x) {
      x$analysis$effective_arguments$sampler_plan$stream_binding$
        peer_role_binding <- "connection_alias"; x
    },
    runtime_claim = function(x) {
      x$analysis$effective_arguments$sampler_plan$stream_binding$
        runtime_sticky_claimed <- TRUE; x
    },
    fraction = function(x) {
      x$analysis$effective_arguments$sampler_plan$implementation_delta <- list(
          numerator = "2", denominator = "2000000"); x
    },
    allocation = function(x) {
      x$analysis$effective_arguments$sampler_plan$allocated_delta <-
        list(numerator = "1", denominator = "10"); x
    },
    selection = function(x) {
      x$analysis$effective_arguments$sampler_plan$backend_selection$
        runtime_failure_consulted <- TRUE; x
    },
    selection_backend = function(x) {
      x$analysis$effective_arguments$sampler_plan$backend_selection$
        policy_sha256 <- strrep("f", 64L); x
    },
    selection_losing_no_wrap = function(x) {
      x$analysis$effective_arguments$sampler_plan$backend_selection$
        candidates$gaussian$absolute_support <-
          "170141183460469231731687303715884105728"; x
    },
    selection_radius_over_support = function(x) {
      x$analysis$effective_arguments$sampler_plan$backend_selection$
        candidates$gaussian$simultaneous_95_abs <- "201"; x
    },
    selection_wrong_winner = function(x) {
      x$analysis$effective_arguments$sampler_plan$backend_selection$
        candidates$gaussian$simultaneous_95_abs <- "4"; x
    },
    selection_losing_request = function(x) {
      x$analysis$effective_arguments$sampler_plan$backend_selection$
        candidates$gaussian$planner_request_sha256 <- strrep("f", 64L); x
    },
    selection_candidate_extra = function(x) {
      x$analysis$effective_arguments$sampler_plan$backend_selection$
        candidates$gaussian$selected_release_support_radius <- "200"; x
    },
    output = function(x) {
      x$analysis$effective_arguments$sampler_plan$output_transform <-
        "unclamped"; x
    },
    preimage = function(x) {
      x$analysis$effective_arguments$sampler_plan$preimage_validation$
        server_replan_required <- FALSE; x
    },
    no_wrap = function(x) {
      x$analysis$effective_arguments$sampler_plan$maximum_noise_per_peer <-
          "170141183460469231731687303715884105728"; x
    },
    no_wrap_hash = function(x) {
      x$analysis$effective_arguments$sampler_plan$no_wrap_sha256 <-
        strrep("f", 64L); x
    },
    zero_noise = function(x) {
      plan <- x$analysis$effective_arguments$sampler_plan
      plan$maximum_noise_per_peer <- "0"
      plan$no_wrap_sha256 <- .dsvert_dp_analysis_frequency_hash_v1(
        "dsVert/frequency/ring128-no-wrap/v1|", list(
          version = "dsvert-frequency-ring128-no-wrap-v1",
          coordinate_upper_bound = "1000",
          maximum_noise_per_peer = "0", maximum_noise_release = "0"))
      x$analysis$effective_arguments$sampler_plan <- plan
      x
    },
    excessive_epsilon = function(x) { x$privacy$epsilon <- 8.1; x },
    excessive_bound = function(x) {
      x$analysis$effective_arguments$coordinate_bounds$upper <- 1000001; x
    },
    vector_adjacency = function(x) {
      x$privacy$adjacency <- c("add_remove_patient", "add_remove_patient"); x
    },
    vector_snapshot_hash = function(x) {
      x$owner_snapshots[[1L]]$snapshot_commitment <-
        c(strrep("a", 64L), strrep("b", 64L)); x
    },
    vector_policy_hash = function(x) {
      x$privacy$contribution$constraints$policy_sha256 <-
        c(strrep("a", 64L), strrep("b", 64L)); x
    },
    numeric = function(x) { x$numeric$value_bits <- 127; x })
  for (mutate in invalid_semantic) {
    expect_error(.dsvert_dp_analysis_artifact_key_v1(
      mutate(fixture$semantic)))
  }

  wrong_kernel <- fixture$execution
  wrong_kernel$backend$kernel <- "other-backend-v1"
  expect_error(.dsvert_dp_analysis_contract_v1(
    fixture$semantic, wrong_kernel), "execution backend")
  wrong_chunk <- fixture$execution
  wrong_chunk$transport$chunk_coordinates <- 1
  expect_error(.dsvert_dp_analysis_contract_v1(
    fixture$semantic, wrong_chunk), "execution transport")
})

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
      .dsvert_dp_noise_root = function(...) {
        stop("noise root must not be called", call. = FALSE)
      },
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
  .dsvert_dp_noise_root = function(...) {
    stop("noise root must not be called", call. = FALSE)
  },
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
