.synopsis_artifact_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (file in c(
      "test-dp-synopsis-analysis.R",
      "test-dp-capsule-source-transport.R",
      "test-joint-dp-vector-capsule.R")) {
    for (expression in parse(testthat::test_path(file))) {
      if (is.call(expression) &&
          identical(as.character(expression[[1L]]), "test_that")) break
      eval(expression, envir = environment)
    }
  }
  environment
})

.synopsis_artifact_fixture <- local({
  fixture <- .synopsis_artifact_helpers$.synopsis_test_fixture
  formals(fixture) <- c(
    formals(fixture), alist(delta = 1e-6, authority_peers = NULL))
  rewrite <- function(value) {
    if (!is.call(value)) return(value)
    pieces <- lapply(as.list(value), rewrite)
    names(pieces) <- names(value)
    if ("global_total_delta" %in% names(pieces)) {
      pieces[["global_total_delta"]] <- quote(delta)
    }
    if ("designated_noise_peers" %in% names(pieces)) {
      pieces[["designated_noise_peers"]] <- quote(
        if (is.null(authority_peers)) peer_names[1:2] else authority_peers)
    }
    as.call(pieces)
  }
  body(fixture) <- rewrite(body(fixture))
  fixture
})

.synopsis_artifact_exact_fixture <- function(k) {
  value <- .synopsis_artifact_helpers$.capsule_source_test_fixture(
    k = k, count_only = TRUE)
  list(
    policy = value$policies[[1L]], manifest = value$manifests[[1L]],
    pins = value$policies[[1L]]$peer_pinset)
}

.synopsis_artifact_claim_set <- function(
    fixture, commitment = strrep("1", 64L), signature_byte = 65L) {
  contract <- .dsvert_dp_capsule_source_contract(
    fixture$policy, fixture$manifest)
  peers <- .dsvert_dp_capsule_source_names(
    contract$source_peers, "test synopsis source peers")
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(
    fixture$policy, fixture$manifest)
  signature <- .synopsis_artifact_helpers$.synopsis_test_b64url(
    as.raw(rep(signature_byte, 64L)))
  claims <- lapply(peers, function(peer) list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_VERSION,
    source_peer_name = peer,
    source_identity_pk = unname(fixture$pins[[peer]]),
    catalog_sha256 = projection$sha256,
    source_vector_commitment = commitment,
    signature = signature))
  .dsvert_dp_synopsis_source_claim_set_v1(
    fixture$policy, fixture$manifest, claims,
    .verifier = function(...) TRUE)
}

.synopsis_artifact_plan <- function(
    request, convolution = FALSE, operational = "a", draw = "100",
    coordinate_offset = 0L, sensitivity = request$sensitivity_steps,
    threat_model = "at_most_one_of_two_noise_peers_colludes_with_analyst",
    threshold_scalar = FALSE) {
  exact_fields <- c(
    "version", "sampler", "stop_bits", "stop_numerator",
    "uniform_bits", "binary_geometric_bits", "bernoulli_thresholds",
    "sensitivity_steps", "total_coordinate_count",
    "epsilon_effective_upper_numerator",
    "epsilon_effective_upper_denominator", "one_geometric_tv_numerator",
    "one_geometric_tv_denominator", "tail_upper_numerator",
    "tail_upper_denominator", "rounding_upper_numerator",
    "rounding_upper_denominator", "implementation_delta_numerator",
    "implementation_delta_denominator", "implementation_delta_bound",
    "maximum_noise_magnitude", "maximum_chunk_coordinates",
    "private_stream_bytes_per_coordinate", "accounting",
    "capability_available")
  plan <- stats::setNames(as.list(rep("1", length(exact_fields))),
                          exact_fields)
  dimension <- as.integer(request$total_coordinate_count + coordinate_offset)
  epsilon <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(
    request$epsilon)
  delta <- .dsvert_dp_analysis_frequency_decimal_fraction_v1(request$delta)
  values <- list(
    version = "dsvert-joint-dp-vector-laplace-plan-v3",
    sampler = "hkdf-sha256-chacha20-xor-binary-geometric-tv-v3",
    stop_bits = 128L, uniform_bits = 128L,
    binary_geometric_bits = 1L,
    bernoulli_thresholds = if (isTRUE(threshold_scalar)) "1" else list("1"),
    sensitivity_steps = sensitivity, total_coordinate_count = dimension,
    epsilon_effective_upper_numerator = as.character(epsilon$numerator),
    epsilon_effective_upper_denominator = as.character(epsilon$denominator),
    implementation_delta_numerator = as.character(delta$numerator),
    implementation_delta_denominator = as.character(delta$denominator),
    implementation_delta_bound = paste0(
      delta$numerator, "/", delta$denominator),
    maximum_noise_magnitude = draw,
    maximum_chunk_coordinates = if (operational == "a") 128L else 64L,
    private_stream_bytes_per_coordinate = if (operational == "a") 16L else 32L,
    accounting = paste(
      "global iid discrete Laplace certificate", operational),
    capability_available = TRUE)
  plan[names(values)] <- values
  if (!isTRUE(convolution)) return(plan)

  extra <- c(
    "independent_noise_peer_count", "complete_epsilon_per_peer",
    "epsilon_divided_by_peer_count",
    "geometric_variables_per_peer_per_coordinate",
    "geometric_variables_total_per_coordinate",
    "per_peer_implementation_delta_numerator",
    "per_peer_implementation_delta_denominator",
    "per_peer_implementation_delta_bound",
    "release_implementation_delta_aggregation",
    "two_peer_ideal_transfer_delta_numerator",
    "two_peer_ideal_transfer_delta_denominator",
    "two_peer_ideal_transfer_delta_bound", "threat_model",
    "privacy_argument")
  plan[extra] <- as.list(rep("1", length(extra)))
  plan$version <- .DSVERT_JOINT_DP_VECTOR_PLAN_VERSION
  plan$sampler <- .DSVERT_JOINT_DP_VECTOR_SAMPLER
  plan$maximum_chunk_coordinates <- min(8192L, dimension)
  plan$independent_noise_peer_count <- 2L
  plan$complete_epsilon_per_peer <- TRUE
  plan$epsilon_divided_by_peer_count <- FALSE
  plan$geometric_variables_per_peer_per_coordinate <- 2L
  plan$geometric_variables_total_per_coordinate <- 4L
  plan$per_peer_implementation_delta_numerator <-
    plan$implementation_delta_numerator
  plan$per_peer_implementation_delta_denominator <-
    plan$implementation_delta_denominator
  plan$per_peer_implementation_delta_bound <-
    plan$implementation_delta_bound
  plan$release_implementation_delta_aggregation <- "max_per_peer_not_sum"
  plan$threat_model <- threat_model
  plan
}

.synopsis_artifact_planner <- function(
    operational = "a", draw = "100", coordinate_offset = 0L,
    sensitivity = NULL, plan_epsilon = NULL, plan_delta = NULL,
    threat_model = "at_most_one_of_two_noise_peers_colludes_with_analyst",
    threshold_scalar = FALSE) {
  make <- function(request, convolution) {
    plan_request <- request
    if (!is.null(plan_epsilon)) plan_request$epsilon <- plan_epsilon
    if (!is.null(plan_delta)) plan_request$delta <- plan_delta
    .synopsis_artifact_plan(
    plan_request, convolution = convolution, operational = operational,
    draw = draw, coordinate_offset = coordinate_offset,
    sensitivity = if (is.null(sensitivity)) {
      request$sensitivity_steps
    } else sensitivity, threat_model = threat_model,
    threshold_scalar = threshold_scalar)
  }
  list(
    `joint-dp-vector-laplace-plan-v3` = function(request) {
      make(request, FALSE)
    },
    `joint-dp-vector-convolution-plan-v3` = function(request) {
      make(request, TRUE)
    })
}

.synopsis_artifact_names <- function(value) {
  if (!is.list(value)) return(character())
  c(names(value), unlist(lapply(
    value, .synopsis_artifact_names), use.names = FALSE))
}

.synopsis_artifact_compile <- function(
    fixture, planner = .synopsis_artifact_planner(), commitment = strrep(
      "1", 64L), signature_byte = 65L) {
  .dsvert_dp_synopsis_artifact_v1(
    fixture$policy, fixture$manifest,
    .synopsis_artifact_claim_set(fixture, commitment, signature_byte),
    .planner = planner, .verifier = function(...) TRUE)
}

test_that("the synopsis physical plan is data-free for exact and convolution", {
  hashes <- list(exact = character(), convolution = character())
  for (k in c(2L, 3L, 5L)) {
    exact <- .synopsis_artifact_exact_fixture(k)
    convolution <- .synopsis_artifact_fixture(k = k)
    plans <- testthat::with_mocked_bindings(list(
      exact = .dsvert_dp_synopsis_physical_plan_v1(
        exact$policy, exact$manifest,
        .planner = .synopsis_artifact_planner()),
      convolution = .dsvert_dp_synopsis_physical_plan_v1(
        convolution$policy, convolution$manifest,
        .planner = .synopsis_artifact_planner())),
      .dsvert_dp_resolve_snapshot = function(...) {
        stop("physical planning resolved protected data")
      },
      .dsvert_dp_admit_units = function(...) {
        stop("physical planning admitted protected units")
      },
      .package = "dsVert")
    for (kind in names(plans)) {
      plan <- plans[[kind]]
      expect_true(all(c(
        "version", "request", "profile", "lattice", "full_plan",
        "full_plan_sha256", "draw_law", "draw_law_sha256") %in%
        names(plan)))
      expect_match(plan$full_plan_sha256, "^[0-9a-f]{64}$")
      expect_match(plan$draw_law_sha256, "^[0-9a-f]{64}$")
      hashes[[kind]] <- c(hashes[[kind]], plan$draw_law_sha256)
    }
  }
  expect_length(unique(hashes$exact), 1L)
  expect_length(unique(hashes$convolution), 1L)
  expect_false(identical(hashes$exact[[1L]], hashes$convolution[[1L]]))
})

test_that("artifact identity ignores lifecycle, signatures and plan operations", {
  base <- .synopsis_artifact_fixture()
  lifetime <- .synopsis_artifact_fixture(lifetime = 4L)
  first <- .synopsis_artifact_compile(base)
  replay <- .synopsis_artifact_compile(
    lifetime, .synopsis_artifact_planner(
      operational = "b", threat_model = "different planner prose",
      threshold_scalar = TRUE),
    signature_byte = 66L)

  expect_named(first, c("semantic", "artifact_key", "physical_plan"))
  expect_match(first$artifact_key, "^[0-9a-f]{64}$")
  expect_identical(
    first$artifact_key,
    .dsvert_dp_analysis_artifact_key_v1(first$semantic))
  expect_identical(replay$artifact_key, first$artifact_key)
  expect_false(identical(
    replay$physical_plan$full_plan_sha256,
    first$physical_plan$full_plan_sha256))
  expect_identical(
    replay$physical_plan$draw_law_sha256,
    first$physical_plan$draw_law_sha256)
  expect_false(any(.synopsis_artifact_names(first$semantic) %in% c(
    "signature", "full_plan_sha256", "maximum_chunk_coordinates",
    "private_stream_bytes_per_coordinate", "accounting",
    "capability_available", "build_sha256", "session_id", "capsule_id",
    "lifetime_max_distinct_capsules", "registered_release_lifecycle",
    "reuse_and_composition")))
})

test_that("artifact identity binds every DP semantic dimension", {
  base_fixture <- .synopsis_artifact_fixture()
  base <- .synopsis_artifact_compile(base_fixture)
  operational_in_semantic <- base$semantic
  operational_in_semantic$release$draw_law$maximum_chunk_coordinates <- 1L
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(operational_in_semantic),
    "draw law")
  duplicate_role <- base$semantic
  duplicate_role$noise_authority_roles$authority_ids[[2L]] <-
    duplicate_role$noise_authority_roles$authority_ids[[1L]]
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(duplicate_role),
    "noise-authority")
  wrong_shape <- base$semantic
  wrong_shape$public_shape$coordinates <-
    wrong_shape$public_shape$coordinates + 1L
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(wrong_shape),
    "public shape")
  wrong_lattice <- base$semantic
  wrong_lattice$release$lattice$output_lattice_bits <- 9L
  wrong_lattice$release$lattice$output_lattice_scale <- 512
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(wrong_lattice),
    "lattice")
  typed_lattice <- base$semantic
  typed_lattice$release$lattice$output_lattice_bits <- "8"
  typed_lattice$release$lattice$output_lattice_scale <- "256"
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(typed_lattice),
    "lattice")
  wrong_draw <- base$semantic
  wrong_draw$release$draw_law$complete_epsilon_per_peer <- FALSE
  wrong_draw$release$draw_law_sha256 <-
    .dsvert_dp_synopsis_artifact_hash_v1(
      .DSVERT_DP_SYNOPSIS_DRAW_LAW_DOMAIN,
      wrong_draw$release$draw_law)
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(wrong_draw),
    "draw law|calibration")
  unreduced_draw <- base$semantic
  unreduced_draw$release$draw_law$epsilon_effective_upper_numerator <- "2"
  unreduced_draw$release$draw_law$epsilon_effective_upper_denominator <- "2"
  unreduced_draw$release$draw_law_sha256 <-
    .dsvert_dp_synopsis_artifact_hash_v1(
      .DSVERT_DP_SYNOPSIS_DRAW_LAW_DOMAIN,
      unreduced_draw$release$draw_law)
  expect_error(
    .dsvert_dp_analysis_artifact_key_v1(unreduced_draw),
    "draw law|reduced|calibration")
  variants <- list(
    source = .synopsis_artifact_compile(
      base_fixture, commitment = strrep("2", 64L)),
    catalog = .synopsis_artifact_compile(
      .synopsis_artifact_fixture(grid_bits = 9L)),
    epsilon = .synopsis_artifact_compile(
      .synopsis_artifact_fixture(epsilon = 0.5)),
    delta = .synopsis_artifact_compile(
      .synopsis_artifact_fixture(delta = 2e-6)),
    draw_law = .synopsis_artifact_compile(
      base_fixture, .synopsis_artifact_planner(draw = "101")),
    backend = .synopsis_artifact_compile(
      .synopsis_artifact_exact_fixture(2L)))
  changed <- vapply(variants, `[[`, character(1L), "artifact_key")
  expect_true(all(changed != base$artifact_key))

  authorities_ab <- .synopsis_artifact_fixture(k = 3L)
  authorities_ac <- .synopsis_artifact_fixture(
    k = 3L, authority_peers = c("peer_a", "peer_c"))
  ab <- .synopsis_artifact_compile(authorities_ab)
  ac <- .synopsis_artifact_compile(authorities_ac)
  expect_false(identical(ab$artifact_key, ac$artifact_key))
  expect_false(identical(
    ab$semantic$noise_authority_roles$authority_ids,
    ac$semantic$noise_authority_roles$authority_ids))
})

test_that("physical planning rejects dimension and sensitivity mismatch", {
  fixture <- .synopsis_artifact_exact_fixture(2L)
  expect_error(.dsvert_dp_synopsis_physical_plan_v1(
    fixture$policy, fixture$manifest,
    .planner = .synopsis_artifact_planner(coordinate_offset = 1L)),
    "coordinate|planner|certificate")
  expect_error(.dsvert_dp_synopsis_physical_plan_v1(
    fixture$policy, fixture$manifest,
    .planner = .synopsis_artifact_planner(sensitivity = "999")),
    "sensitivity|planner|certificate")
  expect_error(.dsvert_dp_synopsis_physical_plan_v1(
    fixture$policy, fixture$manifest,
    .planner = .synopsis_artifact_planner(plan_epsilon = "8.000000000000000000e+00")),
    "epsilon|privacy|calibration|certificate")
  expect_error(.dsvert_dp_synopsis_physical_plan_v1(
    fixture$policy, fixture$manifest,
    .planner = .synopsis_artifact_planner(plan_delta = "1.000000000000000000e-03")),
    "delta|privacy|calibration|certificate")
})

test_that("declared synopsis decimals reproduce Gaussian guarded requests", {
  epsilon <- .dsvert_dp_synopsis_declared_decimal_v1(
    1, "epsilon", 8)
  delta <- .dsvert_dp_synopsis_declared_decimal_v1(
    1e-6, "delta", 1, open_maximum = TRUE)
  expect_identical(as.numeric(epsilon), 1)
  expect_identical(as.numeric(delta), 1e-6)
  expect_identical(
    .dsvert_dp_capsule_exact_gaussian_request(1, 1e-6, 256, 3L),
    .dsvert_dp_capsule_exact_gaussian_request(
      as.numeric(epsilon), as.numeric(delta), 256, 3L))
})

test_that("zero delta reaches Laplace planning but finite v3 plans fail closed", {
  zero <- "0.000000000000000000e+00"
  expect_identical(
    .dsvert_dp_synopsis_declared_decimal_v1(
      0, "delta", 1, open_maximum = TRUE, allow_zero = TRUE),
    zero)
  expect_identical(
    .dsvert_dp_synopsis_decimal_v1(
      zero, "delta", 1, open_maximum = TRUE, allow_zero = TRUE),
    zero)
  expect_error(
    .dsvert_dp_synopsis_declared_decimal_v1(
      0, "delta", 1, open_maximum = TRUE),
    "delta")
  expect_true(.dsvert_dp_synopsis_fraction_leq_decimal_v1(
    "0", "1", zero))
  expect_false(.dsvert_dp_synopsis_fraction_leq_decimal_v1(
    "1", "1000000000000000000000000000000", zero))

  fixtures <- list(
    convolution = .synopsis_artifact_fixture(k = 2L, delta = 0))
  commands <- c(
    convolution = "joint-dp-vector-convolution-plan-v3")
  for (kind in names(fixtures)) {
    observed <- NULL
    planner <- .synopsis_artifact_planner()
    original <- planner[[commands[[kind]]]]
    planner[[commands[[kind]]]] <- function(request) {
      observed <<- request
      original(request)
    }
    expect_error(
      .dsvert_dp_synopsis_physical_plan_v1(
        fixtures[[kind]]$policy, fixtures[[kind]]$manifest,
        .planner = planner),
      "pure DP|positive implementation delta|finite")
    expect_identical(observed$delta, zero)
  }
})

test_that("a manifest-certified Gaussian plan produces the same artifact", {
  value <- .synopsis_artifact_helpers$.vector_capsule_fixture(
    gaussian = TRUE, k = 2L, count_only = TRUE)
  fixture <- list(
    policy = value$policies[[1L]], manifest = value$manifests[[1L]],
    pins = value$policies[[1L]]$peer_pinset)
  artifact <- .dsvert_dp_synopsis_artifact_v1(
    fixture$policy, fixture$manifest,
    .synopsis_artifact_claim_set(fixture),
    .planner = value$planner, .verifier = function(...) TRUE)
  selection <- fixture$manifest$workload$mechanism_selection
  expect_identical(
    artifact$physical_plan$request,
    .dsvert_dp_analysis_canonical_value_v1(
      selection$gaussian_calibration_request))
  expect_identical(
    artifact$physical_plan$full_plan_sha256,
    selection$gaussian_plan_sha256)
  expect_identical(
    .dsvert_dp_analysis_artifact_key_v1(artifact$semantic),
    artifact$artifact_key)
})
