test_that("grouped source roles include label-only owners with two authorities", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .grouped_contract_fixture("lmm", owners = owners)
    spec <- f$contract$spec
    expect_equal(unlist(spec$participating_peers), names(f$policy$peer_pinset))
    expect_equal(unlist(spec$computation_peers), c("peer_a", "peer_b"))
    expect_identical(spec$grouping$owner_peer, "peer_a")
    expect_identical(spec$outcome$owner_peer, "peer_b")
    expect_setequal(vapply(f$contract$source_contract$private_layout$blocks,
      `[[`, character(1L), "owner_peer"), names(f$policy$peer_pinset))
    expect_identical(.dsvert_dp_grouped_cross_contract_validate(
      f$contract, f$policy, f$schema)$spec$family, "lmm")
    if (owners > 2L) {
      expect_false("peer_a" %in% vapply(spec$predictors, `[[`, character(1L), "owner_peer"))
    }
    raw <- f$raw
    raw$grouping$cluster_capacity <- 65
    expect_error(.dsvert_dp_grouped_cross_spec(raw, f$policy, f$authenticated),
                 class = "dsvert_dp_public_failure")
  }
})

test_that("LMM materialization preserves fractional outcomes and private routing validity", {
  f <- .grouped_contract_fixture("lmm")
  artifact <- .dsvert_dp_grouped_cross_workload_artifact(f$contract)
  layout <- f$contract$source_contract$private_layout
  projection <- .dsvert_dp_glm_grid_cross_source_blocks(artifact, layout$private_start)
  expect_equal(projection$cursor - 1, layout$transport_coordinate_count)
  expect_identical(artifact$outcome_encoding, list(kind = "fixed_point", q = 50))
  blocks <- projection$blocks
  outcome <- blocks[["grouped::peer_b$y::value"]]
  predictor <- blocks[["grouped::peer_a$x::value"]]
  input <- list(unit_values = c(0, 1/16, 3/8, 1, NA),
                valid = c(TRUE, TRUE, TRUE, TRUE, FALSE))
  expected <- c(0, 2^46, 3*2^47, 2^50, rep(0, 4))
  expect_identical(.dsvert_dp_grouped_cross_source_values(input, outcome), expected)
  expect_identical(.dsvert_dp_grouped_cross_source_values(input, predictor), expected)
  expect_equal(.dsvert_dp_grouped_cross_source_values(input,
    blocks[["grouped::peer_b$y::validity"]]), c(rep(1, 4), rep(0, 4)))
  routing <- blocks[["grouped::peer_a$cluster::value"]]
  expect_true(routing$private_routing_input)
  expect_identical(routing$input_family, "grouped_grid")
  expect_equal(.dsvert_dp_grouped_cross_source_values(list(cell = c(2, 1, NA)), routing),
               c(1, rep(0, 7)))
  expect_equal(.dsvert_dp_grouped_cross_source_values(list(cell = c(2, 1, NA)),
    blocks[["grouped::peer_a$cluster::validity"]]), c(1, 1, rep(0, 6)))
  expect_error(.dsvert_dp_grouped_cross_source_values(
    list(cell = rep(1, 9)), routing), class = "dsvert_dp_public_failure")
})

test_that("binary grouped outcomes retain integer encoding and reject fractional values", {
  f <- .grouped_contract_fixture("binomial_glmm")
  artifact <- .dsvert_dp_grouped_cross_workload_artifact(f$contract)
  blocks <- .dsvert_dp_grouped_cross_source_blocks(artifact, 8193)$blocks
  input <- list(unit_values = c(0, 1/16, 1, 2), valid = rep(TRUE, 4))
  expect_identical(artifact$outcome_encoding, list(kind = "integer"))
  expect_equal(.dsvert_dp_grouped_cross_source_values(input,
    blocks[["grouped::peer_b$y::value"]]), c(0, 0, 1, rep(0, 5)))
  expect_equal(.dsvert_dp_grouped_cross_source_values(input,
    blocks[["grouped::peer_b$y::validity"]]), c(1, 0, 1, rep(0, 5)))
})

test_that("signed schema pins the private routing sidecar and source scale", {
  f <- .grouped_contract_fixture("lmm", owners = 5L)
  mutations <- list(
    function(x) { x$spec$outcome_encoding$q <- 49; x },
    function(x) { x$spec$predictor_encoding$q <- 49; x },
    function(x) { x$spec$routing_inputs[[1]]$owner_peer <- "peer_b"; x },
    function(x) { x$spec$routing_inputs[[1]]$levels <- rev(x$spec$routing_inputs[[1]]$levels); x },
    function(x) { x$source_contract$private_layout$grouping_controls$source_encoding_sha256 <- strrep("0", 64); x },
    function(x) { x$source_contract$private_layout$blocks[[5]]$private_routing_input <- FALSE; x })
  for (mutate in mutations) {
    expect_error(.dsvert_dp_grouped_cross_contract_validate(
      f$sign(mutate(f$unsigned)), f$policy, f$schema), class = "dsvert_dp_public_failure")
  }
})

test_that("private source producer preserves legacy blocks and only materializes locally owned roles", {
  legacy <- list(dataset = "cohort", variable = "x", owner_peer = "peer_a",
    kind = "value", lower = 0, upper = 1)
  routing <- list(input_family = "grouped_grid", dataset = "cohort", variable = "cluster",
    owner_peer = "peer_a", kind = "value", outcome = FALSE, length = 4L,
    private_routing_input = TRUE, levels = c("a", "b"), maximum = 1)
  outcome <- list(input_family = "grouped_grid", dataset = "cohort", variable = "y",
    owner_peer = "peer_b", kind = "value", outcome = TRUE, length = 4L,
    outcome_encoding = list(kind = "fixed_point", q = 50),
    lower = 0, upper = 1, fraction_bits = 50, maximum = 2^50)
  segments <- list(
    list(type = "private", start = 1L, end = 2L, length = 2L, block = legacy),
    list(type = "private", start = 3L, end = 6L, length = 4L, block = routing),
    list(type = "private", start = 7L, end = 10L, length = 4L, block = outcome))
  context <- list(local_peer = "peer_a", policy = list(), release = list(),
    manifest = list(bounds = list(numeric_grid_bits = 16)),
    layout = list(transport_coordinate_count = 10),
    snapshots = list(cohort = list(data = data.frame(x = c(.25, .75),
      y = c(1/8, 1/2), cluster = c("b", NA_character_)))))
  local_mocked_bindings(
    .dsvert_dp_gaussian_cross_source_context = function(...) context,
    .dsvert_dp_gaussian_cross_source_segments = function(...) segments,
    .dsvert_dp_admit_units = function(...) list(),
    .dsvert_dp_bounded_numeric = function(data, policy, variable, admission)
      list(unit_values = data[[variable]], valid = is.finite(data[[variable]])),
    .dsvert_dp_capsule_bounded_category = function(data, policy, variable, levels, admission)
      list(cell = match(data[[variable]], levels)))
  producer <- .dsvert_dp_gaussian_cross_source_producer(list(), list(), list(),
    compute_commitment = FALSE)
  expect_equal(as.numeric(producer$read_range(1, 10)), c(16384, 49152, 1, rep(0, 7)))
  context$local_peer <- "peer_b"
  producer <- .dsvert_dp_gaussian_cross_source_producer(list(), list(), list(),
    compute_commitment = FALSE)
  expect_equal(as.numeric(producer$read_range(1, 10)), c(rep(0, 6), 2^47, 2^49, 0, 0))
})
