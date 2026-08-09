test_that("DP query ids are canonical, versioned, and semantics-bound", {
  expect_true(.dsvert_dp_assert_canonical_query_runtime())
  secret <- as.raw(seq_len(32L))
  policy <- list(
    mechanism_version =
      "dsvert-dp-v7-contingency-unit-aggregation-1",
    domain = "study-domain",
    noise_root = list(epoch = 1, key_id = "file_test"))
  dataset <- list(
    data_name = "protected", id = "cohort", version = "v1",
    alignment_manifest_hash = NULL,
    alignment_manifest_version = NULL)
  arguments <- list(
    variable = "x", bounds = c(-0, 1L),
    admission = list(max_records = 1L, capacity = 100L))

  expected <- .dsvert_dp_query_hash(
    secret, policy, dataset, "bounded_mean", arguments)
  expect_match(expected, "^[0-9a-f]{64}$")
  # Golden vector: a dependency or R upgrade must not silently change the
  # canonical wire representation and reroll a previously released query.
  expect_identical(
    expected,
    "c90fa516eee010896212cf1d716efe8b14faa0fac50d2c452891e45f733335aa")

  reordered <- list(
    admission = list(capacity = 100, max_records = 1),
    bounds = c(0, 1), variable = "x")
  reordered_dataset <- dataset[c(
    "version", "data_name", "alignment_manifest_version", "id",
    "alignment_manifest_hash")]
  expect_identical(
    .dsvert_dp_query_hash(
      secret, policy, reordered_dataset, "bounded_mean", reordered),
    expected)

  changed <- arguments
  changed$bounds <- c(0, 2)
  expect_false(identical(
    .dsvert_dp_query_hash(
      secret, policy, dataset, "bounded_mean", changed),
    expected))
  changed_policy <- policy
  changed_policy$noise_root$epoch <- 2
  expect_false(identical(
    .dsvert_dp_query_hash(
      secret, changed_policy, dataset, "bounded_mean", arguments),
    expected))

  contingency_arguments <- list(
    row_var = "exposure", col_var = "outcome",
    row_levels = c("no", "yes"), col_levels = c("no", "yes"),
    unit_aggregation_policy = "consistent_cell_else_exclude_v1")
  contingency_hash <- .dsvert_dp_query_hash(
    secret, policy, dataset, "fixed_domain_contingency",
    contingency_arguments)
  without_aggregation_policy <- contingency_arguments
  without_aggregation_policy$unit_aggregation_policy <- NULL
  expect_false(identical(
    .dsvert_dp_query_hash(
      secret, policy, dataset, "fixed_domain_contingency",
      without_aggregation_policy),
    contingency_hash))
  changed_aggregation_policy <- contingency_arguments
  changed_aggregation_policy$unit_aggregation_policy <-
    "different_version"
  expect_false(identical(
    .dsvert_dp_query_hash(
      secret, policy, dataset, "fixed_domain_contingency",
      changed_aggregation_policy),
    contingency_hash))
})

test_that("DP query canonicalisation rejects ambiguous values", {
  expect_error(
    .dsvert_dp_canonical_query_value(list(a = c(x = 1))),
    "vectors must be unnamed")
  expect_error(
    .dsvert_dp_canonical_query_value(list(a = Inf)),
    "non-finite")
  expect_error(
    .dsvert_dp_canonical_query_value(structure(list(a = 1),
                                                names = NA_character_)),
    "invalid object fields")
  expect_error(
    .dsvert_dp_canonical_query_value(list(a = as.raw(1))),
    "unsupported value type")
})
