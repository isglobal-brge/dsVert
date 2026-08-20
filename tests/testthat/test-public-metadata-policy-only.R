test_that("column discovery is policy-only and never touches protected data", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  makeActiveBinding("D", function(value) {
    stop("protected data object was accessed", call. = FALSE)
  }, environment())
  on.exit(rm("D", envir = environment()), add = TRUE)
  testthat::local_mocked_bindings(
    .dsvert_dp_policy = function() list(
      peer_name = "site_a",
      datasets = list(D = list(id = "cohort", version = "v1")),
      patient_column = "patient_id",
      categorical_levels = list(group = c("a", "b")),
      numeric_bounds = list(x = c(0, 10)),
      capsule_dataset_mapping = list(D = c("group", "x"))),
    .dsvert_dp_secret = function() stop("secret was requested", call. = FALSE),
    .dsvert_dp_dataset_binding = function(...) {
      stop("protected dataset binding was requested", call. = FALSE)
    },
    .package = "dsVert"
  )

  result <- dsvertColNamesDS("D")
  expect_identical(names(result), c(
    "version", "peer_name", "dataset_id", "dataset_version", "columns",
    "kinds", "roles", "data_access"))
  expect_identical(result$version, "dsvert-public-column-catalog-v1")
  expect_identical(result$peer_name, "site_a")
  expect_identical(result$dataset_id, "cohort")
  expect_identical(result$dataset_version, "v1")
  expect_identical(result$columns, c("group", "patient_id", "x"))
  expect_identical(result$kinds, c(
    group = "categorical", patient_id = "identifier", x = "numeric"))
  expect_identical(result$roles, c(
    group = "data", patient_id = "id", x = "data"))
  expect_false(result$data_access)
  rejected <- tryCatch(dsvertColNamesDS("missing"), error = identity)
  expect_s3_class(rejected, "dsvert_capsule_manifest_rejected")
  expect_identical(rejected$reason_code, "unknown_policy_dataset")
})
