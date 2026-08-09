test_that("column discovery is policy-only and never touches protected data", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  makeActiveBinding("D", function(value) {
    stop("protected data object was accessed", call. = FALSE)
  }, environment())
  on.exit(rm("D", envir = environment()), add = TRUE)
  testthat::local_mocked_bindings(
    .dsvert_dp_policy = function() list(
      datasets = list(D = list()),
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
  expect_identical(result$columns, c("group", "patient_id", "x"))
  rejected <- tryCatch(dsvertColNamesDS("missing"), error = identity)
  expect_s3_class(rejected, "dsvert_capsule_manifest_rejected")
  expect_identical(rejected$reason_code, "unknown_policy_dataset")
})

test_that("public fixed-cohort count is policy-only", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  makeActiveBinding("D", function(value) {
    stop("protected data object was accessed", call. = FALSE)
  }, environment())
  on.exit(rm("D", envir = environment()), add = TRUE)
  testthat::local_mocked_bindings(
    .dsvert_dp_policy = function() list(
      adjacency = "replace_one_fixed_cohort",
      datasets = list(D = list()), fixed_cohort_size = 17L,
      peer_pinset = c(peer_a = "pin-a", peer_b = "pin-b")),
    .dsvert_dp_secret = function() stop("secret was requested", call. = FALSE),
    .dsvert_dp_resolve_snapshot = function(...) {
      stop("protected snapshot was resolved", call. = FALSE)
    },
    .dsvert_dp_admit_units = function(...) {
      stop("protected units were admitted", call. = FALSE)
    },
    .package = "dsVert"
  )

  result <- dsvertPublicFixedCohortCountDS("D")
  expect_identical(result$value, 17)
  expect_identical(result$data_dependency,
                   "none_public_fixed_cohort_policy")
  rejected <- tryCatch(
    dsvertPublicFixedCohortCountDS("missing"), error = identity)
  expect_s3_class(rejected, "dsvert_capsule_manifest_rejected")
  expect_identical(rejected$reason_code, "unknown_policy_dataset")
})
