test_that("GLMM-scale Gaussian unavailability retains the certified Laplace fallback", {
  # n2000/p3, two beta values crossed with variances 0 and 1/4, g16.
  # Count also occupies the common g16 lattice. Cluster count does not
  # multiply patient sensitivity: one patient changes one cluster range.
  caps <- c(65536, 259817, 277478, 516327, 543518)
  l2 <- .dsvert_dp_capsule_l2_sqrt(sum(caps^2))
  policy <- list(global_total_epsilon = 8, global_total_delta = 2^-100)
  request <- .dsvert_dp_capsule_exact_gaussian_request(
    8, 2^-100, l2, length(caps))
  expect_error(.callMpcTool("joint-dp-vector-gaussian-plan-v2", request),
    "outside the certified support")
  select <- function() .dsvert_dp_capsule_mechanism_selection(
    policy, length(caps), sum(caps), l2)
  selection <- select()
  expect_identical(selection$mechanism, "discrete-laplace")
  expect_identical(selection$sensitivity_norm, "l1")
  expect_equal(selection$sensitivity, 1662676)
  expect_identical(selection$certificate$epsilon, 8)
  expect_identical(selection$certificate$allocated_delta, 2^-100)
  expect_false(selection$certificate$gaussian_backend_available)
  expect_identical(selection$certificate$decision,
    "fixed_work_gaussian_unavailable_explicit_laplace_fallback")
  expect_identical(selection$certificate$deployed_backends,
    c("joint-discrete-laplace-v3", "exact-unbounded-discrete-laplace-modular-v4"))
  expect_identical(select(), selection)
})
