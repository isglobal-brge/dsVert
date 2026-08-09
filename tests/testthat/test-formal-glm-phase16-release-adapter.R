test_that("formal GLM Phase-1.6 signed postprocessing is exact and unclamped", {
  hash <- function(value) digest::digest(
    value, algo = "sha256", serialize = FALSE)
  binding <- list(
    version = "dsvert-formal-glm-phase16-release-adapter-v1",
    binding_sha256 = hash("binding"),
    common_ring_bits = 128L,
    output_lattice_bits = 8L,
    coordinate_count = 4L,
    shifted_upper_bounds = as.list(c("20", "20", "20", "18")),
    signed_lower_bounds = as.list(c("-10", "-10", "-10", "-9")),
    signed_upper_bounds = as.list(c("10", "10", "10", "9")),
    mechanism = "joint_discrete_gaussian_one_global_draw",
    allocation = "one_stacked_capsule_vector",
    sensitivity_steps = "10",
    sensitivity_norm = "l2",
    sensitivity_proof =
      paste0("exact-fixed-point-coordinate-recurrence-signed-floor-",
             "lattice-l2-v1"),
    sensitivity_certificate_kind =
      "machine_proven_integer_lattice_l2_v1",
    sensitivity_certificate_sha256 = hash("certificate"),
    sensitivity_certificate = list(
      version = "dsvert-formal-glm-phase15-l2-sensitivity-certificate-v1",
      kind = "machine_proven_integer_lattice_l2_v1",
      status = "machine_proven",
      norm = "l2",
      selected_proof = paste0(
        "exact-fixed-point-coordinate-recurrence-signed-floor-",
        "lattice-l2-v1"),
      selected_bound_steps = "10",
      coordinate_count = 4L,
      output_lattice_bits = 8L,
      shifted_upper_bounds = as.list(c("20", "20", "20", "18")),
      universal_coordinate_bounds = as.list(c("20", "20", "20", "18")),
      universal_l2_squared = "1524",
      universal_bound_steps = "40",
      recurrence_quantized_bounds = as.list(c("5", "5", "5", "5")),
      recurrence_l2_squared = "100",
      recurrence_bound_steps = "10",
      quantization_inequality = paste0(
        "abs(floor(x/d)-floor(y/d))<=ceil(abs(x-y)/d)_",
        "per_coordinate_v1"),
      selection =
        "minimum_of_machine_proven_positive_integer_l2_bounds_v1"),
    tight_sensitivity_status = "machine_proven",
    quantization =
      "signed_floor_inside_exact_gc_then_public_translation_v1",
    signed_decode =
      "subtract_public_quantized_box_after_single_dp_opening_v1",
    quantization_error = paste0(
      "0<=exact_coefficient-released_lattice_coefficient<",
      "2^-output_lattice_bits_before_dp_noise_v1"),
    range_certificate = paste0(
      "translated_coordinate_in_[0,2Bq]_and_signed_release_",
      "in_[-Bq,Bq]_v1"),
    no_wrap_certificate = paste0(
      "bridge_coordinates_l2_sensitivity_and_common_gaussian_",
      "saturating_clamp_ring128_checked_v1"),
    opening_count = 1L,
    production_ready = FALSE)
  opening <- list(
    release_binding_sha256 = binding$binding_sha256,
    clamped_scaled_values = as.list(c("0", "9", "10", "18")),
    validity = TRUE,
    preclamp_values_returned = FALSE,
    source_share_exposed = FALSE,
    private_seed_exposed = FALSE,
    openings_performed = 1L)

  result <- .dsvert_formal_glm_phase16_signed_postprocess(opening, binding)
  expect_identical(
    unlist(result$signed_lattice_values, use.names = FALSE),
    c("-10", "-1", "0", "9"))
  expect_identical(result$coefficient_denominator, "256")
  expect_identical(result$additional_openings, 0)
  expect_identical(result$total_openings, 1)
  expect_identical(result$common_shifted_values_returned, FALSE)
  expect_identical(
    .dsvert_formal_glm_phase16_signed_postprocess(opening, binding),
    result)

  outside <- opening
  outside$clamped_scaled_values[[4L]] <- "19"
  expect_error(
    .dsvert_formal_glm_phase16_signed_postprocess(outside, binding),
    "outside")
  extra <- opening
  extra$openings_performed <- 2L
  expect_error(
    .dsvert_formal_glm_phase16_signed_postprocess(extra, binding),
    "exactly one")
  tampered <- binding
  tampered$sensitivity_certificate$recurrence_quantized_bounds[[1L]] <- "6"
  expect_error(
    .dsvert_formal_glm_phase16_signed_postprocess(opening, tampered),
    "recurrence")
})

test_that("formal GLM Phase-1.6 blocks mismatched mechanism and manifest with zero openings", {
  binding <- list(
    version = "dsvert-formal-glm-phase16-release-adapter-v1",
    binding_sha256 = paste(rep("a", 64L), collapse = ""),
    mechanism = "joint_discrete_gaussian_one_global_draw",
    allocation = "one_stacked_capsule_vector",
    opening_count = 1L,
    production_ready = FALSE)
  error <- tryCatch(
    .dsvert_formal_glm_phase16_authorize_opening(binding),
    error = identity)
  expect_s3_class(error, "dsvert_formal_glm_phase16_release_unavailable")
  expect_identical(error$code,
    "formal_glm_productive_joint_dp_release_lifecycle_unavailable")
  expect_identical(error$openings_performed, 0L)
  expect_identical(error$production_ready, FALSE)
  expect_length(error$missing, 1L)

  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  aggregate <- trimws(strsplit(
    description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  exports <- sub("^export\\((.*)\\)$", "\\1", grep(
    "^export\\(", readLines(.dsvert_test_package_file("NAMESPACE")),
    value = TRUE))
  for (forbidden in c("formalGLMPhase16", "formalGLMPhase17")) {
    expect_false(any(grepl(forbidden, c(aggregate, exports), fixed = TRUE)))
  }
})
