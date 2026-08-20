.dp_descriptor_test_align <- function(data) {
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(seq_len(32L))))
  .psi_attach_alignment_manifest(data, "patient_id", token)
}

test_that("the local DP descriptor rejects raw and generic-manifest objects", {
  raw <- data.frame(
    patient_id = c("p1", "p2", "p3"),
    age = c(40, 55, 67), stringsAsFactors = FALSE)
  expect_error(
    dsvertDPDatasetDescriptor(raw, "cohort-main", "v1"),
    "not PSI-aligned")

  aligned <- .dp_descriptor_test_align(raw)
  expect_error(
    dsvertDPDatasetDescriptor(aligned, "cohort-main", "v1"),
    "Padded PSI alignment attestation")

  expect_error(dsvertDPDatasetDescriptor(
    aligned, "bad id", "v1"), "unsupported characters")
  expect_error(dsvertDPDatasetDescriptor(
    aligned, "cohort-main", "bad version"), "unsupported characters")
  expect_error(dsvertDPDatasetDescriptor(
    unclass(aligned), "cohort-main", "v1"), "data must be")
})

test_that("the local DP descriptor is absent from every remote and public surface", {
  registry <- .dsvert_remote_function_registry(refresh = TRUE)
  expect_false("dsvertDPDatasetDescriptor" %in% names(registry))

  description <- read.dcf(file.path(.dsvert_test_source_root(), "DESCRIPTION"))
  registered <- unique(trimws(unlist(strsplit(
    paste(description[1L, c("AggregateMethods", "AssignMethods")],
          collapse = ","), ",", fixed = TRUE))))
  expect_false("dsvertDPDatasetDescriptor" %in% registered)

  descriptor <- list(
    id = "cohort-main", version = "v1",
    snapshot_sha256 = strrep("1", 64L),
    alignment_manifest_hash = strrep("2", 64L),
    alignment_manifest_version = 3L)
  public <- .dsvert_dp_policy_public(list(
    schema_version = 8L,
    policy_contract = "single_disclosure_safe_capsule_policy_v1",
    domain = "cohort-release-v1", cohort_id = "cohort-main",
    global_total_epsilon = 1, global_total_delta = 0,
    adjacency = "add_remove_patient", unit_capacity = 100L,
    fixed_cohort_size = NULL, max_records_per_unit = 1L,
    overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    patient_column = "patient_id", datasets = list(DA = descriptor),
    categorical_levels = list(), numeric_bounds = list(age = c(0, 120)),
    numeric_grid_bits = 16L, peer_count = 2L,
    peer_pinset_sha256 = strrep("a", 64L),
    designated_noise_peers = c("site_a", "site_b"),
    noise_selection = list(), transcript_privacy =
      .dsvert_dp_transcript_claim()$policy_value))
  encoded <- jsonlite::toJSON(public, auto_unbox = TRUE, null = "null")
  expect_false(grepl(descriptor$snapshot_sha256, encoded, fixed = TRUE))
  expect_false(grepl(descriptor$alignment_manifest_hash, encoded, fixed = TRUE))
})

test_that("the aligned-dataset registry rechecks its directory after chmod", {
  root <- withr::local_tempdir(pattern = "dsvert-registry-path-recheck-")
  Sys.chmod(root, mode = "0700")
  withr::local_options(list(dsvert.state_dir = root))
  root_checks <- 0L
  link_after_chmod <- function(path) {
    if (identical(path, root)) {
      root_checks <<- root_checks + 1L
      return(root_checks >= 2L)
    }
    FALSE
  }
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_alignment_registry_path(
      "DA", "cohort-main", "v1", paste0("pinset_", strrep("a", 64L))),
    .dsvert_dp_path_is_link = link_after_chmod,
    .package = "dsVert"),
    "owner-only")
  expect_identical(root_checks, 2L)
})

test_that("a padded v4 descriptor is bound to the active peer pinset", {
  pins <- c(
    site_a = base64_to_base64url(jsonlite::base64_enc(as.raw(0:31))),
    site_b = base64_to_base64url(jsonlite::base64_enc(as.raw(32:63))))
  bound <- .dsvert_test_padded_dp_binding(
    data.frame(
      patient_id = c("p1", "p2"), value = c(1, 2),
      stringsAsFactors = FALSE),
    "patient_id", "cohort-main", "v1", pins)
  policy <- list(
    domain = "descriptor-pinset-test",
    patient_column = "patient_id",
    peer_pinset = pins,
    require_alignment_manifest = TRUE,
    datasets = list(DA = bound$descriptor))

  snapshot_digest <- .dsvert_dp_snapshot_digest
  snapshot_sha256 <- snapshot_digest(bound$data)
  expect_identical(
    .dsvert_dp_padded_alignment_binding(bound$data),
    .dsvert_dp_padded_alignment_binding(
      bound$data, snapshot_sha256 = snapshot_sha256))
  expect_error(
    .dsvert_dp_padded_alignment_binding(
      bound$data, snapshot_sha256 = strrep("A", 64L)),
    "precomputed protected snapshot digest is invalid")

  digest_calls <- 0L
  binding <- testthat::with_mocked_bindings(
    .dsvert_dp_dataset_binding(
      policy, "DA", bound$data, as.raw(seq_len(32L))),
    .dsvert_dp_snapshot_digest = function(data) {
      digest_calls <<- digest_calls + 1L
      snapshot_digest(data)
    },
    .package = "dsVert")
  expect_identical(digest_calls, 1L)
  expect_identical(
    binding$public$alignment_manifest_hash,
    bound$descriptor$alignment_manifest_hash)

  rotated <- pins
  rotated[["site_b"]] <- base64_to_base64url(
    jsonlite::base64_enc(as.raw(64:95)))
  policy$peer_pinset <- rotated
  expect_error(
    .dsvert_dp_dataset_binding(
      policy, "DA", bound$data, as.raw(seq_len(32L))),
    "different pinned peer set")
})

test_that("padded v5 keeps local id aliases out of the semantic binding", {
  pins <- c(
    site_a = base64_to_base64url(jsonlite::base64_enc(as.raw(0:31))),
    site_b = base64_to_base64url(jsonlite::base64_enc(as.raw(32:63))))
  bound <- .dsvert_test_padded_dp_binding(
    data.frame(
      subject_id = c("p1", "p2"), value = c(1, 2),
      stringsAsFactors = FALSE),
    "subject_id", "cohort-main", "v1", pins,
    privacy_unit_id = "person:v1")

  binding <- .dsvert_dp_padded_alignment_binding(bound$data)
  expect_identical(binding$semantic$id_column, "person:v1")
  expect_identical(binding$alignment$id_col, "subject_id")
  expect_identical(binding$local_id_column, "subject_id")

  root <- withr::local_tempdir(pattern = "dsvert-registry-alias-")
  Sys.chmod(root, mode = "0700")
  withr::local_options(list(
    dsvert.state_dir = root,
    dsvert.identity_seed = jsonlite::base64_enc(as.raw(rep(7L, 32L))),
    dsvert.peer_name = "site_a",
    dsvert.trusted_peers = pins["site_b"],
    dsvert.dp.patient_column = "subject_id",
    dsvert.dp.datasets = list(
      DA = list(id = "cohort-main", version = "v1"))))

  path <- .dsvert_dp_alignment_registry_commit("DA", bound$data)
  expect_true(file_test("-f", path))
  expect_identical(
    .dsvert_dp_alignment_registry_resolve_templates(
      getOption("dsvert.dp.datasets"), "subject_id", pins)$DA,
    binding$descriptor)
  expect_error(
    .dsvert_dp_alignment_registry_resolve_templates(
      getOption("dsvert.dp.datasets"), "patient_id", pins),
    "contradicts the active custodian policy")
})
