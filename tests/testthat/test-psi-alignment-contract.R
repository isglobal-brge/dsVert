test_that("PSI missing-data policies select rows without mutating the source", {
  D <- data.frame(
    patient_id = c("id-1", "id-2", NA_character_, "id-4"),
    x = c(1, NA, 3, 4), stringsAsFactors = FALSE)
  original <- D

  expect_identical(.psi_analysis_rows(D, "patient_id", "na.omit"),
                   c(1L, 4L))
  expect_identical(.psi_analysis_rows(D, "patient_id", "none"),
                   c(1L, 2L, 4L))
  expect_error(.psi_analysis_rows(D, "patient_id", "na.fail"),
               "missing values")
  expect_identical(D, original)
})

test_that("PSI missing policy and identifiers fail closed", {
  D <- data.frame(patient_id = c("id-1", "id-1", "id-3"), x = 1:3)
  expect_error(.psi_analysis_rows(D, "patient_id", "bad"), "na_action")
  expect_error(.psi_analysis_rows(D, "patient_id", "none"), "unique")

  blank <- data.frame(patient_id = c("id-1", "", "id-3"), x = 1:3)
  expect_identical(.psi_analysis_rows(blank, "patient_id", "none"),
                   c(1L, 3L))
  expect_error(.psi_analysis_rows(blank, "patient_id", "na.fail"),
               "missing identifiers")
})

test_that("private alignment manifests bind current identifier order", {
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))
  D <- data.frame(patient_id = sprintf("id-%02d", 1:6), x = 11:16)
  aligned <- .psi_attach_alignment_manifest(D, "patient_id", token)
  public <- .psi_validate_alignment_manifest(aligned)

  expect_named(public, c("version", "hash", "n", "id_col"))
  expect_identical(public$version, 2L)
  expect_identical(public$n, 6L)
  expect_match(public$hash, "^[0-9a-f]{64}$")
  expect_error(.psi_validate_alignment_manifest(aligned[6:1, , drop = FALSE]),
               "not bound to the current row order")
  expect_error(.psi_validate_alignment_manifest(aligned[1:5, , drop = FALSE]),
               "row count")
  changed <- aligned
  changed$patient_id[[1L]] <- "different-id"
  expect_error(.psi_validate_alignment_manifest(changed),
               "not bound to the current row order")
})

test_that("numeric identifier commitments ignore display options", {
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))
  ids <- c(1, 10000000, 9007199254740991)
  first <- withr::with_options(
    list(scipen = -9, digits = 3, OutDec = ","),
    .psi_alignment_order_binding(ids, token))
  second <- withr::with_options(
    list(scipen = 100, digits = 15, OutDec = "."),
    .psi_alignment_order_binding(ids, token))
  expect_identical(second, first)
  expect_error(.psi_alignment_order_binding(c(1, 1.5), token),
               "exactly representable integers")
})

test_that("padded attestation persists without cardinality or patient digest", {
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))
  contract <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = paste(rep("a", 64L), collapse = ""),
    attestation_id = paste0("attest_", paste(rep("b", 64L), collapse = "")),
    policy_id = paste0("policy_", paste(rep("c", 64L), collapse = "")),
    alignment_purpose = "patient-record-alignment-v1",
    dataset_id = "test-logical-cohort",
    dataset_version = "v1",
    id_column = "patient_id",
    source_binding_id = .psi_padded_test_source_public(
      "patient_id")$source_binding_id,
    pinset_id = paste0("pinset_", paste(rep("d", 64L), collapse = "")),
    capacity = 64L, relay_frame_bytes = 65536L,
    inline_max_bytes = 65536L,
    peer_names = c("site_a", "site_b", "site_c"),
    reference_peer = "site_a", compute_peers = c("site_a", "site_b"))
  D <- .psi_attach_alignment_manifest(
    data.frame(patient_id = sprintf("id-%02d", 1:6)),
    "patient_id", token)
  D <- .psi_padded_attach_attestation(D, contract)

  public <- psiPaddedAttestationDS("D")
  expect_identical(public, .psi_padded_public_attestation(contract))
  reloaded <- unserialize(serialize(D, NULL, version = 3L))
  expect_identical(
    .psi_padded_attestation_impl(NULL, reloaded), public)
  expect_named(public, c(
    "attestation_version", "alignment_attested", "alignment_protocol",
    "attestation_id", "contract_hash", "policy_id", "alignment_purpose",
    "dataset_id", "dataset_version", "id_column", "source_binding_id",
    "pinset_id",
    "capacity_bucket", "relay_frame_bytes", "inline_max_bytes",
    "peer_count", "reference_peer", "compute_peers"))
  expect_false(any(c("n", "hash", "token", "order_binding", "id_col") %in%
                   names(public)))
  transcript <- jsonlite::toJSON(public, auto_unbox = TRUE)
  expect_false(grepl("id-", transcript, fixed = TRUE))
  expect_false(grepl(token, transcript, fixed = TRUE))

  reordered <- D[6:1, , drop = FALSE]
  expect_error(psiPaddedAttestationDS("reordered"),
               "attestation unavailable")
  tampered <- D
  record <- attr(tampered, .PSI_PADDED_ATTESTATION_ATTRIBUTE, exact = TRUE)
  record$public$capacity_bucket <- 128L
  attr(tampered, .PSI_PADDED_ATTESTATION_ATTRIBUTE) <- record
  expect_error(psiPaddedAttestationDS("tampered"),
               "attestation unavailable")
})

test_that("legacy PSI and exact local correlation are absent remotely", {
  legacy <- c(
    "localCorDS", "psiInitDS", "psiStoreBlobDS",
    "psiStoreTransportKeysDS", "psiMaskIdsDS", "psiExportMaskedDS",
    "psiProcessTargetDS", "psiDoubleMaskDS", "psiExportMatchedIndicesDS",
    "psiComputeCommonIndicesDS", "psiExportCommonIndicesDS",
    "psiAlignmentManifestDS", "psiMatchAndAlignDS", "psiSelfAlignDS",
    "psiFilterCommonDS", "psiGetMatchedIndicesDS",
    "psiPaddedExactTransportDS")
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  registered <- c(
    trimws(strsplit(description[1L, "AggregateMethods"], ",",
                    fixed = TRUE)[[1L]]),
    trimws(strsplit(description[1L, "AssignMethods"], ",",
                    fixed = TRUE)[[1L]]))
  expect_false(any(legacy %in% registered))
  expect_false(any(legacy %in% getNamespaceExports("dsVert")))
  expect_false(any(vapply(
    legacy, exists, logical(1L), envir = asNamespace("dsVert"),
    inherits = FALSE)))
})
