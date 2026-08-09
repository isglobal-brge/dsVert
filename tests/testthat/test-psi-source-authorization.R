test_that("padded PSI source authorization is custodian-owned and snapshot-bound", {
  data <- data.frame(
    patient_id = c("p1", "p2"), alternate_id = c("a1", "a2"),
    value = 1:2, stringsAsFactors = FALSE)
  withr::local_options(.psi_padded_test_source_options(
    data, id_col = "patient_id", id = "cohort-main", version = "2026-08"))

  authorization <- .psi_padded_authorize_source(
    "D", "patient_id", data)
  expect_named(authorization, c("public", "snapshot_sha256"))
  expect_identical(
    authorization$public,
    .psi_padded_test_source_public(
      "patient_id", "cohort-main", "2026-08"))
  expect_false(authorization$snapshot_sha256 %in%
                 unlist(authorization$public, use.names = FALSE))

  expect_error(
    .psi_padded_authorize_source("D", "alternate_id", data),
    "not custodian-authorized")
  expect_error(
    .psi_padded_authorize_source("other", "patient_id", data),
    "not custodian-authorized")
  changed <- data
  changed$value[[1L]] <- 99L
  expect_error(
    .psi_padded_authorize_source("D", "patient_id", changed),
    "custodian-approved snapshot")
})

test_that("the local PSI descriptor helper is complete and never remote", {
  data <- data.frame(patient_id = c("p1", NA_character_, ""), value = 1:3)
  descriptor <- dsvertPSISourceDescriptor(
    data, "patient_id", "cohort-main", "2026-08")
  expect_named(descriptor, c(
    "id", "version", "id_col", "purpose", "snapshot_sha256"))
  expect_identical(descriptor$id_col, "patient_id")
  expect_match(descriptor$snapshot_sha256, "^[0-9a-f]{64}$")
  invalid <- data
  invalid$value <- c(1.5, 2, 3)
  expect_error(
    dsvertPSISourceDescriptor(
      invalid, "value", "cohort-main", "2026-08"),
    "exactly representable integers")
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  remote <- c(
    trimws(strsplit(description[1L, "AggregateMethods"], ",",
                    fixed = TRUE)[[1L]]),
    trimws(strsplit(description[1L, "AssignMethods"], ",",
                    fixed = TRUE)[[1L]]))
  expect_false("dsvertPSISourceDescriptor" %in% remote)
})

test_that("unauthorized padded PSI fails before allocating protocol state", {
  data <- data.frame(patient_id = "p1", value = 1L)
  withr::local_options(list(
    dsvert.psi.authorized_sources = NULL,
    default.dsvert.psi.authorized_sources = NULL,
    dsvert.dp.datasets = NULL,
    default.dsvert.dp.datasets = NULL,
    dsvert.dp.patient_column = NULL,
    default.dsvert.dp.patient_column = NULL))
  state <- new.env(parent = emptyenv())
  expect_error(
    .psi_padded_init_impl(
      state, data, "D", "patient_id",
      "52345678-1234-4234-9234-123456789abc",
      paste0("op_", strrep("5", 32L))),
    "source policy is unavailable")
  expect_false(exists(".psi_padded_state", envir = state, inherits = FALSE))
})

test_that("padded PSI reuses a matching custodian DP dataset binding", {
  data <- data.frame(patient_id = c("p1", "p2"), value = 1:2)
  withr::local_options(list(
    dsvert.psi.authorized_sources = NULL,
    default.dsvert.psi.authorized_sources = NULL,
    dsvert.dp.patient_column = "patient_id",
    dsvert.dp.datasets = list(D = list(
      id = "cohort-main", version = "v3",
      snapshot_sha256 = .dsvert_dp_snapshot_digest(data),
      alignment_manifest_hash = NULL,
      alignment_manifest_version = NULL))))

  authorization <- .psi_padded_authorize_source(
    "D", "patient_id", data)
  expect_identical(
    authorization$public,
    .psi_padded_test_source_public(
      "patient_id", "cohort-main", "v3"))
  expect_error(
    .psi_padded_authorize_source("D", "value", data),
    "not custodian-authorized")
})

test_that("padded PSI source binding rejects a validly signed purpose mismatch", {
  testthat::local_mocked_bindings(
    .sign_transport_pk = function(...) jsonlite::base64_enc(as.raw(0:63)),
    .verify_peer_identity = function(...) TRUE,
    .package = "dsVert")
  identities <- stats::setNames(lapply(1:2, function(index) list(
    identity_pk = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(40L * index, 32L)))),
    identity_sk = "test-only")), c("alpha", "beta"))
  transports <- lapply(1:2, function(index) list(
    public_key = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(40L * index + 1L, 32L))))))
  names(transports) <- names(identities)
  pinset <- lapply(identities, `[[`, "identity_pk")
  pinset_id <- .psi_padded_pinset_id(pinset)
  session_id <- "62345678-1234-4234-9234-123456789abc"
  operation_id <- paste0("op_", strrep("6", 32L))
  offers <- stats::setNames(lapply(names(identities), function(peer) {
    source <- .psi_padded_test_source_public(
      purpose = if (identical(peer, "alpha")) {
        "patient-record-alignment-v1"
      } else {
        "different-analysis-purpose-v1"
      })
    .psi_padded_sign_offer(
      peer, identities[[peer]], transports[[peer]]$public_key,
      capacity = 64L, session_id = session_id, operation_id = operation_id,
      policy_id = paste0("policy_", strrep("2", 64L)),
      source_authorization = source, pinset_id = pinset_id,
      snapshot_id = paste0("snap_", digest::digest(
        paste0("snapshot/", peer), algo = "sha256", serialize = FALSE)),
      attestation_nonce = base64_to_base64url(jsonlite::base64_enc(
        as.raw((seq_len(32L) + nchar(peer)) %% 256L))))
  }), names(identities))

  expect_error(
    .psi_padded_contract_from_offers(offers, pinset),
    "one authenticated contract")
})
