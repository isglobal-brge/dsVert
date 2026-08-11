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

.psi_factor_registry_signature <- function(message, key) {
  .dsvert_relay_b64url_encode(digest::hmac(
    key = charToRaw(key), object = message, algo = "sha512",
    serialize = FALSE, raw = TRUE))
}

.psi_factor_registry_fixture <- function(token_byte = 0L) {
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(
    (seq_len(32L) - 1L + token_byte) %% 256L)))
  source <- .psi_padded_test_source_public("patient_id")
  contract <- c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = strrep("a", 64L),
    attestation_id = paste0("attest_", strrep("b", 64L)),
    policy_id = paste0("policy_", strrep("c", 64L))), source, list(
    pinset_id = paste0("pinset_", strrep("d", 64L)),
    capacity = 64L, relay_frame_bytes = 65536L,
    inline_max_bytes = 65536L,
    peer_names = c("site_a", "site_b"),
    reference_peer = "site_a", compute_peers = c("site_a", "site_b")))
  data <- data.frame(
    patient_id = factor(c("id-1", "id-2", "id-3")),
    category = factor(c("z", "a", NA_character_),
                      levels = c("z", "\u00e1", "a")),
    unrelated_factor = factor(
      rep(NA_character_, 3L), levels = character()),
    private_value = c("secret-1", "secret-2", "secret-3"),
    stringsAsFactors = FALSE, check.names = FALSE)
  data <- .psi_padded_attach_attestation(
    .psi_attach_alignment_manifest(data, "patient_id", token), contract)
  identity <- list(
    identity_pk = .dsvert_relay_b64url_encode(as.raw(rep(21L, 32L))),
    identity_sk = "factor-registry-test-key")
  signer <- function(message, identity_sk) {
    .psi_factor_registry_signature(message, identity_sk)
  }
  verifier <- function(message, identity_pk, signature) {
    identical(signature, .psi_factor_registry_signature(
      message, identity$identity_sk))
  }
  data <- .psi_padded_attach_factor_registry_v1(
    data, "site_a", identity, .signer = signer,
    .public_domains = list(category = c("z", "\u00e1", "a")))
  list(data = data, contract = contract, identity = identity,
       verifier = verifier)
}

.psi_factor_registry_validate <- function(
    data, fixture, metadata_only = FALSE) {
  .psi_padded_validate_factor_registry_v1(
    data,
    expected_peer_name = "site_a",
    expected_identity_pk = fixture$identity$identity_pk,
    .verifier = fixture$verifier,
    metadata_only = metadata_only)
}

test_that("padded PSI authenticates canonical factor metadata privately", {
  fixture <- .psi_factor_registry_fixture()
  data <- fixture$data
  public_before <- .psi_padded_validate_persistent_attestation(data)
  record <- .psi_factor_registry_validate(data, fixture)

  expect_identical(attr(
    data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE, exact = TRUE), record)
  expect_named(record, c(
    "version", "peer_name", "peer_identity_pk", "attestation_id",
    "contract_hash", "source_binding_id", "alignment_hash", "entries",
    "public_levels_policy", "registry_sha256", "signature"))
  expect_identical(
    record$public_levels_policy,
    "custodian_named_public_factor_domains_v1")
  expect_length(record$entries, 1L)
  entry <- record$entries[[1L]]
  expect_named(entry, c(
    "version", "variable_name", "variable_id", "levels", "dimension"))
  expect_identical(entry$variable_name, "category")
  expect_identical(entry$levels, as.list(sort(
    enc2utf8(c("z", "\u00e1", "a")), method = "radix")))
  expect_identical(entry$dimension, 3L)
  expect_match(entry$variable_id, "^var_[0-9a-f]{64}$")
  expect_match(.psi_padded_factor_entry_hash_v1(entry), "^[0-9a-f]{64}$")
  expect_match(record$registry_sha256, "^[0-9a-f]{64}$")
  expect_identical(
    .psi_padded_validate_persistent_attestation(data), public_before)

  wire <- .psi_padded_canonical_json(record)
  expect_false(grepl("id-1|secret-1", wire))
  expect_false(grepl("private_value", wire, fixed = TRUE))
  expect_false(grepl("unrelated_factor", wire, fixed = TRUE))
  expect_false("private_value" %in% vapply(
    record$entries, `[[`, character(1L), "variable_name"))
  expect_identical(
    .psi_factor_registry_validate(
      unserialize(serialize(data, NULL, version = 3L)), fixture),
    record)
})

test_that("factor registry is order-canonical and rejects schema mutation", {
  fixture <- .psi_factor_registry_fixture()
  data <- fixture$data
  verifier <- fixture$verifier

  reordered <- data
  reordered$category <- factor(
    as.character(reordered$category),
    levels = rev(levels(reordered$category)))
  attributes(reordered)[c(
    .PSI_ALIGNMENT_ATTRIBUTE, .PSI_PADDED_ATTESTATION_ATTRIBUTE,
    .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE)] <- attributes(data)[c(
      .PSI_ALIGNMENT_ATTRIBUTE, .PSI_PADDED_ATTESTATION_ATTRIBUTE,
      .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE)]
  expect_silent(.psi_factor_registry_validate(reordered, fixture))

  changed_value <- data
  changed_value$category[[1L]] <- "a"
  expect_silent(.psi_factor_registry_validate(changed_value, fixture))

  added_level <- data
  levels(added_level$category) <- c(levels(added_level$category), "dummy")
  expect_error(.psi_factor_registry_validate(added_level, fixture),
               "factor registry")

  character_column <- data
  character_column$category <- as.character(character_column$category)
  expect_error(.psi_factor_registry_validate(character_column, fixture),
               "factor registry")

  tampered <- data
  record <- attr(
    tampered, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE, exact = TRUE)
  record$signature <- .dsvert_relay_b64url_encode(as.raw(rep(0L, 64L)))
  attr(tampered, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- record
  expect_error(.psi_factor_registry_validate(tampered, fixture),
               "factor registry")

  other <- .psi_factor_registry_fixture(token_byte = 1L)$data
  attr(other, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- attr(
    data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE, exact = TRUE)
  expect_error(.psi_factor_registry_validate(other, fixture),
               "factor registry")
  expect_error(.psi_padded_validate_factor_registry_v1(
    data, .verifier = verifier), "factor registry")
  wrong_pk <- .dsvert_relay_b64url_encode(as.raw(rep(22L, 32L)))
  expect_error(.psi_padded_validate_factor_registry_v1(
    data, expected_peer_name = "site_a", expected_identity_pk = wrong_pk,
    .verifier = verifier), "factor registry")
})

test_that("factor metadata validation does not inspect aligned row values", {
  fixture <- .psi_factor_registry_fixture()
  changed_ids <- fixture$data
  changed_ids$patient_id <- as.character(changed_ids$patient_id)
  changed_ids$patient_id[[1L]] <- "different-id"

  expect_error(.psi_factor_registry_validate(changed_ids, fixture),
               "factor registry")
  expect_silent(.psi_factor_registry_validate(
    changed_ids, fixture, metadata_only = TRUE))

  changed_schema <- changed_ids
  levels(changed_schema$category) <- c(
    levels(changed_schema$category), "dummy")
  expect_error(.psi_factor_registry_validate(
    changed_schema, fixture, metadata_only = TRUE),
    "factor registry")
})

test_that("factor claims stay disabled without a custodian public-domain policy", {
  fixture <- .psi_factor_registry_fixture()
  data <- fixture$data
  identity <- fixture$identity
  signer <- function(message, identity_sk) {
    .psi_factor_registry_signature(message, identity_sk)
  }
  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL
  data <- .psi_padded_attach_factor_registry_v1(
    data, "site_a", identity, .signer = signer, .public_domains = list())
  record <- .psi_factor_registry_validate(data, fixture)
  expect_identical(record$entries, list())
  expect_identical(
    record$public_levels_policy, "no_public_factor_domains_v1")
})

test_that("only explicitly public factor domains enter the registry", {
  fixture <- .psi_factor_registry_fixture()
  data <- fixture$data
  identity <- fixture$identity
  signer <- function(message, identity_sk) {
    .psi_factor_registry_signature(message, identity_sk)
  }
  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL

  expect_error(.psi_padded_attach_factor_registry_v1(
    data, "site_a", identity, .signer = signer,
    .public_domains = list(category = c("a", "z"))),
    "factor")

  configured <- .psi_padded_attach_factor_registry_v1(
    data, "site_a", identity, .signer = signer,
    .public_domains = list(category = c("a", "z", "\u00e1"),
                           absent_elsewhere = c("x", "y")))
  record <- .psi_factor_registry_validate(configured, fixture)
  expect_length(record$entries, 1L)
  expect_identical(record$entries[[1L]]$variable_name, "category")

  old <- options(dsvert.dp.categorical_levels = list(
    category = c("a", "z", "\u00e1")))
  on.exit(options(old), add = TRUE)
  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL
  configured <- .psi_padded_attach_factor_registry_v1(
    data, "site_a", identity, .signer = signer)
  expect_length(
    .psi_factor_registry_validate(configured, fixture)$entries, 1L)

  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL
  configured <- .psi_padded_attach_factor_registry_v1(
    data, "site_a", identity, .signer = signer,
    .public_domains = list(category = factor(
      c("z", "\u00e1", "a"), levels = c("a", "z", "\u00e1"))))
  expect_length(
    .psi_factor_registry_validate(configured, fixture)$entries, 1L)
})

test_that("factor cardinality is rejected before scanning undeclared levels", {
  fixture <- .psi_factor_registry_fixture()
  data <- fixture$data
  levels(data$category) <- c(levels(data$category), "must-not-scan")
  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL
  original <- .psi_padded_factor_text_v1

  expect_error(testthat::with_mocked_bindings(
    .psi_padded_attach_factor_registry_v1(
      data, "site_a", fixture$identity,
      .signer = function(message, identity_sk) {
        .psi_factor_registry_signature(message, identity_sk)
      },
      .public_domains = list(category = c("a", "z", "\u00e1"))),
    .psi_padded_factor_text_v1 = function(value, what) {
      if (identical(value, "must-not-scan")) stop("late level scan")
      original(value, what)
    },
    .package = "dsVert"),
  "Invalid padded PSI factor levels")
})

test_that("untrusted factor entries are bounded before canonicalization", {
  fixture <- .psi_factor_registry_fixture()
  entry <- .psi_factor_registry_validate(
    fixture$data, fixture)$entries[[1L]]
  entry$levels <- list("a", "z")
  entry$dimension <- 2L
  other <- entry
  other$variable_name <- "other"
  other$variable_id <- paste0("var_", strrep("e", 64L))

  expect_error(testthat::with_mocked_bindings(
    .psi_padded_factor_domains_from_entries_v1(list(entry, other)),
    .DSVERT_PSI_PADDED_FACTOR_MAX_COLUMNS = 1L,
    .package = "dsVert"), "metadata limit")
  expect_error(testthat::with_mocked_bindings(
    .psi_padded_factor_domains_from_entries_v1(list(entry, other)),
    .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS = 3L,
    .package = "dsVert"), "metadata limit")
  expect_error(testthat::with_mocked_bindings(
    .psi_padded_factor_domains_from_entries_v1(list(entry)),
    .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES = 2L,
    .package = "dsVert"), "metadata limit")
  entry$levels <- list(paste(rep("x", 1025L), collapse = ""))
  entry$dimension <- 1L
  expect_error(.psi_padded_factor_domains_from_entries_v1(list(entry)),
               "factor level")
})

test_that("factor metadata reads raw attributes without S3 dispatch", {
  fixture <- .psi_factor_registry_fixture()
  data <- fixture$data
  class(data$category) <- c("audit_factor", "factor")
  method <- "levels.audit_factor"
  existed <- exists(method, envir = .GlobalEnv, inherits = FALSE)
  if (existed) previous <- get(method, envir = .GlobalEnv, inherits = FALSE)
  assign(method, function(object) stop("factor level dispatch"),
         envir = .GlobalEnv)
  on.exit(if (existed) {
    assign(method, previous, envir = .GlobalEnv)
  } else {
    rm(list = method, envir = .GlobalEnv)
  }, add = TRUE)
  expect_silent(.psi_padded_factor_entries_v1(
    data, public_domains = list(category = c("a", "z", "\u00e1"))))
})

test_that("metadata-only validation reads raw data-frame shape", {
  fixture <- .psi_factor_registry_fixture()
  data <- fixture$data
  class(data) <- c("audit_df", "data.frame")
  methods <- c("names.audit_df", "dim.audit_df")
  existed <- vapply(methods, exists, logical(1L), envir = .GlobalEnv,
                    inherits = FALSE)
  previous <- lapply(methods[existed], get, envir = .GlobalEnv,
                     inherits = FALSE)
  names(previous) <- methods[existed]
  for (method in methods) {
    assign(method, function(object) stop("data-frame shape dispatch"),
           envir = .GlobalEnv)
  }
  on.exit(for (method in methods) {
    if (isTRUE(existed[[method]])) {
      assign(method, previous[[method]], envir = .GlobalEnv)
    } else {
      rm(list = method, envir = .GlobalEnv)
    }
  }, add = TRUE)

  expect_silent(.psi_factor_registry_validate(
    data, fixture, metadata_only = TRUE))
  expect_silent(.psi_padded_factor_entries_v1(
    data, public_domains = list(category = c("a", "z", "\u00e1"))))
})

test_that("untrusted registry keys and signatures are length-gated", {
  fixture <- .psi_factor_registry_fixture()
  original <- .dsvert_relay_b64url_decode
  decode <- function(value, what) {
    if (is.character(value) && length(value) == 1L &&
        nchar(value, type = "bytes") > 100L) stop("late base64 decode")
    original(value, what)
  }
  mutate_record <- function(field) {
    data <- fixture$data
    record <- attr(
      data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE, exact = TRUE)
    record[[field]] <- paste(rep("A", 1000L), collapse = "")
    attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- record
    data
  }
  for (field in c("peer_identity_pk", "signature")) {
    expect_error(testthat::with_mocked_bindings(
      .psi_factor_registry_validate(mutate_record(field), fixture),
      .dsvert_relay_b64url_decode = decode,
      .package = "dsVert"),
    "factor registry", info = field)
  }
})

test_that("factor registry performs one alignment validation per operation", {
  fixture <- .psi_factor_registry_fixture()
  original <- .psi_validate_alignment_manifest
  calls <- 0L
  validate <- function(data) {
    calls <<- calls + 1L
    original(data)
  }

  expect_silent(testthat::with_mocked_bindings(
    .psi_factor_registry_validate(fixture$data, fixture),
    .psi_validate_alignment_manifest = validate,
    .package = "dsVert"))
  expect_identical(calls, 1L)

  data <- fixture$data
  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL
  calls <- 0L
  expect_silent(testthat::with_mocked_bindings(
    .psi_padded_attach_factor_registry_v1(
      data, "site_a", fixture$identity,
      .signer = function(message, identity_sk) {
        .psi_factor_registry_signature(message, identity_sk)
      },
      .public_domains = list(category = c("a", "z", "\u00e1"))),
    .psi_validate_alignment_manifest = validate,
    .package = "dsVert"))
  expect_identical(calls, 1L)
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
