.frequency_analysis_pk <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.frequency_analysis_signature <- function(message, key) {
  .dsvert_relay_b64url_encode(digest::hmac(
    key = charToRaw(key), object = message, algo = "sha512",
    serialize = FALSE, raw = TRUE))
}

.frequency_analysis_signer <- function(message, identity_sk) {
  .frequency_analysis_signature(message, identity_sk)
}

.frequency_analysis_verifier <- function(
    message, identity_pk, signature, peer_name = NULL) {
  identical(signature, .frequency_analysis_signature(message, identity_pk))
}

.frequency_claim_fixture <- function(k = 3L, source_index = 2L) {
  peers <- paste0("site_", seq_len(k))
  pins <- stats::setNames(vapply(
    seq_len(k), .frequency_analysis_pk, character(1L)), peers)
  source_peer <- peers[[source_index]]
  source_identity <- list(
    identity_pk = unname(pins[[source_peer]]),
    identity_sk = unname(pins[[source_peer]]))
  source <- list(
    alignment_purpose = "patient-record-alignment-v1",
    dataset_id = "frequency-table",
    dataset_version = "v1",
    id_column = "patient_id")
  source$source_binding_id <- paste0("source_", digest::digest(
    .psi_padded_canonical_json(source), algo = "sha256", serialize = FALSE))
  token <- .dsvert_relay_b64url_encode(as.raw(0:31))
  contract <- c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = strrep("a", 64L),
    attestation_id = paste0("attest_", strrep("b", 64L)),
    policy_id = paste0("policy_", strrep("c", 64L))), source, list(
    pinset_id = .psi_padded_pinset_id(as.list(pins)),
    capacity = 64L,
    relay_frame_bytes = 65536L,
    inline_max_bytes = 65536L,
    peer_names = peers,
    reference_peer = peers[[1L]],
    compute_peers = peers[1:2]))
  data <- data.frame(
    patient_id = c("p-1", "p-2", "p-3"),
    category = factor(
      c("z", "a", NA_character_), levels = c("z", "\u00e1", "a")),
    unrelated = factor(c("private-a", "private-b", "private-c")),
    private_value = c("secret-1", "secret-2", "secret-3"),
    stringsAsFactors = FALSE, check.names = FALSE)
  data <- .psi_padded_attach_attestation(
    .psi_attach_alignment_manifest(data, "patient_id", token), contract)
  data <- .psi_padded_attach_factor_registry_v1(
    data, source_peer, source_identity,
    .signer = .frequency_analysis_signer,
    .public_domains = list(category = c("z", "\u00e1", "a")))
  list(
    data = data, pins = pins, source_peer = source_peer,
    source_identity = source_identity, contract = contract)
}

.frequency_claim <- function(fixture, data = fixture$data,
                             variable_name = "category") {
  .dsvert_dp_frequency_claim_v1(
    data = data,
    variable_name = variable_name,
    peer_name = fixture$source_peer,
    identity = fixture$source_identity,
    peer_pins = fixture$pins,
    .registry_verifier = .frequency_analysis_verifier,
    .signer = .frequency_analysis_signer)
}

test_that("Frequency Claim exposes one pinned public factor entry only", {
  fixture <- .frequency_claim_fixture()
  claim <- .frequency_claim(fixture)
  validated <- .dsvert_dp_frequency_claim_validate_v1(
    claim, fixture$pins, .verifier = .frequency_analysis_verifier)

  expect_identical(validated, claim)
  expect_setequal(names(claim), c(
    "version", "source_peer_name", "source_identity_pk", "psi_run_sha256",
    "attestation_id", "contract_hash", "source_binding_id", "alignment_hash",
    "alignment_purpose", "dataset_id", "dataset_version",
    "privacy_unit_column", "pinset_id", "capacity_bucket", "factor_entry",
    "factor_entry_sha256", "signature"))
  expect_identical(claim$source_peer_name, fixture$source_peer)
  expect_identical(
    claim$source_identity_pk,
    unname(fixture$pins[[fixture$source_peer]]))
  expect_identical(claim$factor_entry$variable_name, "category")
  expect_identical(
    claim$factor_entry$levels,
    as.list(sort(enc2utf8(c("z", "\u00e1", "a")), method = "radix")))
  expect_identical(claim$factor_entry$dimension, 3L)
  expect_identical(
    claim$factor_entry_sha256,
    .psi_padded_factor_entry_hash_v1(claim$factor_entry))
  expect_match(claim$psi_run_sha256, "^[0-9a-f]{64}$")

  wire <- .dsvert_dp_canonical_json(claim)
  expect_false(grepl("p-1|secret-1|private-a", wire))
  expect_false(grepl("private_value|unrelated", wire))
  expect_false(any(c("registry_sha256", "entries") %in% names(claim)))
})

test_that("Frequency Claim is metadata-only, canonical and fail-closed", {
  fixture <- .frequency_claim_fixture()
  original <- .frequency_claim(fixture)

  changed_rows <- fixture$data
  changed_rows$patient_id[[1L]] <- "different-private-id"
  changed_rows$category[[1L]] <- "a"
  expect_identical(.frequency_claim(fixture, changed_rows), original)

  permuted <- fixture$data
  permuted$category <- factor(
    as.character(permuted$category), levels = rev(levels(permuted$category)))
  attributes(permuted)[c(
    .PSI_ALIGNMENT_ATTRIBUTE, .PSI_PADDED_ATTESTATION_ATTRIBUTE,
    .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE)] <- attributes(fixture$data)[c(
      .PSI_ALIGNMENT_ATTRIBUTE, .PSI_PADDED_ATTESTATION_ATTRIBUTE,
      .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE)]
  expect_identical(.frequency_claim(fixture, permuted), original)

  dummy <- fixture$data
  levels(dummy$category) <- c(levels(dummy$category), "dummy")
  expect_error(.frequency_claim(fixture, dummy), "factor registry")

  character_column <- fixture$data
  character_column$category <- as.character(character_column$category)
  expect_error(.frequency_claim(fixture, character_column), "factor registry")
  expect_error(.frequency_claim(fixture, variable_name = "unrelated"),
               "public factor")

  wrong_identity <- fixture
  wrong_identity$source_identity <- list(
    identity_pk = .frequency_analysis_pk(99L),
    identity_sk = .frequency_analysis_pk(99L))
  expect_error(.frequency_claim(wrong_identity), "pinned")

  tampered <- original
  tampered$psi_run_sha256 <- strrep("f", 64L)
  expect_error(.dsvert_dp_frequency_claim_validate_v1(
    tampered, fixture$pins, .verifier = .frequency_analysis_verifier),
    "signature")
})

test_that("Frequency Claim does not expose a public or registered route", {
  expect_identical(names(formals(.dsvert_dp_frequency_claim_v1)), c(
    "data", "variable_name", "peer_name", "identity", "peer_pins",
    ".registry_verifier", ".signer"))
  expect_false(exists(
    "dsvertDPFrequencyClaimDS", envir = asNamespace("dsVert"),
    inherits = FALSE))
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  registered <- trimws(strsplit(
    description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  expect_false("dsvertDPFrequencyClaimDS" %in% registered)
})

test_that("Frequency Claim rejects oversized crypto fields before decoding", {
  fixture <- .frequency_claim_fixture()
  claim <- .frequency_claim(fixture)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_frequency_signature_v1(strrep("A", 100000L)),
    .dsvert_relay_b64url_decode = function(...) stop("decoder reached"),
    .package = "dsVert"), "signature")

  normalizer <- .dsvert_relay_normalize_identity_pk
  oversized <- claim
  oversized$source_identity_pk <- strrep("A", 100000L)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_frequency_claim_validate_v1(
      oversized, fixture$pins, .verifier = .frequency_analysis_verifier),
    .dsvert_relay_normalize_identity_pk = function(value) {
      if (nchar(value, type = "bytes") > 43L) stop("normalizer reached")
      normalizer(value)
    },
    .package = "dsVert"), "signed Frequency Claim")

  oversized_pins <- fixture$pins
  oversized_pins[[1L]] <- strrep("A", 100000L)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_frequency_peer_pins_v1(oversized_pins),
    .dsvert_relay_normalize_identity_pk = function(value) {
      if (nchar(value, type = "bytes") > 43L) stop("normalizer reached")
      normalizer(value)
    },
    .package = "dsVert"), "peer pins")

  expect_pre_cap <- function(max_levels, max_bytes) {
    converted <- FALSE
    expect_error(testthat::with_mocked_bindings(
      .dsvert_dp_frequency_factor_entry_validate_v1(claim$factor_entry),
      .psi_padded_factor_text_v1 = function(...) {
        converted <<- TRUE
        stop("converter reached")
      },
      .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS = max_levels,
      .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES = max_bytes,
      .package = "dsVert"), "public factor entry")
    expect_false(converted)
  }
  expect_pre_cap(2L, 16L * 1024L * 1024L)
  expect_pre_cap(3L, 2L)
})

.frequency_runtime_manifest <- function() list(
  schema_version = "dsvert-mpc-runtime-capabilities-v1",
  protocol_version = "test-protocol-v1",
  runtime_version = "test-runtime-v1",
  api_version = "test-api-v1",
  capabilities = list(joint_dp_frequency_backend_selection = list(
    available = TRUE,
    capability_id = "joint_dp_frequency_backend_selection_v1",
    protocol_version = "dsvert-joint-dp-frequency-backend-selection-v1",
    commands = "joint-dp-frequency-backend-select-v1",
    operations =
      "public-data-free-certified-frequency-backend-selection-v1")))

.frequency_compile_fixture <- function(k = 3L) {
  fixture <- .frequency_claim_fixture(k = k, source_index = 2L)
  peers <- names(fixture$pins)
  token <- attr(
    fixture$data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)$token
  source_ids <- fixture$data$patient_id
  data <- stats::setNames(lapply(peers, function(peer) {
    if (identical(peer, fixture$source_peer)) return(fixture$data)
    witness <- data.frame(
      patient_id = source_ids,
      witness_private = paste0("private-", peer, "-", seq_along(source_ids)),
      stringsAsFactors = FALSE, check.names = FALSE)
    .psi_padded_attach_attestation(
      .psi_attach_alignment_manifest(witness, "patient_id", token),
      fixture$contract)
  }), peers)
  fixture$data_by_peer <- data
  fixture$claim <- .frequency_claim(fixture)
  fixture$settings <- list(
    domain = "clinical-frequency",
    cohort_id = "eligible-cohort-v1",
    source_owner = list(
      peer_name = fixture$source_peer,
      identity_pk = unname(fixture$pins[[fixture$source_peer]])),
    coordinate_upper_bound = 64L,
    privacy = list(
      adjacency = "add_remove_patient", epsilon = 1, delta = 0.01),
    calibration = list(implementation_delta = 0.001))
  fixture
}

.frequency_alternate_claim <- function(fixture, peer_name) {
  data <- fixture$data_by_peer[[fixture$source_peer]]
  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL
  identity <- list(
    identity_pk = unname(fixture$pins[[peer_name]]),
    identity_sk = unname(fixture$pins[[peer_name]]))
  data <- .psi_padded_attach_factor_registry_v1(
    data, peer_name, identity, .signer = .frequency_analysis_signer,
    .public_domains = list(category = c("z", "\u00e1", "a")))
  .dsvert_dp_frequency_claim_v1(
    data, "category", peer_name, identity, fixture$pins,
    .registry_verifier = .frequency_analysis_verifier,
    .signer = .frequency_analysis_signer)
}

.frequency_psi_rerun <- function(fixture) {
  contract <- fixture$contract
  contract$contract_hash <- strrep("d", 64L)
  contract$attestation_id <- paste0("attest_", strrep("e", 64L))
  token <- .dsvert_relay_b64url_encode(as.raw(31:0))
  data <- stats::setNames(lapply(names(fixture$pins), function(peer) {
    value <- .psi_attach_alignment_manifest(
      fixture$data_by_peer[[peer]], "patient_id", token)
    value <- .psi_padded_attach_attestation(value, contract)
    attr(value, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- NULL
    if (!identical(peer, fixture$source_peer)) return(value)
    .psi_padded_attach_factor_registry_v1(
      value, peer, fixture$source_identity,
      .signer = .frequency_analysis_signer,
      .public_domains = list(category = c("z", "\u00e1", "a")))
  }), names(fixture$pins))
  fixture$contract <- contract
  fixture$data_by_peer <- data
  fixture$data <- data[[fixture$source_peer]]
  fixture$claim <- .frequency_claim(fixture)
  fixture
}

.frequency_local_compile <- function(
    fixture, peer_name, data = fixture$data_by_peer[[peer_name]],
    events = NULL, selector = NULL) {
  if (is.null(selector)) selector <- function(request) {
    if (!is.null(events)) events$value <- c(events$value, "selector")
    .analysis_frequency_oracle_fixture(request)
  }
  index <- match(peer_name, names(fixture$pins))
  identity <- list(
    identity_pk = unname(fixture$pins[[peer_name]]),
    identity_sk = unname(fixture$pins[[peer_name]]))
  testthat::with_mocked_bindings(
    .dsvert_dp_frequency_local_compile_v1(
      source_claim = fixture$claim,
      peer_name = peer_name,
      peer_pins = fixture$pins,
      settings = fixture$settings,
      .source_resolver = function() {
        if (!is.null(events)) events$value <- c(events$value, "source")
        data
      },
      .capability = function(capability) {
        if (!is.null(events)) events$value <- c(events$value, "capability")
        expect_identical(
          capability, "joint_dp_frequency_backend_selection")
        .frequency_runtime_manifest()
      },
      .selector = selector,
      .registry_verifier = .frequency_analysis_verifier,
      .signer = .frequency_analysis_signer),
    .get_identity_keypair = function() identity,
    .get_identity_seed = function() jsonlite::base64_enc(
      as.raw(rep(index + 70L, 32L))),
    .package = "dsVert")
}

.frequency_compiled <- function(fixture) {
  local <- lapply(
    names(fixture$pins), .frequency_local_compile, fixture = fixture)
  config <- local[[1L]]$config
  receipts <- lapply(local, `[[`, "receipt")
  contract <- .dsvert_dp_frequency_compile_v1(
    receipts, config, fixture$claim,
    .verifier = .frequency_analysis_verifier)
  list(local = local, config = config, receipts = receipts,
       contract = contract)
}

.frequency_resign_receipt <- function(receipt) {
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  c(unsigned, list(signature = .frequency_analysis_signer(
    .dsvert_dp_frequency_receipt_message_v1(unsigned),
    receipt$peer_identity_pk)))
}

test_that("Frequency local compiler gates and selects before source access", {
  fixture <- .frequency_compile_fixture()
  events <- new.env(parent = emptyenv())
  events$value <- character()
  local <- .frequency_local_compile(
    fixture, fixture$source_peer, events = events)

  expect_identical(events$value, c("capability", "selector", "source"))
  expect_setequal(names(local), c("config", "receipt"))
  expect_identical(local$config$source_owner, list(
    peer_name = fixture$source_peer,
    identity_pk = unname(fixture$pins[[fixture$source_peer]])))
  expect_identical(local$config$factor_domain, fixture$claim$factor_entry)
  expect_identical(local$config$coordinate_upper_bound, 64)
  expect_identical(local$config$max_records_per_unit, 1)
  expect_identical(
    local$config$repeated_record_policy,
    "psi_v4_first_eligible_source_record_per_privacy_unit_v1")
  expect_identical(
    local$config$overflow_policy,
    "clip_to_psi_v4_first_eligible_source_record_v1")
  expect_identical(
    local$config$missingness_policy,
    "missing_or_out_of_domain_rows_are_ignored")
  expect_identical(
    local$config$backend_selection$summary$selected_primitive,
    "independent_full_global_draw_convolution_ring128_v3")

  source_called <- FALSE
  expect_error(.dsvert_dp_frequency_local_compile_v1(
    source_claim = fixture$claim,
    peer_name = fixture$source_peer,
    peer_pins = fixture$pins,
    settings = fixture$settings,
    .source_resolver = function() {
      source_called <<- TRUE
      stop("source must not be resolved")
    },
    .capability = function(...) list(capabilities = list()),
    .registry_verifier = .frequency_analysis_verifier,
    .signer = .frequency_analysis_signer), "capability")
  expect_false(source_called)

  old_manifest_called <- FALSE
  expect_error(.dsvert_dp_frequency_local_compile_v1(
    source_claim = fixture$claim,
    peer_name = fixture$source_peer,
    peer_pins = fixture$pins,
    settings = fixture$settings,
    .source_resolver = function() {
      old_manifest_called <<- TRUE
      fixture$data_by_peer[[fixture$source_peer]]
    },
    .capability = function(...) list(capabilities = list(
      joint_dp_frequency_backend_selection = list(
        available = TRUE, version = "v1"))),
    .selector = function(request) .analysis_frequency_oracle_fixture(request),
    .registry_verifier = .frequency_analysis_verifier,
    .signer = .frequency_analysis_signer), "capability")
  expect_false(old_manifest_called)
})

test_that("Frequency server-held source owner rejects a valid alternate Claim", {
  fixture <- .frequency_compile_fixture()
  alternate_peer <- setdiff(names(fixture$pins), fixture$source_peer)[[1L]]
  alternate <- .frequency_alternate_claim(fixture, alternate_peer)
  expect_identical(alternate$factor_entry, fixture$claim$factor_entry)
  expect_false(identical(
    alternate$source_identity_pk, fixture$claim$source_identity_pk))
  expect_silent(.dsvert_dp_frequency_claim_validate_v1(
    alternate, fixture$pins, .verifier = .frequency_analysis_verifier))

  rerolled <- fixture
  rerolled$claim <- alternate
  events <- new.env(parent = emptyenv())
  events$value <- character()
  expect_error(.frequency_local_compile(
    rerolled, fixture$source_peer, events = events),
    "configured source owner")
  expect_identical(events$value, character())
})

test_that("Frequency config and receipt bound untrusted crypto and names", {
  fixture <- .frequency_compile_fixture()
  local <- .frequency_local_compile(fixture, fixture$source_peer)
  normalizer <- .dsvert_relay_normalize_identity_pk
  bounded_normalizer <- function(value) {
    if (nchar(value, type = "bytes") > 43L) stop("normalizer reached")
    normalizer(value)
  }

  oversized_config <- local$config
  oversized_config$source_owner$identity_pk <- strrep("A", 100000L)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_frequency_config_validate_v1(oversized_config),
    .dsvert_relay_normalize_identity_pk = bounded_normalizer,
    .package = "dsVert"), "source owner")

  duplicate_privacy <- local$config
  names(duplicate_privacy$privacy) <- c("adjacency", "epsilon", "epsilon")
  expect_error(.dsvert_dp_frequency_config_validate_v1(duplicate_privacy),
               "privacy parameters")

  oversized_receipt <- local$receipt[setdiff(
    names(local$receipt), "signature")]
  oversized_receipt$peer_identity_pk <- strrep("A", 100000L)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_frequency_unsigned_receipt_validate_v1(oversized_receipt),
    .dsvert_relay_normalize_identity_pk = bounded_normalizer,
    .package = "dsVert"), "receipt identity")
})

test_that("Frequency compiles identical K-wide consensus for K=2,3,5", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .frequency_compile_fixture(k)
    events <- stats::setNames(lapply(seq_len(k), function(index) {
      state <- new.env(parent = emptyenv())
      state$value <- character()
      state
    }), names(fixture$pins))
    local <- lapply(names(fixture$pins), function(peer) {
      .frequency_local_compile(fixture, peer, events = events[[peer]])
    })
    configs <- lapply(local, `[[`, "config")
    expect_true(all(vapply(configs, identical, logical(1L), configs[[1L]])))
    expect_true(all(vapply(configs, function(config) {
      identical(config$source_owner, fixture$settings$source_owner)
    }, logical(1L))))
    expect_true(all(vapply(events, function(state) {
      identical(state$value, c("capability", "selector", "source"))
    }, logical(1L))))
    receipts <- lapply(local, `[[`, "receipt")
    contract <- .dsvert_dp_frequency_compile_v1(
      rev(receipts), configs[[1L]], fixture$claim,
      .verifier = .frequency_analysis_verifier)
    arguments <- contract$semantic$analysis$effective_arguments
    expected_secondary <- sort(
      unname(fixture$pins[names(fixture$pins) != fixture$source_peer]),
      method = "radix")[[1L]]
    expect_identical(length(receipts), k)
    expect_identical(arguments$source_owner,
      unname(fixture$pins[[fixture$source_peer]]))
    expect_identical(arguments$levels, fixture$claim$factor_entry$levels)
    expect_identical(arguments$coordinate_bounds,
                     list(lower = 0, upper = 64))
    expect_identical(
      contract$semantic$noise_authority_roles$authority_ids,
      list(unname(fixture$pins[[fixture$source_peer]]), expected_secondary))
    expect_identical(contract$execution$backend$ring, "ring128")
  }
})

test_that("Frequency derives sensitivity from both approved adjacencies", {
  fixture <- .frequency_compile_fixture()
  fixture$settings$privacy$adjacency <- "replace_one_fixed_cohort"
  compile_profile <- function(outcome) {
    local <- lapply(names(fixture$pins), function(peer) {
      .frequency_local_compile(fixture, peer, selector = function(request) {
        .analysis_frequency_oracle_fixture(request, outcome)
      })
    })
    .dsvert_dp_frequency_compile_v1(
      lapply(local, `[[`, "receipt"), local[[1L]]$config, fixture$claim,
      .verifier = .frequency_analysis_verifier)
  }
  convolution <- compile_profile("convolution")
  gaussian <- compile_profile("gaussian")
  expect_identical(
    convolution$semantic$privacy$mechanism$sensitivity$value, 2)
  expect_identical(
    gaussian$semantic$privacy$mechanism$sensitivity$value, sqrt(2))
})

test_that("Frequency source snapshot binds labels by canonical level", {
  fixture <- .frequency_compile_fixture()
  source <- fixture$source_peer
  original <- .frequency_local_compile(fixture, source)

  changed <- fixture$data_by_peer[[source]]
  changed$category[[1L]] <- "a"
  changed_receipt <- .frequency_local_compile(fixture, source, changed)$receipt
  expect_false(identical(
    changed_receipt$snapshot_commitment,
    original$receipt$snapshot_commitment))

  missing <- fixture$data_by_peer[[source]]
  missing$category[[1L]] <- NA_character_
  missing_receipt <- .frequency_local_compile(fixture, source, missing)$receipt
  expect_false(identical(
    missing_receipt$snapshot_commitment,
    original$receipt$snapshot_commitment))

  permuted <- fixture$data_by_peer[[source]]
  permuted$category <- factor(
    as.character(permuted$category), levels = rev(levels(permuted$category)))
  attributes(permuted)[c(
    .PSI_ALIGNMENT_ATTRIBUTE, .PSI_PADDED_ATTESTATION_ATTRIBUTE,
    .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE)] <- attributes(
      fixture$data_by_peer[[source]])[c(
        .PSI_ALIGNMENT_ATTRIBUTE, .PSI_PADDED_ATTESTATION_ATTRIBUTE,
        .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE)]
  permuted_receipt <- .frequency_local_compile(
    fixture, source, permuted)$receipt
  expect_identical(
    permuted_receipt$snapshot_commitment,
    original$receipt$snapshot_commitment)

  dummy <- fixture$data_by_peer[[source]]
  levels(dummy$category) <- c(levels(dummy$category), "dummy")
  expect_error(.frequency_local_compile(fixture, source, dummy),
               "factor registry")
  character_column <- fixture$data_by_peer[[source]]
  character_column$category <- as.character(character_column$category)
  expect_error(.frequency_local_compile(fixture, source, character_column),
               "factor registry")
})

test_that("Frequency receipt consensus rejects partial and mixed evidence", {
  fixture <- .frequency_compile_fixture()
  compiled <- .frequency_compiled(fixture)
  compile <- function(receipts = compiled$receipts,
                      config = compiled$config,
                      claim = fixture$claim) {
    .dsvert_dp_frequency_compile_v1(
      receipts, config, claim,
      .verifier = .frequency_analysis_verifier)
  }
  expect_error(compile(compiled$receipts[-1L]), "one signed receipt")
  expect_error(compile(c(compiled$receipts[-1L],
                         compiled$receipts[2L])), "coverage")

  mixed_claim <- compiled$receipts
  mixed_claim[[1L]]$source_claim_sha256 <- strrep("f", 64L)
  mixed_claim[[1L]] <- .frequency_resign_receipt(mixed_claim[[1L]])
  expect_error(compile(mixed_claim), "Claim")

  mixed_run <- compiled$receipts
  mixed_run[[1L]]$psi_run_sha256 <- strrep("e", 64L)
  mixed_run[[1L]] <- .frequency_resign_receipt(mixed_run[[1L]])
  expect_error(compile(mixed_run), "PSI run")

  common_wrong_run <- lapply(compiled$receipts, function(receipt) {
    receipt$psi_run_sha256 <- strrep("e", 64L)
    .frequency_resign_receipt(receipt)
  })
  expect_error(compile(common_wrong_run), "PSI run")

  tampered_config <- compiled$config
  tampered_config$coordinate_upper_bound <- 63
  expect_error(compile(config = tampered_config), "configuration|receipt")

  wrong_pin <- compiled$receipts
  wrong_pin[[1L]]$peer_identity_pk <- .frequency_analysis_pk(99L)
  wrong_pin[[1L]] <- .frequency_resign_receipt(wrong_pin[[1L]])
  expect_error(compile(wrong_pin), "pinned")
})

.frequency_authorize <- function(
    fixture, compiled, peer_name,
    session_id = "00000000-0000-4000-8000-000000000001",
    ss = new.env(parent = emptyenv()), receipts = compiled$receipts) {
  index <- match(peer_name, names(fixture$pins))
  identity <- list(identity_pk = unname(fixture$pins[[peer_name]]))
  result <- testthat::with_mocked_bindings({
    value <- .dsvert_dp_frequency_authorize_session_v1(
      ss, session_id, compiled$config, receipts, fixture$claim,
      .verifier = .frequency_analysis_verifier)
    list(value = value,
         seed_commitment = .dsvert_dp_frequency_seed_material_v1(value))
  },
    .get_identity_keypair = function() identity,
    .get_identity_seed = function() jsonlite::base64_enc(
      as.raw(rep(index + 70L, 32L))),
    .package = "dsVert")
  list(value = result$value, seed_commitment = result$seed_commitment,
       state = ss)
}

test_that("Frequency PSI reruns do not reroll the sticky artifact", {
  original_fixture <- .frequency_compile_fixture()
  rerun_fixture <- .frequency_psi_rerun(original_fixture)
  original <- .frequency_compiled(original_fixture)
  rerun <- .frequency_compiled(rerun_fixture)
  columns <- function(data) lapply(seq_along(data), function(index) {
    data[[index]]
  })

  expect_identical(
    lapply(original_fixture$data_by_peer, columns),
    lapply(rerun_fixture$data_by_peer, columns))
  expect_false(identical(
    original_fixture$claim$attestation_id,
    rerun_fixture$claim$attestation_id))
  expect_false(identical(
    original_fixture$claim$contract_hash,
    rerun_fixture$claim$contract_hash))
  expect_false(identical(
    original_fixture$claim$psi_run_sha256,
    rerun_fixture$claim$psi_run_sha256))
  expect_false(identical(
    original_fixture$claim$signature, rerun_fixture$claim$signature))
  expect_identical(original$config, rerun$config)
  expect_identical(
    lapply(original$receipts, `[[`, "snapshot_commitment"),
    lapply(rerun$receipts, `[[`, "snapshot_commitment"))
  expect_true(all(vapply(seq_along(original$receipts), function(index) {
    !identical(original$receipts[[index]]$psi_run_sha256,
               rerun$receipts[[index]]$psi_run_sha256) &&
      !identical(original$receipts[[index]]$signature,
                 rerun$receipts[[index]]$signature)
  }, logical(1L))))
  expect_identical(original$contract$artifact_key,
                   rerun$contract$artifact_key)

  original_auth <- .frequency_authorize(
    original_fixture, original, original_fixture$source_peer)
  rerun_auth <- .frequency_authorize(
    rerun_fixture, rerun, rerun_fixture$source_peer)
  expect_identical(original_auth$value$worker_static,
                   rerun_auth$value$worker_static)
  expect_identical(original_auth$seed_commitment,
                   rerun_auth$seed_commitment)
})

test_that("Frequency authorization is two-role, sticky and atomic", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .frequency_compile_fixture(k)
    compiled <- .frequency_compiled(fixture)
    authorities <- compiled$contract$semantic$
      noise_authority_roles$authority_ids
    authority_peers <- vapply(authorities, function(identity_pk) {
      names(fixture$pins)[match(identity_pk, unname(fixture$pins))]
    }, character(1L))
    authority_values <- list()
    for (peer in authority_peers) {
      authorized <- .frequency_authorize(fixture, compiled, peer)
      value <- authorized$value
      authority_values[[peer]] <- value
      expect_identical(value$artifact_key, compiled$contract$artifact_key)
      expect_identical(value$analysis_binding$authority_roles,
                       stats::setNames(as.list(authorities), c(
                         "source_owner", "secondary_noise_authority")))
      expect_identical(value$worker_static$ring_bits, 128L)
      expect_identical(value$worker_static$frac_bits, 0L)
      expect_identical(value$worker_static$output_lattice_bits, 1L)
      expect_identical(value$worker_static$d,
                       fixture$claim$factor_entry$dimension)
      expect_identical(value$worker_static$raw_bound,
                       list(lower = "0", upper = "64", scale = 0L))
      expect_match(authorized$seed_commitment$sha256, "^[0-9a-f]{64}$")
      expect_identical(authorized$seed_commitment$role,
                       value$local_authority$role)
      wire <- .dsvert_dp_canonical_json(value$worker_static)
      expect_false(grepl("frequency-session|psi_run|signature|seed", wire))
      expect_identical(.frequency_authorize(
        fixture, compiled, peer, ss = authorized$state,
        receipts = rev(compiled$receipts))$value, value)
    }
    expect_identical(
      authority_values[[1L]]$worker_static,
      authority_values[[2L]]$worker_static)
    expect_false(identical(
      .frequency_authorize(
        fixture, compiled, authority_peers[[1L]])$seed_commitment$sha256,
      .frequency_authorize(
        fixture, compiled, authority_peers[[2L]])$seed_commitment$sha256))
    non_authorities <- setdiff(names(fixture$pins), authority_peers)
    if (length(non_authorities)) {
      rejected <- new.env(parent = emptyenv())
      expect_error(.frequency_authorize(
        fixture, compiled, non_authorities[[1L]], ss = rejected),
        "noise authority")
      expect_null(rejected$.dp_frequency_authorization)
    }
  }
})

test_that("Frequency authorization never partially overwrites state", {
  fixture <- .frequency_compile_fixture()
  compiled <- .frequency_compiled(fixture)
  peer <- fixture$source_peer
  empty <- new.env(parent = emptyenv())
  expect_error(.frequency_authorize(
    fixture, compiled, peer, ss = empty,
    receipts = compiled$receipts[-1L]), "one signed receipt")
  expect_null(empty$.dp_frequency_authorization)

  first <- .frequency_authorize(fixture, compiled, peer)
  before <- first$value
  conflicting <- compiled$receipts
  conflicting[[1L]]$psi_run_sha256 <- strrep("d", 64L)
  conflicting[[1L]] <- .frequency_resign_receipt(conflicting[[1L]])
  expect_error(.frequency_authorize(
    fixture, compiled, peer, ss = first$state,
    receipts = conflicting), "PSI run")
  expect_identical(first$state$.dp_frequency_authorization, before)

  alternate_fixture <- fixture
  alternate_fixture$settings$privacy$epsilon <- 0.5
  alternate <- .frequency_compiled(alternate_fixture)
  expect_error(.frequency_authorize(
    alternate_fixture, alternate, peer, ss = first$state), "Conflicting")
  expect_identical(first$state$.dp_frequency_authorization, before)
})

test_that("Frequency sticky authorization is invariant across sessions", {
  fixture <- .frequency_compile_fixture()
  compiled <- .frequency_compiled(fixture)
  first <- .frequency_authorize(fixture, compiled, fixture$source_peer)
  second <- .frequency_authorize(
    fixture, compiled, fixture$source_peer,
    session_id = "00000000-0000-4000-8000-000000000002")
  expect_identical(first$value$artifact_key, second$value$artifact_key)
  expect_identical(first$value$worker_static, second$value$worker_static)
  expect_identical(first$seed_commitment, second$seed_commitment)
  expect_false(identical(first$value$authorization_sha256,
                         second$value$authorization_sha256))
})

test_that("Frequency authorization preserves incompatible session state", {
  fixture <- .frequency_compile_fixture()
  compiled <- .frequency_compiled(fixture)
  foreign <- new.env(parent = emptyenv())
  foreign$.dp_count_authorization <- list(version = "foreign-count")
  before <- foreign$.dp_count_authorization
  expect_error(.frequency_authorize(
    fixture, compiled, fixture$source_peer, ss = foreign),
    "existing session state")
  expect_identical(foreign$.dp_count_authorization, before)
  expect_null(foreign$.dp_frequency_authorization)

  for (field in c(
      ".dp_count_authorization", ".exact_gc_peer_binding_digest",
      ".exact_gc_analysis_binding", ".typed_blob_peer_binding_digest")) {
    installed <- .frequency_authorize(
      fixture, compiled, fixture$source_peer)
    frequency_before <- installed$value
    marker <- list(version = paste0("foreign-", field))
    installed$state[[field]] <- marker
    expect_error(.frequency_authorize(
      fixture, compiled, fixture$source_peer, ss = installed$state),
      "existing session state")
    expect_identical(
      installed$state$.dp_frequency_authorization, frequency_before)
    expect_identical(installed$state[[field]], marker)
  }
})
