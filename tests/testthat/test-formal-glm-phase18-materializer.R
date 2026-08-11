.phase18_b64url <- function(value) {
  sub("=+$", "", chartr(
    "+/", "-_", gsub("[\r\n]", "", jsonlite::base64_enc(value))),
    perl = TRUE)
}

.phase18_signature <- function(message, pin) {
  .phase18_b64url(openssl::sha512(c(
    message, .dsvert_relay_b64url_decode(pin, "test pin"))))
}

.phase18_signer <- function(message, peer_name, pin) {
  .phase18_signature(message, pin)
}

.phase18_verifier <- function(message, pin, signature) {
  identical(signature, .phase18_signature(message, pin))
}

.phase18_hash <- function(label) {
  digest::digest(label, algo = "sha256", serialize = FALSE)
}

.phase18_rat <- function(numerator, denominator = "1") {
  list(numerator = as.character(numerator), denominator = denominator)
}

.phase18_fixture <- function(k = 2L, family = "binomial",
                             categorical = FALSE,
                             adjacency = "add_remove") {
  peers <- paste0("peer_", letters[seq_len(k)])
  pins <- vapply(seq_along(peers), function(index) {
    .phase18_b64url(as.raw((seq_len(32L) + index * 37L) %% 256L))
  }, character(1L))
  names(pins) <- peers
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)),
    algo = "sha256", serialize = FALSE)
  designated <- peers[1:2]
  roles <- .dsvert_formal_glm_phase18_roles(
    list(peer_pinset = pins, peer_pinset_sha256 = pin_hash),
    peers, designated)
  capacity <- 4L
  scale <- "256"
  columns <- list(
    y = if (family == "binomial") {
      list(kind = "binary", owner = peers[[1L]], domain = list(0, 1))
    } else {
      list(kind = "count", owner = peers[[1L]], upper = .phase18_rat("8"))
    },
    x = list(kind = "numeric", owner = peers[[2L]],
             lower = .phase18_rat("-1"), upper = .phase18_rat("1")))
  coefficients <- list(
    list(index = 1, name = "(Intercept)", term = list(
      coefficient = "(Intercept)", source_column = NULL,
      source_level = NULL, kind = "intercept", owner = NULL,
      lower = .phase18_rat("1"), upper = .phase18_rat("1"),
      abs_bound = .phase18_rat("1"))))
  predictors <- list("x")
  if (categorical) {
    columns$group <- list(
      kind = "categorical", owner = peers[[2L]],
      levels = list("control", "treated"), reference = "control",
      contrast = "treatment")
    predictors <- list("group", "x")
    coefficients[[2L]] <- list(index = 2, name = "group[treated]", term = list(
      coefficient = "group[treated]", source_column = "group",
      source_level = "treated", kind = "categorical_indicator",
      owner = peers[[2L]], lower = .phase18_rat("0"),
      upper = .phase18_rat("1"), abs_bound = .phase18_rat("1")))
  }
  coefficients[[length(coefficients) + 1L]] <- list(
    index = length(coefficients) + 1, name = "x", term = list(
      coefficient = "x", source_column = "x", source_level = NULL,
      kind = "numeric", owner = peers[[2L]],
      clipping_lower = .phase18_rat("-1"),
      clipping_upper = .phase18_rat("1"),
      quantized_lower = .phase18_rat("-1"),
      quantized_upper = .phase18_rat("1"),
      abs_bound = .phase18_rat("1")))
  p <- length(coefficients)
  owners <- c(peers[[1L]], peers[[1L]],
              rep(peers[[2L]], p - 1L), peers[[1L]], peers[[1L]])
  estimand <- list(
    family = family, response = "y", predictors = predictors,
    coefficients = coefficients, column_registry = columns,
    weights = list(
      mode = "unit", column = NULL,
      source_maximum_patient_weight = .phase18_rat("1"),
      maximum_patient_weight = .phase18_rat("1")),
    offset = list(
      mode = "none", column = NULL, source_lower = .phase18_rat("0"),
      source_upper = .phase18_rat("0"), lower = .phase18_rat("0"),
      upper = .phase18_rat("0")),
    patient_collapse = list(
      unit = "aligned_patient", repeated_records = "reject_duplicates",
      row_order_invariant = TRUE, max_records_per_unit = 1,
      conflict_policy = "zero_weight"))
  artifact <- list(
    estimand = estimand, coefficients = coefficients, common_bits = 8L,
    x_bits = 8L, offset_bits = 8L, reference_bits = 64L)
  x_lower <- c(scale, rep(c(if (categorical) "0" else NULL, "-256"), 1L))
  x_upper <- c(scale, if (categorical) "256", "256")
  kernel <- list(
    family = family, x_lower = as.list(x_lower), x_upper = as.list(x_upper),
    weight_upper = scale,
    outcome_upper = if (family == "binomial") scale else "2048",
    offset_lower = "0", offset_upper = "0")
  plan <- list(kernel = kernel)
  pre <- .dsvert_dp_canonical_query_value(c(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_PRE_VERSION,
    phase = "pre_execution_materialization_authorized",
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = .phase18_hash("capsule"),
    manifest_sha256 = .phase18_hash("manifest"),
    schema_manifest_sha256 = .phase18_hash("schema"),
    workload_sha256 = .phase18_hash("workload"),
    source_context_sha256 = .phase18_hash("source"),
    snapshot_sha256 = .phase18_hash("snapshot"),
    artifact_sha256 = .phase18_hash("artifact"),
    plan_sha256 = .phase18_hash("plan"),
    kernel_spec_sha256 = .phase18_hash("kernel"),
    run_id = paste0("run-phase18-", family, "-", k),
    pinset_sha256 = pin_hash,
    custodian_peers = as.list(peers), custodian_count = k,
    designated_compute_peers = as.list(designated)), roles, list(
    total_capacity = capacity, block_capacity = capacity, total_blocks = 1L,
    coordinate_count = length(owners), coordinate_owners = as.list(owners),
    family = family, adjacency = adjacency,
    capacity_semantics = .DSVERT_FORMAL_GLM_PHASE18_CAPACITY_SEMANTICS,
    adjacency_semantics = .DSVERT_FORMAL_GLM_PHASE18_ADJACENCY_SEMANTICS,
    patient_contribution = .DSVERT_FORMAL_GLM_PHASE18_PATIENT_CONTRIBUTION,
    missingness = "complete_tuple_zero_weight",
    patient_collapse = "one_aligned_record_duplicates_zero_weight_v1",
    frac_bits = 8L, ring_bits = 128L, container_bits = 128L,
    record_bytes = 16L, input_layout = "weight_x_outcome_offset_v1",
    input_sharing = "additive_mod_2k_by_coordinate_owner_v1",
    validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
    alignment_sharing = .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING,
    release_token = "none_pre_execution", worker_token = "none_pre_execution",
    openings_performed = 0L, production_ready = FALSE)))
  pre_hash <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase18/pre-execution/v1|", pre)
  policies <- stats::setNames(lapply(peers, function(peer) {
    data_name <- paste0("data_", peer)
    numeric <- if (peer == peers[[1L]]) {
      list(y = if (family == "binomial") c(0, 1) else c(0, 8))
    } else if (peer == peers[[2L]]) list(x = c(-1, 1)) else {
      stats::setNames(list(c(0, 1)), paste0("dummy_", peer))
    }
    categories <- if (categorical && peer == peers[[2L]]) {
      list(group = c("control", "treated"))
    } else list()
    mapping_columns <- c(names(numeric), names(categories))
    list(
      peer_name = peer, peer_pinset = pins,
      peer_pinset_sha256 = pin_hash, designated_noise_peers = designated,
      unit_capacity = capacity, max_records_per_unit = 2L,
      patient_column = "patient_id", numeric_bounds = numeric,
      categorical_levels = categories,
      capsule_dataset_mapping = stats::setNames(
        list(mapping_columns), data_name),
      datasets = stats::setNames(list(list(
        id = paste0("cohort-", peer), version = "v1",
        snapshot_sha256 = NULL, alignment_manifest_hash = NULL)), data_name))
  }), peers)
  authorizations <- stats::setNames(lapply(peers, function(peer) {
    structure(list(
      pre = c(pre, list(pre_execution_sha256 = pre_hash)),
      pre_execution_sha256 = pre_hash, policy = policies[[peer]],
      alignment_secret = as.raw(rep(match(peer, peers) + 90L, 32L)),
      manifest = list(), artifact = artifact, plan = plan,
      coordinate_owners = owners, peers = peers, designated = designated),
      class = "dsvert_formal_glm_phase18_pre_authorization")
  }), peers)
  list(peers = peers, pins = pins, designated = designated,
       authorizations = authorizations, family = family,
       categorical = categorical)
}

.phase18_snapshot <- function(fixture, peer, token = "phase18-psi-token",
                              duplicate = FALSE, missing = FALSE,
                              out_of_domain = FALSE) {
  data <- data.frame(patient_id = c("p2", "p1", "p3"),
                     stringsAsFactors = FALSE)
  if (peer == fixture$peers[[1L]]) {
    data$y <- if (fixture$family == "binomial") c(1, 0, 1) else c(2, 1.5, 99)
  } else if (peer == fixture$peers[[2L]]) {
    data$x <- c(0.5, if (missing) NA_real_ else -0.5, 2)
    if (fixture$categorical) {
      data$group <- c("treated", "control",
                      if (out_of_domain) "unknown" else "treated")
    }
  } else {
    data[[paste0("dummy_", peer)]] <- c(0, 0, 0)
  }
  if (duplicate) data <- rbind(data, data[data$patient_id == "p2", ])
  if (!is.null(token)) {
    attr(data, .PSI_ALIGNMENT_ATTRIBUTE) <- list(token = token)
  }
  data_name <- paste0("data_", peer)
  descriptor <- fixture$authorizations[[peer]]$policy$datasets[[data_name]]
  stats::setNames(list(list(
    data = data,
    dataset = list(
      public = list(data_name = data_name, id = descriptor$id,
                    version = descriptor$version),
      fingerprint = .phase18_hash(paste0("fingerprint-", peer))))), data_name)
}

.phase18_ticket <- function(authorization, recipient, byte) {
  transport_pk <- .phase18_b64url(as.raw(rep(byte, 32L)))
  unsigned <- .dsvert_formal_glm_phase18_ticket_unsigned(
    authorization, recipient, transport_pk)
  policy <- authorization$policy
  policy$peer_name <- recipient
  signed <- .dsvert_formal_glm_phase18_sign(
    unsigned, policy, .DSVERT_FORMAL_GLM_PHASE18_TICKET_DOMAIN,
    .phase18_signer)
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(signed))
}

.phase18_encryptor <- function(plaintext, recipient_pk) {
  gsub("[\r\n]", "", jsonlite::base64_enc(c(raw(60L), plaintext)))
}

.phase18_random <- function(length) {
  as.raw(rep(seq.int(0L, 255L), length.out = length))
}

.phase18_private_headers <- function(bundle, authorization) {
  value <- if (is.character(bundle)) {
    jsonlite::fromJSON(bundle, simplifyVector = FALSE)
  } else bundle
  share_bytes <- authorization$pre$block_capacity *
    authorization$pre$coordinate_count * authorization$pre$record_bytes +
    authorization$pre$block_capacity
  result <- lapply(value$envelopes, function(envelope) {
    sealed <- .dsvert_relay_b64url_decode(
      envelope$ciphertext, "test formal-GLM ciphertext")
    plaintext <- sealed[-seq_len(60L)]
    .dsvert_dp_capsule_source_unpack(plaintext, share_bytes)$header
  })
  names(result) <- vapply(value$envelopes, `[[`, character(1L),
                          "recipient_name")
  result
}

.phase18_signatures <- function(message, fixture) {
  lapply(fixture$peers, function(peer) list(
    signer = peer,
    signature = .phase18_signature(message, fixture$pins[[peer]])))
}

.phase18_signed_object <- function(value, domain, fixture) {
  signatures <- .phase18_signatures(
    .dsvert_formal_glm_phase18_domain_message(
      domain, .dsvert_formal_glm_phase18_json(value)), fixture)
  list(value = value, signatures = signatures)
}

test_that("Phase-1.8 exact rows enforce missing, domains, caps and padding", {
  fixture <- .phase18_fixture(3L, categorical = TRUE)
  a <- .dsvert_formal_glm_phase18_materialize_block_values(
    fixture$authorizations[[fixture$peers[[1L]]]],
    .phase18_snapshot(fixture, fixture$peers[[1L]]), 0L)
  b <- .dsvert_formal_glm_phase18_materialize_block_values(
    fixture$authorizations[[fixture$peers[[2L]]]],
    .phase18_snapshot(fixture, fixture$peers[[2L]], missing = TRUE), 0L)
  expect_identical(a$validity, c(TRUE, TRUE, TRUE, FALSE))
  expect_identical(b$validity, c(FALSE, TRUE, TRUE, FALSE))
  expect_identical(a$values, c(
    "256", "256", "0", "0", "0", "0",
    "256", "256", "0", "0", "256", "0",
    "256", "256", "0", "0", "256", "0",
    rep("0", 6L)))
  expect_identical(b$values, c(
    rep("0", 6L), "0", "0", "256", "128", "0", "0",
    "0", "0", "256", "256", "0", "0", rep("0", 6L)))

  duplicate <- .dsvert_formal_glm_phase18_materialize_block_values(
    fixture$authorizations[[fixture$peers[[2L]]]],
    .phase18_snapshot(fixture, fixture$peers[[2L]], duplicate = TRUE), 0L)
  expect_false(duplicate$validity[[2L]])
  categorical <- .dsvert_formal_glm_phase18_materialize_block_values(
    fixture$authorizations[[fixture$peers[[2L]]]],
    .phase18_snapshot(fixture, fixture$peers[[2L]], out_of_domain = TRUE), 0L)
  expect_false(categorical$validity[[3L]])

  poisson <- .phase18_fixture(2L, family = "poisson")
  count <- .dsvert_formal_glm_phase18_materialize_block_values(
    poisson$authorizations[[poisson$peers[[1L]]]],
    .phase18_snapshot(poisson, poisson$peers[[1L]]), 0L)
  expect_identical(count$validity, c(FALSE, TRUE, TRUE, FALSE))
  expect_identical(count$values[[4L]], "0")
  expect_identical(count$values[[14L]], "2048")
})

test_that("Phase-1.8 v2 keeps alignment and consensus XOR-shared by role", {
  fixture <- .phase18_fixture(2L)
  peer <- fixture$peers[[1L]]
  authorization <- fixture$authorizations[[peer]]
  tickets <- lapply(seq_along(fixture$designated), function(index) {
    .phase18_ticket(authorization, fixture$designated[[index]], 90L + index)
  })
  make <- function(token) .dsvert_formal_glm_phase18_materialize_block(
    authorization, 0L, tickets[[1L]], tickets[[2L]],
    .resolved_snapshots = .phase18_snapshot(fixture, peer, token = token),
    .random_bytes = .phase18_random, .encryptor = .phase18_encryptor,
    .signer = .phase18_signer, .verifier = .phase18_verifier)
  accepted <- make("shared-token")
  accepted_retry <- make("shared-token")
  rejected <- make(NULL)
  accepted_value <- jsonlite::fromJSON(accepted, simplifyVector = FALSE)
  rejected_value <- jsonlite::fromJSON(rejected, simplifyVector = FALSE)
  accepted_headers <- .phase18_private_headers(accepted_value, authorization)
  retry_headers <- .phase18_private_headers(accepted_retry, authorization)
  rejected_headers <- .phase18_private_headers(rejected_value, authorization)
  expect_equal(nchar(accepted, type = "bytes"), nchar(rejected, type = "bytes"))
  expect_identical(
    vapply(accepted_value$envelopes, `[[`, numeric(1L), "ciphertext_bytes"),
    vapply(rejected_value$envelopes, `[[`, numeric(1L), "ciphertext_bytes"))
  expect_identical(accepted, accepted_retry)
  expect_false("alignment_consensus_seal" %in% names(accepted_value))
  expect_identical(accepted_value$alignment_sharing,
                   .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING)
  expect_false(grepl(
    paste(c(.DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_ACCEPTED,
            .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_REJECTED), collapse = "|"),
    accepted, fixed = FALSE))
  expect_false(grepl(
    paste(c(.DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_ACCEPTED,
            .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_REJECTED), collapse = "|"),
    rejected, fixed = FALSE))
  expect_false(any(vapply(c(accepted_value$envelopes,
                            rejected_value$envelopes), function(envelope) {
    any(grepl("accepted|rejected", names(envelope), fixed = FALSE)) ||
      any(grepl("accepted|rejected", unlist(envelope), fixed = FALSE))
  }, logical(1L))))
  expected_fields <- c(
    "private_alignment_gate_share", "private_alignment_consensus_share")
  expect_true(all(vapply(accepted_headers, function(header) {
    identical(header$version,
              .DSVERT_FORMAL_GLM_PHASE18_PRIVATE_BLOCK_VERSION) &&
      all(expected_fields %in% names(header)) &&
      !any(c("private_alignment_consensus_status",
             "private_alignment_consensus_sha256") %in% names(header))
  }, logical(1L))))
  expect_identical(accepted_headers, retry_headers)
  role_header <- function(headers, role) {
    headers[[which(vapply(headers, function(header) {
      identical(header$recipient_role, role)
    }, logical(1L)))]]
  }
  gate_xor <- function(headers) bitwXor(
    as.integer(role_header(headers, "garbler")$private_alignment_gate_share),
    as.integer(role_header(headers, "evaluator")$private_alignment_gate_share))
  consensus_xor <- function(headers) as.raw(bitwXor(
    as.integer(.dsvert_relay_b64url_decode(
      role_header(headers, "garbler")$private_alignment_consensus_share,
      "garbler consensus share")),
    as.integer(.dsvert_relay_b64url_decode(
      role_header(headers, "evaluator")$private_alignment_consensus_share,
      "evaluator consensus share"))))
  expect_identical(gate_xor(accepted_headers), 1L)
  expect_identical(gate_xor(rejected_headers), 0L)
  materialized <- .dsvert_formal_glm_phase18_materialize_block_values(
    authorization, .phase18_snapshot(fixture, peer, token = "shared-token"),
    0L)
  expected_consensus <- .dsvert_formal_glm_phase18_hex_raw(
    materialized$private_alignment_consensus_sha256, "test consensus")
  expect_identical(consensus_xor(accepted_headers), expected_consensus)
  expect_false(any(vapply(accepted_headers, function(header) {
    identical(.dsvert_relay_b64url_decode(
      header$private_alignment_consensus_share, "consensus share"),
      expected_consensus)
  }, logical(1L))))
  receipt <- .dsvert_formal_glm_phase18_finalize_local(
    authorization, list(accepted), .phase18_signer, .phase18_verifier)
  expect_type(receipt, "character")
  expect_type(.dsvert_formal_glm_phase18_finalize_local(
    authorization, list(rejected), .phase18_signer, .phase18_verifier),
    "character")
  expect_error(.dsvert_formal_glm_phase18_finalize_local(
    authorization, list(accepted, accepted),
    .phase18_signer, .phase18_verifier),
    class = "dsvert_formal_glm_phase18_error")

  forged <- accepted_value
  forged$pair_commitment_sha256 <- .phase18_hash("forged-pair")
  forged <- .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(forged))
  expect_error(.dsvert_formal_glm_phase18_block_bundle_validate(
    forged, authorization, .phase18_verifier),
    class = "dsvert_formal_glm_phase18_error")
  swapped <- accepted_value
  names_by_envelope <- vapply(swapped$envelopes, `[[`, character(1L),
                              "recipient_name")
  swapped$envelopes[[1L]]$recipient_name <- names_by_envelope[[2L]]
  swapped$envelopes[[2L]]$recipient_name <- names_by_envelope[[1L]]
  swapped <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(swapped))
  expect_error(.dsvert_formal_glm_phase18_block_bundle_validate(
    swapped, authorization, .phase18_verifier),
    class = "dsvert_formal_glm_phase18_error")

  legacy <- accepted_value
  legacy$version <- "dsvert-formal-glm-phase18-encrypted-block-bundle-v1"
  legacy <- .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(legacy))
  expect_error(.dsvert_formal_glm_phase18_block_bundle_validate(
    legacy, authorization, .phase18_verifier),
    class = "dsvert_formal_glm_phase18_error")

  tampered <- accepted_value
  tampered$run_id <- "replayed-other-run"
  tampered <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(tampered))
  expect_error(.dsvert_formal_glm_phase18_block_bundle_validate(
    tampered, authorization, .phase18_verifier),
    class = "dsvert_formal_glm_phase18_error")
  expect_false(any(grepl("patient|value|share", names(accepted_value),
                         ignore.case = TRUE)))
})

test_that("Phase-1.8 post evidence is all-K, typed, sealed and never opens", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .phase18_fixture(k)
    reference <- fixture$authorizations[[1L]]
    receipts <- lapply(fixture$peers, function(peer) {
      authorization <- fixture$authorizations[[peer]]
      unsigned <- .dsvert_dp_canonical_query_value(list(
        version = .DSVERT_FORMAL_GLM_PHASE18_LOCAL_RECEIPT_VERSION,
        phase = "local_pre_execution_materialization_committed",
        purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
        capsule_id = authorization$pre$capsule_id,
        plan_sha256 = authorization$pre$plan_sha256,
        pre_execution_sha256 = authorization$pre_execution_sha256,
        run_id = authorization$pre$run_id, source_name = peer,
        source_identity_pk = fixture$pins[[peer]],
        pinset_sha256 = authorization$pre$pinset_sha256,
        total_capacity = authorization$pre$total_capacity,
        block_capacity = authorization$pre$block_capacity,
        total_blocks = authorization$pre$total_blocks,
        coordinate_count = authorization$pre$coordinate_count,
        ring_bits = authorization$pre$ring_bits,
        validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
        alignment_consensus_gate = "private_xor_gate_deferred_to_phase19_v2",
        local_materialization_root_sha256 = .phase18_hash(paste0("root-", peer)),
        release_token = "none_pre_execution",
        phase19_all_k_validity_and_required = TRUE,
        protected_data_e2e_verified = FALSE, openings_performed = 0L,
        production_ready = FALSE))
      policy <- authorization$policy
      policy$peer_name <- peer
      signed <- .dsvert_formal_glm_phase18_sign(
        unsigned, policy, .DSVERT_FORMAL_GLM_PHASE18_RECEIPT_DOMAIN,
        .phase18_signer)
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(signed))
    })
    source_contract <- .dsvert_dp_canonical_query_value(list(
      version = "dsvert-formal-glm-phase17-source-contribution-v1",
      plan_sha256 = reference$pre$plan_sha256,
      kernel_spec_sha256 = reference$pre$kernel_spec_sha256,
      manifest_sha256 = reference$pre$manifest_sha256,
      workload_sha256 = reference$pre$workload_sha256,
      source_context_sha256 = reference$pre$source_context_sha256,
      snapshot_sha256 = reference$pre$snapshot_sha256,
      source_fan_in_transcript_sha256 = .phase18_hash("fanin"),
      pinset_sha256 = reference$pre$pinset_sha256,
      custodian_peers = reference$pre$custodian_peers,
      custodian_count = reference$pre$custodian_count,
      total_capacity = reference$pre$total_capacity,
      capacity_semantics = .DSVERT_FORMAL_GLM_PHASE18_CAPACITY_SEMANTICS,
      adjacency = reference$pre$adjacency,
      adjacency_semantics = .DSVERT_FORMAL_GLM_PHASE18_ADJACENCY_SEMANTICS,
      maximum_active_rows_per_patient = 1L,
      patient_contribution = .DSVERT_FORMAL_GLM_PHASE18_PATIENT_CONTRIBUTION,
      missingness = reference$pre$missingness,
      patient_collapse = reference$pre$patient_collapse,
      materializer_verification =
        "custodian_signed_claim_protected_data_materializer_e2e_pending_v1",
      protected_data_e2e_verified = FALSE, production_ready = FALSE))
    source_signed <- .phase18_signed_object(
      source_contract, .DSVERT_FORMAL_GLM_PHASE18_SOURCE_DOMAIN, fixture)
    source_attestation <- list(
      contract = source_signed$value, signatures = source_signed$signatures)
    source_json <- .dsvert_formal_glm_phase18_json(source_attestation)
    source_checked <- .dsvert_formal_glm_phase18_source_attestation(
      source_json, reference, .phase18_verifier)
    hashes <- stats::setNames(lapply(1:11, function(index) {
      .phase18_hash(paste0("admission-", index))
    }), c("bounds_sha256", "quantization_sha256", "phase15_bridge_sha256",
          "final_receipt_pair_sha256", "sensitivity_certificate_sha256",
          "final_checkpoint_transcript_sha256", "coordinate_order_sha256",
          "phase16_release_binding_sha256", "worker_contract_sha256",
          "release_contract_sha256", "worker_transcript_sha256"))
    hashes$worker_transcript_sha256 <- hashes$release_contract_sha256
    preimage <- .dsvert_dp_canonical_query_value(c(list(
      version = "dsvert-formal-glm-phase17-authenticated-admission-v1",
      capsule_id = reference$pre$capsule_id,
      manifest_sha256 = reference$pre$manifest_sha256,
      schema_manifest_sha256 = reference$pre$schema_manifest_sha256,
      workload_sha256 = reference$pre$workload_sha256,
      source_context_sha256 = reference$pre$source_context_sha256,
      source_contract_sha256 = source_checked$contract_sha256,
      source_contribution_attestation_sha256 = source_checked$attestation_sha256,
      snapshot_sha256 = reference$pre$snapshot_sha256,
      phase15_plan_sha256 = reference$pre$plan_sha256,
      kernel_spec_sha256 = reference$pre$kernel_spec_sha256), hashes, list(
      source_fan_in_transcript_sha256 =
        source_contract$source_fan_in_transcript_sha256,
      release_instance_id = paste0("release-", k),
      pinset_sha256 = reference$pre$pinset_sha256,
      custodian_peers = reference$pre$custodian_peers,
      custodian_count = reference$pre$custodian_count,
      garbler_peer_name = reference$pre$garbler_peer_name,
      garbler_peer_id = reference$pre$garbler_peer_id,
      evaluator_peer_name = reference$pre$evaluator_peer_name,
      evaluator_peer_id = reference$pre$evaluator_peer_id,
      role_selection = reference$pre$role_selection,
      total_capacity = reference$pre$total_capacity,
      capacity_semantics = .DSVERT_FORMAL_GLM_PHASE18_CAPACITY_SEMANTICS,
      adjacency = reference$pre$adjacency,
      adjacency_semantics = .DSVERT_FORMAL_GLM_PHASE18_ADJACENCY_SEMANTICS,
      maximum_active_rows_per_patient = 1L,
      patient_contribution = .DSVERT_FORMAL_GLM_PHASE18_PATIENT_CONTRIBUTION,
      missingness = reference$pre$missingness,
      patient_collapse = reference$pre$patient_collapse,
      mechanism = "joint_discrete_gaussian_one_global_draw",
      allocation = "one_stacked_capsule_vector", epsilon = "1",
      allocated_delta = "1/1000000", authenticated_opening_count = 0L,
      protected_data_e2e_verified = FALSE, production_ready = FALSE)))
    admission_signed <- .phase18_signed_object(
      preimage, .DSVERT_FORMAL_GLM_PHASE18_ADMISSION_DOMAIN, fixture)
    admission_json <- .dsvert_formal_glm_phase18_json(list(
      preimage = admission_signed$value,
      signatures = admission_signed$signatures))
    candidate <- .dsvert_formal_glm_phase18_post_prepare(
      reference, receipts, source_json, admission_json,
      .phase18_verifier)
    message <- .dsvert_formal_glm_phase18_domain_message(
      .DSVERT_FORMAL_GLM_PHASE18_POST_DOMAIN,
      .dsvert_dp_canonical_json(candidate$post))
    token <- .dsvert_formal_glm_phase18_post_seal(
      candidate, .phase18_signatures(message, fixture), .phase18_verifier)
    expect_s3_class(token, "dsvert_formal_glm_phase18_sealed_token")
    expect_null(token$candidate$authorization$alignment_secret)
    expect_false(token$token$opening_authorized)
    expect_false(token$token$protected_data_e2e_verified)
    release_error <- tryCatch(
      .dsvert_formal_glm_phase18_open(token), error = identity)
    expect_s3_class(
      release_error, "dsvert_formal_glm_phase18_release_blocker")
    expect_identical(
      release_error$code,
      "formal_glm_phase19_private_output_not_wired_to_durable_joint_dp_release")
    expect_true(
      "phase19_private_output_to_durable_joint_dp_release" %in%
        release_error$missing)
    expect_false(
      "runtime_consumer_for_authenticated_recipient_inbox_frame" %in%
        release_error$missing)
    expect_error(.dsvert_formal_glm_phase18_post_validate(reference),
                 class = "dsvert_formal_glm_phase18_error")
    expect_error(.dsvert_formal_glm_phase18_post_prepare(
      reference, receipts[-1L], source_json, admission_json,
      .phase18_verifier), class = "dsvert_formal_glm_phase18_error")
  }
})

test_that("Phase-1.8 remains package-internal and cannot wrap silently", {
  split <- .dsvert_formal_glm_phase18_split(
    c("-1", "0", "1"), c(TRUE, FALSE, TRUE), 128L, 16L,
    random_bytes = function(length) raw(length))
  expect_identical(split$coordinate_left, raw(48L))
  expect_identical(as.integer(split$validity_right), c(1L, 0L, 1L))
  expect_identical(as.integer(split$coordinate_right[1:16]),
                   rep(255L, 16L))
  expect_identical(as.integer(split$coordinate_right[17:32]),
                   rep(0L, 16L))
  expect_identical(as.integer(split$coordinate_right[33:48]),
                   c(1L, rep(0L, 15L)))
  expect_error(.dsvert_formal_glm_phase18_residue(
    paste0("1", strrep("0", 100L)), 128L),
    class = "dsvert_formal_glm_phase18_error")
  expect_length(.dsvert_formal_glm_phase18_plan_approval_message(
    strrep("a", 64L)), 8L + nchar(.DSVERT_FORMAL_GLM_PHASE18_PLAN_APPROVAL_DOMAIN,
                                  type = "bytes") + 32L)
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  aggregate <- trimws(strsplit(
    description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  exports <- sub("^export\\((.*)\\)$", "\\1", grep(
    "^export\\(", readLines(.dsvert_test_package_file("NAMESPACE")),
    value = TRUE))
  expect_false(any(grepl("formalGLMPhase18", c(aggregate, exports),
                         fixed = TRUE)))
})

.phase18_raw_contains <- function(value, text) {
  stopifnot(is.raw(value), is.character(text), length(text) == 1L)
  needle <- as.integer(charToRaw(text))
  haystack <- as.integer(value)
  if (!length(needle) || length(needle) > length(haystack)) return(FALSE)
  any(vapply(seq_len(length(haystack) - length(needle) + 1L), function(index) {
    identical(
      haystack[index:(index + length(needle) - 1L)], needle)
  }, logical(1L)))
}

test_that("Phase-1.8 durable outbox replays the first encrypted bundle exactly", {
  fixture <- .phase18_fixture(2L)
  peer <- fixture$peers[[1L]]
  authorization <- fixture$authorizations[[peer]]
  tickets <- lapply(seq_along(fixture$designated), function(index) {
    .phase18_ticket(authorization, fixture$designated[[index]], 90L + index)
  })
  state <- new.env(parent = emptyenv())
  state$random_calls <- 0L
  state$encrypt_calls <- 0L
  state$sign_calls <- 0L
  random_bytes <- function(n) {
    state$random_calls <- state$random_calls + 1L
    as.raw(rep((seq_len(n) + state$random_calls * 31L) %% 256L,
               length.out = n))
  }
  encryptor <- function(plaintext, recipient_pk) {
    state$encrypt_calls <- state$encrypt_calls + 1L
    .phase18_b64url(c(
      as.raw(rep(state$encrypt_calls %% 256L, 60L)), plaintext))
  }
  signer <- function(message, peer_name, pin) {
    state$sign_calls <- state$sign_calls + 1L
    .phase18_signer(message, peer_name, pin)
  }
  root <- file.path(tempdir(), paste0(
    "phase18-durable-outbox-", Sys.getpid(), "-",
    sample.int(.Machine$integer.max, 1L)))
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  key <- as.raw(seq_len(32L))
  materialize <- function() {
    .dsvert_formal_glm_phase18_materialize_block_durable(
      authorization, 0L, tickets[[1L]], tickets[[2L]],
      .resolved_snapshots = .phase18_snapshot(fixture, peer),
      .random_bytes = random_bytes, .encryptor = encryptor,
      .signer = signer, .verifier = .phase18_verifier,
      .root = root, .key = key)
  }
  first <- materialize()
  calls_after_first <- c(
    state$random_calls, state$encrypt_calls, state$sign_calls)
  expect_gt(calls_after_first[[1L]], 0L)
  expect_identical(calls_after_first[[2L]], 2L)
  expect_identical(calls_after_first[[3L]], 2L)
  second <- materialize()
  expect_identical(second, first)
  expect_identical(c(
    state$random_calls, state$encrypt_calls, state$sign_calls),
                   calls_after_first)

  replay_without_data <- .dsvert_formal_glm_phase18_materialize_block_durable(
    authorization, 0L, tickets[[1L]], tickets[[2L]],
    .resolved_snapshots = NULL,
    .random_bytes = function(n) stop("must not rematerialize"),
    .encryptor = function(...) stop("must not re-encrypt"),
    .signer = function(...) stop("must not re-sign"),
    .verifier = .phase18_verifier,
    .root = root, .key = key)
  expect_identical(replay_without_data, first)

  key_id <- .dsvert_formal_glm_phase18_key_id(key)
  records <- list.files(
    file.path(root, "source-outbox-v2", key_id),
    pattern = "^slot-.*\\.bin$", recursive = TRUE, full.names = TRUE)
  expect_length(records, 1L)
  expect_identical(as.numeric(file.info(records)$mode),
                   as.numeric(strtoi("600", base = 8L)))
  persisted <- readBin(records, "raw", n = file.info(records)$size)
  expect_false(any(vapply(c(
    "accepted_phase19_consensus_v1", "rejected_phase19_consensus_v1",
    "private_alignment_consensus_sha256"), function(value) {
      .phase18_raw_contains(persisted, value)
  }, logical(1L))))
})

test_that("Phase-1.8 recipient inbox authenticates and queues ciphertext only", {
  fixture <- .phase18_fixture(3L)
  source <- fixture$peers[[3L]]
  recipient <- fixture$designated[[1L]]
  source_authorization <- fixture$authorizations[[source]]
  recipient_authorization <- fixture$authorizations[[recipient]]
  tickets <- lapply(seq_along(fixture$designated), function(index) {
    .phase18_ticket(
      source_authorization, fixture$designated[[index]], 100L + index)
  })
  opaque_encryptor <- function(plaintext, recipient_pk) {
    transformed <- as.raw(bitwXor(as.integer(plaintext), 0xa5L))
    .phase18_b64url(c(raw(60L), transformed))
  }
  bundle <- .dsvert_formal_glm_phase18_materialize_block(
    source_authorization, 0L, tickets[[1L]], tickets[[2L]],
    .resolved_snapshots = .phase18_snapshot(fixture, source),
    .random_bytes = .phase18_random, .encryptor = opaque_encryptor,
    .signer = .phase18_signer, .verifier = .phase18_verifier)
  root <- file.path(tempdir(), paste0(
    "phase18-durable-inbox-", Sys.getpid(), "-",
    sample.int(.Machine$integer.max, 1L)))
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  key <- as.raw(rev(seq_len(32L)))
  global_root <- .phase18_hash("phase18-global-materialization-root")
  enqueue <- function(value = bundle) {
    .dsvert_formal_glm_phase18_enqueue_recipient(
      value, recipient_authorization, global_root,
      verifier = .phase18_verifier, .root = root, .key = key)
  }
  first <- jsonlite::fromJSON(enqueue(), simplifyVector = FALSE)
  expect_false(first$replayed)
  expect_false(first$production_ready)
  expect_identical(as.numeric(first$openings_performed), 0)
  second <- jsonlite::fromJSON(enqueue(), simplifyVector = FALSE)
  expect_true(second$replayed)
  expect_identical(second$handle, first$handle)

  key_id <- .dsvert_formal_glm_phase18_key_id(key)
  records <- list.files(
    file.path(root, "recipient-inbox-v2", key_id),
    pattern = "^slot-.*\\.bin$", recursive = TRUE, full.names = TRUE)
  expect_length(records, 1L)
  encoded <- readBin(records, "raw", n = file.info(records)$size)
  expect_silent(.dsvert_formal_glm_phase18_frame_verify(encoded, key))
  expect_lte(length(encoded), .DSVERT_FORMAL_GLM_PHASE18_MAX_FRAME_BYTES)
  expect_false(any(vapply(c(
    "private_alignment", "accepted_phase19", "rejected_phase19",
    "patient_id"), function(value) {
      .phase18_raw_contains(encoded, value)
    }, logical(1L))))

  tampered <- jsonlite::fromJSON(bundle, simplifyVector = FALSE)
  tampered$run_id <- "misrouted-run"
  tampered <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(tampered))
  expect_error(enqueue(tampered),
               class = "dsvert_formal_glm_phase18_error")

  changing <- local({
    counter <- 0L
    function(n) {
      counter <<- counter + 1L
      as.raw(rep((seq_len(n) + counter * 17L) %% 256L, length.out = n))
    }
  })
  conflicting <- .dsvert_formal_glm_phase18_materialize_block(
    source_authorization, 0L, tickets[[1L]], tickets[[2L]],
    .resolved_snapshots = .phase18_snapshot(fixture, source),
    .random_bytes = changing,
    .encryptor = function(plaintext, recipient_pk) {
      .phase18_b64url(c(as.raw(rep(99L, 60L)), plaintext))
    }, .signer = .phase18_signer, .verifier = .phase18_verifier)
  expect_error(enqueue(conflicting),
               class = "dsvert_formal_glm_phase18_error")
})

test_that("Phase-1.8 finalizer key bootstraps persistently and epochs rotation", {
  root <- file.path(tempdir(), paste0(
    "phase18-key-bootstrap-", Sys.getpid(), "-",
    sample.int(.Machine$integer.max, 1L)))
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  state <- new.env(parent = emptyenv())
  state$counter <- 0L
  random_bytes <- function(n) {
    state$counter <- state$counter + 1L
    as.raw(rep(state$counter, n))
  }
  first <- .dsvert_formal_glm_phase18_init_key(root, random_bytes)
  second <- .dsvert_formal_glm_phase18_init_key(
    root, function(n) stop("persistent key must be reused"))
  expect_identical(second, first)
  expect_identical(state$counter, 1L)
  key_path <- .dsvert_formal_glm_phase18_key_path(root)
  expect_identical(as.numeric(file.info(key_path)$mode),
                   as.numeric(strtoi("600", base = 8L)))
  old_id <- .dsvert_formal_glm_phase18_key_id(first)
  unlink(key_path, force = TRUE)
  replacement <- .dsvert_formal_glm_phase18_init_key(root, random_bytes)
  expect_false(identical(replacement, first))
  expect_false(identical(
    .dsvert_formal_glm_phase18_key_id(replacement), old_id))
  expect_error(.dsvert_formal_glm_phase18_key_id(raw(32L)),
               class = "dsvert_formal_glm_phase18_error")
})

test_that("Phase-1.8 CAS crash cleanup is isolated to one semantic slot", {
  root <- file.path(tempdir(), paste0(
    "phase18-cas-isolation-", Sys.getpid(), "-",
    sample.int(.Machine$integer.max, 1L)))
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  directory <- .dsvert_formal_glm_phase18_private_dir(root)
  first_slot <- strrep("a", 64L)
  second_slot <- strrep("b", 64L)
  first_prefix <- paste0(".phase18-outbox-", first_slot, "-tmp-")
  second_prefix <- paste0(".phase18-outbox-", second_slot, "-tmp-")
  first_stale <- file.path(directory, paste0(first_prefix, "crash"))
  second_active <- file.path(directory, paste0(second_prefix, "active"))
  writeBin(as.raw(1:4), first_stale)
  writeBin(as.raw(5:8), second_active)
  Sys.chmod(c(first_stale, second_active), mode = "0600")
  target <- file.path(directory, paste0("slot-", first_slot, ".bin"))
  committed <- .dsvert_formal_glm_phase18_atomic_cas(
    target, as.raw(9:16), 1024L, first_prefix)
  expect_false(committed$replayed)
  expect_false(file.exists(first_stale))
  expect_true(file.exists(second_active))
  replay <- .dsvert_formal_glm_phase18_atomic_cas(
    target, as.raw(9:16), 1024L, first_prefix)
  expect_true(replay$replayed)
  expect_error(.dsvert_formal_glm_phase18_atomic_cas(
    target, as.raw(10:17), 1024L, first_prefix),
    class = "dsvert_formal_glm_phase18_error")
})

test_that("Phase-1.8 ingress framing matches the Go golden vector", {
  ciphertext <- as.raw((seq_len(240L) - 1L) %% 256L)
  frame <- list(
    capsule_sha256 = strrep("a", 64L),
    plan_sha256 = strrep("b", 64L),
    pre_execution_sha256 = strrep("c", 64L),
    global_materialization_root = strrep("d", 64L),
    run_id = "phase18-golden-run", source_name = "peer-a",
    recipient_name = "peer-b",
    recipient_ticket_sha256 = strrep("e", 64L),
    pair_commitment_sha256 = strrep("f", 64L),
    block_commitment_sha256 = strrep("0", 64L),
    ciphertext_sha256 = digest::digest(
      ciphertext, algo = "sha256", serialize = FALSE),
    envelope_sha256 = strrep("1", 64L),
    source_slot = 2L, recipient_slot = 1L, block_index = 1L,
    total_blocks = 3L, global_slot_offset = 8L, slots_in_block = 2L,
    coordinate_count = 4L, coordinate_records = 8L, ring_bits = 128L,
    record_bytes = 16L, validity_records = 2L,
    ciphertext = ciphertext)
  encoded <- .dsvert_formal_glm_phase18_frame_encode(
    frame, as.raw(seq_len(32L)))
  expect_length(encoded, 1026L)
  expect_identical(
    digest::digest(encoded, algo = "sha256", serialize = FALSE),
    "0fc813f230010c3163f5ad5132794037c233b0990bf35c7110858d7ff268cb5b")
  wrong_width <- frame
  wrong_width$record_bytes <- 17L
  expect_error(.dsvert_formal_glm_phase18_frame_encode(
    wrong_width, as.raw(seq_len(32L))),
    class = "dsvert_formal_glm_phase18_error")
  expect_error(.dsvert_formal_glm_phase18_frame_encode(frame, raw(32L)),
               class = "dsvert_formal_glm_phase18_error")
})

test_that("Phase-1.8 private plaintext matches the Go golden vector", {
  header <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_PHASE18_PRIVATE_BLOCK_VERSION,
    purpose = .DSVERT_FORMAL_GLM_PHASE18_PURPOSE,
    capsule_id = strrep("a", 64L), plan_sha256 = strrep("b", 64L),
    pre_execution_sha256 = strrep("c", 64L),
    run_id = "phase18-private-golden", source_name = "peer-a",
    source_slot = 2L, recipient_name = "peer-b",
    recipient_role = "evaluator",
    recipient_ticket_sha256 = strrep("d", 64L),
    block_index = 1L, total_blocks = 3L, global_slot_offset = 8L,
    slots_in_block = 2L, coordinate_count = 4L,
    coordinate_share_bytes = 128L, validity_share_bytes = 2L,
    ring_bits = 128L, record_bytes = 16L,
    validity_sharing = .DSVERT_FORMAL_GLM_PHASE18_VALIDITY,
    alignment_sharing = .DSVERT_FORMAL_GLM_PHASE18_ALIGNMENT_SHARING,
    private_alignment_gate_share = 1L,
    private_alignment_consensus_share = .dsvert_relay_b64url_encode(
      as.raw(seq.int(0L, 31L))),
    phase19_required_operation = paste0(
      "xor_reconstruct_validity_alignment_and_consensus_then_",
      "all_k_mask_full_tuple_before_glm_kernel_v2"),
    release_token = "none_pre_execution", openings_performed = 0L))
  packed <- .dsvert_dp_capsule_source_pack(
    header, as.raw(seq.int(0L, 129L)))
  expect_length(packed, 1391L)
  expect_identical(
    digest::digest(packed, algo = "sha256", serialize = FALSE),
    "a3bcfcfda23017b96785bef73660f8206bf97705106279e7b4392a43fc4182af")
})
