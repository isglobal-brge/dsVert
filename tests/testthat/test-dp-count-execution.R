test_that("Count execution exposes only the new stateless phases", {
  public <- c(
    "dsvertDPCountAuthorizeDS", "dsvertDPCountStartDS",
    "dsvertDPCountFinalShareDS", "dsvertDPCountReleaseDS")
  expect_true(all(vapply(
    public, exists, logical(1L), envir = asNamespace("dsVert"),
    mode = "function", inherits = FALSE)))
  expect_identical(
    names(formals(.dsvert_dp_count_authorize_endpoint_v1)),
    c("config_json", "receipts_json", "session_id"))
  expect_identical(
    names(formals(dsvertDPCountAuthorizeDS)),
    c("config_json", "receipts_json", "session_id"))
  expect_identical(
    names(formals(.dsvert_dp_count_start_endpoint_v1)),
    c("data_name", "session_id", "operation_id", "source_key",
      "output_key", "authorizations_json"))
  expect_identical(
    names(formals(dsvertDPCountStartDS)),
    c("data_name", "session_id", "operation_id", "source_key",
      "output_key", "authorizations_json"))
  expect_identical(
    names(formals(.dsvert_dp_count_final_share_endpoint_v1)),
    c("session_id", "operation_id", "output_key", "recipient_pk"))
  expect_identical(
    names(formals(dsvertDPCountFinalShareDS)),
    c("session_id", "operation_id", "output_key", "recipient_pk"))
  expect_identical(
    names(formals(.dsvert_dp_count_release_endpoint_v1)),
    c("session_id", "operation_id", "output_key"))
  expect_identical(
    names(formals(dsvertDPCountReleaseDS)),
    c("session_id", "operation_id", "output_key"))
  expect_false(exists(
    "dsvertPublicFixedCohortCountDS", envir = asNamespace("dsVert"),
    inherits = FALSE))
})

test_that("Count source encoding counts aligned membership once", {
  expect_identical(
    .dsvert_dp_count_execution_source_share_v1(7L, "garbler"),
    .exact_gc_decimal_residues_b64("7", 127L))
  expect_identical(
    .dsvert_dp_count_execution_source_share_v1(7L, "evaluator"),
    .exact_gc_decimal_residues_b64("0", 127L))
  expect_identical(
    .dsvert_dp_count_execution_source_share_v1(0L, "garbler"),
    .exact_gc_decimal_residues_b64("0", 127L))
  expect_identical(
    .dsvert_dp_count_execution_source_share_v1(0L, "evaluator"),
    .exact_gc_decimal_residues_b64("0", 127L))
  expect_error(
    .dsvert_dp_count_execution_source_share_v1(7L, "observer"),
    "authority role")
})

.count_execution_pk <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.count_execution_config <- function(k = 3L, upper = 10L) {
  peers <- paste0("site_", seq_len(k))
  pins <- stats::setNames(vapply(
    seq_len(k), .count_execution_pk, character(1L)), peers)
  list(
    version = .DSVERT_DP_COUNT_CONFIG_VERSION,
    domain = "count-execution-domain",
    cohort_id = "count-execution-cohort",
    dataset_id = "count-execution-table",
    dataset_version = "v1",
    privacy_unit_column = "patient_id",
    alignment_purpose = "patient-record-alignment-v1",
    count_upper_bound = upper,
    max_records_per_unit = 1,
    overflow_policy = "reject_operation",
    privacy = list(epsilon = 1, delta = 1e-6),
    calibration = list(implementation_delta = 1e-9),
    peer_pins = pins,
    backend_build_sha256 = strrep("a", 64L),
    transport_chunk_coordinates = 4096)
}

.count_execution_plan <- function(
    epsilon, delta, sensitivity_steps, coordinate_count,
    bernoulli_bits, max_steps) {
  list(
    version = "dsvert-joint-dp-laplace-plan-v2",
    sampler = .DSVERT_DP_ANALYSIS_COUNT_TV_SAMPLER,
    bernoulli_bits = as.integer(bernoulli_bits),
    stop_numerator = "51",
    max_geometric_steps = 76L,
    sensitivity_steps = as.character(sensitivity_steps),
    coordinate_count = as.integer(coordinate_count),
    epsilon_effective_upper_numerator = "1",
    epsilon_effective_upper_denominator = "1",
    implementation_delta_numerator = "1",
    implementation_delta_denominator = "1000000000",
    implementation_delta_bound = "1/1000000000",
    accounting = "exact-rational finite sampler certificate",
    bernoulli_trials = 608L,
    aes_blocks = 38L,
    capability_available = FALSE,
    unavailable_reason = "test planner")
}

.count_execution_signature <- function(message, key) {
  .dsvert_relay_b64url_encode(digest::hmac(
    key = charToRaw(key), object = message, algo = "sha512",
    serialize = FALSE, raw = TRUE))
}

.count_execution_signer <- function(message, peer_name, identity_pk) {
  .count_execution_signature(message, identity_pk)
}

.count_execution_verifier <- function(
    message, identity_pk, signature, peer_name = NULL) {
  identical(signature, .count_execution_signature(message, identity_pk))
}

.count_execution_receipts <- function(config) {
  config <- .dsvert_dp_count_config_validate_v1(config)
  plan <- .dsvert_dp_count_plan_certificate_v1(
    .count_execution_plan(
      .dsvert_dp_count_decimal_text(config$privacy$epsilon),
      .dsvert_dp_count_decimal_text(
        config$calibration$implementation_delta),
      "1", 1L, 8L, 4096L), config)
  peers <- sort(names(config$peer_pins), method = "radix")
  lapply(peers, function(peer) {
    draft <- .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_DP_COUNT_RECEIPT_VERSION,
      peer_name = peer,
      peer_identity_pk = unname(config$peer_pins[[peer]]),
      config_sha256 = .dsvert_dp_count_config_hash_v1(config),
      psi_run_sha256 = strrep("b", 64L),
      snapshot_commitment = digest::digest(
        paste0("snapshot|", peer), algo = "sha256", serialize = FALSE),
      sampler_plan = plan))
    .dsvert_dp_count_sign_receipt_v1(
      draft, .signer = .count_execution_signer)
  })
}

.count_execution_identity_seed <- function(index) {
  gsub("[\r\n]", "", jsonlite::base64_enc(
    as.raw(rep(as.integer(index + 40L), 32L))))
}

.count_execution_authorization <- function(
    config, receipts, session_id, identity_pk) {
  testthat::with_mocked_bindings(
    .dsvert_dp_count_authorize_session_v1(
      new.env(parent = emptyenv()), session_id, config, receipts,
      .verifier = .count_execution_verifier,
      .planner = .count_execution_plan),
    .get_identity_keypair = function() list(identity_pk = identity_pk),
    .package = "dsVert")
}

.count_execution_public_authorization <- function(
    authorization, index) {
  identity <- authorization$local_authority$identity_pk
  testthat::with_mocked_bindings(
    .dsvert_dp_count_public_authorization_v1(
      authorization,
      .signer = function(message, identity_sk) {
        .count_execution_signature(message, identity_sk)
      }),
    .get_identity_keypair = function() list(
      identity_pk = identity, identity_sk = identity),
    .get_identity_seed = function() .count_execution_identity_seed(index),
    .package = "dsVert")
}

.count_execution_fixture <- function(k = 3L, upper = 10L,
                                     session_id =
                                       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa") {
  config <- .count_execution_config(k, upper)
  receipts <- .count_execution_receipts(config)
  contract <- .dsvert_dp_count_compile_v1(
    receipts, config, .verifier = .count_execution_verifier)
  roles <- .exact_gc_analysis_contract_binding(contract)$binding$
    authority_roles
  values <- lapply(seq_along(roles), function(index) {
    authorization <- .count_execution_authorization(
      config, receipts, session_id, roles[[index]])
    peer_index <- match(
      authorization$local_authority$peer_name, names(config$peer_pins))
    list(
      authorization = authorization,
      public = .count_execution_public_authorization(
        authorization, peer_index))
  })
  names(values) <- names(roles)
  list(
    config = config, receipts = receipts, contract = contract,
    roles = roles, values = values, session_id = session_id)
}

.count_execution_authorizations_json <- function(fixture) {
  .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
    fixture$values$garbler$public,
    fixture$values$evaluator$public)))
}

.count_execution_compiler <- function(input) {
  circuit <- digest::digest(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(input)),
    algo = "sha256", serialize = FALSE)
  policy <- list(
    version = .DSVERT_JOINT_DP_BACKEND_TEMPLATE_V2,
    sampler = .DSVERT_DP_ANALYSIS_COUNT_TV_SAMPLER,
    bernoulli_bits = input$bernoulli_bits,
    stop_numerator = "51",
    max_geometric_steps = 76L,
    sensitivity_steps = input$sensitivity_steps,
    epsilon = input$epsilon,
    allocated_delta = input$allocated_delta,
    encoded_lower = input$encoded_lower,
    encoded_upper = input$encoded_upper,
    transcript_hash = input$transcript_hash,
    garbler_commitment_context = input$garbler_commitment_context,
    evaluator_commitment_context = input$evaluator_commitment_context,
    garbler_seed_commitment = input$garbler_seed_commitment,
    evaluator_seed_commitment = input$evaluator_seed_commitment,
    circuit_digest = circuit,
    implementation_delta_numerator = "1",
    implementation_delta_denominator = "1000000000")
  list(
    version = .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT,
    capability_id = .DSVERT_JOINT_DP_COUNT_EXACT_CAPABILITY,
    operation = "joint-dp-laplace-v2",
    purpose = paste0("joint-dp-laplace-v2/", circuit),
    circuit_digest = circuit,
    input_contract = "public-data-free-count-v1",
    protected_inputs_accepted = FALSE,
    private_seed_accepted = FALSE,
    worker_policy = policy,
    capability_available = TRUE)
}

test_that("public Count authorization is signed, sticky and K-generic", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .count_execution_fixture(k)
    expect_length(fixture$values, 2L)
    for (role in c("garbler", "evaluator")) {
      value <- fixture$values[[role]]$public
      expect_identical(
        .dsvert_dp_count_public_authorization_validate_v1(
          value, .verifier = .count_execution_verifier),
        value)
      expect_identical(value$local_authority$role, role)
      expect_identical(
        value$worker_static_sha256,
        .dsvert_dp_count_worker_static_sha256_v1(
          fixture$values[[role]]$authorization$worker_static))
      expect_false(any(c("contract", "config", "receipts") %in%
                         names(value)))
      expect_false(any(grepl(
        "identity_seed|private_seed|noise_root|budget|lifetime",
        .dsvert_dp_canonical_json(value), fixed = FALSE)))
    }
    json <- .count_execution_authorizations_json(fixture)
    local <- fixture$values$garbler
    peer_index <- match(
      local$authorization$local_authority$peer_name,
      names(fixture$config$peer_pins))
    decoded <- testthat::with_mocked_bindings(
      .dsvert_dp_count_decode_authorizations_v1(
        json, local$authorization,
        .verifier = .count_execution_verifier),
      .get_identity_keypair = function() list(
        identity_pk = local$authorization$local_authority$identity_pk),
      .get_identity_seed = function() .count_execution_identity_seed(
        peer_index),
      .package = "dsVert")
    expect_identical(names(decoded), c("garbler", "evaluator"))
  }

  fixture <- .count_execution_fixture(3L)
  first <- fixture$values$garbler$public
  authorization <- fixture$values$garbler$authorization
  expect_identical(first$contract_sha256,
                   "4af7de71c59cd58b886c56a9aa919811fe89a9c3f4682de859233e2abf8cd11e")
  expect_identical(first$analysis_binding_sha256,
                   "e57c641b4593198a54f922f667d24f5e109c00c98eaf795a9713fedb8473aa89")
  expect_identical(first$worker_static_sha256,
                   "13c6cc9546265dbd8820efc2a5b2ea2def16b7ae5f2647b3b56023eb2ff38401")
  expect_identical(
    vapply(fixture$values, function(value) {
      value$public$authorization_sha256
    }, character(1L)),
    c(
      evaluator = "955aa8d267758db1632f05ff3447a9e250a056b8017201cd1aec98362bd883cf",
      garbler = "a8d5bf5cd4b4e8d4ba8688ac6fdddfb74d0dca38ae42e7bb1b820b078956ff6d"))
  expect_identical(
    vapply(fixture$values, function(value) {
      value$public$seed_commitment
    }, character(1L)),
    c(
      evaluator = "2027a9ba66a7ab4aace463041c7220149ab263d4eb0103c7d08b75b4bf98a772",
      garbler = "d20cd194b4ee082aa38ab23941af35afc9b587a7b4176dc9507f7421792d8c4c"))
  index <- match(
    authorization$local_authority$peer_name,
    names(fixture$config$peer_pins))
  expect_identical(
    .count_execution_public_authorization(authorization, index), first)

  reversed <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(rev(list(
      fixture$values$garbler$public,
      fixture$values$evaluator$public))))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_decode_authorizations_v1(
      reversed, authorization, .verifier = .count_execution_verifier),
    .get_identity_keypair = function() list(
      identity_pk = authorization$local_authority$identity_pk),
    .get_identity_seed = function() .count_execution_identity_seed(index),
    .package = "dsVert"), "canonical role order")

  tampered <- fixture$values$garbler$public
  tampered$seed_commitment <- strrep("f", 64L)
  expect_error(
    .dsvert_dp_count_public_authorization_validate_v1(
      tampered, .verifier = .count_execution_verifier),
    "signature verification")

  restart <- .count_execution_fixture(
    3L, session_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
  expect_identical(
    vapply(fixture$values, function(value) {
      value$public$seed_commitment
    }, character(1L)),
    vapply(restart$values, function(value) {
      value$public$seed_commitment
    }, character(1L)))
  changed <- .count_execution_fixture(3L, upper = 11L)
  expect_false(identical(
    vapply(fixture$values, function(value) {
      value$public$seed_commitment
    }, character(1L)),
    vapply(changed$values, function(value) {
      value$public$seed_commitment
    }, character(1L))))
})

test_that("Authorize accepts only framed canonical arrays and rolls back", {
  fixture <- .count_execution_fixture(3L)
  local <- fixture$values$garbler$authorization
  peer_index <- match(
    local$local_authority$peer_name, names(fixture$config$peer_pins))
  config_wire <- fixture$config
  config_wire$peer_pins <- as.list(config_wire$peer_pins)
  config_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(config_wire))
  receipts_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(fixture$receipts))
  config_frame <- .dsvert_dsi_text_encode(config_json)
  receipts_frame <- .dsvert_dsi_text_encode(receipts_json)
  call_endpoint <- function(ss, signer_fails = FALSE) {
    testthat::with_mocked_bindings(
      .dsvert_dp_count_authorize_endpoint_v1(
        config_frame, receipts_frame, fixture$session_id),
      .S = function(session_id) ss,
      .get_identity_keypair = function() list(
        identity_pk = local$local_authority$identity_pk,
        identity_sk = local$local_authority$identity_pk),
      .get_identity_seed = function() .count_execution_identity_seed(
        peer_index),
      .dsvert_relay_verify_message = .count_execution_verifier,
      .dsvert_relay_sign_message = function(message, identity_sk) {
        if (signer_fails) stop("test signer failed", call. = FALSE)
        .count_execution_signature(message, identity_sk)
      },
      .dsvert_joint_dp_laplace_plan_v2 = .count_execution_plan,
      .package = "dsVert")
  }
  ss <- new.env(parent = emptyenv())
  value <- call_endpoint(ss)
  expect_identical(value, call_endpoint(ss))
  expect_identical(
    value$artifact_key, fixture$contract$artifact_key)
  expect_identical(ss$.dp_count_authorization$artifact_key,
                   fixture$contract$artifact_key)

  failed <- new.env(parent = emptyenv())
  expect_error(call_endpoint(failed, signer_fails = TRUE),
               "test signer failed")
  expect_null(failed$.dp_count_authorization)

  touched <- FALSE
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_authorize_endpoint_v1(
      config_json, receipts_frame, fixture$session_id),
    .S = function(session_id) {
      touched <<- TRUE
      new.env(parent = emptyenv())
    },
    .package = "dsVert"), "framed DSI text")
  expect_false(touched)
})

test_that("Start stages aligned Count once at garbler and zero at evaluator", {
  fixture <- .count_execution_fixture(3L)
  authorizations_json <- .count_execution_authorizations_json(fixture)
  operation_id <- "op_11111111111111111111111111111111"
  source_key <- "exact_gc_in_11111111111111111111111111111111"
  output_key <- "exact_gc_out_11111111111111111111111111111111"
  private_seeds <- list()
  for (role in c("garbler", "evaluator")) {
    local <- fixture$values[[role]]$authorization
    peer_index <- match(
      local$local_authority$peer_name, names(fixture$config$peer_pins))
    ss <- new.env(parent = emptyenv())
    staged <- list()
    init_calls <- 0L
    call_start <- function(output = output_key, operation = operation_id) {
      testthat::with_mocked_bindings(
        .dsvert_dp_count_start_impl_v1(
          data.frame(patient_id = paste0("p", seq_len(7L))),
          fixture$session_id, operation, source_key, output,
          authorizations_json,
          .verifier = .count_execution_verifier,
          .compiler = .count_execution_compiler,
          binary = "test-worker"),
        .S = function(session_id) ss,
        .dsvert_dp_count_session_authorization_validate_v1 =
          function(ss, session_id, artifact_key = NULL) local,
        .dsvert_dp_count_execution_binding_v1 = function(...) invisible(),
        .dsvert_dp_count_execution_snapshot_v1 = function(...) list(
          count = 7L,
          snapshot_commitment = local$contract$semantic$owner_snapshots[[
            local$local_authority$identity_pk]]$snapshot_commitment,
          psi_run_sha256 = local$psi_run_sha256),
        .exact_gc_operation_state = function(...) {
          if (init_calls) list(existing = TRUE) else NULL
        },
        .exact_gc_stage_share = function(
            ss, key, share, ring_bits, vector_len, producer, operation,
            purpose, frac_bits, output_kind, ...) {
          staged[[length(staged) + 1L]] <<- list(
            share = share, ring_bits = ring_bits, vector_len = vector_len,
            producer = producer, operation = operation, purpose = purpose,
            frac_bits = frac_bits, output_kind = output_kind)
          invisible(key)
        },
        .exact_gc_init_impl = function(
            ss, session_id, operation_id, capability_id, source_key,
            output_key, operation, ring, frac_bits, vector_len, purpose,
            joint_dp, private_seed, binary, ...) {
          init_calls <<- init_calls + 1L
          private_seeds[[role]] <<- private_seed
          list(state = "running", role = role, purpose = purpose)
        },
        .get_identity_keypair = function() list(
          identity_pk = local$local_authority$identity_pk),
        .get_identity_seed = function() .count_execution_identity_seed(
          peer_index),
        .package = "dsVert")
    }
    result <- call_start()
    expect_identical(result$state, "running")
    expect_length(staged, 1L)
    expect_identical(
      staged[[1L]]$share,
      .exact_gc_decimal_residues_b64(
        if (identical(role, "garbler")) "7" else "0", 127L))
    expect_identical(staged[[1L]]$ring_bits, 127L)
    expect_identical(staged[[1L]]$vector_len, 1L)
    expect_identical(staged[[1L]]$producer,
                     .DSVERT_DP_COUNT_EXECUTION_PRODUCER)
    expect_identical(staged[[1L]]$operation, "joint-dp-laplace-v2")
    expect_identical(call_start(), result)
    expect_length(staged, 1L)
    expect_identical(init_calls, 2L)
    expect_error(call_start(paste0(output_key, "x")),
                 "state key|Conflicting retry")
    expect_error(call_start(
      output = "exact_gc_out_33333333333333333333333333333333",
      operation = "op_33333333333333333333333333333333"),
      "exactly one cryptographic operation")
  }
  expect_false(identical(private_seeds$garbler,
                         private_seeds$evaluator))
})

test_that("Start fails before inspecting a source without authorization bind", {
  fixture <- .count_execution_fixture(2L)
  local <- fixture$values$garbler$authorization
  ss <- new.env(parent = emptyenv())
  inspected <- FALSE
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_count_start_impl_v1(
      data.frame(patient_id = "p1"), fixture$session_id,
      "op_22222222222222222222222222222222",
      "exact_gc_in_22222222222222222222222222222222",
      "exact_gc_out_22222222222222222222222222222222",
      .count_execution_authorizations_json(fixture),
      binary = "test-worker"),
    .S = function(session_id) ss,
    .dsvert_dp_count_session_authorization_validate_v1 =
      function(...) local,
    .dsvert_dp_count_execution_binding_v1 = function(...) {
      stop("authorized bind missing", call. = FALSE)
    },
    .dsvert_dp_count_execution_snapshot_v1 = function(...) {
      inspected <<- TRUE
      stop("must not inspect", call. = FALSE)
    },
    .package = "dsVert"), "authorized bind missing")
  expect_false(inspected)
  expect_null(ss$.dp_count_execution)
})

test_that("snapshot revalidation reuses the signed sampler certificate", {
  fixture <- .count_execution_fixture(3L)
  authorization <- fixture$values$garbler$authorization
  signed <- authorization$contract$semantic$analysis$effective_arguments$
    sampler_plan
  seen <- FALSE
  value <- testthat::with_mocked_bindings(
    .dsvert_dp_count_execution_snapshot_v1(
      data.frame(patient_id = c("p1", "p2")), authorization),
    .dsvert_dp_count_local_draft_v1 = function(
        data, config, peer_name, .planner, ...) {
      seen <<- TRUE
      plan <- .planner(
        epsilon = "ignored", delta = "ignored",
        sensitivity_steps = "ignored", coordinate_count = 999L,
        bernoulli_bits = 999L, max_steps = 999L)
      expect_identical(
        plan[setdiff(names(plan),
                     c("capability_available", "unavailable_reason"))],
        signed)
      expect_true(plan$capability_available)
      list(
        snapshot_commitment = authorization$contract$semantic$
          owner_snapshots[[authorization$local_authority$identity_pk]]$
          snapshot_commitment,
        psi_run_sha256 = authorization$psi_run_sha256,
        sampler_plan = signed,
        config_sha256 = authorization$config_sha256)
    },
    .dsvert_joint_dp_laplace_plan_v2 = function(...) {
      stop("planner subprocess must not run", call. = FALSE)
    },
    .package = "dsVert")
  expect_true(seen)
  expect_identical(value$count, 2L)
})

.count_execution_record <- function(
    fixture, role, operation_id =
      "op_44444444444444444444444444444444",
    output_key = "exact_gc_out_44444444444444444444444444444444") {
  authorization <- fixture$values[[role]]$authorization
  authorizations <- list(
    evaluator = fixture$values$evaluator$public,
    garbler = fixture$values$garbler$public)
  worker <- .dsvert_dp_count_compile_worker_v1(
    authorization, authorizations,
    .compiler = .count_execution_compiler)
  execution <- .dsvert_dp_count_execution_request_v1(
    authorization, authorizations,
    list(
      snapshot_commitment = authorization$contract$semantic$
        owner_snapshots[[authorization$local_authority$identity_pk]]$
        snapshot_commitment,
      psi_run_sha256 = authorization$psi_run_sha256),
    operation_id,
    "exact_gc_in_44444444444444444444444444444444",
    output_key, worker)
  list(
    authorization = authorization,
    execution = execution,
    exact_state = list(
      role = role, status = "complete", output_key = output_key,
      purpose = worker$purpose,
      context_hash = digest::digest(
        paste0("exact-context|", fixture$session_id),
        algo = "sha256", serialize = FALSE),
      analysis_binding_sha256 = authorization$analysis_binding_sha256))
}

.count_execution_output <- function(value, validity, record) {
  list(
    share = .exact_gc_decimal_residues_b64(as.character(value), 127L),
    validity_share = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(as.integer(validity)))),
    context_hash = record$exact_state$context_hash)
}

test_that("final payload is closed and final-share response leaks no share", {
  fixture <- .count_execution_fixture(3L)
  record <- .count_execution_record(fixture, "garbler")
  output <- .count_execution_output(3L, 0L, record)
  payload <- .dsvert_dp_count_final_payload_v1(record, output)
  encoded <- charToRaw(.dsvert_dp_canonical_json(payload))
  decoded <- .dsvert_dp_count_final_payload_decode_v1(encoded)
  expect_identical(decoded$share, output$share)
  changed <- payload
  changed$exact_context_hash <- strrep("f", 64L)
  changed$unexpected <- TRUE
  expect_error(.dsvert_dp_count_final_payload_decode_v1(charToRaw(
    .dsvert_dp_canonical_json(changed))), "Invalid encrypted")

  ss <- new.env(parent = emptyenv())
  peer_transport <- gsub("[\r\n]", "", jsonlite::base64_enc(
    as.raw(rep(91L, 32L))))
  ss$peer_transport_pks <- stats::setNames(
    list(peer_transport),
    record$execution$role_map$finalizer$peer_name)
  recipient <- base64_to_base64url(peer_transport)
  transfer <- list(
    ticket = "ticket", transfer_id = paste0("tb_", strrep("1", 32L)),
    capability_id = .DSVERT_DP_COUNT_FINAL_CAPABILITY,
    sender_name = record$execution$role_map$source$peer_name,
    recipient_name = record$execution$role_map$finalizer$peer_name,
    payload_chars = 12, payload_sha256 = strrep("a", 64L))
  calls <- new.env(parent = emptyenv())
  calls$encrypt <- 0L
  calls$mint <- 0L
  invoke <- function() .dsvert_dp_count_final_share_impl_v1(
      ss, fixture$session_id, record$execution$operation_id,
      record$execution$output_key, recipient)
  results <- testthat::with_mocked_bindings({
    first <- invoke()
    second <- invoke()
    list(first, second)
  },
    .S = function(session_id) ss,
    .dsvert_dp_count_execution_record_v1 = function(...) record,
    .dsvert_typed_blob_recipient_name = function(...) {
      record$execution$role_map$finalizer$peer_name
    },
    .dsvert_typed_blob_operation_replay = function(...) list(hit = FALSE),
    .dsvert_dp_count_output_v1 = function(...) output,
    .callMpcTool = function(command, input) {
      expect_identical(command, "transport-encrypt")
      calls$encrypt <- calls$encrypt + 1L
      list(sealed = gsub("[\r\n]", "", jsonlite::base64_enc(
        charToRaw("opaque-ciphertext"))))
    },
    .dsvert_typed_blob_mint = function(...) {
      calls$mint <- calls$mint + 1L
      transfer
    },
    .dsvert_typed_blob_operation_commit = function(
        ss, producer, request, result) result,
    .package = "dsVert")
  result <- results[[1L]]
  expect_identical(results[[2L]], result)
  expect_identical(calls$encrypt, 1L)
  expect_identical(calls$mint, 1L)
  expect_identical(result$state, "final_share_sealed")
  expect_false(result$intermediate_values_exposed)
  expect_setequal(
    intersect(names(result), c(
      "share", "validity_share", "count", "seed", "private_seed")),
    character())
  expect_identical(
    result$transfer, .dsvert_dp_canonical_query_value(transfer))
})

test_that("Ring127 reconstruction is exact modulo 2^127", {
  maximum <- as.raw(c(rep(255L, 15L), 127L))
  one <- as.raw(c(1L, rep(0L, 15L)))
  expect_identical(
    .dsvert_dp_count_ring127_add_v1(maximum, one), raw(16L))
  expect_identical(
    .dsvert_dp_count_ring127_add_v1(
      as.raw(c(3L, rep(0L, 15L))),
      as.raw(c(4L, rep(0L, 15L)))),
    as.raw(c(7L, rep(0L, 15L))))
  noncanonical <- raw(16L)
  noncanonical[[16L]] <- as.raw(128L)
  expect_error(
    .dsvert_dp_count_ring127_add_v1(noncanonical, raw(16L)),
    "canonical Ring127")
})

.count_execution_release_call <- function(
    fixture, own_value = 3L, peer_value = 4L,
    own_validity = 0L, peer_validity = 1L,
    ss = new.env(parent = emptyenv()),
    record = .count_execution_record(fixture, "evaluator"),
    consume_fails_once = FALSE) {
  own_output <- .count_execution_output(own_value, own_validity, record)
  peer_output <- .count_execution_output(peer_value, peer_validity, record)
  peer_payload <- charToRaw(.dsvert_dp_canonical_json(
    .dsvert_dp_count_final_payload_v1(record, peer_output)))
  encrypted <- .dsvert_relay_b64url_encode(charToRaw("sealed"))
  calls <- new.env(parent = emptyenv())
  calls$typed <- 0L
  calls$output <- 0L
  ss$.exact_gc_outputs <- stats::setNames(
    list(list(present = TRUE)), record$execution$output_key)
  finalizer <- record$execution$role_map$finalizer$identity_pk
  invoke <- function() testthat::with_mocked_bindings(
    .dsvert_dp_count_release_impl_v1(
      ss, fixture$session_id, record$execution$operation_id,
      record$execution$output_key,
      .signer = function(message, identity_sk) {
        .count_execution_signature(message, identity_sk)
      }),
    .S = function(session_id) ss,
    .dsvert_dp_count_execution_record_v1 = function(...) record,
    .dsvert_typed_blob_consume = function(
        ss, capability_id, context, sender_name = NULL,
        required = TRUE, consume = TRUE) {
      calls$typed <- calls$typed + 1L
      if (consume_fails_once && consume && calls$typed == 2L) {
        stop("cleanup interrupted", call. = FALSE)
      }
      encrypted
    },
    .callMpcTool = function(command, input) {
      expect_identical(command, "transport-decrypt")
      list(data = gsub("[\r\n]", "", jsonlite::base64_enc(peer_payload)))
    },
    .key_get = function(name, ss) "recipient-secret",
    .dsvert_dp_count_output_v1 = function(ss, record, consume = FALSE) {
      calls$output <- calls$output + 1L
      if (consume) ss$.exact_gc_outputs[[record$execution$output_key]] <- NULL
      own_output
    },
    .get_identity_keypair = function() list(
      identity_pk = finalizer, identity_sk = finalizer),
    .package = "dsVert")
  list(invoke = invoke, calls = calls, ss = ss, record = record)
}

test_that("Release opens once, validates XOR/range and retries cleanup", {
  fixture <- .count_execution_fixture(3L)
  run <- .count_execution_release_call(fixture)
  first <- run$invoke()
  second <- run$invoke()
  expect_identical(second, first)
  expect_identical(first$value, "7")
  expect_identical(first$bounds, list(lower = "0", upper = "10"))
  expect_equal(first$public_openings, 1L)
  expect_false(first$intermediate_values_exposed)
  expect_false(any(c(
    "session_id", "operation_id", "attempt", "timestamp", "share",
    "validity_share", "seed", "count") %in% names(first)))
  expect_identical(run$calls$typed, 2L)
  expect_identical(run$calls$output, 2L)

  invalid <- .count_execution_release_call(
    fixture, own_validity = 0L, peer_validity = 0L)
  expect_error(invalid$invoke(), "validity certificate")
  expect_null(invalid$ss$.dp_count_releases$op_44444444444444444444444444444444)

  outside <- .count_execution_release_call(
    fixture, own_value = 8L, peer_value = 8L)
  expect_error(outside$invoke(), "clamp bounds")

  interrupted <- .count_execution_release_call(
    fixture, consume_fails_once = TRUE)
  expect_error(interrupted$invoke(), "cleanup interrupted")
  cached <- interrupted$invoke()
  expect_identical(cached$value, "7")
  expect_true(interrupted$ss$.dp_count_releases[[
    "op_44444444444444444444444444444444"]]$typed_consumed)
  expect_true(interrupted$ss$.dp_count_releases[[
    "op_44444444444444444444444444444444"]]$output_consumed)
})

test_that("signed release bytes exclude session and operation identity", {
  first_fixture <- .count_execution_fixture(3L)
  second_fixture <- .count_execution_fixture(
    3L, session_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
  first <- .count_execution_record(first_fixture, "evaluator")
  second <- .count_execution_record(
    second_fixture, "evaluator",
    operation_id = "op_55555555555555555555555555555555",
    output_key = "exact_gc_out_55555555555555555555555555555555")
  finalizer <- first$execution$role_map$finalizer$identity_pk
  signer <- function(message, identity_sk) {
    .count_execution_signature(message, identity_sk)
  }
  releases <- testthat::with_mocked_bindings(list(
    .dsvert_dp_count_release_v1(first, "7", .signer = signer),
    .dsvert_dp_count_release_v1(second, "7", .signer = signer)),
    .get_identity_keypair = function() list(
      identity_pk = finalizer, identity_sk = finalizer),
    .package = "dsVert")
  expect_identical(releases[[1L]], releases[[2L]])
  expect_identical(
    releases[[1L]]$release_sha256,
    "0baf127ec5a3ebdb1c790b30741e8985c568b90e735f4588e636d1e62dbb8e3f")
  encoded <- .dsvert_dp_canonical_json(releases[[1L]])
  expect_false(grepl(first_fixture$session_id, encoded, fixed = TRUE))
  expect_false(grepl(first$execution$operation_id, encoded, fixed = TRUE))
})

test_that("Count execution has no retired privacy-state call graph", {
  source <- paste(readLines(
    testthat::test_path("..", "..", "R", "dpCountExecutionDS.R"),
    warn = FALSE), collapse = "\n")
  forbidden <- c(
    "DBI::", "RSQLite", "SQLite", "noise_root", "dp_policy",
    "lifetime", "rate_limit", "budget", "capsule", "manifest",
    "jointDPCountAdapter", "dsvert_joint_dp_count_")
  expect_false(any(vapply(
    forbidden, grepl, logical(1L), x = source, fixed = TRUE)))
})
