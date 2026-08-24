.formal_glm_registered_source_b64 <- function(value) {
  gsub("[\r\n]", "", jsonlite::base64_enc(value))
}

.formal_glm_registered_source_b64url <- function(value) {
  sub("=+$", "", chartr("+/", "-_", value), perl = TRUE)
}

.formal_glm_registered_source_fixture <- function(
    k = 2L, family = "binomial", predictors = FALSE,
    source_name = "site_a") {
  peers <- c("site_a", "site_b", if (k > 2L) {
    paste0("witness_", seq_len(k - 2L))
  } else character())
  pins_raw <- stats::setNames(lapply(seq_along(peers), function(index) {
    as.raw((seq_len(32L) + index * 41L) %% 256L)
  }), peers)
  pins <- vapply(pins_raw, .formal_glm_registered_source_b64, character(1L))
  rows <- data.frame(
    patient_id = sprintf("patient-%02d", seq_len(4L)),
    outcome = if (identical(family, "binomial")) c(0, 1, 1, 0) else
      c(0, 2, 3, 9), stringsAsFactors = FALSE)
  if (isTRUE(predictors)) {
    rows$exposure <- c(-2, -0.5, 0.5, 2)
    rows$group <- c("control", "treated", "treated", "control")
  }
  binding <- .dsvert_test_padded_dp_binding(
    rows, "patient_id", "glm-cohort", "v1",
    stats::setNames(pins, peers))
  source <- new.env(parent = emptyenv())
  assign("glm_local", binding$data, envir = source)
  lockBinding("glm_local", source)
  hashes <- stats::setNames(vapply(c(
    "contract", "authorization", "logical-snapshot"), function(label) {
      digest::digest(label, algo = "sha256", serialize = FALSE)
    }, character(1L)), c("contract", "authorization", "logical"))
  local_columns <- list(list(
    owner = "site_a", dataset_id = "glm-cohort", dataset_version = "v1",
    column = "outcome", role = "response",
    kind = if (identical(family, "binomial")) "binary" else "count",
    lower_rational = "0", upper_rational =
      if (identical(family, "binomial")) "1" else "5"))
  terms <- list(list(
    index = 0L, coefficient = "(Intercept)", kind = "intercept",
    owner = NULL, source_column = NULL, source_level = NULL))
  columns <- list(outcome = "outcome")
  if (isTRUE(predictors)) {
    local_columns <- c(local_columns, list(
      list(owner = "site_a", dataset_id = "glm-cohort", dataset_version = "v1",
           column = "exposure", role = "predictor", kind = "numeric",
           lower_rational = "-1", upper_rational = "1"),
      list(owner = "site_a", dataset_id = "glm-cohort", dataset_version = "v1",
           column = "group", role = "predictor", kind = "factor",
           levels = c("control", "treated"), reference_level = "control",
           contrast = "treatment")))
    terms <- c(terms, list(
      list(index = 1L, coefficient = "site_a$exposure", kind = "numeric",
           owner = "site_a", source_column = "exposure", source_level = NULL),
      list(index = 2L, coefficient = "site_a$group[treated]",
           kind = "factor_level", owner = "site_a", source_column = "group",
           source_level = "treated")))
    columns <- c(columns, list(exposure = "exposure", group = "group"))
  }
  if (!identical(source_name, "site_a")) {
    local_columns <- list()
    columns <- list()
  }
  authorization <- list(
    version = "dsvert-formal-glm-registered-phase18-authorization-v1",
    phase = "registered_pre_execution_materialization_authorized",
    purpose = "formal_glm_registered_source_bound_phase18_materialization_v1",
    authorization_sha256 = hashes[["authorization"]],
    source_contract_sha256 = hashes[["contract"]],
    logical_snapshot_sha256 = hashes[["logical"]],
    local_source = list(
      signer_peer_name = source_name, cohort_id = "glm-cohort",
      source_binding_id = "binding-a", dataset_id = "glm-cohort",
      dataset_version = "v1"),
    local_peer_identity = list(
      peer_name = source_name, identity_pk = .formal_glm_registered_source_b64url(
        .formal_glm_registered_source_b64(pins_raw[[source_name]]))),
    local_columns = local_columns,
    geometry = list(
      total_capacity = 4L, block_capacity = 2L, total_blocks = 2L,
      coordinate_count = length(terms) + 3L,
      coordinate_owners = rep("site_a", length(terms) + 3L),
      ring_bits = 128L, container_bits = 128L, record_bytes = 16L),
    science = list(
      family = family, adjacency = "add_remove",
      coefficient_order = vapply(terms, `[[`, character(1L), "coefficient"),
      term_map = terms,
      fraction_bits = 8L, missingness = "complete_tuple_zero_weight",
      patient_collapse = "one_aligned_record_duplicates_zero_weight_v1",
      input_layout = "weight_x_outcome_offset_v1",
      input_sharing = "additive_mod_2k_by_coordinate_owner_v1"),
    private_carrier_requirement =
      "rock_local_nonserialized_materializer_inputs_required_v1",
    openings_performed = 0L, production_ready = FALSE)
  list(
    peers = peers, pins = pins, pins_raw = pins_raw,
    source_contract_json = "{\"contract\":\"registered\"}",
    authorization = authorization, source = source,
    spec = list(
      source_name = source_name,
      source_contract_sha256 = hashes[["contract"]],
      authorization_sha256 = hashes[["authorization"]],
      logical_snapshot_sha256 = hashes[["logical"]],
      pins = as.list(pins), dataset = binding$descriptor,
      data_name = "glm_local", patient_column = "patient_id",
      columns = columns))
}

test_that("registered formal GLM source opens only its configured PSI snapshot", {
  fixture <- .formal_glm_registered_source_fixture()
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      expect_identical(command, "formal-glm-phase18-source-project")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      list(
        version = "dsvert-formal-glm-phase18-source-project-response-v1",
        authorization_json = jsonlite::toJSON(
          fixture$authorization, auto_unbox = TRUE, null = "null",
          pretty = FALSE),
        authorization_sha256 = fixture$authorization$authorization_sha256)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))

  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  expect_true(is.environment(context))
  expect_false(is.list(context))
  expect_identical(context$source_name, "site_a")
  expect_identical(context$rows$outcome, c(0, 1, 1, 0))
  expect_false(any(grepl("key|secret|path|result|opening", ls(context),
                         ignore.case = TRUE)))
  first <- .dsvert_formal_glm_registered_source_block(context, 0L)
  expect_identical(first$values, c(
    "256", "256", "0", "0",
    "256", "256", "256", "0"))
  expect_identical(first$validity, c(TRUE, TRUE))
  expect_identical(first$block_index, 0L)
  expect_identical(first$global_slot_offset, 0L)
  expect_length(jsonlite::base64_dec(first$private_consensus), 32L)
  second <- .dsvert_formal_glm_registered_source_block(context, 1L)
  expect_identical(second$values, c(
    "256", "256", "256", "0",
    "256", "256", "0", "0"))
  expect_identical(second$validity, c(TRUE, TRUE))
  expect_error(.dsvert_formal_glm_registered_source_block(context, 2L),
               class = "dsvert_formal_glm_registered_source_error")

  changed <- fixture$spec
  changed$authorization_sha256 <- strrep("0", 64L)
  withr::local_options(list(
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(changed), "site_a")))
  expect_error(.dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source),
    class = "dsvert_formal_glm_registered_source_error")

  reordered <- new.env(parent = emptyenv())
  value <- get("glm_local", envir = fixture$source)
  assign("glm_local", value[rev(seq_len(nrow(value))), , drop = FALSE],
         envir = reordered)
  lockBinding("glm_local", reordered)
  withr::local_options(list(
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  expect_error(.dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, reordered),
    class = "dsvert_formal_glm_registered_source_error")
})

test_that("registered formal GLM source materializes Poisson blocks at K2 K3 K5", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .formal_glm_registered_source_fixture(k, "poisson")
    testthat::local_mocked_bindings(
      .dsvert_require_configured_local_peer_name = function() "site_a",
      .get_identity_keypair = function(...) list(
        identity_pk = fixture$pins[["site_a"]],
        identity_sk = .formal_glm_registered_source_b64(raw(64L))),
      .callMpcTool = function(command, input) {
        expect_identical(command, "formal-glm-phase18-source-project")
        expect_identical(input$pins, fixture$spec$pins)
        list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null",
            pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256)
      },
      .package = "dsVert")
    withr::local_options(list(
      dsvert.peer_name = "site_a",
      dsvert.formal_glm.registered_source_specs = stats::setNames(
        list(fixture$spec), "site_a")))
    context <- .dsvert_formal_glm_registered_source_open(
      fixture$source_contract_json, fixture$source)
    expect_identical(
      .dsvert_formal_glm_registered_source_block(context, 0L)$values,
      c("256", "256", "0", "0", "256", "256", "512", "0"))
    expect_identical(
      .dsvert_formal_glm_registered_source_block(context, 1L)$values,
      c("256", "256", "768", "0", "256", "256", "1280", "0"))
  }
})

test_that("registered formal GLM witnesses materialize zero-owned K3 blocks", {
  fixture <- .formal_glm_registered_source_fixture(
    k = 3L, source_name = "witness_1")
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "witness_1",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["witness_1"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) list(
      version = "dsvert-formal-glm-phase18-source-project-response-v1",
      authorization_json = jsonlite::toJSON(
        fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
      authorization_sha256 = fixture$authorization$authorization_sha256),
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "witness_1",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "witness_1")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  block <- .dsvert_formal_glm_registered_source_block(context, 0L)
  expect_identical(block$values, rep("0", 8L))
  expect_identical(block$validity, c(TRUE, TRUE))
})

test_that("registered formal GLM source forwards only its materialized block", {
  fixture <- .formal_glm_registered_source_fixture(predictors = TRUE)
  tickets <- list(list(ticket = "garbler"), list(ticket = "evaluator"))
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$version,
                       "dsvert-formal-glm-registered-phase18-source-command-v1")
      expect_identical(input$action, "produce")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      expect_identical(input$recipient_tickets, tickets)
      expect_identical(input$block_index, 0L)
      expect_identical(input$values, c(
        "256", "256", "-256", "0", "0", "0",
        "256", "256", "-128", "256", "256", "0"))
      expect_identical(input$validity, c(TRUE, TRUE))
      expect_length(jsonlite::base64_dec(input$private_consensus), 32L)
      expect_false(any(c("data", "path", "rows", "result") %in% names(input)))
      list(
        version = "dsvert-formal-glm-registered-phase18-source-command-v1",
        source_receipt = list(version = "receipt"),
        pair_json = "{\"encrypted\":true}", replayed = FALSE)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  produced <- .dsvert_formal_glm_registered_source_produce_block(
    context, tickets, 0L)
  expect_identical(produced, list(
    source_receipt = list(version = "receipt"),
    pair_json = "{\"encrypted\":true}", replayed = FALSE))
  expect_error(.dsvert_formal_glm_registered_source_produce_block(
    context, list(tickets[[1L]]), 0L),
    class = "dsvert_formal_glm_registered_source_error")
})

test_that("registered formal GLM source reads only a bounded opaque pair chunk", {
  fixture <- .formal_glm_registered_source_fixture(predictors = TRUE)
  tickets <- list(list(ticket = "garbler"), list(ticket = "evaluator"))
  chunk <- charToRaw("opaque-encrypted-pair")
  encoded_chunk <- gsub("[\\r\\n]", "", jsonlite::base64_enc(chunk))
  chunk_digest <- paste(rep("b", 64L), collapse = "")
  pair_digest <- paste(rep("a", 64L), collapse = "")
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$action, "chunk")
      expect_identical(input$recipient_tickets, tickets)
      expect_identical(input$block_index, 0L)
      expect_identical(input$chunk_offset, 0L)
      expect_false(any(c(
        "values", "validity", "private_consensus", "pair_json", "data", "path",
        "rows", "result") %in% names(input)))
      list(
        version = "dsvert-formal-glm-registered-phase18-source-command-v1",
        chunk_receipt = list(
          version = "dsvert-formal-glm-registered-phase18-source-outbox-receipt-v3",
          purpose = "formal_glm_owner_local_bounded_signed_pair_chunk_v3",
          handle = "handle", artifact_id = pair_digest,
          source_contract_sha256 = pair_digest, authorization_sha256 = pair_digest,
          source = "site_a", block_index = 0L, pair_sha256 = pair_digest,
          pair_bytes = length(chunk), offset = 0L, chunk_sha256 = chunk_digest,
          chunk_bytes = length(chunk), complete = TRUE, production_ready = FALSE),
        pair_chunk_base64 = encoded_chunk, replayed = FALSE)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  received <- .dsvert_formal_glm_registered_source_read_block_chunk(
    context, tickets, 0, 0)
  expect_identical(received$pair_chunk, chunk)
  expect_false(received$replayed)
  expect_error(.dsvert_formal_glm_registered_source_read_block_chunk(
    context, tickets, 0.5, 0), class = "dsvert_formal_glm_registered_source_error")
  expect_error(.dsvert_formal_glm_registered_source_read_block_chunk(
    context, tickets, 0, -1), class = "dsvert_formal_glm_registered_source_error")
})

test_that("registered formal GLM source imports only an encrypted pair", {
  fixture <- .formal_glm_registered_source_fixture(predictors = TRUE)
  tickets <- list(list(ticket = "garbler"), list(ticket = "evaluator"))
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      calls <<- calls + 1L
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$version,
                       "dsvert-formal-glm-registered-phase18-source-command-v1")
      expect_identical(input$action, "import")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      expect_identical(input$recipient_tickets, tickets)
      expect_identical(input$pair_json, "{\"encrypted\":true}")
      expect_false(any(c(
        "authorization_json", "values", "validity", "private_consensus",
        "data", "path", "rows", "result") %in% names(input)))
      list(
        version = "dsvert-formal-glm-registered-phase18-source-command-v1",
        pending_receipt = list(version = "pending-receipt"), replayed = TRUE)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  imported <- .dsvert_formal_glm_registered_source_import_pair(
    context, tickets, "{\"encrypted\":true}")
  expect_identical(imported, list(
    pending_receipt = list(version = "pending-receipt"), replayed = TRUE))
  expect_identical(calls, 1L)
  expect_error(.dsvert_formal_glm_registered_source_import_pair(
    context, list(tickets[[1L]]), "{\"encrypted\":true}"),
    class = "dsvert_formal_glm_registered_source_error")
  expect_error(.dsvert_formal_glm_registered_source_import_pair(
    context, tickets, ""),
    class = "dsvert_formal_glm_registered_source_error")
  expect_identical(calls, 1L)
})

test_that("registered formal GLM source issues and persists its closed ticket set", {
  fixture <- .formal_glm_registered_source_fixture()
  issued <- list(version = "ticket", recipient = "site_a")
  tickets <- list(issued, list(version = "ticket", recipient = "site_b"))
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$version,
                       "dsvert-formal-glm-registered-phase18-source-command-v1")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      expect_false(any(c(
        "authorization_json", "values", "validity", "private_consensus",
        "data", "path", "rows", "result") %in% names(input)))
      if (identical(input$action, "ticket")) {
        expect_false("recipient_tickets" %in% names(input))
        return(list(
          version = "dsvert-formal-glm-registered-phase18-source-command-v1",
          ticket = issued, replayed = FALSE))
      }
      expect_identical(input$action, "ticket_set")
      expect_identical(input$recipient_tickets, tickets)
      list(
        version = "dsvert-formal-glm-registered-phase18-source-command-v1",
        ticket_receipts = list(list(version = "receipt-a"),
                               list(version = "receipt-b")),
        replayed = TRUE)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  expect_identical(
    .dsvert_formal_glm_registered_source_issue_ticket(context),
    list(ticket = issued, replayed = FALSE))
  expect_identical(
    .dsvert_formal_glm_registered_source_persist_ticket_set(context, tickets),
    list(ticket_receipts = list(list(version = "receipt-a"),
                                list(version = "receipt-b")), replayed = TRUE))
  expect_error(.dsvert_formal_glm_registered_source_persist_ticket_set(
    context, list(issued)), class = "dsvert_formal_glm_registered_source_error")
})

test_that("registered formal GLM source seals only public local evidence", {
  fixture <- .formal_glm_registered_source_fixture()
  tickets <- list(list(ticket = "garbler"), list(ticket = "evaluator"))
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      calls <<- calls + 1L
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$version,
                       "dsvert-formal-glm-registered-phase18-source-command-v1")
      expect_identical(input$action, "local_receipt")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      expect_identical(input$recipient_tickets, tickets)
      expect_true(is.character(input$authorization_json))
      expect_false(any(c(
        "values", "validity", "private_consensus", "pair_json", "data",
        "path", "rows", "result") %in% names(input)))
      list(
        version = "dsvert-formal-glm-registered-phase18-source-command-v1",
        local_receipt_json = "{\"signed\":true}", replayed = TRUE)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  sealed <- .dsvert_formal_glm_registered_source_seal_local_receipt(
    context, tickets)
  expect_identical(sealed, list(
    local_receipt_json = "{\"signed\":true}", replayed = TRUE))
  expect_identical(calls, 1L)
  expect_error(.dsvert_formal_glm_registered_source_seal_local_receipt(
    context, list(tickets[[1L]])),
    class = "dsvert_formal_glm_registered_source_error")
  expect_identical(calls, 1L)
})

test_that("registered formal GLM source assembles only signed public receipts", {
  fixture <- .formal_glm_registered_source_fixture()
  receipt <- "{\"signed\":true}"
  calls <- character()
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$version,
                       "dsvert-formal-glm-registered-phase18-source-command-v1")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      expect_false(any(c(
        "authorization_json", "recipient_tickets", "block_index", "values",
        "validity", "private_consensus", "pair_json", "data", "path", "rows",
        "result") %in% names(input)))
      calls <<- c(calls, input$action)
      if (identical(input$action, "receipt_commit")) {
        expect_identical(input$local_receipt_json, receipt)
        return(list(
          version = "dsvert-formal-glm-registered-phase18-source-command-v1",
          local_receipt_json = receipt, replayed = FALSE))
      }
      expect_identical(input$action, "receipt_set")
      expect_false("local_receipt_json" %in% names(input))
      list(
        version = "dsvert-formal-glm-registered-phase18-source-command-v1",
        receipt_set_json = "{\"sealed\":true}", replayed = TRUE)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  expect_identical(
    .dsvert_formal_glm_registered_source_commit_local_receipt(context, receipt),
    list(local_receipt_json = receipt, replayed = FALSE))
  expect_identical(
    .dsvert_formal_glm_registered_source_seal_receipt_set(context),
    list(receipt_set_json = "{\"sealed\":true}", replayed = TRUE))
  expect_identical(calls, c("receipt_commit", "receipt_set"))
  expect_error(.dsvert_formal_glm_registered_source_commit_local_receipt(
    context, ""), class = "dsvert_formal_glm_registered_source_error")
  expect_identical(calls, c("receipt_commit", "receipt_set"))
})

test_that("registered formal GLM source commits only the persisted binding", {
  fixture <- .formal_glm_registered_source_fixture()
  tickets <- list(list(ticket = "garbler"), list(ticket = "evaluator"))
  host_receipt <- list(
    version = "dsvert-formal-glm-registered-phase20-job-host-provision-v1",
    peer = "site_a", artifact_id = strrep("a", 64L),
    receipt_set_sha256 = strrep("b", 64L), config_sha256 = strrep("c", 64L),
    replayed = TRUE, production_ready = FALSE)
  calls <- character()
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      calls <<- c(calls, input$action)
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$version,
                       "dsvert-formal-glm-registered-phase18-source-command-v1")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      expect_false(any(c(
        "authorization_json", "block_index", "values", "validity",
        "private_consensus", "pair_json", "local_receipt_json", "data", "path",
        "rows", "result") %in% names(input)))
      if (identical(input$action, "binding")) {
        expect_identical(input$recipient_tickets, tickets)
        return(list(
          version = "dsvert-formal-glm-registered-phase18-source-command-v1",
          binding_record_json = "{\"binding\":true}", replayed = TRUE))
      }
      expect_identical(input$action, "host_provision")
      list(version = "dsvert-formal-glm-registered-phase18-source-command-v1",
           job_host_receipt = host_receipt, replayed = TRUE)
    },
    .dsvert_formal_glm_registered_source_job_host_healthy = function(...) TRUE,
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  expect_identical(
    .dsvert_formal_glm_registered_source_commit_binding(context, tickets),
    list(binding_record_json = "{\"binding\":true}", replayed = TRUE))
  expect_identical(calls, c("binding", "host_provision"))
  expect_error(.dsvert_formal_glm_registered_source_commit_binding(
    context, list(tickets[[1L]])), class = "dsvert_formal_glm_registered_source_error")
  expect_identical(calls, c("binding", "host_provision"))
})

test_that("registered formal GLM source provisions no worker input or result", {
  fixture <- .formal_glm_registered_source_fixture()
  receipt <- list(
    version = "dsvert-formal-glm-registered-phase20-job-host-provision-v1",
    peer = "site_a", artifact_id = strrep("a", 64L),
    receipt_set_sha256 = strrep("b", 64L), config_sha256 = strrep("c", 64L),
    replayed = TRUE, production_ready = FALSE)
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(command, input) {
      if (identical(command, "formal-glm-phase18-source-project")) {
        return(list(
          version = "dsvert-formal-glm-phase18-source-project-response-v1",
          authorization_json = jsonlite::toJSON(
            fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
          authorization_sha256 = fixture$authorization$authorization_sha256))
      }
      calls <<- calls + 1L
      expect_identical(command, "formal-glm-registered-phase18-source")
      expect_identical(input$version,
                       "dsvert-formal-glm-registered-phase18-source-command-v1")
      expect_identical(input$action, "host_provision")
      expect_identical(input$source_contract_json, fixture$source_contract_json)
      expect_identical(input$pins, fixture$spec$pins)
      expect_identical(input$local_peer_name, "site_a")
      expect_false(any(c(
        "authorization_json", "recipient_tickets", "block_index", "values",
        "validity", "private_consensus", "pair_json", "local_receipt_json",
        "data", "path", "rows", "result") %in% names(input)))
      list(
        version = "dsvert-formal-glm-registered-phase18-source-command-v1",
        job_host_receipt = receipt, replayed = TRUE)
    },
    .dsvert_formal_glm_registered_source_job_host_healthy = function(...) TRUE,
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  expect_identical(
    .dsvert_formal_glm_registered_source_provision_job_host(context),
    list(job_host_receipt = receipt, replayed = TRUE))
  expect_identical(calls, 1L)
})

test_that("registered formal GLM source controls only a provisioned live host", {
  receipt <- list(
    version = "dsvert-formal-glm-registered-phase20-job-host-provision-v1",
    peer = "site_a", artifact_id = strrep("a", 64L),
    receipt_set_sha256 = strrep("b", 64L), config_sha256 = strrep("c", 64L),
    replayed = TRUE, production_ready = FALSE)
  command <- NULL
  testthat::local_mocked_bindings(
    .callMpcTool = function(name, input) {
      command <<- list(name = name, input = input)
      list(version = "dsvert-formal-glm-registered-phase20-job-control-v1",
           payload = structure(list(), names = character()))
    },
    .package = "dsVert")
  expect_true(.dsvert_formal_glm_registered_source_job_host_healthy(receipt))
  expect_identical(command$name, "formal-glm-job-control")
  expect_identical(command$input, list(
    version = "dsvert-formal-glm-registered-phase20-job-control-v1",
    peer = "site_a", artifact_id = strrep("a", 64L),
    receipt_set_sha256 = strrep("b", 64L), action = "health",
    payload = structure(list(), names = character())))
  expect_error(.dsvert_formal_glm_registered_source_job_host_healthy(
    utils::modifyList(receipt, list(config_sha256 = "not-a-digest"))),
    class = "dsvert_formal_glm_registered_source_error")
})

test_that("registered formal GLM source starts a host only after failed health", {
  receipt <- list(
    version = "dsvert-formal-glm-registered-phase20-job-host-provision-v1",
    peer = "site_a", artifact_id = strrep("a", 64L),
    receipt_set_sha256 = strrep("b", 64L), config_sha256 = strrep("c", 64L),
    replayed = FALSE, production_ready = FALSE)
  checks <- 0L
  launches <- 0L
  output <- .dsvert_formal_glm_registered_source_ensure_job_host(
    list(job_host_receipt = receipt, replayed = FALSE),
    .healthy = function(value) {
      expect_identical(value, receipt)
      checks <<- checks + 1L
      checks >= 2L
    },
    .launch = function(value) {
      expect_identical(value, receipt)
      launches <<- launches + 1L
      TRUE
    })
  expect_identical(output, list(job_host_receipt = receipt, replayed = FALSE))
  expect_identical(checks, 2L)
  expect_identical(launches, 1L)
  expect_error(.dsvert_formal_glm_registered_source_ensure_job_host(
    list(job_host_receipt = receipt, replayed = FALSE),
    .healthy = function(...) FALSE, .launch = function(...) FALSE),
    class = "dsvert_formal_glm_registered_source_error")
  expect_error(.dsvert_formal_glm_registered_source_ensure_job_host(
    list(job_host_receipt = receipt, replayed = TRUE),
    .healthy = function(...) TRUE),
    class = "dsvert_formal_glm_registered_source_error")
})

test_that("registered formal GLM source clamps numeric terms and expands factors", {
  fixture <- .formal_glm_registered_source_fixture(
    family = "binomial", predictors = TRUE)
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_a"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(...) list(
      version = "dsvert-formal-glm-phase18-source-project-response-v1",
      authorization_json = jsonlite::toJSON(
        fixture$authorization, auto_unbox = TRUE, null = "null", pretty = FALSE),
      authorization_sha256 = fixture$authorization$authorization_sha256),
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  context <- .dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source)
  expect_identical(
    .dsvert_formal_glm_registered_source_block(context, 0L)$values,
    c("256", "256", "-256", "0", "0", "0",
      "256", "256", "-128", "256", "256", "0"))
  expect_identical(
    .dsvert_formal_glm_registered_source_block(context, 1L)$values,
    c("256", "256", "128", "256", "256", "0",
      "256", "256", "256", "0", "0", "0"))
})

test_that("registered formal GLM source rejects an unpinned identity before projection", {
  fixture <- .formal_glm_registered_source_fixture()
  testthat::local_mocked_bindings(
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function(...) list(
      identity_pk = fixture$pins[["site_b"]],
      identity_sk = .formal_glm_registered_source_b64(raw(64L))),
    .callMpcTool = function(...) fail("source projection must not run"),
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = "site_a",
    dsvert.formal_glm.registered_source_specs = stats::setNames(
      list(fixture$spec), "site_a")))
  expect_error(.dsvert_formal_glm_registered_source_open(
    fixture$source_contract_json, fixture$source),
    class = "dsvert_formal_glm_registered_source_error")
})
