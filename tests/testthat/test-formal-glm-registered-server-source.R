.formal_glm_registered_source_b64 <- function(value) {
  gsub("[\r\n]", "", jsonlite::base64_enc(value))
}

.formal_glm_registered_source_b64url <- function(value) {
  sub("=+$", "", chartr("+/", "-_", value), perl = TRUE)
}

.formal_glm_registered_source_fixture <- function() {
  peers <- c("site_a", "site_b")
  pins_raw <- stats::setNames(lapply(seq_along(peers), function(index) {
    as.raw((seq_len(32L) + index * 41L) %% 256L)
  }), peers)
  pins <- vapply(pins_raw, .formal_glm_registered_source_b64, character(1L))
  rows <- data.frame(
    patient_id = sprintf("patient-%02d", seq_len(4L)),
    outcome = c(0, 1, 1, 0), stringsAsFactors = FALSE)
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
  authorization <- list(
    version = "dsvert-formal-glm-registered-phase18-authorization-v1",
    phase = "registered_pre_execution_materialization_authorized",
    purpose = "formal_glm_registered_source_bound_phase18_materialization_v1",
    authorization_sha256 = hashes[["authorization"]],
    source_contract_sha256 = hashes[["contract"]],
    logical_snapshot_sha256 = hashes[["logical"]],
    local_source = list(
      signer_peer_name = "site_a", cohort_id = "glm-cohort",
      source_binding_id = "binding-a", dataset_id = "glm-cohort",
      dataset_version = "v1"),
    local_peer_identity = list(
      peer_name = "site_a", identity_pk = .formal_glm_registered_source_b64url(
        .formal_glm_registered_source_b64(pins_raw[["site_a"]]))),
    local_columns = list(list(
      owner = "site_a", dataset_id = "glm-cohort", dataset_version = "v1",
      column = "outcome", role = "response", kind = "binary")),
    geometry = list(
      total_capacity = 4L, block_capacity = 2L, total_blocks = 2L,
      coordinate_count = 4L,
      coordinate_owners = c("site_a", "site_a", "site_a", "site_a"),
      ring_bits = 128L, container_bits = 128L, record_bytes = 16L),
    science = list(
      family = "binomial", adjacency = "add_remove",
      coefficient_order = "(Intercept)", term_map = list(),
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
      source_name = "site_a",
      source_contract_sha256 = hashes[["contract"]],
      authorization_sha256 = hashes[["authorization"]],
      logical_snapshot_sha256 = hashes[["logical"]],
      pins = as.list(pins), dataset = binding$descriptor,
      data_name = "glm_local", patient_column = "patient_id",
      columns = list(outcome = "outcome")))
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
