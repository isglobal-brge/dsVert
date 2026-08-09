.formal_frontdoor_b64url <- function(value) {
  sub("=+$", "", chartr(
    "+/", "-_", gsub("[\r\n]", "", jsonlite::base64_enc(value))),
    perl = TRUE)
}

.formal_frontdoor_hash <- function(value) {
  digest::digest(value, algo = "sha256", serialize = FALSE)
}

.formal_frontdoor_fixture <- function(k = 2L, family = "binomial",
                                      peer_index = 1L) {
  peers <- paste0("peer_", letters[seq_len(k)])
  pins <- vapply(seq_along(peers), function(index) {
    .formal_frontdoor_b64url(as.raw(
      (seq_len(32L) + index * 31L) %% 256L))
  }, character(1L))
  names(pins) <- peers
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)),
    algo = "sha256", serialize = FALSE)
  policy <- list(
    domain = "formal-glm-study", cohort_id = "formal-glm-cohort",
    peer_name = peers[[peer_index]], peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = as.integer(k),
    designated_noise_peers = peers[1:2],
    global_total_epsilon = 1, global_total_delta = 1e-6,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 8L, max_records_per_unit = 1L,
    overflow_policy = "reject_snapshot",
    noise_root = list(epoch = 1, key_id = "formal-glm-test-root"),
    ledger_path = tempfile("formal-glm-frontdoor-ledger-"))
  formula <- "y ~ x + z"
  formula_hash <- .formal_frontdoor_hash(paste0(
    "dsVert/formal-glm/frontdoor-formula/v1|y ~ 1 + x + z"))
  spec <- list(
    version = .DSVERT_FORMAL_GLM_FRONTDOOR_SPEC_VERSION,
    analysis_id = "primary_model", data_name = "study",
    family = family, formula = formula,
    schema_sha256 = .formal_frontdoor_hash("schema"),
    artifact_sha256 = .formal_frontdoor_hash("artifact"),
    phase15_plan_sha256 = .formal_frontdoor_hash("phase15"),
    capsule_id = .formal_frontdoor_hash("capsule"),
    logical_snapshot_sha256 = .formal_frontdoor_hash("snapshot"),
    release_binding_domain = .DSVERT_FORMAL_GLM_FRONTDOOR_RELEASE_DOMAIN,
    execution_path = .DSVERT_FORMAL_GLM_FRONTDOOR_EXECUTION_PATH,
    registry_generation = 1L)
  list(
    peers = peers, pins = pins, policy = policy,
    specs = list(primary_model = spec),
    assets = list(primary_model = list(
      version = .DSVERT_FORMAL_GLM_FRONTDOOR_ASSET_VERSION,
      analysis_id = "primary_model", manifest_json = "{}",
      artifact_json = "{}", plan_json = "{}", plan_approvals = list())),
    formula_hash = formula_hash,
    signer = function(message, peer_name, pin) strrep("A", 86L))
}

.formal_frontdoor_condition <- function(expr) {
  tryCatch(expr, error = function(error) error)
}

test_that("formal GLM candidate binds server policy for K=2,3,4,5", {
  for (family in c("binomial", "poisson")) {
    for (k in 2:5) {
      fixture <- .formal_frontdoor_fixture(k, family)
      receipt <- .dsvert_formal_glm_frontdoor_prepare_candidate(
        analysis_id = "primary_model", data_name = "study",
        family = family, formula_sha256 = fixture$formula_hash,
        .policy = fixture$policy, .specs = fixture$specs,
        .signer = fixture$signer)

      expect_identical(receipt$family, family)
      expect_identical(receipt$analysis_id, "primary_model")
      expect_identical(receipt$pinset_sha256,
                       fixture$policy$peer_pinset_sha256)
      expect_equal(as.numeric(receipt$custodian_count), k)
      expect_identical(
        unlist(receipt$designated_compute_peers, use.names = FALSE),
        fixture$peers[1:2])
      expect_true(receipt$server_owned_analysis)
      expect_false(receipt$analyst_epsilon_accepted)
      expect_false(receipt$analyst_bounds_accepted)
      expect_false(receipt$analyst_seed_accepted)
      expect_false(receipt$analyst_roles_accepted)
      expect_false(receipt$operation_limit)
      expect_false(receipt$request_limit)
      expect_false(receipt$history_can_deny_operation)
      expect_false(receipt$phase19_worker_started)
      expect_false(receipt$relay_started)
      expect_false(receipt$opening_authorized)
      expect_identical(as.integer(receipt$openings_performed), 0L)
      expect_false(receipt$registered_remote_method)
      expect_false(receipt$production_ready)
      expect_identical(receipt$signature, strrep("A", 86L))
    }
  }
})

test_that("formal GLM candidate is deterministic and purpose-bound", {
  fixture <- .formal_frontdoor_fixture(4L, "poisson", peer_index = 3L)
  prepare <- function(specs = fixture$specs) {
    .dsvert_formal_glm_frontdoor_prepare_candidate(
      "primary_model", "study", "poisson", fixture$formula_hash,
      .policy = fixture$policy, .specs = specs,
      .signer = fixture$signer)
  }
  first <- prepare()
  retry <- prepare()
  expect_identical(first, retry)

  rotated <- fixture$specs
  rotated$primary_model$registry_generation <- 2L
  second_generation <- prepare(rotated)
  expect_false(identical(first$purpose, second_generation$purpose))
  expect_false(identical(first$registry_binding_sha256,
                         second_generation$registry_binding_sha256))
})

test_that("unknown analysis and selector mismatch are indistinguishable", {
  fixture <- .formal_frontdoor_fixture()
  run <- function(id = "primary_model", data = "study",
                  family = "binomial", hash = fixture$formula_hash) {
    .formal_frontdoor_condition(
      .dsvert_formal_glm_frontdoor_prepare_candidate(
        id, data, family, hash, .policy = fixture$policy,
        .specs = fixture$specs, .signer = fixture$signer))
  }
  unknown <- run(id = "unknown_model")
  wrong_data <- run(data = "other_study")
  wrong_family <- run(family = "poisson")
  wrong_formula <- run(hash = strrep("0", 64L))

  for (condition in list(
      unknown, wrong_data, wrong_family, wrong_formula)) {
    expect_s3_class(condition, "dsvert_formal_glm_frontdoor_error")
    expect_identical(condition$code, "formal_glm_analysis_unavailable")
    expect_identical(condition$message,
                     "The requested formal GLM analysis is unavailable.")
    expect_identical(condition$openings_performed, 0L)
  }
})

test_that("registry and pinset tampering fail closed", {
  fixture <- .formal_frontdoor_fixture(3L)
  prepare <- function(policy = fixture$policy, specs = fixture$specs) {
    .dsvert_formal_glm_frontdoor_prepare_candidate(
      "primary_model", "study", "binomial", fixture$formula_hash,
      .policy = policy, .specs = specs, .signer = fixture$signer)
  }

  bad_policy <- fixture$policy
  bad_policy$peer_pinset_sha256 <- strrep("0", 64L)
  expect_error(prepare(policy = bad_policy),
               class = "dsvert_formal_glm_frontdoor_error")

  bad_spec <- fixture$specs
  bad_spec$primary_model$epsilon <- 0.1
  expect_error(prepare(specs = bad_spec),
               class = "dsvert_formal_glm_frontdoor_error")

  bad_spec <- fixture$specs
  bad_spec$primary_model$artifact_sha256 <- strrep("z", 64L)
  expect_error(prepare(specs = bad_spec),
               class = "dsvert_formal_glm_frontdoor_error")

  bad_spec <- fixture$specs
  bad_spec$primary_model$execution_path <- "legacy_glm"
  expect_error(prepare(specs = bad_spec),
               class = "dsvert_formal_glm_frontdoor_error")
})

test_that("candidate exposes no remote method or analyst privacy knobs", {
  expect_false(endsWith(
    ".dsvert_formal_glm_frontdoor_prepare_candidate", "DS"))
  argument_names <- names(formals(
    .dsvert_formal_glm_frontdoor_prepare_candidate))
  expect_identical(argument_names[1:4],
                   c("analysis_id", "data_name", "family",
                     "formula_sha256"))
  expect_false(any(c(
    "epsilon", "delta", "bounds", "seed", "ring", "precision",
    "numeric_backend", "compute_peers", "roles") %in% argument_names))
})

test_that("server registry authorizes the exact Phase-1.8 purpose for all K", {
  for (family in c("binomial", "poisson")) {
    for (k in 2:5) {
      fixture <- .formal_frontdoor_fixture(k, family)
      context <- .dsvert_formal_glm_frontdoor_policy(fixture$policy)
      normalized_spec <- .dsvert_formal_glm_frontdoor_spec(
        "primary_model", fixture$specs)
      expected_run <- .dsvert_formal_glm_frontdoor_run_id(
        normalized_spec, context)
      observed <- NULL
      authorize <- function(manifest_json, artifact_json, plan_json,
                            plan_approvals, .policy, .secret, .verifier) {
        observed <<- list(
          manifest_json = manifest_json, artifact_json = artifact_json,
          plan_json = plan_json, plan_approvals = plan_approvals,
          policy = .policy)
        structure(list(
          pre = list(
            artifact_sha256 = fixture$specs$primary_model$artifact_sha256,
            plan_sha256 = fixture$specs$primary_model$phase15_plan_sha256,
            schema_manifest_sha256 =
              fixture$specs$primary_model$schema_sha256,
            capsule_id = fixture$specs$primary_model$capsule_id,
            snapshot_sha256 =
              fixture$specs$primary_model$logical_snapshot_sha256,
            family = family, run_id = expected_run,
            pinset_sha256 = fixture$policy$peer_pinset_sha256,
            custodian_peers = as.list(fixture$peers),
            designated_compute_peers = as.list(fixture$peers[1:2]),
            custodian_count = k, openings_performed = 0L,
            production_ready = FALSE),
          artifact = list(estimand = list(formula = "y ~ 1 + x + z"))),
          class = "dsvert_formal_glm_phase18_pre_authorization")
      }
      value <- .dsvert_formal_glm_frontdoor_authorize_phase18_candidate(
        "primary_model", "study", family, fixture$formula_hash,
        .policy = fixture$policy, .specs = fixture$specs,
        .assets = fixture$assets, .authorize = authorize)

      expect_s3_class(
        value, "dsvert_formal_glm_frontdoor_phase18_authorization")
      expect_identical(value$expected_run_id, expected_run)
      expect_identical(value$analysis_id, "primary_model")
      expect_identical(value$openings_performed, 0L)
      expect_false(value$production_ready)
      expect_identical(observed$manifest_json, "{}")
      expect_identical(observed$policy, fixture$policy)
    }
  }
})

test_that("Phase-1.8 registry binding rejects purpose or asset drift", {
  fixture <- .formal_frontdoor_fixture(3L, "binomial")
  context <- .dsvert_formal_glm_frontdoor_policy(fixture$policy)
  normalized_spec <- .dsvert_formal_glm_frontdoor_spec(
    "primary_model", fixture$specs)
  expected_run <- .dsvert_formal_glm_frontdoor_run_id(
    normalized_spec, context)
  make_authorizer <- function(change = list()) {
    force(change)
    function(...) {
      pre <- list(
        artifact_sha256 = fixture$specs$primary_model$artifact_sha256,
        plan_sha256 = fixture$specs$primary_model$phase15_plan_sha256,
        schema_manifest_sha256 = fixture$specs$primary_model$schema_sha256,
        capsule_id = fixture$specs$primary_model$capsule_id,
        snapshot_sha256 =
          fixture$specs$primary_model$logical_snapshot_sha256,
        family = "binomial", run_id = expected_run,
        pinset_sha256 = fixture$policy$peer_pinset_sha256,
        custodian_peers = as.list(fixture$peers),
        designated_compute_peers = as.list(fixture$peers[1:2]),
        custodian_count = 3L, openings_performed = 0L,
        production_ready = FALSE)
      pre[names(change)] <- change
      structure(list(
        pre = pre,
        artifact = list(estimand = list(formula = "y ~ 1 + x + z"))),
        class = "dsvert_formal_glm_phase18_pre_authorization")
    }
  }
  run <- function(authorize = make_authorizer(), assets = fixture$assets) {
    .dsvert_formal_glm_frontdoor_authorize_phase18_candidate(
      "primary_model", "study", "binomial", fixture$formula_hash,
      .policy = fixture$policy, .specs = fixture$specs,
      .assets = assets, .authorize = authorize)
  }

  expect_error(run(make_authorizer(list(run_id = strrep("0", 64L)))),
               class = "dsvert_formal_glm_frontdoor_error")
  expect_error(run(make_authorizer(list(
    designated_compute_peers = as.list(rev(fixture$peers[1:2]))))),
    class = "dsvert_formal_glm_frontdoor_error")
  expect_error(run(make_authorizer(list(
    snapshot_sha256 = strrep("0", 64L)))),
    class = "dsvert_formal_glm_frontdoor_error")

  assets <- fixture$assets
  assets$primary_model$epsilon <- 1
  expect_error(run(assets = assets),
               class = "dsvert_formal_glm_frontdoor_error")
})
