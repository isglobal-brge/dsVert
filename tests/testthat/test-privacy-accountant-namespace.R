.privacy_namespace_fixture <- function(
    .local_envir = parent.frame()) {
  root <- withr::local_tempdir(
    pattern = "dsvert-privacy-accountant-namespace-",
    .local_envir = .local_envir)
  Sys.chmod(root, mode = "0700")
  seed_path <- file.path(root, "identity.seed")
  withr::local_options(list(
    dsvert.state_dir = root,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = seed_path,
    default.dsvert.identity_seed_path = NULL),
    .local_envir = .local_envir)
  .dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) as.raw(seq_len(n) + 17L),
    .allow_test_path = TRUE)
  policy <- list(
    ledger_path = file.path(root, "privacy", "ledger.sqlite"),
    peer_name = "peer_a")
  dir.create(dirname(policy$ledger_path), recursive = TRUE, mode = "0700")
  Sys.chmod(dirname(policy$ledger_path), mode = "0700")
  common <- list(
    protocol = "test-joint-dp-v1", domain = "study",
    cohort_id = "cohort", ordered_peer_pinset = list(
      peer_a = paste(rep("a", 64L), collapse = ""),
      peer_b = paste(rep("b", 64L), collapse = "")),
    epsilon_capsule = 1, delta_capsule = 1e-6,
    lifetime_max_distinct_capsules = 8)
  context <- list(
    common = common,
    consortium_id = paste0("jdpc1_", .dsvert_joint_dp_hash(common)),
    peer_name = "peer_a")
  list(root = root, seed_path = seed_path, policy = policy,
       context = context)
}

test_that("privacy-accountant receipt is identity-bound and exact", {
  fixture <- .privacy_namespace_fixture()
  expected <- .dsvert_privacy_accountant_namespace_enforce(
    fixture$policy, fixture$context, allow_virgin_bootstrap = TRUE)
  receipt_path <- .dsvert_privacy_accountant_namespace_receipt_path()
  expect_identical(
    receipt_path,
    paste0(fixture$seed_path, ".privacy-accountant-namespace-v1"))
  expect_true(file.exists(receipt_path))
  expect_identical(
    .dsvert_privacy_accountant_namespace_validate(
      receipt_path, fixture$policy, fixture$context),
    expected)
  expect_identical(
    expected$paths$vector_store,
    paste0(expected$paths$local_ledger, ".joint-dp-vector-v4.sqlite"))
  expect_identical(
    expected$paths$source_store,
    paste0(expected$paths$local_ledger, ".capsule-source-v3.sqlite"))

  rotated <- fixture$policy
  rotated$datasets <- list(replacement_snapshot = "sha256")
  rotated$capsule_workload_scope <- list(mode = "catalog_v1")
  rotated$noise_root <- list(epoch = 99, key_id = "rotated")
  before <- readBin(receipt_path, "raw", n = file.info(receipt_path)$size)
  expect_identical(
    .dsvert_privacy_accountant_namespace_enforce(
      rotated, fixture$context),
    expected)
  expect_identical(
    readBin(receipt_path, "raw", n = file.info(receipt_path)$size), before)
})

test_that("missing receipt with an existing identity fails closed", {
  fixture <- .privacy_namespace_fixture()
  testthat::local_mocked_bindings(
    .dsvert_privacy_accountant_namespace_state_is_virgin =
      function(...) stop("state was inspected", call. = FALSE),
    .package = "dsVert")
  condition <- tryCatch(
    .dsvert_privacy_accountant_namespace_enforce(
      fixture$policy, fixture$context),
    error = identity)
  expect_s3_class(
    condition, "dsvert_privacy_accountant_namespace_missing")
  expect_false(grepl("state was inspected", conditionMessage(condition),
                     fixed = TRUE))
})

test_that("receipt mismatch fails before any accountant-state read", {
  fixture <- .privacy_namespace_fixture()
  .dsvert_privacy_accountant_namespace_enforce(
    fixture$policy, fixture$context, allow_virgin_bootstrap = TRUE)
  changed <- fixture$policy
  changed$ledger_path <- file.path(fixture$root, "other", "ledger.sqlite")
  dir.create(dirname(changed$ledger_path), recursive = TRUE, mode = "0700")
  testthat::local_mocked_bindings(
    .dsvert_privacy_accountant_namespace_state_is_virgin =
      function(...) stop("state was inspected", call. = FALSE),
    .package = "dsVert")
  condition <- tryCatch(
    .dsvert_privacy_accountant_namespace_enforce(
      changed, fixture$context, allow_virgin_bootstrap = TRUE),
    error = identity)
  expect_s3_class(
    condition, "dsvert_privacy_accountant_namespace_mismatch")
  expect_false(grepl("state was inspected", conditionMessage(condition),
                     fixed = TRUE))
})

test_that("virgin bootstrap audits current v3 stores and every sidecar", {
  fixture <- .privacy_namespace_fixture()
  bases <- .dsvert_identity_dp_state_bases(fixture$policy$ledger_path)
  expect_true(any(endsWith(
    bases,
    ".joint-mpc-single-opening-v2.sqlite.capsule-registry-v3.sqlite")))
  expect_true(any(endsWith(bases, ".capsule-source-v3.sqlite")))
  blocking <- paste0(bases[endsWith(bases, ".capsule-source-v3.sqlite")],
                     ".lock")
  expect_true(file.create(blocking))
  condition <- tryCatch(
    .dsvert_privacy_accountant_namespace_enforce(
      fixture$policy, fixture$context, allow_virgin_bootstrap = TRUE),
    error = identity)
  expect_s3_class(
    condition, "dsvert_privacy_accountant_namespace_bootstrap_denied")
  unlink(blocking)
  expect_silent(.dsvert_privacy_accountant_namespace_enforce(
    fixture$policy, fixture$context, allow_virgin_bootstrap = TRUE))
})

test_that("concurrent virgin bootstrap converges on one exact receipt", {
  skip_on_os("windows")
  fixture <- .privacy_namespace_fixture()
  results <- parallel::mclapply(
    seq_len(6L), function(unused) {
      tryCatch(
        .dsvert_privacy_accountant_namespace_enforce(
          fixture$policy, fixture$context,
          allow_virgin_bootstrap = TRUE),
        error = identity)
    }, mc.cores = 6L, mc.preschedule = FALSE)
  expect_false(any(vapply(results, inherits, logical(1L), "error")))
  encoded <- vapply(
    results, .dsvert_dp_canonical_json, character(1L))
  expect_length(unique(encoded), 1L)
  expect_identical(
    .dsvert_privacy_accountant_namespace_validate(
      .dsvert_privacy_accountant_namespace_receipt_path(),
      fixture$policy, fixture$context),
    results[[1L]])
})

test_that("consortium and common policy changes are rejected", {
  fixture <- .privacy_namespace_fixture()
  .dsvert_privacy_accountant_namespace_enforce(
    fixture$policy, fixture$context, allow_virgin_bootstrap = TRUE)
  changed <- fixture$context
  changed$common$cohort_id <- "different-cohort"
  changed$consortium_id <- paste0(
    "jdpc1_", .dsvert_joint_dp_hash(changed$common))
  expect_error(
    .dsvert_privacy_accountant_namespace_enforce(
      fixture$policy, changed),
    class = "dsvert_privacy_accountant_namespace_mismatch")
})

test_that("tampered and partial namespace receipts fail typed closed", {
  for (kind in c("tampered", "partial")) {
    fixture <- .privacy_namespace_fixture(.local_envir = environment())
    .dsvert_privacy_accountant_namespace_enforce(
      fixture$policy, fixture$context, allow_virgin_bootstrap = TRUE)
    path <- .dsvert_privacy_accountant_namespace_receipt_path()
    bytes <- readBin(path, "raw", n = file.info(path)$size)
    if (identical(kind, "tampered")) {
      bytes[[max(1L, length(bytes) - 8L)]] <-
        as.raw(bitwXor(as.integer(bytes[[max(1L, length(bytes) - 8L)]]), 1L))
    } else {
      bytes <- bytes[seq_len(max(1L, length(bytes) %/% 2L))]
    }
    connection <- file(path, open = "wb")
    writeBin(bytes, connection)
    close(connection)
    Sys.chmod(path, mode = "0600")
    expect_error(
      .dsvert_privacy_accountant_namespace_enforce(
        fixture$policy, fixture$context),
      class = "dsvert_privacy_accountant_namespace_mismatch")
  }
})

test_that("linked or non-private namespace receipts fail typed closed", {
  skip_on_os("windows")
  fixture <- .privacy_namespace_fixture()
  .dsvert_privacy_accountant_namespace_enforce(
    fixture$policy, fixture$context, allow_virgin_bootstrap = TRUE)
  path <- .dsvert_privacy_accountant_namespace_receipt_path()

  Sys.chmod(path, mode = "0644")
  expect_error(
    .dsvert_privacy_accountant_namespace_enforce(
      fixture$policy, fixture$context),
    class = "dsvert_privacy_accountant_namespace_mismatch")
  Sys.chmod(path, mode = "0600")

  alias <- paste0(path, ".hardlink")
  expect_true(file.link(path, alias))
  expect_error(
    .dsvert_privacy_accountant_namespace_enforce(
      fixture$policy, fixture$context),
    class = "dsvert_privacy_accountant_namespace_mismatch")
  unlink(alias)

  target <- paste0(path, ".target")
  expect_true(file.rename(path, target))
  expect_true(file.symlink(target, path))
  expect_error(
    .dsvert_privacy_accountant_namespace_enforce(
      fixture$policy, fixture$context),
    class = "dsvert_privacy_accountant_namespace_mismatch")
})

test_that("normal policy build never infers namespace bootstrap", {
  root <- withr::local_tempdir(
    pattern = "dsvert-privacy-accountant-policy-order-")
  ledger_dir <- file.path(root, "privacy")
  dir.create(ledger_dir, mode = "0700")
  seed_path <- file.path(root, "identity.seed")
  pins <- c(
    peer_a = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(11L, 32L)))),
    peer_b = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(29L, 32L)))))
  pins <- vapply(
    pins, .dsvert_relay_normalize_identity_pk, character(1L))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)),
    algo = "sha256", serialize = FALSE)
  withr::local_options(list(
    dsvert.identity_seed_path = seed_path,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 1e-6,
    dsvert.dp.lifetime_max_distinct_capsules = 8,
    dsvert.dp.domain = "namespace-order-study",
    dsvert.dp.cohort_id = "namespace-order-cohort",
    dsvert.dp.ledger_path = file.path(ledger_dir, "ledger.sqlite"),
    dsvert.dp.adjacency = "add_remove_patient",
    dsvert.dp.patient_column = "patient_id",
    dsvert.dp.unit_capacity = 100L,
    dsvert.dp.max_records_per_unit = 2L,
    dsvert.dp.overflow_policy = "reject_snapshot",
    dsvert.dp.contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    dsvert.dp.numeric_grid_bits = 16L,
    dsvert.dp.datasets = list(
      protected = list(id = "protected", version = "v1"))))
  control <- new.env(parent = emptyenv())
  control$events <- character()
  control$allow <- logical()
  control$fail <- FALSE
  control$alignment_calls <- 0L
  control$noise_calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_identity_test_mode = function() FALSE,
    .dsvert_enforce_release_mode = function(...) invisible(TRUE),
    .dsvert_dp_peer_pinset = function() list(
      peer_name = "peer_a", pinset = pins, sha256 = pin_hash),
    .dsvert_privacy_accountant_namespace_enforce = function(
        policy, context, allow_virgin_bootstrap = FALSE) {
      control$events <- c(control$events, "namespace")
      control$allow <- c(control$allow, allow_virgin_bootstrap)
      if (isTRUE(control$fail)) {
        stop("namespace blocker", call. = FALSE)
      }
      invisible(list(
        privacy_accountant_namespace_id = context$consortium_id))
    },
    .dsvert_dp_alignment_registry_resolve_templates = function(...) {
      control$alignment_calls <- control$alignment_calls + 1L
      stop("alignment registry was read", call. = FALSE)
    },
    .dsvert_dp_noise_root = function(...) {
      control$noise_calls <- control$noise_calls + 1L
      control$events <- c(control$events, "noise")
      list(epoch = 1, key_id = "test-key")
    },
    .package = "dsVert")
  build <- function(...) .dsvert_dp_policy_build(
    .test_only_skip_snapshot_binding = TRUE,
    .test_only_skip_alignment_binding = TRUE,
    .test_only_allow_nonprivate_ledger = TRUE, ...)

  expect_silent(build())
  expect_identical(control$events, c("namespace", "noise"))
  expect_identical(control$allow, FALSE)

  expect_true(file.create(seed_path))
  control$events <- character()
  control$allow <- logical()
  expect_silent(build())
  expect_identical(control$events, c("namespace", "noise"))
  expect_identical(control$allow, FALSE)

  control$events <- character()
  control$allow <- logical()
  expect_silent(build(.privacy_accountant_bootstrap_empty = TRUE))
  expect_identical(control$allow, TRUE)

  control$events <- character()
  control$fail <- TRUE
  control$alignment_calls <- 0L
  control$noise_calls <- 0L
  expect_error(
    .dsvert_dp_policy_build(
      .test_only_allow_nonprivate_ledger = TRUE),
    "namespace blocker", fixed = TRUE)
  expect_identical(control$events, "namespace")
  expect_identical(control$alignment_calls, 0L)
  expect_identical(control$noise_calls, 0L)
})

test_that("local administrative bootstrap requires an explicit affirmation", {
  control <- new.env(parent = emptyenv())
  control$calls <- list()
  testthat::local_mocked_bindings(
    .dsvert_dp_policy_build = function(...) {
      control$calls <- c(control$calls, list(list(...)))
      list(
        privacy_accountant_namespace_id = paste0(
          "jdpc1_", paste(rep("c", 64L), collapse = "")),
        receipt_path =
          "/private/admin/identity.seed.privacy-accountant-namespace-v1")
    },
    .package = "dsVert")

  expect_error(
    dsvertBootstrapPrivacyAccountantNamespace(),
    "confirm_no_other_history must be exactly TRUE", fixed = TRUE)
  expect_length(control$calls, 0L)
  result <- dsvertBootstrapPrivacyAccountantNamespace(
    confirm_no_other_history = TRUE)
  expect_length(control$calls, 1L)
  expect_identical(
    control$calls[[1L]]$.privacy_accountant_bootstrap_empty, TRUE)
  expect_match(result$privacy_accountant_namespace_id, "^jdpc1_")
  expect_identical(
    result$receipt_path,
    "/private/admin/identity.seed.privacy-accountant-namespace-v1")

  expect_true(
    "dsvertBootstrapPrivacyAccountantNamespace" %in%
      getNamespaceExports("dsVert"))
  registry <- .dsvert_remote_function_registry(refresh = TRUE)
  expect_false(
    "dsvertBootstrapPrivacyAccountantNamespace" %in% names(registry))
  description <- read.dcf(testthat::test_path("..", "..", "DESCRIPTION"))
  registered <- paste(description[1L, c("AggregateMethods", "AssignMethods")],
                      collapse = ",")
  expect_false(grepl(
    "dsvertBootstrapPrivacyAccountantNamespace", registered, fixed = TRUE))
})

test_that("real administrative bootstrap returns before accountant access", {
  skip_on_os("windows")
  root <- withr::local_tempdir(
    pattern = "dsvert-privacy-accountant-admin-e2e-")
  Sys.chmod(root, mode = "0700")
  ledger_dir <- file.path(root, "privacy")
  dir.create(ledger_dir, mode = "0700")
  Sys.chmod(ledger_dir, mode = "0700")
  ledger_path <- file.path(ledger_dir, "ledger.sqlite")
  identity_path <- file.path(root, "identity.seed")
  noise_path <- file.path(root, "noise-root")
  pins <- c(
    peer_a = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(41L, 32L)))),
    peer_b = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(73L, 32L)))))
  pins <- vapply(
    pins, .dsvert_relay_normalize_identity_pk, character(1L))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)),
    algo = "sha256", serialize = FALSE)
  withr::local_options(list(
    dsvert.state_dir = root,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = identity_path,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.noise_key_epoch = 1L,
    dsvert.dp.total_epsilon = 1,
    dsvert.dp.total_delta = 1e-6,
    dsvert.dp.lifetime_max_distinct_capsules = 8,
    dsvert.dp.domain = "namespace-admin-study",
    dsvert.dp.cohort_id = "namespace-admin-cohort",
    dsvert.dp.ledger_path = ledger_path,
    dsvert.dp.designated_noise_peers = c("peer_a", "peer_b"),
    dsvert.dp.adjacency = "add_remove_patient",
    dsvert.dp.patient_column = "patient_id",
    dsvert.dp.unit_capacity = 100L,
    dsvert.dp.fixed_cohort_size = NULL,
    dsvert.dp.max_records_per_unit = 2L,
    dsvert.dp.overflow_policy = "reject_snapshot",
    dsvert.dp.contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    dsvert.dp.lock_timeout_ms = 30000L,
    dsvert.dp.numeric_grid_bits = 16L))
  calls <- new.env(parent = emptyenv())
  calls$alignment <- 0L
  calls$noise <- 0L
  calls$ledger <- 0L
  calls$datasets <- 0L
  testthat::local_mocked_bindings(
    # setup-security-gate enables multi-peer test identities globally; this
    # focal restores the installed production value for the real enforcer.
    .dsvert_identity_test_mode = function() FALSE,
    .dsvert_dp_peer_pinset = function() list(
      peer_name = "peer_a", pinset = pins, sha256 = pin_hash),
    .dsvert_dp_reject_ephemeral_or_library_path =
      function(...) invisible(NULL),
    .dsvert_dp_alignment_registry_resolve_templates = function(...) {
      calls$alignment <- calls$alignment + 1L
      stop("alignment registry accessed", call. = FALSE)
    },
    .dsvert_dp_noise_root = function(...) {
      calls$noise <- calls$noise + 1L
      stop("noise root accessed", call. = FALSE)
    },
    .dsvert_dp_ledger_path = function(...) {
      calls$ledger <- calls$ledger + 1L
      stop("ledger opened", call. = FALSE)
    },
    .dsvert_dp_datasets = function(...) {
      calls$datasets <- calls$datasets + 1L
      stop("datasets materialized", call. = FALSE)
    },
    .package = "dsVert")

  first <- dsvertBootstrapPrivacyAccountantNamespace(
    confirm_no_other_history = TRUE)
  expect_identical(
    unlist(as.list(calls), use.names = FALSE), rep(0L, 4L))
  expect_true(file.exists(identity_path))
  expect_true(file.exists(first$receipt_path))

  canonical_ledger <- file.path(
    normalizePath(ledger_dir, winslash = "/", mustWork = TRUE),
    basename(ledger_path))
  namespace_policy <- list(
    domain = "namespace-admin-study",
    cohort_id = "namespace-admin-cohort",
    peer_name = "peer_a",
    peer_pinset = pins,
    peer_pinset_sha256 = pin_hash,
    peer_count = 2L,
    designated_noise_peers = c("peer_a", "peer_b"),
    global_total_epsilon = 1,
    global_total_delta = 1e-6,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient",
    patient_column = "patient_id",
    unit_capacity = 100L,
    max_records_per_unit = 2L,
    overflow_policy = "reject_snapshot",
    ledger_path = canonical_ledger)
  context <- .dsvert_joint_dp_policy_context_preflight(
    namespace_policy, require_designated = FALSE)
  expected <- .dsvert_privacy_accountant_namespace_validate(
    first$receipt_path, namespace_policy, context)
  expect_identical(
    first$privacy_accountant_namespace_id,
    expected$privacy_accountant_namespace_id)
  expect_identical(
    expected$paths$vector_store,
    paste0(canonical_ledger, ".joint-dp-vector-v4.sqlite"))
  expect_identical(
    expected$paths$source_store,
    paste0(canonical_ledger, ".capsule-source-v3.sqlite"))

  bases <- .dsvert_identity_dp_state_bases(canonical_ledger)
  artifacts <- unique(unlist(lapply(
    bases, function(path) paste0(
      path, c("", ".lock", "-wal", "-shm", "-journal"))),
    use.names = FALSE))
  expect_false(any(vapply(artifacts, function(path) {
    file.exists(path) || .dsvert_dp_path_is_link(path)
  }, logical(1L))))
  before <- readBin(
    first$receipt_path, what = "raw", n = file.info(first$receipt_path)$size)
  replay <- dsvertBootstrapPrivacyAccountantNamespace(
    confirm_no_other_history = TRUE)
  after <- readBin(
    first$receipt_path, what = "raw", n = file.info(first$receipt_path)$size)
  expect_identical(replay, first)
  expect_identical(after, before)
  expect_identical(
    unlist(as.list(calls), use.names = FALSE), rep(0L, 4L))
})
