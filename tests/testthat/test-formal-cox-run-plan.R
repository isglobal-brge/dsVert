.formal_cox_run_plan_schema <- function(k) {
  keys <- stats::setNames(
    replicate(k, openssl::ed25519_keygen(), simplify = FALSE),
    paste0("site", seq_len(k)))
  pins <- lapply(keys, function(key) {
    raw <- as.list(as.list(key)$pubkey)$data
    chartr("+/", "-_", sub("=+$", "", jsonlite::base64_enc(raw)))
  })
  owner2 <- if (k >= 3L) "site3" else "site2"
  unsigned <- .dsvert_formal_cox_schema_compile(
    artifact_sha256 = strrep("1", 64L), logical_snapshot_id = "cohort_v1",
    peer_pinset = pins, outcome_owner = "site1",
    covariate_owners = c(x1 = "site2", x2 = owner2), capacity = 64L,
    time_grid_ticks = 0:24, x_lower = c(x1 = -2, x2 = -2),
    x_upper = c(x1 = 2, x2 = 2), covariate_l2_bound = 2.8,
    beta_l2_bound = 4, minimum_at_risk_per_event = 1L, iterations = 8L,
    step_numerator = 1L, step_denominator = 8L, ridge_numerator = 0L,
    ridge_denominator = 100L, epsilon_numerator = 2L,
    epsilon_denominator = 1L, delta_numerator = 1L,
    delta_denominator = 1000000L, adjacency = "add_remove_patient",
    entry_mode = "none", frac_bits = 30L)
  signatures <- lapply(keys, function(key) {
    signature <- openssl::ed25519_sign(
      .dsvert_formal_cox_schema_message(unsigned), key)
    base64_to_base64url(gsub(
      "[\r\n[:space:]]", "", jsonlite::base64_enc(signature)))
  })
  .dsvert_formal_cox_schema_seal(unsigned, signatures)
}

.formal_cox_run_plan_specs <- function(schema) {
  formula_sha256 <- digest::digest(
    "dsVert/formal-cox/frontdoor-formula/v1|Surv(time,status) ~ x1 + x2",
    algo = "sha256", serialize = FALSE)
  list(
    primary = list(
      version = "dsvert-formal-cox-run-spec-v1", analysis_id = "primary",
      data_name = "study", formula_sha256 = formula_sha256, schema = schema),
    alias = list(
      version = "dsvert-formal-cox-run-spec-v1", analysis_id = "alias",
      data_name = "study", formula_sha256 = formula_sha256, schema = schema))
}

test_that("registered formal Cox plans are deterministic and redacted at K=2/3/5", {
  for (k in c(2L, 3L, 5L)) {
    schema <- .formal_cox_run_plan_schema(k)
    specs <- .formal_cox_run_plan_specs(schema)
    withr::local_options(list(dsvert.dp.formal_cox_run_specs = specs))

    first <- .dsvert_formal_cox_run_plan(
      "primary", "study", specs$primary$formula_sha256)
    replay <- .dsvert_formal_cox_run_plan(
      "primary", "study", specs$primary$formula_sha256)
    alias <- .dsvert_formal_cox_run_plan(
      "alias", "study", specs$alias$formula_sha256)

    expect_identical(first, replay, info = paste("K", k))
    expect_identical(first$version, "dsvert-formal-cox-run-plan-v1")
    expect_identical(first$schema_sha256, schema$schema_sha256)
    expect_match(first$run_id, "^[0-9a-f]{64}$")
    expect_identical(first$run_id, .dsvert_formal_cox_run_id(schema))
    expect_identical(first$run_id, alias$run_id)
    expect_identical(first$compute_peers,
                     unname(unlist(schema$unsigned$compute_peers,
                                   use.names = FALSE)))
    expect_false(first$production_ready)
    expect_false(any(c("schema", "pins", "path", "key", "source",
                       "epsilon", "delta") %in% names(first)))
  }
})

test_that("registered formal Cox plan resolution fails before source or MPC", {
  schema <- .formal_cox_run_plan_schema(2L)
  specs <- .formal_cox_run_plan_specs(schema)
  withr::local_options(list(dsvert.dp.formal_cox_run_specs = specs))
  testthat::local_mocked_bindings(
    .callMpcTool = function(...) stop("must not call MPC"),
    .package = "dsVert")

  expect_error(.dsvert_formal_cox_run_plan(
    "primary", "other", specs$primary$formula_sha256),
    class = "dsvert_formal_cox_run_error")
  expect_error(.dsvert_formal_cox_run_plan(
    "primary", "study", strrep("0", 64L)),
    class = "dsvert_formal_cox_run_error")

  tampered <- specs
  tampered$primary$schema$unsigned$capacity <- "65"
  withr::local_options(list(dsvert.dp.formal_cox_run_specs = tampered))
  expect_error(.dsvert_formal_cox_run_plan(
    "primary", "study", specs$primary$formula_sha256),
    class = "dsvert_formal_cox_run_error")
})
