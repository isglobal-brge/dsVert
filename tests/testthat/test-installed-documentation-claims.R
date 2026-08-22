.dsvert_installed_doc <- function(filename) {
  .dsvert_test_package_file(
    "inst", "docs", "disclosure_budget", filename)
}

.dsvert_installed_formal_docs <- function(filename) {
  .dsvert_test_package_file("inst", "docs", filename)
}

test_that("installed Cox and LMM notes cannot promote quarantined routes", {
  forbidden <- "\\b(shipping|shipped|currently|current|proof|PASS(_PRACTICAL)?)\\b"
  for (filename in c("cox.md", "lmm.md")) {
    path <- .dsvert_installed_doc(filename)
    text <- paste(readLines(path, warn = FALSE), collapse = "\n")
    expect_match(text, "quarantined", ignore.case = TRUE,
                 info = paste(filename, "must state quarantine"))
    expect_match(text, "before any DSI call", fixed = TRUE,
                 info = paste(filename, "must state the zero-DSI gate"))
    expect_false(grepl(forbidden, text, ignore.case = TRUE, perl = TRUE),
                 info = paste(filename, "contains a release-status overclaim"))
    if (identical(filename, "cox.md")) {
      expect_match(text, "Security-profile schema v4", fixed = TRUE)
      expect_match(text, "`route_claims$formal_cox_ready = FALSE`",
                   fixed = TRUE)
      expect_match(text, "neither can promote this quarantined Cox frontdoor",
                   fixed = TRUE)
    }
  }
})

test_that("installed legacy Cox and LMM experiments are marked archival", {
  paths <- c(
    .dsvert_test_package_file(
      "inst", "docs", "acceptance", "path_b_targets.md"),
    .dsvert_test_package_file(
      "inst", "docs", "error_bounds", "cox_newton_onestep.md"))
  for (path in paths) {
    text <- paste(readLines(path, warn = FALSE), collapse = "\n")
    expect_match(text, "Archived historical design record", fixed = TRUE)
    expect_match(text, "fails? before any DSI call")
  }
})

test_that("formal GLM and Cox notes cannot inherit profile readiness", {
  glm_docs <- c(
    "formal_glm_phase15_streaming.md",
    "formal_glm_phase16_dp_release_adapter.md",
    "formal_glm_phase17_authenticated_admission.md")

  for (filename in glm_docs) {
    for (path in .dsvert_installed_formal_docs(filename)) {
      text <- paste(readLines(path, warn = FALSE), collapse = "\n")
      expect_match(text, "security-profile schema v4", fixed = TRUE)
      expect_match(text, "`route_claims$formal_glm_ready = FALSE`",
                   fixed = TRUE)
      expect_match(text,
                   "`sealed_no_registered_r_dsi_joint_dp_release_lifecycle`",
                   fixed = TRUE)
      expect_match(text, "`formal_dp_claim_eligible`", fixed = TRUE)
      expect_match(text, "neither promotes formal\\s+GLM or formal Cox",
                   perl = TRUE)
      expect_match(text, "R/DSI", fixed = TRUE)
      expect_match(text, "durable common finalizer", fixed = TRUE)
      expect_match(text, "route-level end-to-end numeric certificate",
                   fixed = TRUE)
    }
  }

  for (path in .dsvert_installed_formal_docs(
      "formal_cox_capsule_internal.md")) {
    text <- paste(readLines(path, warn = FALSE), collapse = "\n")
    expect_match(text, "security-profile schema v4", fixed = TRUE)
    expect_match(text, "`route_claims$formal_cox_ready = FALSE`", fixed = TRUE)
    expect_match(
      text,
      paste0("`sealed_no_recipient_encrypted_r_dsi_lifecycle_or_",
             "end_to_end_numeric_certificate`"),
      fixed = TRUE)
    expect_match(text, "`formal_dp_claim_eligible`", fixed = TRUE)
    expect_match(text, "neither promotes formal GLM or formal Cox",
                 fixed = TRUE)
    expect_match(text, "registered R/DSI schedule", fixed = TRUE)
    expect_match(text, "durable common finalizer", fixed = TRUE)
    expect_match(text, "route-level end-to-end numeric/identifiability",
                 fixed = TRUE)
  }
})

test_that("public schema-v4 profile docs keep readiness route-specific", {
  source <- paste(readLines(.dsvert_test_package_file(
    "R", "securityProfileDS.R", source_only = TRUE), warn = FALSE),
    collapse = "\n")
  readme <- paste(readLines(.dsvert_test_package_file(
    "README.md", source_only = TRUE), warn = FALSE), collapse = "\n")

  expect_match(source, "schema_version = 4L", fixed = TRUE)
  expect_match(source, "formal_glm_ready = FALSE", fixed = TRUE)
  expect_match(source, "formal_cox_ready = FALSE", fixed = TRUE)
  expect_match(source, "formal_dp_claim_eligible", fixed = TRUE)
  expect_match(source, "never promote formal GLM or formal", fixed = TRUE)

  expect_match(readme, "Security-profile schema v4", fixed = TRUE)
  expect_match(readme, "formal_dp_claim_eligible", fixed = TRUE)
  expect_match(readme, "formal GLM and formal Cox\\s+not ready", perl = TRUE)
  expect_match(readme, "never\\s+promotes either sealed model route",
               perl = TRUE)
})

test_that("README makes the no-admission Synopsis contract explicit", {
  readme <- paste(readLines(.dsvert_test_package_file(
    "README.md", source_only = TRUE), warn = FALSE), collapse = "\n")

  expect_match(readme, "dsvert.dp.synopsis_state_path", fixed = TRUE)
  expect_match(readme, "no request counter, rate", fixed = TRUE)
  expect_match(readme, "catalog limit, lifetime admission limit", fixed = TRUE)
  expect_match(readme, "### Archived capsule-control record", fixed = TRUE)
  expect_match(readme, "not deployment configuration", fixed = TRUE)
})
