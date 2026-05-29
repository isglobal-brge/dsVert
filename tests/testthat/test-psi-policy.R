test_that("PSI shared-key policy is study separated and public output is non-secret", {
  old <- options(
    dsvert.psi.pseudonym_mode = "shared_key",
    dsvert.psi.pseudonym_key = "unit-test-study-key",
    dsvert.psi.study_id = "study-alpha",
    dsvert.psi.key_custody = "shared_key",
    dsvert.psi.require_keyed_pseudonyms = TRUE
  )
  on.exit(options(old), add = TRUE)

  p1 <- .psi_policy("session-a")
  expect_identical(p1$pseudonym_mode, "shared_key")
  expect_identical(p1$key_custody, "shared_key")
  expect_identical(p1$study_id, "study-alpha")
  expect_true(nzchar(p1$key_id))

  pub <- .psi_public_policy(p1)
  expect_false("pseudonym_key" %in% names(pub))
  expect_false("study_id" %in% names(pub))
  expect_true(nzchar(pub$key_id))

  options(dsvert.psi.study_id = "study-beta")
  p2 <- .psi_policy("session-a")
  expect_false(identical(p1$key_id, p2$key_id))
  expect_false(identical(p1$study_id_hash, p2$study_id_hash))
})

test_that("PSI keyed pseudonym and threshold policies fail closed when unavailable", {
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.pseudonym_key = "",
    dsvert.psi.require_keyed_pseudonyms = TRUE
  )
  on.exit(options(old), add = TRUE)
  expect_error(.psi_policy("session-a"), "keyed pseudonymisation is required")

  options(
    dsvert.psi.pseudonym_mode = "threshold",
    dsvert.psi.require_keyed_pseudonyms = FALSE
  )
  expect_error(.psi_policy("session-a"), "threshold-OPRF key custody")
})

test_that("PSI identifier validation skips NA and empty IDs", {
  expect_identical(.psi_valid_id_rows(c("id-1", NA_character_, "", "id-4")),
                   c(1L, 4L))
})

test_that("PSI input caps, rate limits and audit events are enforced", {
  old <- options(
    datashield.privacyLevel = 1,
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.max_input_ids = 15,
    dsvert.psi.rate_limit_n = 100,
    dsvert.psi.rate_limit_window_sec = 60,
    dsvert.psi.audit_log_path = ""
  )
  on.exit(options(old), add = TRUE)
  storage <- .session_storage()
  storage$.psi_rate_log <- NULL

  sid_cap <- "psi-test-cap"
  ss_cap <- .S(sid_cap)
  ss_cap$psi_policy <- .psi_policy(sid_cap)
  expect_error(.psi_guard_input_set(sid_cap, "mask-cap", 20L, 20L),
               "exceeding")
  statuses <- vapply(ss_cap$psi_audit, `[[`, character(1L), "status")
  expect_true("blocked_max_input" %in% statuses)

  options(dsvert.psi.max_input_ids = 1000, dsvert.psi.rate_limit_n = 1)
  storage$.psi_rate_log <- NULL
  sid_rate <- "psi-test-rate"
  ss_rate <- .S(sid_rate)
  ss_rate$psi_policy <- .psi_policy(sid_rate)
  expect_silent(.psi_guard_input_set(sid_rate, "mask-rate", 20L, 20L))
  expect_error(.psi_guard_input_set(sid_rate, "mask-rate", 20L, 20L),
               "rate limit")
  statuses <- vapply(ss_rate$psi_audit, `[[`, character(1L), "status")
  expect_true("accepted" %in% statuses)
  expect_true("blocked_rate_limit" %in% statuses)
  expect_false(any(grepl("id-", unlist(ss_rate$psi_audit), fixed = TRUE)))
})

test_that("PSI minimum intersection guard follows nfilter.subset", {
  old <- options(nfilter.subset = 3, default.nfilter.subset = 3)
  on.exit(options(old), add = TRUE)

  expect_error(.psi_guard_intersection_count(2L, "PSI common intersection"),
               "too small")
  expect_silent(.psi_guard_intersection_count(3L, "PSI common intersection"))
})

test_that("PSI matched row maps are not disclosed to the analyst by default", {
  old <- options(dsvert.psi.allow_matched_indices_reveal = FALSE)
  on.exit(options(old), add = TRUE)

  sid <- "psi-test-no-map"
  ss <- .S(sid)
  ss$psi_matched_ref_indices <- 0:4
  expect_error(psiGetMatchedIndicesDS(sid), "disabled by default")
})

test_that("PSI final filter blocks empty or very small common intersections", {
  old <- options(nfilter.subset = 3, default.nfilter.subset = 3)
  on.exit(options(old), add = TRUE)

  sid <- "psi-test-filter-guard"
  D <- data.frame(patient_id = paste0("id-", 1:5), x = 1:5)
  ss <- .S(sid)
  ss$psi_matched_ref_indices <- 0:4
  expect_error(
    psiFilterCommonDS("D", common_indices = integer(0), session_id = sid),
    "intersection too small"
  )
  expect_error(
    psiFilterCommonDS("D", common_indices = 0:1, session_id = sid),
    "intersection too small"
  )
})

test_that("bundled MPC binary supports shared-key PSI pseudonymisation", {
  raw <- .callMpcTool("psi-mask", list(
    ids = list("patient-1"),
    scalar = "",
    pseudonym_mode = "none"
  ))
  keyed <- .callMpcTool("psi-mask", list(
    ids = list("patient-1"),
    scalar = raw$scalar,
    pseudonym_mode = "shared_key",
    pseudonym_key = "unit-test-study-key",
    study_id = "study-alpha"
  ))

  expect_length(raw$masked_points, 1L)
  expect_length(keyed$masked_points, 1L)
  expect_false(identical(raw$masked_points[[1L]], keyed$masked_points[[1L]]))
})
