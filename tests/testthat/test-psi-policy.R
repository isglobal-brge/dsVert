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

test_that("security-sensitive PSI options reject malformed values", {
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = "typo",
    dsvert.psi.max_input_ids = 100L,
    dsvert.psi.study_id = NULL)
  on.exit(options(old), add = TRUE)
  expect_error(.psi_policy("psi-malformed-bool"), "expected TRUE or FALSE")

  options(dsvert.psi.require_keyed_pseudonyms = FALSE,
          dsvert.psi.max_input_ids = "100")
  expect_error(.psi_policy("psi-malformed-int"), "positive integer")

  options(dsvert.psi.max_input_ids = 100L,
          dsvert.psi.study_id = c("a", "b"))
  expect_error(.psi_policy("psi-malformed-scalar"), "one non-missing")
})

test_that("PSI identifier validation skips NA and empty IDs", {
  expect_identical(.psi_valid_id_rows(c("id-1", NA_character_, "", "id-4")),
                   c(1L, 4L))
})

test_that("padded PSI policy has a shape cap but no request quota", {
  old <- options(
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.max_input_ids = 1024L,
    dsvert.psi.rate_limit_n = 1L,
    dsvert.psi.rate_limit_window_sec = 1L)
  on.exit(options(old), add = TRUE)
  source <- .psi_padded_test_source_public()
  policies <- replicate(10L, .psi_padded_policy("same-session", source),
                        simplify = FALSE)
  expect_true(all(vapply(policies, function(x) {
    identical(x$private$max_capacity, 1024L)
  }, logical(1L))))
  expect_false(any(c("rate_limit_n", "rate_limit_window_sec") %in%
                   names(policies[[1L]]$public)))
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
