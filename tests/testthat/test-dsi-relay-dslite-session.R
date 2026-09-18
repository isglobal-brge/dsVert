test_that("relay public UUIDs retain DSLite private storage isolation", {
  root <- withr::local_tempdir(pattern = "dsvert-dslite-relay-")
  Sys.chmod(root, "0700")
  withr::local_options(list(dsvert.state_dir = root))
  session_id <- "f1234567-89ab-cdef-0123-456789abcdef"
  identity <- jsonlite::base64_enc(as.raw(seq_len(32L)))
  bridge <- function() .S(session_id)
  host <- function() {
    frame <- sys.frame(sys.nframe())
    attr(frame, "name") <- "DSLiteEnv_relay-regression"
    bridge()
  }
  ss <- host()
  withr::defer({
    if (is.environment(ss$.dsvert_dsi_relay)) .dsvert_relay_close(ss)
    .session_dir_cleanup(ss)
    .dsvert_resource_unregister(ss)
  })
  private_id <- ss$.session_id
  expect_match(private_id, "__dslite_[0-9a-f]{16}$")
  expect_no_error(.dsvert_relay_init(ss, session_id, identity, identity, "psi.padded.v4"))
  expect_identical(ss$.session_id, private_id)
  expect_identical(.dsvert_relay_state(ss)$session_id, session_id)
  expect_match(.dsvert_relay_state(ss)$spool, private_id, fixed = TRUE)
  expect_error(.dsvert_relay_init(ss, "e1234567-89ab-cdef-0123-456789abcdef",
    identity, identity, "psi.padded.v4"), "does not match")
  ss$.session_id <- paste0("e1234567-89ab-cdef-0123-456789abcdef", "__dslite_", strrep("a", 16))
  expect_error(.dsvert_relay_init(ss, session_id, identity, identity, "psi.padded.v4"),
    "does not match")
  ss$.session_id <- private_id
})
