# Tests for MHE Transport Key Pinning
# Mirrors the PSI key pinning pattern for mheStoreTransportKeysDS.

# =============================================================================
# MHE Key Pinning OFF (default): accept any PKs
# =============================================================================

test_that("mheStoreTransportKeysDS accepts any PKs when pinning is OFF", {
  skip_if_not(mheAvailable())

  sid <- "test-mhe-pin-off"
  ss <- dsVert:::.S(sid)

  # Setup: generate transport keys for this server
  key_self <- .callMheTool("transport-keygen", list())
  ss$secret_key <- "dummy_sk"
  ss$transport_sk <- key_self$secret_key
  ss$transport_pk <- key_self$public_key

  # Generate a random PK (not pre-configured anywhere)
  key_random <- .callMheTool("transport-keygen", list())

  # Ensure pinning is OFF
  old_opt <- getOption("dsvert.mhe_key_pinning")
  on.exit(options(dsvert.mhe_key_pinning = old_opt), add = TRUE)
  options(dsvert.mhe_key_pinning = FALSE)

  # Should succeed: any PK is accepted when pinning is OFF
  result <- mheStoreTransportKeysDS(
    transport_keys = list(
      self = base64_to_base64url(key_self$public_key),
      other = base64_to_base64url(key_random$public_key)
    ),
    session_id = sid
  )
  expect_true(result)

  dsVert:::.cleanup_session(sid)
})

# =============================================================================
# MHE Key Pinning ON: reject unknown PKs
# =============================================================================

test_that("mheStoreTransportKeysDS rejects unknown PKs when pinning is ON", {
  skip_if_not(mheAvailable())

  sid <- "test-mhe-pin-reject"
  ss <- dsVert:::.S(sid)

  # Setup: generate keys for self and a trusted peer
  key_self <- .callMheTool("transport-keygen", list())
  key_trusted <- .callMheTool("transport-keygen", list())
  key_rogue <- .callMheTool("transport-keygen", list())

  ss$secret_key <- "dummy_sk"
  ss$transport_sk <- key_self$secret_key
  ss$transport_pk <- key_self$public_key

  # Configure pinning with only the trusted peer's PK
  old_pin <- getOption("dsvert.mhe_key_pinning")
  old_peers <- getOption("dsvert.mhe_peers")
  on.exit({
    options(dsvert.mhe_key_pinning = old_pin, dsvert.mhe_peers = old_peers)
  }, add = TRUE)

  options(dsvert.mhe_key_pinning = TRUE)
  options(dsvert.mhe_peers = jsonlite::toJSON(c(key_trusted$public_key)))

  # Should fail: rogue PK not in trusted set

  expect_error(
    mheStoreTransportKeysDS(
      transport_keys = list(
        self = base64_to_base64url(key_self$public_key),
        rogue = base64_to_base64url(key_rogue$public_key)
      ),
      session_id = sid
    ),
    "MHE Key Pinning: unknown transport PK"
  )

  dsVert:::.cleanup_session(sid)
})

# =============================================================================
# MHE Key Pinning ON: accept trusted PKs
# =============================================================================

test_that("mheStoreTransportKeysDS accepts trusted PKs when pinning is ON", {
  skip_if_not(mheAvailable())

  sid <- "test-mhe-pin-accept"
  ss <- dsVert:::.S(sid)

  # Setup: generate keys for self and two trusted peers
  key_self <- .callMheTool("transport-keygen", list())
  key_peer1 <- .callMheTool("transport-keygen", list())
  key_peer2 <- .callMheTool("transport-keygen", list())

  ss$secret_key <- "dummy_sk"
  ss$transport_sk <- key_self$secret_key
  ss$transport_pk <- key_self$public_key

  # Configure pinning with both peers' PKs
  old_pin <- getOption("dsvert.mhe_key_pinning")
  old_peers <- getOption("dsvert.mhe_peers")
  on.exit({
    options(dsvert.mhe_key_pinning = old_pin, dsvert.mhe_peers = old_peers)
  }, add = TRUE)

  options(dsvert.mhe_key_pinning = TRUE)
  options(dsvert.mhe_peers = jsonlite::toJSON(
    c(key_peer1$public_key, key_peer2$public_key)
  ))

  # Should succeed: all PKs are in the trusted set (self is skipped)
  result <- mheStoreTransportKeysDS(
    transport_keys = list(
      self = base64_to_base64url(key_self$public_key),
      peer1 = base64_to_base64url(key_peer1$public_key),
      peer2 = base64_to_base64url(key_peer2$public_key)
    ),
    session_id = sid
  )
  expect_true(result)

  dsVert:::.cleanup_session(sid)
})

# =============================================================================
# MHE Key Pinning ON: missing peers config
# =============================================================================

test_that("mheStoreTransportKeysDS errors when pinning ON but peers not set", {
  skip_if_not(mheAvailable())

  sid <- "test-mhe-pin-nopeers"
  ss <- dsVert:::.S(sid)

  key_self <- .callMheTool("transport-keygen", list())
  ss$secret_key <- "dummy_sk"
  ss$transport_sk <- key_self$secret_key
  ss$transport_pk <- key_self$public_key

  old_pin <- getOption("dsvert.mhe_key_pinning")
  old_peers <- getOption("dsvert.mhe_peers")
  on.exit({
    options(dsvert.mhe_key_pinning = old_pin, dsvert.mhe_peers = old_peers)
  }, add = TRUE)

  options(dsvert.mhe_key_pinning = TRUE)
  options(dsvert.mhe_peers = NULL)

  expect_error(
    mheStoreTransportKeysDS(
      transport_keys = list(self = base64_to_base64url(key_self$public_key)),
      session_id = sid
    ),
    "dsvert.mhe_key_pinning=TRUE but dsvert.mhe_peers not set"
  )

  dsVert:::.cleanup_session(sid)
})
