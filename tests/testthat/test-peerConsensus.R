# Tests for Peer Manifest Consensus Functions

# =============================================================================
# .build_manifest: deterministic JSON output
# =============================================================================

test_that(".build_manifest produces deterministic JSON with sorted keys", {
  m1 <- dsVert:::.build_manifest(
    job_id = "test-123",
    method = "gaussian",
    peers = c("serverC", "serverA", "serverB"),
    transport_pks = list(serverB = "pkB", serverA = "pkA", serverC = "pkC"),
    y_server = "serverA",
    non_label_servers = c("serverC", "serverB"),
    topology = "pairwise"
  )

  m2 <- dsVert:::.build_manifest(
    job_id = "test-123",
    method = "gaussian",
    peers = c("serverA", "serverB", "serverC"),
    transport_pks = list(serverA = "pkA", serverC = "pkC", serverB = "pkB"),
    y_server = "serverA",
    non_label_servers = c("serverB", "serverC"),
    topology = "pairwise"
  )

  # Same inputs in different order should produce identical JSON
  expect_equal(m1, m2)

  # Verify it's valid JSON
  parsed <- jsonlite::fromJSON(m1)
  expect_equal(parsed$job_id, "test-123")
  expect_equal(parsed$peers, c("serverA", "serverB", "serverC"))
})

# =============================================================================
# .compute_manifest_hash: consistent hashing
# =============================================================================

test_that(".compute_manifest_hash is consistent for same input", {
  json <- '{"job_id":"test","peers":["A","B"]}'
  h1 <- dsVert:::.compute_manifest_hash(json)
  h2 <- dsVert:::.compute_manifest_hash(json)
  expect_equal(h1, h2)
  expect_match(h1, "^[0-9a-f]{64}$")  # SHA-256 hex
})

test_that(".compute_manifest_hash differs for different input", {
  h1 <- dsVert:::.compute_manifest_hash('{"peers":["A","B"]}')
  h2 <- dsVert:::.compute_manifest_hash('{"peers":["A","C"]}')
  expect_false(h1 == h2)
})

# =============================================================================
# peerManifestStoreDS: requires transport keys
# =============================================================================

test_that("peerManifestStoreDS requires transport keys", {
  skip_if_not(mheAvailable())

  sid <- "test-manifest-store-err"
  ss <- dsVert:::.S(sid)
  ss$transport_sk <- NULL

  expect_error(
    peerManifestStoreDS('{"test":true}', session_id = sid),
    "Transport SK not stored"
  )

  dsVert:::.cleanup_session(sid)
})

# =============================================================================
# peerManifestValidateDS: requires manifest
# =============================================================================

test_that("peerManifestValidateDS requires manifest stored first", {
  skip_if_not(mheAvailable())

  sid <- "test-manifest-validate-err"
  ss <- dsVert:::.S(sid)
  key <- .callMheTool("transport-keygen", list())
  ss$transport_sk <- key$secret_key
  ss$manifest_hash <- NULL

  expect_error(
    peerManifestValidateDS("peerA", session_id = sid),
    "Manifest not stored"
  )

  dsVert:::.cleanup_session(sid)
})

# =============================================================================
# End-to-end: encrypted hash exchange with real transport-encrypt/decrypt
# =============================================================================

test_that("Manifest consensus works end-to-end with transport encryption", {
  skip_if_not(mheAvailable())

  # Setup: two servers (A and B) with transport keys
  sidA <- "test-manifest-e2e-A"
  sidB <- "test-manifest-e2e-B"

  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())

  ssA <- dsVert:::.S(sidA)
  ssA$secret_key <- "dummy_sk_A"
  ssA$transport_sk <- keyA$secret_key
  ssA$transport_pk <- keyA$public_key
  ssA$peer_transport_pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key
  )

  ssB <- dsVert:::.S(sidB)
  ssB$secret_key <- "dummy_sk_B"
  ssB$transport_sk <- keyB$secret_key
  ssB$transport_pk <- keyB$public_key
  ssB$peer_transport_pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key
  )

  # Both servers receive the same manifest
  manifest <- dsVert:::.build_manifest(
    job_id = "test-session",
    method = "gaussian",
    peers = c("serverA", "serverB"),
    transport_pks = list(
      serverA = keyA$public_key,
      serverB = keyB$public_key
    ),
    y_server = "serverA",
    non_label_servers = "serverB",
    topology = "pairwise"
  )

  # Phase 1: Each server stores manifest and gets encrypted hashes
  enc_hashes_A <- peerManifestStoreDS(manifest, session_id = sidA)
  enc_hashes_B <- peerManifestStoreDS(manifest, session_id = sidB)

  # Phase 2: Client relays A's hash to B and B's hash to A via blob storage
  # A's hash for B -> store on B
  if (is.null(ssB$blobs)) ssB$blobs <- list()
  ssB$blobs[["manifest_hash_serverA"]] <- enc_hashes_A[["serverB"]]

  # B's hash for A -> store on A
  if (is.null(ssA$blobs)) ssA$blobs <- list()
  ssA$blobs[["manifest_hash_serverB"]] <- enc_hashes_B[["serverA"]]

  # Phase 3: Each server validates the peer's hash
  expect_true(peerManifestValidateDS("serverB", session_id = sidA))
  expect_true(peerManifestValidateDS("serverA", session_id = sidB))

  # Verify validated peers are tracked
  expect_true("serverB" %in% ssA$validated_peers)
  expect_true("serverA" %in% ssB$validated_peers)

  dsVert:::.cleanup_session(sidA)
  dsVert:::.cleanup_session(sidB)
})

# =============================================================================
# Manifest mismatch detection
# =============================================================================

test_that("Manifest consensus detects mismatch (phantom peer attack)", {
  skip_if_not(mheAvailable())

  sidA <- "test-manifest-mismatch-A"
  sidB <- "test-manifest-mismatch-B"

  keyA <- .callMheTool("transport-keygen", list())
  keyB <- .callMheTool("transport-keygen", list())

  ssA <- dsVert:::.S(sidA)
  ssA$secret_key <- "dummy_sk_A"
  ssA$transport_sk <- keyA$secret_key
  ssA$transport_pk <- keyA$public_key
  ssA$peer_transport_pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key
  )

  ssB <- dsVert:::.S(sidB)
  ssB$secret_key <- "dummy_sk_B"
  ssB$transport_sk <- keyB$secret_key
  ssB$transport_pk <- keyB$public_key
  ssB$peer_transport_pks <- list(
    serverA = keyA$public_key,
    serverB = keyB$public_key
  )

  # Malicious client sends DIFFERENT manifests to A and B
  manifest_A <- dsVert:::.build_manifest(
    job_id = "test-session",
    method = "gaussian",
    peers = c("serverA", "serverB"),
    transport_pks = list(serverA = keyA$public_key, serverB = keyB$public_key),
    y_server = "serverA",
    non_label_servers = "serverB",
    topology = "pairwise"
  )
  manifest_B <- dsVert:::.build_manifest(
    job_id = "test-session",
    method = "gaussian",
    peers = c("serverA", "serverB", "serverC"),  # phantom peer!
    transport_pks = list(serverA = keyA$public_key, serverB = keyB$public_key),
    y_server = "serverA",
    non_label_servers = c("serverB", "serverC"),
    topology = "pairwise"
  )

  enc_hashes_A <- peerManifestStoreDS(manifest_A, session_id = sidA)
  enc_hashes_B <- peerManifestStoreDS(manifest_B, session_id = sidB)

  # Relay A's hash to B
  if (is.null(ssB$blobs)) ssB$blobs <- list()
  ssB$blobs[["manifest_hash_serverA"]] <- enc_hashes_A[["serverB"]]

  # B should detect the mismatch (A's hash != B's hash)
  expect_error(
    peerManifestValidateDS("serverA", session_id = sidB),
    "Manifest consensus FAILED"
  )

  dsVert:::.cleanup_session(sidA)
  dsVert:::.cleanup_session(sidB)
})
