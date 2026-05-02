test_that("plaintext DCF weights are gated by default", {
  expect_error(
    k2SetWeightsDS("D", "w", peer_pk = "unused", session_id = "weights-privacy"),
    "Plaintext DCF weights are disabled",
    fixed = TRUE
  )
  expect_error(
    k2ReceiveWeightsDS(session_id = "weights-privacy"),
    "Plaintext DCF weights are disabled",
    fixed = TRUE
  )
  expect_error(
    k2ApplyWeightsDS(session_id = "weights-privacy"),
    "Plaintext DCF weights are disabled",
    fixed = TRUE
  )
  expect_error(
    k2ApplySqrtWeightsDS(session_id = "weights-privacy"),
    "Plaintext DCF weights are disabled",
    fixed = TRUE
  )
})
