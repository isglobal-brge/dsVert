test_that("padded PSI AND schedules respect the fixed typed-input cap", {
  contract <- list(protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = strrep("a", 64), compute_peers = c("a", "b"),
    peer_names = c("a", "b", "c"), reference_peer = "a", capacity = 16384L)
  chunks <- lapply(seq_len(8L), function(i) .psi_padded_and_chunk_contract(contract, i))
  expect_identical(vapply(chunks, `[[`, integer(1), "vector_len"), rep(2048L, 8))
  expect_true(all(vapply(chunks, function(chunk) 3 * 64 * chunk$vector_len <= 524288,
    logical(1))))
  positions <- unlist(lapply(chunks, function(chunk)
    chunk$offset + seq_len(chunk$vector_len)), use.names = FALSE)
  expect_identical(positions, seq_len(contract$capacity))
  expect_length(unique(vapply(chunks, `[[`, character(1), "operation_id")), 8L)
  expect_error(.psi_padded_and_chunk_contract(contract, 9L), "AND chunk index")
  contract$capacity <- 64L
  expect_identical(.psi_padded_and_chunk_contract(contract, 1L)$vector_len, 64L)
})
