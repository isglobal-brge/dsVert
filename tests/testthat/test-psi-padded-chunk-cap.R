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

test_that("large PSI membership vectors use bounded canonical share chunks", {
  bits <- rep(c(0L, 1L, 1L, 0L), 4096L)
  draws <- integer()
  entropy <- function(n) {
    draws <<- c(draws, n)
    as.raw(rep(255L, n))
  }
  shares <- .psi_padded_membership_share_bits(bits, 16384L, entropy)
  expect_identical(draws, rep(8L * 2048L, 8L))
  reconstructed <- .psi_padded_ring63_decode_small(
    .psi_padded_ring63_sum(list(shares$left, shares$right)), 1L)
  expect_identical(reconstructed, bits)
  expect_error(.psi_padded_ring63_share_bits(bits, entropy), "bit vector")
  expect_error(.psi_padded_membership_share_bits(bits[-1], 16384L, entropy), "shape")
  bits[[length(bits)]] <- 2L
  expect_error(.psi_padded_membership_share_bits(bits, 16384L, entropy), "bit vector")
  small <- bits[1:64]
  expect_identical(.psi_padded_membership_share_bits(small, 64L, entropy),
    .psi_padded_ring63_share_bits(small, entropy))
})
