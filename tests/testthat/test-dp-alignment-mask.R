.alignment_mask_test_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

test_that("alignment-mask geometry is exact for K=2,3,5", {
  contract_hash <- strrep("a", 64L)
  batch <- "op_11111111111111111111111111111111"
  for (k in c(2L, 3L, 5L)) {
    chunk_size <- .dsvert_dp_alignment_mask_chunk_size(k)
    total <- chunk_size + 3L
    parsed <- list(
      sources = paste0("source_", seq_len(k)),
      contract_hash = contract_hash,
      contract = list(coordinate_count = total))
    chunk_count <- 2L
    for (index in seq_len(chunk_count)) {
      operation_id <- .dsvert_dp_alignment_mask_operation_id(
        batch, contract_hash, index, chunk_count)
      geometry <- .dsvert_dp_alignment_mask_geometry(
        parsed, batch, operation_id, index, chunk_count)
      expect_identical(geometry$source_count, k)
      expect_identical(geometry$chunk_count, 2L)
      expect_identical(geometry$n,
                       if (index == 1L) chunk_size else 3L)
      expect_identical(
        128L * (3L * geometry$n + 4L * k + 1L) <=
          .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS, TRUE)
    }
    expect_error(.dsvert_dp_alignment_mask_geometry(
      parsed, batch,
      .dsvert_dp_alignment_mask_operation_id(
        batch, contract_hash, 1L, chunk_count),
      2L, chunk_count), "chunk contract")
  }
})

test_that("each computation peer sees only one XOR share per source", {
  for (k in c(2L, 3L, 5L)) {
    sources <- paste0("source_", seq_len(k))
    shares <- stats::setNames(lapply(seq_len(k), function(index) {
      .alignment_mask_test_b64url(as.raw(
        (seq_len(32L) + index * 17L) %% 256L))
    }), sources)
    state <- list(private_alignment_consensus_shares = shares)
    records <- .dsvert_dp_alignment_mask_digest_records(state, sources)
    expect_type(records, "raw")
    expect_length(records, 32L * k)
    expect_false("private_alignment_consensus_hash" %in% names(state))
    expect_error(.dsvert_dp_alignment_mask_digest_records(
      list(private_alignment_consensus_shares = shares[-1L]), sources),
      "incomplete")
    changed <- shares
    changed[[1L]] <- .alignment_mask_test_b64url(raw(31L))
    expect_error(.dsvert_dp_alignment_mask_digest_records(
      list(private_alignment_consensus_shares = changed), sources),
      "invalid")
  }
})

test_that("alignment terminal response has one uniform semantic failure", {
  make_batch <- function(state) {
    batch <- new.env(parent = emptyenv())
    batch$status <- state
    batch$source_count <- 5L
    batch$total <- 4099
    batch$chunk_count <- 2L
    batch
  }
  for (failure in c(
      "content_mismatch", "shape_mismatch", "phase_mismatch",
      "source_1", "source_2", "source_5")) {
    # The private cause is deliberately absent from the public batch state.
    value <- .dsvert_dp_alignment_mask_terminal_public(
      make_batch("alignment_contract_invalid"))
    expect_identical(names(value), c(
      "capability_id", "version", "state", "terminal_outcome",
      "fixed_transcript", "source_count", "coordinate_count",
      "chunk_count", "alignment_digest_exposed",
      "mismatch_source_exposed", "gate_share_exposed"))
    expect_identical(anyDuplicated(names(value)), 0L)
    expect_identical(value$state, "alignment_contract_invalid")
    expect_identical(value$terminal_outcome,
                     "alignment_contract_invalid")
    expect_false(value$alignment_digest_exposed)
    expect_false(value$mismatch_source_exposed)
    expect_false(value$gate_share_exposed)
    expect_false(failure %in% unlist(value, use.names = FALSE))
  }
})

test_that("alignment batches cannot become readable before terminal success", {
  ss <- new.env(parent = emptyenv())
  ss$.dp_alignment_mask_batches <- new.env(parent = emptyenv())
  batch <- new.env(parent = emptyenv())
  batch$status <- "running"
  batch$capsule_id <- "dpc_11111111111111111111111111111111"
  batch$contract_hash <- strrep("a", 64L)
  ss$.dp_alignment_mask_batches[[
    "op_11111111111111111111111111111111"]] <- batch
  expect_error(.dsvert_dp_alignment_mask_complete_batch(
    ss, batch$capsule_id, batch$contract_hash), "not complete")
  batch$status <- "alignment_contract_invalid"
  expect_error(.dsvert_dp_alignment_mask_complete_batch(
    ss, batch$capsule_id, batch$contract_hash), "not complete")
  batch$status <- "complete"
  expect_identical(.dsvert_dp_alignment_mask_complete_batch(
    ss, batch$capsule_id, batch$contract_hash), batch)
})
