.frequency_epoch_helpers <- local({
  environment <- new.env(parent = environment())
  for (expression in parse(testthat::test_path("test-dp-frequency-analysis.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) next
    eval(expression, envir = environment)
  }
  environment
})

test_that("Frequency authenticates original ordered factors before computing coordinates", {
  h <- .frequency_epoch_helpers
  h$.frequency_test_state()
  fixture <- h$.frequency_compile_fixture()
  peer <- fixture$source_peer
  # Ordered factors are supported public factor inputs. Reconstructing them as
  # ordinary factors before seal validation silently changes their schema.
  fixture$data_by_peer[[peer]]$category <- ordered(
    c("z", "a", NA_character_), levels = c("z", "\u00e1", "a"))
  fixture$contract$authorization_epochs[[1L]]$authorization_epoch <- strrep("f", 64L)
  fixture <- h$.frequency_psi_rerun(fixture)
  compiled <- h$.frequency_compiled(fixture)
  authorization <- list(config = compiled$config,
    local_authority = list(peer_name = peer,
      identity_pk = unname(fixture$pins[[peer]])),
    contract = compiled$contract,
    psi_run_sha256 = compiled$receipts[[1L]]$psi_run_sha256,
    worker_static = list(d = 3L))
  histogram <- h$.frequency_test_as_peer(fixture$pins, peer,
    .dsvert_dp_frequency_execution_histogram_v1(fixture$data, authorization,
      fixture$claim, h$.frequency_analysis_verifier))
  expect_identical(histogram, c(1, 1, 0))
  expect_silent(h$.frequency_test_as_peer(fixture$pins, peer,
    .psi_padded_validate_persistent_attestation(fixture$data)))
  tampered <- fixture$data
  tampered$category[[1L]] <- "a"
  expect_error(h$.frequency_test_as_peer(fixture$pins, peer,
    .dsvert_dp_frequency_execution_histogram_v1(tampered, authorization,
      fixture$claim, h$.frequency_analysis_verifier)), "integrity|attestation")
})

test_that("Frequency binds a membership-only epoch into both noise contexts", {
  h <- .frequency_epoch_helpers
  h$.frequency_test_state()
  original <- h$.frequency_compile_fixture()
  compiled <- h$.frequency_compiled(original)
  roles <- .dsvert_dp_frequency_analysis_binding_v1(compiled$contract)$value$authority_roles
  # A new publication of the same bytes by a third peer is represented by a
  # changed signed epoch. The peer contributes no categorical source values.
  witness <- names(original$pins)[!unname(original$pins) %in%
    unlist(roles, use.names = FALSE)][[1L]]
  rotated <- original
  selected <- which(vapply(rotated$contract$authorization_epochs, function(entry)
    identical(entry$peer_identity, unname(original$pins[[witness]])), logical(1L)))
  rotated$contract$authorization_epochs[[selected]]$authorization_epoch <-
    paste0(format(openssl::rand_bytes(32L)), collapse = "")
  rotated <- h$.frequency_psi_rerun(rotated)
  next_compiled <- h$.frequency_compiled(rotated)
  expect_false(identical(compiled$contract$artifact_key,
                         next_compiled$contract$artifact_key))
  for (identity in unlist(roles, use.names = FALSE)) {
    peer <- names(original$pins)[match(identity, unname(original$pins))]
    first <- h$.frequency_authorize(original, compiled, peer)
    second <- h$.frequency_authorize(rotated, next_compiled, peer)
    expect_false(identical(first$value$worker_static$commitment_contexts,
                           second$value$worker_static$commitment_contexts))
    expect_false(identical(first$seed_commitment$sha256,
                           second$seed_commitment$sha256))
  }
  # Previously attested old frames retain their own immutable admission pins.
  expect_identical(h$.frequency_compiled(original)$contract, compiled$contract)
  replay <- h$.frequency_psi_rerun(original)
  expect_identical(h$.frequency_compiled(replay)$contract, compiled$contract)
})
