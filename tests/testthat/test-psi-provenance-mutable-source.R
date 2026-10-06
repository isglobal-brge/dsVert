test_that("first PSI registration detaches mutable source columns through finalization", {
  skip_if_not_installed("data.table")
  # setup-security-gate.R otherwise replaces this with the compatibility gate.
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  expect_identical(.dsvert_enforce_release_mode, .dsvert_test_production_gate)
  root <- tempfile("psi-mutable-source-")
  dir.create(root, mode = "0700")
  withr::defer(unlink(root, recursive = TRUE))
  withr::local_envvar(c(DSVERT_STATE_DIR = root))
  withr::local_options(list(
    dsvert.state_dir = NULL, default.dsvert.state_dir = NULL,
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only"))
  seeds <- list(
    alpha = jsonlite::base64_enc(as.raw(rep(191L, 32L))),
    beta = jsonlite::base64_enc(as.raw(rep(192L, 32L))))
  identities <- lapply(seeds, function(seed) {
    .callMpcTool("derive-identity", list(seed = seed))
  })
  live <- data.table::data.table(id = c("p1", "p2"), value = c(1L, 2L))
  frames <- list(alpha = live,
    beta = data.frame(id = c("p1", "p2"), other = c(10L, 20L)))
  descriptors <- lapply(frames, function(frame) {
    dsvertPSISourceDescriptor(frame, "id", "mutable-source", "v1")
  })
  states <- lapply(frames, function(frame) new.env(parent = emptyenv()))
  session_id <- "52345678-1234-4234-9234-123456789abc"
  operation_id <- paste0("op_", strrep("e", 32L))
  previous_session <- .mpc_sessions[[session_id]]
  on.exit({
    if (is.null(previous_session)) {
      if (exists(session_id, .mpc_sessions, inherits = FALSE)) {
        rm(list = session_id, envir = .mpc_sessions)
      }
    } else {
      .mpc_sessions[[session_id]] <- previous_session
    }
  }, add = TRUE)
  with_peer <- function(peer, code) {
    other <- setdiff(names(seeds), peer)
    old <- options(
      dsvert.identity_seed = seeds[[peer]], dsvert.peer_name = peer,
      dsvert.trusted_peers = stats::setNames(
        identities[[other]]$identity_pk, other),
      dsvert.psi.authorized_sources = list(D = descriptors[[peer]]))
    on.exit(options(old), add = TRUE)
    .mpc_sessions[[session_id]] <- states[[peer]]
    force(code)
  }
  # Only deterministic peer identities are test-enabled; the public release
  # guard, signed messages, source admission and durable store remain active.
  with_peer("alpha", expect_error(.S(session_id), "single disclosure-safe"))
  offers <- lapply(names(frames), function(peer) {
    with_peer(peer, suppressMessages(.psi_padded_init_impl(
      states[[peer]], frames[[peer]], "D", "id", session_id, operation_id)))
  })
  names(offers) <- names(frames)
  bindings <- lapply(names(frames), function(peer) {
    with_peer(peer, .psi_padded_bind_impl(states[[peer]], offers, names(frames)))
  })
  names(bindings) <- names(frames)
  receipts <- lapply(bindings, `[[`, "receipt")
  for (peer in names(frames)) {
    with_peer(peer, .psi_padded_confirm_impl(states[[peer]], receipts))
  }
  first <- with_peer("alpha", psiPaddedPrepareDS("D", session_id))
  expect_true(first$prepared)
  original_digest <- states$alpha$.psi_padded_state$snapshot_digest
  original_epoch <- states$alpha$.psi_padded_state$authorization_epoch

  # Partial assignment mutates an existing atomic vector. Merely copying the
  # frame/list still shares this vector and fails this regression.
  data.table::set(live, i = 1L, j = "value", value = 99L)
  expect_identical(live$value, c(99L, 2L))
  expect_identical(states$alpha$.psi_padded_state$authorized_data$value, c(1L, 2L))
  expect_identical(.dsvert_dp_snapshot_digest(
    states$alpha$.psi_padded_state$authorized_data), original_digest)
  expect_identical(with_peer("alpha", psiPaddedPrepareDS("D", session_id)), first)
  retained <- with_peer("alpha", .dsvert_dp_provenance_lookup(
    .psi_padded_authorization_public(descriptors$alpha)))
  expect_identical(retained$descriptor, descriptors$alpha)
  expect_identical(retained$epoch, original_epoch)
  expect_identical(retained$data$value, c(1L, 2L))

  with_peer("beta", psiPaddedPrepareDS("D", session_id))
  contract <- states$alpha$.psi_padded_state$contract
  reference <- contract$reference_peer
  target <- setdiff(names(frames), reference)
  reference_export <- with_peer(reference,
    .psi_padded_reference_export_impl(states[[reference]], target))
  target_export <- with_peer(target, .psi_padded_target_process_impl(
    states[[target]], reference_export$envelope))
  double_export <- with_peer(reference, .psi_padded_reference_double_impl(
    states[[reference]], target, target_export$envelope))
  membership <- with_peer(target, .psi_padded_target_match_impl(
    states[[target]], double_export$envelope))
  for (compute in contract$compute_peers) {
    with_peer(compute, .psi_padded_membership_accept_impl(
      states[[compute]], target, membership$envelopes[[compute]]))
  }
  # The existing two-peer protocol fixture reconstructs this test-only AND
  # from the actual secret shares; all signed pair exchanges above are real.
  shares <- lapply(contract$compute_peers, function(peer) {
    states[[peer]]$.psi_padded_state$membership_sum_share
  })
  states[[reference]]$.psi_padded_state$global_membership_chunks <- list(
    `1` = .psi_padded_and_reference(shares[[1L]], shares[[2L]], 1L))
  final <- with_peer(reference, psiPaddedFinalPrepareDS(session_id))
  expect_identical(final$transports[[target]]$transport, "inline")
  aligned <- list()
  aligned[[reference]] <- with_peer(reference,
    psiPaddedFilterDS("D", session_id = session_id))
  aligned[[target]] <- with_peer(target, psiPaddedFilterDS("D",
    envelope = final$transports[[target]]$envelope, session_id = session_id))
  expect_setequal(aligned$alpha$id, c("p1", "p2"))
  expect_identical(aligned$alpha$value[match(c("p1", "p2"), aligned$alpha$id)],
    c(1L, 2L))
  for (peer in names(frames)) {
    attestation <- with_peer(peer,
      .psi_padded_validate_persistent_attestation(aligned[[peer]]))
    expect_identical(attestation$authorization_epochs, contract$authorization_epochs)
    retained <- with_peer(peer, .dsvert_dp_provenance_lookup(
      .psi_padded_authorization_public(descriptors[[peer]])))
    expect_identical(retained$descriptor, descriptors[[peer]])
    expect_identical(retained$epoch, states[[peer]]$.psi_padded_state$authorization_epoch)
  }
})
