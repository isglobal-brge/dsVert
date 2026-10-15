.irls_state_stores <- function(f) {
  base <- tempfile("irls-state-")
  dir.create(base, mode = "0700")
  peers <- unlist(f$spec$privacy_source$computation_peers, use.names = FALSE)
  paths <- stats::setNames(file.path(base, peers, "reservations.sqlite"), peers)
  for (peer in peers)
    .dsvert_dp_irls_store_create(paths[[peer]], f$signed, f$pins, peer)
  list(base = base, paths = paths, peers = peers)
}

.irls_state_prepare_pair <- function(f, stores, t, predecessor, payload) {
  lapply(stores$peers, function(peer) .dsvert_dp_irls_successor_prepare(
    stores$paths[[peer]], f$signed, f$pins, t, predecessor, payload,
    f$identities[[peer]]$identity_sk))
}

.irls_state_commit_pair <- function(f, stores, pair) {
  results <- lapply(stores$paths, function(path)
    .dsvert_dp_irls_successor_commit(path, f$signed, f$pins, pair))
  expect_identical(.dsvert_dp_irls_state_json(results[[1L]]),
                   .dsvert_dp_irls_state_json(results[[2L]]))
  results[[1L]]
}

test_that("authorities recompute, reserve one successor and replay durable bytes", {
  f <- .irls_contract_fixture()
  s <- .irls_state_stores(f)
  on.exit(unlink(s$base, recursive = TRUE), add = TRUE)
  pred <- .dsvert_dp_irls_start_digest(f$spec)
  payload <- f$payload("0")
  peer <- s$peers[[1L]]
  prepare <- function(...) .dsvert_dp_irls_successor_prepare(
    s$paths[[peer]], f$signed, f$pins, "0", pred, payload,
    f$identities[[peer]]$identity_sk, ...)
  expect_error(prepare(crash_after_prepare = TRUE), "Simulated crash")
  retained <- prepare()
  expect_identical(.dsvert_dp_irls_state_json(retained),
                   .dsvert_dp_irls_state_json(prepare()))
  bad_beta <- f$spec$path$start$beta
  bad_beta[[1L]] <- list(d = "1", n = "1")
  expect_error(prepare(candidate_beta = bad_beta), "Alternate IRLS beta")
  changed <- payload
  changed$g[[1L]] <- as.character(gmp::as.bigz(changed$g[[1L]]) + 1L)
  expect_error(.dsvert_dp_irls_successor_prepare(s$paths[[peer]], f$signed,
    f$pins, "0", pred, changed, f$identities[[peer]]$identity_sk), "fork")
  expect_error(.dsvert_dp_irls_successor_prepare(s$paths[[peer]], f$signed,
    f$pins, "0", strrep("f", 64L), payload,
    f$identities[[peer]]$identity_sk), "predecessor")
  pair <- .irls_state_prepare_pair(f, s, "0", pred, payload)
  expect_identical(.dsvert_dp_irls_state_json(pair[[1L]]$body),
                   .dsvert_dp_irls_state_json(pair[[2L]]$body))
  next_pred <- pair[[1L]]$body$payload_digest
  expect_error(.irls_state_prepare_pair(f, s, "1", next_pred, f$payload("1")),
               "dual-committed")
  expect_error(.dsvert_dp_irls_successor_commit(s$paths[[peer]], f$signed,
    f$pins, pair, crash_after_commit = TRUE), "Simulated crash")
  stage <- .irls_state_commit_pair(f, s, pair)
  expect_identical(.dsvert_dp_irls_state_json(stage),
    .dsvert_dp_irls_state_json(.dsvert_dp_irls_successor_commit(
      s$paths[[peer]], f$signed, f$pins, pair)))
  pair1 <- .irls_state_prepare_pair(f, s, "1", next_pred, f$payload("1"))
  stage1 <- .irls_state_commit_pair(f, s, pair1)
  audit <- .irls_state_prepare_pair(f, s, "2", stage1$body$payload_digest,
                                   f$payload("2"))
  terminal <- .irls_state_commit_pair(f, s, audit)
  expect_identical(terminal$body$purpose, "terminal-audit")
  expect_null(terminal$body$update_result)
  expect_identical(terminal$body$beta, stage1$body$update_result$beta)
  expect_error(.irls_state_prepare_pair(f, s, "3", terminal$body$payload_digest,
                                       f$payload("2")))
})

test_that("pins, signatures, epochs and durable state fail closed", {
  f <- .irls_contract_fixture()
  s <- .irls_state_stores(f)
  on.exit(unlink(s$base, recursive = TRUE), add = TRUE)
  peer <- s$peers[[1L]]
  pred <- .dsvert_dp_irls_start_digest(f$spec)
  pair <- .irls_state_prepare_pair(f, s, "0", pred, f$payload("0"))
  bad <- pair
  bad[[2L]]$signatures[[1L]] <- strrep("A", 86L)
  expect_error(.dsvert_dp_irls_successor_commit(s$paths[[peer]], f$signed,
    f$pins, bad), "signature")
  bad <- pair
  bad[[2L]]$body$update_result$k <- "999"
  expect_error(.dsvert_dp_irls_successor_commit(s$paths[[peer]], f$signed,
    f$pins, bad), "disagree")
  pins <- f$pins
  pins[[1L]] <- pins[[2L]]
  expect_error(.dsvert_dp_irls_successor_prepare(s$paths[[peer]], f$signed,
    pins, "0", pred, f$payload("0"), f$identities[[peer]]$identity_sk))
  epoch <- f$spec
  epoch$privacy_source$closure$dependencies[[1L]]$dependency$authorization_epoch <-
    strrep("e", 64L)
  epoch$privacy_source$closure$dependencies[[1L]]$dependency$authorization_epochs[[1L]]$authorization_epoch <-
    strrep("e", 64L)
  signed_epoch <- f$sign(epoch)
  expect_error(.dsvert_dp_irls_successor_prepare(s$paths[[peer]], signed_epoch,
    f$pins, "0", pred, f$payload("0"), f$identities[[peer]]$identity_sk),
    "epoch splice")
  accounting <- .dsvert_dp_irls_successor_accounting(s$paths[[peer]],
                                                   f$signed, f$pins)
  expect_identical(accounting,
    .dsvert_dp_irls_accounting(f$spec, list(list(t = "0", lanes = list("g", "H")))))
  db <- DBI::dbConnect(RSQLite::SQLite(), s$paths[[peer]])
  DBI::dbExecute(db, "DELETE FROM successors")
  DBI::dbDisconnect(db)
  expect_error(.dsvert_dp_irls_successor_prepare(s$paths[[peer]], f$signed,
    f$pins, "0", pred, f$payload("0"), f$identities[[peer]]$identity_sk))
  unlink(s$paths[[peer]])
  expect_error(.dsvert_dp_irls_successor_prepare(s$paths[[peer]], f$signed,
    f$pins, "0", pred, f$payload("0"), f$identities[[peer]]$identity_sk), "missing")
  expect_error(.dsvert_dp_irls_store_create(s$paths[[peer]], f$signed, f$pins, peer),
               "already provisioned")
})
