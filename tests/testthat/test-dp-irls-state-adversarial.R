.irls_adversarial_stores <- function(f) {
  base <- tempfile("irls-adversarial-")
  dir.create(base, mode = "0700")
  peers <- unlist(f$spec$privacy_source$computation_peers, use.names = FALSE)
  paths <- setNames(file.path(base, peers, "state.sqlite"), peers)
  for (peer in peers) .dsvert_dp_irls_store_create(paths[[peer]], f$signed, f$pins, peer)
  list(base = base, paths = paths, peers = peers)
}
.irls_adversarial_prepare <- function(f, stores, t, predecessor, payload) {
  lapply(stores$peers, function(peer) .dsvert_dp_irls_successor_prepare(
    stores$paths[[peer]], f$signed, f$pins, t, predecessor, payload,
    f$identities[[peer]]$identity_sk))
}
.irls_adversarial_commit <- function(f, stores, pair) {
  result <- lapply(stores$paths, function(path)
    .dsvert_dp_irls_successor_commit(path, f$signed, f$pins, pair))
  expect_identical(.dsvert_dp_irls_state_json(result[[1L]]),
                   .dsvert_dp_irls_state_json(result[[2L]]))
  result[[1L]]
}

test_that("score-only successors require the latest committed H and retain its bytes", {
  f <- .irls_contract_fixture(); q <- .irls_q
  f$spec$path$T <- "3"
  f$spec$path$damping <- rep(list(q("1")), 3L)
  f$spec$path$trust <- rep(list(q("1")), 3L)
  f$spec$path$refresh_mask <- list("1", "1", "0")
  audit <- f$spec$accounting$stages[[3L]]; audit$t <- "3"
  f$spec$accounting$stages[[3L]] <- list(t = "2", purpose = "optimizer",
    g = q("1"), H = q("0"), epsilon = q("1"), alpha_g = q("1", "8"), alpha_H = q("0"))
  f$spec$accounting$stages[[4L]] <- audit
  f$spec$accounting$epsilon_path <- q("9")
  f$spec <- .dsvert_dp_irls_contract_normalize(f$spec); f$signed <- f$sign(f$spec)
  stores <- .irls_adversarial_stores(f)
  on.exit(unlink(stores$base, recursive = TRUE), add = TRUE)
  first <- .irls_adversarial_commit(f, stores, .irls_adversarial_prepare(f, stores,
    "0", .dsvert_dp_irls_start_digest(f$spec), f$payload()))
  next_payload <- f$payload(); next_payload$H[[1L]] <- "21"
  second <- .irls_adversarial_commit(f, stores, .irls_adversarial_prepare(f, stores,
    "1", first$body$payload_digest, next_payload))
  payload <- list(g = list("16", "16"), H_reference = first$body[c("stage_id", "payload_digest")])
  expect_error(.irls_adversarial_prepare(f, stores, "2", second$body$payload_digest, payload), "prior-H")
  payload$H_reference <- second$body[c("stage_id", "payload_digest")]
  bad <- payload; bad$H_reference$payload_digest <- first$body$payload_digest
  expect_error(.irls_adversarial_prepare(f, stores, "2", second$body$payload_digest, bad), "prior-H")
  pair <- .irls_adversarial_prepare(f, stores, "2", second$body$payload_digest, payload)
  third <- .irls_adversarial_commit(f, stores, pair)
  expect_null(third$body$payload[["H"]])
  expect_identical(third$body$update_input$h, next_payload$H)
  expect_identical(.dsvert_dp_irls_state_json(third$body$payload$H_reference),
                   .dsvert_dp_irls_state_json(payload$H_reference))
  expect_identical(.dsvert_dp_irls_state_json(.irls_adversarial_prepare(
    f, stores, "2", second$body$payload_digest, payload)[[1L]]),
    .dsvert_dp_irls_state_json(pair[[1L]]))
  accounting <- .dsvert_dp_irls_successor_accounting(stores$paths[[1L]], f$signed, f$pins)
  expect_identical(accounting$charged_epsilon, q("5"))
  expect_identical(accounting$stages[[3L]]$observed_lanes, list("g"))
})

test_that("a validly resigned epoch cannot splice into a committed predecessor", {
  f <- .irls_contract_fixture(); stores <- .irls_adversarial_stores(f)
  on.exit(unlink(stores$base, recursive = TRUE), add = TRUE)
  first <- .irls_adversarial_commit(f, stores, .irls_adversarial_prepare(f, stores,
    "0", .dsvert_dp_irls_start_digest(f$spec), f$payload()))
  fresh <- f$spec
  dep <- fresh$privacy_source$closure$dependencies[[1L]]$dependency
  dep$authorization_epoch <- strrep("c", 64L)
  dep$authorization_epochs[[1L]]$authorization_epoch <- dep$authorization_epoch
  fresh$privacy_source$closure$dependencies[[1L]]$dependency <- dep
  signed_fresh <- f$sign(fresh)
  expect_identical(.dsvert_dp_irls_contract_validate(signed_fresh, f$pins),
                   .dsvert_dp_irls_contract_normalize(fresh))
  for (peer in stores$peers) expect_error(.dsvert_dp_irls_successor_prepare(
    stores$paths[[peer]], signed_fresh, f$pins, "1", first$body$payload_digest,
    f$payload(), f$identities[[peer]]$identity_sk), "epoch splice")
  # Refused requests cannot damage the original reservation namespace.
  second <- .irls_adversarial_commit(f, stores, .irls_adversarial_prepare(f, stores,
    "1", first$body$payload_digest, f$payload()))
  expect_identical(second$body$root, first$body$root)
})

test_that("concurrent fork contenders produce exactly one durable successor", {
  skip_on_os("windows")
  f <- .irls_contract_fixture(); stores <- .irls_adversarial_stores(f)
  on.exit(unlink(stores$base, recursive = TRUE), add = TRUE)
  peer <- stores$peers[[1L]]; path <- stores$paths[[peer]]
  pred <- .dsvert_dp_irls_start_digest(f$spec)
  payloads <- list(f$payload(), f$payload()); payloads[[2L]]$g[[1L]] <- "17"
  results <- parallel::mclapply(payloads, function(payload) tryCatch({
    value <- .dsvert_dp_irls_successor_prepare(path, f$signed, f$pins, "0", pred,
      payload, f$identities[[peer]]$identity_sk)
    list(ok = TRUE, bytes = .dsvert_dp_irls_state_json(value))
  }, error = function(e) list(ok = FALSE, error = conditionMessage(e))), mc.cores = 2L)
  success <- vapply(results, `[[`, logical(1L), "ok")
  expect_identical(sum(success), 1L)
  expect_match(results[[which(!success)]]$error, "fork")
  winner <- which(success)
  replay <- .dsvert_dp_irls_successor_prepare(path, f$signed, f$pins, "0", pred,
    payloads[[winner]], f$identities[[peer]]$identity_sk)
  expect_identical(.dsvert_dp_irls_state_json(replay), results[[winner]]$bytes)
  expect_identical(.dsvert_dp_irls_successor_accounting(path, f$signed, f$pins)$charged_epsilon,
                   .irls_q("2"))
})
