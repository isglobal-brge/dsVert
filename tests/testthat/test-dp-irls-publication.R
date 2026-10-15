.irls_publication_fixture <- function() {
  f <- .irls_smoke_fixture()
  base <- tempfile("irls-publication-"); dir.create(base, mode = "0700")
  f$base <- base
  f$state <- setNames(file.path(base, paste0(names(f$pins), "-state"), "state.sqlite"), names(f$pins))
  f$pub <- setNames(file.path(base, paste0(names(f$pins), "-pub"), "publication.sqlite"), names(f$pins))
  for (peer in names(f$pins)) {
    .dsvert_dp_irls_store_create(f$state[[peer]], f$signed, f$pins, peer)
    .dsvert_dp_irls_publication_create(f$pub[[peer]], f$signed, f$pins, peer)
  }
  f
}

test_that("every durable publication boundary replays identical bytes", {
  f <- .irls_publication_fixture(); on.exit(unlink(f$base, recursive = TRUE), add = TRUE)
  pred <- .dsvert_dp_irls_start_digest(f$spec)
  json <- .dsvert_dp_irls_state_json
  lanes <- list(); commits <- list(); stages <- list(); parents <- list()
  read <- function(peer) .dsvert_dp_irls_publication_read(f$pub[[peer]], f$signed, f$pins)
  for (lane in c("g", "H")) {
    lanes[[lane]] <- lapply(names(f$pins), function(peer) {
      call <- function(crash = FALSE) .dsvert_dp_irls_lane_prepare(f$pub[[peer]],
        f$signed, f$pins, "0", pred, lane, f$payload()[[lane]],
        f$identities[[peer]]$identity_sk, crash_after = crash)
      expect_error(call(TRUE), "durable lane PREPARE")
      receipt <- call(); expect_identical(json(receipt), json(call()))
      expect_identical(read(peer), list())
      receipt
    })
    commits[[lane]] <- lapply(names(f$pins), function(peer) {
      call <- function(crash = FALSE) .dsvert_dp_irls_lane_commit(f$pub[[peer]],
        f$signed, f$pins, lanes[[lane]], f$identities[[peer]]$identity_sk, crash_after = crash)
      expect_error(call(TRUE), "durable lane COMMIT")
      receipt <- call(); expect_identical(json(receipt), json(call()))
      expect_identical(read(peer), list())
      receipt
    })
  }
  for (peer in names(f$pins)) {
    call <- function(crash = FALSE) .dsvert_dp_irls_parent_prepare(f$pub[[peer]],
      f$state[[peer]], f$signed, f$pins, "0", pred, commits,
      f$identities[[peer]]$identity_sk, crash_after = crash)
    expect_error(call("barrier"), "durable lane BARRIER")
    expect_error(call(TRUE), "durable IRLS PREPARE")
    stages[[peer]] <- call()
    expect_identical(json(stages[[peer]]), json(call()))
    expect_identical(read(peer), list())
  }
  for (peer in names(f$pins)) {
    call <- function(crash = FALSE) .dsvert_dp_irls_parent_commit(f$pub[[peer]],
      f$state[[peer]], f$signed, f$pins, stages, f$identities[[peer]]$identity_sk,
      crash_after = crash)
    expect_error(call("successor-commit"), "durable successor COMMIT")
    expect_error(call(TRUE), "durable parent COMMIT")
    parents[[peer]] <- call()
    expect_identical(json(parents[[peer]]), json(call()))
    expect_identical(read(peer), list())
  }
  for (peer in names(f$pins)) {
    call <- function(crash = FALSE) .dsvert_dp_irls_parent_publish(f$pub[[peer]],
      f$signed, f$pins, parents, crash_after = crash)
    expect_error(call(TRUE), "durable PUBLICATION")
    stage <- call(); expect_identical(json(stage), json(call()))
    expect_identical(json(read(peer)), json(list(stage)))
    next_plan <- .dsvert_dp_irls_stage_plan(f$state[[peer]], f$signed, f$pins, "1", stage$body$payload_digest)
    expect_identical(next_plan$beta, list("0", "0", "0"))
  }
  expect_identical(json(read(names(f$pins)[[1L]])), json(read(names(f$pins)[[2L]])))
})

test_that("a lane or one authority cannot cross the parent barrier", {
  f <- .irls_publication_fixture(); on.exit(unlink(f$base, recursive = TRUE), add = TRUE)
  peer <- names(f$pins)[[1L]]; pred <- .dsvert_dp_irls_start_digest(f$spec)
  receipt <- .dsvert_dp_irls_lane_prepare(f$pub[[peer]], f$signed, f$pins,
    "0", pred, "g", f$payload()$g, f$identities[[peer]]$identity_sk)
  expect_error(.dsvert_dp_irls_lane_commit(f$pub[[peer]], f$signed, f$pins,
    list(receipt, receipt), f$identities[[peer]]$identity_sk), "authorities")
  expect_error(.dsvert_dp_irls_parent_prepare(f$pub[[peer]], f$state[[peer]],
    f$signed, f$pins, "0", pred, list(g = list(receipt, receipt), H = list()),
    f$identities[[peer]]$identity_sk), "boundary")
  expect_identical(.dsvert_dp_irls_publication_read(f$pub[[peer]], f$signed, f$pins), list())
  changed <- f$payload()$g; changed[[1L]] <- as.character(as.integer(changed[[1L]]) + 1L)
  expect_error(.dsvert_dp_irls_lane_prepare(f$pub[[peer]], f$signed, f$pins,
    "0", pred, "g", changed, f$identities[[peer]]$identity_sk), "replay conflicts")
  unlink(f$pub[[peer]])
  expect_error(.dsvert_dp_irls_publication_read(f$pub[[peer]], f$signed, f$pins), "missing")
  expect_error(.dsvert_dp_irls_publication_create(f$pub[[peer]], f$signed, f$pins, peer), "already provisioned")
})

test_that("signed translation subtracts A and refuses either finalizer endpoint", {
  f <- .irls_smoke_fixture(); payload <- f$payload()
  payload$g[[1L]] <- as.character(gmp::as.bigz(payload$g[[1L]]) - 4096L)
  payload$H[[2L]] <- as.character(gmp::as.bigz(payload$H[[2L]]) - 2048L)
  decoded <- .dsvert_dp_irls_decode_payload(f$spec, "0", payload)
  expect_equal(.dsvert_dp_irls_bigq(decoded$values$g[[1L]]), gmp::as.bigq(-1))
  expect_equal(.dsvert_dp_irls_bigq(decoded$values$H[[2L]]), gmp::as.bigq(-1, 2))
  expect_false(decoded$inference_refused)
  for (t in c("0", "2")) for (lane in c("g", "H")) for (upper in c(FALSE, TRUE)) {
    p <- payload; p[[lane]][[1L]] <- if (upper) f$spec$numeric$upper_limits[[lane]][[1L]] else "0"
    d <- .dsvert_dp_irls_decode_payload(f$spec, t, p)
    expect_true(d$endpoint_hits[[lane]][[1L]]); expect_true(d$inference_refused)
    expected <- gmp::as.bigq(f$spec$numeric$translation[[lane]][[1L]], 4096L) * if (upper) 1L else -1L
    expect_equal(.dsvert_dp_irls_bigq(d$values[[lane]][[1L]]), expected)
  }
})
