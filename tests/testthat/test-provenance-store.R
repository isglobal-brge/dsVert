.provenance_store_fixture <- function(env = parent.frame()) {
  path <- tempfile('authorization-store-')
  dir.create(path, mode = '0700')
  withr::local_envvar(c(DSVERT_STATE_DIR = path), .local_envir = env)
  withr::local_options(list(dsvert.identity_seed =
    jsonlite::base64_enc(as.raw(rep(193L, 32L))),
    dsvert.dp.provenance_store_uuid = NULL,
    dsvert.dp.provenance_record_bytes = 8192,
    dsvert.dp.provenance_store_bytes = 16384), .local_envir = env)
  list(public = list(kind = 'test-source', id = 'cohort', version = 'v1'),
       descriptor = list(id = 'cohort', version = 'v1'),
       data = data.frame(id = c('p1', 'p2'), value = c(1, 2)))
}

test_that('authorization event retries retain original material without reading replacements', {
  f <- .provenance_store_fixture()
  first <- .dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
                                       event_id = 'event-1')
  retry <- .dsvert_dp_provenance_source(f$public, stop('descriptor read'),
    stop('data read'), event_id = 'event-1')
  expect_identical(retry, first)
  second <- .dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
                                        event_id = 'event-2')
  expect_false(identical(first$epoch, second$epoch))
  expect_identical(first$snapshot_sha256, second$snapshot_sha256)
  expect_identical(.dsvert_dp_provenance_lookup(f$public, first$epoch), first)
  expect_identical(.dsvert_dp_provenance_lookup(f$public), second)
  expect_error(.dsvert_dp_provenance_source(f$public, f$descriptor,
    stop('capacity must precede private inspection'), event_id = 'event-3'),
    'no capacity')
  expect_identical(.dsvert_dp_provenance_lookup(f$public), second)
})

test_that('authorization MAC and deletion failures never recreate old epochs', {
  f <- .provenance_store_fixture()
  first <- .dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
                                       event_id = 'event-1')
  paths <- .dsvert_dp_provenance_paths()
  bytes <- readBin(paths$file, 'raw', file.info(paths$file)$size)
  changed <- bytes; changed[length(changed)] <- as.raw(bitwXor(
    as.integer(changed[length(changed)]), 1L))
  writeBin(changed, paths$file)
  expect_error(.dsvert_dp_provenance_lookup(f$public), 'custodian recovery')
  expect_error(.dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
    automatic = TRUE), 'custodian recovery')
  writeBin(bytes, paths$file)
  expect_identical(.dsvert_dp_provenance_lookup(f$public), first)
  unlink(paths$file)
  expect_error(.dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
    automatic = TRUE), 'custodian recovery')
})

test_that('external expected authorization UUID detects a lost complete store', {
  f <- .provenance_store_fixture()
  .dsvert_dp_provenance_source(f$public, f$descriptor, f$data, event_id='event-1')
  uuid <- dsvertListSourceAuthorizations()$uuid
  withr::local_options(list(dsvert.dp.provenance_store_uuid = uuid))
  paths <- .dsvert_dp_provenance_paths()
  unlink(c(paths$file, paths$marker))
  expect_error(.dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
    automatic = TRUE), 'custodian recovery')
})

test_that('unregistered legacy imports reject without inspecting current content', {
  f <- .provenance_store_fixture()
  expect_error(.dsvert_dp_provenance_source(f$public, f$descriptor,
    stop('must not inspect current intersection')), 'authorization migration required')
  expect_null(dsvertListSourceAuthorizations())
})

test_that('authorization administration is absent from the analyst allowlist', {
  remote <- .dsvert_registered_remote_methods(.dsvert_test_package_file("DESCRIPTION"))
  expect_false(any(c("dsvertAuthorizeSource", "dsvertReauthorizeSource",
    "dsvertListSourceAuthorizations") %in% remote))
})

test_that('provenance hashing is independent of named field insertion order', {
  left <- list(kind="source", recipe=list(policy="v1", epochs=list(
    list(peer_identity="alice", authorization_epoch="epoch"))))
  right <- list(recipe=list(epochs=list(list(authorization_epoch="epoch",
    peer_identity="alice")), policy="v1"), kind="source")
  expect_identical(.dsvert_dp_provenance_hash("test/v1|", left),
                   .dsvert_dp_provenance_hash("test/v1|", right))
})

test_that('concurrent retries publish exactly one durable authorization', {
  skip_on_os("windows")
  f <- .provenance_store_fixture()
  jobs <- lapply(1:2, function(i) parallel::mcparallel(
    .dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
                               event_id="concurrent-event")))
  result <- unname(parallel::mccollect(jobs))
  expect_length(result, 2L)
  expect_true(all(vapply(result, is.list, logical(1L))))
  expect_identical(result[[1L]], result[[2L]])
  expect_identical(.dsvert_dp_provenance_lookup(f$public), result[[1L]])
  expect_length(dsvertListSourceAuthorizations()$sources, 1L)
})

test_that('explicit events cannot alias the automatic registration event', {
  f <- .provenance_store_fixture()
  automatic <- suppressMessages(.dsvert_dp_provenance_source(
    f$public, f$descriptor, f$data, automatic=TRUE))
  explicit <- .dsvert_dp_provenance_source(f$public, f$descriptor, f$data,
    event_id="automatic-first-registration")
  expect_false(identical(automatic$epoch, explicit$epoch))
})
