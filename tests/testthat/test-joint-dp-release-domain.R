.release_domain_connection <- function() {
  connection <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
  DBI::dbExecute(connection, paste(
    "CREATE TABLE vector_meta (key TEXT PRIMARY KEY,",
    "value TEXT NOT NULL,row_mac TEXT NOT NULL)"))
  connection
}

.release_domain_entropy <- function(values) {
  index <- 0L
  function(size) {
    expect_identical(size, 32L)
    index <<- index + 1L
    if (index > length(values)) stop("unexpected entropy request")
    values[[index]]
  }
}

test_that("release domain is random, durable and data independent", {
  connection <- .release_domain_connection()
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  secret <- as.raw(seq_len(32L))
  calls <- 0L
  entropy <- function(size) {
    calls <<- calls + 1L
    expect_identical(size, 32L)
    as.raw(rep(17L, size))
  }

  first <- .dsvert_joint_dp_release_domain_load_connection(
    connection, secret, entropy)
  second <- .dsvert_joint_dp_release_domain_load_connection(
    connection, secret, function(...) stop("durable domain rerolled"))

  expect_identical(first, second)
  expect_identical(calls, 1L)
  expect_identical(first$generation, 1)
  expect_identical(first$domain_id,
                   paste0("rd_", paste(rep("11", 32L), collapse = "")))
  expect_null(first$previous_domain_id)
  expect_false(any(grepl(
    "snapshot|patient|dataset|cohort", names(first), ignore.case = TRUE)))
  public <- .dsvert_joint_dp_release_domain_public(first)
  expect_identical(public$snapshot_derived, FALSE)
  expect_identical(public$key_material_exposed, FALSE)
  expect_false("previous_domain_id" %in% names(public))
})

test_that("release-domain rotation is atomic and stale retries are idempotent", {
  connection <- .release_domain_connection()
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  secret <- as.raw(seq_len(32L))
  entropy <- .release_domain_entropy(list(
    as.raw(rep(1L, 32L)), as.raw(rep(2L, 32L))))
  current <- .dsvert_joint_dp_release_domain_load_connection(
    connection, secret, entropy)

  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  rotated <- .dsvert_joint_dp_release_domain_rotate_connection(
    connection, secret, current$domain_id,
    "durable_final_chunk_unavailable", entropy)
  DBI::dbCommit(connection)
  expect_identical(rotated$generation, 2)
  expect_identical(rotated$rotation_count, 1)
  expect_identical(rotated$previous_domain_id, current$domain_id)
  expect_false(identical(rotated$domain_id, current$domain_id))

  stale <- .dsvert_joint_dp_release_domain_rotate_connection(
    connection, secret, current$domain_id,
    "durable_final_chunk_unavailable",
    function(...) stop("stale retry rerolled the domain"))
  expect_identical(stale, rotated)
  expect_identical(
    .dsvert_joint_dp_release_domain_load_connection(
      connection, secret, function(...) stop("durable domain rerolled")),
    rotated)
})

test_that("release-domain corruption recovers with fresh randomness", {
  connection <- .release_domain_connection()
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  secret <- as.raw(seq_len(32L))
  first <- .dsvert_joint_dp_release_domain_load_connection(
    connection, secret, function(size) as.raw(rep(3L, size)))
  DBI::dbExecute(connection, paste(
    "UPDATE vector_meta SET value = replace(value, 'first_vector_store',",
    "'forged_vector_store') WHERE key='release_domain'"))
  recovered <- .dsvert_joint_dp_release_domain_load_connection(
    connection, secret, function(size) as.raw(rep(8L, size)))
  expect_false(identical(recovered$domain_id, first$domain_id))
  expect_identical(recovered$reason, "corrupt_record_recovery")
  expect_identical(recovered$generation, 1)
  expect_identical(
    .dsvert_joint_dp_release_domain_load_connection(
      connection, secret, function(...) stop("recovery was not durable")),
    recovered)
})

test_that("a newly created vector store receives a fresh release domain", {
  secret <- as.raw(seq_len(32L))
  first_connection <- .release_domain_connection()
  second_connection <- .release_domain_connection()
  on.exit(DBI::dbDisconnect(first_connection), add = TRUE)
  on.exit(DBI::dbDisconnect(second_connection), add = TRUE)
  first <- .dsvert_joint_dp_release_domain_load_connection(
    first_connection, secret, function(size) as.raw(rep(4L, size)))
  second <- .dsvert_joint_dp_release_domain_load_connection(
    second_connection, secret, function(size) as.raw(rep(5L, size)))
  expect_false(identical(first$domain_id, second$domain_id))
  expect_identical(first$generation, second$generation)
})
