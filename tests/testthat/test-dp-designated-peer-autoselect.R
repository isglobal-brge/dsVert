test_that("missing noise-peer override deterministically selects two pinned peers", {
  pins <- c(site_e = "e", site_c = "c", site_a = "a",
            site_d = "d", site_b = "b")
  expect_identical(
    .dsvert_dp_resolve_designated_noise_peers(NULL, pins),
    c("site_a", "site_b"))
  expect_identical(
    .dsvert_dp_resolve_designated_noise_peers(
      c("site_e", "site_c"), pins),
    c("site_c", "site_e"))
  expect_error(
    .dsvert_dp_resolve_designated_noise_peers(
      c("site_a", "missing"), pins),
    "designated_noise_peers")
  expect_error(
    .dsvert_dp_resolve_designated_noise_peers(
      c("site_a", "site_a"), pins),
    "designated_noise_peers")
})

test_that("K=3 through K=5 contexts bind the same automatic pair", {
  make_pk <- function(offset) {
    gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(((seq_len(32L) + offset - 1L) %% 255L) + 1L)))
  }
  for (k in 3:5) {
    names_k <- paste0("site_", letters[seq_len(k)])
    pins <- stats::setNames(vapply(
      seq_len(k), make_pk, character(1L)), names_k)
    pins <- pins[order(names(pins), method = "radix")]
    normalized_pins <- vapply(
      pins, .dsvert_relay_normalize_identity_pk, character(1L))
    policy <- list(
      domain = "automatic-peer-test",
      cohort_id = "cohort-v1",
      peer_name = "site_a",
      peer_pinset = pins,
      peer_pinset_sha256 = digest::digest(
        .dsvert_dp_canonical_json(as.list(normalized_pins)), algo = "sha256",
        serialize = FALSE),
      peer_count = as.integer(k),
      designated_noise_peers = NULL,
      global_total_epsilon = 1,
      global_total_delta = 2^-100,
      lifetime_max_distinct_capsules = 8,
      adjacency = "add_remove_patient",
      patient_column = "patient_id",
      unit_capacity = 1000L,
      max_records_per_unit = 1L,
      overflow_policy = "reject_snapshot",
      noise_root = list(epoch = 1, key_id = "automatic-root-v1"),
      ledger_path = tempfile("automatic-peer-ledger-"))
    context <- .dsvert_joint_dp_policy_context(
      policy, require_designated = FALSE)
    expect_identical(
      context$common$designated_noise_peers,
      c("site_a", "site_b"))
    expect_identical(as.numeric(context$common$peer_count), as.numeric(k))
    expect_identical(names(context$pins), c("site_a", "site_b"))
  }
})
