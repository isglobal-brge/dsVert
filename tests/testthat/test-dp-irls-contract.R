test_that("IRLS signed contract normalizes every numeric field without floating point", {
  f <- .irls_contract_fixture()
  expect_identical(.dsvert_dp_irls_contract_validate(f$signed, f$pins), f$spec)
  parsed <- jsonlite::fromJSON(.dsvert_dp_irls_json(f$signed), simplifyVector = FALSE)
  expect_identical(.dsvert_dp_irls_contract_validate(parsed, f$pins), f$spec)
  s <- f$spec; s$path$floor <- .irls_q("2", "2")
  expect_identical(.dsvert_dp_irls_contract_normalize(s), f$spec)
  signed <- f$signed; signed$contract <- s
  expect_error(.dsvert_dp_irls_contract_validate(signed, f$pins), "noncanonical")
  for (bad in list(1, 1L, TRUE, NA_character_, NaN, Inf, "-0", "+1", "01", "1.0", "1e0")) {
    s <- f$spec; s$path$T <- bad
    expect_error(.dsvert_dp_irls_contract_normalize(s))
  }
  for (bad in list(.irls_q("1", "0"), .irls_q("0", "-1"), list(d = "1", n = "1", extra = "1"))) {
    s <- f$spec; s$path$floor <- bad
    expect_error(.dsvert_dp_irls_contract_normalize(s))
  }
  s <- f$spec[rev(names(f$spec))]
  expect_identical(.dsvert_dp_irls_contract_normalize(s), f$spec)
})

test_that("IRLS fails closed when any required signed field is absent", {
  f <- .irls_contract_fixture()
  paths <- list()
  collect <- function(x, path = character()) {
    if (!is.list(x)) return(invisible(NULL))
    for (i in seq_along(x)) {
      part <- if (is.null(names(x))) as.character(i) else names(x)[[i]]
      nextpath <- c(path, part)
      if (!is.null(names(x))) paths[[length(paths) + 1L]] <<- nextpath
      collect(x[[i]], nextpath)
    }
  }
  collect(f$spec)
  remove <- function(x, path) {
    key <- if (is.null(names(x))) as.integer(path[[1L]]) else path[[1L]]
    if (length(path) == 1L) x[[key]] <- NULL else x[[key]] <- remove(x[[key]], path[-1L])
    x
  }
  for (path in paths) expect_error(.dsvert_dp_irls_contract_normalize(remove(f$spec, path)),
    info = paste(path, collapse = "/"))
  s <- f$spec; s$unknown <- "1"
  expect_error(.dsvert_dp_irls_contract_normalize(s), "fields")
})

test_that("IRLS identities bind full epochs, purposes, versions and signed payload order", {
  f <- .irls_contract_fixture(); s <- f$spec
  root <- .dsvert_dp_irls_root(s); start <- .dsvert_dp_irls_start_digest(s)
  k <- .dsvert_dp_irls_stage_id(s, "0", start)
  expect_identical(root, .dsvert_dp_irls_root(s[rev(names(s))]))
  expect_identical(k, .dsvert_dp_irls_stage_id(s, "0", start, "optimizer"))
  expect_error(.dsvert_dp_irls_stage_id(s, "0", start, "terminal-audit"), "purpose")
  expect_error(.dsvert_dp_irls_stage_id(s, "0", root), "initial predecessor")
  expect_error(.dsvert_dp_irls_stage_id(s, "3", root), "stage number")
  expect_false(identical(k, .dsvert_dp_irls_stage_id(s, "2", root)))
  expect_identical(.dsvert_dp_irls_lane_id(k, "g"), list(lane = "g", stage_id = k))
  expect_false(identical(.dsvert_dp_irls_lane_id(k, "g"), .dsvert_dp_irls_lane_id(k, "H")))
  expect_error(.dsvert_dp_irls_lane_id(k, "loss"))
  original <- .dsvert_dp_irls_payload_digest(s, "0", f$payload())
  payload <- f$payload(); payload$H[[2L]] <- "15"
  expect_false(identical(original, .dsvert_dp_irls_payload_digest(s, "0", payload)))
  payload <- f$payload(); payload$g[[1L]] <- "-1"
  expect_error(.dsvert_dp_irls_payload_digest(s, "0", payload), "range")
  payload <- f$payload(); payload$g[[1L]] <- "33"
  expect_error(.dsvert_dp_irls_payload_digest(s, "0", payload), "range")
  # Membership-only dependencies participate in the root, despite no model column.
  idx <- match("membership", unlist(s$privacy_source$source_ids))
  s$privacy_source$closure$dependencies[[idx]]$dependency$authorization_epoch <- root
  s$privacy_source$closure$dependencies[[idx]]$dependency$authorization_epochs[[1L]]$authorization_epoch <- root
  expect_false(identical(root, .dsvert_dp_irls_root(s)))
  s <- f$spec; s$numeric$compiler_version <- "synthetic-compiler-v2"
  expect_false(identical(root, .dsvert_dp_irls_root(s)))
  s <- f$spec; s$privacy_source$source_ids <- s$privacy_source$source_ids[-idx]
  expect_error(.dsvert_dp_irls_contract_normalize(s), "complete source vector")
})

test_that("IRLS split accounting includes terminal audit, pilot and partial lanes exactly", {
  f <- .irls_contract_fixture(); s <- f$spec
  report <- .dsvert_dp_irls_accounting(s)
  expect_identical(report$epsilon_path, .irls_q("8"))
  expect_identical(report$charged_epsilon, .irls_q("0"))
  report <- .dsvert_dp_irls_accounting(s, list(list(t = "0", lanes = list("g")),
    list(t = "0", lanes = list("g"))))
  expect_identical(report$charged_epsilon, .irls_q("1"))
  expect_identical(report$stages[[1L]]$status, "partial")
  expect_identical(report$reserved_epsilon, .irls_q("8"))
  report <- .dsvert_dp_irls_accounting(s, lapply(0:2, function(t) list(t = as.character(t), lanes = list("g", "H"))))
  expect_identical(report$charged_epsilon, .irls_q("8"))
  for (epsilon in c("7", "9")) {
    x <- s; x$accounting$epsilon_path <- .irls_q(epsilon)
    expect_error(.dsvert_dp_irls_contract_normalize(x), "allocation sum")
  }
  x <- s; x$accounting$stages[[1L]]$alpha_g <- .irls_q("1", "4")
  expect_error(.dsvert_dp_irls_contract_normalize(x), "lane alpha")
  x <- s; x$accounting$sensitivity$g <- "7"
  expect_error(.dsvert_dp_irls_contract_normalize(x), "sensitivity")
  x <- s; x$accounting$stages[[1L]]$epsilon <- .irls_q("1")
  expect_error(.dsvert_dp_irls_contract_normalize(x), "stage allocation")
  x <- s; x$path$start$kind <- "pilot"; x$path$start$epsilon <- .irls_q("1", "3")
  x$path$start$digest <- .dsvert_dp_irls_root(s); x$path$start$composition_sha256 <- .dsvert_dp_irls_start_digest(s)
  x$accounting$pilot_epsilon <- .irls_q("1", "3")
  x$accounting$auxiliary <- list(list(id = "prior-model-selection", epsilon = .irls_q("1", "7")))
  x$accounting$epsilon_path <- .irls_q("178", "21")
  report <- .dsvert_dp_irls_accounting(x, observed_auxiliary = list("prior-model-selection"))
  expect_identical(report$charged_epsilon, .irls_q("10", "21"))
  expect_identical(report$reservation_refund, .irls_q("0"))
})

test_that("IRLS score-only stages require a signed retained curvature reference", {
  f <- .irls_contract_fixture(); s <- f$spec
  s$path$refresh_mask[[2L]] <- "0"
  s$accounting$stages[[2L]]$H <- .irls_q("0")
  s$accounting$stages[[2L]]$alpha_H <- .irls_q("0")
  s$accounting$stages[[2L]]$epsilon <- .irls_q("1")
  s$accounting$epsilon_path <- .irls_q("7")
  s <- .dsvert_dp_irls_contract_normalize(s)
  expect_error(.dsvert_dp_irls_payload_digest(s, "1", f$payload()), "fields")
  payload <- list(g = list("16", "16"), H_reference = list(stage_id = .dsvert_dp_irls_stage_id(s, "0", .dsvert_dp_irls_start_digest(s)),
    payload_digest = .dsvert_dp_irls_payload_digest(s, "0", f$payload())))
  digest <- .dsvert_dp_irls_payload_digest(s, "1", payload)
  expect_identical(digest, .dsvert_dp_irls_hash("dsvert-v3-irls-public-payload-v1",
    list(list(lane = "g", values = payload$g), list(lane = "H", reference = payload$H_reference))))
  payload$H_reference$payload_digest <- .dsvert_dp_irls_root(s)
  expect_false(identical(digest, .dsvert_dp_irls_payload_digest(s, "1", payload)))
  expect_error(.dsvert_dp_irls_accounting(s, list(list(t = "1", lanes = list("H")))), "observed lane")
  expect_identical(.dsvert_dp_irls_accounting(s, list(list(t = "1", lanes = list("g"))))$stages[[2L]]$status, "complete")
})

test_that("IRLS rejects signature/pin, source, resource and path inconsistencies", {
  f <- .irls_contract_fixture()
  signed <- f$signed; signed$signatures$peer_a <- signed$signatures$peer_b
  expect_error(.dsvert_dp_irls_contract_validate(signed, f$pins), "signature")
  signed <- f$signed; signed$signatures$peer_b <- NULL
  expect_error(.dsvert_dp_irls_contract_validate(signed, f$pins), "unanimous")
  pins <- f$pins[c(2L, 1L)]; names(pins) <- names(f$pins)
  expect_error(.dsvert_dp_irls_contract_validate(f$signed, pins), "external pins")
  for (field in names(f$spec$numeric$certificate)) {
    s <- f$spec; s$numeric$certificate[[field]] <- as.character(gmp::as.bigz(s$numeric$certificate[[field]]) + 1)
    s$numeric$certificate_sha256 <- .dsvert_dp_irls_hash("dsvert-v3-irls-numeric-certificate-v1", s$numeric$certificate)
    expect_error(.dsvert_dp_irls_contract_normalize(s), "certificate")
  }
  mutations <- list(
    function(s) {s$numeric$translation$g[[1L]] <- "15"; s},
    function(s) {s$numeric$upper_limits$H[[1L]] <- "31"; s},
    function(s) {s$numeric$layout <- rev(s$numeric$layout); s},
    function(s) {s$numeric$rounding_slack$H <- .irls_q("0"); s},
    function(s) {s$path$box$lower[[1L]] <- .irls_q("-1", "3"); s},
    function(s) {s$path$damping[[1L]] <- .irls_q("0"); s},
    function(s) {s$path$floor <- .irls_q("0"); s},
    function(s) {s$path$refresh_mask[[1L]] <- "0"; s},
    function(s) {s$path$start$beta[[1L]] <- .irls_q("1"); s},
    function(s) {s$inference$refusal$any_shift <- "0"; s},
    function(s) {s$operations$shape$p <- "3"; s},
    function(s) {s$accounting$delta <- .irls_q("1", "100"); s},
    function(s) {s$privacy_source$closure$dependencies[[1L]]$dependency$provenance_kind <- "padded_psi"; s})
  for (mutate in mutations) expect_error(.dsvert_dp_irls_contract_normalize(mutate(f$spec)))
})

test_that("IRLS rejects undersized signed widths before certificate derivation", {
  f <- .irls_contract_fixture(); s <- f$spec
  s$numeric$certificate$input_bits <- "1"
  s$numeric$certificate$temporary_bits <- "120"
  s$numeric$certificate_sha256 <- .dsvert_dp_irls_hash(
    "dsvert-v3-irls-numeric-certificate-v1", s$numeric$certificate)
  expect_error(.dsvert_dp_irls_contract_normalize(s), "certificate input bits")
  s <- f$spec
  s$path$trust[[1L]] <- .irls_q("18446744073709551616")
  expect_error(.dsvert_dp_irls_contract_normalize(s), "certificate input bits")
})
