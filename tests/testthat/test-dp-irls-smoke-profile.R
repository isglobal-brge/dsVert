test_that("the smoke name admits the complete frozen schedule only", {
  f <- .irls_smoke_fixture()
  expect_identical(.dsvert_dp_irls_profile_admit(f$signed, f$pins)$contract, f$spec)
  mutate <- list(
    function(s) {s$path$T <- "3"; s},
    function(s) {s$path$refresh_mask[[2L]] <- "0"; s},
    function(s) {s$path$terminal_audit <- "0"; s},
    function(s) {s$path$floor <- .irls_q("1"); s},
    function(s) {s$path$floor_quantum <- .irls_q("1"); s},
    function(s) {s$path$ridge <- .irls_q("1"); s},
    function(s) {s$path$damping[[1L]] <- .irls_q("1", "2"); s},
    function(s) {s$path$trust[[2L]] <- .irls_q("1", "2"); s},
    function(s) {s$path$box$upper[[3L]] <- .irls_q("1", "2"); s},
    function(s) {s$path$start$kind <- "pilot"; s},
    function(s) {s$accounting$stages[[1L]]$g <- .irls_q("2"); s},
    function(s) {s$accounting$stages[[3L]]$H <- .irls_q("1"); s},
    function(s) {s$accounting$epsilon_path <- .irls_q("9"); s},
    function(s) {s$privacy_source$capacity <- "32"; s},
    function(s) {s$estimand$family <- "poisson"; s},
    function(s) {s$estimand$intercept <- "0"; s},
    function(s) {s$operations$max_stage_seconds <- "241"; s})
  for (change in mutate)
    expect_error(.dsvert_dp_irls_smoke_check(change(f$spec)), "smoke schedule")
  alias <- .irls_producer_fixture("binomial", "64")$spec
  alias$profile_id <- .DSVERT_DP_IRLS_SMOKE_VERSION
  expect_error(.dsvert_dp_irls_profile_admit(f$sign(alias), f$pins), "smoke schedule")
})

test_that("each noise lane recomputes alpha and authenticates epsilon and S1", {
  f <- .irls_smoke_fixture()
  for (i in seq_len(3L)) for (lane in c("g", "H")) {
    a <- f$spec$accounting$stages[[i]]
    expect_equal(.dsvert_dp_irls_bigq(a[[paste0("alpha_", lane)]]),
      .dsvert_dp_irls_bigq(a[[lane]]) / gmp::as.bigz(f$spec$accounting$sensitivity[[lane]]))
    bad <- f$signed; bad$contract$accounting$stages[[i]][[lane]] <- .irls_q("3")
    expect_error(.dsvert_dp_irls_profile_admit(bad, f$pins))
    bad <- f$signed; bad$contract$accounting$sensitivity[[lane]] <- "99999"
    expect_error(.dsvert_dp_irls_profile_admit(bad, f$pins))
  }
})
