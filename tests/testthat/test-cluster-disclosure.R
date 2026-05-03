library(testthat)

with_cluster_privacy <- function(code) {
  old <- options(datashield.privacyLevel = 5L,
                 dsvert.min_cluster_size = 2L)
  on.exit(options(old), add = TRUE)
  force(code)
}

new_k2_session <- function(prefix = "cluster-disclosure") {
  sid <- paste0(prefix, "-", format(Sys.time(), "%H%M%OS3"),
                "-", sample.int(1e6, 1L))
  ss <- dsVert:::.S(sid)
  ss$peer_transport_pks <- list("peer")
  list(sid = sid, ss = ss)
}

test_that("cluster-size aggregates fail closed for small clusters", {
  with_cluster_privacy({
    D <- data.frame(cluster = c(1L, 1L, rep(2L, 5L)))
    expect_error(
      dsVert::dsvertClusterSizesDS("D", "cluster"),
      "cluster size below datashield\\.privacyLevel")
  })
})

test_that("per-cluster residual aggregates fail closed for small clusters", {
  with_cluster_privacy({
    D <- data.frame(
      y = seq_len(7),
      x = seq_len(7) / 10,
      cluster = c(1L, 1L, rep(2L, 5L)))
    expect_error(
      dsVert::dsvertClusterResidualsDS(
        "D", y_var = "y", x_names = "x", betahat = 0.1,
        intercept = 0, cluster_col = "cluster"),
      "cluster size below datashield\\.privacyLevel")
  })
})

test_that("per-cluster binomial moments fail closed for small clusters", {
  with_cluster_privacy({
    D <- data.frame(
      y = c(0L, 1L, 0L, 1L, 1L, 0L, 1L),
      x = seq_len(7) / 10,
      cluster = c(1L, 1L, rep(2L, 5L)))
    expect_error(
      dsVert::dsvertClusterBinomialMomentsDS(
        "D", y_var = "y", x_names = "x", betahat = 0.1,
        intercept = 0, cluster_col = "cluster"),
      "cluster size below datashield\\.privacyLevel")
  })
})

test_that("LMM variance-component aggregates fail closed for small clusters", {
  with_cluster_privacy({
    D <- data.frame(
      y = seq_len(7),
      cluster = c(1L, 1L, rep(2L, 5L)))
    expect_error(
      dsVert::dsvertLMMVarianceComponentsDS(
        "D", y_var = "y", cluster_col = "cluster"),
      "cluster size below datashield\\.privacyLevel")
  })
})

test_that("per-cluster share sums fail before MPC work for small clusters", {
  with_cluster_privacy({
    s <- new_k2_session()
    s$ss$dsvert_cluster_ids <- c(1L, 1L, rep(2L, 5L))
    s$ss$dummy_share <- "unused-before-privacy-guard"
    expect_error(
      dsVert::dsvertPerClusterSumShareDS(
        share_key = "dummy_share", session_id = s$sid),
      "cluster size below datashield\\.privacyLevel")
  })
})

test_that("LMM exact per-cluster R2 shares fail closed for small clusters", {
  with_cluster_privacy({
    s <- new_k2_session()
    n <- 7L
    s$ss$dummy_r2 <- jsonlite::base64_enc(as.raw(rep(0L, n * 8L)))
    D <- data.frame(cluster = c(1L, 1L, rep(2L, 5L)))
    expect_error(
      dsVert::dsvertLMMExactClusterR2DS(
        data_name = "D", cluster_col = "cluster",
        r2_key = "dummy_r2", session_id = s$sid),
      "cluster size below datashield\\.privacyLevel")
  })
})

test_that("cluster aggregates still pass when all clusters meet threshold", {
  with_cluster_privacy({
    D <- data.frame(
      y = seq_len(10),
      x = seq_len(10) / 10,
      cluster = rep(1:2, each = 5L))
    sizes <- dsVert::dsvertClusterSizesDS("D", "cluster")
    expect_equal(sizes$sizes, c(5L, 5L))
    vc <- dsVert::dsvertLMMVarianceComponentsDS(
      "D", y_var = "y", cluster_col = "cluster")
    expect_equal(vc$n_per_cluster, c(5L, 5L))
  })
})
