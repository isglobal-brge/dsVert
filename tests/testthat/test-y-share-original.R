test_that("canonical deviance preserves the original y share", {
  sid <- paste0("test-y-share-original-", sample.int(1e6, 1L))
  ss <- dsVert:::.S(sid)
  ss$k2_ring <- 63L
  ss$k2_x_n <- 3L
  fp_y <- dsVert:::.callMpcTool("k2-float-to-fp", list(
    values = c(1, 0, 1), frac_bits = 20L, ring = "ring63"))$fp_data
  fp_eta <- dsVert:::.callMpcTool("k2-float-to-fp", list(
    values = c(0.2, -0.3, 0.4), frac_bits = 20L, ring = "ring63"))$fp_data
  ss$k2_y_share_fp <- fp_y
  ss$k2_eta_share_fp <- fp_eta

  expect_silent(dsVert::glmRing63PrepDevianceDS(
    mode = "canonical", session_id = sid))
  expect_identical(ss$k2_y_share_fp_original, fp_y)
  expect_false(identical(ss$k2_y_share_fp, fp_y))
})
