.typed_body_text <- function(name) {
  paste(deparse(body(get(name, envir = asNamespace("dsVert")))),
        collapse = "\n")
}

test_that("every active-first typed producer caches and mints purpose-bound output", {
  producers <- c(
    ".k2_share_input_impl", "glmRing63ExportOwnShareDS",
    "k2GradientR1DS", "k2BeaverShareVectorDS", "k2BeaverVecmulR1DS",
    "k2ShareWeightsDS",
    "k2IknpBaseSenderChoicesDS", "k2IknpBaseReceiverEncryptDS",
    "k2IknpReceiverExtendDS", "k2IknpSenderEncryptDS")
  for (producer in producers) {
    text <- .typed_body_text(producer)
    expect_match(text, ".dsvert_typed_blob_operation_replay", fixed = TRUE,
                 info = producer)
    expect_match(text, ".dsvert_typed_blob_mint", fixed = TRUE,
                 info = producer)
    expect_match(text, ".dsvert_typed_blob_operation_commit", fixed = TRUE,
                 info = producer)
  }
})

test_that("every active-first recipient requires typed provenance", {
  consumers <- c(
    "k2ReceiveShareDS", "glmRing63ReceiveExtraShareDS", "k2GradientR2DS",
    "k2BeaverReceiveVectorDS", ".k2_beaver_vecmul_r2_compute",
    "k2ReceiveWeightSharesDS",
    "k2IknpBaseReceiverEncryptDS", "k2IknpBaseSenderFinalizeDS",
    "k2IknpSenderEncryptDS", "k2IknpReceiverDecryptDS")
  for (consumer in consumers) {
    expect_match(
      .typed_body_text(consumer), ".dsvert_typed_blob_consume", fixed = TRUE,
      info = consumer)
  }
})

test_that("retired correlation controls are internal and unreachable", {
  methods <- c("glmRing63CorSetZeroYDS", "glmRing63CorSetColDS")
  registered <- .dsvert_registered_remote_methods(
    .dsvert_test_package_file("DESCRIPTION"))
  expect_length(intersect(methods, registered), 0L)
  expect_length(intersect(methods, getNamespaceExports("dsVert")), 0L)
  for (method in methods) {
    expect_true(exists(method, envir = asNamespace("dsVert"),
                       mode = "function", inherits = FALSE))
  }
})
