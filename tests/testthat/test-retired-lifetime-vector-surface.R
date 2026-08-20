legacy_lifetime_vector_surface <- c(
  "dsvertJointDPVectorAllocationProofDS",
  "dsvertJointDPVectorAllocationPrepareDS",
  "dsvertJointDPVectorAllocationCommitDS",
  "dsvertJointDPVectorAllocationAuthorizeDS",
  "dsvertJointDPVectorAllocationOpenDS",
  "dsvertJointDPVectorPrepareDS", "dsvertJointDPVectorStartDS",
  "dsvertJointDPVectorResultDS", "dsvertJointDPVectorFinalShareDS",
  "dsvertJointDPVectorReleaseDS", "dsvertJointDPVectorReplayDS",
  "dsvertJointDPVectorFinalizeAckDS"
)

test_that("the lifetime-gated vector lifecycle is internal-only", {
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  registered <- trimws(strsplit(
    description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  exports <- getNamespaceExports("dsVert")

  expect_false(any(legacy_lifetime_vector_surface %in% registered))
  expect_false(any(legacy_lifetime_vector_surface %in% exports))
  expect_false(any(legacy_lifetime_vector_surface %in%
                     .dsvert_disclosure_safe_remote_methods))
  expect_true(all(vapply(
    legacy_lifetime_vector_surface, exists, logical(1L),
    envir = asNamespace("dsVert"), mode = "function", inherits = FALSE)))
})
