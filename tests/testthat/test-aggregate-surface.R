test_that("the remotely invocable aggregate surface is an exact allowlist", {
  pre_audit_registered <- c(
    "getObsCountDS", "glmStandardizeDS", "mpcCleanupDS",
    "mpcGcDS", "mpcStoreBlobDS", "mpcTypedBlobStoreDS",
    "mpcTypedBlobReadDS", "mpcTypedBlobReceiptDS",
    "mpcTypedSourceProbeDS",
    "mpcStoreTransportKeysDS",
    "k2ShareInputDS", "glmRing63ShareExtraInputDS", "k2ReceiveShareDS",
    "k2ComputeEtaShareDS",
    "k2SetOffsetDS", "k2ShareWeightsDS", "k2ReceiveWeightSharesDS",
    "k2PrepareWeightedResidualShareDS", "k2FinalizeWeightedResidualShareDS",
    "k2GradientR1DS", "k2GradientR2DS",
    "k2IdentityLinkDS", "dsvertColNamesDS", "dsvertIdentityPkDS",
    "dsvertJointDPCapsuleStatusDS", "dsvertPublicFixedCohortCountDS",
    "dsvertDPCapsuleManifestDraftDS",
    "dsvertDPCapsuleManifestSignDS",
    "dsvertDPCapsuleManifestBuildDS",
    "dsvertDPCapsuleSourceTicketDS",
    "dsvertDPCapsuleSourcePrepareDS",
    "dsvertDPCapsuleSourceChunkDS",
    "dsvertDPCapsuleSourceAcceptDS",
    "dsvertDPAlignmentMaskStartDS",
    "dsvertDPAlignmentMaskStoreDS",
    "dsvertDPAlignmentMaskSealDS",
    "dsvertDPAlignmentMaskReceiveDS",
    "dsvertDPCategoricalCrossBindDS",
    "dsvertDPCategoricalCrossPrepareDS",
    "dsvertDPCategoricalCrossFinalizeDS",
    "dsvertDPGaussianCrossBindDS",
    "dsvertDPGaussianCrossPrepareDS",
    "dsvertDPGaussianCrossFinalizeDS",
    "dsvertJointDPVectorAllocationProofDS",
    "dsvertJointDPVectorAllocationPrepareDS",
    "dsvertJointDPVectorAllocationCommitDS",
    "dsvertJointDPVectorAllocationAuthorizeDS",
    "dsvertJointDPVectorAllocationOpenDS",
    "dsvertJointDPVectorPrepareDS", "dsvertJointDPVectorStartDS",
    "dsvertJointDPVectorResultDS", "dsvertJointDPVectorFinalShareDS",
    "dsvertJointDPVectorReleaseDS", "dsvertJointDPVectorReplayDS",
    "dsvertJointDPVectorFinalizeAckDS",
    "dsvertSecurityProfileDS", "dsvertTransportProbeDS",
    "dsvertNumericPolicyDS",
    "exactGCTransportInitDS", "exactGCBindPeersDS", "exactGCExchangeDS",
    "exactGCAbortDS", "exactGCCleanupDS", "exactGCGLMSoftplusPrepareDS",
    "exactGCVecmulClaimInputsDS",
    "exactGCVecmulBindInputsDS",
    "exactGCVecmulStartDS", "exactGCVecmulValidityDS",
    "exactGCVecmulValidityReceiveDS", "exactGCVecmulCommitDS",
    "dsvertLocalMomentsDS", "dsvertNBProfileSumsDS",
    "dsvertNBEtaShareDS", "dsvertNBEtaTotalReceiveDS",
    "dsvertNBEtaShareConfirmDS", "dsvertNBYThetaShareDS",
    "dsvertNBYThetaShareReceiveDS", "dsvertNBPsiAggregateDS",
    "dsvertOrdinalShareClassMasksDS", "dsvertOrdinalReceiveClassMaskDS",
    "dsvertComputeResidualShareDS", "dsvertPrepareMultinomGradDS",
    "dsvertSoftmaxDenominatorDS",
    "dsvertClusterIDsBroadcastDS", "dsvertClusterIDsReceiveDS",
    "dsvertGEEAR1OrderBroadcastDS", "dsvertGEEAR1OrderReceiveDS",
    "dsvertGEEAR1TransformShareDS", "dsvertPerClusterSumShareDS",
    "dsvertGLMMOneMinusMuDS", "dsvertImputeColumnDS",
    "dsvertPearsonR2ColDS", "dsvertGEEInterceptShareDS",
    "dsvertGEERestoreFeatureShapeDS", "dsvertClusterSizesDS",
    "dsvertClusterResidualsDS", "dsvertExpandClusterWeightsDS",
    "dsvertLMMVarianceComponentsDS", "dsvertLMMXCovarianceWithinStoredDS",
    "dsvertBeaverPolicyDS",
    "k2BeaverVecmulR1DS", "k2BeaverVecmulR2DS", "k2OtBeaverSampleDS",
    "k2OtBeaverFinalizeDS", "k2IknpBaseReceiverSetupDS",
    "k2IknpBaseSenderChoicesDS", "k2IknpBaseReceiverEncryptDS",
    "k2IknpBaseSenderFinalizeDS", "k2IknpReceiverExtendDS",
    "k2IknpSenderEncryptDS", "k2IknpReceiverDecryptDS",
    "k2BeaverExtractColumnDS", "k2BeaverSumShareDS",
    "k2BeaverStridedSumShareDS",
    "k2Ring127AffineCombineDS",
    "dsvertClusterZtZDS", "dsvertOutcomeLevelsDS",
    "dsvertLMMPeerFittedShareDS", "dsvertLMMCoordResidualShareDS",
    "dsvertLMMPeerResidualFinaliseDS", "dsvertLMMBroadcastClusterIDsDS",
    "dsvertLMMReceiveClusterIDsDS", "dsvertLMMPerClusterSumDS",
    "dsvertLMMGlobalSumDS", "dsvertLMMGLSTransformDS",
    "dsvertLMMLocalGramDS", "k2SeedSingleClusterDS",
    "dsvertLMMReceiveGramSharesDS", "dsvertLMMGramR1DS",
    "dsvertLMMGramR2DS", "glmRing63TransportInitDS",
    "glmRing63PrepDevianceDS", "glmRing63DevianceSumsDS",
    "glmRing63ExportOwnShareDS", "glmRing63ReceiveExtraShareDS",
    "glmRing63ReorderXFullDS", "psiPaddedInitDS", "psiPaddedBindDS",
    "psiPaddedConfirmDS", "psiPaddedPrepareDS",
    "psiPaddedReferenceExportDS", "psiPaddedTargetProcessDS",
    "psiPaddedReferenceDoubleDS", "psiPaddedTargetMatchDS",
    "psiPaddedMembershipAcceptDS", "psiPaddedANDStartDS",
    "psiPaddedANDFinalizeDS", "psiPaddedANDAcceptDS",
    "psiPaddedFinalPrepareDS", "psiPaddedAttestationDS",
    "psiPaddedRelayExchangeDS", "dsvertCoxDiscreteReceiveSharesDS",
    "dsvertCoxDiscreteShareMaskDS", "dsvertCoxEventTimeShareMaskDS",
    "dsvertCoxDiscreteExpandXDS", "dsvertNBMomentSumsDS",
    "dsvertOrdinalExtractXColumnDS", "c=base::c", "list=base::list",
    "numeric=base::numeric", "character=base::character"
  )
  expected <- setdiff(
    .dsvert_test_disclosure_safe_methods, "psiPaddedFilterDS")

  description <- system.file("DESCRIPTION", package = "dsVert")
  expect_true(nzchar(description))
  fields <- read.dcf(description)
  actual <- trimws(strsplit(fields[1L, "AggregateMethods"], ",",
                            fixed = TRUE)[[1L]])

  expect_setequal(actual, expected)
  expect_identical(anyDuplicated(actual), 0L)
  deregistered <- setdiff(pre_audit_registered, expected)
  exports <- getNamespaceExports("dsVert")
  expect_length(deregistered, 98L)
  expect_false(any(deregistered %in% actual))
  expect_false(any(deregistered %in% exports))

  retired <- c(
    "dsvertNaOmitDS", "dsvertClusterBinomialMomentsDS",
    "dsvertLMMExactClusterR2DS", "dsvertLMMGLSAggregatesDS",
    "dsvertLMMXCovarianceWithinDS", "dsvertNBSumShareDS",
    "k2CmpGenKeysDS", "k2ClearOffsetDS", "k2ClearWeightsDS",
    "k2CmpStoreKeysDS", "k2CmpRound1DS", "k2CmpRound2DS",
    "k2StoreSumShareDS", "k2GetStoredShareDS", "k2FPSubStoreDS",
    "k2BeaverVecmulGenTriplesDS", "glmRing63GenSplineTriplesDS",
    "glmRing63GenGradTriplesDS", "exactGCStatusDS", "exactGCInitDS",
    "exactGCVecmulPrepDS", "exactGCVecmulStageInputsDS",
    "exactGCVecmulR1DS", "exactGCVecmulR1ReceiveDS",
    "exactGCVecmulR2StageDS", "exactGCVecmulConsumeDS",
    "k2Ring127LocalScaleDS", "k2StoreGradTripleDS",
    "k2BeaverVecmulConsumeTripleDS", "dsvertContingencyDS",
    "localCorDS", "psiPaddedExactTransportDS",
    "psiInitDS", "psiStoreBlobDS", "psiStoreTransportKeysDS",
    "psiMaskIdsDS", "psiExportMaskedDS", "psiProcessTargetDS",
    "psiDoubleMaskDS", "psiExportMatchedIndicesDS",
    "psiComputeCommonIndicesDS", "psiExportCommonIndicesDS",
    "psiAlignmentManifestDS", "psiMatchAndAlignDS", "psiSelfAlignDS",
    "psiFilterCommonDS", "psiGetMatchedIndicesDS"
  )
  expect_false(any(retired %in% actual))

  targets <- sub("^[^=]+=", "", actual)
  for (target in targets) {
    if (grepl("::", target, fixed = TRUE)) {
      bits <- strsplit(target, "::", fixed = TRUE)[[1L]]
      expect_true(exists(bits[[2L]], envir = asNamespace(bits[[1L]]),
                         inherits = FALSE), info = target)
    } else {
      expect_true(exists(target, envir = asNamespace("dsVert"),
                         inherits = FALSE), info = target)
    }
  }
})

test_that("remote aliases fail closed instead of bypassing the central gate", {
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  description[1L, "AggregateMethods"] <- paste(
    description[1L, "AggregateMethods"], "c=base::c", sep = ",")
  path <- tempfile("dsvert-alias-description-")
  on.exit(unlink(path), add = TRUE)
  write.dcf(description, file = path)

  expect_error(
    .dsvert_registered_remote_methods(path),
    "Remote method aliases are forbidden")
})

test_that("legacy per-query DP and scalar-count endpoints are not remote", {
  retired <- c(
    "dsvertDPStatusDS", "dsvertDPCountDS", "dsvertDPContingencyDS",
    "dsvertDPMeanVarDS", "dsvertDPDescribeDS", "dsvertDPSurvivalDS",
    "dsvertJointDPPrepareDS", "dsvertJointDPCommitDS",
    "dsvertJointDPAuthorizeDS", "dsvertJointDPOpenDS",
    "dsvertJointDPResultReceiptDS", "dsvertJointDPDeliveryDS",
    "dsvertJointDPDeliveryContractDS", "dsvertJointDPCountReplayDS",
    "dsvertJointDPCountProposalDS", "dsvertJointDPCountSourceDS",
    "dsvertJointDPCountBackendPrepareDS",
    "dsvertJointDPCountBackendTokenDS", "dsvertJointDPCountStartDS",
    "dsvertJointDPCountResultDS", "dsvertJointDPCountFinalShareDS",
    "dsvertJointDPCountReleaseDS")
  description <- .dsvert_test_package_file("DESCRIPTION")
  aggregate <- trimws(strsplit(
    read.dcf(description)[1L, "AggregateMethods"],
    ",", fixed = TRUE)[[1L]])
  exports <- sub("^export\\((.*)\\)$", "\\1",
                 grep("^export\\(", readLines(
                   .dsvert_test_package_file("NAMESPACE")), value = TRUE))
  expect_false(any(retired %in% aggregate))
  expect_false(any(retired %in% exports))
  expect_true("dsvertPublicFixedCohortCountDS" %in% aggregate)
  expect_true("dsvertPublicFixedCohortCountDS" %in% exports)
})

test_that("retired remote primitives are not namespace exports", {
  retired <- c(
    "dsvertClusterBinomialMomentsDS", "dsvertLMMExactClusterR2DS",
    "dsvertLMMGLSAggregatesDS", "dsvertLMMXCovarianceWithinDS",
    "dsvertNBSumShareDS", "k2CmpGenKeysDS", "k2ClearOffsetDS",
    "k2ClearWeightsDS", "k2CmpStoreKeysDS", "k2CmpRound1DS",
    "k2CmpRound2DS", "k2StoreSumShareDS", "k2GetStoredShareDS",
    "k2FPSubStoreDS", "psiGetMatchedIndicesDS", "dsvertNaOmitDS",
    "k2BeaverVecmulGenTriplesDS", "glmRing63GenSplineTriplesDS",
    "glmRing63GenGradTriplesDS", "exactGCStatusDS", "exactGCInitDS",
    "exactGCVecmulPrepDS", "exactGCVecmulStageInputsDS",
    "exactGCVecmulR1DS", "exactGCVecmulR1ReceiveDS",
    "exactGCVecmulR2StageDS", "exactGCVecmulConsumeDS",
    "k2Ring127LocalScaleDS",
    "dsvertInjectNADS", "dsvertAddClusterColumnDS",
    "dsvertAddSyntheticSurvivalDS", "dsvertAddQuartileColumnDS",
    "dsvertAddFactorDummiesDS", "dsvertResetDataFrameDS",
    "glmRing63GenDcfKeysDS", "k2StoreDcfKeysPersistentDS",
    "k2WideSplinePhase1DS", "k2WideSplinePhase2DS",
    "k2WideSplinePhase3DS", "k2WideSplinePhase4DS",
    "k2CrossOneHotCountsDS", "localCorDS", "psiPaddedExactTransportDS",
    "psiInitDS", "psiStoreBlobDS", "psiStoreTransportKeysDS",
    "psiMaskIdsDS", "psiExportMaskedDS", "psiProcessTargetDS",
    "psiDoubleMaskDS", "psiExportMatchedIndicesDS",
    "psiComputeCommonIndicesDS", "psiExportCommonIndicesDS",
    "psiAlignmentManifestDS", "psiMatchAndAlignDS", "psiSelfAlignDS",
    "psiFilterCommonDS"
  )
  expect_false(any(retired %in% getNamespaceExports("dsVert")))
})

test_that("the remotely invocable assign surface is an exact allowlist", {
  description <- system.file("DESCRIPTION", package = "dsVert")
  expect_true(nzchar(description))
  fields <- read.dcf(description)
  actual <- trimws(strsplit(fields[1L, "AssignMethods"], ",",
                            fixed = TRUE)[[1L]])

  expect_identical(
    actual,
    "psiPaddedFilterDS")
  expect_identical(anyDuplicated(actual), 0L)
  expect_true(all(actual %in% getNamespaceExports("dsVert")))
})

test_that("roxygen cannot silently re-export the retired surface", {
  inventory <- jsonlite::read_json(.dsvert_test_package_file(
    "inst", "docs", "remote_surface_classification.json"),
    simplifyVector = FALSE)
  retired <- unlist(
    inventory$retired_registered_surface, use.names = FALSE)
  r_dir <- .dsvert_test_package_file("R", source_only = TRUE)
  files <- list.files(r_dir, pattern = "[.]R$", full.names = TRUE)
  annotated <- character()
  for (file in files) {
    lines <- readLines(file, warn = FALSE)
    exports <- grep("^#' @export[[:space:]]*$", lines)
    for (line in exports) {
      candidates <- seq.int(line + 1L, min(length(lines), line + 100L))
      definitions <- candidates[grepl(
        "^[A-Za-z][A-Za-z0-9.]*[[:space:]]*<-[[:space:]]*function\\b",
        lines[candidates], perl = TRUE)]
      if (length(definitions)) {
        annotated <- c(annotated, sub(
          "[[:space:]]*<-.*$", "", lines[definitions[[1L]]]))
      }
    }
  }
  expect_length(intersect(retired, unique(annotated)), 0L)
})
