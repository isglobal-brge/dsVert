setwd('/Users/david/Documents/GitHub/dsvert-crossowner/integrator-evidence/cycle45-20260920/proof-snapshot')
pkgload::load_all('dsVert', quiet = TRUE)
pkgload::load_all('dsVertClient', quiet = TRUE)
e <- new.env(parent = asNamespace('dsVertClient'))
for (path in list.files('dsVertClient/tests/testthat', '^helper.*[.]R$', full.names=TRUE)) sys.source(path, e)
for (name in c('test-dp-cox-admission-dispatch.R', 'test-dp-cox-staged-orchestration.R', 'test-dp-cox-cross-public-evidence.R', 'test-dp-lmm-cross-public-release.R', 'test-dp-cox-catalog-draft.R', 'test-dp-categorical-cross-transport.R', 'test-dp-glm-grid-cross-contract.R')) {
 result <- testthat::test_file(file.path('dsVertClient/tests/testthat',name), env=e, reporter='summary')
 frame <- as.data.frame(result)
 write.csv(frame[, !vapply(frame, is.list, logical(1L))], file.path('/Users/david/Documents/GitHub/dsvert-crossowner/integrator-evidence/cycle45-20260920',paste0(name,'.csv')),row.names=FALSE)
}
