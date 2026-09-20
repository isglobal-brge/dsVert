args <- commandArgs(TRUE)
pkgload::load_all(file.path(args[[1]], 'dsVert'), quiet = TRUE)
e <- new.env(parent = asNamespace('dsVert'))
e$test_that <- testthat::test_that
for (name in getNamespaceExports('testthat')) assign(name, getExportedValue('testthat', name), e)
expressions <- parse(file.path(args[[1]], 'dsVert/tests/testthat/test-crossgrid-cox.R'))
eval(expressions[[1]], e)
eval(expressions[[length(expressions)]], e)
