args <- commandArgs(TRUE)
root <- normalizePath(args[[1]])
out <- normalizePath(args[[2]])
pkgload::load_all(file.path(root, 'dsVert'), quiet = TRUE)
e <- new.env(parent = asNamespace('dsVert'))
for (path in list.files(file.path(root, 'dsVert/tests/testthat'), '^helper.*[.]R$', full.names=TRUE)) sys.source(path, e)
for (name in c('test-crossgrid-cox.R', 'test-dp-glm-grid-cross-contract.R')) {
 result <- testthat::test_file(file.path(root,'dsVert/tests/testthat',name), env=e, reporter='summary')
 frame <- as.data.frame(result)
 write.csv(frame[, !vapply(frame, is.list, logical(1L))], file.path(out,paste0(name,'.csv')),row.names=FALSE)
}
