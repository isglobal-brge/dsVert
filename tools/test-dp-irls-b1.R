# Run only the B1 contract/state files; invoke from the server worktree.
pkgload::load_all('.',quiet=TRUE)
source('tests/testthat/helper-dp-irls-contract.R')
files <- c('test-dp-irls-contract.R','test-dp-irls-state.R',
           'test-dp-irls-state-adversarial.R')
counts <- lapply(files,function(file) {
 r <- testthat::test_file(file.path('tests/testthat',file),reporter='summary')
 d <- as.data.frame(r)
 data.frame(file=file,tests=nrow(d),assertions=sum(d$passed),
   failed=sum(d$failed),errors=sum(d$error),warnings=sum(d$warning),skipped=sum(d$skipped))
})
counts <- do.call(rbind,counts); print(counts,row.names=FALSE)
if(any(counts$failed>0|counts$errors>0|counts$warnings>0|counts$skipped>0)) quit(status=1L)
