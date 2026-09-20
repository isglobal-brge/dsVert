args <- commandArgs(TRUE)
root <- args[[1L]]
fixture <- args[[2L]]
output <- args[[3L]]
pkgload::load_all(file.path(root,'dsVert'),quiet=TRUE)
scan <- get('.exact_gc_segment_list',asNamespace('dsVert'))
source_path <- file.path(root,'dsVert/R/exactGCTransportDS.R')
source_hash <- digest::digest(file=source_path,algo='sha256')
rows <- list()
for (count in c(1L,100L,800L)) {
  path <- file.path(fixture,as.character(count))
  for (trial in seq_len(4L)) {
    started <- proc.time()
    observed <- scan(path)
    elapsed <- proc.time()-started
    stopifnot(nrow(observed)==count,all(observed$size==2^20),
      identical(observed$offset,as.numeric(0:(count-1L))*2^20))
    rows[[length(rows)+1L]] <- data.frame(segments=count,trial=trial,
      elapsed_seconds=unname(elapsed[['elapsed']]),
      user_seconds=unname(elapsed[['user.self']]),
      system_seconds=unname(elapsed[['sys.self']]))
  }
}
runs <- do.call(rbind,rows)
summary <- aggregate(cbind(elapsed_seconds,user_seconds,system_seconds)~segments,runs,mean)
stopifnot(identical(source_hash,digest::digest(file=source_path,algo='sha256')))
record <- list(scope='Local public sparse-file segment-directory enumeration only; no worker, transport, crypto or DP release',
  source_file='dsVert/R/exactGCTransportDS.R',source_sha256=source_hash,
  bytes_per_segment=2^20,counts=c(1L,100L,800L),repetitions=4L,
  summary=summary,runs=runs)
writeLines(jsonlite::toJSON(record,auto_unbox=TRUE,pretty=TRUE,digits=NA),output)
print(summary,row.names=FALSE)
cat('PUBLIC_SEGMENT_SCAN_RESULTS',output,'\n')
