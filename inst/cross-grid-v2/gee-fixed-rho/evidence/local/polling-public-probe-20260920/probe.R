args <- commandArgs(TRUE)
root <- args[[1]]
output <- args[[2]]
source(file.path(root, 'dsVertClient/inst/validation/v1.2.0/worked_example_custodian.R'))
pkgload::load_all(file.path(root, 'dsVertClient'), quiet=TRUE)
ns <- asNamespace('dsVertClient')
direct <- get('.dsvert_dsi_direct_aggregate', ns)
validate <- get('.dsvert_validate_dsi_expression_sizes', ns)
clock <- function() unname(proc.time()[['elapsed']])
workers <- list()
close_workers <- function() for (w in workers) try(w$close(), silent=TRUE)
main <- function() {
  on.exit(close_workers(), add=TRUE)
  conns <- list()
  for (i in 1:2) {
    w <- callr::r_session$new(wait=TRUE)
    workers[[i]] <<- w
    w$run(function() {
      library(DSLite)
      server <- newDSLiteServer(tables=list())
      server$aggregateMethod('geePublicRelayProbeDS', function(payload, reply_chars, delay) {
        start <- proc.time()[['elapsed']]
        if (delay > 0) Sys.sleep(delay)
        list(payload_chars=nchar(payload, type='bytes'),
             payload=strrep('A', reply_chars),
             worker_seconds=proc.time()[['elapsed']]-start)
      })
      assign('.dsvert_e2e_server', server, .GlobalEnv)
      assign('.dsvert_e2e_sid', server$newSession(), .GlobalEnv)
      TRUE
    })
    name <- paste0('public_', i)
    conns[[name]] <- new('DSVertE2EProcessConnection', name=name,
      sid=paste0('public-poll-audit:', w$get_pid()), server=.we_dummy_server, worker=w)
  }
  public <- strrep('A', 4L*480L*1024L/3L)
  profiles <- list(default=c(.05,1,2), short=c(.005,.01,.02))
  cases <- list(control=list(payload='', reply_chars=0L, delay=0, peers=2L),
                full_upload=list(payload=public, reply_chars=0L, delay=0, peers=1L),
                full_download=list(payload='', reply_chars=nchar(public), delay=0, peers=1L),
                delayed55ms=list(payload='', reply_chars=0L, delay=.055, peers=1L),
                delayed1010ms=list(payload='', reply_chars=0L, delay=1.01, peers=1L))
  one <- function(profile, name, repeat_id) {
    settings <- profiles[[profile]]
    options(datashield.polling.sleep.0=settings[[1]],
            datashield.polling.sleep.1=settings[[2]],
            datashield.polling.sleep.10=settings[[3]])
    case <- cases[[name]]
    selected <- conns[seq_len(case$peers)]
    expressions <- setNames(rep(list(call('geePublicRelayProbeDS', payload=case$payload,
      reply_chars=case$reply_chars, delay=case$delay)), length(selected)), names(selected))
    start <- clock()
    sizes <- validate(expressions)
    guard <- clock()-start
    sleeps <- numeric()
    actual_sleep <- 0
    value <- direct(selected, expressions, .sleep=function(seconds) {
      sleeps <<- c(sleeps, seconds)
      t <- clock()
      Sys.sleep(seconds)
      actual_sleep <<- actual_sleep+clock()-t
    })
    elapsed <- clock()-start
    stopifnot(length(value)==length(selected),
      all(vapply(value, function(x) identical(x$payload_chars, nchar(case$payload)) &&
        identical(nchar(x$payload), as.integer(case$reply_chars)), logical(1))))
    data.frame(profile=profile, case=name, repeat_id=repeat_id, elapsed=elapsed,
      guard=guard, sleep_requested=sum(sleeps), sleep_actual=actual_sleep,
      sleep_calls=length(sleeps), max_sleep=if(length(sleeps)) max(sleeps) else 0,
      worker_seconds=max(vapply(value, `[[`, numeric(1), 'worker_seconds')),
      request_serialized_bytes=sum(vapply(expressions, function(x) length(serialize(x,NULL,version=3)), integer(1))),
      response_serialized_bytes=sum(vapply(value, function(x) length(serialize(x,NULL,version=3)), integer(1))))
  }
  invisible(one('default','control',0L))
  rows <- list()
  for (repeat_id in 1:3) for (name in names(cases)) {
    ordering <- if (repeat_id %% 2L) names(profiles) else rev(names(profiles))
    for (profile in ordering) rows[[length(rows)+1L]] <- one(profile,name,repeat_id)
  }
  results <- do.call(rbind,rows)
  summary <- aggregate(cbind(elapsed,guard,sleep_requested,sleep_actual,sleep_calls,max_sleep,worker_seconds)~profile+case,results,mean)
  record <- list(scope='Public DSLite/callr direct-dispatch microbenchmark; no exactGC crypto/spool, DP noise, protected data or real release',
    snapshot_source_root=root, source_sha256=digest::digest(file=file.path(root,'dsVertClient/R/dsi_fanout.R'),algo='sha256'),
    raw_chunk_bytes=480L*1024L, repetitions=3L, profiles=profiles, summary=summary, runs=results)
  writeLines(jsonlite::toJSON(record,auto_unbox=TRUE,pretty=TRUE,digits=NA),output)
  print(summary,row.names=FALSE)
  cat('PUBLIC_POLL_AUDIT_RESULTS',output,'\n')
}
main()
