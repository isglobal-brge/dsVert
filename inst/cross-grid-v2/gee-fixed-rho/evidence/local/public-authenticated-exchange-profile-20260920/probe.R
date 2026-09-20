pkgload::load_all('/Users/david/Documents/GitHub/dsvert-gee/dsVert', quiet=TRUE)
out <- '/tmp/gee-public-exchange-profile-20260920'
state_root <- file.path(out,'public-state')
dir.create(state_root,mode='0700',showWarnings=FALSE)
Sys.setenv(DSVERT_STATE_DIR=state_root)
main <- function() {
  testthat::local_mocked_bindings(.dsvert_identity_test_mode=function() TRUE,.package='dsVert')
  seed_a <- jsonlite::base64_enc(as.raw(1:32))
  seed_b <- jsonlite::base64_enc(as.raw(33:64))
  options(dsvert.identity_seed=seed_a)
  identity_a <- .get_identity_keypair()
  options(dsvert.identity_seed=seed_b)
  identity_b <- .get_identity_keypair()
  options(dsvert.identity_seed=seed_a)
  sid <- 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
  op <- paste0('op_',strrep('a',32))
  ss <- new.env(parent=emptyenv())
  ss$.session_id <- sid; ss$.created_at <- as.numeric(Sys.time()); ss$.last_activity <- ss$.created_at
  sessions <- new.env(parent=emptyenv()); sessions[[sid]] <- ss
  assign('.dsvert_sessions',sessions,envir=.GlobalEnv)
  s <- new.env(parent=emptyenv())
  s$status <- 'running'; s$session_id <- sid; s$operation_id <- op
  s$self_peer_id <- .dsvert_relay_peer_id(identity_a$identity_pk)
  s$peer_id <- .dsvert_relay_peer_id(identity_b$identity_pk)
  s$peer_identity_pk <- identity_b$identity_pk; s$context_hash <- strrep('b',64)
  s$request_max_bytes <- 2^20; s$spool_max_bytes <- 64*2^20; s$chunk_bytes <- 480*1024
  s$spool <- file.path(out,'spool'); dir.create(s$spool,mode='0700',showWarnings=FALSE)
  for (name in c('inbound.segments','outbound.segments')) dir.create(file.path(s$spool,name),mode='0700',showWarnings=FALSE)
  for (name in c('inbound.ack','outbound.ack','outbound.head')) .exact_gc_private_file(file.path(s$spool,name),charToRaw('0'))
  .exact_gc_private_file(file.path(s$spool,'inbound.state'),charToRaw(paste(.DSVERT_EXACT_GC_INBOUND_STATE_VERSION,'0','-','-','-',sep='|')))
  s$process <- list(is_alive=function() TRUE)
  now <- .exact_gc_now()
  s$ttl_seconds <- 900; s$max_runtime_seconds <- 86400
  s$last_activity <- now; s$started_at <- now; s$relay_heartbeat_at <- now
  s$worker_pid <- Sys.getpid(); s$worker_heartbeat_session <- strrep('c',64)
  s$worker_heartbeat_key <- as.raw(1:32); s$worker_heartbeat_seen_at <- now; s$worker_heartbeat_counter <- 1
  heartbeat <- list(version='dsvert-exact-gc-worker-heartbeat-v1',session_id=s$worker_heartbeat_session,pid=s$worker_pid,counter=1)
  material <- paste(heartbeat$version,heartbeat$session_id,heartbeat$pid,'1',sep='|')
  heartbeat$mac <- digest::hmac(s$worker_heartbeat_key,charToRaw(material),algo='sha256',serialize=FALSE)
  .exact_gc_private_replace(file.path(s$spool,'worker.hb'),charToRaw(jsonlite::toJSON(heartbeat,auto_unbox=TRUE)))
  operations <- .exact_gc_ops(ss); operations[[op]] <- s
  payload <- rep(as.raw(0:255),1920)
  sender <- new.env(parent=emptyenv())
  for (name in c('session_id','operation_id','context_hash')) sender[[name]] <- s[[name]]
  sender$self_peer_id <- s$peer_id; sender$peer_id <- s$self_peer_id
  rows <- list()
  for (i in 0:9) {
    offset <- as.numeric(i*length(payload))
    .exact_gc_segment_publish(file.path(s$spool,'outbound.segments'),offset,payload,s$spool_max_bytes)
    .exact_gc_offset_write(file.path(s$spool,'outbound.head'),offset+length(payload))
    options(dsvert.identity_seed=seed_b)
    delivery <- .exact_gc_make_envelope(sender,offset,payload)
    options(dsvert.identity_seed=seed_a)
    Rprof(file.path(out,paste0('exchange-',i,'.Rprof')),interval=.001)
    started <- proc.time()
    response <- exactGCExchangeDS(sid,op,s$self_peer_id,offset,
      delivery_offset=offset,delivery_chunk_bytes=length(payload),
      delivery_payload_hash=delivery$payload_hash,delivery_payload=delivery$payload,
      delivery_signature=delivery$signature,long_poll=FALSE)
    timing <- proc.time()-started
    Rprof(NULL)
    stopifnot(response$inbound_size==offset+length(payload),response$outbound$chunk_bytes==length(payload),
      response$outbound$offset==offset,identical(response$state,'running'))
    rows[[length(rows)+1L]] <- data.frame(iteration=i,elapsed=timing[['elapsed']],user=timing[['user.self']],system=timing[['sys.self']],child_user=timing[['user.child']],child_system=timing[['sys.child']])
    .exact_gc_offset_write(file.path(s$spool,'inbound.ack'),offset+length(payload))
    unlink(list.files(file.path(s$spool,'inbound.segments'),full.names=TRUE))
  }
  runs <- do.call(rbind,rows)
  write.csv(runs,file.path(out,'timings.csv'),row.names=FALSE)
  profiles <- lapply(0:9,function(i) summaryRprof(file.path(out,paste0('exchange-',i,'.Rprof'))))
  for (i in 0:9) {
    write.csv(profiles[[i+1]]$by.self,file.path(out,paste0('self-',i,'.csv')))
    write.csv(profiles[[i+1]]$by.total,file.path(out,paste0('total-',i,'.csv')))
  }
  print(runs)
  cat('MEAN_TIMINGS\n'); print(colMeans(runs[-1]))
  cat('LAST_PROFILE_SELF\n'); print(head(profiles[[10]]$by.self,20))
  cat('LAST_PROFILE_TOTAL\n'); print(head(profiles[[10]]$by.total,25))
  cat('BINARY',.findMpcBinary(),'\n')
  for (path in c('R/exactGCTransportDS.R','R/mpcUtils.R','R/dsiRelay.R')) cat('SOURCE_SHA256',path,digest::digest(file=file.path('/Users/david/Documents/GitHub/dsvert-gee/dsVert',path),algo='sha256'),'\n')
}
main()
