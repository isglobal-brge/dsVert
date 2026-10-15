# Statistical endpoints accept only the custodian-provisioned analysis selector.
# Relay carries authenticated ciphertext; it cannot select beta or predecessor.
.dsvert_dp_irls_registry <- new.env(parent = emptyenv())

.dsvert_dp_irls_entry <- function(analysis_id) {
  .dsvert_dp_analysis_scalar_id(analysis_id, "IRLS analysis selector")
  if (!exists(analysis_id, .dsvert_dp_irls_registry, inherits = FALSE))
    .dsvert_dp_irls_fail("unprovisioned analysis selector")
  entry <- get(analysis_id, .dsvert_dp_irls_registry, inherits = FALSE)
  .dsvert_dp_irls_profile_admit(entry$signed_contract, entry$pins)
  entry
}

.dsvert_dp_irls_provision <- function(analysis_id, signed_contract, trusted_pins,
    authority, identity_sk, sources, directory, transport, peer_transport_pk,
    peer_transport_signature) {
  .dsvert_dp_analysis_scalar_id(analysis_id, "IRLS analysis selector")
  if (exists(analysis_id, .dsvert_dp_irls_registry, inherits = FALSE))
    .dsvert_dp_irls_fail("already provisioned analysis selector")
  admitted <- .dsvert_dp_irls_profile_admit(signed_contract, trusted_pins)
  contract <- admitted$contract
  pair <- unlist(contract$privacy_source$computation_peers, use.names = FALSE)
  if (!authority %in% pair || !dir.exists(directory) || nzchar(Sys.readlink(directory)))
    .dsvert_dp_irls_fail("custodian provisioning context")
  peer <- setdiff(pair, authority)
  if (!isTRUE(.verify_peer_identity(peer_transport_pk,
      .base64url_to_base64(contract$privacy_source$peer_pins[[peer]]), peer_transport_signature)))
    .dsvert_dp_irls_fail("peer transport pin")
  entry <- new.env(parent = emptyenv())
  entry$analysis_id <- analysis_id; entry$signed_contract <- signed_contract
  entry$contract <- contract; entry$pins <- trusted_pins
  entry$authority <- authority; entry$peer <- peer; entry$pair <- pair
  entry$identity_sk <- identity_sk; entry$transport <- transport
  entry$peer_transport_pk <- peer_transport_pk
  entry$root <- .dsvert_dp_irls_root(contract)
  entry$directory <- normalizePath(directory)
  entry$state_path <- file.path(entry$directory, "state", "state.sqlite")
  entry$publication_path <- file.path(entry$directory, "publication", "publication.sqlite")
  entry$registry_path <- file.path(entry$directory,"private-registry.sqlite")
  entry$sealed_source <- .dsvert_dp_irls_source_seal(contract, authority, sources, identity_sk)
  .dsvert_dp_irls_store_create(entry$state_path, signed_contract, trusted_pins, authority)
  .dsvert_dp_irls_publication_create(entry$publication_path, signed_contract, trusted_pins, authority)
  entry$noise_seed <- paste(sprintf("%02x", as.integer(.dsvert_secure_random_bytes(32L))), collapse = "")
  entry$store_key <- jsonlite::base64_enc(.dsvert_secure_random_bytes(32L))
  entry$stages <- list(); entry$worker <- NULL; entry$stage_index <- "0"
  entry$status <- "ready"; entry$metrics <- list(); entry$received <- list(); entry$recovery<-NULL;entry$recovery_history<-character();entry$recovery_requests<-character()
  assign(analysis_id, entry, .dsvert_dp_irls_registry)
  .dsvert_dp_irls_registry_create(entry$registry_path)
  .dsvert_dp_irls_persist(entry)
  invisible(entry$root)
}

.dsvert_dp_irls_status <- function(entry, version = "dsvert-dp-irls-status-v1")
  list(version = version, analysis_id = entry$analysis_id, root = entry$root,
       status = entry$status, stage_index = entry$stage_index)

#' Inspect a provisioned signed DP IRLS path (AGGREGATE)
#' @param analysis_id Custodian-provisioned analysis selector.
#' @export
dpIRLSMetadataDS <- function(analysis_id) {
  entry <- .dsvert_dp_irls_entry(analysis_id)
  list(version = "dsvert-dp-irls-metadata-v1", analysis_id = analysis_id,
    signed_contract = entry$signed_contract, root = entry$root, stages = entry$stages)
}

.dsvert_dp_irls_worker_start <- function(entry) {
  t <- as.character(length(entry$stages)); entry$stage_index <- t
  if (length(entry$stages) == length(entry$contract$accounting$stages)) {
    entry$status <- "complete"; return(invisible(NULL))
  }
  predecessor <- if (t == "0") .dsvert_dp_irls_start_digest(entry$contract) else
    entry$stages[[length(entry$stages)]]$body$payload_digest
  plan <- .dsvert_dp_irls_stage_plan(entry$state_path, entry$signed_contract,
    entry$pins, t, predecessor)
  plan$source_abi <- .DSVERT_DP_IRLS_SOURCE_ABI
  allocation <- entry$contract$accounting$stages[[as.integer(t)+1L]]
  policy <- list(plan = plan, adjacency = if (entry$contract$privacy_source$adjacency ==
    "add-remove-person") "add_remove" else "replace_one",
    epsilon_g = allocation$g, epsilon_h = allocation$H)
  descriptor <- .callMpcTool("dp-irls-noise-plan", policy)
  before <- proc.time()[[3L]]
  source <- .dsvert_dp_irls_source_materialize(entry$contract, entry$sealed_source)
  source_seconds <- proc.time()[[3L]] - before
  session <- plan$stage_id
  # The signed contract's stage envelope bounds the native worker too (the
  # worker admits 10..86400 seconds).
  stage_seconds <- as.integer(entry$contract$operations$max_stage_seconds)
  if (is.na(stage_seconds) || stage_seconds < 10L || stage_seconds > 86400L)
    .dsvert_dp_irls_fail("stage envelope")
  derived <- .callMpcTool("exact-gc-derive-master", list(
    local_secret = entry$transport$secret_key, local_public = entry$transport$public_key,
    peer_public = entry$peer_transport_pk, session_id = session,
    garbler_id = entry$pair[[1L]], evaluator_id = entry$pair[[2L]],
    purpose = descriptor$purpose, operation = "dp-irls-fused-stage-v1",
    ring_bits = 128L, frac_bits = 0L, vector_len = 9L))
  spool <- file.path(entry$directory, paste0("stage-", t, "-spool",
    if(!is.null(entry$recovery$id) && nzchar(entry$recovery$id)) paste0("-",entry$recovery$id) else ""))
  if (dir.exists(spool)) .dsvert_dp_irls_fail("retained worker spool requires recovery")
  dir.create(spool, mode = "0700")
  for (nm in c("inbound.segments", "outbound.segments")) dir.create(file.path(spool,nm),mode="0700")
  for (nm in c("inbound.bin","outbound.bin")) .exact_gc_private_file(file.path(spool,nm), raw(0))
  for (nm in c("exchange.hb","worker.hb")) .exact_gc_private_file(file.path(spool,nm),charToRaw("."))
  .exact_gc_private_file(file.path(spool,"inbound.state"),charToRaw(paste(
    .DSVERT_EXACT_GC_INBOUND_STATE_VERSION,"0","-","-","-",sep="|")))
  for (nm in c("inbound.ack","outbound.head","outbound.ack"))
    .exact_gc_private_file(file.path(spool,nm),charToRaw("0"))
  config <- list(version="dsvert-exact-gc-worker-v4", role=if(entry$authority==entry$pair[[1L]]) "garbler" else "evaluator",
    session_id=session, master_key=derived$master_key, garbler_id=entry$pair[[1L]],evaluator_id=entry$pair[[2L]],
    purpose=descriptor$purpose,operation="dp-irls-fused-stage-v1",ring_bits=128L,frac_bits=0L,vector_len=9L,
    source_share=source$source_share,spool_dir=spool,max_spool_bytes=64*1024^2,ttl_seconds=stage_seconds,
    heartbeat_key=jsonlite::base64_enc(.dsvert_secure_random_bytes(32L)),
    dp_irls=c(policy,list(store_dir=file.path(entry$directory,paste0("stage-",t,"-private")),
      store_key=entry$store_key,noise_seed=entry$noise_seed)))
  config_path <- file.path(spool,"worker-config.json")
  .exact_gc_private_file(config_path,charToRaw(as.character(jsonlite::toJSON(config,auto_unbox=TRUE,null="null",digits=17))))
  worker <- new.env(parent=emptyenv());worker$spool<-spool
  # Frames follow the custodian's exact-GC chunk policy (default 480 KiB,
  # admitted 16 KiB..8 MiB); 8 chunks must fit the 64 MiB spool.
  worker$spool_max_bytes<-64*1024^2;worker$chunk_bytes<-min(.exact_gc_chunk_bytes(),8*1024^2)
  worker$process<-NULL;worker$config_path<-config_path
  worker$started<-proc.time()[[3L]];worker$source_seconds<-source_seconds
  worker$policy<-policy;worker$predecessor<-predecessor;worker$plan<-plan
  worker$noised<-NULL;worker$peer_noised<-NULL;worker$publication_messages<-list()
  worker$last_ack<-0;worker$outbound_ack_offset<-0;worker$ttl_seconds<-stage_seconds
  entry$worker<-worker;entry$status<-"running";entry$received<-list()
  .dsvert_dp_irls_persist(entry)
  worker$process<-processx::process$new(Sys.getenv("DS_VERT_MPC"),c("exact-gc-worker",config_path),
    stdout=file.path(spool,"worker-private.log"),stderr="2>&1",cleanup=TRUE,cleanup_tree=TRUE)
  invisible(NULL)
}

#' Start the next signed DP IRLS stage (AGGREGATE)
#' @param analysis_id Custodian-provisioned analysis selector.
#' @export
dpIRLSStartDS <- function(analysis_id) {
  entry <- .dsvert_dp_irls_entry(analysis_id)
  if (entry$status %in% c("ready","stage-published")) .dsvert_dp_irls_worker_start(entry)
  .dsvert_dp_irls_status(entry)
}

#' Resume the selected DP IRLS stage (AGGREGATE)
#' @param analysis_id Custodian-provisioned analysis selector.
#' @export
dpIRLSResumeDS <- function(analysis_id) {
  entry <- .dsvert_dp_irls_entry(analysis_id)
  worker<-entry$worker
  if(!is.null(worker) && !.dsvert_dp_irls_recovering(entry) &&
      !is.null(worker$process) && !worker$process$is_alive() &&
      !file.exists(file.path(worker$spool,"result.json"))) .dsvert_dp_irls_recovery_request(entry)
  .dsvert_dp_irls_progress(entry)
  .dsvert_dp_irls_status(entry)
}

.dsvert_dp_irls_frame_seal <- function(entry, body) {
  body <- c(list(version="dsvert-v3-irls-relay-frame-v1",root=entry$root,
    stage_id=entry$worker$plan$stage_id,from=entry$authority,to=entry$peer),body)
  signature <- .dsvert_relay_sign_message(charToRaw(.dsvert_dp_irls_state_json(body)),entry$identity_sk)
  plain <- charToRaw(.dsvert_dp_irls_state_json(list(body=body,signature=signature)))
  # base64url is inside the narrow DSI expression-parser alphabet, so the
  # client relays frames verbatim instead of re-encoding them.
  base64_to_base64url(.callMpcTool("transport-encrypt",
    list(data=jsonlite::base64_enc(plain),recipient_pk=entry$peer_transport_pk))$sealed)
}

.dsvert_dp_irls_frame_open <- function(entry, frame) {
  if (!is.character(frame)||length(frame)!=1L||is.na(frame)||nchar(frame,type="bytes")>16*1024^2)
    .dsvert_dp_irls_fail("relay frame")
  opened <- .callMpcTool("transport-decrypt",list(sealed=.base64url_to_base64(frame),recipient_sk=entry$transport$secret_key))
  envelope <- .dsvert_dp_irls_state_decode(rawToChar(jsonlite::base64_dec(opened$data)))
  .dsvert_dp_irls_fields(envelope,c("body","signature")); body<-envelope$body
  .dsvert_dp_irls_fields(body,c("version","root","stage_id","from","to","offset","ack","data","noised","publication","recovery"))
  if (body$version!="dsvert-v3-irls-relay-frame-v1"||body$root!=entry$root||
      body$stage_id!=entry$worker$plan$stage_id||body$from!=entry$peer||body$to!=entry$authority||
      !isTRUE(.dsvert_relay_verify_message(charToRaw(.dsvert_dp_irls_state_json(body)),
        entry$contract$privacy_source$peer_pins[[entry$peer]],envelope$signature)))
    .dsvert_dp_irls_fail("relay authentication")
  body
}

#' Relay opaque authenticated DP IRLS protocol frames (AGGREGATE)
#' @param analysis_id Custodian-provisioned analysis selector.
#' @param frame Opaque encrypted peer frame, or an empty polling frame.
#' @export
dpIRLSRelayDS <- function(analysis_id, frame = "") {
  entry <- .dsvert_dp_irls_entry(analysis_id); worker<-entry$worker
  if (is.null(worker)) .dsvert_dp_irls_fail("stage not started")
  if (!is.character(frame)||length(frame)!=1L||is.na(frame)) .dsvert_dp_irls_fail("relay frame")
  # Frames are base64url (DSI-safe); "none" stands for an empty frame because
  # DSI expression parsers reject empty string literals.
  if (identical(frame, "none")) frame <- "" else if (!grepl("^[A-Za-z0-9_-]+$", frame))
    .dsvert_dp_irls_fail("relay frame")
  if (nzchar(frame)) {
    body <- .dsvert_dp_irls_frame_open(entry,frame)
    .dsvert_dp_irls_recovery_receive(entry,body$recovery)
    worker<-entry$worker
    if(!.dsvert_dp_irls_recovering(entry) && (is.null(entry$recovery) ||
        (!is.null(body$recovery) && body$recovery$phase=="started" && identical(body$recovery$id,entry$recovery$id)))) {
    ack <- .exact_gc_integer(body$ack,"IRLS relay ack",0,2^53)
    offset <- .exact_gc_integer(body$offset,"IRLS relay offset",0,2^53)
    .exact_gc_outbound_compact(worker,ack)
    raw <- jsonlite::base64_dec(body$data)
    if (length(raw)>worker$chunk_bytes) .dsvert_dp_irls_fail("relay chunk size")
    if (length(raw)) .exact_gc_inbound_append(worker,offset,raw)
    if (!is.null(body$noised)) {
      if (!is.null(worker$peer_noised) && !identical(.dsvert_dp_irls_state_json(worker$peer_noised),
          .dsvert_dp_irls_state_json(body$noised))) .dsvert_dp_irls_fail("noised result replay")
      worker$peer_noised<-body$noised
    }
    if (length(body$publication)) for (message in body$publication) {
      .dsvert_dp_irls_fields(message,c("phase","lane","value"))
      if (!message$phase %in% c("lane-prepared","lane-committed","parent-prepared","parent-committed") ||
          !message$lane %in% c("g","H","parent")) .dsvert_dp_irls_fail("publication relay phase")
      key<-paste(message$phase,message$lane,sep="|");prior<-entry$received[[key]]
      if (!is.null(prior) && !identical(.dsvert_dp_irls_state_json(prior),.dsvert_dp_irls_state_json(message)))
        .dsvert_dp_irls_fail("publication relay replay")
      entry$received[[key]]<-message
    }
    }
  }
  .exact_gc_private_replace(file.path(worker$spool,"exchange.hb"),charToRaw("."))
  .dsvert_dp_irls_progress(entry)
  offset <- .exact_gc_offset_read(file.path(worker$spool,"outbound.ack"),"IRLS outbound ack")
  data <- .exact_gc_segment_read(worker,offset,worker$chunk_bytes)
  ack <- .exact_gc_inbound_state_read(worker)$head
  response <- .dsvert_dp_irls_status(entry,"dsvert-dp-irls-relay-v1")
  response$frame <- .dsvert_dp_irls_frame_seal(entry,list(offset=as.character(offset),ack=as.character(ack),
    data=jsonlite::base64_enc(data),noised=worker$noised,publication=unname(worker$publication_messages),recovery=entry$recovery))
  response
}

#' Read only fully committed dual-signed DP IRLS stages (AGGREGATE)
#' @param analysis_id Custodian-provisioned analysis selector.
#' @export
dpIRLSPublicationDS <- function(analysis_id) {
  entry <- .dsvert_dp_irls_entry(analysis_id)
  .dsvert_dp_irls_progress(entry)
  list(version="dsvert-dp-irls-publication-v1",analysis_id=analysis_id,root=entry$root,stages=entry$stages)
}

.dsvert_dp_irls_progress <- function(entry) {
  worker <- entry$worker
  if (is.null(worker) || .dsvert_dp_irls_recovering(entry) || entry$status %in% c("stage-published","complete")) return(invisible(NULL))
  if (proc.time()[[3L]]-worker$started>worker$ttl_seconds) {
    if (!is.null(worker$process)) worker$process$kill_tree(); .dsvert_dp_irls_fail("bounded stage runtime")
  }
  result_path <- file.path(worker$spool,"result.json")
  if (is.null(worker$noised) && file.exists(result_path)) {
    result <- jsonlite::fromJSON(result_path,simplifyVector=FALSE)
    if (!identical(result$kind,"dp-irls-noised-lanes-v1") ||
        !identical(result$share,"") || !is.null(result$validity_share) ||
        !is.list(result$dp_irls)) .dsvert_dp_irls_fail("mandatory noise result")
    worker$noised <- result$dp_irls$lanes
    worker$timings <- result$dp_irls$timings
    worker$publication_started <- proc.time()[[3L]]
  }
  if (is.null(worker$noised)) {
    if (is.null(worker$process) || !worker$process$is_alive()) .dsvert_dp_irls_fail("protected worker failed; recover retained encrypted attempt")
    return(invisible(NULL))
  }
  if (is.null(worker$peer_noised)) return(invisible(NULL))
  if (is.null(worker$released)) {
    left <- if(entry$authority==entry$pair[[1L]]) worker$noised else worker$peer_noised
    right <- if(entry$authority==entry$pair[[1L]]) worker$peer_noised else worker$noised
    # Keep the lane objects intact: simplification would turn the lane array
    # into a data frame and lose each lane's translated_values.
    worker$released <- .callMpcTool("dp-irls-finalize",list(policy=worker$policy,left=left,right=right),
      simplify_output = FALSE)
  }
  add <- function(phase,lane,value) {
    key<-paste(phase,lane,sep="|")
    message<-list(phase=phase,lane=lane,value=value)
    prior<-worker$publication_messages[[key]]
    if (!is.null(prior) && !identical(.dsvert_dp_irls_state_json(prior),.dsvert_dp_irls_state_json(message)))
      .dsvert_dp_irls_fail("publication retry bytes")
    worker$publication_messages[[key]]<-message
  }
  received <- function(phase,lane) {
    key<-paste(phase,lane,sep="|"); entry$received[[key]]$value
  }
  own <- function(phase,lane) worker$publication_messages[[paste(phase,lane,sep="|")]]$value
  for (i in seq_along(c("g","H"))) {
    lane<-c("g","H")[[i]]
    if (is.null(own("lane-prepared",lane))) add("lane-prepared",lane,
      .dsvert_dp_irls_lane_prepare(entry$publication_path,entry$signed_contract,entry$pins,
        entry$stage_index,worker$predecessor,lane,worker$released[[i]]$translated_values,entry$identity_sk))
    peer<-received("lane-prepared",lane)
    if (!is.null(peer) && is.null(own("lane-committed",lane))) add("lane-committed",lane,
      .dsvert_dp_irls_lane_commit(entry$publication_path,entry$signed_contract,entry$pins,
        list(own("lane-prepared",lane),peer),entry$identity_sk))
  }
  committed <- lapply(c("g","H"),function(lane) list(own("lane-committed",lane),received("lane-committed",lane)))
  names(committed)<-c("g","H")
  if (any(vapply(committed,function(z) any(vapply(z,is.null,logical(1L))),logical(1L)))) return(invisible(NULL))
  if (is.null(own("parent-prepared","parent"))) add("parent-prepared","parent",
    .dsvert_dp_irls_parent_prepare(entry$publication_path,entry$state_path,entry$signed_contract,
      entry$pins,entry$stage_index,worker$predecessor,committed,entry$identity_sk))
  peer<-received("parent-prepared","parent")
  if (is.null(peer)) return(invisible(NULL))
  if (is.null(own("parent-committed","parent"))) add("parent-committed","parent",
    .dsvert_dp_irls_parent_commit(entry$publication_path,entry$state_path,entry$signed_contract,
      entry$pins,list(own("parent-prepared","parent"),peer),entry$identity_sk))
  peer<-received("parent-committed","parent")
  if (is.null(peer)) return(invisible(NULL))
  .dsvert_dp_irls_parent_publish(entry$publication_path,entry$signed_contract,entry$pins,
    list(own("parent-committed","parent"),peer))
  entry$stages <- .dsvert_dp_irls_publication_read(entry$publication_path,entry$signed_contract,entry$pins)
  entry$metrics[[entry$stage_index]] <- list(compile=worker$timings$compile_seconds,
    source=worker$source_seconds,protected_compute=worker$timings$protected_seconds,
    noise=worker$timings$noise_seconds,publication=proc.time()[[3L]]-worker$publication_started)
  entry$status <- if(length(entry$stages)==length(entry$contract$accounting$stages)) "complete" else "stage-published"
  .dsvert_dp_irls_persist(entry)
  invisible(NULL)
}

# Local custodian instrumentation only; not a DataSHIELD endpoint.
.dsvert_dp_irls_timings <- function(analysis_id) {
  entry<-.dsvert_dp_irls_entry(analysis_id);metrics<-entry$metrics;worker<-entry$worker
  if (!is.null(worker) && is.null(metrics[[entry$stage_index]])) {
    timings<-worker$timings
    result_path<-file.path(worker$spool,"result.json")
    if(is.null(timings)&&file.exists(result_path)) timings<-jsonlite::fromJSON(result_path,simplifyVector=FALSE)$dp_irls$timings
    unknown<-function(x) if(is.null(x)) NA_real_ else x
    metrics[[entry$stage_index]]<-list(compile=unknown(timings$compile_seconds),
      source=worker$source_seconds,protected_compute=unknown(timings$protected_seconds),
      noise=unknown(timings$noise_seconds),publication=if(is.null(worker$publication_started)) NA_real_ else proc.time()[[3L]]-worker$publication_started)
  }
  metrics
}
.dsvert_dp_irls_diagnostics <- function(analysis_id) {
  entry<-.dsvert_dp_irls_entry(analysis_id);worker<-entry$worker
  if(is.null(worker)) return(list(status=entry$status))
  path<-file.path(worker$spool,"worker-private.log")
  list(status=entry$status,elapsed=proc.time()[[3L]]-worker$started,
    process_alive=if(is.null(worker$process)) FALSE else worker$process$is_alive(),
    process_exit=if(is.null(worker$process)) NULL else worker$process$get_exit_status(),
    log=if(file.exists(path)) tail(readLines(path,warn=FALSE),20L) else character())
}

.dsvert_dp_irls_persist <- function(entry) {
  names <- c("analysis_id","signed_contract","contract","pins","authority","peer","pair",
    "identity_sk","transport","peer_transport_pk","root","directory","state_path",
    "publication_path","registry_path","sealed_source","noise_seed","store_key","stage_index","metrics","recovery","recovery_history","recovery_requests")
  record <- as.list.environment(entry,all.names=TRUE)[names]
  if (!is.null(entry$worker)) {
    worker_names <- c("spool","spool_max_bytes","chunk_bytes","source_seconds","policy",
      "predecessor","plan","ttl_seconds","config_path")
    record$worker <- as.list.environment(entry$worker,all.names=TRUE)[worker_names]
  }
  bytes <- serialize(record,NULL,version=3L)
  message <- charToRaw(paste0("dsvert-v3-irls-private-registry-v1|",
    digest::digest(bytes,algo="sha256",serialize=FALSE)))
  envelope <- serialize(list(bytes=bytes,signature=.dsvert_relay_sign_message(message,entry$identity_sk)),NULL,version=3L)
  .dsvert_dp_irls_store_open(entry$registry_path,function(db) {
    DBI::dbWithTransaction(db,DBI::dbExecute(db,"INSERT OR REPLACE INTO registry (id,record) VALUES (1,?)",
      params=list(jsonlite::base64_enc(envelope))))
  })
  invisible(NULL)
}

# Custodian restore takes external identity pins and authenticates the retained
# private source/key record. It never derives fresh noise roots after a crash.
.dsvert_dp_irls_restore <- function(directory, trusted_pins) {
  path <- file.path(directory,"private-registry.sqlite")
  envelope <- .dsvert_dp_irls_store_open(path,function(db) {
    row<-DBI::dbGetQuery(db,"SELECT record FROM registry WHERE id=1")
    if(nrow(row)!=1L) .dsvert_dp_irls_fail("missing private provisioning record")
    unserialize(jsonlite::base64_dec(row$record[[1L]]))
  })
  if (!is.list(envelope) || !is.raw(envelope$bytes)) .dsvert_dp_irls_fail("private provisioning record")
  record <- unserialize(envelope$bytes)
  contract <- .dsvert_dp_irls_contract_validate(record$signed_contract,trusted_pins)
  message <- charToRaw(paste0("dsvert-v3-irls-private-registry-v1|",
    digest::digest(envelope$bytes,algo="sha256",serialize=FALSE)))
  if (!identical(normalizePath(directory),record$directory) ||
      !isTRUE(.dsvert_relay_verify_message(message,contract$privacy_source$peer_pins[[record$authority]],envelope$signature)))
    .dsvert_dp_irls_fail("private provisioning authentication")
  entry <- list2env(record,parent=emptyenv());entry$pins<-trusted_pins
  entry$stages <- .dsvert_dp_irls_publication_read(entry$publication_path,entry$signed_contract,entry$pins)
  entry$received <- list();entry$status<-if(length(entry$stages)) "stage-published" else "ready"
  if (length(entry$stages)==length(contract$accounting$stages)) entry$status<-"complete"
  if (!is.null(record$worker) && as.integer(entry$stage_index)>=length(entry$stages)) {
    worker<-list2env(record$worker,parent=emptyenv());worker$process<-NULL
    worker$noised<-NULL;worker$peer_noised<-NULL;worker$publication_messages<-list()
    worker$outbound_ack_offset<-.exact_gc_offset_read(file.path(worker$spool,"outbound.ack"),"IRLS restored outbound ack")
    worker$started<-proc.time()[[3L]];entry$worker<-worker;entry$status<-"running"
    # A completed worker is replayable through every later publication crash.
    # Mid-protocol process loss requires coordinated encrypted-attempt recovery;
    # refusing here retains the reserved lane journals and never redraws noise.
    if (!file.exists(file.path(worker$spool,"result.json"))) {
      .dsvert_dp_irls_kill_retained_worker(worker)
      .dsvert_dp_irls_recovery_request(entry)
    }
  } else entry$worker<-NULL
  assign(entry$analysis_id,entry,.dsvert_dp_irls_registry)
  .dsvert_dp_irls_progress(entry)
  invisible(entry$root)
}

.dsvert_dp_irls_recovering <- function(entry) !is.null(entry$recovery) &&
  entry$recovery$phase %in% c("request","offer","ack")

.dsvert_dp_irls_recovery_request <- function(entry) {
  nonce<-paste(sprintf("%02x",as.integer(.dsvert_secure_random_bytes(16L))),collapse="")
  entry$recovery<-list(phase=if(entry$authority==entry$pair[[1L]]) "offer" else "request",
    id=nonce)
  .dsvert_dp_irls_persist(entry)
  invisible(NULL)
}

.dsvert_dp_irls_recovery_restart <- function(entry,id) {
  old<-entry$worker
  if(!is.null(old$process) && old$process$is_alive()) {
    old$process$kill_tree();old$process$wait(timeout=5000L)
  }
  entry$recovery_history<-unique(c(entry$recovery_history,id))
  entry$recovery<-list(phase="started",id=id)
  # Policy/source/seed/private store remain identical. The Go durable executor
  # exchanges fresh per-peer recovery nonces before its encrypted channels.
  # Both authorities have acknowledged abort before entering this fresh spool.
  .dsvert_dp_irls_worker_start(entry)
  invisible(NULL)
}

.dsvert_dp_irls_recovery_receive <- function(entry,message) {
  if(is.null(message)) return(invisible(NULL))
  .dsvert_dp_irls_fields(message,c("phase","id"))
  if(!message$phase %in% c("request","offer","ack","started") ||
      !is.character(message$id)||length(message$id)!=1L||!grepl("^[0-9a-f]{32}$",message$id))
    .dsvert_dp_irls_fail("encrypted recovery proposal")
  garbler<-entry$authority==entry$pair[[1L]];current<-entry$recovery
  if(garbler && message$phase=="request") {
    if(!message$id %in% entry$recovery_requests) {
      entry$recovery_requests<-c(entry$recovery_requests,message$id)
      if(is.null(current)||current$phase=="started") .dsvert_dp_irls_recovery_request(entry)
    }
  } else if(!garbler && message$phase=="offer") {
    if(!message$id %in% entry$recovery_history && (is.null(current)||current$phase=="request"||!identical(current$id,message$id))) {
      if(!is.null(entry$worker$process)&&entry$worker$process$is_alive()) {
        entry$worker$process$kill_tree();entry$worker$process$wait(timeout=5000L)
      }
      entry$recovery<-list(phase="ack",id=message$id)
      .dsvert_dp_irls_persist(entry)
    }
  } else if(garbler && message$phase=="ack" && !is.null(current) &&
            current$phase=="offer" && identical(current$id,message$id)) {
    .dsvert_dp_irls_recovery_restart(entry,message$id)
  } else if(!garbler && message$phase=="started" && !is.null(current) &&
            current$phase=="ack" && identical(current$id,message$id)) {
    .dsvert_dp_irls_recovery_restart(entry,message$id)
  }
  invisible(NULL)
}

.dsvert_dp_irls_kill_retained_worker <- function(worker) {
  # The signed retained absolute config path uniquely identifies this attempt.
  # Scan only process command lines, so a recycled PID is never killed by number.
  for(pid in list.files("/proc",pattern="^[0-9]+$")) {
    path<-file.path("/proc",pid,"cmdline")
    bytes<-tryCatch(readBin(path,"raw",n=65536L),error=function(e) raw())
    if(!length(bytes)) next
    text<-rawToChar(replace(bytes,bytes==as.raw(0),as.raw(32)))
    if(grepl(paste0("exact-gc-worker ",worker$config_path),text,fixed=TRUE))
      tryCatch(tools::pskill(as.integer(pid),signal=15L),error=function(e) NULL)
  }
  invisible(NULL)
}

.dsvert_dp_irls_registry_create <- function(path) {
  if(file.exists(path) || !dir.create(paste0(path,".provisioned"),mode="0700",showWarnings=FALSE))
    .dsvert_dp_irls_fail("private registry already provisioned; recover retained state")
  old<-Sys.umask("0077");on.exit(Sys.umask(old),add=TRUE)
  db<-DBI::dbConnect(RSQLite::SQLite(),path);on.exit(DBI::dbDisconnect(db),add=TRUE)
  DBI::dbExecute(db,"PRAGMA journal_mode=DELETE")
  DBI::dbExecute(db,"PRAGMA synchronous=FULL")
  DBI::dbExecute(db,"CREATE TABLE registry (id INTEGER PRIMARY KEY CHECK(id=1),record TEXT NOT NULL)")
  Sys.chmod(path,"0600")
  invisible(NULL)
}
