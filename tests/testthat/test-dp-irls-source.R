test_that("source conversion is exact nearest-even with signed bounds", {
  q<-function(n,d="1") list(n=as.character(n),d=as.character(d))
  bounds<-list(lower=q(-1),upper=q(1))
  encode<-function(x) .dsvert_dp_irls_encode_scalar(x,bounds)
  for (i in -8:8) {
    x<-(i+0.5)/65536
    expected<-as.character(if(i%%2==0) i else i+1)
    expect_identical(encode(x),list(value=expected,valid=TRUE))
  }
  expect_identical(encode(-1),list(value="-65536",valid=TRUE))
  expect_identical(encode(1),list(value="65536",valid=TRUE))
  expect_identical(encode(0.1),list(value="6554",valid=TRUE))
  expect_identical(encode(2^-1074),list(value="0",valid=TRUE))
  for(x in list(NA_real_,NaN,Inf,-Inf,1+2^-52,-1-2^-52,"0",factor("0"),list(0)))
    expect_identical(encode(x),list(value="0",valid=FALSE))
  for(x in c(0,1)) expect_true(.dsvert_dp_irls_encode_scalar(x,list(lower=q(0),upper=q(1)),TRUE)$valid)
  expect_false(.dsvert_dp_irls_encode_scalar(0.5,list(lower=q(0),upper=q(1)),TRUE)$valid)
  expect_identical(.dsvert_dp_irls_conversion_certificate()$failure_probability,list(d="1",n="0"))
})

test_that("signed source Ring128 encoding preserves negatives without opening", {
  raw<-.dsvert_dp_irls_ring128_bytes(list("-1","0","65536","-65536"))
  expect_identical(raw[1:16],rep(as.raw(255),16))
  expect_identical(raw[17:32],raw(16))
  expect_identical(raw[33:36],as.raw(c(0,0,1,0)))
  expect_identical(raw[49:52],as.raw(c(0,0,255,255)))
})

test_that("logical IRLS endpoints expose only a provisioned selector", {
  for(f in list(dpIRLSMetadataDS,dpIRLSStartDS,dpIRLSResumeDS,dpIRLSPublicationDS)) {
    expect_identical(names(formals(f)),"analysis_id")
    expect_error(do.call(f,list(analysis_id="unprovisioned",beta=list(0))),"unused argument")
    expect_error(do.call(f,list(analysis_id="unprovisioned",predecessor="injected")),"unused argument")
    expect_error(f("unprovisioned"),"unprovisioned")
  }
  expect_identical(names(formals(dpIRLSRelayDS)),c("analysis_id","frame"))
  expect_error(dpIRLSRelayDS("unprovisioned",beta=0),"unused argument")
})

test_that("frozen owner source masks only its malformed person", {
  f<-.irls_producer_fixture();s<-f$spec
  data<-data.frame(x=c(0.5,NA,1+2^-52),z=c(-1,0,0.25))
  frozen<-list(predictors=data)
  body<-list(root=.dsvert_dp_irls_root(s),owner="peer_b",source_abi=.DSVERT_DP_IRLS_SOURCE_ABI,
    conversion=.dsvert_dp_irls_conversion_certificate(),person_slot_binding=paste(rep("ab",32),collapse=""),
    records=list(predictors=list(snapshot_sha256=digest::digest(serialize(data,NULL,version=3L),algo="sha256",serialize=FALSE))))
  sealed<-list(body=body,frozen=frozen,signature=.dsvert_relay_sign_message(
    .dsvert_dp_irls_source_message(body),f$identities$peer_b$identity_sk))
  material<-.dsvert_dp_irls_source_materialize(s,sealed)
  raw<-jsonlite::base64_dec(material$source_share)
  word<-function(i) raw[((i-1)*16+1):(i*16)]
  expect_identical(word(2),c(as.raw(1),raw(15)))
  expect_identical(word(4),.dsvert_dp_irls_ring128_bytes(list("32768")))
  expect_identical(word(5),.dsvert_dp_irls_ring128_bytes(list("-65536")))
  for(row in 2:4) expect_identical(raw[((row-1)*7*16+1):(row*7*16)],raw(7*16))
  expect_identical(tail(raw,32),rep(as.raw(171),32))
  bad<-sealed;bad$frozen$predictors$x[[1]]<-0
  expect_error(.dsvert_dp_irls_source_materialize(s,bad),"snapshot")
  bad<-sealed;bad$body$person_slot_binding<-paste(rep("cd",32),collapse="")
  expect_error(.dsvert_dp_irls_source_materialize(s,bad),"authenticated source")
  other<-s;other$privacy_source$closure$dependencies[[1]]$dependency$authorization_epoch<-paste(rep("f",64),collapse="")
  expect_error(.dsvert_dp_irls_source_materialize(other,sealed))
})

test_that("recovery abort agreement precedes both fresh worker attempts", {
  started<-character()
  testthat::local_mocked_bindings(
    .dsvert_dp_irls_persist=function(entry) invisible(NULL),
    .dsvert_dp_irls_worker_start=function(entry) {started<<-c(started,entry$authority);invisible(NULL)},
    .package="dsVert")
  peer<-function(name) {e<-new.env(parent=emptyenv());e$authority<-name;e$pair<-c("a","b")
    e$worker<-new.env(parent=emptyenv());e$worker$process<-NULL;e$recovery<-NULL;e}
  a<-peer("a");b<-peer("b")
  .dsvert_dp_irls_recovery_request(b)
  expect_identical(b$recovery$phase,"request")
  .dsvert_dp_irls_recovery_receive(a,b$recovery)
  expect_identical(a$recovery$phase,"offer");expect_length(started,0)
  .dsvert_dp_irls_recovery_receive(b,a$recovery)
  expect_identical(b$recovery$phase,"ack");expect_length(started,0)
  .dsvert_dp_irls_recovery_receive(a,b$recovery)
  expect_identical(started,"a");expect_identical(a$recovery$phase,"started")
  .dsvert_dp_irls_recovery_receive(b,a$recovery)
  expect_identical(started,c("a","b"));expect_false(.dsvert_dp_irls_recovering(a))
  expect_false(.dsvert_dp_irls_recovering(b))
  .dsvert_dp_irls_recovery_receive(a,b$recovery)
  .dsvert_dp_irls_recovery_receive(b,a$recovery)
  expect_identical(started,c("a","b"))
})

test_that("private provisioning registry is durable and rejects seed loss", {
  path<-file.path(tempdir(),paste0("irls-private-registry-",Sys.getpid(),"-",sample.int(1e8,1)),"private.sqlite")
  dir.create(dirname(path),mode="0700");on.exit(unlink(dirname(path),recursive=TRUE),add=TRUE)
  .dsvert_dp_irls_registry_create(path)
  expect_true(file.exists(path))
  .dsvert_dp_irls_store_open(path,function(db) {
    expect_identical(DBI::dbGetQuery(db,"PRAGMA synchronous")[[1]],2L)
    DBI::dbWithTransaction(db,DBI::dbExecute(db,"INSERT INTO registry VALUES (1,?)",params=list("retained-noise-root")))
  })
  expect_identical(.dsvert_dp_irls_store_open(path,function(db)
    DBI::dbGetQuery(db,"SELECT record FROM registry")$record),"retained-noise-root")
  expect_error(.dsvert_dp_irls_registry_create(path),"already provisioned")
  unlink(path)
  expect_error(.dsvert_dp_irls_store_open(path,identity),"missing")
  expect_error(.dsvert_dp_irls_registry_create(path),"already provisioned")
})
