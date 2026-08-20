\name{dsvertDPSynopsisLifecycleDS}
\alias{dsvertDPSynopsisLifecycleDS}
\alias{dsvertDPSynopsisBootstrapDS}
\alias{dsvertDPSynopsisBindDS}
\alias{dsvertDPSynopsisClaimDS}
\alias{dsvertDPSynopsisCompileDS}
\alias{dsvertDPSynopsisPrepareDS}
\alias{dsvertDPSynopsisStartDS}
\alias{dsvertDPSynopsisResultDS}
\alias{dsvertDPSynopsisFinalShareDS}
\alias{dsvertDPSynopsisReleaseDS}
\alias{dsvertDPSynopsisSourceTicketDS}
\alias{dsvertDPSynopsisSourcePrepareDS}
\alias{dsvertDPSynopsisSourceChunkDS}
\alias{dsvertDPSynopsisSourceAcceptDS}
\alias{dsvertDPSynopsisPublicationDS}
\alias{dsvertDPSynopsisPublishedReplayDS}
\alias{dsvertDPSynopsisFinalizeAckDS}
\alias{dsvertDPSynopsisCategoricalCrossBindDS}
\alias{dsvertDPSynopsisCategoricalCrossFinalizeDS}
\alias{dsvertDPSynopsisAlignmentMaskStartDS}
\alias{dsvertDPSynopsisAlignmentMaskStoreDS}
\alias{dsvertDPSynopsisAlignmentMaskSealDS}
\alias{dsvertDPSynopsisAlignmentMaskReceiveDS}
\title{Execute one stateless sticky catalog Synopsis lifecycle}
\usage{
dsvertDPSynopsisBootstrapDS()

dsvertDPSynopsisBindDS(bootstrap_set_json)

dsvertDPSynopsisClaimDS(manifest_sha256)

dsvertDPSynopsisCompileDS(manifest_sha256, claims_json)

dsvertDPSynopsisPrepareDS(
  session_id,
  manifest_sha256,
  claim_set_json,
  compilation_json
)

dsvertDPSynopsisStartDS(
  session_id,
  first_prepare_json,
  second_prepare_json,
  chunk_index
)

dsvertDPSynopsisResultDS(
  session_id,
  first_prepare_json,
  second_prepare_json
)

dsvertDPSynopsisFinalShareDS(
  session_id,
  first_result_json,
  second_result_json,
  public_chunk_index
)

dsvertDPSynopsisReleaseDS(
  session_id,
  first_result_json,
  second_result_json
)

dsvertDPSynopsisSourceTicketDS(
  manifest_sha256,
  claim_set_json,
  compilation_json
)

dsvertDPSynopsisSourcePrepareDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  first_ticket_json,
  second_ticket_json
)

dsvertDPSynopsisSourceChunkDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  source_transfer_id,
  chunk_index
)

dsvertDPSynopsisSourceAcceptDS(manifest_sha256, envelope_json)

dsvertDPSynopsisPublicationDS(manifest_sha256)

dsvertDPSynopsisPublishedReplayDS(
  artifact_key,
  first_release_json,
  second_release_json,
  public_chunk_index
)

dsvertDPSynopsisFinalizeAckDS(
  manifest_sha256,
  first_release_json,
  second_release_json
)

dsvertDPSynopsisCategoricalCrossBindDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  analysis_id,
  session_id
)

dsvertDPSynopsisCategoricalCrossFinalizeDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  analysis_id,
  session_id
)

dsvertDPSynopsisAlignmentMaskStartDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  batch_operation_id,
  operation_id,
  chunk_index,
  chunk_count,
  session_id
)

dsvertDPSynopsisAlignmentMaskStoreDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  batch_operation_id,
  operation_id,
  chunk_index,
  chunk_count,
  session_id
)

dsvertDPSynopsisAlignmentMaskSealDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  batch_operation_id,
  session_id
)

dsvertDPSynopsisAlignmentMaskReceiveDS(
  manifest_sha256,
  claim_set_json,
  compilation_json,
  peer_blob,
  batch_operation_id,
  session_id
)
}
\arguments{
\item{bootstrap_set_json}{Canonical two-round Bind request containing the
exact pinned-peer Bootstrap set and, in the second round, the exact pinned-peer
schema-signature set.}

\item{manifest_sha256}{SHA-256 identity of the server-authoritative catalog
manifest.}

\item{artifact_key}{SHA-256 identity of the canonical compiled Synopsis
artifact.}

\item{claims_json}{Canonical array containing one signed Claim from every
pinned peer.}

\item{session_id}{Authenticated UUID for the two-authority execution.}

\item{claim_set_json}{Canonical, unanimously compiled source Claim set.}

\item{compilation_json}{Canonical compiled artifact and complete signed
receipt set.}

\item{first_prepare_json, second_prepare_json}{The two designated
authorities' signed PREPARE records.}

\item{chunk_index}{Zero-based fixed execution or source chunk index.}

\item{first_result_json, second_result_json}{The two designated authorities'
signed RESULT records.}

\item{public_chunk_index}{Zero-based public release chunk index.}

\item{first_release_json, second_release_json}{The two complete Publication
envelopes supplied to PublishedReplay and FinalizeAck; each carries the
exact-K signed compilation set and one authority's signed durable RELEASE.}

\item{first_ticket_json, second_ticket_json}{The designated authorities'
recipient-bound source tickets.}

\item{source_transfer_id}{Server-minted source-transfer identifier.}

\item{envelope_json}{One framed canonical signed ciphertext envelope for the
manifest-bound Synopsis source transfer.}

\item{analysis_id}{The signed categorical-pair analysis identifier selected
by the projected manifest.}

\item{batch_operation_id, operation_id}{Manifest-bound identifiers for the
fixed-shape private alignment batch and one of its exact-GC chunks.}

\item{chunk_count}{Public fixed number of alignment-mask chunks.}

\item{peer_blob}{Opaque authenticated terminal validity share emitted by the
other designated computation peer.}
}
\value{
A bounded canonical JSON lifecycle record. Inputs ending in \code{_json} and
all JSON results cross DSI in the package's framed text encoding.
}
\description{
These endpoints compile and execute one server-authoritative catalog Synopsis
across a pinned consortium. Every peer contributes Claim and Compile evidence;
only the two identity-selected authorities create execution state or combine
source shares. RELEASE and session-free PublishedReplay expose only the signed,
Merkle-proved public DP vector. Bootstrap and the two-round Bind derive the
manifest solely from custodian-owned configuration. Publication and FinalizeAck
preserve durable replay while reclaiming artifact-bound source intermediates
without a session. PublishedReplay supersedes the retired session-bound replay
route.
}
\details{
The route accepts no analyst-selected privacy parameters, numeric bounds,
owners or artifact geometry. The ordinary catalog path rejects cross-owner
artifacts. One separately authorized signed categorical-pair projection may
instead use the manifest-bound alignment-mask and cross-product endpoints
above; exact marginals, products and cells remain unopened until the one noisy
Synopsis release.
Private source shares, sticky seeds, sampled noise, pre-release aggregates and
recipient final shares remain encrypted or server-local. Identical requests
replay the same signed evidence and committed public chunks. Privacy is scoped
honestly to each canonical sticky artifact; the route has no request-rate
limit, catalog quota, lifetime release allocator, or global finite-composition
claim. A manifest and logical snapshot identify one immutable artifact;
custodians must rotate the signed snapshot version if protected data changes.
}
