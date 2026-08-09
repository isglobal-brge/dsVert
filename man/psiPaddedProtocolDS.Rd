\name{psiPaddedProtocolDS}
\alias{psiPaddedInitDS}
\alias{psiPaddedBindDS}
\alias{psiPaddedConfirmDS}
\alias{psiPaddedPrepareDS}
\alias{psiPaddedReferenceExportDS}
\alias{psiPaddedTargetProcessDS}
\alias{psiPaddedReferenceDoubleDS}
\alias{psiPaddedTargetMatchDS}
\alias{psiPaddedMembershipAcceptDS}
\alias{psiPaddedANDStartDS}
\alias{psiPaddedANDFinalizeDS}
\alias{psiPaddedANDAcceptDS}
\alias{psiPaddedFinalPrepareDS}
\alias{psiPaddedFilterDS}
\alias{psiPaddedAttestationDS}
\alias{psiPaddedRelayExchangeDS}
\title{Purpose-bound fixed-capacity pinned PSI server protocol}
\usage{
psiPaddedInitDS(data_name, id_col, session_id, operation_id)

psiPaddedBindDS(offers_b64url, connection_names_b64url, session_id)

psiPaddedConfirmDS(receipts_b64url, session_id)

psiPaddedPrepareDS(data_name, session_id)

psiPaddedReferenceExportDS(target, session_id, force_relay = FALSE)

psiPaddedTargetProcessDS(envelope = "", relay_descriptor_b64url = "",
  session_id, force_relay = FALSE)

psiPaddedReferenceDoubleDS(target, envelope = "",
  relay_descriptor_b64url = "", session_id, force_relay = FALSE)

psiPaddedTargetMatchDS(envelope = "", relay_descriptor_b64url = "",
  session_id, force_relay = FALSE)

psiPaddedMembershipAcceptDS(target, envelope = "",
  relay_descriptor_b64url = "", session_id)

psiPaddedANDStartDS(chunk_index, session_id)

psiPaddedANDFinalizeDS(chunk_index, session_id, force_relay = FALSE)

psiPaddedANDAcceptDS(chunk_index, sender, envelope = "",
  relay_descriptor_b64url = "", session_id)

psiPaddedFinalPrepareDS(session_id, force_relay = FALSE)

psiPaddedFilterDS(data_name, envelope = "", relay_descriptor_b64url = "",
  session_id)

psiPaddedAttestationDS(data_name, session_id = "")

psiPaddedRelayExchangeDS(request_json, session_id,
  outbound_operation_id = "", terminal_receipt_b64url = "")
}
\arguments{
\item{data_name}{Validated server-side source or aligned-object symbol.}
\item{id_col}{Identifier-column name.}
\item{session_id}{Canonical protocol session identifier. An empty value is
accepted only by the persistent attestation check.}
\item{operation_id}{Canonical purpose-bound operation identifier.}
\item{offers_b64url}{Bounded canonical base64url JSON bootstrap set.}
\item{connection_names_b64url}{Bounded canonical base64url JSON logical peer
names.}
\item{receipts_b64url}{Bounded canonical base64url JSON all-peer receipt set.}
\item{target}{Logical pinned target-peer name.}
\item{force_relay}{Logical; force the bounded streaming relay instead of the
bounded inline envelope path.}
\item{envelope}{Authenticated inline ciphertext, or the empty string when a
relay descriptor is used.}
\item{relay_descriptor_b64url}{Bounded descriptor for a purpose-bound relay
ciphertext.}
\item{chunk_index}{One-based fixed-capacity exact-AND chunk index.}
\item{sender}{Logical pinned sender-peer name.}
\item{request_json}{Bounded fixed-schema relay exchange request.}
\item{outbound_operation_id}{Optional purpose-bound outbound relay operation.}
\item{terminal_receipt_b64url}{Optional authenticated terminal delivery
receipt.}
}
\description{
These sixteen purpose-bound DataSHIELD entry points implement the sole public
record-alignment route used by \code{dsVertClient::ds.psiAlign()}. Inputs are
padded to a public, server-owned fixed-capacity bucket. The relay transports
only signed, encrypted, fixed-shape protocol messages and cannot choose an
arbitrary payload source or destination.
}
\details{
The contract binds every named pinned peer, snapshot, capacity, relay geometry,
reference and pair of exact-GC compute peers. Every peer signs the contract
before private processing begins. Exact GC/OT computes the all-server
membership predicate in fixed chunks; the client never obtains identifiers,
row maps, membership vectors or exact cardinality. Relay retries are offset
bound and idempotent, and final delivery requires authenticated receipts.

These functions are protocol internals registered for DataSHIELD dispatch.
Call the client front door rather than invoking phases individually.
}
\value{
Bounded protocol acknowledgements, authenticated ciphertext descriptors, or a
fixed-schema public attestation. \code{psiPaddedFilterDS()} is an assign method
that returns the locally aligned data frame with authenticated private
alignment metadata.
}
