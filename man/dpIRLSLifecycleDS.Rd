\name{dpIRLSLifecycleDS}
\alias{dpIRLSMetadataDS}
\alias{dpIRLSStartDS}
\alias{dpIRLSResumeDS}
\alias{dpIRLSPublicationDS}
\alias{dpIRLSRelayDS}
\title{Run a custodian-provisioned experimental DP IRLS stage}
\usage{
dpIRLSMetadataDS(analysis_id)
dpIRLSStartDS(analysis_id)
dpIRLSResumeDS(analysis_id)
dpIRLSPublicationDS(analysis_id)
dpIRLSRelayDS(analysis_id, frame = "")
}
\arguments{
\item{analysis_id}{The custodian-provisioned signed analysis selector.}
\item{frame}{An opaque authenticated peer ciphertext or the empty polling frame.}
}
\description{Executes a fixed signed two-authority score and curvature stage with
mandatory split discrete Laplace convolution noise and durable dual-signed
publication. These experimental adapters do not provide qualified inference.}
\details{Sources, person slots, epochs, identities, schedule, coefficient path and
privacy allocations are provisioned by the custodian. The analyst cannot set a
coefficient, predecessor, source, peer key or noise-off option. Relay frames carry
only ciphertext addressed to the pinned peer. The publication reader returns
only completed parent stages. Source validity and exact aggregates are never
returned.}
\value{A public signed-contract description, a public stage status, an opaque
relay frame, or the completed dual-signed DP stage chain.}
