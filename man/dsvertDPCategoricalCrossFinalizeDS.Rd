\name{dsvertDPCategoricalCrossFinalizeDS}
\alias{dsvertDPCategoricalCrossFinalizeDS}
\title{Finalize a cross-owner categorical exact transcript}
\usage{
dsvertDPCategoricalCrossFinalizeDS(manifest_json, analysis_id, session_id)
}
\arguments{
\item{manifest_json}{Canonical signed biomedical-capsule manifest.}
\item{analysis_id}{Signed cross-owner categorical analysis identifier.}
\item{session_id}{Pinned two-peer exact-computation session identifier.}
}
\value{A signed, redacted persistence receipt.}
\description{
Reduces the fixed product segments into one private additive share of the
final column-major contingency vector. The share is stored for direct joint-DP
sampling and is never returned to the analyst.
}
