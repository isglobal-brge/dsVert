\name{dsvertDPCategoricalCrossBindDS}
\alias{dsvertDPCategoricalCrossBindDS}
\title{Bind signed cross-owner categorical inputs}
\usage{
dsvertDPCategoricalCrossBindDS(
  manifest_json,
  analysis_id,
  session_id,
  first_opening_json,
  second_opening_json
)
}
\arguments{
\item{manifest_json}{Canonical signed biomedical-capsule manifest.}
\item{analysis_id}{Signed cross-owner categorical analysis identifier.}
\item{session_id}{Pinned two-peer exact-computation session identifier.}
\item{first_opening_json, second_opening_json}{Cross-signed allocation
openings verified before any private aggregate share is loaded.}
}
\value{A signed, redacted binding receipt.}
\description{
Binds fixed-capacity one-hot Ring128 source shares to one purpose-bound exact
two-peer computation. No source value, alignment hash, marginal, or exact cell
count is returned.
}
