\name{dsvertDPGaussianCrossBindDS}
\alias{dsvertDPGaussianCrossBindDS}
\title{Bind signed cross-owner Gaussian inputs}
\usage{
dsvertDPGaussianCrossBindDS(manifest_json, analysis_id, session_id)
}
\arguments{
\item{manifest_json}{Canonical signed biomedical-capsule manifest.}
\item{analysis_id}{Signed cross-owner Gaussian analysis identifier.}
\item{session_id}{Pinned two-peer exact-computation session identifier.}
}
\value{A signed, redacted binding receipt.}
\description{
Binds fixed-capacity private Ring128 source shares to a purpose-bound exact
two-peer computation. No source value, alignment hash, or exact statistic is
returned.
}
