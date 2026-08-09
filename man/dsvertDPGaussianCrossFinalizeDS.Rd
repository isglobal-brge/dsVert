\name{dsvertDPGaussianCrossFinalizeDS}
\alias{dsvertDPGaussianCrossFinalizeDS}
\title{Finalize a cross-owner Gaussian exact transcript}
\usage{
dsvertDPGaussianCrossFinalizeDS(manifest_json, analysis_id, session_id)
}
\arguments{
\item{manifest_json}{Canonical signed biomedical-capsule manifest.}
\item{analysis_id}{Signed cross-owner Gaussian analysis identifier.}
\item{session_id}{Pinned two-peer exact-computation session identifier.}
}
\value{A signed, redacted persistence receipt.}
\description{
Reduces and assembles the completed Ring128 transcript into one private
additive share of the final sufficient-statistic vector. The share is stored
for direct joint-DP sampling and is never returned to the analyst.
}
