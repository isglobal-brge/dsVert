\name{dsvertDPGaussianCrossPrepareDS}
\alias{dsvertDPGaussianCrossPrepareDS}
\title{Prepare a fixed cross-owner Gaussian exact stage}
\usage{
dsvertDPGaussianCrossPrepareDS(analysis_id, stage, stage_index, session_id)
}
\arguments{
\item{analysis_id}{Signed cross-owner Gaussian analysis identifier.}
\item{stage}{One fixed transcript stage.}
\item{stage_index}{The signed stage index.}
\item{session_id}{Pinned two-peer exact-computation session identifier.}
}
\value{An opaque one-shot exact-multiplication manifest.}
\description{
Prepares the next purpose-bound multiplication in the signed, fixed-capacity
cross-owner Gaussian transcript.
}
