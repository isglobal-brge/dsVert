\name{dsvertOrdinalReceiveClassMaskDS}
\alias{dsvertOrdinalReceiveClassMaskDS}
\title{Receive one strict ordinal class-mask share}
\usage{
dsvertOrdinalReceiveClassMaskDS(
  mask_blob_key,
  output_key,
  session_id = NULL
)
}
\arguments{
\item{mask_blob_key}{Session blob slot containing the encrypted mask share.}
\item{output_key}{Session slot to receive the Ring127 share.}
\item{session_id}{MPC session id.}
}
\value{
List with \code{stored = TRUE} and the output session key.
}
\description{
Peer-side counterpart to \code{dsvertOrdinalShareClassMasksDS}. Decrypts one
opaque class-mask share blob and stores it under \code{output_key}.
}
