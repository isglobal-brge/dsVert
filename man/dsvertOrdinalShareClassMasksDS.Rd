\name{dsvertOrdinalShareClassMasksDS}
\alias{dsvertOrdinalShareClassMasksDS}
\title{Secret-share ordinal class masks for the strict joint path}
\usage{
dsvertOrdinalShareClassMasksDS(
  data_name,
  indicator_cols,
  level_names,
  output_prefix = "ord_mask",
  peer_pk,
  session_id = NULL
)
}
\arguments{
\item{data_name}{Name of the aligned data frame.}
\item{indicator_cols}{Character vector of K-1 cumulative indicator columns.}
\item{level_names}{Ordered class names.}
\item{output_prefix}{Prefix for session slots that will hold mask shares.}
\item{peer_pk}{Transport public key of the peer DCF party.}
\item{session_id}{MPC session id.}
}
\value{
List with stored flag, mask session keys, opaque encrypted mask blobs, and
guarded class counts.
}
\description{
Outcome-side helper for the non-disclosive ordinal joint likelihood. It
derives one-hot class indicators from cumulative \code{I(Y <= k)} columns,
splits each indicator vector into additive Ring127 shares, keeps one share
locally, and transport-encrypts the peer share. The analyst/client receives
only opaque encrypted blobs and guarded class counts.
}
