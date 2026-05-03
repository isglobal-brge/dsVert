% Generated manually for dsVert cluster share helpers
\name{cluster-share-helpers}
\alias{dsvertClusterIDsBroadcastDS}
\alias{dsvertClusterIDsReceiveDS}
\alias{dsvertPerClusterSumShareDS}
\alias{dsvertGLMMOneMinusMuDS}
\title{Cluster share helpers for vertical mixed-model moments}
\usage{
dsvertClusterIDsBroadcastDS(data_name, cluster_col, peer_pk, session_id = NULL)

dsvertClusterIDsReceiveDS(session_id = NULL)

dsvertPerClusterSumShareDS(
  share_key,
  session_id = NULL,
  frac_bits = 20L,
  ring = 63L
)

dsvertGLMMOneMinusMuDS(
  output_key = "glmm_one_minus_mu_share",
  is_party0 = FALSE,
  session_id = NULL,
  frac_bits = 20L,
  ring = 63L
)
}
\arguments{
\item{data_name}{Aligned data frame.}
\item{cluster_col}{Cluster column on the outcome server.}
\item{peer_pk}{Transport public key of the DCF peer.}
\item{session_id}{Active MPC session identifier.}
\item{share_key}{Session slot holding an FP share vector.}
\item{frac_bits}{Fixed-point fractional bits.}
\item{ring}{Integer 63 or 127.}
\item{output_key}{Session slot for the generated share.}
\item{is_party0}{Logical; TRUE for the first DCF party.}
}
\value{
Metadata for the stored shares or per-cluster FP scalar shares.
}
\description{
Helpers used by vertical GLMM/LMM-style follow-on rounds. Cluster
membership is transported only between DCF parties; the analyst client
relays opaque blobs and receives aggregate per-cluster sums only. Original
cluster labels are not returned to the client, and helpers fail closed when
a cluster is smaller than \code{datashield.privacyLevel}.
}
