\name{gee-ar1-order-primitives}
\alias{dsvertGEEAR1OrderBroadcastDS}
\alias{dsvertGEEAR1OrderReceiveDS}
\alias{dsvertGEEAR1TransformShareDS}
\title{GEE AR1 Order-Share Aggregate Primitives}
\description{
Low-level DataSHIELD aggregate primitives used by the dsVertClient GEE AR1
route. They relay encrypted order metadata between the selected DCF parties
and transform share-domain residual slots for AR1 working-correlation
assembly. They are registered for orchestration and are not analyst-facing
estimators.
}
\usage{
dsvertGEEAR1OrderBroadcastDS(data_name, cluster_col, order_col, peer_pk,
  session_id = NULL)

dsvertGEEAR1OrderReceiveDS(session_id = NULL)

dsvertGEEAR1TransformShareDS(source_key, output_key,
  transform = c("lead", "lag", "nonlast", "nonfirst", "interior"),
  session_id = NULL, frac_bits = 20L, ring = 63L)
}
\arguments{
\item{data_name}{Aligned data frame name.}
\item{cluster_col, order_col}{Cluster and within-cluster order columns.}
\item{peer_pk}{Transport public key of the peer DCF party.}
\item{session_id}{MPC session identifier.}
\item{source_key, output_key}{Session slots containing the input and output shares.}
\item{transform}{Share-domain AR1 transformation to apply.}
\item{frac_bits, ring}{Fixed-point encoding controls.}
}
\keyword{internal}
