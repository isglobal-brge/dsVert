% Generated manually for dsVert LMM stored-cluster helper
\name{dsvertLMMXCovarianceWithinStoredDS}
\alias{dsvertLMMXCovarianceWithinStoredDS}
\title{Within-cluster X covariance from stored cluster IDs}
\usage{
dsvertLMMXCovarianceWithinStoredDS(data_name, x_vars, session_id = NULL)
}
\arguments{
\item{data_name}{Aligned data frame name.}
\item{x_vars}{Character vector of X column names on this server.}
\item{session_id}{Active MPC session identifier.}
}
\value{
list(SX2_within = matrix p x p, df_within = integer scalar,
p = ncol, x_vars = character).
}
\description{
Non-disclosive variant of \code{dsvertLMMXCovarianceWithinDS}. The
cluster assignment vector is read from the active MPC session after an
encrypted \code{dsvertClusterIDsBroadcastDS}/\code{dsvertClusterIDsReceiveDS}
exchange, so the analyst client does not receive row-level cluster
membership.
}
