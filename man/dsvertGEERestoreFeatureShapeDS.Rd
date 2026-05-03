% Generated manually for dsVert GEE sandwich helpers
\name{dsvertGEERestoreFeatureShapeDS}
\alias{dsvertGEERestoreFeatureShapeDS}
\title{Restore GLM feature-share dimensions for GEE follow-on rounds}
\usage{
dsvertGEERestoreFeatureShapeDS(p_own, p_peer, session_id = NULL)
}
\arguments{
\item{p_own}{Number of feature columns owned by this DCF party.}
\item{p_peer}{Number of feature columns held in the peer-share matrix.}
\item{session_id}{Active MPC session identifier.}
}
\value{
List with \code{stored}, \code{p_own}, and \code{p_peer}.
}
\description{
The GLM deviance pass temporarily changes the active \code{k2_x_*}
shape to an n-by-1 residual vector. Follow-on sandwich rounds need the
original feature-share dimensions so \code{k2ComputeEtaShareDS()} can
rebuild the full design share without rerunning PSI or input sharing.
}
