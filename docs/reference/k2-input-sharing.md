# K=2 Input-Sharing + Gradient (ALL in FixedPoint Ring63)

All operations stay in the FixedPoint ring until the final gradient
scalars are converted to float64. This prevents the int64 wrapping
non-additivity issue that caused gradient divergence.
