test_that("plaintext DCF weight helpers are absent", {
  ns <- asNamespace("dsVert")
  removed <- c(
    "k2SetWeightsDS",
    "k2ReceiveWeightsDS",
    "k2ApplyWeightsDS",
    "k2ApplySqrtWeightsDS")
  present <- vapply(removed, exists, logical(1), envir = ns, inherits = FALSE)
  expect_false(any(present), info = paste(names(present)[present], collapse = ", "))
})
