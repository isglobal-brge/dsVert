#' Hash list of text or IDs
#'
#' @param strings list of string elements to be turned into hashes
#' @param method additive or polynomial methods currently implemented
#'
#' @return a vector of the original list size containing the hash values
#' @export
#'
#' @examples hash_text(c("one", "two", "three"))
#' @examples hash_text(c("one", "two", "three"), "additive")
#' @examples hash_text(c("one", "two", "three"), method = "polynomial")
#'
hash_text <- function(strings, method = "additive") {
  hashes <- numeric(length(strings))

  for (i in seq_along(strings)) {
    if (method == "additive") {
      hashes[i] <- additive_hash(strings[[i]])
    } else if (method == "polynomial") {
      hashes[i] <- polynomial_hash(strings[[i]])
    } else {
      stop("Wrong hash method.")
    }
  }

  return(hashes)
}

#additive hash function
additive_hash <- function(s) {
  hash <- 0
  for (char in utf8ToInt(s)) {
    hash <- hash + char
  }
  return(hash)
}

#polynomial hash function that uses a prime number
polynomial_hash <- function(s, a = 37) {
  hash <- 0
  for (char in utf8ToInt(s)) {
    hash <- a*hash + char
  }
  return(hash)
}


