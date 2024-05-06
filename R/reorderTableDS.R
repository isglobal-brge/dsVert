#' Serverside function for ordering a dataset according to a list of hashes of the same id variable
#'
#' @param table_name The dataframe that needs to be ordered
#' @param id_var The id variable to be hashed (if this is different from the one used in hash_list we end up with an ordered df with all NULL VALUES)
#' @param hash_list List of hashes to be used for ordering
#' @param new_table_name Name of new object to be created that is in the same order as the hash_list
#'
#' @return Should assign a new object only
#' @export
#'
#' @examples reorderTableDS(D,"id",all_hashes, "orderedTable")
reorderTableDS <- function(table_name, id_var, hash_list, new_table_name = "orderedTable") {

  # The same strategy as in hashRownamesDS.R
  beforeHash <- table_name[[id_var]]
  orderHash <- vector("character", length(beforeHash))
  for(i in 1:length(beforeHash)){
    orderHash[i] <- digest(beforeHash[i], algo = "sha256")
  }

  # Then match and create new ordered table
  hash_match <- match(hash_list, orderHash)

  table_name <- table_name[hash_match, ]
  assign(new_table_name, table_name, envir = .GlobalEnv)

}
