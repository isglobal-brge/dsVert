library(digest)
library(microbenchmark)

generate_id_strings <- function(n, length = 10) {
  replicate(n, paste0(sample(c(letters, LETTERS, 0:9), length, replace = TRUE), collapse = ""))
}

timed_hash_and_reorder <- function(n_ids, algo, id_length = 10) {

  ids <- geneIDrate_id_strings(n_ids, id_length)

  Partition1 <- data.frame(id = ids, var1 = rnorm(n_ids))
  Partition2 <- data.frame(id = ids, var2 = rnorm(n_ids))
  Partition3 <- data.frame(id = ids, var3 = rnorm(n_ids))

  timing_result <- microbenchmark(
    {
      all_hashes <- hashIdDS(Partition1, "id", algo)
      reordered_data2 <- reorderTableDS(Partition2, "id", all_hashes, algo)
      reordered_data3 <- reorderTableDS(Partition3, "id", all_hashes, algo)
    }, times = 10
  )

  return(timing_result)
}

run_experiment <- function(id_lengths = c(1000, 5000, 10000,20000), algorithms = c("md5", "sha1", "sha256", "sha512")) {
  results <- list()

  for (n_ids in id_lengths) {
    for (algo in algorithms) {
      #message(paste("Running experiment for", algo, "with", n_ids, "IDs"))

      timing <- timed_hash_and_reorder(n_ids, algo)

      results[[paste(algo, n_ids, sep = "_")]] <- summary(timing, unit="ms")
    }
  }

  return(results)
}

hashIdDS <- function(data_name, id_variable, algo = "sha256") {
  beforeHash <- data_name[[id_variable]]
  orderHash1 <- sapply(beforeHash, digest, algo = algo)
  return(orderHash1)
}

reorderTableDS <- function(table_name, id_var, hash_list, algo = "sha256") {
  beforeHash <- table_name[[id_var]]
  orderHash <- sapply(beforeHash, digest, algo = algo)
  hash_match <- match(hash_list, orderHash)
  table_name <- table_name[hash_match, ]
  return(table_name)
}

experiment_results <- run_experiment()
print(experiment_results)
