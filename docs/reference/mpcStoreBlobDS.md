# Store a blob on server (adaptive chunking support)

Store a blob on server (adaptive chunking support)

## Usage

``` r
mpcStoreBlobDS(key, chunk, chunk_index = 1L, n_chunks = 1L, session_id = NULL)
```

## Arguments

- key:

  Character. Blob key.

- chunk:

  Character. Blob data (or chunk if multi-part).

- chunk_index:

  Integer. Chunk index (1-based).

- n_chunks:

  Integer. Total chunks.

- session_id:

  Character or NULL.

## Value

TRUE on success.
