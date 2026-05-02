# Append synthetic exponential time + binary event columns (test helper)

Draw `time ~ Exp(lambda_i)` with
`lambda_i = 1 / (base_scale * (1 + beta * x))` where `x` is a covariate
column held on this server, and a binary `event` indicator with rate
`event_rate`. Used to validate `ds.vertCox` on datasets that do not ship
with native time-to-event data. Both new columns are written back to the
data frame. Only aggregate counts are returned.

## Usage

``` r
dsvertAddSyntheticSurvivalDS(
  data_name,
  covariate_column,
  beta = 0.05,
  base_scale = 20,
  event_rate = 0.6,
  time_column = "time",
  event_column = "event",
  seed = 13L,
  id_column = "patient_id"
)
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- covariate_column:

  Character. Name of the covariate column whose effect drives the
  synthetic survival times.

- beta:

  Numeric. True regression coefficient for the synthetic data generator.

- base_scale:

  Numeric. Baseline-hazard scale for the exponential survival generator.

- event_rate:

  Numeric in (0, 1). Target marginal event rate for censoring.

- time_column:

  Character. Name of the survival-time column to add.

- event_column:

  Character. Name of the event-indicator column to add.

- seed:

  Integer. RNG seed for reproducibility (NULL leaves RNG untouched).

- id_column:

  Character. Name of the row-id column.
