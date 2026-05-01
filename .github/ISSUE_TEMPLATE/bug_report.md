---
name: Bug report
about: Report a problem in dsVert (the server-side package)
labels: bug
---

## What happened

<!-- A clear description of the unexpected behaviour. -->

## What did you expect

<!-- What you thought would happen. -->

## Reproducer

```r
# Minimal R session that reproduces the issue:
library(dsVert)
# ...
```

If the issue is method-specific (e.g. `dsvertCoxNewtonGradDS`),
include the upstream `ds.vert*` client call as well, or note that
you were calling the method directly.

## Environment

- dsVert version: <output of `packageVersion("dsVert")`>
- dsVertClient version: <output of `packageVersion("dsVertClient")`>
- R version: <output of `R.version.string`>
- Platform: <macOS / Linux / Windows + arch>
- DataSHIELD backend: <Opal version, or DSLite, or local-harness>
- K (number of servers): <2 or 3>

## Disclosure check

- [ ] The bug, if a fix is applied, would not change which observation-level
      data each server sees.
- [ ] The bug, if a fix is applied, would not introduce a new
      inter-server leakage tier beyond the disclosure ledger
      (paper §VI Table 3).

If either box is unchecked, please describe what disclosure-pattern
implication the fix would carry.

## Logs / output

```
<paste relevant error / verbose output here>
```
