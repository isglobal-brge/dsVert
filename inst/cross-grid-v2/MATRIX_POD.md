## Complete pod measured matrix

Times include compilation, secure kernel batches and globally calibrated joint noise. Bytes are measured two-direction traffic. AND counts cover the fused kernel (including padded tails), not just the scalar profile. All integer and DP-oracle equalities pass. This Go measurement excludes DataSHIELD framing and the catalog count coordinate.

| Family | n | p | Grid | Total seconds | Total bytes | Kernel AND | AND/evaluation | Kernel bytes/evaluation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| binomial | 1000 | 5 | 16 | 155.926 | 2,498,471,536 | 62,176,320 | 3886.020 | 145197.452 |
| binomial | 1000 | 5 | 50 | 418.661 | 8,386,961,213 | 196,608,264 | 3932.165 | 148176.450 |
| binomial | 1000 | 10 | 16 | 184.828 | 2,825,711,536 | 67,276,320 | 4204.770 | 165649.952 |
| binomial | 1000 | 10 | 50 | 840.004 | 9,532,301,179 | 214,458,264 | 4289.165 | 171083.249 |
| binomial | 10000 | 5 | 16 | 520.446 | 23,405,768,410 | 621,758,606 | 3885.991 | 145190.351 |
| binomial | 10000 | 5 | 50 | 1659.673 | 75,062,442,900 | 1,966,065,601 | 3932.131 | 148168.608 |
| binomial | 10000 | 10 | 16 | 554.579 | 26,678,168,349 | 672,758,606 | 4204.741 | 165642.850 |
| binomial | 10000 | 10 | 50 | 2795.701 | 86,515,842,839 | 2,144,565,601 | 4289.131 | 171075.408 |
| poisson | 1000 | 5 | 16 | 167.800 | 3,170,518,051 | 82,363,472 | 5147.717 | 185593.837 |
| poisson | 1000 | 5 | 50 | 1029.791 | 10,453,794,980 | 259,705,864 | 5194.117 | 188581.012 |
| poisson | 1000 | 10 | 16 | 256.135 | 3,497,758,046 | 87,463,472 | 5466.467 | 206046.337 |
| poisson | 1000 | 10 | 50 | 749.459 | 11,599,134,964 | 277,555,864 | 5551.117 | 211487.812 |
| poisson | 10000 | 5 | 16 | 692.363 | 29,894,582,636 | 823,620,398 | 5147.627 | 185584.787 |
| poisson | 10000 | 5 | 50 | 1905.672 | 95,310,355,319 | 2,597,011,201 | 5194.022 | 188571.222 |
| poisson | 10000 | 10 | 16 | 578.912 | 33,166,982,625 | 874,620,398 | 5466.377 | 206037.287 |
| poisson | 10000 | 10 | 50 | 2695.032 | 106,763,755,314 | 2,775,511,201 | 5551.022 | 211478.022 |

Source logs: `matrix-pod-n1000-p10-g16-binomial.log`, `matrix-pod-n1000-p10-g16-poisson.log`, `matrix-pod-n1000-p10-g50-binomial.log`, `matrix-pod-n1000-p10-g50-poisson.log`, `matrix-pod-n1000-p5-g16.log`, `matrix-pod-n1000-p5-g50-poisson.log`, `matrix-pod-n1000-p5-g50.log`, `matrix-pod-n10000-p10-g16-binomial.log`, `matrix-pod-n10000-p10-g16-poisson.log`, `matrix-pod-n10000-p5-g16-binomial.log`, `matrix-pod-n10000-p5-g16-poisson.log`, `matrix-pod-n10000-p5-g50-binomial.log`, `matrix-pod-n10000-p5-g50-poisson.log`, `pod-full-n10000.log`.

Interrupted process logs retained: `matrix-pod-n1000-p5-g50.log`. Only completed FULL_MEASUREMENT records with successful integer/DP oracle checks are included; missing family results were resumed separately. Resumed pod runs use GOMEMLIMIT=6GiB/GOGC=25; the original full-envelope measurements retain their original GC settings.
