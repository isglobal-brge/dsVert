## Complete mac measured matrix

Times include compilation, secure kernel batches and globally calibrated joint noise. Bytes are measured two-direction traffic. AND counts cover the fused kernel (including padded tails), not just the scalar profile. All integer and DP-oracle equalities pass. This Go measurement excludes DataSHIELD framing and the catalog count coordinate.

| Family | n | p | Grid | Total seconds | Total bytes | Kernel AND | AND/evaluation | Kernel bytes/evaluation |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| binomial | 1000 | 5 | 16 | 57.993 | 2,498,471,536 | 62,176,320 | 3886.020 | 145197.452 |
| binomial | 1000 | 5 | 50 | 370.385 | 8,386,961,208 | 196,608,264 | 3932.165 | 148176.450 |
| binomial | 1000 | 10 | 16 | 74.906 | 2,825,711,537 | 67,276,320 | 4204.770 | 165649.952 |
| binomial | 1000 | 10 | 50 | 340.136 | 9,532,301,208 | 214,458,264 | 4289.165 | 171083.250 |
| binomial | 10000 | 5 | 16 | 243.947 | 23,405,768,381 | 621,758,606 | 3885.991 | 145190.350 |
| binomial | 10000 | 5 | 50 | 1676.498 | 75,062,442,846 | 1,966,065,601 | 3932.131 | 148168.608 |
| binomial | 10000 | 10 | 16 | 278.215 | 26,678,168,331 | 672,758,606 | 4204.741 | 165642.850 |
| binomial | 10000 | 10 | 50 | 1017.426 | 86,515,842,886 | 2,144,565,601 | 4289.131 | 171075.408 |
| poisson | 1000 | 5 | 16 | 84.548 | 3,170,518,051 | 82,363,472 | 5147.717 | 185593.837 |
| poisson | 1000 | 5 | 50 | 403.330 | 10,453,794,966 | 259,705,864 | 5194.117 | 188581.012 |
| poisson | 1000 | 10 | 16 | 95.431 | 3,497,758,062 | 87,463,472 | 5466.467 | 206046.338 |
| poisson | 1000 | 10 | 50 | 525.095 | 11,599,134,982 | 277,555,864 | 5551.117 | 211487.812 |
| poisson | 10000 | 5 | 16 | 455.854 | 29,894,582,610 | 823,620,398 | 5147.627 | 185584.787 |
| poisson | 10000 | 5 | 50 | 1155.829 | 95,310,355,376 | 2,597,011,201 | 5194.022 | 188571.222 |
| poisson | 10000 | 10 | 16 | 334.810 | 33,166,982,606 | 874,620,398 | 5466.377 | 206037.287 |
| poisson | 10000 | 10 | 50 | 1215.588 | 106,763,755,277 | 2,775,511,201 | 5551.022 | 211478.022 |

Source logs: `matrix-mac-n1000-p10-g16.log`, `matrix-mac-n1000-p10-g50.log`, `matrix-mac-n1000-p5-g16.log`, `matrix-mac-n1000-p5-g50.log`, `matrix-mac-n10000-p10-g16.log`, `matrix-mac-n10000-p10-g50.log`, `matrix-mac-n10000-p5-g16.log`, `matrix-mac-n10000-p5-g50.log`.
