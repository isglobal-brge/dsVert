# dsVert

The `dsVert` package, part of the ISGlobal-BRGE project, provides tools for the analysis of vertically partitioned data within the DataSHIELD framework. This package aims to enable secure, privacy-preserving statistical analysis without needing to share individual-level data.

## Features

- **Vertical Data Analysis**: Perform statistical analysis on vertically partitioned data.
- **Privacy Preservation**: Ensures that data privacy is maintained by not requiring direct access to individual-level data.

## Installation

To install `dsVert` from GitHub, use the following command in R:

```R
devtools::install_github("isglobal-brge/dsVert")
```

## Usage

After installation, load dsVert into your R environment:

```R
library(dsVert)
```

Refer to the vignettes for detailed examples on how to use the package for your data analysis needs:

```R
browseVignettes(package = "dsVert")
```
## License

This project is licensed under the MIT License - see the LICENSE file for details.
