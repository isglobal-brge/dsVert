# Local public segment enumeration — 2026-09-20

This local macOS probe measured `.exact_gc_segment_list` on three new temporary
public directories containing 1, 100 and 800 canonical segment files. It is
not a pod4, transport, cryptographic, correctness or release-capacity result.
No worker, protected data, DP draw or existing session was used. The process
exited zero; the synthetic directories were deleted after measurement.

Each file was a sparse 1 MiB zero file, mode 0600, inside a mode-0700 directory.
The file names used consecutive nonoverlapping offsets and the actual SHA256
of 1 MiB of zero bytes. The Python orchestration created each file by seeking
to byte 1,048,575 and writing a zero. `fixture-layout.json` records both logical
and allocated sizes before cleanup. Directory enumeration validates metadata
and canonical names; this probe did not invoke full segment-content hashing.

The executed R script loaded the local server package and called the original
helper four times per directory. It checked the returned count, offsets and
sizes, and required the complete source-file hash to remain unchanged.

| Files | Mean elapsed seconds per scan |
|---:|---:|
| 1 | 0.00500 |
| 100 | 0.01150 |
| 800 | 0.10825 |

`results.json` retains all 12 observations, CPU times and the source hash.
The first one-file call includes warmup; elapsed values have millisecond
resolution. These small local samples are observations, not stable performance
promises or portable timing bounds.

Static source inspection found up to three outbound-directory scans for a
fresh source frame acknowledging prior bytes: initial compaction, compaction
at the new acknowledgement, and selection of the next output chunk. Multiplying
this probe's 800-file scan mean by three gives 0.32475 seconds of illustrative
local scan work. That multiplication is not a measured full exchange and does
not attribute the pod's missing latency. Earlier GEE producer stages with
smaller queues cannot be explained by assuming the sampler's wide queue.

The companion polling public probe isolates client/connector dispatch. A
causal production attribution would additionally need actual per-call timings
for signing, verification, private invocation files, spool scans/hashes,
base64 conversion and durable file operations. No optimization was applied.

`probe.R` and `probe.log` are byte-identical copies of the executed source and
successful output. `provenance.json` records local scope and platform.
`SHA256SUMS` covers the retained files.
