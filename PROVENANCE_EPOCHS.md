# Custodian authorization epochs (1.4.1)

Count, Frequency and Synopsis require dsVertClient 1.4.1 and the
`dsvert-provenance-epochs-v1` capability on every participating server. Analyst
function arguments are unchanged. Upgrade the federation together and drain
old jobs. The new protocol is a new release domain; it does not change or
protect outputs already released by 1.4.0.

## One-time migration of aligned imports

**Legacy generic alignment imports must be authorized once before use.** The
same rule applies to descriptors approving already-aligned content without an
authenticated complete dependency history. Every attempt before migration
fails with the same authorization-migration category, without checking whether
the imported intersection changed. Public Synopsis endpoints may wrap this in
their existing protected-operation failure category.

In the custodian's trusted R session, after reviewing the current frame and
updating its descriptor through the existing descriptor provisioning workflow:

```r
dsVert::dsvertAuthorizeSource(
  data = aligned,
  descriptor = getOption("dsvert.dp.datasets")$aligned,
  event_id = "migration-1.4.1",
  kind = "dataset",
  patient_column = "id"
)
```

Run this for every configured imported dataset used by Synopsis, on every
custodian. Substitute the actual object, configured descriptor and identifier
column. This captures the complete frame durably. An import whose original
upstream history is unavailable becomes an explicitly authorized **frozen
materialized root**. Its epoch records that publication, not a reconstruction
of historical upstream PSI participants.

For an already-aligned descriptor used as the input to padded PSI through
`dsvert.dp.datasets`, explicitly authorize that publication as a PSI input:

```r
source <- dsVert::dsvertPSISourceDescriptor(aligned, "id", "cohort", "v1")
dsVert::dsvertAuthorizeSource(aligned, source, "migration-psi-1.4.1", kind="psi")
```

The source id/version/purpose and local identifier column must match the
configured fallback. The explicit authorization records an imported root;
subsequent PSI signs the new federation's complete epoch vector.

Raw padded-PSI sources whose current content matches their custodian-approved
raw digest register automatically once on first use. Trusted padded-PSI finalization captures the aligned descriptor and complete
epoch coverage durably before returning its output, including explicit
descriptors derived from that output. Registration writes a custodian log notice. First-load
raw digest mismatches retain the source-admission refusal. Old attestations
without complete epochs require migration; their historical closure cannot be
inferred from an aligned content hash.

## Publication, retries and staleness

Every explicit event allocates an independent 256-bit CSPRNG epoch, even for
identical bytes and unchanged logical dataset versions:

```r
source <- dsVert::dsvertPSISourceDescriptor(raw, "id", "cohort", "v1")
dsVert::dsvertReauthorizeSource(raw, source, "publication-2026-10-06", kind="psi")
options(dsvert.psi.authorized_sources = list(raw = source))
private_inventory <- dsVert::dsvertListSourceAuthorizations()
```

Reuse `event_id` only to retry the same event. A retry returns its original
record without reading replacement material. A new event id publishes a new
epoch. Merely rebuilding a descriptor, restarting R, rerunning PSI, or changing
a frame in place does not publish an event. Old epochs remain available for
already-authorized operations. These administrative functions are exported for
custodians and are absent from the DataSHIELD allowlist. Their return values
contain private descriptors; never expose them to analysts.

Once captured, a source is frozen indefinitely until explicit publication.
Changing the live raw frame or imported intersection does not change the frozen
publication or select between success and refusal. New requests within that
publication use its frozen material. Stable numeric artifacts and semantic
receipts replay within the retained protocol/key/runtime domain. Fresh PSI
sessions still have new operational attestation IDs, signatures and run hashes;
these are not the stable receipt.

## Binding and private integrity

Each PSI peer signs its local epoch. A canonical complete vector E binds every
participant, including peers that contribute only intersection membership.
Stable derivation policy excludes session fallback IDs. Count and Frequency
commit public source semantics, E and public request/layout. Synopsis binds
E_star, the effective dataset dependency closure, retaining each dataset's full
PSI vector. Reauthorizing any effective dependency changes every affected
artifact and authority stream, including when content is unchanged. Publicly
provable unused datasets do not affect the effective identity.

Private content hashes remain admission and integrity checks. Trusted PSI
finalization seals all local aligned values, not only IDs/order. Producer pins
protect Frequency coordinates and Synopsis source/cross blocks before
transport. Tampering with an aligned object, attestation, retained frame or
private state fails closed; the package never repairs a seal using the current
content. These integrity failures are observable and are distinct from normal
in-place replacement of the registered source, which serves the frozen copy.

## State and recovery

Authorizations are stored under `DSVERT_STATE_DIR/privacy/source-authorizations`
in identity-specific owner-only storage. The complete serialized index and
frames are authenticated before decoding, with process locks and atomic synced
publication. A separately authenticated UUID marker detects missing payload
state. No authorization or pin is evicted or recycled.

After first provisioning, pin the UUID in deployment configuration outside the
state volume:

```r
private_inventory <- dsVert::dsvertListSourceAuthorizations()
options(dsvert.dp.provenance_store_uuid = private_inventory$uuid)
```

Persist that option across restarts. Missing/corrupt state with a retained
marker or expected UUID requires custodian recovery; it never silently
reallocates epochs. The first installation may create a store to support
zero-touch raw-source migration. Without the externally retained UUID, loss of
both store and marker cannot be distinguished from first installation.
A MAC does not detect rollback of an entire valid snapshot; trusted storage and
consistent backups of identity keys, authorizations, pins and stable artifacts
are required. Do not restore selected rows or reset the store to fix an error.

Logical capacity defaults to `dsvert.dp.provenance_store_bytes = 1024^3`;
`dsvert.dp.provenance_record_bytes = 64*1024^2` reserves a fixed allowance per
frame publication/pin, while digest-only pins reserve 8192 bytes. Reservations
are based on new public identities, are never refunded, and existing reads
remain available at capacity. Provision storage and frame allowances for the
deployment's source geometry, and expand capacity administratively. This is a
logical reservation budget, not a hard bound on physical disk usage: retained
frames can exceed an allowance, and the authenticated whole store is rewritten
atomically on mutation. Provision and monitor disk capacity accordingly; there
is no content-size admission threshold or content-dependent eviction.

## Guarantee and limits

Within intact authenticated state, complete fixed provenance and fixed public
analysis semantics, one effective content is admitted to a noise stream.
Changing source content in place cannot reroll the frozen release. Every new
explicit authorization changes the public identity regardless of content.
Thus stable identity/receipt equality no longer tests whether aligned private
content changed. Numeric releases still convey their calibrated information.

This does not hide custodian publication timing, integrity/storage failures,
existing PSI metadata, timing, other DataSHIELD outputs or administration driven
by private events. It is not a whole-transcript or lifetime DP theorem. Distinct
publication/request releases compose under the existing conditional mechanism
assumptions. Samplers, sensitivities, clipping, component allocations, epsilon,
delta and backend selection are unchanged. Legacy capsules and formal GLM/Cox
retain their mechanisms and identities apart from shared PSI compatibility.
