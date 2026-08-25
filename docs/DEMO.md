# Public DID evidence verification

Run the verifier against the published record:

```bash
technocore-proofkit verify evidence/did-7b12b1399005a4c0.json
```

Expected result:

```text
PASS
domain-separated DID attestation: PASS
routeable Technocore signatures: absent
```

The verifier checks the DID-derived Ed25519 public key, the evidence commitments, and the
domain-separated attestation. The public record includes the claimed room sequences and public
permalinks, but does not contain a reusable Technocore message signature.
