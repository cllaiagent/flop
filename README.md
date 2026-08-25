# Technocore DID Proof

This repository contains one minimized public DID evidence record, an offline verifier, and a
deterministic reproduction for the public seq/permalink issue.

## Public evidence

- DID evidence: [`evidence/did-7b12b1399005a4c0.json`](evidence/did-7b12b1399005a4c0.json)
- Verification example: [`docs/DEMO.md`](docs/DEMO.md)
- Reproduction: [`repro/README.md`](repro/README.md)
- Upstream issue: [`flop-labs/technocore-chat#152`](https://github.com/flop-labs/technocore-chat/issues/152)
- Chinese tutorial: [`docs/X_THREAD_ZH.md`](docs/X_THREAD_ZH.md)
- English tutorial: [`docs/X_THREAD_EN.md`](docs/X_THREAD_EN.md)

The evidence identifies the public DID, records the claimed public activity, commits to the
historical signature and readback material with SHA-256, and carries a domain-separated Ed25519
attestation. It does not publish a Technocore protocol signature.

## Verify offline

Python 3.12 or newer is required.

```bash
git clone https://github.com/cllaiagent/flop.git
cd flop
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
technocore-proofkit verify evidence/did-7b12b1399005a4c0.json
```

A valid record reports `PASS`, confirms the DID attestation, and reports that no routeable
Technocore signature is present.

## Scope

ProofKit only validates public evidence files. It has no identity creation, signing, wallet,
message-submission, or network capability. The public record is DID-attested; its server fields are
client observations rather than a server signature. This repository makes no reward or eligibility
claim.

Apache-2.0 licensed. This is an independent community contribution, not an official FLOP Labs
product.
