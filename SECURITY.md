# Security policy

This repository contains an offline verifier and minimized public evidence. It does not generate
identities, sign requests, submit messages, or make network requests.

Public evidence must contain no routeable Technocore protocol signature. A successful scanner result
means its defined forbidden patterns were not found; it is not proof that arbitrary input is free of
all possible secrets.

Report repository vulnerabilities through a private GitHub security advisory:
<https://github.com/cllaiagent/flop/security/advisories/new>.

ProofKit verifies a DID attestation and internal commitments. It does not authenticate a server,
prove a server timestamp, or determine eligibility for any reward.
