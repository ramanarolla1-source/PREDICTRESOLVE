# PredictResolve — Security and Privacy

## 1. Purpose

PredictResolve is designed around a specific security problem:

> **A prediction should be verifiable and enforceably settled without requiring the participant to publicly expose the private information used to calculate that settlement.**

The architecture therefore separates:

- public external evidence;
- private prediction inputs;
- confidential computation;
- attested resolution;
- historical provenance;
- on-chain settlement.

The overall trust model is:

```text
PUBLIC EVENT
     ↓
FDC / Web2Json
     ↓
VERIFIED OUTCOME
     ↓
TEE + PRIVATE INPUTS
     ↓
CONFIDENTIAL RESOLUTION
     ↓
TEE ATTESTATION
     ↓
TRUST RECEIPT
     ↓
ON-CHAIN VERIFICATION
     ↓
FXRP SETTLEMENT
