# PredictResolve — FDC / Web2Json

## 1. Purpose

PredictResolve uses **Flare Data Connector (FDC) Web2Json** as the external-outcome verification layer.

The prediction itself may remain private, but the real-world event that determines the result needs a verifiable external data path.

The architecture is:

```text
Public Web2 Source
        ↓
AI Source Qualification
        ↓
Supported Web2Json Source
        ↓
FDC Attestation
        ↓
Proof Verification
        ↓
Verified External Outcome
        ↓
Flare Confidential Compute / TEE
        ↓
Confidential Resolution
