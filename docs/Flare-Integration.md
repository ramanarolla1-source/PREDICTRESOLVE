# PredictResolve — Flare Integration

## 1. Overview

PredictResolve is built around a multi-layer Flare trust path:

```text
PUBLIC WEB2
    ↓
FDC / Web2Json
    ↓
VERIFIED EXTERNAL OUTCOME
    ↓
FLARE CONFIDENTIAL COMPUTE / TEE
    ↓
CONFIDENTIAL RESOLUTION
    ↓
TEE ATTESTATION
    ↓
TRUST RECEIPT
    ↓
FLARE EVM SETTLEMENT CONTRACT
    ↓
FXRP
