# PredictResolve — Trust Receipt

## 1. Purpose

The **Trust Receipt** is the provenance layer of PredictResolve.

It preserves a cryptographically identifiable record of how a prediction was resolved and settled without requiring the participant's private prediction terms, odds or strategy to become public.

The Trust Receipt connects:

```text
Verified External Outcome
        +
FDC Evidence
        +
TEE Resolution
        +
Resolution Rules
        +
Settlement Result
        +
Settlement Transaction
        ↓
   TRUST RECEIPT
        ↓
Cryptographic Commitment
        ↓
   On-chain Registry
