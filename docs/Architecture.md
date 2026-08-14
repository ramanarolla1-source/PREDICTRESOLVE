# PredictResolve — Architecture

## 1. Overview

PredictResolve is a confidential prediction-resolution and on-chain settlement architecture built around four product stages:

> **Predict. Verify. Resolve. Settle.**

The system separates public event verification from private prediction information.

The external outcome is verified through **Flare FDC/Web2Json**.

Private prediction terms and settlement logic are processed inside a **Flare Confidential Compute Trusted Execution Environment (TEE)**.

A **Trust Receipt** preserves the provenance of the resolution.

A **Flare EVM settlement contract** verifies the attested result and executes the permitted **FXRP settlement**.

The architecture is therefore:

```text
Private Prediction
        +
Public Real-World Outcome
        ↓
FDC / Web2Json
        ↓
Verified External Evidence
        ↓
Flare Confidential Compute / TEE
        ↓
Confidential Resolution
        ↓
TEE Attestation
        ↓
Trust Receipt
        ↓
Settlement Contract
        ↓
FXRP Settlement
