# PredictResolve — Confidential Compute

## 1. Purpose

Confidential Compute is the core technical requirement of PredictResolve.

The product has to solve a specific problem:

> **How can a prediction be resolved and a payout calculated correctly without exposing the participant's private prediction terms, odds, stake, exposure or settlement strategy to the public blockchain?**

PredictResolve addresses this by moving the sensitive resolution computation into a **Trusted Execution Environment (TEE)** provided through Flare Confidential Compute.

The resulting architecture is:

```text
Private Prediction Terms
        +
Verified External Outcome
        ↓
   Flare TEE
        ↓
Confidential Resolution
        ↓
TEE Attestation
        ↓
On-chain Verification
        ↓
FXRP Settlement
