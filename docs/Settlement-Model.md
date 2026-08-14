# PredictResolve — Settlement Model

## 1. Purpose

This document defines how PredictResolve converts a verified real-world outcome and a confidential prediction position into an enforceable on-chain settlement.

The settlement model intentionally separates:

- **external evidence**
- **private prediction terms**
- **confidential resolution**
- **attestation**
- **Trust Receipt provenance**
- **on-chain enforcement**
- **FXRP asset movement**

The core settlement path is:

```text
Prediction
    ↓
Verified External Outcome
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
