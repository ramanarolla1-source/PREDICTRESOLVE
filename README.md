<img width="1536" height="1024" alt="PredictResove Architectural Diagram" src="https://github.com/user-attachments/assets/6a3840c9-f237-4910-aeda-593331ed114e" />

One Pager: https://docs.google.com/document/d/1fKg8yP_tovysuMKeFm63YRaQCJlvbtmDzwFKjwBC4QA/edit?usp=sharing

Demo Video: https://youtu.be/swBQAQB8-lw


# PredictResolve

## Predict. Verify. Resolve. Settle.

**Confidential prediction resolution and on-chain settlement powered by Flare.**

PredictResolve is a prototype for prediction and event-settlement workflows where:

- the **prediction, stake, odds and settlement parameters can remain private**;
- the **real-world outcome is externally verified through Flare FDC/Web2Json**;
- the **resolution calculation runs inside a Flare Confidential Compute Trusted Execution Environment (TEE)**;
- a **Trust Receipt preserves resolution provenance**;
- and an on-chain settlement contract **verifies the attested result and executes the permitted FXRP settlement**.

The product is designed for **Bounty 2 — Confidential Compute Apps** in Flare Summer Signal.

---

# The Problem

Prediction systems have a fundamental tension.

The outcome needs to be verifiable.

But the information used to calculate the payout does not always need to be public.

A participant may have:

- a private prediction;
- a private stake;
- private odds;
- exposure limits;
- settlement parameters;
- strategy-specific conditions.

A fully public blockchain workflow can make the settlement transparent, but exposing all of those inputs can also expose the participant's strategy.

PredictResolve separates the two.

> **The outcome becomes verifiable without making every prediction input public.**

---

# The Solution

PredictResolve follows four product steps:

```text
PREDICT
    ↓
VERIFY
    ↓
RESOLVE
    ↓
SETTLE

Predict

The participant creates a prediction with protected terms such as:
Prediction:
Team A wins

Stake:
100 FXRP

Odds:
1.85

Maximum payout:
185 FXRP

The position and settlement parameters do not need to be publicly exposed.

Verify

When the real-world event occurs, PredictResolve uses a selected supported Web2 source through Flare FDC/Web2Json.

The external response is attested and can be verified by the application.

Resolve

The verified outcome is combined with the protected prediction terms inside a Flare Confidential Compute Trusted Execution Environment.

The confidential computation determines:

whether the prediction won or lost;
whether settlement conditions were satisfied;
the permitted payout;
the resulting settlement state.
Settle

The TEE returns an attested resolution result.

The on-chain settlement contract verifies the attestation and executes the permitted FXRP settlement.

The blockchain therefore becomes the enforcement layer, not merely an audit database.

Core Architecture
                    PUBLIC REAL WORLD
                           │
                           ▼
                    Supported Web2
                         Source
                           │
                           ▼
                    FDC / Web2Json
                           │
                           ▼
                  Verified External
                       Outcome
                           │
                           │
                           ▼
                 ┌───────────────────┐
                 │   FLARE TEE       │
                 │ Confidential      │
                 │ Resolution        │
                 │                   │
 PRIVATE INPUTS  │ Prediction        │
 ─────────────►  │ Stake             │
                 │ Odds              │
                 │ Exposure          │
                 │ Settlement Rules  │
                 └─────────┬─────────┘
                           │
                    TEE Attestation
                           │
              ┌────────────┴────────────┐
              ▼                         ▼
       TRUST RECEIPT             Settlement Contract
              │                         │
              │                         ▼
              │                  Verify Attestation
              │                         │
              │                         ▼
              │                    FXRP Settlement
              │                         │
              ▼                         ▼
      Cryptographic              On-chain State
       Provenance

Flare's Role

PredictResolve deliberately uses different Flare capabilities for different trust problems.

| Flare capability               | PredictResolve role                                                              |
| ------------------------------ | -------------------------------------------------------------------------------- |
| **FDC / Web2Json**             | Verify the response returned by a supported external Web2 source                 |
| **Confidential Compute / TEE** | Privately calculate the prediction outcome and settlement using protected inputs |
| **Smart Accounts**             | Provide controlled account-level interaction and authorization where applicable  |
| **Flare EVM**                  | Host the resolution and settlement contracts                                     |
| **FXRP**                       | Provide the interoperable settlement asset                                       |


## Flare Technology Basis

PredictResolve is architected around documented Flare capabilities.

### FDC / Web2Json

Flare's FDC Web2Json attestation type can retrieve a supported Web2 response, apply JQ post-processing, ABI-encode the selected result, and expose an attestation proof that can be verified on-chain.

In PredictResolve, this capability is used as the **external-outcome verification boundary**:

> FDC establishes a verifiable representation of the selected external response; the application then uses that verified evidence for resolution.

See the official Flare documentation:

[Flare Web2Json documentation](https://dev.flare.network/fdc/guides/foundry/web2-json)

### Confidential Compute / TEE

Flare's Confidential Compute architecture provides TEE-based execution in which protected inputs and computation can remain confidential while an attested result can be returned for on-chain verification.

PredictResolve uses this capability as the **confidential resolution boundary**:

> The TEE combines the verified external outcome with private prediction and settlement parameters and produces an attested resolution result.

Flare's Weather Insurance example demonstrates a closely related pattern in which private policy information and external data are processed in a TEE and the resulting attestation is verified before on-chain settlement.

[Flare Confidential Compute — Weather Insurance](https://dev.flare.network/fcc/guides/weather-insurance-extension)

Why Confidential Compute?

The TEE is not an optional add-on.

It solves a specific problem that a transparent smart contract cannot solve cleanly:

How can a settlement calculation use private prediction terms while still producing an independently verifiable result?

Consider:
Private:
Prediction = Team A wins
Stake = 100 FXRP
Odds = 1.85
Maximum payout = 185 FXRP
Settlement rules = private
Public:
FDC-verified outcome = Team A wins
Inside the TEE:
Prediction matches outcome
        ↓
WIN
        ↓
100 FXRP × 1.85
        ↓
185 FXRP

The public settlement layer does not need to see the participant's private odds or strategy.

It receives the attested result required to enforce settlement.

The TEE Is Not the Settlement Layer

PredictResolve deliberately separates confidential computation from asset movement.
TEE
 ↓
Calculate resolution
 ↓
Produce attested result
 ↓
Settlement Contract
 ↓
Verify TEE attestation
 ↓
Execute FXRP payout

This means:

The TEE computes. The contract enforces.

The confidential execution environment does not receive unrestricted authority to move user funds.

AI's Role

AI is used as a bounded intelligence layer.

It can assist with:

Source qualification

Evaluate candidate Web2 sources according to:

authority;
provenance;
relevance;
freshness;
corroboration.
Response interpretation

Normalize different representations of the same event.

For example:
"FT"
"Final"
"Completed"
"Match finished"
can be interpreted as:
EVENT_STATUS = FINAL

Conflict detection

If multiple relevant sources disagree:
Source A → Team A wins
Source B → Team A wins
Source C → Match abandoned
PredictResolve can flag:
CONFLICT DETECTED
SETTLEMENT = PENDING
AI does not independently authorize or execute a payout.

The final settlement condition is determined by explicit rules and enforced on-chain.

Trust Receipt

The Trust Receipt preserves the provenance of how a prediction was resolved and settled.

It can contain or reference:

prediction/event ID;
FDC evidence reference;
TEE attestation reference;
resolution rule/version;
settlement result;
settlement transaction;
cryptographic commitments;
timestamp;
receipt version/history.

Sensitive position information and private odds remain protected.

Conceptually:
Verified Outcome
      +
TEE Attestation
      +
Resolution Rule
      +
Settlement Result
      +
Transaction Reference
      ↓
Trust Receipt
      ↓
Cryptographic Commitment
      ↓
On-chain Registry
The Trust Receipt answers:

What happened, how was it resolved, and what was actually settled?

It does not claim that the original prediction was economically correct.

It preserves the integrity and provenance of the resolution process.

On-Chain Settlement

PredictResolve does not stop at an off-chain calculation.

The final result becomes an enforceable on-chain state transition.
TEE Attestation
      ↓
Contract Verification
      ↓
Settlement Conditions
      ↓
FXRP Transfer
      ↓
Settlement Transaction

The settlement contract can verify:

the relevant prediction/event;
the TEE attestation;
the resolution result;
the permitted settlement conditions;
the Trust Receipt commitment.

Only after the required conditions are satisfied does the contract execute the permitted FXRP settlement.

This makes the blockchain an enforcement layer rather than merely an audit layer.

Why FXRP?

FXRP is Flare's FAsset representation of XRP and is an ERC-20 token usable in Flare smart contracts and DeFi applications.

PredictResolve uses FXRP as the settlement asset because it gives an interoperable XRP-derived asset a programmable use case:
XRP
 ↓
FXRP
 ↓
Prediction Position
 ↓
Verified Event
 ↓
Confidential Resolution
 ↓
FXRP Settlement

Flare's developer documentation describes FXRP as an ERC-20 representation of XRP on Flare that is compatible with smart contracts and DeFi applications.

Flare FXRP documentation

Example
Private Prediction
Prediction:
Team A wins

Stake:
100 FXRP

Odds:
1.85

Maximum payout:
185 FXRP
External Event

A supported public source reports:
Status:
Final

Winner:
Team A
FDC

The response is processed through:
Web2Json
    ↓
FDC Attestation
    ↓
Proof Verification

TEE

The protected terms and verified outcome are evaluated:
Prediction = Team A wins
Outcome    = Team A wins

Result:
WIN

Payout:
185 FXRP

Settlement
TEE Attestation
      ↓
Settlement Contract
      ↓
185 FXRP

Trust Receipt
Prediction ID
FDC Evidence Reference
TEE Attestation Reference
Resolution Rule
Settlement Result
Settlement Transaction
Cryptographic Commitment

Beyond Sports

Sports is the initial demonstration because event outcomes are easy to understand and verify.

The same architecture can support other event-driven applications.

Weather

Rainfall threshold
       ↓
FDC-verified data
       ↓
TEE confidential policy evaluation
       ↓
Settlement

Financial / Market Events
Rate / price / public market event
       ↓
Verified external data
       ↓
Private position + terms
       ↓
Confidential resolution
       ↓
Settlement

Public Events
Defined public outcome
       ↓
External evidence
       ↓
Verified outcome
       ↓
Private resolution
       ↓
Settlement

The data source and resolution rules change.

The trust architecture remains the same.

Security Model

PredictResolve separates four important responsibilities:

External evidence

FDC/Web2Json

Provides an attested response from the selected supported source.

Intelligence

AI

Qualifies sources, normalizes responses and identifies potential conflicts.

Confidential computation

TEE

Processes protected prediction terms and settlement logic.

Enforcement

Smart Contract

Verifies the attested result and controls the FXRP settlement.

This prevents any single component from having unlimited authority.

Privacy Model

The following information can remain protected:

participant identity/context;
prediction position;
stake;
odds;
exposure limits;
payout parameters;
private settlement rules;
strategy-specific data.

The public chain receives only the information required to verify and enforce the resulting state transition.

The detailed Trust Receipt can be stored in encrypted protected storage, while a cryptographic commitment can be anchored on-chain.

Repository Structure
predictresolve/
│
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
├── requirements.txt
│
├── docs/
│   ├── Architecture.md
│   ├── Flare-Integration.md
│   ├── FDC-Web2Json.md
│   ├── Confidential-Compute.md
│   ├── Trust-Receipt.md
│   ├── Settlement-Model.md
│   ├── Security-and-Privacy.md
│   └── Demo-Guide.md
│
├── contracts/
│   ├── PredictResolveSettlement.sol
│   └── TrustReceiptRegistry.sol
│
├── src/
│   ├── source_intelligence.py
│   ├── outcome_verification.py
│   ├── resolution_engine.py
│   ├── confidential_resolution.py
│   ├── trust_receipt.py
│   └── pipeline.py
│
├── data/
│   ├── sources.json
│   ├── prediction.json
│   └── sample_outcome.json
│
└── demo/
    └── demo-flow.md

Demo Workflow

The demonstration follows:
1. Create private prediction
2. Define private stake / odds / settlement terms
3. Event occurs
4. Select supported public source
5. Verify external response through FDC/Web2Json
6. Normalize and inspect the verified outcome
7. Execute confidential resolution inside the TEE
8. Produce TEE attestation
9. Generate Trust Receipt
10. Verify settlement conditions on-chain
11. Execute FXRP settlement
12. Preserve settlement provenance
See:

docs/Demo-Guide.md

Prototype Status

This repository is a hackathon prototype.

The repository explicitly distinguishes between:

implemented functionality;
demonstration/simulated components;
deployment-specific Flare configuration;
future production extensions.

Where placeholder attestation identifiers, transaction hashes, addresses or synthetic outcomes are used, they must not be interpreted as live production values.

A production deployment would require:

supported/whitelisted Web2Json sources;
live FDC request and proof handling;
production FCC/TEE deployment;
secure key management;
audited settlement contracts;
production-grade FXRP configuration;
enterprise/user identity controls.
Design Principles
Privacy without losing verifiability

Private prediction terms can remain private while settlement remains verifiable.

Evidence before resolution

The outcome used for settlement must come from an externally verified evidence path.

Confidential computation

Sensitive resolution logic belongs inside the TEE rather than on public chain state.

AI without financial authority

AI can assist with interpretation and conflict detection but does not directly control settlement.

Contract-enforced settlement

The TEE produces an attested result. The smart contract enforces the financial consequence.

Provenance without exposure

The Trust Receipt preserves how settlement was produced without exposing protected strategy inputs.

Core Principle

PredictResolve follows a simple rule:

FDC verifies the external outcome. AI interprets the evidence. The TEE resolves the private position. The Trust Receipt preserves provenance. The contract enforces settlement.

Product Identity
PredictResolve
Predict. Verify. Resolve. Settle.

FDC / Web2Json • Confidential Compute / TEE • Trust Receipt • Smart Account Authority • FXRP • On-Chain Settlement


