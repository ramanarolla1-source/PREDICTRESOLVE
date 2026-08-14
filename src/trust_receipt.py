"""
PredictResolve — Trust Receipt

Purpose
-------
Build a cryptographically identifiable Trust Receipt for a prediction
resolution and settlement.

The Trust Receipt connects:

    Event
      +
    FDC evidence
      +
    TEE resolution
      +
    Resolution rule
      +
    Settlement result
      +
    Settlement transaction
            ↓
       Trust Receipt
            ↓
    Cryptographic Commitment
            ↓
      On-chain Registry

Privacy principle
-----------------
The Trust Receipt can preserve resolution provenance without requiring
private prediction terms, odds, strategy or other sensitive inputs to be
published on-chain.

This module does NOT:

- implement FDC verification;
- implement a real TEE;
- encrypt storage;
- manage encryption keys;
- submit blockchain transactions;
- transfer FXRP.

Those responsibilities belong to the corresponding integration layers.

The important boundary is:

    Private receipt content
            ↓
    canonical representation
            ↓
    cryptographic commitment
            ↓
    public on-chain provenance
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TrustReceiptError(Exception):
    """Base exception for Trust Receipt failures."""


class TrustReceiptValidationError(TrustReceiptError):
    """Raised when receipt input is invalid."""


class TrustReceiptVersionError(TrustReceiptError):
    """Raised when receipt versioning is invalid."""


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(
        timezone.utc
    ).isoformat()


def canonical_json(
    payload: Mapping[str, Any],
) -> str:
    """
    Produce deterministic JSON suitable for hashing.

    Stable key ordering and separators ensure that equivalent structured
    payloads produce the same canonical representation.
    """

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_commitment(
    payload: Mapping[str, Any],
) -> str:
    """
    Create a SHA-256 cryptographic commitment.

    The 0x prefix is included for convenient blockchain-oriented display.
    """

    digest = hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()

    return f"0x{digest}"


# ---------------------------------------------------------------------------
# Trust Receipt model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrustReceipt:
    """
    Complete PredictResolve Trust Receipt.

    `protected_payload` represents the detailed receipt content.

    In production, that payload may be encrypted and stored in protected
    off-chain storage.

    `receipt_commitment` is the public cryptographic identity of the
    canonical receipt.
    """

    receipt_id: str
    prediction_id: str
    event_id: str

    version: int
    state: str

    created_at: str

    source_id: str

    fdc_attestation_id: str
    fdc_proof_reference: str
    evidence_commitment: str

    tee_attestation_id: Optional[str]
    resolution_commitment: str

    resolution: str
    payout: float
    asset: str

    resolution_rule: str

    settlement_commitment: str
    settlement_transaction: Optional[str]

    protected_payload: Dict[str, Any]

    receipt_commitment: str

    previous_receipt_id: Optional[str] = None

    def to_dict(
        self,
        *,
        include_protected_payload: bool = True,
    ) -> Dict[str, Any]:
        """
        Return a serializable receipt representation.

        The protected payload can be omitted when producing a public-facing
        representation.
        """

        result = {
            "receipt_id": self.receipt_id,
            "prediction_id": self.prediction_id,
            "event_id": self.event_id,
            "version": self.version,
            "state": self.state,
            "created_at": self.created_at,
            "source_id": self.source_id,
            "fdc_attestation_id": self.fdc_attestation_id,
            "fdc_proof_reference": self.fdc_proof_reference,
            "evidence_commitment": self.evidence_commitment,
            "tee_attestation_id": self.tee_attestation_id,
            "resolution_commitment": self.resolution_commitment,
            "resolution": self.resolution,
            "payout": self.payout,
            "asset": self.asset,
            "resolution_rule": self.resolution_rule,
            "settlement_commitment": self.settlement_commitment,
            "settlement_transaction": (
                self.settlement_transaction
            ),
            "receipt_commitment": self.receipt_commitment,
            "previous_receipt_id": (
                self.previous_receipt_id
            ),
        }

        if include_protected_payload:
            result["protected_payload"] = (
                self.protected_payload
            )

        return result


# ---------------------------------------------------------------------------
# Trust Receipt Builder
# ---------------------------------------------------------------------------

class TrustReceiptBuilder:
    """
    Build PredictResolve Trust Receipts.

    The builder intentionally keeps private prediction inputs separate from
    the public receipt metadata.

    Example:

        builder = TrustReceiptBuilder(
            prediction_id="PR-2026-001",
            event_id="EVT-2026-FINAL-001",
            source_id="SRC-001",
            fdc_attestation_id="...",
            fdc_proof_reference="...",
            evidence_commitment="...",
            tee_attestation_id="...",
            resolution_commitment="...",
            resolution="WIN",
            payout=185,
            asset="FXRP",
            resolution_rule="PREDICTRESOLVE-RULES-V1.0",
            protected_payload={...}
        )

        receipt = builder.build()
    """

    VALID_STATES = {
        "active",
        "superseded",
        "cancelled",
        "pending",
    }

    def __init__(
        self,
        *,
        prediction_id: str,
        event_id: str,
        source_id: str,
        fdc_attestation_id: str,
        fdc_proof_reference: str,
        evidence_commitment: str,
        tee_attestation_id: Optional[str],
        resolution_commitment: str,
        resolution: str,
        payout: float,
        asset: str,
        resolution_rule: str,
        protected_payload: Optional[
            Mapping[str, Any]
        ] = None,
        settlement_transaction: Optional[str] = None,
        receipt_id: Optional[str] = None,
        version: int = 1,
        previous_receipt_id: Optional[str] = None,
        state: str = "active",
    ) -> None:

        self.prediction_id = prediction_id
        self.event_id = event_id
        self.source_id = source_id

        self.fdc_attestation_id = (
            fdc_attestation_id
        )
        self.fdc_proof_reference = (
            fdc_proof_reference
        )
        self.evidence_commitment = (
            evidence_commitment
        )

        self.tee_attestation_id = (
            tee_attestation_id
        )
        self.resolution_commitment = (
            resolution_commitment
        )

        self.resolution = resolution
        self.payout = payout
        self.asset = asset

        self.resolution_rule = resolution_rule

        self.protected_payload = dict(
            protected_payload
            if protected_payload is not None
            else {}
        )

        self.settlement_transaction = (
            settlement_transaction
        )

        self.receipt_id = (
            receipt_id
            if receipt_id is not None
            else f"TR-{prediction_id}-V{version}"
        )

        self.version = version
        self.previous_receipt_id = (
            previous_receipt_id
        )
        self.state = state

        self._validate()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self) -> None:

        required_text = {
            "prediction_id": self.prediction_id,
            "event_id": self.event_id,
            "source_id": self.source_id,
            "fdc_attestation_id": (
                self.fdc_attestation_id
            ),
            "fdc_proof_reference": (
                self.fdc_proof_reference
            ),
            "evidence_commitment": (
                self.evidence_commitment
            ),
            "resolution_commitment": (
                self.resolution_commitment
            ),
            "resolution_rule": (
                self.resolution_rule
            ),
            "asset": self.asset,
            "receipt_id": self.receipt_id,
        }

        for name, value in required_text.items():
            if not str(value).strip():
                raise TrustReceiptValidationError(
                    f"{name} must not be empty"
                )

        if self.version <= 0:
            raise TrustReceiptVersionError(
                "Receipt version must be greater than zero"
            )

        if self.state not in self.VALID_STATES:
            raise TrustReceiptValidationError(
                f"Unsupported receipt state: {self.state}"
            )

        if self.payout < 0:
            raise TrustReceiptValidationError(
                "Payout cannot be negative"
            )

        if (
            self.resolution == "WIN"
            and self.tee_attestation_id is None
        ):
            raise TrustReceiptValidationError(
                "A winning resolution must have a TEE attestation"
            )

    # ------------------------------------------------------------------
    # Commitment payload
    # ------------------------------------------------------------------

    def build_commitment_payload(
        self,
    ) -> Dict[str, Any]:
        """
        Build the canonical receipt payload used to derive the commitment.

        Private data is represented inside `protected_payload`, but the
        canonical payload itself is not automatically written on-chain.
        """

        return {
            "receipt_id": self.receipt_id,
            "prediction_id": self.prediction_id,
            "event_id": self.event_id,
            "version": self.version,
            "state": self.state,
            "source_id": self.source_id,
            "fdc_attestation_id": (
                self.fdc_attestation_id
            ),
            "fdc_proof_reference": (
                self.fdc_proof_reference
            ),
            "evidence_commitment": (
                self.evidence_commitment
            ),
            "tee_attestation_id": (
                self.tee_attestation_id
            ),
            "resolution_commitment": (
                self.resolution_commitment
            ),
            "resolution": self.resolution,
            "payout": self.payout,
            "asset": self.asset,
            "resolution_rule": (
                self.resolution_rule
            ),
            "settlement_commitment": (
                self._settlement_commitment
            ),
            "settlement_transaction": (
                self.settlement_transaction
            ),
            "protected_payload": (
                self.protected_payload
            ),
            "previous_receipt_id": (
                self.previous_receipt_id
            ),
        }

    # ------------------------------------------------------------------
    # Settlement commitment
    # ------------------------------------------------------------------

    @property
    def _settlement_commitment(self) -> str:
        """
        Generate a commitment to the settlement state.

        This intentionally excludes confidential strategy inputs.
        """

        payload = {
            "prediction_id": self.prediction_id,
            "event_id": self.event_id,
            "resolution": self.resolution,
            "payout": self.payout,
            "asset": self.asset,
            "resolution_commitment": (
                self.resolution_commitment
            ),
            "settlement_transaction": (
                self.settlement_transaction
            ),
        }

        return sha256_commitment(payload)

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build(self) -> TrustReceipt:
        """
        Build the complete Trust Receipt.
        """

        created_at = utc_now()

        payload = self.build_commitment_payload()

        # Bind creation timestamp into the actual commitment so that the
        # receipt identity includes its creation context.
        payload["created_at"] = created_at

        receipt_commitment = sha256_commitment(
            payload
        )

        return TrustReceipt(
            receipt_id=self.receipt_id,
            prediction_id=self.prediction_id,
            event_id=self.event_id,
            version=self.version,
            state=self.state,
            created_at=created_at,
            source_id=self.source_id,
            fdc_attestation_id=(
                self.fdc_attestation_id
            ),
            fdc_proof_reference=(
                self.fdc_proof_reference
            ),
            evidence_commitment=(
                self.evidence_commitment
            ),
            tee_attestation_id=(
                self.tee_attestation_id
            ),
            resolution_commitment=(
                self.resolution_commitment
            ),
            resolution=self.resolution,
            payout=self.payout,
            asset=self.asset,
            resolution_rule=self.resolution_rule,
            settlement_commitment=(
                self._settlement_commitment
            ),
            settlement_transaction=(
                self.settlement_transaction
            ),
            protected_payload=dict(
                self.protected_payload
            ),
            receipt_commitment=receipt_commitment,
            previous_receipt_id=(
                self.previous_receipt_id
            ),
        )


# ---------------------------------------------------------------------------
# Public receipt verification
# ---------------------------------------------------------------------------

def rebuild_receipt_commitment(
    receipt: TrustReceipt,
) -> str:
    """
    Rebuild the cryptographic commitment from a complete receipt.

    IMPORTANT:
    This function deliberately uses the exact same canonical fields as the
    builder. The creation timestamp is part of the commitment.
    """

    settlement_payload = {
        "prediction_id": receipt.prediction_id,
        "event_id": receipt.event_id,
        "resolution": receipt.resolution,
        "payout": receipt.payout,
        "asset": receipt.asset,
        "resolution_commitment": (
            receipt.resolution_commitment
        ),
        "settlement_transaction": (
            receipt.settlement_transaction
        ),
    }

    settlement_commitment = sha256_commitment(
        settlement_payload
    )

    payload = {
        "receipt_id": receipt.receipt_id,
        "prediction_id": receipt.prediction_id,
        "event_id": receipt.event_id,
        "version": receipt.version,
        "state": receipt.state,
        "source_id": receipt.source_id,
        "fdc_attestation_id": (
            receipt.fdc_attestation_id
        ),
        "fdc_proof_reference": (
            receipt.fdc_proof_reference
        ),
        "evidence_commitment": (
            receipt.evidence_commitment
        ),
        "tee_attestation_id": (
            receipt.tee_attestation_id
        ),
        "resolution_commitment": (
            receipt.resolution_commitment
        ),
        "resolution": receipt.resolution,
        "payout": receipt.payout,
        "asset": receipt.asset,
        "resolution_rule": (
            receipt.resolution_rule
        ),
        "settlement_commitment": (
            settlement_commitment
        ),
        "settlement_transaction": (
            receipt.settlement_transaction
        ),
        "protected_payload": (
            receipt.protected_payload
        ),
        "previous_receipt_id": (
            receipt.previous_receipt_id
        ),
        "created_at": receipt.created_at,
    }

    return sha256_commitment(
        payload
    )


def verify_receipt(
    receipt: TrustReceipt,
) -> bool:
    """
    Verify the Trust Receipt commitment.
    """

    calculated = rebuild_receipt_commitment(
        receipt
    )

    return (
        calculated.lower()
        == receipt.receipt_commitment.lower()
    )


# ---------------------------------------------------------------------------
# Public / protected representations
# ---------------------------------------------------------------------------

def public_receipt(
    receipt: TrustReceipt,
) -> Dict[str, Any]:
    """
    Return a public-safe receipt representation.

    Private protected payload is intentionally omitted.
    """

    return receipt.to_dict(
        include_protected_payload=False
    )


def protected_receipt(
    receipt: TrustReceipt,
) -> Dict[str, Any]:
    """
    Return the complete receipt.

    Production code should encrypt this object before storing it outside the
    blockchain.
    """

    return receipt.to_dict(
        include_protected_payload=True
    )


# ---------------------------------------------------------------------------
# Receipt versioning
# ---------------------------------------------------------------------------

def create_superseding_receipt(
    previous: TrustReceipt,
    *,
    resolution: str,
    payout: float,
    resolution_commitment: str,
    tee_attestation_id: Optional[str],
    protected_payload: Optional[
        Mapping[str, Any]
    ] = None,
    settlement_transaction: Optional[str] = None,
) -> TrustReceipt:
    """
    Create a new version of an existing receipt.

    The previous receipt is never modified.

    Example:

        V1 → original resolution
        V2 → approved revised resolution

    The new receipt retains a reference to V1.
    """

    if previous.version <= 0:
        raise TrustReceiptVersionError(
            "Previous receipt has invalid version"
        )

    builder = TrustReceiptBuilder(
        receipt_id=(
            f"TR-{previous.prediction_id}"
            f"-V{previous.version + 1}"
        ),
        prediction_id=previous.prediction_id,
        event_id=previous.event_id,
        source_id=previous.source_id,
        fdc_attestation_id=(
            previous.fdc_attestation_id
        ),
        fdc_proof_reference=(
            previous.fdc_proof_reference
        ),
        evidence_commitment=(
            previous.evidence_commitment
        ),
        tee_attestation_id=(
            tee_attestation_id
        ),
        resolution_commitment=(
            resolution_commitment
        ),
        resolution=resolution,
        payout=payout,
        asset=previous.asset,
        resolution_rule=(
            previous.resolution_rule
        ),
        protected_payload=(
            protected_payload
            if protected_payload is not None
            else previous.protected_payload
        ),
        settlement_transaction=(
            settlement_transaction
        ),
        version=previous.version + 1,
        previous_receipt_id=previous.receipt_id,
        state="active",
    )

    return builder.build()


# ---------------------------------------------------------------------------
# Evidence / resolution helper functions
# ---------------------------------------------------------------------------

def build_evidence_commitment(
    *,
    event_id: str,
    source_id: str,
    fdc_attestation_id: str,
    proof_reference: str,
    normalized_outcome: str,
    event_status: str,
) -> str:
    """
    Create a commitment to the normalized public evidence associated with
    the resolution.
    """

    payload = {
        "event_id": event_id,
        "source_id": source_id,
        "fdc_attestation_id": (
            fdc_attestation_id
        ),
        "proof_reference": proof_reference,
        "normalized_outcome": normalized_outcome,
        "event_status": event_status,
    }

    return sha256_commitment(payload)


def build_resolution_commitment(
    *,
    prediction_id: str,
    event_id: str,
    evidence_commitment: str,
    outcome: str,
    payout: float,
    asset: str,
    rule_version: str,
) -> str:
    """
    Create a commitment to the deterministic confidential resolution result.
    """

    payload = {
        "prediction_id": prediction_id,
        "event_id": event_id,
        "evidence_commitment": evidence_commitment,
        "outcome": outcome,
        "payout": payout,
        "asset": asset,
        "rule_version": rule_version,
    }

    return sha256_commitment(payload)


# ---------------------------------------------------------------------------
# Complete receipt factory
# ---------------------------------------------------------------------------

def create_trust_receipt(
    *,
    prediction_id: str,
    event_id: str,
    source_id: str,
    fdc_attestation_id: str,
    fdc_proof_reference: str,
    evidence_commitment: str,
    tee_attestation_id: Optional[str],
    resolution: str,
    payout: float,
    asset: str,
    resolution_rule: str,
    protected_payload: Optional[
        Mapping[str, Any]
    ] = None,
    settlement_transaction: Optional[str] = None,
    resolution_commitment: Optional[str] = None,
    receipt_id: Optional[str] = None,
    version: int = 1,
) -> TrustReceipt:
    """
    High-level helper for creating a Trust Receipt.
    """

    if resolution_commitment is None:
        resolution_commitment = (
            build_resolution_commitment(
                prediction_id=prediction_id,
                event_id=event_id,
                evidence_commitment=(
                    evidence_commitment
                ),
                outcome=resolution,
                payout=payout,
                asset=asset,
                rule_version=resolution_rule,
            )
        )

    builder = TrustReceiptBuilder(
        receipt_id=receipt_id,
        prediction_id=prediction_id,
        event_id=event_id,
        source_id=source_id,
        fdc_attestation_id=(
            fdc_attestation_id
        ),
        fdc_proof_reference=(
            fdc_proof_reference
        ),
        evidence_commitment=(
            evidence_commitment
        ),
        tee_attestation_id=(
            tee_attestation_id
        ),
        resolution_commitment=(
            resolution_commitment
        ),
        resolution=resolution,
        payout=payout,
        asset=asset,
        resolution_rule=resolution_rule,
        protected_payload=(
            protected_payload
        ),
        settlement_transaction=(
            settlement_transaction
        ),
        version=version,
    )

    return builder.build()


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Demonstrate:

        evidence
          ↓
        resolution
          ↓
        Trust Receipt
          ↓
        commitment verification
    """

    evidence_commitment = (
        build_evidence_commitment(
            event_id="EVT-2026-FINAL-001",
            source_id="SRC-001",
            fdc_attestation_id=(
                "DEMO-FDC-PR-2026-001"
            ),
            proof_reference=(
                "DEMO-FDC-PROOF-PR-2026-001"
            ),
            normalized_outcome=(
                "TEAM_A_WIN"
            ),
            event_status="FINAL",
        )
    )

    resolution_commitment = (
        build_resolution_commitment(
            prediction_id="PR-2026-001",
            event_id="EVT-2026-FINAL-001",
            evidence_commitment=(
                evidence_commitment
            ),
            outcome="WIN",
            payout=185.0,
            asset="FXRP",
            rule_version=(
                "PREDICTRESOLVE-MATCH-WINNER-V1"
            ),
        )
    )

    receipt = create_trust_receipt(
        prediction_id="PR-2026-001",
        event_id="EVT-2026-FINAL-001",
        source_id="SRC-001",
        fdc_attestation_id=(
            "DEMO-FDC-PR-2026-001"
        ),
        fdc_proof_reference=(
            "DEMO-FDC-PROOF-PR-2026-001"
        ),
        evidence_commitment=(
            evidence_commitment
        ),
        tee_attestation_id=(
            "DEMO-TEE-PR-2026-001"
        ),
        resolution="WIN",
        payout=185.0,
        asset="FXRP",
        resolution_rule=(
            "PREDICTRESOLVE-MATCH-WINNER-V1"
        ),
        protected_payload={
            "prediction": {
                "selection": "TEAM_A_WIN",
                "visibility": "private",
            },
            "stake": {
                "amount": 100,
                "asset": "FXRP",
                "visibility": "private",
            },
            "odds": {
                "value": 1.85,
                "visibility": "private",
            },
            "maximum_payout": {
                "amount": 185,
                "asset": "FXRP",
                "visibility": "private",
            },
        },
        settlement_transaction=(
            "DEMO-TX-PR-2026-001"
        ),
        resolution_commitment=(
            resolution_commitment
        ),
    )

    print(
        "PREDICTRESOLVE — TRUST RECEIPT"
    )
    print("=" * 72)

    print("\nPUBLIC RECEIPT")
    print("-" * 72)

    print(
        json.dumps(
            public_receipt(receipt),
            indent=2,
        )
    )

    print("\nVERIFICATION")
    print("-" * 72)

    print(
        "Receipt valid:",
        verify_receipt(receipt),
    )

    print(
        "\nReceipt commitment:",
        receipt.receipt_commitment,
    )

    print(
        "\nSettlement commitment:",
        receipt.settlement_commitment,
    )

    print(
        "\nPROTECTED PAYLOAD"
    )
    print("-" * 72)

    print(
        json.dumps(
            receipt.protected_payload,
            indent=2,
        )
    )

    print(
        "\nNOTE: In production, the protected payload should "
        "be encrypted before protected off-chain storage."
    )


if __name__ == "__main__":
    main()
