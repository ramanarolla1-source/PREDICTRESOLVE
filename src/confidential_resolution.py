"""
PredictResolve — Confidential Resolution

Purpose
-------
Models the confidential-resolution boundary of PredictResolve.

The intended production architecture is:

    FDC / Web2Json
            ↓
    Verified External Outcome
            +
    Private Prediction Terms
            ↓
       Flare TEE / FCC
            ↓
    Confidential Resolution
            ↓
       TEE Attestation
            ↓
    Settlement Contract
            ↓
          FXRP

This module separates:

1. Private prediction inputs
2. Verified external outcome
3. Deterministic settlement rules
4. Confidential-resolution output
5. TEE attestation boundary

IMPORTANT
---------
This Python module is NOT itself a Trusted Execution Environment.

The repository uses it to model the computation that would execute inside
a Flare Confidential Compute TEE.

A production implementation must replace the demonstration TEE adapter with
the appropriate live Flare Confidential Compute deployment and attestation
verification mechanism.

Security principle:

    The TEE computes.
    The contract enforces.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConfidentialResolutionError(Exception):
    """Base exception for confidential-resolution failures."""


class InvalidPredictionError(ConfidentialResolutionError):
    """Raised when private prediction terms are invalid."""


class InvalidOutcomeError(ConfidentialResolutionError):
    """Raised when the verified external outcome is invalid."""


class InvalidResolutionRuleError(ConfidentialResolutionError):
    """Raised when the settlement rule is unsupported or invalid."""


class TEEAttestationError(ConfidentialResolutionError):
    """Raised when TEE attestation requirements are not satisfied."""


class ResolutionConflictError(ConfidentialResolutionError):
    """Raised when the event cannot be safely resolved."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ResolutionOutcome(str, Enum):
    WIN = "WIN"
    LOSS = "LOSS"
    REFUND = "REFUND"
    PENDING = "PENDING"


class EventStatus(str, Enum):
    FINAL = "FINAL"
    CANCELLED = "CANCELLED"
    ABANDONED = "ABANDONED"
    UNKNOWN = "UNKNOWN"


class ResolutionState(str, Enum):
    COMPUTED = "computed"
    ATTESTED = "attested"
    REJECTED = "rejected"
    PENDING = "pending"


# ---------------------------------------------------------------------------
# Private prediction model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PrivatePrediction:
    """
    Protected prediction terms.

    These values represent information that should not be written directly
    to the public settlement contract.

    In a production deployment, the values should enter the confidential
    execution boundary through protected/encrypted input channels.
    """

    prediction_id: str
    event_id: str
    selection: str
    stake: float
    asset: str
    odds: float
    maximum_payout: float
    exposure_limit: float
    settlement_rule_version: str

    def __post_init__(self) -> None:
        if not self.prediction_id.strip():
            raise InvalidPredictionError(
                "prediction_id must not be empty"
            )

        if not self.event_id.strip():
            raise InvalidPredictionError(
                "event_id must not be empty"
            )

        if not self.selection.strip():
            raise InvalidPredictionError(
                "selection must not be empty"
            )

        if self.stake <= 0:
            raise InvalidPredictionError(
                "stake must be greater than zero"
            )

        if not self.asset.strip():
            raise InvalidPredictionError(
                "settlement asset must not be empty"
            )

        if self.odds <= 0:
            raise InvalidPredictionError(
                "odds must be greater than zero"
            )

        if self.maximum_payout <= 0:
            raise InvalidPredictionError(
                "maximum_payout must be greater than zero"
            )

        if self.exposure_limit <= 0:
            raise InvalidPredictionError(
                "exposure_limit must be greater than zero"
            )

        if not self.settlement_rule_version.strip():
            raise InvalidPredictionError(
                "settlement_rule_version must not be empty"
            )

        expected_payout = self.stake * self.odds

        if self.maximum_payout + 1e-9 < expected_payout:
            raise InvalidPredictionError(
                "maximum_payout is lower than the stake × odds payout"
            )

        if self.stake > self.exposure_limit:
            raise InvalidPredictionError(
                "stake exceeds the configured exposure limit"
            )


# ---------------------------------------------------------------------------
# Verified external outcome
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifiedOutcome:
    """
    External event outcome accepted by the evidence pipeline.

    `fdc_verified=True` means the application has passed its FDC/Web2Json
    verification boundary.

    This object should not be constructed from an arbitrary raw Web2 response
    in production. It should be created only after the evidence pipeline has
    completed source validation and proof verification.
    """

    event_id: str
    status: EventStatus
    normalized_outcome: str

    fdc_verified: bool
    fdc_attestation_id: str
    evidence_commitment: str

    source_id: str
    outcome_confidence: float = 1.0
    source_conflict: bool = False

    def __post_init__(self) -> None:
        if not self.event_id.strip():
            raise InvalidOutcomeError(
                "event_id must not be empty"
            )

        if not self.normalized_outcome.strip():
            raise InvalidOutcomeError(
                "normalized_outcome must not be empty"
            )

        if not self.fdc_attestation_id.strip():
            raise InvalidOutcomeError(
                "fdc_attestation_id must not be empty"
            )

        if not self.evidence_commitment.strip():
            raise InvalidOutcomeError(
                "evidence_commitment must not be empty"
            )

        if not self.source_id.strip():
            raise InvalidOutcomeError(
                "source_id must not be empty"
            )

        if not 0.0 <= self.outcome_confidence <= 1.0:
            raise InvalidOutcomeError(
                "outcome_confidence must be between 0.0 and 1.0"
            )


# ---------------------------------------------------------------------------
# Confidential resolution result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolutionResult:
    """
    Result produced by the confidential resolution logic.

    The result contains only what is necessary for downstream attestation and
    settlement. Private inputs are deliberately not included.
    """

    prediction_id: str
    event_id: str
    outcome: ResolutionOutcome
    payout: float
    asset: str

    rule_version: str
    resolution_commitment: str

    state: ResolutionState

    fdc_attestation_id: str
    evidence_commitment: str

    tee_attestation_id: Optional[str] = None

    def to_public_dict(self) -> Dict[str, Any]:
        """
        Return a settlement-oriented public representation.

        Private prediction terms such as odds and exposure are intentionally
        excluded.
        """

        return {
            "prediction_id": self.prediction_id,
            "event_id": self.event_id,
            "outcome": self.outcome.value,
            "payout": self.payout,
            "asset": self.asset,
            "rule_version": self.rule_version,
            "resolution_commitment": self.resolution_commitment,
            "state": self.state.value,
            "fdc_attestation_id": self.fdc_attestation_id,
            "evidence_commitment": self.evidence_commitment,
            "tee_attestation_id": self.tee_attestation_id,
        }


@dataclass(frozen=True)
class TEEAttestation:
    """
    Demonstration representation of a TEE attestation.

    A production implementation should derive this from the actual Flare
    Confidential Compute attestation mechanism.

    `attested_payload_commitment` binds the attestation to the confidential
    resolution output.
    """

    attestation_id: str
    prediction_id: str
    resolution_commitment: str

    verification_mode: str
    verified: bool

    attested_payload_commitment: str

    def __post_init__(self) -> None:
        if self.verification_mode not in {
            "demonstration",
            "live",
        }:
            raise TEEAttestationError(
                "verification_mode must be 'demonstration' or 'live'"
            )

        if not self.attestation_id.strip():
            raise TEEAttestationError(
                "attestation_id must not be empty"
            )

        if not self.prediction_id.strip():
            raise TEEAttestationError(
                "prediction_id must not be empty"
            )

        if not self.resolution_commitment.strip():
            raise TEEAttestationError(
                "resolution_commitment must not be empty"
            )

        if not self.attested_payload_commitment.strip():
            raise TEEAttestationError(
                "attested_payload_commitment must not be empty"
            )


# ---------------------------------------------------------------------------
# Canonicalization / commitments
# ---------------------------------------------------------------------------

def canonical_json(payload: Mapping[str, Any]) -> str:
    """
    Produce a deterministic JSON representation.
    """

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_commitment(payload: Mapping[str, Any]) -> str:
    """
    Produce a deterministic SHA-256 commitment.

    The commitment is prefixed with 0x for blockchain-oriented display.
    """

    digest = hashlib.sha256(
        canonical_json(payload).encode("utf-8")
    ).hexdigest()

    return f"0x{digest}"


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class ConfidentialResolutionEngine:
    """
    Deterministic resolution engine.

    This is the computation that the prototype models as running inside
    the Flare Confidential Compute TEE.

    The engine deliberately does not fetch Web2 data and does not authorize
    or execute blockchain transactions.
    """

    SUPPORTED_RULES = {
        "PREDICTRESOLVE-RULES-V1.0",
    }

    def __init__(self, rule_version: str) -> None:
        if rule_version not in self.SUPPORTED_RULES:
            raise InvalidResolutionRuleError(
                f"Unsupported settlement rule: {rule_version}"
            )

        self.rule_version = rule_version

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_event(
        prediction: PrivatePrediction,
        outcome: VerifiedOutcome,
    ) -> None:
        if prediction.event_id != outcome.event_id:
            raise InvalidOutcomeError(
                "Prediction and verified outcome refer to different events"
            )

        if not outcome.fdc_verified:
            raise InvalidOutcomeError(
                "External outcome has not passed FDC verification"
            )

        if outcome.source_conflict:
            raise ResolutionConflictError(
                "External sources are in conflict; resolution must remain pending"
            )

        if outcome.status == EventStatus.UNKNOWN:
            raise InvalidOutcomeError(
                "Event status is unknown"
            )

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(
        self,
        prediction: PrivatePrediction,
        outcome: VerifiedOutcome,
    ) -> ResolutionResult:
        """
        Resolve a private prediction against a verified external outcome.

        Rules:

        FINAL + matching selection
            -> WIN

        FINAL + non-matching selection
            -> LOSS

        CANCELLED / ABANDONED
            -> REFUND

        Anything else
            -> PENDING
        """

        self._validate_event(
            prediction,
            outcome,
        )

        # --------------------------------------------------------------
        # Cancelled / abandoned event
        # --------------------------------------------------------------

        if outcome.status in {
            EventStatus.CANCELLED,
            EventStatus.ABANDONED,
        }:
            return self._build_result(
                prediction=prediction,
                outcome=ResolutionOutcome.REFUND,
                payout=prediction.stake,
                external_outcome=outcome,
            )

        # --------------------------------------------------------------
        # Finalized event
        # --------------------------------------------------------------

        if outcome.status == EventStatus.FINAL:
            normalized_selection = (
                prediction.selection.strip().upper()
            )

            normalized_outcome = (
                outcome.normalized_outcome.strip().upper()
            )

            if normalized_selection == normalized_outcome:
                payout = min(
                    prediction.stake * prediction.odds,
                    prediction.maximum_payout,
                )

                return self._build_result(
                    prediction=prediction,
                    outcome=ResolutionOutcome.WIN,
                    payout=round(payout, 8),
                    external_outcome=outcome,
                )

            return self._build_result(
                prediction=prediction,
                outcome=ResolutionOutcome.LOSS,
                payout=0.0,
                external_outcome=outcome,
            )

        # --------------------------------------------------------------
        # Anything not yet final
        # --------------------------------------------------------------

        return self._build_result(
            prediction=prediction,
            outcome=ResolutionOutcome.PENDING,
            payout=0.0,
            external_outcome=outcome,
        )

    # ------------------------------------------------------------------
    # Result construction
    # ------------------------------------------------------------------

    def _build_result(
        self,
        *,
        prediction: PrivatePrediction,
        outcome: ResolutionOutcome,
        payout: float,
        external_outcome: VerifiedOutcome,
    ) -> ResolutionResult:
        """
        Build a resolution result and commitment.

        Notice that private odds, stake and exposure are NOT included in
        the public resolution commitment payload. A production system may
        choose to include commitments to those private inputs separately.
        """

        commitment_payload = {
            "prediction_id": prediction.prediction_id,
            "event_id": prediction.event_id,
            "external_outcome": external_outcome.normalized_outcome,
            "event_status": external_outcome.status.value,
            "resolution": outcome.value,
            "payout": payout,
            "asset": prediction.asset,
            "rule_version": self.rule_version,
            "evidence_commitment": (
                external_outcome.evidence_commitment
            ),
        }

        resolution_commitment = sha256_commitment(
            commitment_payload
        )

        state = (
            ResolutionState.PENDING
            if outcome == ResolutionOutcome.PENDING
            else ResolutionState.COMPUTED
        )

        return ResolutionResult(
            prediction_id=prediction.prediction_id,
            event_id=prediction.event_id,
            outcome=outcome,
            payout=payout,
            asset=prediction.asset,
            rule_version=self.rule_version,
            resolution_commitment=resolution_commitment,
            state=state,
            fdc_attestation_id=(
                external_outcome.fdc_attestation_id
            ),
            evidence_commitment=(
                external_outcome.evidence_commitment
            ),
        )


# ---------------------------------------------------------------------------
# TEE adapter
# ---------------------------------------------------------------------------

class TEEAdapter:
    """
    Demonstration boundary representing the Flare Confidential Compute TEE.

    This class intentionally does NOT claim to be a real TEE.

    It provides the interface that a production Flare FCC adapter can
    implement.

    Production responsibilities would include:
        - secure input delivery;
        - enclave/TEE identity;
        - confidential execution;
        - attestation generation;
        - attestation key management;
        - result binding;
        - replay protection.
    """

    def execute(
        self,
        resolution: ResolutionResult,
        *,
        mode: str = "demonstration",
    ) -> tuple[ResolutionResult, TEEAttestation]:

        if mode not in {
            "demonstration",
            "live",
        }:
            raise TEEAttestationError(
                "mode must be 'demonstration' or 'live'"
            )

        if resolution.state != ResolutionState.COMPUTED:
            raise TEEAttestationError(
                "Only computed resolutions can be attested"
            )

        if mode == "live":
            raise NotImplementedError(
                "Live Flare Confidential Compute integration must be "
                "implemented using the current Flare FCC deployment and "
                "attestation mechanism."
            )

        attestation_id = (
            "DEMO-TEE-"
            + resolution.prediction_id
            + "-"
            + secrets.token_hex(4).upper()
        )

        attested_payload = {
            "prediction_id": resolution.prediction_id,
            "event_id": resolution.event_id,
            "outcome": resolution.outcome.value,
            "payout": resolution.payout,
            "asset": resolution.asset,
            "rule_version": resolution.rule_version,
            "resolution_commitment": (
                resolution.resolution_commitment
            ),
            "evidence_commitment": (
                resolution.evidence_commitment
            ),
        }

        attested_payload_commitment = (
            sha256_commitment(attested_payload)
        )

        attestation = TEEAttestation(
            attestation_id=attestation_id,
            prediction_id=resolution.prediction_id,
            resolution_commitment=(
                resolution.resolution_commitment
            ),
            verification_mode="demonstration",
            verified=True,
            attested_payload_commitment=(
                attested_payload_commitment
            ),
        )

        attested_resolution = ResolutionResult(
            prediction_id=resolution.prediction_id,
            event_id=resolution.event_id,
            outcome=resolution.outcome,
            payout=resolution.payout,
            asset=resolution.asset,
            rule_version=resolution.rule_version,
            resolution_commitment=(
                resolution.resolution_commitment
            ),
            state=ResolutionState.ATTESTED,
            fdc_attestation_id=(
                resolution.fdc_attestation_id
            ),
            evidence_commitment=(
                resolution.evidence_commitment
            ),
            tee_attestation_id=attestation_id,
        )

        return (
            attested_resolution,
            attestation,
        )


# ---------------------------------------------------------------------------
# Public result verification
# ---------------------------------------------------------------------------

def verify_tee_result(
    resolution: ResolutionResult,
    attestation: TEEAttestation,
) -> bool:
    """
    Demonstration-level validation that the attestation is bound to the
    expected prediction and resolution commitment.

    A production system must replace this with actual Flare FCC
    attestation verification.
    """

    if not attestation.verified:
        return False

    if (
        attestation.prediction_id
        != resolution.prediction_id
    ):
        return False

    if (
        attestation.resolution_commitment
        != resolution.resolution_commitment
    ):
        return False

    if (
        attestation.attested_payload_commitment.strip()
        == ""
    ):
        return False

    return True


# ---------------------------------------------------------------------------
# High-level confidential-resolution workflow
# ---------------------------------------------------------------------------

def confidential_resolve(
    *,
    prediction: PrivatePrediction,
    verified_outcome: VerifiedOutcome,
    rule_version: Optional[str] = None,
    tee_mode: str = "demonstration",
) -> Dict[str, Any]:
    """
    Execute the complete prototype confidential-resolution workflow.

    Flow:

        private prediction
              +
        verified outcome
              ↓
        deterministic resolution
              ↓
        TEE boundary
              ↓
        attested result
    """

    selected_rule = (
        rule_version
        if rule_version is not None
        else prediction.settlement_rule_version
    )

    engine = ConfidentialResolutionEngine(
        selected_rule
    )

    computed_resolution = engine.resolve(
        prediction=prediction,
        outcome=verified_outcome,
    )

    # Pending resolutions must not be attested as executable settlement
    # results.
    if computed_resolution.state == ResolutionState.PENDING:
        return {
            "status": "pending",
            "resolution": computed_resolution.to_public_dict(),
            "tee_attestation": None,
            "settlement_ready": False,
        }

    tee = TEEAdapter()

    attested_resolution, attestation = tee.execute(
        computed_resolution,
        mode=tee_mode,
    )

    valid = verify_tee_result(
        attested_resolution,
        attestation,
    )

    if not valid:
        raise TEEAttestationError(
            "TEE attestation failed validation"
        )

    return {
        "status": "attested",
        "resolution": (
            attested_resolution.to_public_dict()
        ),
        "tee_attestation": asdict(attestation),
        "settlement_ready": (
            attested_resolution.outcome
            in {
                ResolutionOutcome.WIN,
                ResolutionOutcome.LOSS,
                ResolutionOutcome.REFUND,
            }
        ),
    }


# ---------------------------------------------------------------------------
# Demonstration helpers
# ---------------------------------------------------------------------------

def build_demo_prediction() -> PrivatePrediction:
    """
    Build the synthetic prediction used by the repository demo.
    """

    return PrivatePrediction(
        prediction_id="PR-2026-001",
        event_id="EVT-2026-FINAL-001",
        selection="TEAM_A_WIN",
        stake=100.0,
        asset="FXRP",
        odds=1.85,
        maximum_payout=185.0,
        exposure_limit=185.0,
        settlement_rule_version=(
            "PREDICTRESOLVE-RULES-V1.0"
        ),
    )


def build_demo_verified_outcome() -> VerifiedOutcome:
    """
    Build the synthetic FDC-verified outcome used by the repository demo.
    """

    return VerifiedOutcome(
        event_id="EVT-2026-FINAL-001",
        status=EventStatus.FINAL,
        normalized_outcome="TEAM_A_WIN",
        fdc_verified=True,
        fdc_attestation_id=(
            "DEMO-FDC-PR-2026-001"
        ),
        evidence_commitment=(
            "0x1111111111111111111111111111111111111111111111111111111111111111"
        ),
        source_id="SRC-001",
        outcome_confidence=0.96,
        source_conflict=False,
    )


# ---------------------------------------------------------------------------
# CLI demonstration
# ---------------------------------------------------------------------------

def main() -> None:
    prediction = build_demo_prediction()

    verified_outcome = build_demo_verified_outcome()

    result = confidential_resolve(
        prediction=prediction,
        verified_outcome=verified_outcome,
        tee_mode="demonstration",
    )

    print("PREDICTRESOLVE — CONFIDENTIAL RESOLUTION")
    print("=" * 72)

    print("\nPRIVATE INPUTS")
    print(
        f"Prediction : {prediction.selection}"
    )
    print(
        f"Stake      : {prediction.stake} {prediction.asset}"
    )
    print(
        f"Odds       : {prediction.odds}"
    )
    print(
        f"Max payout : {prediction.maximum_payout} {prediction.asset}"
    )

    print("\nVERIFIED EXTERNAL OUTCOME")
    print(
        f"Event      : {verified_outcome.event_id}"
    )
    print(
        f"Outcome    : {verified_outcome.normalized_outcome}"
    )
    print(
        f"FDC proof  : {verified_outcome.fdc_attestation_id}"
    )

    print("\nCONFIDENTIAL RESOLUTION RESULT")

    print(
        json.dumps(
            result,
            indent=2,
        )
    )

    if result["settlement_ready"]:
        print(
            "\n✓ Resolution is ready for the settlement contract."
        )

    print(
        "\nNOTE: This demonstration models the TEE boundary. "
        "The actual Flare FCC/TEE attestation mechanism must be "
        "connected for a live deployment."
    )


if __name__ == "__main__":
    main()
