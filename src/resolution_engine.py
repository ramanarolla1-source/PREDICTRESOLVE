"""
PredictResolve — Resolution Engine

Purpose
-------
Provides deterministic prediction-resolution rules.

The resolution engine answers:

    "Given a verified external outcome and a defined prediction rule,
     what is the logical result of the prediction?"

It does NOT:

- fetch Web2 data;
- verify FDC proofs;
- perform source qualification;
- run inside a TEE by itself;
- decide whether a source is trustworthy;
- transfer FXRP;
- execute blockchain transactions.

The intended architecture is:

    FDC / Web2Json
          ↓
    Verified Outcome
          ↓
    Resolution Engine
          ↓
    Deterministic Result
          ↓
    Flare Confidential Compute / TEE
          ↓
    Attested Resolution
          ↓
    Settlement Contract

The same deterministic rules can be executed inside the confidential
resolution boundary so that private inputs remain protected.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping, Optional


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ResolutionEngineError(Exception):
    """Base exception for resolution-engine failures."""


class InvalidRuleError(ResolutionEngineError):
    """Raised when an unsupported resolution rule is requested."""


class InvalidInputError(ResolutionEngineError):
    """Raised when resolution inputs are invalid."""


class EventNotResolvableError(ResolutionEngineError):
    """Raised when an event is not in a state suitable for resolution."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventStatus(str, Enum):
    FINAL = "FINAL"
    CANCELLED = "CANCELLED"
    ABANDONED = "ABANDONED"
    PENDING = "PENDING"


class ResolutionOutcome(str, Enum):
    WIN = "WIN"
    LOSS = "LOSS"
    REFUND = "REFUND"
    PENDING = "PENDING"


# ---------------------------------------------------------------------------
# Rule identifiers
# ---------------------------------------------------------------------------

RULE_MATCH_WINNER_V1 = "PREDICTRESOLVE-MATCH-WINNER-V1"
RULE_BINARY_EVENT_V1 = "PREDICTRESOLVE-BINARY-EVENT-V1"
RULE_THRESHOLD_V1 = "PREDICTRESOLVE-THRESHOLD-V1"


SUPPORTED_RULES = {
    RULE_MATCH_WINNER_V1,
    RULE_BINARY_EVENT_V1,
    RULE_THRESHOLD_V1,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ResolutionInput:
    """
    Public/verified event information.

    Private prediction terms are represented separately.
    """

    prediction_id: str
    event_id: str

    event_status: EventStatus

    verified_outcome: str

    fdc_verified: bool
    evidence_commitment: str

    source_conflict: bool = False

    observed_value: Optional[float] = None


@dataclass(frozen=True)
class PredictionTerms:
    """
    Prediction terms used by the deterministic rules.

    These values may be private in a production deployment and can therefore
    be supplied to the confidential computation boundary rather than stored
    publicly.
    """

    selection: str

    stake: float
    odds: float

    asset: str

    maximum_payout: float
    exposure_limit: float

    rule_version: str

    threshold: Optional[float] = None
    direction: Optional[str] = None


@dataclass(frozen=True)
class ResolutionDecision:
    """
    Deterministic result produced by the resolution engine.

    This object contains the result needed by the confidential-resolution
    layer and does not represent authorization to move funds.
    """

    prediction_id: str
    event_id: str

    rule_version: str

    outcome: ResolutionOutcome

    payout: float
    asset: str

    evidence_commitment: str
    resolution_commitment: str

    reason: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["outcome"] = self.outcome.value
        return result


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def canonical_json(value: Mapping[str, Any]) -> str:
    """Produce deterministic JSON for commitment generation."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_commitment(value: Mapping[str, Any]) -> str:
    """Generate a deterministic SHA-256 commitment."""

    digest = hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()

    return f"0x{digest}"


def normalize_selection(value: str) -> str:
    """Normalize a prediction selection."""

    normalized = value.strip().upper()

    aliases = {
        "TEAM A": "TEAM_A_WIN",
        "TEAM_A": "TEAM_A_WIN",
        "HOME": "TEAM_A_WIN",
        "HOME_TEAM": "TEAM_A_WIN",

        "TEAM B": "TEAM_B_WIN",
        "TEAM_B": "TEAM_B_WIN",
        "AWAY": "TEAM_B_WIN",
        "AWAY_TEAM": "TEAM_B_WIN",

        "YES": "YES",
        "NO": "NO",
    }

    return aliases.get(
        normalized,
        normalized,
    )


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class ResolutionValidator:
    """Validates public evidence and private prediction terms."""

    @staticmethod
    def validate_input(
        resolution_input: ResolutionInput,
    ) -> None:

        if not resolution_input.prediction_id.strip():
            raise InvalidInputError(
                "prediction_id must not be empty"
            )

        if not resolution_input.event_id.strip():
            raise InvalidInputError(
                "event_id must not be empty"
            )

        if not resolution_input.verified_outcome.strip():
            raise InvalidInputError(
                "verified_outcome must not be empty"
            )

        if not resolution_input.evidence_commitment.strip():
            raise InvalidInputError(
                "evidence_commitment must not be empty"
            )

    @staticmethod
    def validate_terms(
        terms: PredictionTerms,
    ) -> None:

        if not terms.selection.strip():
            raise InvalidInputError(
                "selection must not be empty"
            )

        if terms.stake <= 0:
            raise InvalidInputError(
                "stake must be greater than zero"
            )

        if terms.odds <= 0:
            raise InvalidInputError(
                "odds must be greater than zero"
            )

        if not terms.asset.strip():
            raise InvalidInputError(
                "asset must not be empty"
            )

        if terms.maximum_payout <= 0:
            raise InvalidInputError(
                "maximum_payout must be greater than zero"
            )

        if terms.exposure_limit <= 0:
            raise InvalidInputError(
                "exposure_limit must be greater than zero"
            )

        if terms.stake > terms.exposure_limit:
            raise InvalidInputError(
                "stake exceeds exposure limit"
            )

        expected_payout = terms.stake * terms.odds

        if terms.maximum_payout + 1e-9 < expected_payout:
            raise InvalidInputError(
                "maximum_payout is lower than stake × odds"
            )

        if not terms.rule_version.strip():
            raise InvalidRuleError(
                "rule_version must not be empty"
            )

        if (
            terms.rule_version == RULE_THRESHOLD_V1
            and terms.threshold is None
        ):
            raise InvalidInputError(
                "threshold is required for threshold rules"
            )


# ---------------------------------------------------------------------------
# Rule Engine
# ---------------------------------------------------------------------------

class ResolutionEngine:
    """
    Deterministic resolution engine.

    Each rule returns only a logical settlement outcome.

    The engine does not authorize or execute the financial settlement.
    """

    def __init__(self) -> None:
        self._rules = {
            RULE_MATCH_WINNER_V1: self._resolve_match_winner,
            RULE_BINARY_EVENT_V1: self._resolve_binary_event,
            RULE_THRESHOLD_V1: self._resolve_threshold,
        }

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def resolve(
        self,
        *,
        resolution_input: ResolutionInput,
        prediction_terms: PredictionTerms,
    ) -> ResolutionDecision:
        """
        Resolve one prediction against a verified external outcome.
        """

        ResolutionValidator.validate_input(
            resolution_input
        )

        ResolutionValidator.validate_terms(
            prediction_terms
        )

        if (
            resolution_input.event_id
            != resolution_input.event_id
        ):
            raise InvalidInputError(
                "Invalid event linkage"
            )

        if not resolution_input.fdc_verified:
            raise InvalidInputError(
                "FDC verification is required before resolution"
            )

        if resolution_input.source_conflict:
            return self._pending_decision(
                resolution_input=resolution_input,
                prediction_terms=prediction_terms,
                reason=(
                    "Source conflict prevents automatic resolution"
                ),
            )

        rule = self._rules.get(
            prediction_terms.rule_version
        )

        if rule is None:
            raise InvalidRuleError(
                f"Unsupported resolution rule: "
                f"{prediction_terms.rule_version}"
            )

        return rule(
            resolution_input,
            prediction_terms,
        )

    # ------------------------------------------------------------------
    # Common guards
    # ------------------------------------------------------------------

    @staticmethod
    def _require_final_event(
        resolution_input: ResolutionInput,
    ) -> None:

        if resolution_input.event_status == EventStatus.PENDING:
            raise EventNotResolvableError(
                "Event is not finalized"
            )

        if resolution_input.event_status not in {
            EventStatus.FINAL,
            EventStatus.CANCELLED,
            EventStatus.ABANDONED,
        }:
            raise EventNotResolvableError(
                "Event is not in a resolvable state"
            )

    # ------------------------------------------------------------------
    # Match winner rule
    # ------------------------------------------------------------------

    def _resolve_match_winner(
        self,
        resolution_input: ResolutionInput,
        prediction_terms: PredictionTerms,
    ) -> ResolutionDecision:

        self._require_final_event(
            resolution_input
        )

        selection = normalize_selection(
            prediction_terms.selection
        )

        observed = normalize_selection(
            resolution_input.verified_outcome
        )

        if resolution_input.event_status in {
            EventStatus.CANCELLED,
            EventStatus.ABANDONED,
        }:
            return self._refund_decision(
                resolution_input=resolution_input,
                prediction_terms=prediction_terms,
                reason=(
                    "Event cancelled or abandoned"
                ),
            )

        if selection == observed:
            payout = min(
                prediction_terms.stake
                * prediction_terms.odds,
                prediction_terms.maximum_payout,
            )

            return self._build_decision(
                resolution_input=resolution_input,
                prediction_terms=prediction_terms,
                outcome=ResolutionOutcome.WIN,
                payout=round(payout, 8),
                reason=(
                    "Prediction matches verified final outcome"
                ),
            )

        return self._build_decision(
            resolution_input=resolution_input,
            prediction_terms=prediction_terms,
            outcome=ResolutionOutcome.LOSS,
            payout=0.0,
            reason=(
                "Prediction does not match verified final outcome"
            ),
        )

    # ------------------------------------------------------------------
    # Binary event rule
    # ------------------------------------------------------------------

    def _resolve_binary_event(
        self,
        resolution_input: ResolutionInput,
        prediction_terms: PredictionTerms,
    ) -> ResolutionDecision:

        self._require_final_event(
            resolution_input
        )

        selection = normalize_selection(
            prediction_terms.selection
        )

        observed = normalize_selection(
            resolution_input.verified_outcome
        )

        if resolution_input.event_status in {
            EventStatus.CANCELLED,
            EventStatus.ABANDONED,
        }:
            return self._refund_decision(
                resolution_input=resolution_input,
                prediction_terms=prediction_terms,
                reason=(
                    "Binary event was cancelled or abandoned"
                ),
            )

        if selection == observed:
            payout = min(
                prediction_terms.stake
                * prediction_terms.odds,
                prediction_terms.maximum_payout,
            )

            return self._build_decision(
                resolution_input=resolution_input,
                prediction_terms=prediction_terms,
                outcome=ResolutionOutcome.WIN,
                payout=round(payout, 8),
                reason=(
                    "Binary prediction matches verified result"
                ),
            )

        return self._build_decision(
            resolution_input=resolution_input,
            prediction_terms=prediction_terms,
            outcome=ResolutionOutcome.LOSS,
            payout=0.0,
            reason=(
                "Binary prediction does not match verified result"
            ),
        )

    # ------------------------------------------------------------------
    # Threshold rule
    # ------------------------------------------------------------------

    def _resolve_threshold(
        self,
        resolution_input: ResolutionInput,
        prediction_terms: PredictionTerms,
    ) -> ResolutionDecision:

        self._require_final_event(
            resolution_input
        )

        if resolution_input.event_status in {
            EventStatus.CANCELLED,
            EventStatus.ABANDONED,
        }:
            return self._refund_decision(
                resolution_input=resolution_input,
                prediction_terms=prediction_terms,
                reason=(
                    "Threshold event was cancelled or abandoned"
                ),
            )

        if resolution_input.observed_value is None:
            raise InvalidInputError(
                "observed_value is required for threshold resolution"
            )

        if prediction_terms.threshold is None:
            raise InvalidInputError(
                "threshold is required for threshold resolution"
            )

        direction = (
            prediction_terms.direction or "GREATER_THAN"
        ).upper()

        if direction == "GREATER_THAN":
            condition_met = (
                resolution_input.observed_value
                > prediction_terms.threshold
            )

        elif direction == "GREATER_THAN_OR_EQUAL":
            condition_met = (
                resolution_input.observed_value
                >= prediction_terms.threshold
            )

        elif direction == "LESS_THAN":
            condition_met = (
                resolution_input.observed_value
                < prediction_terms.threshold
            )

        elif direction == "LESS_THAN_OR_EQUAL":
            condition_met = (
                resolution_input.observed_value
                <= prediction_terms.threshold
            )

        else:
            raise InvalidRuleError(
                f"Unsupported threshold direction: {direction}"
            )

        if condition_met:
            payout = min(
                prediction_terms.stake
                * prediction_terms.odds,
                prediction_terms.maximum_payout,
            )

            return self._build_decision(
                resolution_input=resolution_input,
                prediction_terms=prediction_terms,
                outcome=ResolutionOutcome.WIN,
                payout=round(payout, 8),
                reason=(
                    "Observed value satisfies threshold condition"
                ),
            )

        return self._build_decision(
            resolution_input=resolution_input,
            prediction_terms=prediction_terms,
            outcome=ResolutionOutcome.LOSS,
            payout=0.0,
            reason=(
                "Observed value does not satisfy threshold condition"
            ),
        )

    # ------------------------------------------------------------------
    # Result builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_decision(
        *,
        resolution_input: ResolutionInput,
        prediction_terms: PredictionTerms,
        outcome: ResolutionOutcome,
        payout: float,
        reason: str,
    ) -> ResolutionDecision:

        commitment_payload = {
            "prediction_id": (
                resolution_input.prediction_id
            ),
            "event_id": (
                resolution_input.event_id
            ),
            "rule_version": (
                prediction_terms.rule_version
            ),
            "verified_outcome": (
                resolution_input.verified_outcome
            ),
            "outcome": outcome.value,
            "payout": payout,
            "asset": prediction_terms.asset,
            "evidence_commitment": (
                resolution_input.evidence_commitment
            ),
        }

        resolution_commitment = sha256_commitment(
            commitment_payload
        )

        return ResolutionDecision(
            prediction_id=(
                resolution_input.prediction_id
            ),
            event_id=(
                resolution_input.event_id
            ),
            rule_version=(
                prediction_terms.rule_version
            ),
            outcome=outcome,
            payout=payout,
            asset=prediction_terms.asset,
            evidence_commitment=(
                resolution_input.evidence_commitment
            ),
            resolution_commitment=(
                resolution_commitment
            ),
            reason=reason,
        )

    @staticmethod
    def _refund_decision(
        *,
        resolution_input: ResolutionInput,
        prediction_terms: PredictionTerms,
        reason: str,
    ) -> ResolutionDecision:

        return ResolutionEngine._build_decision(
            resolution_input=resolution_input,
            prediction_terms=prediction_terms,
            outcome=ResolutionOutcome.REFUND,
            payout=prediction_terms.stake,
            reason=reason,
        )

    @staticmethod
    def _pending_decision(
        *,
        resolution_input: ResolutionInput,
        prediction_terms: PredictionTerms,
        reason: str,
    ) -> ResolutionDecision:

        return ResolutionEngine._build_decision(
            resolution_input=resolution_input,
            prediction_terms=prediction_terms,
            outcome=ResolutionOutcome.PENDING,
            payout=0.0,
            reason=reason,
        )


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------

def build_match_winner_input(
    *,
    prediction_id: str,
    event_id: str,
    verified_outcome: str,
    fdc_attestation_verified: bool = True,
    evidence_commitment: str = (
        "0x1111111111111111111111111111111111111111111111111111111111111111"
    ),
    event_status: EventStatus = EventStatus.FINAL,
    source_conflict: bool = False,
) -> ResolutionInput:
    """Create a standard match-winner resolution input."""

    return ResolutionInput(
        prediction_id=prediction_id,
        event_id=event_id,
        event_status=event_status,
        verified_outcome=verified_outcome,
        fdc_verified=fdc_attestation_verified,
        evidence_commitment=evidence_commitment,
        source_conflict=source_conflict,
    )


def build_match_winner_terms(
    *,
    selection: str,
    stake: float = 100.0,
    odds: float = 1.85,
    asset: str = "FXRP",
    maximum_payout: float = 185.0,
    exposure_limit: float = 185.0,
) -> PredictionTerms:
    """Create the standard demonstration prediction terms."""

    return PredictionTerms(
        selection=selection,
        stake=stake,
        odds=odds,
        asset=asset,
        maximum_payout=maximum_payout,
        exposure_limit=exposure_limit,
        rule_version=RULE_MATCH_WINNER_V1,
    )


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------

def main() -> None:
    engine = ResolutionEngine()

    resolution_input = build_match_winner_input(
        prediction_id="PR-2026-001",
        event_id="EVT-2026-FINAL-001",
        verified_outcome="TEAM_A_WIN",
    )

    prediction_terms = build_match_winner_terms(
        selection="TEAM_A_WIN",
        stake=100.0,
        odds=1.85,
        maximum_payout=185.0,
        exposure_limit=185.0,
    )

    decision = engine.resolve(
        resolution_input=resolution_input,
        prediction_terms=prediction_terms,
    )

    print("PREDICTRESOLVE — DETERMINISTIC RESOLUTION")
    print("=" * 72)

    print(
        json.dumps(
            decision.to_dict(),
            indent=2,
        )
    )

    print("\nRESULT")
    print("-" * 72)
    print(
        f"Outcome : {decision.outcome.value}"
    )
    print(
        f"Payout  : {decision.payout} "
        f"{decision.asset}"
    )
    print(
        f"Rule    : {decision.rule_version}"
    )

    print(
        "\nNOTE: "
        "This engine determines the logical resolution only. "
        "A confidential TEE boundary and settlement contract "
        "remain responsible for confidential execution and asset enforcement."
    )


if __name__ == "__main__":
    main()
