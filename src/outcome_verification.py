"""
PredictResolve — Outcome Verification

Purpose
-------
Process a public Web2 event response before it enters the confidential
resolution workflow.

Architecture:

    Public Web2 Source
            ↓
    Source Identity Validation
            ↓
    Response Schema Validation
            ↓
    FDC / Web2Json Verification Boundary
            ↓
    Normalized Outcome
            ↓
    VerifiedOutcome
            ↓
    Flare Confidential Compute / TEE

Important
---------
This module does NOT implement the Flare FDC protocol itself.

The repository uses an explicit FDCAdapter boundary so that:

    demonstration mode
        → synthetic / placeholder attestation data

can later be replaced by:

    live mode
        → real Web2Json request + FDC proof retrieval +
          Flare verification

The module also does not decide whether a prediction wins.

Its responsibility ends at:

    "This external event outcome has passed the evidence
     and verification boundary."
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OutcomeVerificationError(Exception):
    """Base exception for outcome-verification failures."""


class SourceValidationError(OutcomeVerificationError):
    """Raised when the selected source is not acceptable."""


class ResponseValidationError(OutcomeVerificationError):
    """Raised when the external response is malformed."""


class FDCVerificationError(OutcomeVerificationError):
    """Raised when the FDC/Web2Json verification boundary fails."""


class OutcomeNormalizationError(OutcomeVerificationError):
    """Raised when the public response cannot be normalized."""


class SourceConflictError(OutcomeVerificationError):
    """Raised when required sources disagree."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EventStatus(str, Enum):
    FINAL = "FINAL"
    CANCELLED = "CANCELLED"
    ABANDONED = "ABANDONED"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceExpectation:
    """
    Application-level expectations for the public source.

    These checks are intentionally separate from FDC proof validation.

    A valid proof can establish what was returned by the submitted source,
    while this layer establishes whether that source is the one the
    application intended to use.
    """

    source_id: str
    expected_domain: str
    expected_path_prefix: str
    supports_web2json: bool = True

    def __post_init__(self) -> None:
        if not self.source_id.strip():
            raise SourceValidationError(
                "source_id must not be empty"
            )

        if not self.expected_domain.strip():
            raise SourceValidationError(
                "expected_domain must not be empty"
            )

        if not self.expected_path_prefix.strip():
            raise SourceValidationError(
                "expected_path_prefix must not be empty"
            )

        if not self.supports_web2json:
            raise SourceValidationError(
                "Selected source is not configured for Web2Json"
            )


@dataclass(frozen=True)
class Web2JsonVerification:
    """
    Represents the result of the FDC/Web2Json verification boundary.

    In demonstration mode the identifiers are synthetic.

    In live mode they should correspond to actual Flare attestation data.
    """

    verified: bool
    verification_mode: str

    attestation_id: str
    proof_reference: str

    response_commitment: str

    request_commitment: Optional[str] = None

    def __post_init__(self) -> None:
        if self.verification_mode not in {
            "demonstration",
            "live",
        }:
            raise FDCVerificationError(
                "verification_mode must be "
                "'demonstration' or 'live'"
            )

        if not self.attestation_id.strip():
            raise FDCVerificationError(
                "attestation_id must not be empty"
            )

        if not self.proof_reference.strip():
            raise FDCVerificationError(
                "proof_reference must not be empty"
            )

        if not self.response_commitment.strip():
            raise FDCVerificationError(
                "response_commitment must not be empty"
            )


@dataclass(frozen=True)
class NormalizedOutcome:
    """
    Normalized event outcome consumed by the confidential-resolution layer.
    """

    event_id: str
    event_status: EventStatus
    normalized_outcome: str

    home_team: Optional[str]
    away_team: Optional[str]
    home_score: Optional[int]
    away_score: Optional[int]

    confidence: float

    def __post_init__(self) -> None:
        if not self.event_id.strip():
            raise OutcomeNormalizationError(
                "event_id must not be empty"
            )

        if not self.normalized_outcome.strip():
            raise OutcomeNormalizationError(
                "normalized_outcome must not be empty"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise OutcomeNormalizationError(
                "confidence must be between 0 and 1"
            )


@dataclass(frozen=True)
class VerifiedOutcome:
    """
    Final outcome object accepted by confidential resolution.

    This object contains only the public/verified outcome information required
    by downstream logic. Private prediction terms are intentionally absent.
    """

    event_id: str
    status: EventStatus
    normalized_outcome: str

    fdc_verified: bool
    fdc_attestation_id: str
    proof_reference: str

    evidence_commitment: str
    source_id: str

    outcome_confidence: float

    source_conflict: bool = False

    home_team: Optional[str] = None
    away_team: Optional[str] = None
    home_score: Optional[int] = None
    away_score: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["status"] = self.status.value
        return result


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def canonical_json(value: Mapping[str, Any]) -> str:
    """
    Produce deterministic JSON for hashing.
    """

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_commitment(value: Mapping[str, Any]) -> str:
    """
    Produce a SHA-256 commitment over a canonical JSON representation.
    """

    digest = hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()

    return f"0x{digest}"


# ---------------------------------------------------------------------------
# Source validation
# ---------------------------------------------------------------------------

class SourceValidator:
    """
    Performs application-level validation of a Web2 source.

    This is intentionally separate from FDC proof verification.
    """

    @staticmethod
    def validate(
        *,
        source: Mapping[str, Any],
        expectation: SourceExpectation,
    ) -> None:

        source_id = str(
            source.get("source_id", "")
        )

        if source_id != expectation.source_id:
            raise SourceValidationError(
                "Source ID does not match the expected source"
            )

        if not source.get("supports_web2json", False):
            raise SourceValidationError(
                "Source is not marked as Web2Json-compatible"
            )

        whitelist_status = str(
            source.get(
                "whitelist_status",
                "",
            )
        ).lower()

        if whitelist_status not in {
            "demonstration_supported",
            "supported",
            "whitelisted",
        }:
            raise SourceValidationError(
                "Source is not marked as supported/whitelisted "
                "for the Web2Json workflow"
            )

        url_validation = source.get(
            "url_validation",
            {},
        )

        if url_validation.get("required", True) is not True:
            raise SourceValidationError(
                "Source URL validation must be enabled"
            )

        expected_domain = str(
            url_validation.get(
                "expected_domain",
                "",
            )
        )

        if expected_domain != expectation.expected_domain:
            raise SourceValidationError(
                "Configured expected domain does not match "
                "the application expectation"
            )

        expected_path = str(
            url_validation.get(
                "expected_path_pattern",
                expectation.expected_path_prefix,
            )
        )

        if not expected_path:
            raise SourceValidationError(
                "Expected URL path pattern must not be empty"
            )


# ---------------------------------------------------------------------------
# Response validation
# ---------------------------------------------------------------------------

class ResponseValidator:
    """
    Validates the structure of the response selected for event resolution.
    """

    REQUIRED_FIELDS = {
        "status",
        "winner",
    }

    @staticmethod
    def validate(
        response: Mapping[str, Any],
        *,
        required_fields: Optional[Sequence[str]] = None,
    ) -> None:

        if not isinstance(response, Mapping):
            raise ResponseValidationError(
                "External response must be a JSON object/mapping"
            )

        if not response:
            raise ResponseValidationError(
                "External response must not be empty"
            )

        fields = (
            set(required_fields)
            if required_fields is not None
            else ResponseValidator.REQUIRED_FIELDS
        )

        missing = [
            field
            for field in fields
            if field not in response
        ]

        if missing:
            raise ResponseValidationError(
                "Required response fields are missing: "
                + ", ".join(sorted(missing))
            )


# ---------------------------------------------------------------------------
# Outcome normalization
# ---------------------------------------------------------------------------

class OutcomeNormalizer:
    """
    Converts source-specific representations into the common outcome model.
    """

    _FINAL_STATUSES = {
        "final",
        "finished",
        "completed",
        "complete",
        "ft",
    }

    _CANCELLED_STATUSES = {
        "cancelled",
        "canceled",
    }

    _ABANDONED_STATUSES = {
        "abandoned",
        "void",
    }

    @classmethod
    def normalize_status(
        cls,
        value: Any,
    ) -> EventStatus:

        if value is None:
            return EventStatus.UNKNOWN

        normalized = str(value).strip().lower()

        if normalized in cls._FINAL_STATUSES:
            return EventStatus.FINAL

        if normalized in cls._CANCELLED_STATUSES:
            return EventStatus.CANCELLED

        if normalized in cls._ABANDONED_STATUSES:
            return EventStatus.ABANDONED

        return EventStatus.UNKNOWN

    @staticmethod
    def normalize_winner(
        value: Any,
    ) -> str:

        if value is None:
            raise OutcomeNormalizationError(
                "Winner field is missing"
            )

        value = str(value).strip().upper()

        aliases = {
            "TEAM A": "TEAM_A_WIN",
            "TEAM_A": "TEAM_A_WIN",
            "A": "TEAM_A_WIN",
            "HOME": "TEAM_A_WIN",
            "HOME_TEAM": "TEAM_A_WIN",

            "TEAM B": "TEAM_B_WIN",
            "TEAM_B": "TEAM_B_WIN",
            "B": "TEAM_B_WIN",
            "AWAY": "TEAM_B_WIN",
            "AWAY_TEAM": "TEAM_B_WIN",
        }

        return aliases.get(
            value,
            value,
        )

    @staticmethod
    def normalize_score(
        value: Any,
    ) -> Optional[int]:

        if value is None:
            return None

        try:
            score = int(value)
        except (TypeError, ValueError) as exc:
            raise OutcomeNormalizationError(
                f"Invalid score value: {value!r}"
            ) from exc

        if score < 0:
            raise OutcomeNormalizationError(
                "Score cannot be negative"
            )

        return score

    def normalize(
        self,
        *,
        event_id: str,
        response: Mapping[str, Any],
        confidence: float = 0.96,
    ) -> NormalizedOutcome:

        status = self.normalize_status(
            response.get("status")
        )

        if status == EventStatus.FINAL:
            normalized_outcome = self.normalize_winner(
                response.get("winner")
            )
        elif status in {
            EventStatus.CANCELLED,
            EventStatus.ABANDONED,
        }:
            normalized_outcome = (
                "EVENT_CANCELLED"
                if status == EventStatus.CANCELLED
                else "EVENT_ABANDONED"
            )
        else:
            normalized_outcome = "EVENT_PENDING"

        return NormalizedOutcome(
            event_id=event_id,
            event_status=status,
            normalized_outcome=normalized_outcome,
            home_team=(
                str(response["home_team"])
                if response.get("home_team") is not None
                else None
            ),
            away_team=(
                str(response["away_team"])
                if response.get("away_team") is not None
                else None
            ),
            home_score=self.normalize_score(
                response.get("home_score")
            ),
            away_score=self.normalize_score(
                response.get("away_score")
            ),
            confidence=confidence,
        )


# ---------------------------------------------------------------------------
# FDC adapter
# ---------------------------------------------------------------------------

class FDCAdapter:
    """
    Boundary for live Flare FDC/Web2Json integration.

    The prototype uses demonstration mode.

    A production implementation should replace the demonstration branch with:

        1. Web2Json request creation
        2. request submission
        3. finalization wait
        4. proof retrieval
        5. proof verification
        6. response decoding
    """

    def verify_web2json(
        self,
        *,
        source: Mapping[str, Any],
        response: Mapping[str, Any],
        mode: str = "demonstration",
        attestation_id: str = "DEMO-FDC",
        proof_reference: str = "DEMO-FDC-PROOF",
    ) -> Web2JsonVerification:

        if mode not in {
            "demonstration",
            "live",
        }:
            raise FDCVerificationError(
                "mode must be 'demonstration' or 'live'"
            )

        if not source.get(
            "supports_web2json",
            False,
        ):
            raise FDCVerificationError(
                "Source does not support Web2Json"
            )

        if not response:
            raise FDCVerificationError(
                "Response is empty"
            )

        response_commitment = sha256_commitment(
            response
        )

        if mode == "demonstration":
            return Web2JsonVerification(
                verified=True,
                verification_mode="demonstration",
                attestation_id=attestation_id,
                proof_reference=proof_reference,
                response_commitment=response_commitment,
            )

        raise NotImplementedError(
            "Live FDC/Web2Json integration must be implemented "
            "against the current Flare FDC environment."
        )


# ---------------------------------------------------------------------------
# Outcome Verification Pipeline
# ---------------------------------------------------------------------------

class OutcomeVerificationPipeline:
    """
    Converts a public Web2 response into a VerifiedOutcome.
    """

    def __init__(
        self,
        *,
        fdc_adapter: Optional[FDCAdapter] = None,
    ) -> None:

        self.fdc_adapter = (
            fdc_adapter
            if fdc_adapter is not None
            else FDCAdapter()
        )

        self.normalizer = OutcomeNormalizer()

    def verify(
        self,
        *,
        event_id: str,
        source: Mapping[str, Any],
        expectation: SourceExpectation,
        response: Mapping[str, Any],
        required_fields: Optional[Sequence[str]] = None,
        verification_mode: str = "demonstration",
        attestation_id: str = "DEMO-FDC",
        proof_reference: str = "DEMO-FDC-PROOF",
        source_conflict: bool = False,
    ) -> VerifiedOutcome:
        """
        Complete verification flow:

            source validation
                ↓
            response validation
                ↓
            FDC verification boundary
                ↓
            normalization
                ↓
            evidence commitment
                ↓
            VerifiedOutcome
        """

        if not event_id.strip():
            raise ValueError(
                "event_id must not be empty"
            )

        SourceValidator.validate(
            source=source,
            expectation=expectation,
        )

        ResponseValidator.validate(
            response=response,
            required_fields=required_fields,
        )

        if source_conflict:
            raise SourceConflictError(
                "Source conflict prevents automatic outcome acceptance"
            )

        verification = (
            self.fdc_adapter.verify_web2json(
                source=source,
                response=response,
                mode=verification_mode,
                attestation_id=attestation_id,
                proof_reference=proof_reference,
            )
        )

        if not verification.verified:
            raise FDCVerificationError(
                "FDC/Web2Json verification failed"
            )

        normalized = self.normalizer.normalize(
            event_id=event_id,
            response=response,
        )

        evidence_payload = {
            "event_id": event_id,
            "source_id": source["source_id"],
            "attestation_id": (
                verification.attestation_id
            ),
            "proof_reference": (
                verification.proof_reference
            ),
            "response_commitment": (
                verification.response_commitment
            ),
            "normalized_outcome": (
                normalized.normalized_outcome
            ),
            "event_status": (
                normalized.event_status.value
            ),
            "home_team": normalized.home_team,
            "away_team": normalized.away_team,
            "home_score": normalized.home_score,
            "away_score": normalized.away_score,
        }

        evidence_commitment = sha256_commitment(
            evidence_payload
        )

        return VerifiedOutcome(
            event_id=event_id,
            status=normalized.event_status,
            normalized_outcome=(
                normalized.normalized_outcome
            ),
            fdc_verified=True,
            fdc_attestation_id=(
                verification.attestation_id
            ),
            proof_reference=(
                verification.proof_reference
            ),
            evidence_commitment=evidence_commitment,
            source_id=str(source["source_id"]),
            outcome_confidence=normalized.confidence,
            source_conflict=False,
            home_team=normalized.home_team,
            away_team=normalized.away_team,
            home_score=normalized.home_score,
            away_score=normalized.away_score,
        )


# ---------------------------------------------------------------------------
# Multi-source consistency
# ---------------------------------------------------------------------------

def compare_outcomes(
    outcomes: Sequence[VerifiedOutcome],
) -> Dict[str, Any]:
    """
    Compare multiple already-verified outcomes.

    This function does not perform FDC verification itself. It evaluates
    whether the independently verified outcomes agree.
    """

    if not outcomes:
        return {
            "source_count": 0,
            "status": "no_evidence",
            "conflict": True,
            "normalized_outcomes": [],
        }

    normalized = [
        outcome.normalized_outcome
        for outcome in outcomes
    ]

    unique = sorted(set(normalized))

    return {
        "source_count": len(outcomes),
        "status": (
            "consistent"
            if len(unique) == 1
            else "conflict"
        ),
        "conflict": len(unique) > 1,
        "normalized_outcomes": normalized,
        "unique_outcomes": unique,
    }


def require_consistent_outcomes(
    outcomes: Sequence[VerifiedOutcome],
) -> VerifiedOutcome:
    """
    Return the agreed outcome or raise on conflict.

    The most conservative result is used:
    conflicting evidence prevents automatic settlement.
    """

    comparison = compare_outcomes(
        outcomes
    )

    if comparison["conflict"]:
        raise SourceConflictError(
            "Verified sources do not agree on the event outcome"
        )

    # At this point all normalized outcomes agree.
    return outcomes[0]


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def verify_public_outcome(
    *,
    event_id: str,
    source: Mapping[str, Any],
    response: Mapping[str, Any],
    expected_domain: str,
    expected_path_prefix: str,
    source_id: str,
) -> VerifiedOutcome:
    """
    Convenience wrapper for the repository demonstration.
    """

    expectation = SourceExpectation(
        source_id=source_id,
        expected_domain=expected_domain,
        expected_path_prefix=expected_path_prefix,
        supports_web2json=True,
    )

    pipeline = OutcomeVerificationPipeline()

    return pipeline.verify(
        event_id=event_id,
        source=source,
        expectation=expectation,
        response=response,
        required_fields=[
            "status",
            "winner",
            "home_team",
            "away_team",
            "home_score",
            "away_score",
        ],
        verification_mode="demonstration",
        attestation_id=(
            f"DEMO-FDC-{event_id}"
        ),
        proof_reference=(
            f"DEMO-FDC-PROOF-{event_id}"
        ),
    )


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    source = {
        "source_id": "SRC-001",
        "name": "Official Sports Results API",
        "publisher": "Demonstration Sports Data Provider",
        "source_type": "sports_results_api",
        "url": (
            "https://example-sports-provider.com/"
            "api/matches/EVT-2026-FINAL-001"
        ),
        "supports_web2json": True,
        "whitelist_status": "demonstration_supported",
        "url_validation": {
            "required": True,
            "expected_domain": (
                "example-sports-provider.com"
            ),
            "expected_path_pattern": "/api/matches/",
        },
    }

    response = {
        "status": "final",
        "home_team": "Team A",
        "away_team": "Team B",
        "home_score": 2,
        "away_score": 1,
        "winner": "TEAM_A",
    }

    verified = verify_public_outcome(
        event_id="EVT-2026-FINAL-001",
        source=source,
        response=response,
        expected_domain=(
            "example-sports-provider.com"
        ),
        expected_path_prefix="/api/matches/",
        source_id="SRC-001",
    )

    print(
        "PREDICTRESOLVE — VERIFIED OUTCOME"
    )
    print("=" * 60)

    print(
        json.dumps(
            verified.to_dict(),
            indent=2,
        )
    )

    print("\nPUBLIC OUTCOME")
    print(
        f"Status  : {verified.status.value}"
    )
    print(
        f"Outcome : {verified.normalized_outcome}"
    )
    print(
        f"FDC     : {verified.fdc_attestation_id}"
    )
    print(
        f"Proof   : {verified.proof_reference}"
    )

    print(
        "\nThe result is now suitable as an input "
        "to confidential_resolution.py."
    )
