"""
PredictResolve — End-to-End Pipeline

Purpose
-------
Orchestrates the PredictResolve workflow:

    Source Intelligence
            ↓
    Public Outcome Verification
            ↓
    FDC / Web2Json Boundary
            ↓
    Verified Outcome
            ↓
    Confidential Resolution
            ↓
    TEE Attestation
            ↓
    Trust Receipt
            ↓
    On-chain Settlement Payload
            ↓
    FXRP Settlement Contract

Architecture boundary
---------------------
This module coordinates the application.

It does NOT:

- implement the Flare FDC protocol itself;
- implement a real Trusted Execution Environment;
- hold user private keys;
- directly transfer FXRP;
- independently decide what a prediction should mean;
- bypass the on-chain settlement contract.

The repository uses explicit adapters for the FDC and TEE boundaries so that
the demonstration can remain reproducible without fabricating live protocol
attestations or transactions.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

try:
    from .confidential_resolution import (
        EventStatus,
        PrivatePrediction,
        ResolutionOutcome,
        confidential_resolve,
    )
    from .outcome_verification import (
        OutcomeVerificationPipeline,
        SourceExpectation,
        VerifiedOutcome,
        compare_outcomes,
    )
except ImportError:
    # Allows:
    # python src/pipeline.py
    from confidential_resolution import (
        EventStatus,
        PrivatePrediction,
        ResolutionOutcome,
        confidential_resolve,
    )
    from outcome_verification import (
        OutcomeVerificationPipeline,
        SourceExpectation,
        VerifiedOutcome,
        compare_outcomes,
    )


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PipelineError(Exception):
    """Base exception for PredictResolve pipeline failures."""


class PipelineConfigurationError(PipelineError):
    """Raised when repository data is missing or malformed."""


class SettlementReadinessError(PipelineError):
    """Raised when the resolution is not ready for settlement."""


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def canonical_json(value: Mapping[str, Any]) -> str:
    """Return deterministic JSON for commitment generation."""

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


def load_json(path: Path) -> Dict[str, Any]:
    """Load a JSON repository data file."""

    if not path.exists():
        raise FileNotFoundError(
            f"Required data file not found: {path}"
        )

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        raise PipelineConfigurationError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SourceCandidate:
    source_id: str
    name: str
    classification: str
    overall_score: float
    supports_web2json: bool


@dataclass
class OutcomeVerificationResult:
    event_id: str
    selected_source_id: str
    verified_outcome: VerifiedOutcome
    compared_outcomes: List[VerifiedOutcome]
    source_consistency: Dict[str, Any]


@dataclass
class ConfidentialResolutionResult:
    prediction: PrivatePrediction
    verification: OutcomeVerificationResult
    resolution: Dict[str, Any]


@dataclass
class TrustReceiptPayload:
    """
    Protected receipt representation.

    The payload contains references/commitments rather than assuming that
    private prediction terms should be written to the public chain.
    """

    receipt_id: str
    version: int
    prediction_id: str
    event_id: str

    source_id: str

    fdc_attestation_id: str
    fdc_proof_reference: str
    evidence_commitment: str

    tee_attestation_id: Optional[str]
    resolution_commitment: str

    resolution: str
    payout: float
    asset: str

    rule_version: str

    settlement_commitment: str
    receipt_commitment: str

    state: str


@dataclass
class PipelineResult:
    prediction_id: str
    event_id: str

    source: SourceCandidate

    outcome: Dict[str, Any]

    resolution: Dict[str, Any]

    trust_receipt: Dict[str, Any]

    settlement: Dict[str, Any]

    status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Source intelligence adapter
# ---------------------------------------------------------------------------

class SourceIntelligenceAdapter:
    """
    Minimal adapter over data/sources.json.

    A production implementation can replace the scoring/selection mechanism
    with a live AI-assisted source-intelligence service while preserving the
    output contract used by this pipeline.
    """

    CLASSIFICATION_PRIORITY = {
        "preferred": 0,
        "secondary": 1,
        "context_only": 2,
        "reject": 3,
        "rejected": 3,
    }

    def __init__(
        self,
        sources: Mapping[str, Any],
    ) -> None:
        self.sources = list(
            sources.get("sources", [])
        )

        if not self.sources:
            raise PipelineConfigurationError(
                "No sources found in sources.json"
            )

    def rank(
        self,
        source_ids: Sequence[str],
    ) -> List[SourceCandidate]:
        candidates: List[SourceCandidate] = []

        for source in self.sources:
            if source.get("source_id") not in source_ids:
                continue

            ai = source.get(
                "ai_assessment",
                {},
            )

            classification = str(
                ai.get(
                    "classification",
                    "context_only",
                )
            ).lower()

            candidates.append(
                SourceCandidate(
                    source_id=str(
                        source["source_id"]
                    ),
                    name=str(
                        source["name"]
                    ),
                    classification=classification,
                    overall_score=float(
                        ai.get(
                            "overall",
                            0.0,
                        )
                    ),
                    supports_web2json=bool(
                        source.get(
                            "supports_web2json",
                            False,
                        )
                    ),
                )
            )

        candidates.sort(
            key=lambda item: (
                self.CLASSIFICATION_PRIORITY.get(
                    item.classification,
                    99,
                ),
                -item.overall_score,
                item.source_id,
            )
        )

        return candidates

    def select(
        self,
        source_ids: Sequence[str],
    ) -> SourceCandidate:
        ranked = self.rank(source_ids)

        for candidate in ranked:
            if (
                candidate.classification
                in {"preferred", "secondary"}
                and candidate.supports_web2json
            ):
                return candidate

        raise PipelineConfigurationError(
            "No suitable supported/whitelisted Web2Json source "
            "was found for the event"
        )

    def get_raw_source(
        self,
        source_id: str,
    ) -> Dict[str, Any]:
        for source in self.sources:
            if source.get("source_id") == source_id:
                return dict(source)

        raise PipelineConfigurationError(
            f"Source not found: {source_id}"
        )


# ---------------------------------------------------------------------------
# Prediction loader
# ---------------------------------------------------------------------------

class PredictionLoader:
    """
    Converts data/prediction.json into a PrivatePrediction.

    The JSON file is synthetic demonstration input.
    """

    @staticmethod
    def load(
        data: Mapping[str, Any],
    ) -> PrivatePrediction:

        prediction = data.get(
            "prediction",
            {},
        )

        private_terms = data.get(
            "private_terms",
            {},
        )

        prediction_terms = private_terms.get(
            "prediction",
            {},
        )

        stake = private_terms.get(
            "stake",
            {},
        )

        odds = private_terms.get(
            "odds",
            {},
        )

        maximum_payout = private_terms.get(
            "maximum_payout",
            {},
        )

        exposure_limit = private_terms.get(
            "exposure_limit",
            {},
        )

        settlement_rule_version = (
            private_terms.get(
                "settlement_rule_version"
            )
            or "PREDICTRESOLVE-RULES-V1.0"
        )

        return PrivatePrediction(
            prediction_id=str(
                prediction["prediction_id"]
            ),
            event_id=str(
                prediction["event_id"]
            ),
            selection=str(
                prediction_terms["selection"]
            ),
            stake=float(
                stake["amount"]
            ),
            asset=str(
                stake["asset"]
            ),
            odds=float(
                odds["value"]
            ),
            maximum_payout=float(
                maximum_payout["amount"]
            ),
            exposure_limit=float(
                exposure_limit["amount"]
            ),
            settlement_rule_version=str(
                settlement_rule_version
            ),
        )


# ---------------------------------------------------------------------------
# Outcome loader
# ---------------------------------------------------------------------------

class OutcomeLoader:
    """
    Converts data/sample_outcome.json into the public response used by the
    outcome-verification pipeline.
    """

    @staticmethod
    def load(
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:

        outcome = data.get(
            "outcome",
            {},
        )

        public_response = data.get(
            "public_response",
            {},
        )

        return {
            "event_id": str(
                outcome["event_id"]
            ),
            "response": dict(
                public_response
            ),
        }


# ---------------------------------------------------------------------------
# Trust Receipt builder
# ---------------------------------------------------------------------------

class PipelineTrustReceiptBuilder:
    """
    Lightweight Trust Receipt builder used by the orchestration layer.

    The repository also contains src/trust_receipt.py, which provides the
    lower-level commitment/receipt implementation.

    This class prepares the pipeline-specific receipt payload before that
    payload is handed to the registry/storage layer.
    """

    @staticmethod
    def build(
        *,
        prediction: PrivatePrediction,
        verification: OutcomeVerificationResult,
        resolution: Mapping[str, Any],
        receipt_id: Optional[str] = None,
        version: int = 1,
    ) -> TrustReceiptPayload:

        receipt_id = (
            receipt_id
            if receipt_id is not None
            else f"TR-{prediction.prediction_id}-V{version}"
        )

        resolution_data = dict(
            resolution.get(
                "resolution",
                {},
            )
        )

        resolution_commitment = str(
            resolution_data.get(
                "resolution_commitment",
                "",
            )
        )

        tee_attestation_id = (
            resolution_data.get(
                "tee_attestation_id"
            )
        )

        resolution_outcome = str(
            resolution_data.get(
                "outcome",
                ResolutionOutcome.PENDING.value,
            )
        )

        payout = float(
            resolution_data.get(
                "payout",
                0.0,
            )
        )

        evidence = verification.verified_outcome

        if not resolution_commitment:
            raise PipelineError(
                "Resolution commitment is missing"
            )

        settlement_payload = {
            "prediction_id": prediction.prediction_id,
            "event_id": prediction.event_id,
            "resolution": resolution_outcome,
            "payout": payout,
            "asset": prediction.asset,
            "resolution_commitment": resolution_commitment,
            "tee_attestation_id": tee_attestation_id,
        }

        settlement_commitment = sha256_commitment(
            settlement_payload
        )

        receipt_payload = {
            "receipt_id": receipt_id,
            "version": version,
            "prediction_id": prediction.prediction_id,
            "event_id": prediction.event_id,
            "source_id": evidence.source_id,
            "fdc_attestation_id": (
                evidence.fdc_attestation_id
            ),
            "fdc_proof_reference": (
                evidence.proof_reference
            ),
            "evidence_commitment": (
                evidence.evidence_commitment
            ),
            "tee_attestation_id": (
                tee_attestation_id
            ),
            "resolution_commitment": (
                resolution_commitment
            ),
            "resolution": resolution_outcome,
            "payout": payout,
            "asset": prediction.asset,
            "rule_version": (
                prediction.settlement_rule_version
            ),
            "settlement_commitment": (
                settlement_commitment
            ),
        }

        receipt_commitment = sha256_commitment(
            receipt_payload
        )

        state = (
            "active"
            if resolution_outcome
            in {
                ResolutionOutcome.WIN.value,
                ResolutionOutcome.LOSS.value,
                ResolutionOutcome.REFUND.value,
            }
            else "pending"
        )

        return TrustReceiptPayload(
            receipt_id=receipt_id,
            version=version,
            prediction_id=prediction.prediction_id,
            event_id=prediction.event_id,
            source_id=evidence.source_id,
            fdc_attestation_id=(
                evidence.fdc_attestation_id
            ),
            fdc_proof_reference=(
                evidence.proof_reference
            ),
            evidence_commitment=(
                evidence.evidence_commitment
            ),
            tee_attestation_id=tee_attestation_id,
            resolution_commitment=(
                resolution_commitment
            ),
            resolution=resolution_outcome,
            payout=payout,
            asset=prediction.asset,
            rule_version=(
                prediction.settlement_rule_version
            ),
            settlement_commitment=(
                settlement_commitment
            ),
            receipt_commitment=receipt_commitment,
            state=state,
        )


# ---------------------------------------------------------------------------
# PredictResolve Pipeline
# ---------------------------------------------------------------------------

class PredictResolvePipeline:
    """
    End-to-end PredictResolve orchestrator.
    """

    def __init__(
        self,
        *,
        prediction_data: Mapping[str, Any],
        outcome_data: Mapping[str, Any],
        sources_data: Mapping[str, Any],
    ) -> None:

        self.prediction_data = prediction_data
        self.outcome_data = outcome_data
        self.sources_data = sources_data

        self.prediction = (
            PredictionLoader.load(
                prediction_data
            )
        )

        self.source_intelligence = (
            SourceIntelligenceAdapter(
                sources_data
            )
        )

        self.outcome_verification = (
            OutcomeVerificationPipeline()
        )

    # ------------------------------------------------------------------
    # Step 1 — Source selection
    # ------------------------------------------------------------------

    def select_source(
        self,
    ) -> tuple[SourceCandidate, Dict[str, Any]]:

        outcome = OutcomeLoader.load(
            self.outcome_data
        )

        raw_sources = self.outcome_data.get(
            "source",
            {},
        )

        source_ids = self._candidate_source_ids()

        selected = (
            self.source_intelligence.select(
                source_ids
            )
        )

        source = (
            self.source_intelligence.get_raw_source(
                selected.source_id
            )
        )

        # Prefer the source metadata stored directly in sample_outcome.json
        # when it agrees with the selected source.
        if raw_sources:
            if (
                raw_sources.get("source_id")
                == selected.source_id
            ):
                source.update(
                    {
                        key: value
                        for key, value
                        in raw_sources.items()
                        if key not in {
                            "source_id"
                        }
                    }
                )

        return selected, source

    def _candidate_source_ids(
        self,
    ) -> List[str]:

        source_data = self.outcome_data.get(
            "source",
            {},
        )

        if source_data.get("source_id"):
            return [
                str(
                    source_data["source_id"]
                )
            ]

        return [
            str(
                source["source_id"]
            )
            for source in self.sources_data.get(
                "sources",
                [],
            )
            if source.get(
                "supports_web2json",
                False,
            )
        ]

    # ------------------------------------------------------------------
    # Step 2 — Outcome verification
    # ------------------------------------------------------------------

    def verify_outcome(
        self,
        *,
        selected_source: SourceCandidate,
        source_record: Mapping[str, Any],
    ) -> OutcomeVerificationResult:

        loaded = OutcomeLoader.load(
            self.outcome_data
        )

        event_id = loaded["event_id"]
        response = loaded["response"]

        url_validation = source_record.get(
            "url_validation",
            {},
        )

        expected_domain = str(
            url_validation.get(
                "expected_domain",
                "",
            )
        )

        expected_path = str(
            url_validation.get(
                "expected_path_pattern",
                "",
            )
        )

        if not expected_domain:
            raise PipelineConfigurationError(
                "Expected source domain is missing"
            )

        if not expected_path:
            raise PipelineConfigurationError(
                "Expected source path pattern is missing"
            )

        verified = (
            self.outcome_verification.verify(
                event_id=event_id,
                source=source_record,
                expectation=SourceExpectation(
                    source_id=selected_source.source_id,
                    expected_domain=expected_domain,
                    expected_path_prefix=expected_path,
                    supports_web2json=True,
                ),
                response=response,
                required_fields=[
                    "status",
                    "winner",
                    "home_team",
                    "away_team",
                    "home_score",
                    "away_score",
                ],
                verification_mode=(
                    self.outcome_data
                    .get(
                        "fdc_attestation",
                        {},
                    )
                    .get(
                        "verification_mode",
                        "demonstration",
                    )
                ),
                attestation_id=(
                    self.outcome_data
                    .get(
                        "fdc_attestation",
                        {},
                    )
                    .get(
                        "attestation_id",
                        f"DEMO-FDC-{event_id}",
                    )
                ),
                proof_reference=(
                    self.outcome_data
                    .get(
                        "fdc_attestation",
                        {},
                    )
                    .get(
                        "proof_reference",
                        f"DEMO-FDC-PROOF-{event_id}",
                    )
                ),
            )
        )

        consistency = compare_outcomes(
            [verified]
        )

        return OutcomeVerificationResult(
            event_id=event_id,
            selected_source_id=(
                selected_source.source_id
            ),
            verified_outcome=verified,
            compared_outcomes=[verified],
            source_consistency=consistency,
        )

    # ------------------------------------------------------------------
    # Step 3 — Confidential resolution
    # ------------------------------------------------------------------

    def resolve(
        self,
        verification: OutcomeVerificationResult,
    ) -> Dict[str, Any]:

        result = confidential_resolve(
            prediction=self.prediction,
            verified_outcome=(
                verification.verified_outcome
            ),
            rule_version=(
                self.prediction
                .settlement_rule_version
            ),
            tee_mode="demonstration",
        )

        return result

    # ------------------------------------------------------------------
    # Step 4 — Trust Receipt
    # ------------------------------------------------------------------

    def build_trust_receipt(
        self,
        *,
        verification: OutcomeVerificationResult,
        resolution: Mapping[str, Any],
    ) -> TrustReceiptPayload:

        return PipelineTrustReceiptBuilder.build(
            prediction=self.prediction,
            verification=verification,
            resolution=resolution,
        )

    # ------------------------------------------------------------------
    # Step 5 — Settlement payload
    # ------------------------------------------------------------------

    def build_settlement_payload(
        self,
        *,
        verification: OutcomeVerificationResult,
        resolution: Mapping[str, Any],
        trust_receipt: TrustReceiptPayload,
    ) -> Dict[str, Any]:

        resolution_data = dict(
            resolution.get(
                "resolution",
                {},
            )
        )

        tee_attestation = resolution.get(
            "tee_attestation"
        )

        settlement_ready = bool(
            resolution.get(
                "settlement_ready",
                False,
            )
        )

        resolution_outcome = resolution_data.get(
            "outcome",
            ResolutionOutcome.PENDING.value,
        )

        return {
            "prediction_id": (
                self.prediction.prediction_id
            ),
            "event_id": (
                self.prediction.event_id
            ),
            "settlement_asset": (
                self.prediction.asset
            ),
            "outcome": resolution_outcome,
            "payout": float(
                resolution_data.get(
                    "payout",
                    0.0,
                )
            ),
            "resolution_commitment": (
                resolution_data.get(
                    "resolution_commitment"
                )
            ),
            "trust_receipt_commitment": (
                trust_receipt.receipt_commitment
            ),
            "fdc_attestation_id": (
                verification
                .verified_outcome
                .fdc_attestation_id
            ),
            "tee_attestation_id": (
                resolution_data.get(
                    "tee_attestation_id"
                )
            ),
            "settlement_ready": (
                settlement_ready
            ),
            "tee_attestation_valid": bool(
                tee_attestation
                and tee_attestation.get(
                    "verified",
                    False,
                )
            ),
            "execution_mode": "demonstration",
            "note": (
                "This payload is ready for the settlement "
                "contract boundary. Live FXRP transfer requires "
                "a deployed contract, funding/escrow and live "
                "TEE attestation verification."
            ),
        }

    # ------------------------------------------------------------------
    # Complete pipeline
    # ------------------------------------------------------------------

    def run(self) -> PipelineResult:

        # 1. Select source
        selected_source, source_record = (
            self.select_source()
        )

        # 2. Verify public outcome
        verification = self.verify_outcome(
            selected_source=selected_source,
            source_record=source_record,
        )

        # A final event must be present for automatic resolution.
        if (
            verification.verified_outcome.status
            not in {
                EventStatus.FINAL,
                EventStatus.CANCELLED,
                EventStatus.ABANDONED,
            }
        ):
            raise SettlementReadinessError(
                "Event is not in a resolvable state"
            )

        # 3. Confidential resolution
        resolution = self.resolve(
            verification
        )

        # 4. Trust Receipt
        trust_receipt = (
            self.build_trust_receipt(
                verification=verification,
                resolution=resolution,
            )
        )

        # 5. Settlement payload
        settlement = (
            self.build_settlement_payload(
                verification=verification,
                resolution=resolution,
                trust_receipt=trust_receipt,
            )
        )

        resolution_outcome = str(
            settlement.get(
                "outcome",
                ResolutionOutcome.PENDING.value,
            )
        )

        if settlement["settlement_ready"]:
            status = (
                "READY_FOR_ONCHAIN_SETTLEMENT"
            )
        elif resolution_outcome == (
            ResolutionOutcome.PENDING.value
        ):
            status = "PENDING_RESOLUTION"
        else:
            status = "NOT_READY"

        return PipelineResult(
            prediction_id=(
                self.prediction.prediction_id
            ),
            event_id=(
                self.prediction.event_id
            ),
            source=selected_source,
            outcome=(
                verification
                .verified_outcome
                .to_dict()
            ),
            resolution=resolution,
            trust_receipt=asdict(
                trust_receipt
            ),
            settlement=settlement,
            status=status,
        )


# ---------------------------------------------------------------------------
# Repository demo runner
# ---------------------------------------------------------------------------

def run_repository_demo(
    repository_root: Optional[Path] = None,
) -> PipelineResult:
    """
    Run the complete demonstration from repository data files.
    """

    root = (
        repository_root
        if repository_root is not None
        else Path(__file__).resolve().parents[1]
    )

    prediction_data = load_json(
        root / "data" / "prediction.json"
    )

    outcome_data = load_json(
        root / "data" / "sample_outcome.json"
    )

    sources_data = load_json(
        root / "data" / "sources.json"
    )

    pipeline = PredictResolvePipeline(
        prediction_data=prediction_data,
        outcome_data=outcome_data,
        sources_data=sources_data,
    )

    return pipeline.run()


# ---------------------------------------------------------------------------
# CLI presentation
# ---------------------------------------------------------------------------

def main() -> None:

    result = run_repository_demo()

    print()
    print("=" * 76)
    print("PREDICTRESOLVE — END-TO-END PIPELINE")
    print("Predict. Verify. Resolve. Settle.")
    print("=" * 76)

    print("\n1. PREDICTION")
    print("-" * 76)
    print(
        f"Prediction ID : "
        f"{result.prediction_id}"
    )
    print(
        f"Event ID      : "
        f"{result.event_id}"
    )
    print(
        f"Asset         : "
        f"{result.settlement['settlement_asset']}"
    )

    print("\n2. SOURCE INTELLIGENCE")
    print("-" * 76)
    print(
        f"Selected Source : "
        f"{result.source.name}"
    )
    print(
        f"Classification   : "
        f"{result.source.classification}"
    )
    print(
        f"Source Score     : "
        f"{result.source.overall_score:.3f}"
    )

    print("\n3. FDC / WEB2JSON")
    print("-" * 76)
    print(
        f"FDC Attestation : "
        f"{result.outcome['fdc_attestation_id']}"
    )
    print(
        f"FDC Verified    : "
        f"{result.outcome['fdc_verified']}"
    )
    print(
        f"External Outcome: "
        f"{result.outcome['normalized_outcome']}"
    )

    print("\n4. CONFIDENTIAL RESOLUTION")
    print("-" * 76)
    print(
        f"TEE Attestation : "
        f"{result.resolution['tee_attestation']}"
    )

    print(
        json.dumps(
            result.resolution,
            indent=2,
        )
    )

    print("\n5. TRUST RECEIPT")
    print("-" * 76)
    print(
        f"Receipt ID      : "
        f"{result.trust_receipt['receipt_id']}"
    )
    print(
        f"Resolution      : "
        f"{result.trust_receipt['resolution']}"
    )
    print(
        f"Receipt Commit  : "
        f"{result.trust_receipt['receipt_commitment']}"
    )

    print("\n6. ON-CHAIN SETTLEMENT")
    print("-" * 76)
    print(
        f"Outcome         : "
        f"{result.settlement['outcome']}"
    )
    print(
        f"Payout          : "
        f"{result.settlement['payout']} "
        f"{result.settlement['settlement_asset']}"
    )
    print(
        f"Settlement Ready: "
        f"{result.settlement['settlement_ready']}"
    )

    print("\nFINAL STATUS")
    print("-" * 76)
    print(result.status)

    if result.status == (
        "READY_FOR_ONCHAIN_SETTLEMENT"
    ):
        print(
            "\n✓ Confidential resolution completed."
        )
        print(
            "✓ Trust Receipt prepared."
        )
        print(
            "✓ Settlement payload is ready "
            "for the Flare EVM contract boundary."
        )

    print(
        "\nNOTE:"
    )
    print(
        "The repository currently uses demonstration "
        "FDC/TEE adapters. A live deployment requires "
        "actual Flare verification, deployed contracts "
        "and FXRP funding/escrow."
    )


if __name__ == "__main__":
    main()
