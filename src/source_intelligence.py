"""
PredictResolve — Source Intelligence

Purpose
-------
Evaluate and rank candidate public Web2 sources before they enter the
FDC/Web2Json evidence workflow.

This module answers:

    "Which source is appropriate for this event?"

It does NOT answer:

    "Is this source absolutely truthful?"

It also does NOT perform FDC proof verification.

The intended architecture is:

    Candidate Sources
          ↓
    Source Intelligence
          ↓
    Authority / Provenance / Relevance / Freshness / Corroboration
          ↓
    Source Classification
          ↓
    Supported / Preferred Source
          ↓
    FDC / Web2Json
          ↓
    Verified External Outcome

Important security boundary
---------------------------
A source can receive a high intelligence score and still be unsuitable for
the FDC workflow if it is not supported/whitelisted.

Similarly, a valid FDC proof does not by itself establish that the supplied
source was the source the application intended to use.

Therefore source intelligence, source-policy validation and FDC proof
verification remain separate controls.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SourceIntelligenceError(Exception):
    """Base exception for source-intelligence failures."""


class SourceValidationError(SourceIntelligenceError):
    """Raised when a source record is malformed."""


class NoSuitableSourceError(SourceIntelligenceError):
    """Raised when no source satisfies the selection policy."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SourceClassification(str, Enum):
    PREFERRED = "preferred"
    SECONDARY = "secondary"
    CONTEXT_ONLY = "context_only"
    REJECTED = "rejected"


# Lower value = better ranking.
_CLASSIFICATION_PRIORITY = {
    SourceClassification.PREFERRED: 0,
    SourceClassification.SECONDARY: 1,
    SourceClassification.CONTEXT_ONLY: 2,
    SourceClassification.REJECTED: 3,
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SourceCriteria:
    """
    Source-quality dimensions.

    All values are normalized to 0.0–1.0.
    """

    authority: float
    provenance: float
    relevance: float
    freshness: float
    corroboration: float

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not isinstance(value, (int, float)):
                raise SourceValidationError(
                    f"{name} must be numeric"
                )

            if not 0.0 <= value <= 1.0:
                raise SourceValidationError(
                    f"{name} must be between 0.0 and 1.0"
                )


@dataclass(frozen=True)
class SourceProfile:
    """
    Structured source-intelligence result.
    """

    source_id: str
    name: str
    publisher: str
    source_type: str
    url: str

    criteria: SourceCriteria

    supports_web2json: bool
    whitelist_status: str

    classification: SourceClassification
    overall_score: float

    recommendation: str

    source_status: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)

        result["classification"] = (
            self.classification.value
        )

        return result


@dataclass(frozen=True)
class SourceSelectionPolicy:
    """
    Application-level policy for selecting an external source.
    """

    minimum_classification: SourceClassification = (
        SourceClassification.SECONDARY
    )

    require_web2json: bool = True

    require_supported_source: bool = True

    require_url_validation: bool = True

    require_corroboration: bool = False

    minimum_score: float = 0.70

    def __post_init__(self) -> None:
        if not 0.0 <= self.minimum_score <= 1.0:
            raise SourceValidationError(
                "minimum_score must be between 0 and 1"
            )


# ---------------------------------------------------------------------------
# Source Intelligence Engine
# ---------------------------------------------------------------------------

class SourceIntelligence:
    """
    Deterministic source-intelligence engine.

    The current repository uses structured source assessments from
    data/sources.json.

    A production implementation can replace or augment the scoring stage
    with a live AI model without changing the SourceProfile interface.
    """

    DEFAULT_WEIGHTS = {
        "authority": 0.20,
        "provenance": 0.20,
        "relevance": 0.20,
        "freshness": 0.20,
        "corroboration": 0.20,
    }

    def __init__(
        self,
        *,
        weights: Optional[Mapping[str, float]] = None,
    ) -> None:

        self.weights = dict(
            weights
            if weights is not None
            else self.DEFAULT_WEIGHTS
        )

        self._validate_weights()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_weights(self) -> None:
        expected = {
            "authority",
            "provenance",
            "relevance",
            "freshness",
            "corroboration",
        }

        if set(self.weights) != expected:
            raise SourceValidationError(
                "Source weights must contain exactly: "
                + ", ".join(sorted(expected))
            )

        for name, value in self.weights.items():
            if not isinstance(value, (int, float)):
                raise SourceValidationError(
                    f"Weight {name} must be numeric"
                )

            if value < 0:
                raise SourceValidationError(
                    f"Weight {name} must not be negative"
                )

        total = sum(self.weights.values())

        if total <= 0:
            raise SourceValidationError(
                "Source weights must have a positive total"
            )

        # Normalize automatically.
        self.weights = {
            key: value / total
            for key, value in self.weights.items()
        }

    @staticmethod
    def _validate_source_record(
        source: Mapping[str, Any],
    ) -> None:

        required = [
            "source_id",
            "name",
            "publisher",
            "source_type",
            "url",
        ]

        missing = [
            field
            for field in required
            if not source.get(field)
        ]

        if missing:
            raise SourceValidationError(
                "Source is missing required fields: "
                + ", ".join(missing)
            )

        ai_assessment = source.get(
            "ai_assessment"
        )

        if not isinstance(
            ai_assessment,
            Mapping,
        ):
            raise SourceValidationError(
                "Source ai_assessment must be an object"
            )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def calculate_score(
        self,
        criteria: SourceCriteria,
    ) -> float:
        """
        Calculate weighted source-quality score.
        """

        score = (
            criteria.authority
            * self.weights["authority"]
            + criteria.provenance
            * self.weights["provenance"]
            + criteria.relevance
            * self.weights["relevance"]
            + criteria.freshness
            * self.weights["freshness"]
            + criteria.corroboration
            * self.weights["corroboration"]
        )

        return round(
            score,
            4,
        )

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    @staticmethod
    def classify(
        score: float,
    ) -> SourceClassification:

        if score >= 0.85:
            return SourceClassification.PREFERRED

        if score >= 0.70:
            return SourceClassification.SECONDARY

        if score >= 0.50:
            return SourceClassification.CONTEXT_ONLY

        return SourceClassification.REJECTED

    # ------------------------------------------------------------------
    # Recommendation
    # ------------------------------------------------------------------

    @staticmethod
    def build_recommendation(
        *,
        classification: SourceClassification,
        supports_web2json: bool,
        whitelist_status: str,
        score: float,
    ) -> str:

        supported = whitelist_status.lower() in {
            "supported",
            "whitelisted",
            "demonstration_supported",
        }

        if classification == SourceClassification.REJECTED:
            return (
                f"Reject for decision-grade evidence "
                f"(score={score:.2f})."
            )

        if classification == SourceClassification.CONTEXT_ONLY:
            return (
                "Use for contextual or discovery purposes only; "
                "do not rely on this source alone for settlement."
            )

        if not supports_web2json:
            return (
                "Source quality is acceptable, but this source is "
                "not configured for the current Web2Json workflow."
            )

        if not supported:
            return (
                "Source may be suitable, but it must be "
                "supported/whitelisted before FDC/Web2Json use."
            )

        if classification == SourceClassification.SECONDARY:
            return (
                "Suitable as secondary decision-grade evidence "
                "subject to application policy and corroboration."
            )

        return (
            "Preferred source candidate for the FDC/Web2Json "
            "evidence workflow."
        )

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def analyze(
        self,
        source: Mapping[str, Any],
    ) -> SourceProfile:

        self._validate_source_record(
            source
        )

        assessment = source["ai_assessment"]

        criteria = SourceCriteria(
            authority=float(
                assessment.get(
                    "authority",
                    0.0,
                )
            ),
            provenance=float(
                assessment.get(
                    "provenance",
                    0.0,
                )
            ),
            relevance=float(
                assessment.get(
                    "relevance",
                    0.0,
                )
            ),
            freshness=float(
                assessment.get(
                    "freshness",
                    0.0,
                )
            ),
            corroboration=float(
                assessment.get(
                    "corroboration",
                    0.0,
                )
            ),
        )

        calculated_score = (
            self.calculate_score(criteria)
        )

        classification = self.classify(
            calculated_score
        )

        supports_web2json = bool(
            source.get(
                "supports_web2json",
                False,
            )
        )

        whitelist_status = str(
            source.get(
                "whitelist_status",
                "unknown",
            )
        )

        recommendation = (
            self.build_recommendation(
                classification=classification,
                supports_web2json=(
                    supports_web2json
                ),
                whitelist_status=(
                    whitelist_status
                ),
                score=calculated_score,
            )
        )

        return SourceProfile(
            source_id=str(
                source["source_id"]
            ),
            name=str(
                source["name"]
            ),
            publisher=str(
                source["publisher"]
            ),
            source_type=str(
                source["source_type"]
            ),
            url=str(
                source["url"]
            ),
            criteria=criteria,
            supports_web2json=(
                supports_web2json
            ),
            whitelist_status=(
                whitelist_status
            ),
            classification=classification,
            overall_score=calculated_score,
            recommendation=recommendation,
            source_status=str(
                source.get(
                    "status",
                    "unknown",
                )
            ),
        )

    # ------------------------------------------------------------------
    # Batch analysis
    # ------------------------------------------------------------------

    def analyze_many(
        self,
        sources: Iterable[
            Mapping[str, Any]
        ],
    ) -> List[SourceProfile]:

        return [
            self.analyze(source)
            for source in sources
        ]

    # ------------------------------------------------------------------
    # Ranking
    # ------------------------------------------------------------------

    def rank(
        self,
        sources: Iterable[
            Mapping[str, Any]
        ],
        *,
        policy: Optional[
            SourceSelectionPolicy
        ] = None,
    ) -> List[SourceProfile]:

        policy = (
            policy
            if policy is not None
            else SourceSelectionPolicy()
        )

        profiles = self.analyze_many(
            sources
        )

        eligible = [
            profile
            for profile in profiles
            if self._policy_allows(
                profile,
                policy,
            )
        ]

        eligible.sort(
            key=lambda profile: (
                _CLASSIFICATION_PRIORITY[
                    profile.classification
                ],
                -profile.overall_score,
                profile.source_id,
            )
        )

        return eligible

    # ------------------------------------------------------------------
    # Policy filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _policy_allows(
        profile: SourceProfile,
        policy: SourceSelectionPolicy,
    ) -> bool:

        classification_priority = (
            _CLASSIFICATION_PRIORITY[
                profile.classification
            ]
        )

        minimum_priority = (
            _CLASSIFICATION_PRIORITY[
                policy.minimum_classification
            ]
        )

        if (
            classification_priority
            > minimum_priority
        ):
            return False

        if profile.overall_score < (
            policy.minimum_score
        ):
            return False

        if (
            policy.require_web2json
            and not profile.supports_web2json
        ):
            return False

        if policy.require_supported_source:
            if profile.whitelist_status.lower() not in {
                "supported",
                "whitelisted",
                "demonstration_supported",
            }:
                return False

        return True

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def select(
        self,
        sources: Sequence[
            Mapping[str, Any]
        ],
        *,
        policy: Optional[
            SourceSelectionPolicy
        ] = None,
    ) -> SourceProfile:

        ranked = self.rank(
            sources,
            policy=policy,
        )

        if not ranked:
            raise NoSuitableSourceError(
                "No source satisfies the current "
                "source-selection policy"
            )

        return ranked[0]

    # ------------------------------------------------------------------
    # Source lookup
    # ------------------------------------------------------------------

    @staticmethod
    def find_source(
        sources: Iterable[
            Mapping[str, Any]
        ],
        source_id: str,
    ) -> Mapping[str, Any]:

        for source in sources:
            if (
                str(
                    source.get(
                        "source_id",
                        "",
                    )
                )
                == source_id
            ):
                return source

        raise SourceValidationError(
            f"Source not found: {source_id}"
        )

    # ------------------------------------------------------------------
    # Corroboration
    # ------------------------------------------------------------------

    def build_corroboration_report(
        self,
        profiles: Sequence[
            SourceProfile
        ],
    ) -> Dict[str, Any]:

        if not profiles:
            return {
                "source_count": 0,
                "preferred_count": 0,
                "secondary_count": 0,
                "context_only_count": 0,
                "rejected_count": 0,
                "average_score": 0.0,
                "web2json_supported_count": 0,
            }

        counts = {
            SourceClassification.PREFERRED: 0,
            SourceClassification.SECONDARY: 0,
            SourceClassification.CONTEXT_ONLY: 0,
            SourceClassification.REJECTED: 0,
        }

        web2json_count = 0

        for profile in profiles:
            counts[
                profile.classification
            ] += 1

            if profile.supports_web2json:
                web2json_count += 1

        average_score = (
            sum(
                profile.overall_score
                for profile in profiles
            )
            / len(profiles)
        )

        return {
            "source_count": len(profiles),
            "preferred_count": counts[
                SourceClassification.PREFERRED
            ],
            "secondary_count": counts[
                SourceClassification.SECONDARY
            ],
            "context_only_count": counts[
                SourceClassification.CONTEXT_ONLY
            ],
            "rejected_count": counts[
                SourceClassification.REJECTED
            ],
            "average_score": round(
                average_score,
                4,
            ),
            "web2json_supported_count": (
                web2json_count
            ),
        }


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def analyze_source_registry(
    sources: Iterable[
        Mapping[str, Any]
    ],
) -> List[Dict[str, Any]]:
    """
    Analyze all sources and return serializable results.
    """

    engine = SourceIntelligence()

    profiles = engine.analyze_many(
        sources
    )

    return [
        profile.to_dict()
        for profile in profiles
    ]


def select_fdc_source(
    sources: Sequence[
        Mapping[str, Any]
    ],
) -> Dict[str, Any]:
    """
    Select the highest-ranked source suitable for the current
    FDC/Web2Json workflow.
    """

    engine = SourceIntelligence()

    selected = engine.select(
        sources,
        policy=SourceSelectionPolicy(
            minimum_classification=(
                SourceClassification.SECONDARY
            ),
            require_web2json=True,
            require_supported_source=True,
            require_url_validation=True,
            minimum_score=0.70,
        ),
    )

    return selected.to_dict()


def find_preferred_sources(
    sources: Sequence[
        Mapping[str, Any]
    ],
) -> List[Dict[str, Any]]:
    """
    Return all preferred sources in ranked order.
    """

    engine = SourceIntelligence()

    profiles = engine.rank(
        sources,
        policy=SourceSelectionPolicy(
            minimum_classification=(
                SourceClassification.PREFERRED
            ),
            require_web2json=True,
            require_supported_source=True,
            minimum_score=0.85,
        ),
    )

    return [
        profile.to_dict()
        for profile in profiles
    ]


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------

def main() -> None:
    sources = [
        {
            "source_id": "SRC-001",
            "name": "Official Sports Results API",
            "publisher": (
                "Demonstration Sports Data Provider"
            ),
            "source_type": "sports_results_api",
            "url": (
                "https://example-sports-provider.com/"
                "api/matches/EVT-2026-FINAL-001"
            ),
            "supports_web2json": True,
            "whitelist_status": (
                "demonstration_supported"
            ),
            "status": (
                "eligible_for_fdc_verification"
            ),
            "ai_assessment": {
                "authority": 0.97,
                "provenance": 0.96,
                "relevance": 0.99,
                "freshness": 0.96,
                "corroboration": 0.91,
            },
        },
        {
            "source_id": "SRC-005",
            "name": "Established Sports News Source",
            "publisher": (
                "Demonstration News Organization"
            ),
            "source_type": "news",
            "url": (
                "https://example-news.com/"
                "sports/event/EVT-2026-FINAL-001"
            ),
            "supports_web2json": False,
            "whitelist_status": (
                "not_configured"
            ),
            "status": "contextual",
            "ai_assessment": {
                "authority": 0.83,
                "provenance": 0.88,
                "relevance": 0.87,
                "freshness": 0.94,
                "corroboration": 0.79,
            },
        },
        {
            "source_id": "SRC-007",
            "name": "Unverified Social Media Post",
            "publisher": "Unknown User",
            "source_type": "social_media",
            "url": (
                "https://social.example.com/"
                "posts/EVT-2026-FINAL-001"
            ),
            "supports_web2json": False,
            "whitelist_status": (
                "not_configured"
            ),
            "status": "rejected",
            "ai_assessment": {
                "authority": 0.17,
                "provenance": 0.29,
                "relevance": 0.54,
                "freshness": 0.89,
                "corroboration": 0.12,
            },
        },
    ]

    engine = SourceIntelligence()

    profiles = engine.analyze_many(
        sources
    )

    print("PREDICTRESOLVE — SOURCE INTELLIGENCE")
    print("=" * 72)

    for profile in profiles:
        print(
            f"{profile.source_id} | "
            f"{profile.name}"
        )
        print(
            f"  Classification : "
            f"{profile.classification.value}"
        )
        print(
            f"  Score          : "
            f"{profile.overall_score:.3f}"
        )
        print(
            f"  Web2Json       : "
            f"{profile.supports_web2json}"
        )
        print(
            f"  Supported      : "
            f"{profile.whitelist_status}"
        )
        print(
            f"  Recommendation : "
            f"{profile.recommendation}"
        )
        print()

    print("=" * 72)
    print("FDC SOURCE SELECTION")
    print("=" * 72)

    try:
        selected = engine.select(
            sources
        )

        print(
            f"Selected source: "
            f"{selected.name}"
        )

        print(
            f"Score: "
            f"{selected.overall_score:.3f}"
        )

        print(
            f"Classification: "
            f"{selected.classification.value}"
        )

    except NoSuitableSourceError as exc:
        print(
            f"No suitable FDC source: {exc}"
        )

    print("\nCORROBORATION REPORT")
    print("=" * 72)

    print(
        json.dumps(
            engine.build_corroboration_report(
                profiles
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
