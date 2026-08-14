// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PredictResolveSettlement
 * @notice
 *   Prototype settlement contract for PredictResolve.
 *
 *   Product lifecycle:
 *
 *   Private prediction / odds / settlement terms
 *                    +
 *             FDC-verified outcome
 *                    ↓
 *            Confidential TEE
 *                    ↓
 *             TEE attestation
 *                    ↓
 *          this settlement contract
 *                    ↓
 *                FXRP payout
 *
 *   IMPORTANT:
 *   This contract does not implement the Flare Confidential Compute TEE
 *   attestation protocol itself.
 *
 *   A production deployment should connect `attestationVerifier` to the
 *   appropriate Flare Confidential Compute verification mechanism.
 *
 *   For the prototype, the verifier boundary is represented by an
 *   authorized attestation verifier address.
 *
 *   The contract intentionally does NOT store:
 *   - private odds
 *   - private user strategy
 *   - confidential settlement parameters
 *   - encrypted receipt contents
 *
 *   The chain stores only the information required to enforce and preserve
 *   the settlement state.
 */
contract PredictResolveSettlement {
    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error PredictionAlreadyExists();
    error PredictionNotFound();
    error InvalidPredictionId();
    error InvalidParticipant();
    error InvalidAsset();
    error InvalidAmount();
    error InvalidOdds();
    error InvalidAttestation();
    error UnauthorizedVerifier();
    error UnauthorizedParticipant();
    error InvalidState();
    error SettlementAlreadyProcessed();
    error SettlementNotYetAllowed();
    error TransferFailed();
    error InvalidReceiptCommitment();
    error InvalidDecisionCommitment();
    error InvalidExpiry();
    error PredictionExpired();
    error ZeroAddress();

    // ---------------------------------------------------------------------
    // Enums
    // ---------------------------------------------------------------------

    enum PredictionState {
        Created,
        Verifying,
        Resolved,
        Settled,
        Cancelled
    }

    enum Outcome {
        Unknown,
        Win,
        Loss,
        Refund
    }

    // ---------------------------------------------------------------------
    // Structs
    // ---------------------------------------------------------------------

    struct Prediction {
        bytes32 predictionId;

        // Participant receiving the settlement.
        address participant;

        // Settlement asset, intended to be FXRP in the deployed system.
        address settlementAsset;

        // Amount locked for the prediction.
        uint256 stake;

        // Public reference to the event. This should not contain confidential
        // prediction details.
        bytes32 eventId;

        // Hash/commitment to the private prediction terms.
        //
        // Example private payload:
        // prediction side + odds + stake + settlement rules
        bytes32 termsCommitment;

        // Hash/commitment representing the approved settlement policy/rules.
        bytes32 ruleCommitment;

        // Trust Receipt commitment.
        bytes32 trustReceiptCommitment;

        // Attested resolution commitment.
        bytes32 resolutionCommitment;

        PredictionState state;

        Outcome outcome;

        // Final payout determined by the confidential computation.
        uint256 payout;

        // Optional deadline for resolution.
        uint64 expiry;

        uint64 createdAt;
        uint64 resolvedAt;
        uint64 settledAt;
    }

    struct Resolution {
        bytes32 predictionId;

        Outcome outcome;

        uint256 payout;

        // Commitment to the confidential resolution result.
        bytes32 resolutionCommitment;

        // Commitment to the Trust Receipt.
        bytes32 trustReceiptCommitment;

        // Identifier/reference supplied by the TEE/FCC verifier.
        bytes32 attestationId;

        uint64 resolvedAt;
    }

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    mapping(bytes32 => Prediction) private predictions;

    mapping(bytes32 => bool) public predictionExists;

    // Addresses allowed to submit an already verified TEE result.
    mapping(address => bool) public authorizedAttestationVerifiers;

    // Address of the configured settlement asset.
    //
    // In a test deployment this can be the appropriate FXRP token contract.
    address public immutable settlementAsset;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event PredictionCreated(
        bytes32 indexed predictionId,
        bytes32 indexed eventId,
        address indexed participant,
        address settlementAsset,
        uint256 stake,
        bytes32 termsCommitment,
        bytes32 ruleCommitment,
        uint256 timestamp
    );

    event PredictionStateChanged(
        bytes32 indexed predictionId,
        PredictionState previousState,
        PredictionState newState,
        uint256 timestamp
    );

    event ResolutionAttested(
        bytes32 indexed predictionId,
        Outcome outcome,
        uint256 payout,
        bytes32 indexed resolutionCommitment,
        bytes32 indexed trustReceiptCommitment,
        bytes32 attestationId,
        address verifier,
        uint256 timestamp
    );

    event SettlementExecuted(
        bytes32 indexed predictionId,
        address indexed participant,
        address indexed settlementAsset,
        uint256 payout,
        bytes32 trustReceiptCommitment,
        uint256 timestamp
    );

    event AttestationVerifierAuthorizationChanged(
        address indexed verifier,
        bool authorized
    );

    // ---------------------------------------------------------------------
    // Constructor
    // ---------------------------------------------------------------------

    constructor(
        address settlementAsset_,
        address initialVerifier
    ) {
        if (settlementAsset_ == address(0)) {
            revert ZeroAddress();
        }

        settlementAsset = settlementAsset_;

        if (initialVerifier != address(0)) {
            authorizedAttestationVerifiers[initialVerifier] = true;

            emit AttestationVerifierAuthorizationChanged(
                initialVerifier,
                true
            );
        }
    }

    // ---------------------------------------------------------------------
    // Admin / verifier configuration
    // ---------------------------------------------------------------------

    /**
     * @notice
     *   Authorize or revoke an address that is permitted to submit
     *   already-verified TEE resolution results.
     *
     *   NOTE:
     *   This prototype uses a simple authorization mapping.
     *   Production governance should replace this with explicit
     *   administrator / multisig / protocol governance.
     */
    function setAttestationVerifier(
        address verifier,
        bool authorized
    ) external {
        if (verifier == address(0)) {
            revert ZeroAddress();
        }

        authorizedAttestationVerifiers[verifier] = authorized;

        emit AttestationVerifierAuthorizationChanged(
            verifier,
            authorized
        );
    }

    // ---------------------------------------------------------------------
    // Prediction creation
    // ---------------------------------------------------------------------

    /**
     * @notice
     *   Create a prediction position.
     *
     *   The private prediction terms are represented only by a commitment.
     *   No private odds or strategy details are written to the public chain.
     *
     *   The prototype does not transfer the stake here. A production version
     *   can integrate an FXRP escrow/allowance flow.
     */
    function createPrediction(
        bytes32 predictionId,
        bytes32 eventId,
        uint256 stake,
        bytes32 termsCommitment,
        bytes32 ruleCommitment,
        uint64 expiry
    ) external {
        if (predictionId == bytes32(0)) {
            revert InvalidPredictionId();
        }

        if (predictionExists[predictionId]) {
            revert PredictionAlreadyExists();
        }

        if (eventId == bytes32(0)) {
            revert InvalidPredictionId();
        }

        if (stake == 0) {
            revert InvalidAmount();
        }

        if (termsCommitment == bytes32(0)) {
            revert InvalidOdds();
        }

        if (ruleCommitment == bytes32(0)) {
            revert InvalidDecisionCommitment();
        }

        if (
            expiry != 0 &&
            expiry <= block.timestamp
        ) {
            revert InvalidExpiry();
        }

        predictions[predictionId] = Prediction({
            predictionId: predictionId,
            participant: msg.sender,
            settlementAsset: settlementAsset,
            stake: stake,
            eventId: eventId,
            termsCommitment: termsCommitment,
            ruleCommitment: ruleCommitment,
            trustReceiptCommitment: bytes32(0),
            resolutionCommitment: bytes32(0),
            state: PredictionState.Created,
            outcome: Outcome.Unknown,
            payout: 0,
            expiry: expiry,
            createdAt: uint64(block.timestamp),
            resolvedAt: 0,
            settledAt: 0
        });

        predictionExists[predictionId] = true;

        emit PredictionCreated(
            predictionId,
            eventId,
            msg.sender,
            settlementAsset,
            stake,
            termsCommitment,
            ruleCommitment,
            block.timestamp
        );
    }

    // ---------------------------------------------------------------------
    // Resolution preparation
    // ---------------------------------------------------------------------

    /**
     * @notice
     *   Move a prediction into the confidential-resolution stage.
     *
     *   This is intentionally separate from resolution submission.
     */
    function beginResolution(
        bytes32 predictionId
    ) external {
        Prediction storage prediction = _getPrediction(predictionId);

        if (msg.sender != prediction.participant) {
            revert UnauthorizedParticipant();
        }

        if (prediction.state != PredictionState.Created) {
            revert InvalidState();
        }

        if (
            prediction.expiry != 0 &&
            block.timestamp > prediction.expiry
        ) {
            revert PredictionExpired();
        }

        PredictionState previous = prediction.state;

        prediction.state = PredictionState.Verifying;

        emit PredictionStateChanged(
            predictionId,
            previous,
            prediction.state,
            block.timestamp
        );
    }

    // ---------------------------------------------------------------------
    // TEE attested resolution
    // ---------------------------------------------------------------------

    /**
     * @notice
     *   Record a resolution result after the TEE/FCC attestation has been
     *   verified by an authorized verifier.
     *
     *   The contract does NOT recompute the private odds or private rules.
     *   It enforces the attested result submitted by the configured verifier.
     *
     *   A production implementation should replace the verifier mapping
     *   with the appropriate Flare Confidential Compute verification flow.
     */
    function submitResolution(
        bytes32 predictionId,
        Outcome outcome,
        uint256 payout,
        bytes32 resolutionCommitment,
        bytes32 trustReceiptCommitment,
        bytes32 attestationId
    ) external {
        Prediction storage prediction = _getPrediction(predictionId);

        if (
            !authorizedAttestationVerifiers[msg.sender]
        ) {
            revert UnauthorizedVerifier();
        }

        if (prediction.state != PredictionState.Verifying) {
            revert InvalidState();
        }

        if (outcome == Outcome.Unknown) {
            revert InvalidAttestation();
        }

        if (
            resolutionCommitment == bytes32(0)
        ) {
            revert InvalidAttestation();
        }

        if (
            trustReceiptCommitment == bytes32(0)
        ) {
            revert InvalidReceiptCommitment();
        }

        if (attestationId == bytes32(0)) {
            revert InvalidAttestation();
        }

        // Basic payout invariant:
        //
        // A LOSS should not result in a positive payout.
        //
        // A REFUND may return the original stake or another explicitly
        // permitted amount.
        //
        // A WIN may have a positive payout.
        if (
            outcome == Outcome.Loss &&
            payout != 0
        ) {
            revert InvalidAmount();
        }

        if (
            outcome == Outcome.Refund &&
            payout != prediction.stake
        ) {
            revert InvalidAmount();
        }

        PredictionState previous = prediction.state;

        prediction.resolutionCommitment =
            resolutionCommitment;

        prediction.trustReceiptCommitment =
            trustReceiptCommitment;

        prediction.outcome = outcome;

        prediction.payout = payout;

        prediction.resolvedAt =
            uint64(block.timestamp);

        prediction.state =
            PredictionState.Resolved;

        emit ResolutionAttested(
            predictionId,
            outcome,
            payout,
            resolutionCommitment,
            trustReceiptCommitment,
            attestationId,
            msg.sender,
            block.timestamp
        );

        emit PredictionStateChanged(
            predictionId,
            previous,
            prediction.state,
            block.timestamp
        );
    }

    // ---------------------------------------------------------------------
    // Settlement
    // ---------------------------------------------------------------------

    /**
     * @notice
     *   Execute an already resolved settlement.
     *
     *   In this prototype, the contract expects the settlement asset to
     *   already be available to the contract.
     *
     *   A production implementation should add an explicit funding/escrow
     *   mechanism, such as:
     *
     *   participant / operator
     *        ↓
     *   FXRP transferFrom(...)
     *        ↓
     *   settlement contract
     *
     *   before this function can pay out.
     */
    function settle(
        bytes32 predictionId
    ) external {
        Prediction storage prediction = _getPrediction(predictionId);

        if (prediction.state != PredictionState.Resolved) {
            revert InvalidState();
        }

        if (prediction.payout == 0) {
            // A zero-payout resolution can still be marked settled.
            // This is useful for losses.
        }

        PredictionState previous = prediction.state;

        prediction.state = PredictionState.Settled;
        prediction.settledAt = uint64(block.timestamp);

        if (prediction.payout > 0) {
            _transferSettlementAsset(
                prediction.participant,
                prediction.payout
            );
        }

        emit SettlementExecuted(
            predictionId,
            prediction.participant,
            settlementAsset,
            prediction.payout,
            prediction.trustReceiptCommitment,
            block.timestamp
        );

        emit PredictionStateChanged(
            predictionId,
            previous,
            prediction.state,
            block.timestamp
        );
    }

    // ---------------------------------------------------------------------
    // Cancellation
    // ---------------------------------------------------------------------

    /**
     * @notice
     *   Cancel a prediction before resolution.
     *
     *   The historical record remains on-chain.
     */
    function cancelPrediction(
        bytes32 predictionId
    ) external {
        Prediction storage prediction = _getPrediction(predictionId);

        if (msg.sender != prediction.participant) {
            revert UnauthorizedParticipant();
        }

        if (
            prediction.state != PredictionState.Created &&
            prediction.state != PredictionState.Verifying
        ) {
            revert InvalidState();
        }

        PredictionState previous = prediction.state;

        prediction.state = PredictionState.Cancelled;

        emit PredictionStateChanged(
            predictionId,
            previous,
            prediction.state,
            block.timestamp
        );
    }

    // ---------------------------------------------------------------------
    // Read functions
    // ---------------------------------------------------------------------

    /**
     * @notice Return public prediction metadata.
     *
     * Private odds / prediction terms are deliberately not stored directly.
     */
    function getPrediction(
        bytes32 predictionId
    )
        external
        view
        returns (Prediction memory)
    {
        return _getPrediction(predictionId);
    }

    function getPredictionState(
        bytes32 predictionId
    )
        external
        view
        returns (PredictionState)
    {
        return _getPrediction(predictionId).state;
    }

    function getOutcome(
        bytes32 predictionId
    )
        external
        view
        returns (
            Outcome outcome,
            uint256 payout,
            bytes32 resolutionCommitment,
            bytes32 trustReceiptCommitment
        )
    {
        Prediction storage prediction =
            _getPrediction(predictionId);

        return (
            prediction.outcome,
            prediction.payout,
            prediction.resolutionCommitment,
            prediction.trustReceiptCommitment
        );
    }

    /**
     * @notice Verify the stored Trust Receipt commitment.
     */
    function verifyTrustReceipt(
        bytes32 predictionId,
        bytes32 suppliedCommitment
    ) external view returns (bool) {
        return
            _getPrediction(predictionId)
                .trustReceiptCommitment ==
            suppliedCommitment;
    }

    /**
     * @notice Verify the stored resolution commitment.
     */
    function verifyResolutionCommitment(
        bytes32 predictionId,
        bytes32 suppliedCommitment
    ) external view returns (bool) {
        return
            _getPrediction(predictionId)
                .resolutionCommitment ==
            suppliedCommitment;
    }

    // ---------------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------------

    function _getPrediction(
        bytes32 predictionId
    )
        internal
        view
        returns (Prediction storage prediction)
    {
        if (!predictionExists[predictionId]) {
            revert PredictionNotFound();
        }

        return predictions[predictionId];
    }

    /**
     * @dev Minimal ERC-20 style settlement transfer.
     *
     * The configured `settlementAsset` must expose:
     *
     *   transfer(address,uint256)
     *
     * A production implementation should use a standard SafeERC20 library.
     */
    function _transferSettlementAsset(
        address recipient,
        uint256 amount
    ) internal {
        (bool success, bytes memory data) =
            settlementAsset.call(
                abi.encodeWithSignature(
                    "transfer(address,uint256)",
                    recipient,
                    amount
                )
            );

        if (!success) {
            revert TransferFailed();
        }

        // ERC-20 contracts normally return bool. Some tokens return no data.
        if (
            data.length > 0 &&
            !abi.decode(data, (bool))
        ) {
            revert TransferFailed();
        }
    }
}
