// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title TrustReceiptRegistry
 * @notice
 *   On-chain registry for PredictResolve Trust Receipts.
 *
 *   A Trust Receipt preserves the provenance of a prediction resolution:
 *
 *   External evidence
 *        +
 *   FDC attestation reference
 *        +
 *   TEE resolution attestation reference
 *        +
 *   Resolution rule
 *        +
 *   Settlement result
 *        +
 *   Settlement transaction reference
 *        ↓
 *      Trust Receipt
 *        ↓
 *   Cryptographic commitment
 *
 *   IMPORTANT
 *   ---------
 *   Private prediction terms, odds, participant strategy and other sensitive
 *   inputs are NOT stored in this contract.
 *
 *   The detailed receipt may remain encrypted off-chain while this registry
 *   stores its cryptographic commitment and non-sensitive provenance.
 *
 *   This contract does not implement FDC or Confidential Compute attestation
 *   verification itself. It records references/commitments after the relevant
 *   verification boundary has been satisfied by the application.
 */
contract TrustReceiptRegistry {
    // ---------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------

    error ZeroAddress();
    error InvalidReceiptId();
    error InvalidPredictionId();
    error InvalidCommitment();
    error ReceiptAlreadyExists();
    error ReceiptNotFound();
    error UnauthorizedIssuer();
    error InvalidVersion();
    error InvalidState();
    error PreviousReceiptMismatch();

    // ---------------------------------------------------------------------
    // Enums
    // ---------------------------------------------------------------------

    enum ReceiptState {
        Active,
        Superseded,
        Cancelled
    }

    // ---------------------------------------------------------------------
    // Structs
    // ---------------------------------------------------------------------

    struct TrustReceipt {
        // Unique receipt identifier.
        bytes32 receiptId;

        // Prediction/event to which the receipt belongs.
        bytes32 predictionId;

        // Event that generated the resolution.
        bytes32 eventId;

        // Commitment to the FDC evidence set / normalized evidence.
        bytes32 evidenceCommitment;

        // Reference to the FDC attestation.
        bytes32 fdcAttestationId;

        // Reference to the TEE attestation.
        bytes32 teeAttestationId;

        // Commitment to the confidential resolution result.
        bytes32 resolutionCommitment;

        // Commitment to the final settlement state.
        bytes32 settlementCommitment;

        // Full receipt commitment.
        bytes32 receiptCommitment;

        // Non-sensitive reference to encrypted protected receipt storage.
        string encryptedReceiptReference;

        // Receipt version.
        uint32 version;

        // Previous receipt in the same prediction history.
        bytes32 previousReceiptId;

        // Address that registered the receipt.
        address issuer;

        ReceiptState state;

        uint64 createdAt;
        uint64 supersededAt;
    }

    // ---------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------

    mapping(bytes32 => TrustReceipt) private receipts;

    mapping(bytes32 => bool) public receiptExists;

    // Latest receipt for each prediction.
    mapping(bytes32 => bytes32) public latestReceiptForPrediction;

    // Optional application-level access registry.
    //
    // IMPORTANT:
    // This mapping does not make blockchain data private. It only represents
    // an enterprise/application authorization state. Actual confidentiality
    // must be enforced through encrypted storage and key management.
    mapping(bytes32 => mapping(address => bool))
        public authorizedViewers;

    // ---------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------

    event TrustReceiptRegistered(
        bytes32 indexed receiptId,
        bytes32 indexed predictionId,
        bytes32 indexed receiptCommitment,
        uint32 version,
        address issuer,
        uint256 timestamp
    );

    event TrustReceiptSuperseded(
        bytes32 indexed previousReceiptId,
        bytes32 indexed newReceiptId,
        bytes32 indexed predictionId,
        uint256 timestamp
    );

    event TrustReceiptCancelled(
        bytes32 indexed receiptId,
        bytes32 indexed predictionId,
        address indexed cancelledBy,
        uint256 timestamp
    );

    event ViewerAuthorizationChanged(
        bytes32 indexed receiptId,
        address indexed viewer,
        bool authorized
    );

    // ---------------------------------------------------------------------
    // Receipt Registration
    // ---------------------------------------------------------------------

    /**
     * @notice Register a new Trust Receipt.
     *
     * @param receiptId Unique receipt identifier.
     * @param predictionId Associated PredictResolve prediction.
     * @param eventId Associated real-world event.
     * @param evidenceCommitment Commitment to normalized verified evidence.
     * @param fdcAttestationId Reference to the FDC attestation.
     * @param teeAttestationId Reference to the TEE attestation.
     * @param resolutionCommitment Commitment to the confidential resolution.
     * @param settlementCommitment Commitment to the settlement result/state.
     * @param receiptCommitment Commitment to the complete protected receipt.
     * @param encryptedReceiptReference Non-sensitive storage reference.
     * @param version Receipt version.
     * @param previousReceiptId Previous receipt; zero for first version.
     */
    function registerReceipt(
        bytes32 receiptId,
        bytes32 predictionId,
        bytes32 eventId,
        bytes32 evidenceCommitment,
        bytes32 fdcAttestationId,
        bytes32 teeAttestationId,
        bytes32 resolutionCommitment,
        bytes32 settlementCommitment,
        bytes32 receiptCommitment,
        string calldata encryptedReceiptReference,
        uint32 version,
        bytes32 previousReceiptId
    ) external {
        if (receiptId == bytes32(0)) {
            revert InvalidReceiptId();
        }

        if (predictionId == bytes32(0)) {
            revert InvalidPredictionId();
        }

        if (eventId == bytes32(0)) {
            revert InvalidPredictionId();
        }

        if (evidenceCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }

        if (fdcAttestationId == bytes32(0)) {
            revert InvalidCommitment();
        }

        if (teeAttestationId == bytes32(0)) {
            revert InvalidCommitment();
        }

        if (resolutionCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }

        if (settlementCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }

        if (receiptCommitment == bytes32(0)) {
            revert InvalidCommitment();
        }

        if (version == 0) {
            revert InvalidVersion();
        }

        if (receiptExists[receiptId]) {
            revert ReceiptAlreadyExists();
        }

        // If this is a subsequent version, make sure the previous receipt
        // belongs to the same prediction.
        if (previousReceiptId != bytes32(0)) {
            if (!receiptExists[previousReceiptId]) {
                revert ReceiptNotFound();
            }

            if (
                receipts[previousReceiptId].predictionId
                    != predictionId
            ) {
                revert PreviousReceiptMismatch();
            }
        }

        receipts[receiptId] = TrustReceipt({
            receiptId: receiptId,
            predictionId: predictionId,
            eventId: eventId,
            evidenceCommitment: evidenceCommitment,
            fdcAttestationId: fdcAttestationId,
            teeAttestationId: teeAttestationId,
            resolutionCommitment: resolutionCommitment,
            settlementCommitment: settlementCommitment,
            receiptCommitment: receiptCommitment,
            encryptedReceiptReference: encryptedReceiptReference,
            version: version,
            previousReceiptId: previousReceiptId,
            issuer: msg.sender,
            state: ReceiptState.Active,
            createdAt: uint64(block.timestamp),
            supersededAt: 0
        });

        receiptExists[receiptId] = true;

        // If the prediction already has an active receipt, supersede it.
        bytes32 previousLatest =
            latestReceiptForPrediction[predictionId];

        if (previousLatest != bytes32(0)) {
            TrustReceipt storage oldReceipt =
                receipts[previousLatest];

            oldReceipt.state = ReceiptState.Superseded;
            oldReceipt.supersededAt = uint64(block.timestamp);

            emit TrustReceiptSuperseded(
                previousLatest,
                receiptId,
                predictionId,
                block.timestamp
            );
        }

        latestReceiptForPrediction[predictionId] =
            receiptId;

        emit TrustReceiptRegistered(
            receiptId,
            predictionId,
            receiptCommitment,
            version,
            msg.sender,
            block.timestamp
        );
    }

    // ---------------------------------------------------------------------
    // Receipt Cancellation
    // ---------------------------------------------------------------------

    /**
     * @notice Cancel a receipt without deleting the historical record.
     *
     * Cancellation changes the state; it does not erase the receipt.
     */
    function cancelReceipt(
        bytes32 receiptId
    ) external {
        TrustReceipt storage receipt =
            _getReceipt(receiptId);

        if (msg.sender != receipt.issuer) {
            revert UnauthorizedIssuer();
        }

        if (receipt.state != ReceiptState.Active) {
            revert InvalidState();
        }

        receipt.state = ReceiptState.Cancelled;

        emit TrustReceiptCancelled(
            receiptId,
            receipt.predictionId,
            msg.sender,
            block.timestamp
        );
    }

    // ---------------------------------------------------------------------
    // Viewer Authorization
    // ---------------------------------------------------------------------

    /**
     * @notice Record application-level authorization for access to a
     * protected receipt.
     *
     * This does NOT make the receipt private on-chain.
     *
     * Actual privacy must be implemented using encrypted storage and
     * secure key management.
     */
    function setViewerAuthorization(
        bytes32 receiptId,
        address viewer,
        bool authorized
    ) external {
        TrustReceipt storage receipt =
            _getReceipt(receiptId);

        if (msg.sender != receipt.issuer) {
            revert UnauthorizedIssuer();
        }

        if (viewer == address(0)) {
            revert ZeroAddress();
        }

        authorizedViewers[receiptId][viewer] =
            authorized;

        emit ViewerAuthorizationChanged(
            receiptId,
            viewer,
            authorized
        );
    }

    function isAuthorizedViewer(
        bytes32 receiptId,
        address viewer
    ) external view returns (bool) {
        _getReceipt(receiptId);

        return authorizedViewers[receiptId][viewer];
    }

    // ---------------------------------------------------------------------
    // Commitment Verification
    // ---------------------------------------------------------------------

    /**
     * @notice Verify the complete protected receipt against its on-chain
     *         commitment.
     */
    function verifyReceiptCommitment(
        bytes32 receiptId,
        bytes32 suppliedCommitment
    ) external view returns (bool) {
        return
            _getReceipt(receiptId).receiptCommitment
                == suppliedCommitment;
    }

    /**
     * @notice Verify the evidence commitment.
     */
    function verifyEvidenceCommitment(
        bytes32 receiptId,
        bytes32 suppliedCommitment
    ) external view returns (bool) {
        return
            _getReceipt(receiptId).evidenceCommitment
                == suppliedCommitment;
    }

    /**
     * @notice Verify the confidential resolution commitment.
     */
    function verifyResolutionCommitment(
        bytes32 receiptId,
        bytes32 suppliedCommitment
    ) external view returns (bool) {
        return
            _getReceipt(receiptId).resolutionCommitment
                == suppliedCommitment;
    }

    /**
     * @notice Verify the settlement commitment.
     */
    function verifySettlementCommitment(
        bytes32 receiptId,
        bytes32 suppliedCommitment
    ) external view returns (bool) {
        return
            _getReceipt(receiptId).settlementCommitment
                == suppliedCommitment;
    }

    // ---------------------------------------------------------------------
    // Read Functions
    // ---------------------------------------------------------------------

    /**
     * @notice Return the public receipt metadata.
     *
     * Sensitive receipt content is deliberately not stored or returned here.
     */
    function getReceipt(
        bytes32 receiptId
    )
        external
        view
        returns (TrustReceipt memory)
    {
        return _getReceipt(receiptId);
    }

    /**
     * @notice Return the latest Trust Receipt for a prediction.
     */
    function getLatestReceipt(
        bytes32 predictionId
    ) external view returns (bytes32) {
        return latestReceiptForPrediction[predictionId];
    }

    function getReceiptState(
        bytes32 receiptId
    ) external view returns (ReceiptState) {
        return _getReceipt(receiptId).state;
    }

    // ---------------------------------------------------------------------
    // Internal Helpers
    // ---------------------------------------------------------------------

    function _getReceipt(
        bytes32 receiptId
    )
        internal
        view
        returns (TrustReceipt storage receipt)
    {
        if (!receiptExists[receiptId]) {
            revert ReceiptNotFound();
        }

        return receipts[receiptId];
    }
}
