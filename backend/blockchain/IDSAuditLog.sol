// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * IDSAuditLog.sol
 * ===============
 * Smart contract for tamper-proof intrusion detection audit logging.
 * Deployed on local Ganache Ethereum network.
 */
contract IDSAuditLog {

    address public owner;
    uint256 public alertCount;

    struct Alert {
        uint256 alertId;
        string  attackCategory;
        string  severity;
        string  sourceIp;
        string  destinationIp;
        uint256 confidence;       // stored as integer e.g. 7879 = 78.79%
        string  topFeatures;      // JSON string of top 3 SHAP features
        uint256 timestamp;
        bool    exists;
    }

    // alertId => Alert
    mapping(uint256 => Alert) public alerts;

    // all alert IDs in order
    uint256[] public alertIds;

    // Events
    event AlertLogged(
        uint256 indexed alertId,
        string  attackCategory,
        string  severity,
        string  sourceIp,
        uint256 confidence,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor() {
        owner      = msg.sender;
        alertCount = 0;
    }

    /**
     * Log a new intrusion alert to the blockchain.
     */
    function logAlert(
        uint256 alertId,
        string  memory attackCategory,
        string  memory severity,
        string  memory sourceIp,
        string  memory destinationIp,
        uint256 confidence,
        string  memory topFeatures
    ) public onlyOwner returns (bool) {
        require(!alerts[alertId].exists, "Alert ID already logged");

        alerts[alertId] = Alert({
            alertId:         alertId,
            attackCategory:  attackCategory,
            severity:        severity,
            sourceIp:        sourceIp,
            destinationIp:   destinationIp,
            confidence:      confidence,
            topFeatures:     topFeatures,
            timestamp:       block.timestamp,
            exists:          true
        });

        alertIds.push(alertId);
        alertCount++;

        emit AlertLogged(
            alertId,
            attackCategory,
            severity,
            sourceIp,
            confidence,
            block.timestamp
        );

        return true;
    }

    /**
     * Retrieve a single alert by ID.
     */
    function getAlert(uint256 alertId) public view returns (
        uint256 id,
        string  memory attackCategory,
        string  memory severity,
        string  memory sourceIp,
        string  memory destinationIp,
        uint256 confidence,
        string  memory topFeatures,
        uint256 timestamp
    ) {
        require(alerts[alertId].exists, "Alert not found");
        Alert memory a = alerts[alertId];
        return (
            a.alertId,
            a.attackCategory,
            a.severity,
            a.sourceIp,
            a.destinationIp,
            a.confidence,
            a.topFeatures,
            a.timestamp
        );
    }

    /**
     * Get total number of logged alerts.
     */
    function getAlertCount() public view returns (uint256) {
        return alertCount;
    }

    /**
     * Get all alert IDs.
     */
    function getAllAlertIds() public view returns (uint256[] memory) {
        return alertIds;
    }

    /**
     * Verify an alert exists on chain.
     */
    function verifyAlert(uint256 alertId) public view returns (bool) {
        return alerts[alertId].exists;
    }
}
