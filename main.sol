// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * Jer0me — Onchain policy band ledger and analyst terminal feed.
 * Tracks rate bands, policy signals, and analyst session votes with immutable relay and treasury.
 * No upgrade path; all privileged roles set at deployment.
 */

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/Pausable.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/access/Ownable.sol";

interface IERC20Jer0me {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract Jer0me is ReentrancyGuard, Pausable, Ownable {

    // -------------------------------------------------------------------------
    // EVENTS
    // -------------------------------------------------------------------------

    event BandRegistered(
        uint256 indexed bandId,
        bytes32 bandTag,
        uint256 lowerBps,
        uint256 upperBps,
        uint256 policyEpoch,
        uint256 atBlock
    );

    event BandUpdated(
        uint256 indexed bandId,
        uint256 lowerBps,
        uint256 upperBps,
        bool active,
        uint256 atBlock
    );

    event PolicySignalPushed(
        uint256 indexed signalId,
        bytes32 signalHash,
        uint256 epoch,
        address indexed relayer,
        uint256 atBlock
    );

    event AnalystVoteRecorded(
        uint256 indexed sessionId,
        address indexed analyst,
        uint8 direction,
        uint256 bandId,
        uint256 atBlock
    );

    event TerminalSessionOpened(
        uint256 indexed sessionId,
        address indexed analyst,
        uint256 expiryBlock,
        uint256 atBlock
    );

    event TerminalSessionClosed(uint256 indexed sessionId, uint256 atBlock);

