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

    event RelayFeedUpdated(
        uint256 indexed feedIndex,
        int256 value,
        uint256 timestamp,
        uint256 atBlock
    );

    event TreasurySweep(address indexed token, address indexed to, uint256 amount, uint256 atBlock);

    event RelayRotated(address indexed previousRelay, address indexed newRelay, uint256 atBlock);

    event EpochAdvanced(uint256 indexed previousEpoch, uint256 newEpoch, uint256 atBlock);

    event GuardianPauseToggled(bool paused, uint256 atBlock);

    event BandCapSet(uint256 previousCap, uint256 newCap, uint256 atBlock);

    event AnalystWhitelistSet(address indexed analyst, bool allowed, uint256 atBlock);

    event StaleWindowSet(uint256 previousWindow, uint256 newWindow, uint256 atBlock);

    event FeeBpsSet(uint256 previousBps, uint256 newBps, uint256 atBlock);

    event FallbackReceiverSet(address indexed previous, address indexed current, uint256 atBlock);

    // -------------------------------------------------------------------------
    // ERRORS
    // -------------------------------------------------------------------------

    error J0R_NotRelay();
    error J0R_NotGuardian();
    error J0R_NotAnalyst();
    error J0R_ZeroAddress();
    error J0R_ZeroAmount();
    error J0R_BandNotFound();
    error J0R_BandInactive();
    error J0R_BandBoundsInvalid();
    error J0R_SessionExpired();
    error J0R_SessionNotOpen();
    error J0R_StaleFeed();
    error J0R_DirectionInvalid();
    error J0R_CapExceeded();
    error J0R_EpochNotAdvanced();
    error J0R_TransferFailed();
    error J0R_ArrayLengthMismatch();
    error J0R_EmptyArray();
    error J0R_Reentrancy();
    error J0R_Paused();
    error J0R_FeeBpsTooHigh();
    error J0R_StaleWindowTooLarge();

    // -------------------------------------------------------------------------
    // CONSTANTS
    // -------------------------------------------------------------------------

    uint256 public constant JER0ME_VERSION = 2;
    bytes32 public constant JER0ME_NAMESPACE = keccak256("Jer0me.fed.v2");
    uint256 public constant BPS_DENOMINATOR = 10_000;
    uint256 public constant MAX_FEE_BPS = 500;
    uint256 public constant MAX_STALE_BLOCKS = 200;
    uint256 public constant MIN_BAND_GAP = 1;
    uint256 public constant MAX_BANDS_DEFAULT = 64;
    uint256 public constant VOTE_DIRECTION_HOLD = 0;
    uint256 public constant VOTE_DIRECTION_UP = 1;
    uint256 public constant VOTE_DIRECTION_DOWN = 2;
    uint256 public constant SESSION_DURATION_BLOCKS = 150;
    uint256 public constant MAX_FEEDS = 16;
    uint256 public constant BATCH_SIGNALS_MAX = 32;
    uint256 public constant EPOCH_BLOCKS = 2016;

