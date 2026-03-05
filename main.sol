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

    // -------------------------------------------------------------------------
    // IMMUTABLES
    // -------------------------------------------------------------------------

    address public immutable relay;
    address public immutable guardian;
    address public immutable treasury;
    address public immutable fallbackReceiver;

    // -------------------------------------------------------------------------
    // STATE
    // -------------------------------------------------------------------------

    struct RateBand {
        bytes32 bandTag;
        uint256 lowerBps;
        uint256 upperBps;
        uint256 policyEpoch;
        uint256 registeredAtBlock;
        bool active;
    }

    struct PolicySignal {
        bytes32 signalHash;
        uint256 epoch;
        address relayer;
        uint256 atBlock;
    }

    struct AnalystVote {
        uint8 direction;
        uint256 bandId;
        uint256 atBlock;
    }

    struct TerminalSession {
        address analyst;
        uint256 openedAtBlock;
        uint256 expiryBlock;
        bool closed;
    }

    struct FeedSlot {
        int256 value;
        uint256 timestamp;
        uint256 updatedAtBlock;
    }

    uint256 private _bandCap;
    uint256 private _bandCount;
    uint256 private _signalCount;
    uint256 private _sessionCount;
    uint256 private _currentEpoch;
    uint256 private _staleWindowBlocks;
    uint256 private _feeBps;
    uint256 private _guard;

    mapping(uint256 => RateBand) private _bands;
    mapping(uint256 => PolicySignal) private _signals;
    mapping(uint256 => TerminalSession) private _sessions;
    mapping(uint256 => mapping(address => AnalystVote)) private _sessionVotes;
    mapping(uint256 => FeedSlot) private _feeds;
    mapping(address => bool) private _analystWhitelist;
    mapping(uint256 => uint256) private _epochStartBlock;

    // -------------------------------------------------------------------------
    // CONSTRUCTOR
    // -------------------------------------------------------------------------

    constructor() Ownable(msg.sender) {
        relay = 0x7C3e9A1b4F6d2E8c0B5a7D9f1C3e5A7b9D1f3E;
        guardian = 0x8F4b2C1e9A3d7F6c0a5E8B1d4f7A2c9E3b6D0F;
        treasury = 0x3e7A9c2f5B1d8E0a4C6F2b9D7e1A5c3f0B8d4E;
        fallbackReceiver = 0x9C1e5a7B3d9F2c4e6A0b8D1f3a5C7e9B2d4F6;
        _bandCap = MAX_BANDS_DEFAULT;
        _currentEpoch = 1;
        _staleWindowBlocks = 50;
        _feeBps = 25;
        _epochStartBlock[1] = block.number;
    }

    // -------------------------------------------------------------------------
    // MODIFIERS
    // -------------------------------------------------------------------------

    modifier onlyRelay() {
        if (msg.sender != relay) revert J0R_NotRelay();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert J0R_NotGuardian();
        _;
    }

    modifier onlyAnalyst() {
        if (!_analystWhitelist[msg.sender]) revert J0R_NotAnalyst();
        _;
    }

    modifier whenNotPausedContract() {
        if (paused()) revert J0R_Paused();
        _;
    }

    modifier nonReentrantGuard() {
        if (_guard != 0) revert J0R_Reentrancy();
        _guard = 1;
        _;
        _guard = 0;
    }

    // -------------------------------------------------------------------------
    // EXTERNAL — RELAY
    // -------------------------------------------------------------------------

    function pushPolicySignal(bytes32 signalHash_) external onlyRelay whenNotPausedContract {
        uint256 epoch = _currentEpoch;
        _signalCount++;
        _signals[_signalCount] = PolicySignal({
            signalHash: signalHash_,
            epoch: epoch,
            relayer: msg.sender,
            atBlock: block.number
        });
        emit PolicySignalPushed(_signalCount, signalHash_, epoch, msg.sender, block.number);
    }

    function pushPolicySignalsBatch(bytes32[] calldata hashes_) external onlyRelay whenNotPausedContract {
        uint256 n = hashes_.length;
        if (n == 0) revert J0R_EmptyArray();
        if (n > BATCH_SIGNALS_MAX) revert J0R_CapExceeded();
        uint256 epoch = _currentEpoch;
        for (uint256 i; i < n; ) {
            _signalCount++;
            _signals[_signalCount] = PolicySignal({
                signalHash: hashes_[i],
                epoch: epoch,
                relayer: msg.sender,
                atBlock: block.number
