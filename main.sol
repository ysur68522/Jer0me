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
            });
            emit PolicySignalPushed(_signalCount, hashes_[i], epoch, msg.sender, block.number);
            unchecked { ++i; }
        }
    }

    function updateFeed(uint256 feedIndex_, int256 value_) external onlyRelay whenNotPausedContract {
        if (feedIndex_ >= MAX_FEEDS) revert J0R_CapExceeded();
        _feeds[feedIndex_] = FeedSlot({
            value: value_,
            timestamp: block.timestamp,
            updatedAtBlock: block.number
        });
        emit RelayFeedUpdated(feedIndex_, value_, block.timestamp, block.number);
    }

    function registerBand(
        bytes32 bandTag_,
        uint256 lowerBps_,
        uint256 upperBps_
    ) external onlyRelay whenNotPausedContract {
        if (lowerBps_ >= upperBps_) revert J0R_BandBoundsInvalid();
        if (_bandCount >= _bandCap) revert J0R_CapExceeded();
        _bandCount++;
        _bands[_bandCount] = RateBand({
            bandTag: bandTag_,
            lowerBps: lowerBps_,
            upperBps: upperBps_,
            policyEpoch: _currentEpoch,
            registeredAtBlock: block.number,
            active: true
        });
        _appendBandHistory(_bandCount, lowerBps_, upperBps_, true);
        emit BandRegistered(_bandCount, bandTag_, lowerBps_, upperBps_, _currentEpoch, block.number);
    }

    function advanceEpoch() external onlyRelay whenNotPausedContract {
        uint256 prev = _currentEpoch;
        _currentEpoch++;
        _epochStartBlock[_currentEpoch] = block.number;
        emit EpochAdvanced(prev, _currentEpoch, block.number);
    }

    // -------------------------------------------------------------------------
    // EXTERNAL — GUARDIAN
    // -------------------------------------------------------------------------

    function setPaused(bool paused_) external onlyGuardian {
        if (paused_) _pause(); else _unpause();
        emit GuardianPauseToggled(paused_, block.number);
    }

    function setBandCap(uint256 newCap_) external onlyGuardian {
        if (newCap_ < _bandCount) revert J0R_BandBoundsInvalid();
        uint256 prev = _bandCap;
        _bandCap = newCap_;
        emit BandCapSet(prev, newCap_, block.number);
    }

    function setStaleWindow(uint256 newWindow_) external onlyGuardian {
        if (newWindow_ > MAX_STALE_BLOCKS) revert J0R_StaleWindowTooLarge();
        uint256 prev = _staleWindowBlocks;
        _staleWindowBlocks = newWindow_;
        emit StaleWindowSet(prev, newWindow_, block.number);
    }

    function setFeeBps(uint256 newBps_) external onlyGuardian {
        if (newBps_ > MAX_FEE_BPS) revert J0R_FeeBpsTooHigh();
        uint256 prev = _feeBps;
        _feeBps = newBps_;
        emit FeeBpsSet(prev, newBps_, block.number);
    }

    function setAnalystWhitelist(address analyst_, bool allowed_) external onlyGuardian {
        _analystWhitelist[analyst_] = allowed_;
        emit AnalystWhitelistSet(analyst_, allowed_, block.number);
    }

    function setAnalystWhitelistBatch(address[] calldata analysts_, bool[] calldata allowed_) external onlyGuardian {
        uint256 n = analysts_.length;
        if (n != allowed_.length) revert J0R_ArrayLengthMismatch();
        for (uint256 i; i < n; ) {
            _analystWhitelist[analysts_[i]] = allowed_[i];
            emit AnalystWhitelistSet(analysts_[i], allowed_[i], block.number);
            unchecked { ++i; }
        }
    }

    function updateBand(uint256 bandId_, uint256 lowerBps_, uint256 upperBps_, bool active_) external onlyGuardian {
        if (_bands[bandId_].registeredAtBlock == 0) revert J0R_BandNotFound();
        if (lowerBps_ >= upperBps_) revert J0R_BandBoundsInvalid();
        _bands[bandId_].lowerBps = lowerBps_;
        _bands[bandId_].upperBps = upperBps_;
        _bands[bandId_].active = active_;
        _appendBandHistory(bandId_, lowerBps_, upperBps_, active_);
        emit BandUpdated(bandId_, lowerBps_, upperBps_, active_, block.number);
    }

    // -------------------------------------------------------------------------
    // EXTERNAL — ANALYST (TERMINAL)
    // -------------------------------------------------------------------------

    function openTerminalSession() external onlyAnalyst whenNotPausedContract returns (uint256 sessionId) {
        _sessionCount++;
        sessionId = _sessionCount;
        uint256 expiry = block.number + SESSION_DURATION_BLOCKS;
        _sessions[sessionId] = TerminalSession({
            analyst: msg.sender,
            openedAtBlock: block.number,
            expiryBlock: expiry,
            closed: false
        });
        emit TerminalSessionOpened(sessionId, msg.sender, expiry, block.number);
    }

    function closeTerminalSession(uint256 sessionId_) external {
        TerminalSession storage s = _sessions[sessionId_];
        if (s.openedAtBlock == 0) revert J0R_SessionNotOpen();
        if (s.analyst != msg.sender && owner() != msg.sender) revert J0R_NotAnalyst();
        if (s.closed) revert J0R_SessionNotOpen();
        s.closed = true;
        emit TerminalSessionClosed(sessionId_, block.number);
    }

    function castVote(uint256 sessionId_, uint8 direction_, uint256 bandId_) external onlyAnalyst whenNotPausedContract {
        TerminalSession storage s = _sessions[sessionId_];
        if (s.openedAtBlock == 0) revert J0R_SessionNotOpen();
        if (s.analyst != msg.sender) revert J0R_NotAnalyst();
        if (s.closed) revert J0R_SessionNotOpen();
        if (block.number > s.expiryBlock) revert J0R_SessionExpired();
        if (direction_ > VOTE_DIRECTION_DOWN) revert J0R_DirectionInvalid();
        if (_bands[bandId_].registeredAtBlock == 0 || !_bands[bandId_].active) revert J0R_BandNotFound();
        _sessionVotes[sessionId_][msg.sender] = AnalystVote({
            direction: direction_,
            bandId: bandId_,
            atBlock: block.number
        });
        emit AnalystVoteRecorded(sessionId_, msg.sender, direction_, bandId_, block.number);
    }

    // -------------------------------------------------------------------------
    // EXTERNAL — OWNER
    // -------------------------------------------------------------------------

    function sweepToken(address token_, address to_, uint256 amount_) external onlyOwner nonReentrantGuard {
        if (to_ == address(0)) revert J0R_ZeroAddress();
        if (amount_ == 0) revert J0R_ZeroAmount();
        bool ok = IERC20Jer0me(token_).transfer(to_, amount_);
        if (!ok) revert J0R_TransferFailed();
        emit TreasurySweep(token_, to_, amount_, block.number);
    }

    function sweepNative(address payable to_, uint256 amount_) external onlyOwner nonReentrantGuard {
        if (to_ == address(0)) revert J0R_ZeroAddress();
        (bool sent,) = to_.call{value: amount_}("");
        if (!sent) revert J0R_TransferFailed();
    }

    receive() external payable {}

    // -------------------------------------------------------------------------
    // VIEW — BANDS & SIGNALS
    // -------------------------------------------------------------------------

    function getBand(uint256 bandId_) external view returns (
        bytes32 bandTag,
        uint256 lowerBps,
        uint256 upperBps,
        uint256 policyEpoch,
        uint256 registeredAtBlock,
        bool active
    ) {
        RateBand storage b = _bands[bandId_];
        if (b.registeredAtBlock == 0) revert J0R_BandNotFound();
        return (b.bandTag, b.lowerBps, b.upperBps, b.policyEpoch, b.registeredAtBlock, b.active);
    }

    function getBandCount() external view returns (uint256) { return _bandCount; }

    function getBandCap() external view returns (uint256) { return _bandCap; }

    function getSignal(uint256 signalId_) external view returns (
        bytes32 signalHash,
        uint256 epoch,
        address relayer,
        uint256 atBlock
    ) {
        PolicySignal storage s = _signals[signalId_];
        return (s.signalHash, s.epoch, s.relayer, s.atBlock);
    }

    function getSignalCount() external view returns (uint256) { return _signalCount; }

    function getBandsBatch(uint256 fromId_, uint256 toId_) external view returns (
        uint256[] memory ids,
        bytes32[] memory tags,
        uint256[] memory lowerBps,
        uint256[] memory upperBps,
        bool[] memory active
    ) {
        if (fromId_ > toId_) revert J0R_BandBoundsInvalid();
        uint256 n = toId_ - fromId_ + 1;
        ids = new uint256[](n);
        tags = new bytes32[](n);
        lowerBps = new uint256[](n);
        upperBps = new uint256[](n);
        active = new bool[](n);
        for (uint256 i; i < n; ) {
            uint256 id = fromId_ + i;
            RateBand storage b = _bands[id];
            ids[i] = id;
            tags[i] = b.bandTag;
            lowerBps[i] = b.lowerBps;
            upperBps[i] = b.upperBps;
            active[i] = b.active;
            unchecked { ++i; }
        }
    }

    // -------------------------------------------------------------------------
    // VIEW — SESSIONS & VOTES
    // -------------------------------------------------------------------------

    function getSession(uint256 sessionId_) external view returns (
        address analyst,
        uint256 openedAtBlock,
        uint256 expiryBlock,
        bool closed
    ) {
        TerminalSession storage s = _sessions[sessionId_];
        if (s.openedAtBlock == 0) revert J0R_SessionNotOpen();
        return (s.analyst, s.openedAtBlock, s.expiryBlock, s.closed);
    }

    function getSessionCount() external view returns (uint256) { return _sessionCount; }

    function getVote(uint256 sessionId_, address analyst_) external view returns (
        uint8 direction,
        uint256 bandId,
        uint256 atBlock
    ) {
        AnalystVote storage v = _sessionVotes[sessionId_][analyst_];
        return (v.direction, v.bandId, v.atBlock);
    }

    function isSessionOpen(uint256 sessionId_) external view returns (bool) {
        TerminalSession storage s = _sessions[sessionId_];
        return s.openedAtBlock != 0 && !s.closed && block.number <= s.expiryBlock;
    }

    function isAnalystWhitelisted(address account_) external view returns (bool) {
        return _analystWhitelist[account_];
    }

    // -------------------------------------------------------------------------
    // VIEW — FEEDS & CONFIG
    // -------------------------------------------------------------------------

    function getFeed(uint256 feedIndex_) external view returns (int256 value, uint256 timestamp, uint256 updatedAtBlock) {
        if (feedIndex_ >= MAX_FEEDS) revert J0R_CapExceeded();
        FeedSlot storage f = _feeds[feedIndex_];
        return (f.value, f.timestamp, f.updatedAtBlock);
    }

    function getFeedStale(uint256 feedIndex_) external view returns (bool) {
        if (feedIndex_ >= MAX_FEEDS) return true;
        FeedSlot storage f = _feeds[feedIndex_];
        if (f.updatedAtBlock == 0) return true;
        return block.number > f.updatedAtBlock + _staleWindowBlocks;
    }

    function currentEpoch() external view returns (uint256) { return _currentEpoch; }

    function epochStartBlock(uint256 epoch_) external view returns (uint256) { return _epochStartBlock[epoch_]; }

    function staleWindowBlocks() external view returns (uint256) { return _staleWindowBlocks; }

    function feeBps() external view returns (uint256) { return _feeBps; }

    function resolveBandForBps(uint256 bps_) external view returns (uint256 bandId, bool found) {
        for (uint256 i = 1; i <= _bandCount; ) {
            RateBand storage b = _bands[i];
            if (b.active && bps_ >= b.lowerBps && bps_ <= b.upperBps) return (i, true);
            unchecked { ++i; }
        }
        return (0, false);
    }

    function resolveBandsForBpsBatch(uint256[] calldata bpsList_) external view returns (
        uint256[] memory bandIds,
        bool[] memory found
    ) {
        uint256 n = bpsList_.length;
        bandIds = new uint256[](n);
        found = new bool[](n);
        for (uint256 j; j < n; ) {
            uint256 bps = bpsList_[j];
            for (uint256 i = 1; i <= _bandCount; ) {
                RateBand storage b = _bands[i];
                if (b.active && bps >= b.lowerBps && bps <= b.upperBps) {
                    bandIds[j] = i;
                    found[j] = true;
                    break;
                }
                unchecked { ++i; }
            }
            unchecked { ++j; }
        }
    }

    // -------------------------------------------------------------------------
    // PURE / VIEW HELPERS
    // -------------------------------------------------------------------------

    function computeFee(uint256 amount_) external view returns (uint256) {
        return (amount_ * _feeBps) / BPS_DENOMINATOR;
    }

    function namespaceHash() external pure returns (bytes32) { return JER0ME_NAMESPACE; }

    function version() external pure returns (uint256) { return JER0ME_VERSION; }

    // -------------------------------------------------------------------------
    // BAND HISTORY & SNAPSHOTS (extended ledger)
    // -------------------------------------------------------------------------

    struct BandHistoryEntry {
        uint256 bandId;
        uint256 lowerBps;
        uint256 upperBps;
        bool active;
        uint256 atBlock;
    }

    uint256 private _bandHistoryCount;
    mapping(uint256 => BandHistoryEntry) private _bandHistory;

    event BandHistoryAppended(uint256 indexed bandId, uint256 entryIndex, uint256 atBlock);

    function _appendBandHistory(uint256 bandId_, uint256 lowerBps_, uint256 upperBps_, bool active_) internal {
        _bandHistoryCount++;
        _bandHistory[_bandHistoryCount] = BandHistoryEntry({
            bandId: bandId_,
            lowerBps: lowerBps_,
            upperBps: upperBps_,
            active: active_,
            atBlock: block.number
        });
        emit BandHistoryAppended(bandId_, _bandHistoryCount, block.number);
    }

    function getBandHistoryEntry(uint256 entryId_) external view returns (
        uint256 bandId,
        uint256 lowerBps,
        uint256 upperBps,
        bool active,
        uint256 atBlock
    ) {
        BandHistoryEntry storage e = _bandHistory[entryId_];
        return (e.bandId, e.lowerBps, e.upperBps, e.active, e.atBlock);
    }

    function getBandHistoryCount() external view returns (uint256) { return _bandHistoryCount; }

    function getBandHistoryRange(uint256 from_, uint256 to_) external view returns (
        uint256[] memory bandIds,
        uint256[] memory lowerBps,
        uint256[] memory upperBps,
        bool[] memory active,
        uint256[] memory atBlocks
    ) {
        if (from_ > to_) revert J0R_BandBoundsInvalid();
        uint256 n = to_ - from_ + 1;
        bandIds = new uint256[](n);
        lowerBps = new uint256[](n);
        upperBps = new uint256[](n);
        active = new bool[](n);
        atBlocks = new uint256[](n);
        for (uint256 i; i < n; ) {
            uint256 idx = from_ + i;
            BandHistoryEntry storage e = _bandHistory[idx];
            bandIds[i] = e.bandId;
            lowerBps[i] = e.lowerBps;
            upperBps[i] = e.upperBps;
            active[i] = e.active;
            atBlocks[i] = e.atBlock;
            unchecked { ++i; }
        }
    }

    // -------------------------------------------------------------------------
    // FEED AGGREGATION & SNAPSHOT VIEWS
    // -------------------------------------------------------------------------

    function getFeedSum(uint256 fromIndex_, uint256 toIndex_) external view returns (int256 sum) {
        if (fromIndex_ > toIndex_ || toIndex_ >= MAX_FEEDS) revert J0R_BandBoundsInvalid();
        for (uint256 i = fromIndex_; i <= toIndex_; ) {
            sum += _feeds[i].value;
            unchecked { ++i; }
        }
    }

    function getFeedMean(uint256 fromIndex_, uint256 toIndex_) external view returns (int256 mean) {
        if (fromIndex_ > toIndex_ || toIndex_ >= MAX_FEEDS) revert J0R_BandBoundsInvalid();
        uint256 count = toIndex_ - fromIndex_ + 1;
        int256 sum;
        for (uint256 i = fromIndex_; i <= toIndex_; ) {
            sum += _feeds[i].value;
            unchecked { ++i; }
        }
        mean = count == 0 ? 0 : sum / int256(uint256(count));
    }

    function getFeedsBatch(uint256[] calldata indices_) external view returns (
        int256[] memory values,
        uint256[] memory timestamps,
        uint256[] memory updatedAtBlocks
    ) {
        uint256 n = indices_.length;
        if (n == 0) revert J0R_EmptyArray();
        values = new int256[](n);
        timestamps = new uint256[](n);
        updatedAtBlocks = new uint256[](n);
        for (uint256 i; i < n; ) {
            uint256 idx = indices_[i];
            if (idx >= MAX_FEEDS) revert J0R_CapExceeded();
            FeedSlot storage f = _feeds[idx];
            values[i] = f.value;
            timestamps[i] = f.timestamp;
            updatedAtBlocks[i] = f.updatedAtBlock;
            unchecked { ++i; }
        }
    }

    function getSignalsBatch(uint256 fromId_, uint256 toId_) external view returns (
        uint256[] memory ids,
        bytes32[] memory hashes,
        uint256[] memory epochs,
        uint256[] memory atBlocks
    ) {
        if (fromId_ > toId_) revert J0R_BandBoundsInvalid();
        uint256 n = toId_ - fromId_ + 1;
        ids = new uint256[](n);
        hashes = new bytes32[](n);
        epochs = new uint256[](n);
        atBlocks = new uint256[](n);
        for (uint256 i; i < n; ) {
            uint256 id = fromId_ + i;
            PolicySignal storage s = _signals[id];
            ids[i] = id;
            hashes[i] = s.signalHash;
            epochs[i] = s.epoch;
            atBlocks[i] = s.atBlock;
            unchecked { ++i; }
        }
    }

    function getSessionsBatch(uint256 fromId_, uint256 toId_) external view returns (
        uint256[] memory ids,
        address[] memory analysts,
        uint256[] memory openedAtBlocks,
        uint256[] memory expiryBlocks,
        bool[] memory closed
    ) {
        if (fromId_ > toId_) revert J0R_BandBoundsInvalid();
        uint256 n = toId_ - fromId_ + 1;
        ids = new uint256[](n);
        analysts = new address[](n);
        openedAtBlocks = new uint256[](n);
        expiryBlocks = new uint256[](n);
        closed = new bool[](n);
        for (uint256 i; i < n; ) {
            uint256 id = fromId_ + i;
            TerminalSession storage s = _sessions[id];
            ids[i] = id;
            analysts[i] = s.analyst;
            openedAtBlocks[i] = s.openedAtBlock;
            expiryBlocks[i] = s.expiryBlock;
            closed[i] = s.closed;
            unchecked { ++i; }
        }
    }

    function countActiveBands() external view returns (uint256 count) {
        for (uint256 i = 1; i <= _bandCount; ) {
            if (_bands[i].active) count++;
            unchecked { ++i; }
        }
    }

