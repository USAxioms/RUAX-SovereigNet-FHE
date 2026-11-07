// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title WAD18 - exact fixed-point rules (no hidden rounding), mirrors the capsule's integer rules.
library WAD18 {
    uint256 internal constant WAD = 1e18;

    error InexactMul();
    error InexactDiv();
    error DivByZero();

    /// a*b/WAD, reverts instead of rounding (Solidity 0.8 also reverts on overflow).
    function mulExact(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 p = a * b;
        if (p % WAD != 0) revert InexactMul();
        return p / WAD;
    }

    /// a*WAD/b, reverts instead of rounding.
    function divExact(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) revert DivByZero();
        uint256 n = a * WAD;
        if (n % b != 0) revert InexactDiv();
        return n / b;
    }

    /// Exact rationals of the 45% cap and 48% breaker: over_cap <=> 20D > 9E, over_breaker <=> 25D > 12E.
    function solvencyFlags(uint256 debt, uint256 ev) internal pure returns (bool overCap, bool overBreaker) {
        overCap = 20 * debt > 9 * ev;
        overBreaker = 25 * debt > 12 * ev;
    }
}

/// @title CognitiveStateLedger
/// @notice Draft on-chain CSL. It ANCHORS and SEQUENCES; it does not verify RLWE/BFV maths.
///         Decryption results (flags) are custodian attestations bound to ciphertext digests.
/// @dev    UNCOMPILED, UNTESTED DRAFT. Not audited. Do not deploy with real assets.
contract CognitiveStateLedger {
    using WAD18 for uint256;

    enum Status { None, Pending, Verified, Rejected }
    enum Op { Add, Sub, Mul, Div }

    struct Entry {
        bytes32 stateHash;        // SHA-256 of canonical CSL state (computed off-chain)
        bytes32 rlweCommitment;   // sha256(paramsDigest, evkDigest, inputCtDigest)
        bytes32 transitionDigest; // digest of the WAD-18 transition being claimed
        bytes32 chainHash;        // sha256(prevChainHash, fields, block.number)
        uint64  submittedBlock;
        address submitter;
        address approver;         // H_decision: must differ from submitter
        Status  status;
        bool    overCap;          // attested flags
        bool    overBreaker;
        bytes32 outputCtDigest;   // digest of the two output flag ciphertexts
    }

    bytes32 public constant GENESIS = keccak256("CSL_GENESIS_V1");

    address public admin;
    mapping(address => bool) public custodian;
    Entry[] private _entries;
    uint256 public nextToVerify; // strict FIFO: entry i is verified only after 0..i-1
    bool public frozen;          // sticky, mirrors capsule FROZEN semantics

    event EntrySubmitted(uint256 indexed id, bytes32 stateHash, bytes32 rlweCommitment, bytes32 chainHash, address submitter);
    event DecisionRecorded(uint256 indexed id, address indexed approver);
    event VerificationRecorded(uint256 indexed id, bool overCap, bool overBreaker, bytes32 outputCtDigest, Status status);
    event Frozen(uint256 indexed id);
    event Released(address indexed by);
    event CustodianSet(address indexed who, bool allowed);

    error NotAdmin();
    error NotCustodian();
    error LedgerFrozen();
    error BadId();
    error BadStatus();
    error OutOfSequence();
    error SameBlock();            // verification must come in a strictly later block than submission
    error SelfApproval();
    error NotApproved();

    modifier onlyAdmin() { if (msg.sender != admin) revert NotAdmin(); _; }
    modifier onlyCustodian() { if (!custodian[msg.sender]) revert NotCustodian(); _; }

    constructor(address firstCustodian) {
        admin = msg.sender;
        custodian[firstCustodian] = true;
        emit CustodianSet(firstCustodian, true);
    }

    function setCustodian(address who, bool allowed) external onlyAdmin {
        custodian[who] = allowed;
        emit CustodianSet(who, allowed);
    }

    // ---------------------------------------------------------------- pure interfaces

    /// Defines the RLWE audit commitment so off-chain code and on-chain checks agree.
    function commitRlwe(bytes32 paramsDigest, bytes32 evkDigest, bytes32 inputCtDigest) public pure returns (bytes32) {
        return sha256(abi.encode(paramsDigest, evkDigest, inputCtDigest));
    }

    /// Check a claimed WAD-18 result; reverts nothing, returns false on any inexact/overflow/zero-div case.
    function verifyWadTransition(Op op, uint256 a, uint256 b, uint256 claimed) external pure returns (bool) {
        if (op == Op.Add) {
            unchecked { uint256 s = a + b; if (s < a) return false; return s == claimed; }
        } else if (op == Op.Sub) {
            if (b > a) return false;
            unchecked { return a - b == claimed; }
        } else if (op == Op.Mul) {
            if (b != 0 && a > type(uint256).max / b) return false;
            uint256 p = a * b;
            if (p % WAD18.WAD != 0) return false;
            return p / WAD18.WAD == claimed;
        } else {
            if (b == 0) return false;
            if (a > type(uint256).max / WAD18.WAD) return false;
            uint256 n = a * WAD18.WAD;
            if (n % b != 0) return false;
            return n / b == claimed;
        }
    }

    /// Plaintext cross-check of the cap/breaker rule (only meaningful for values the custodian chooses to disclose).
    function solvencyRule(uint256 debt, uint256 ev) external pure returns (bool overCap, bool overBreaker) {
        if (debt > type(uint256).max / 25 || ev > type(uint256).max / 12) revert WAD18.InexactMul();
        return WAD18.solvencyFlags(debt, ev);
    }

    // ---------------------------------------------------------------- normative sequence
    // 1) submitEntry  (ledger entry FIRST)
    // 2) approve      (H_decision by a different custodian)
    // 3) recordVerification (strictly later block, strict FIFO)

    function submitEntry(bytes32 stateHash, bytes32 rlweCommitment, bytes32 transitionDigest)
        external onlyCustodian returns (uint256 id)
    {
        if (frozen) revert LedgerFrozen();
        id = _entries.length;
        bytes32 prev = id == 0 ? GENESIS : _entries[id - 1].chainHash;
        bytes32 ch = sha256(abi.encode(prev, stateHash, rlweCommitment, transitionDigest, uint64(block.number)));
        _entries.push(Entry({
            stateHash: stateHash,
            rlweCommitment: rlweCommitment,
            transitionDigest: transitionDigest,
            chainHash: ch,
            submittedBlock: uint64(block.number),
            submitter: msg.sender,
            approver: address(0),
            status: Status.Pending,
            overCap: false,
            overBreaker: false,
            outputCtDigest: bytes32(0)
        }));
        emit EntrySubmitted(id, stateHash, rlweCommitment, ch, msg.sender);
    }

    function approve(uint256 id) external onlyCustodian {
        if (id >= _entries.length) revert BadId();
        Entry storage e = _entries[id];
        if (e.status != Status.Pending) revert BadStatus();
        if (e.submitter == msg.sender) revert SelfApproval();
        e.approver = msg.sender;
        emit DecisionRecorded(id, msg.sender);
    }

    /// @param ctDigests: (paramsDigest, evkDigest, inputCtDigest) must reproduce the committed rlweCommitment.
    function recordVerification(
        uint256 id,
        bytes32 paramsDigest,
        bytes32 evkDigest,
        bytes32 inputCtDigest,
        bool overCap,
        bool overBreaker,
        bytes32 outputCtDigest
    ) external onlyCustodian {
        if (frozen) revert LedgerFrozen();
        if (id >= _entries.length) revert BadId();
        if (id != nextToVerify) revert OutOfSequence();
        Entry storage e = _entries[id];
        if (e.status != Status.Pending) revert BadStatus();
        if (block.number <= e.submittedBlock) revert SameBlock();
        if (e.approver == address(0)) revert NotApproved();

        bool commitOk = commitRlwe(paramsDigest, evkDigest, inputCtDigest) == e.rlweCommitment;
        e.overCap = overCap;
        e.overBreaker = overBreaker;
        e.outputCtDigest = outputCtDigest;
        // A commitment mismatch or a cap breach is recorded as Rejected; it still consumes its sequence slot.
        e.status = (commitOk && !overCap && !overBreaker) ? Status.Verified : Status.Rejected;
        nextToVerify = id + 1;
        emit VerificationRecorded(id, overCap, overBreaker, outputCtDigest, e.status);

        if (commitOk && overBreaker) {
            frozen = true;
            emit Frozen(id);
        }
    }

    /// Release is an out-of-band governance action (admin only here; production needs multi-party control).
    function release() external onlyAdmin {
        frozen = false;
        emit Released(msg.sender);
    }

    // ---------------------------------------------------------------- views

    function entryCount() external view returns (uint256) { return _entries.length; }

    function getEntry(uint256 id) external view returns (Entry memory) {
        if (id >= _entries.length) revert BadId();
        return _entries[id];
    }

    function head() external view returns (bytes32) {
        return _entries.length == 0 ? GENESIS : _entries[_entries.length - 1].chainHash;
    }

    /// Re-derive the chain from genesis; true iff every stored chainHash matches its predecessor and fields.
    function verifyChain() external view returns (bool) {
        bytes32 prev = GENESIS;
        for (uint256 i = 0; i < _entries.length; i++) {
            Entry storage e = _entries[i];
            bytes32 ch = sha256(abi.encode(prev, e.stateHash, e.rlweCommitment, e.transitionDigest, e.submittedBlock));
            if (ch != e.chainHash) return false;
            prev = ch;
        }
        return true;
    }
}
