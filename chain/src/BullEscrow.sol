// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
}

/// @title BullEscrow
/// @notice Non-custodial two-party OTC escrow. The buyer pays (ETH or an ERC-20), the seller delivers an ERC-20.
///         The swap settles atomically in the transaction of whoever funds second. There is no owner, no admin,
///         no upgrade path and no pause: nobody except the two parties can move the funds.
/// @dev    Unaudited. Do not use with real funds before an independent audit.
contract BullEscrow {
    enum Status { None, Open, Settled, Cancelled }

    struct Deal {
        address buyer;
        address seller;
        address sellToken;   // ERC-20 the seller delivers
        uint256 sellAmount;
        address payToken;    // address(0) = native ETH
        uint256 payAmount;
        uint64 deadline;     // after this, anyone can cancel and refund both sides
        bool buyerFunded;
        bool sellerFunded;
        Status status;
        address sellerPayout; // Ghost mode: where the seller's proceeds go (a different address than the depositor)
        address buyerReceive; // where the buyer's tokens go (defaults to the buyer)
        uint16 feeBps;        // fixed at creation, taken from the payment on settlement
    }

    /// @notice Inputs of a deal, grouped to keep the function readable.
    struct DealParams {
        address seller;        // wallet that deposits the tokens (Ghost mode: a one-time wallet)
        address sellerPayout;  // receives the proceeds (0x0 = seller)
        address buyerReceive;  // receives the tokens (0x0 = buyer)
        address sellToken;
        uint256 sellAmount;
        address payToken;      // address(0) = native ETH
        uint256 payAmount;
        uint64 deadline;
    }

    /// @notice Fee quote signed by `feeSigner`. The fee depends on the USD value of the deal (tiers set by Bull), which the
    ///         contract cannot know, so Bull signs it. The signer can only pick a fee up to MAX_FEE_BPS and cannot touch funds.
    struct Quote {
        uint16 feeBps;
        uint64 expiry;
        bytes sig;
    }

    uint16 public constant MAX_FEE_BPS = 250; // hard cap: 2.5%, enforced for every deal
    address public immutable treasury;
    address public immutable feeSigner;

    uint256 public nextId = 1;
    mapping(uint256 => Deal) internal _deals;

    uint256 private _lock = 1;

    event DealCreated(uint256 indexed id, address indexed buyer, address indexed seller, uint16 feeBps);
    event Funded(uint256 indexed id, address indexed by);
    event Settled(uint256 indexed id, uint256 fee);
    event Cancelled(uint256 indexed id, address indexed by);

    error NotParty();
    error BadState();
    error BadInput();
    error WrongAmount();
    error TransferFailed();
    error Reentrancy();
    error BadQuote();

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(address _treasury, address _feeSigner) {
        if (_treasury == address(0) || _feeSigner == address(0)) revert BadInput();
        treasury = _treasury;
        feeSigner = _feeSigner;
    }

    /// @notice Reads a deal. Returned as one struct: the ABI encoding is the same as 13 separate return values.
    function deals(uint256 id) external view returns (Deal memory) {
        return _deals[id];
    }

    /// @notice The buyer opens a deal. `p.seller` is the address that will deposit the tokens (in Ghost mode a fresh
    ///         one-time wallet). `p.sellerPayout` receives the proceeds, so the payout never touches the depositing
    ///         wallet. `p.buyerReceive` receives the tokens (0x0 = the buyer). `q` is Bull's signed fee quote for exactly
    ///         these parameters.
    function createDeal(DealParams calldata p, Quote calldata q) external returns (uint256 id) {
        if (p.seller == address(0) || p.seller == msg.sender) revert BadInput();
        if (p.sellToken == address(0) || p.sellToken == p.payToken) revert BadInput();
        if (p.sellAmount == 0 || p.payAmount == 0) revert BadInput();
        if (p.deadline <= block.timestamp) revert BadInput();
        if (p.sellerPayout == address(this) || p.buyerReceive == address(this)) revert BadInput();
        if (q.feeBps > MAX_FEE_BPS || block.timestamp > q.expiry) revert BadQuote();
        if (_quoteSigner(p, q) != feeSigner) revert BadQuote();

        id = nextId++;
        Deal storage d = _deals[id];
        d.buyer = msg.sender;
        d.seller = p.seller;
        d.sellToken = p.sellToken;
        d.sellAmount = p.sellAmount;
        d.payToken = p.payToken;
        d.payAmount = p.payAmount;
        d.deadline = p.deadline;
        d.status = Status.Open;
        d.sellerPayout = p.sellerPayout == address(0) ? p.seller : p.sellerPayout;
        d.buyerReceive = p.buyerReceive == address(0) ? msg.sender : p.buyerReceive;
        d.feeBps = q.feeBps;
        emit DealCreated(id, msg.sender, p.seller, q.feeBps);
    }

    /// @notice Buyer deposits the payment. For ERC-20 payments, approve this contract first.
    function fundPayment(uint256 id) external payable nonReentrant {
        Deal storage d = _deals[id];
        if (d.status != Status.Open || block.timestamp > d.deadline) revert BadState();
        if (msg.sender != d.buyer) revert NotParty();
        if (d.buyerFunded) revert BadState();

        d.buyerFunded = true; // effects before interactions
        if (d.payToken == address(0)) {
            if (msg.value != d.payAmount) revert WrongAmount();
        } else {
            if (msg.value != 0) revert WrongAmount();
            _pull(d.payToken, msg.sender, d.payAmount);
        }
        emit Funded(id, msg.sender);
        _maybeSettle(id, d);
    }

    /// @notice Seller deposits the tokens. Approve this contract first.
    function fundTokens(uint256 id) external nonReentrant {
        Deal storage d = _deals[id];
        if (d.status != Status.Open || block.timestamp > d.deadline) revert BadState();
        if (msg.sender != d.seller) revert NotParty();
        if (d.sellerFunded) revert BadState();

        d.sellerFunded = true;
        _pull(d.sellToken, msg.sender, d.sellAmount);
        emit Funded(id, msg.sender);
        _maybeSettle(id, d);
    }

    /// @notice Gasless deposit for the seller (Ghost mode). The seller signs an EIP-2612 permit offline with the
    ///         one-time wallet; anyone (a relayer) can submit it and pay the gas, so the one-time wallet never needs
    ///         ETH and never has to be funded from a traceable wallet. Tokens move only from `d.seller`, and only for
    ///         exactly `sellAmount` to this contract, so a third party cannot misdirect anything.
    function fundTokensWithPermit(uint256 id, uint256 permitDeadline, uint8 v, bytes32 r, bytes32 s) external nonReentrant {
        Deal storage d = _deals[id];
        if (d.status != Status.Open || block.timestamp > d.deadline) revert BadState();
        if (d.sellerFunded) revert BadState();

        // A front-run permit call by someone else only sets the same allowance; ignore its failure.
        try IERC20Permit(d.sellToken).permit(d.seller, address(this), d.sellAmount, permitDeadline, v, r, s) {} catch {}

        d.sellerFunded = true;
        _pull(d.sellToken, d.seller, d.sellAmount);
        emit Funded(id, d.seller);
        _maybeSettle(id, d);
    }

    /// @notice Cancel an unsettled deal and refund whatever was deposited.
    ///         Either party can cancel at any time before settlement. After the deadline, anyone can.
    function cancel(uint256 id) external nonReentrant {
        Deal storage d = _deals[id];
        if (d.status != Status.Open) revert BadState();
        if (msg.sender != d.buyer && msg.sender != d.seller && block.timestamp <= d.deadline) revert NotParty();

        d.status = Status.Cancelled;
        bool bf = d.buyerFunded;
        bool sf = d.sellerFunded;
        d.buyerFunded = false;
        d.sellerFunded = false;

        if (bf) _send(d.payToken, d.buyer, d.payAmount);
        if (sf) _send(d.sellToken, d.seller, d.sellAmount);
        emit Cancelled(id, msg.sender);
    }

    // ---- internals ----

    function _maybeSettle(uint256 id, Deal storage d) private {
        if (!(d.buyerFunded && d.sellerFunded)) return;
        d.status = Status.Settled;

        uint256 fee = (d.payAmount * d.feeBps) / 10_000;
        _send(d.sellToken, d.buyerReceive, d.sellAmount);
        _send(d.payToken, d.sellerPayout, d.payAmount - fee);
        if (fee > 0) _send(d.payToken, treasury, fee);
        emit Settled(id, fee);
    }

    /// @dev The quote binds chain, contract, buyer and every deal parameter, so it cannot be reused for another deal.
    ///      Hash = keccak256(abi.encode(chainid, this, buyer, keccak256(abi.encode(params)), feeBps, expiry)).
    function _quoteHash(DealParams calldata p, uint16 feeBps, uint64 expiry) private view returns (bytes32) {
        DealParams memory m = p;
        bytes32 ph = keccak256(abi.encode(m));
        return keccak256(abi.encode(block.chainid, address(this), msg.sender, ph, feeBps, expiry));
    }

    function _quoteSigner(DealParams calldata p, Quote calldata q) private view returns (address) {
        bytes32 h = _quoteHash(p, q.feeBps, q.expiry);
        return _recover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h)), q.sig);
    }

    function _recover(bytes32 digest, bytes memory sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        return ecrecover(digest, v, r, s);
    }

    /// @dev Pull exactly `amount`. Fee-on-transfer / tax tokens are rejected on purpose.
    function _pull(address token, address from, uint256 amount) private {
        uint256 before = IERC20(token).balanceOf(address(this));
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, address(this), amount));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
        if (IERC20(token).balanceOf(address(this)) - before != amount) revert WrongAmount();
    }

    /// @dev `token == address(0)` sends ETH.
    function _send(address token, address to, uint256 amount) private {
        if (token == address(0)) {
            (bool ok, ) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, amount));
            if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert TransferFailed();
        }
    }
}