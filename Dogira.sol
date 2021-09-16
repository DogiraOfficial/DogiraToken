/**
 * Dogira Token
 * https://Dogira.net
 */

pragma solidity ^0.6.12;
// SPDX-License-Identifier: Unlicensed

import "./Address.sol";
import "./IERC20.sol";
import "./IUniswapV2Factory.sol";
import "./IUniswapV2Router02.sol";
import "./Ownable.sol";
import "./SafeMath.sol";

contract Dogira is Context, IERC20, Ownable {
    using SafeMath for uint256;
    using Address for address;

    mapping (address => uint256) private _balances;
    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private constant MAX = ~uint256(0);
    uint256 private constant _tTotal = 1000000000 * 10**9;

    string private constant _name = "Dogira";
    string private constant _symbol = "DOGIRA";
    uint8 private constant _decimals = 9;

    uint256 public _taxFee = 0;
    uint256 private _previousTaxFee = _taxFee;
    address[] private _includedInFees;

    IUniswapV2Router02 public uniswapV2Router;
    address public uniswapV2Pair;
    address public previousUniswapV2Pair;
    address public pendingUniswapV2Pair;
    uint256 public pairSwitchUnlockTimestamp = 0;
    bool public pairSwitchPossible = false;

    address public bridge;

    address payable public devWallet;

    bool inSwapTokens;
    bool public SwapTokensEnabled = true;

    uint256 public maxTxAmount = 50000000 * 10**9;
    uint256 private numTokensSwap = 50000 * 10**9;

    event MinTokensBeforeSwapUpdated(uint256 minTokensBeforeSwap);
    event SwapTokensEnabledUpdated(bool enabled);
    event TokenSwapped(
        uint256 tokensSwapped,
        uint256 ethReceived
    );

    event FeeAppliedTo(address _address);
    event FeeExcludedFrom(address _address);

    event SwapRouterUpdated(address _router);
    event SwapPairUpdated(address _pair);
    event SwapPairRequested(address _pair, uint256 unlockTimestamp);
    event SwapPairLocked(address _pair);
    event BridgeAddressUpdated(address _bridge);
    event TaxUpdated(uint256 taxFee);
    event MaxTxPercentUpdated(uint256 maxTxPercent);
    event DevWalletChanged(address newWallet);
    event GlobalTradingEnabled();

    address[] private blacklist;
    uint256 public blacklistUnlockTimestamp = 0;
    uint8 constant private _maxBlacklistings = 5;
    uint8 private _currentBlacklistings = 0;
    bool public limitedBlacklist = true;
    bool public blacklistPossible = true;

    event Blacklisted(address indexed node, uint8 blacklistsThisUnlock);
    event Unblacklisted(address indexed node);
    event BlacklistUnlockCalled(uint256 unlockTimestamp, uint daysUntilUnlock, bool isLimited);
    event BlacklistLockCalled(uint256 lockTimestamp);

    /// @dev A record of each accounts delegate
    mapping (address => address) internal _delegates;

    /// @notice A checkpoint for marking number of votes from a given block
    struct Checkpoint {
        uint32 fromBlock;
        uint256 votes;
    }

    /// @notice A record of votes checkpoints for each account, by index
    mapping (address => mapping (uint32 => Checkpoint)) public checkpoints;

    /// @notice The number of checkpoints for each account
    mapping (address => uint32) public numCheckpoints;

    /// @notice The EIP-712 typehash for the contract's domain
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");

    /// @notice The EIP-712 typehash for the delegation struct used by the contract
    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");

    /// @notice A record of states for signing / validating signatures
    mapping (address => uint) public nonces;

    /// @notice An event thats emitted when an account changes its delegate
    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);

    /// @notice An event thats emitted when a delegate account's vote balance changes
    event DelegateVotesChanged(address indexed delegate, uint previousBalance, uint newBalance);

    bool public globalTradingEnabled = false;

    modifier lockTheSwap {
        inSwapTokens = true;
        _;
        inSwapTokens = false;
    }

    // 
    modifier globalTradingStarted {
        require(_msgSender() == owner() || globalTradingEnabled, "Can send tokens after global trading is activated");
        _;
    }

    constructor (address _wallet) public {
        _balances[_msgSender()] = _tTotal;
        _moveDelegates(address(0), _delegates[_msgSender()], _tTotal, 0);

        // This Router address should be changed based on network.

        IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        // Create a uniswap pair for this new token
        uniswapV2Pair = IUniswapV2Factory(_uniswapV2Router.factory())
        .createPair(address(this), _uniswapV2Router.WETH());

        // set the rest of the contract variables
        uniswapV2Router = _uniswapV2Router;
        devWallet = payable(_wallet);

        emit Transfer(address(0), _msgSender(), _tTotal);

        //Public list of flashbots & front-runners
        blacklistPreloadedAddress(address(0xA39C50bf86e15391180240938F469a7bF4fDAe9a));
        blacklistPreloadedAddress(address(0xFFFFF6E70842330948Ca47254F2bE673B1cb0dB7));
        blacklistPreloadedAddress(address(0xD334C5392eD4863C81576422B968C6FB90EE9f79));
        blacklistPreloadedAddress(address(0x20f6fCd6B8813c4f98c0fFbD88C87c0255040Aa3));
        blacklistPreloadedAddress(address(0xC6bF34596f74eb22e066a878848DfB9fC1CF4C65));
        blacklistPreloadedAddress(address(0x231DC6af3C66741f6Cf618884B953DF0e83C1A2A));
        blacklistPreloadedAddress(address(0x00000000003b3cc22aF3aE1EAc0440BcEe416B40));
        blacklistPreloadedAddress(address(0x42d4C197036BD9984cA652303e07dD29fA6bdB37));
        blacklistPreloadedAddress(address(0x22246F9BCa9921Bfa9A3f8df5baBc5Bc8ee73850));
        blacklistPreloadedAddress(address(0xbCb05a3F85d34f0194C70d5914d5C4E28f11Cc02));
        blacklistPreloadedAddress(address(0x5B83A351500B631cc2a20a665ee17f0dC66e3dB7));
        blacklistPreloadedAddress(address(0x39608b6f20704889C51C0Ae28b1FCA8F36A5239b));
        blacklistPreloadedAddress(address(0x136F4B5b6A306091b280E3F251fa0E21b1280Cd5));
        blacklistPreloadedAddress(address(0x4aEB32e16DcaC00B092596ADc6CD4955EfdEE290));
        blacklistPreloadedAddress(address(0xe986d48EfeE9ec1B8F66CD0b0aE8e3D18F091bDF));
        blacklistPreloadedAddress(address(0x59341Bc6b4f3Ace878574b05914f43309dd678c7));
        blacklistPreloadedAddress(address(0xc496D84215d5018f6F53E7F6f12E45c9b5e8e8A9));
        blacklistPreloadedAddress(address(0xfe9d99ef02E905127239E85A611c29ad32c31c2F));
        blacklistPreloadedAddress(address(0x9eDD647D7d6Eceae6bB61D7785Ef66c5055A9bEE));
        blacklistPreloadedAddress(address(0x72b30cDc1583224381132D379A052A6B10725415));
        blacklistPreloadedAddress(address(0x7100e690554B1c2FD01E8648db88bE235C1E6514));
        blacklistPreloadedAddress(address(0x000000917de6037d52b1F0a306eeCD208405f7cd));
        blacklistPreloadedAddress(address(0x59903993Ae67Bf48F10832E9BE28935FEE04d6F6));
        blacklistPreloadedAddress(address(0x00000000000003441d59DdE9A90BFfb1CD3fABf1));
        blacklistPreloadedAddress(address(0x0000000000007673393729D5618DC555FD13f9aA));
        blacklistPreloadedAddress(address(0xA3b0e79935815730d942A444A84d4Bd14A339553));
        blacklistPreloadedAddress(address(0x000000005804B22091aa9830E50459A15E7C9241));
        blacklistPreloadedAddress(address(0x323b7F37d382A68B0195b873aF17CeA5B67cd595));
        blacklistPreloadedAddress(address(0x6dA4bEa09C3aA0761b09b19837D9105a52254303));
        blacklistPreloadedAddress(address(0x000000000000084e91743124a982076C59f10084));
        blacklistPreloadedAddress(address(0x1d6E8BAC6EA3730825bde4B005ed7B2B39A2932d));
        blacklistPreloadedAddress(address(0xfad95B6089c53A0D1d861eabFaadd8901b0F8533));
        blacklistPreloadedAddress(address(0x9282dc5c422FA91Ff2F6fF3a0b45B7BF97CF78E7));
        blacklistPreloadedAddress(address(0x45fD07C63e5c316540F14b2002B085aEE78E3881));
        blacklistPreloadedAddress(address(0xDC81a3450817A58D00f45C86d0368290088db848));
        blacklistPreloadedAddress(address(0xFe76f05dc59fEC04184fA0245AD0C3CF9a57b964));
        blacklistPreloadedAddress(address(0xd7d3EE77D35D0a56F91542D4905b1a2b1CD7cF95));
        blacklistPreloadedAddress(address(0xa1ceC245c456dD1bd9F2815a6955fEf44Eb4191b));
        blacklistPreloadedAddress(address(0xe516bDeE55b0b4e9bAcaF6285130De15589B1345));
        blacklistPreloadedAddress(address(0xE031b36b53E53a292a20c5F08fd1658CDdf74fce));
        blacklistPreloadedAddress(address(0x65A67DF75CCbF57828185c7C050e34De64d859d0));
        blacklistPreloadedAddress(address(0x7589319ED0fD750017159fb4E4d96C63966173C1));
        blacklistPreloadedAddress(address(0x0000000099cB7fC48a935BcEb9f05BbaE54e8987));
        blacklistPreloadedAddress(address(0x03BB05BBa541842400541142d20e9C128Ba3d17c));
    }

    function name() public pure returns (string memory) {
        return _name;
    }

    function symbol() public pure returns (string memory) {
        return _symbol;
    }

    function decimals() public pure returns (uint8) {
        return _decimals;
    }

    function totalSupply() public view override returns (uint256) {
        return _tTotal;
    }

    function balanceOf(address account) public view override returns (uint256) {
        return _balances[account];
    }

    function transfer(address recipient, uint256 amount) external override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) external override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) external override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) external virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) external virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));
        return true;
    }

    function includeInFee(address _address) external onlyOwner {
        _includedInFees.push(_address);

        emit FeeAppliedTo(_address);
    }

    function isIncludedInFees(address _address) public view returns(bool) {
        for(uint i = 0; i < _includedInFees.length; i++) {
            if(_includedInFees[i] == _address) {
                return true;
            }
        }

        return false;
    }

    function excludeFromFee(address _address) external onlyOwner {
        for(uint i = 0; i < _includedInFees.length; i++) {
            if(_includedInFees[i] == _address) {
                _includedInFees[i] = _includedInFees[_includedInFees.length - 1];
                _includedInFees[_includedInFees.length - 1] = address(0x0);
                _includedInFees.pop();

                emit FeeExcludedFrom(_address);
                break;
            }
        }
    }

    function setUniswapRouter(address _router) external onlyOwner {
        require(_router != address(0x0), "Invalid address");
        uniswapV2Router = IUniswapV2Router02(_router);

        emit SwapRouterUpdated(_router);
    }

    function requestPairSwitch(address _pair) external onlyOwner {
        require(_pair != address(0x0), "Invalid address");
        pendingUniswapV2Pair = _pair;
        previousUniswapV2Pair = uniswapV2Pair;
        pairSwitchUnlockTimestamp = now + 7 days;
        pairSwitchPossible = true;
        emit SwapPairRequested(_pair, pairSwitchUnlockTimestamp);
    }

    function setUniswapPairToPending() external onlyOwner {
        require(pairSwitchPossible, "Cannot update pair - requestPairSwitch has not been called.");
        require(now > pairSwitchUnlockTimestamp, "Cannot update pair - required unlock time period has not yet passed.");

        uniswapV2Pair = pendingUniswapV2Pair;
        emit SwapPairUpdated(pendingUniswapV2Pair);
    }

    function revertToPreviousPair() external onlyOwner {
        require(pairSwitchPossible, "Cannot update pair - requestPairSwitch has not been called.");
        require(now > pairSwitchUnlockTimestamp, "Cannot update pair - required unlock time period has not yet passed.");

        uniswapV2Pair = previousUniswapV2Pair;
        emit SwapPairUpdated(uniswapV2Pair);
    }

    function lockPairSwitching() external onlyOwner {
        pairSwitchPossible = false;
        emit SwapPairLocked(uniswapV2Pair);
    }

    function setBridgeAddress(address _bridge) external onlyOwner {
        require(_bridge != address(0x0), "Invalid address");
        bridge = _bridge;

        emit BridgeAddressUpdated(_bridge);
    }

    function setTaxFeePercent(uint256 taxFee) external onlyOwner() {
        require(taxFee <= 2, "Input number between 0 - 2");
        _taxFee = taxFee;

        emit TaxUpdated(taxFee);
    }

    function setMaxTxPercent(uint256 maxTxPercent) external onlyOwner() {
        require(maxTxPercent >= 1, "Anti-whale limitations cannot fall below 1%/supply per Tx.");
        maxTxAmount = _tTotal.mul(maxTxPercent).div(
            10**2
        );

        emit MaxTxPercentUpdated(maxTxPercent);
    }

    function setConvertMinimum(uint256 _numTokensSwap) external onlyOwner {
        require(_numTokensSwap < 500000, "Minimum token conversion amount cannot exceed 500,000 tokens!");
        require(_numTokensSwap > 500, "Minimum token conversion amount cannot be under 500 tokens!");
        numTokensSwap = _numTokensSwap * 10**9;
        emit MinTokensBeforeSwapUpdated(numTokensSwap);
    }

    function setDevWallet(address payable newWallet) external onlyOwner {
        require(newWallet != address(0x0), "Invalid address");
        require(devWallet != newWallet, "Wallet already set!");
        devWallet = payable(newWallet);

        emit DevWalletChanged(newWallet);
    }

    function setSwapEnabled(bool enabled) external onlyOwner {
        SwapTokensEnabled = enabled;
        emit SwapTokensEnabledUpdated(enabled);
    }

    function setGlobalTradingEnabled() external onlyOwner {
        globalTradingEnabled = true;
        emit GlobalTradingEnabled();
    }

    //to receive ETH from uniswapV2Router when swapping
    receive() external payable {}

    function _getValues(uint256 tAmount) private view returns (uint256, uint256) {
        uint256 tFee = calculateTaxFee(tAmount);
        uint256 tTransferAmount = tAmount.sub(tFee);
        return (tTransferAmount, tFee);
    }


    function _takeFee(uint256 tFee) private {
        _balances[address(this)] = _balances[address(this)].add(tFee);
    }

    function calculateTaxFee(uint256 _amount) private view returns (uint256) {
        return _amount.mul(_taxFee).div(
            10**2
        );
    }

    function removeAllFee() private {
        if(_taxFee == 0) return;

        _previousTaxFee = _taxFee;
        _taxFee = 0;
    }

    function restoreAllFee() private {
        _taxFee = _previousTaxFee;
    }

    function _approve(address owner, address spender, uint256 amount) private {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) private globalTradingStarted {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        require(!isInBlacklist(from) && !isInBlacklist(to) && !isInBlacklist(tx.origin),
            "This address is blacklisted. Please contact DOGIRA Support if you believe this is in error.");

        require(amount > 0, "Transfer amount must be greater than zero");
        if(from != owner() && to != owner())
            require(amount <= maxTxAmount, "Transfer amount exceeds the maxTxAmount.");

        uint256 contractTokenBalance = balanceOf(address(this));

        if(contractTokenBalance >= maxTxAmount)
        {
            contractTokenBalance = maxTxAmount;
        }

        bool overMinTokenBalance = contractTokenBalance >= numTokensSwap;
        if (
            overMinTokenBalance &&
            !inSwapTokens &&
            from != uniswapV2Pair &&
            SwapTokensEnabled
        ) {
            contractTokenBalance = numTokensSwap;
            swapTokens(contractTokenBalance);
        }

        //indicates if fee should be deducted from transfer
        bool takeFee = false;

        //if any non-owner/contract account belongs to _isIncludedInFees account then fee will be applied
        if(from != owner() && to != owner() && from != address(this) && to != address(this)) {
            if(isIncludedInFees(from) || isIncludedInFees(to)){
                takeFee = true;
            }
        }


        //transfer amount, take fee if applicable
        _tokenTransfer(from,to,amount,takeFee);
    }

    function swapTokens(uint256 contractTokenBalance) private lockTheSwap {
        uint256 initialBalance = address(this).balance;

        // swap tokens for ETH
        uint256 toSwapForEth = contractTokenBalance;
        swapTokensForEth(toSwapForEth);

        // how much ETH did we just swap into?
        uint256 fromSwap = address(this).balance.sub(initialBalance);

        emit TokenSwapped(toSwapForEth, fromSwap);

        devWallet.transfer(fromSwap);
    }

    function swapTokensForEth(uint256 tokenAmount) private {
        // generate the uniswap pair path of token -> weth
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = uniswapV2Router.WETH();

        _approve(address(this), address(uniswapV2Router), tokenAmount);

        // make the swap
        uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokenAmount,
            0, // accept any amount of ETH
            path,
            address(this),
            block.timestamp
        );
    }

    //this method is responsible for taking all fee, if takeFee is true
    function _tokenTransfer(address sender, address recipient, uint256 amount,bool takeFee) private {
        if(!takeFee)
            removeAllFee();

        _transferStandard(sender, recipient, amount);

        if(!takeFee)
            restoreAllFee();
    }

    function _transferStandard(address sender, address recipient, uint256 tAmount) private {
        (uint256 tTransferAmount, uint256 tFee) = _getValues(tAmount);
        _balances[sender] = _balances[sender].sub(tAmount);
        _balances[recipient] = _balances[recipient].add(tTransferAmount);
        _takeFee(tFee);

        _moveDelegates(sender, recipient, tTransferAmount, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    // Blacklist Lock & Unlock functions.
    // Unlocking the blacklist requires a minimum of 3 days notice.
    function unlockBlacklist(bool _limitedBlacklist, uint _daysUntilUnlock) external onlyOwner {
        require(_daysUntilUnlock > 2, "Unlocking blacklist functionality requires a minimum of 3 days notice.");
        blacklistUnlockTimestamp = now + (_daysUntilUnlock * 60 * 60 * 24);
        limitedBlacklist = _limitedBlacklist;
        blacklistPossible = true;
        emit BlacklistUnlockCalled(blacklistUnlockTimestamp, _daysUntilUnlock, limitedBlacklist);
    }

    function lockBlacklist() external onlyOwner {
        blacklistPossible = false;
        _currentBlacklistings = 0;
        emit BlacklistLockCalled(now);
    }

    function addToBlacklist(address _address) external onlyOwner {
        require(blacklistPossible, "Blacklisting is currently locked.");
        require(now > blacklistUnlockTimestamp, "Blacklisting is enabled, but currently timelocked.");
        require(!isInBlacklist(_address), "This address is already blacklisted.");
        if (limitedBlacklist) {
            require(_currentBlacklistings <= _maxBlacklistings, "Blacklisting limit reached, re-lock and timed unlock required.");
        }
        require(_address != address(0x0), "Invalid address");
        require(_address != address(this) && _address != owner() && _address != address(uniswapV2Router) && _address != uniswapV2Pair && _address != bridge, "this address cannot be blocked");

        blacklist.push(_address);
        _currentBlacklistings++;
        emit Blacklisted(_address, _currentBlacklistings);
    }

    // Function is only called within the constructor, and cannot be called after this contract is launched.
    // This is used solely to preload the Blacklist with known flashbots and frontrunners.
    function blacklistPreloadedAddress(address _address) private {
        blacklist.push(_address);
        _currentBlacklistings++;
    }

    function checkBlacklistUnlockTime() external view returns(uint256) {
        require(blacklistPossible, "Blacklisting is locked, no unlock time available.");
        return blacklistUnlockTimestamp;
    }

    function removeFromBlacklist(address _address) external onlyOwner {
        require(isInBlacklist(_address), "This address is not blacklisted.");
        for(uint i = 0; i < blacklist.length; i++) {
            if(blacklist[i] == _address) {
                blacklist[i] = blacklist[blacklist.length - 1];
                blacklist[blacklist.length - 1] = address(0x0);
                blacklist.pop();
                break;
            }
        }

        emit Unblacklisted(_address);
    }

    function isInBlacklist(address _address) public view returns (bool){
        for(uint i = 0; i < blacklist.length; i++) {
            if(blacklist[i] == _address) {
                return true;
            }
        }

        return false;
    }

    function transferERC20(address tokenAddress, address ownerAddress, uint tokens) external onlyOwner returns (bool success) {
        return IERC20(tokenAddress).transfer(ownerAddress, tokens);
    }


    /**
     * @notice Delegate votes from `msg.sender` to `delegatee`
     * @param delegator The address to get delegatee for
     */
    function delegates(address delegator)
    external
    view
    returns (address)
    {
        return _delegates[delegator];
    }

    /**
     * @notice Delegate votes from `msg.sender` to `delegatee`
     * @param delegatee The address to delegate votes to
     */

    function delegate(address delegatee) external {
        return _delegate(msg.sender, delegatee);
    }

    /**
     * @notice Delegates votes from signatory to `delegatee`
     * @param delegatee The address to delegate votes to
     * @param nonce The contract state required to match the signature
     * @param expiry The time at which to expire the signature
     * @param v The recovery byte of the signature
     * @param r Half of the ECDSA signature pair
     * @param s Half of the ECDSA signature pair
     */
    function delegateBySig(
        address delegatee,
        uint nonce,
        uint expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
    external
    {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name())),
                getChainId(),
                address(this)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(
                DELEGATION_TYPEHASH,
                delegatee,
                nonce,
                expiry
            )
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                structHash
            )
        );

        address signatory = ecrecover(digest, v, r, s);
        require(signatory != address(0), "DOGIRA::delegateBySig: invalid signature");
        require(nonce == nonces[signatory]++, "DOGIRA::delegateBySig: invalid nonce");
        require(now <= expiry, "DOGIRA::delegateBySig: signature expired");
        return _delegate(signatory, delegatee);
    }

    /**
     * @notice Gets the current votes balance for `account`
     * @param account The address to get votes balance
     * @return The number of current votes for `account`
     */
    function getCurrentVotes(address account)
    external
    view
    returns (uint256)
    {
        uint32 nCheckpoints = numCheckpoints[account];
        return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;
    }

    /**
     * @notice Determine the prior number of votes for an account as of a block number
     * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.
     * @param account The address of the account to check
     * @param blockNumber The block number to get the vote balance at
     * @return The number of votes the account had as of the given block
     */
    function getPriorVotes(address account, uint blockNumber)
    external
    view
    returns (uint256)
    {
        require(blockNumber < block.number, "DOGIRA::getPriorVotes: not yet determined");

        uint32 nCheckpoints = numCheckpoints[account];
        if (nCheckpoints == 0) {
            return 0;
        }

        // First check most recent balance
        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {
            return checkpoints[account][nCheckpoints - 1].votes;
        }

        // Next check implicit zero balance
        if (checkpoints[account][0].fromBlock > blockNumber) {
            return 0;
        }

        uint32 lower = 0;
        uint32 upper = nCheckpoints - 1;
        while (upper > lower) {
            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow
            Checkpoint memory cp = checkpoints[account][center];
            if (cp.fromBlock == blockNumber) {
                return cp.votes;
            } else if (cp.fromBlock < blockNumber) {
                lower = center;
            } else {
                upper = center - 1;
            }
        }
        return checkpoints[account][lower].votes;
    }

    function _delegate(address delegator, address delegatee)
    internal
    {
        address currentDelegate = _delegates[delegator];
        uint256 delegatorBalance = balanceOf(delegator); // balance of underlying DOGIRAs (not scaled);
        _delegates[delegator] = delegatee;

        emit DelegateChanged(delegator, currentDelegate, delegatee);

        _moveDelegates(currentDelegate, delegatee, delegatorBalance, 0);
    }

    function _moveDelegates(address srcRep, address dstRep, uint256 amount, uint256 fee) internal {
        if (srcRep != dstRep && amount > 0) {
            if (srcRep != address(0)) {
                // decrease old representative
                uint32 srcRepNum = numCheckpoints[srcRep];
                uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;
                uint256 srcRepNew = srcRepOld.sub(amount).sub(fee);
                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);
            }

            if (dstRep != address(0)) {
                // increase new representative
                uint32 dstRepNum = numCheckpoints[dstRep];
                uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;
                uint256 dstRepNew = dstRepOld.add(amount);
                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);
            }
        }
    }

    function _writeCheckpoint(
        address delegatee,
        uint32 nCheckpoints,
        uint256 oldVotes,
        uint256 newVotes
    )
    internal
    {
        uint32 blockNumber = safe32(block.number, "DOGIRA::_writeCheckpoint: block number exceeds 32 bits");

        if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {
            checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;
        } else {
            checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);
            numCheckpoints[delegatee] = nCheckpoints + 1;
        }

        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);
    }

    function safe32(uint n, string memory errorMessage) internal pure returns (uint32) {
        require(n < 2**32, errorMessage);
        return uint32(n);
    }


    function getChainId() internal pure returns (uint) {
        uint256 chainId;
        assembly { chainId := chainid() }
        return chainId;
    }

}