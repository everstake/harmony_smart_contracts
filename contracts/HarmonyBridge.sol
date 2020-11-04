pragma solidity ^0.6.0;
pragma experimental ABIEncoderV2;

import "./IERC20.sol";
import "./SafeMath.sol";


contract Bridge {
    using SafeMath for uint256;
    
    mapping(address => uint256) public tokenBalances;
    mapping(address => bool) public tokens;
    mapping(address => bool) public validators;
    mapping(address => bool) public workers;
    mapping(address => uint256) public dailyLimit;
    mapping(address => uint256) public dailySpend;
    uint256 public fee;

    mapping(address => uint256) dailyLimitSetTime;
    uint256 signatureThreshold;
    uint256 maxvalidatorCount;
    uint256 txExpirationTime;
    address owner;
    uint256 transferNonce;
    
    event Transfer(
        string receiver,
        address sender,
        uint256 amount,
        address asset,
        uint256 transferNonce,
        uint256 timestamp
    );
    
    struct SwapMessage {
        uint256 chainId;
        address payable receiver;
        string sender;
        uint256 timestamp;
        uint256 amount;
        address asset;
        uint256 transferNonce;
    }
    
    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "Only owner can call this function."
        );
        _;
    }
    
    modifier onlyWorker() {
        require(
            workers[msg.sender],
            "Only worker can call this function."
        );
        _;
    }
    
    constructor(uint256 threshold, uint256 maxPermissibleValidatorCount, uint256 transferFee, uint256 coinDailyLimit) public {
        owner = msg.sender;
        signatureThreshold = threshold;
        maxvalidatorCount = maxPermissibleValidatorCount;
        fee = transferFee;
        txExpirationTime = 86400;  // 1 day by default
        dailyLimit[address(0)] = coinDailyLimit;
        dailyLimitSetTime[address(0)] = block.timestamp;
        transferNonce = 0;
    }
    
    function transferOwnership(address newOwner) public onlyOwner() {
        owner = newOwner;
    }
    
    function setFee(uint256 newFee) public onlyOwner() {
        fee = newFee;
    }
    
    function addValidator(address newValidator) public onlyOwner() {
        validators[newValidator] = true;
    }
    
    function removeValidator(address removedValidator) public onlyOwner() {
        validators[removedValidator] = false;
    }
    
    function addWorker(address newWorker) public onlyOwner() {
        workers[newWorker] = true;
    }
    
    function removeWorker(address removedWorker) public onlyOwner() {
        workers[removedWorker] = false;
    }
    
    function setThreshold(uint256 newSignaturesThreshold) public onlyOwner() {
        signatureThreshold = newSignaturesThreshold;
    }
    
    function addToken(address newToken, uint256 tokenDailyLimit) public onlyOwner() {
        tokens[newToken] = true;
        dailyLimit[newToken] = tokenDailyLimit;
        dailyLimitSetTime[newToken] = block.timestamp;
    }
    
    function removeToken(address removedToken) public onlyOwner() {
        tokens[removedToken] = false;
        dailyLimit[removedToken] = 0;
        dailyLimitSetTime[removedToken] = 0;
    }
    
    function setDailyLimit(uint256 newLimit, address assetLimited) public onlyOwner() {
        require(tokens[assetLimited], "There is no such an asset in the Bridge contract");
        dailyLimit[assetLimited] = newLimit;
    }
    
    function setTxExpirationTime(uint256 newTxExpirationTime) public onlyOwner() {
        txExpirationTime = newTxExpirationTime;
    }
    
    function checkAsset(address assetAddress) public view returns (bool) {
        if (assetAddress == address(0) || tokens[assetAddress]) {
            return true;
        } else {
            return false;
        }
    }

    function checkExpirationTime(uint256 txTime) private view returns (bool) {
        uint currentTime = block.timestamp;
        if (currentTime.sub(txTime) > txExpirationTime) {
            return false;
        } else {
            return true;
        }
    }
    
    function hashMessage(SwapMessage memory transferInfo) public pure returns (bytes32) {
        return keccak256(abi.encode(transferInfo.chainId, transferInfo.receiver, transferInfo.sender, transferInfo.timestamp, transferInfo.amount, transferInfo.asset, transferInfo.transferNonce));
    }
    
    function verifySignatures(bytes32 signedMessage, bytes[] memory signatures) private view returns (bool) {
        address[] memory signers = new address[](signatures.length);
        for (uint256 i=0; i<signatures.length; i++) {
            address signerAddress = recover(signedMessage, signatures[i]);
            if (!validators[signerAddress]) return false;
            if (i > 0) {
                if (!checkUnique(signerAddress, signers)) return false;
            }
            signers[i] = signerAddress;
        }
        return true;
    }
    
    function checkUnique(address signer, address[] memory allSigners) private pure returns (bool) {
        for (uint256 i=0; i < allSigners.length; i++) {
            if (signer == allSigners[i]) {
                return false;
            }
        }
        return true;
    }

    // DEV function, remove in future
    function getSigner(SwapMessage memory transferInfo, bytes memory signature) public pure returns (address) {
        bytes32 hashedMessage = hashMessage(transferInfo);
        address signerAddress = recover(hashedMessage, signature);
        return signerAddress;
    }
    
    function updateDailyLimit(address asset) private {
        uint256 currentTime = block.timestamp;
        if (currentTime.sub(dailyLimitSetTime[asset]) > 86400) {  // we don't check dailyLimitSetTime on zero because if execution came here token already in tokens mapp and dailyLimitSetTime also filled
            dailyLimitSetTime[asset] = currentTime;
            dailySpend[asset] = 0;
        }
    }
    
    function makeSwap(SwapMessage memory transferInfo) private returns (bool) {
        uint assetDailyLimit = dailyLimit[transferInfo.asset];
        
        require(assetDailyLimit > 0, "Can't transfer asset without daily limit");
        
        updateDailyLimit(transferInfo.asset);
        
        require(transferInfo.amount.add(dailySpend[transferInfo.asset]) <= assetDailyLimit, "Daily limit has already reached for this asset");

        dailySpend[transferInfo.asset] = dailySpend[transferInfo.asset].add(transferInfo.amount);
        
        if (transferInfo.asset == address(0)) {
            uint256 amountToSend = transferInfo.amount.sub(transferInfo.amount.mul(fee).div(100));
            require(transferInfo.receiver.send(amountToSend), "Error while transfer coins to the receiver");
        } else {
            uint256 amountToSend = transferInfo.amount.sub(transferInfo.amount.mul(fee).div(100));
            IERC20 assetContract = IERC20(transferInfo.asset);
            require(assetContract.mint(transferInfo.receiver, amountToSend), "Error while mint tokens for the receiver");
        }
        return true;
    }
    
    function requestSwap(SwapMessage memory transferInfo, bytes[] memory signatures) public onlyWorker() returns (bool) {
        require(checkExpirationTime(transferInfo.timestamp), "Transaction can't be sent because of expiration time");

        require(this.checkAsset(transferInfo.asset), "Unknown asset is trying to transfer");
        
        require(transferInfo.receiver == address(transferInfo.receiver),"Invalid receiver address");
        
        require(signatures.length >= signatureThreshold && signatures.length <= maxvalidatorCount, "Wrong count of signatures to make transfer");
        
        bytes32 signedMessage = this.hashMessage(transferInfo);
        require(verifySignatures(signedMessage, signatures), "Signatures verification is failed");
        
        bool res = makeSwap(transferInfo);
        return res;
    }

    function transferCoin(string memory receiver) public payable {
        require(msg.value > 0, "You have to attach some amount of assets to make transfer");
        transferNonce++;
        emit Transfer(receiver, msg.sender, msg.value, address(0), transferNonce, block.timestamp);
    }
    
    function transferToken(string memory receiver, uint amount, address asset) public {
        require(this.checkAsset(asset), "Unknown asset is trying to transfer");
        IERC20 assetContract = IERC20(asset);
        require(assetContract.balanceOf(msg.sender) >= amount, "Sender doesn't have enough tokens to make transfer");
        require(assetContract.burn(msg.sender, amount), "Error while burn sender's tokens");
        transferNonce++;
        
        emit Transfer(receiver, msg.sender, amount, asset, transferNonce, block.timestamp);
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            revert("ECDSA: invalid signature length");
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert("ECDSA: invalid signature 's' value");
        }

        if (v != 27 && v != 28) {
            revert("ECDSA: invalid signature 'v' value");
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");

        return signer;
    }
}