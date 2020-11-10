// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract EdgewareToken is ERC20 {

    address private _bridge;
    address private _owner;

    modifier onlyBridgeAndOwner() {
        require(
            msg.sender == _owner || msg.sender == _bridge,
            "Only owner or Bridge owner can call this function."
        );
        _;
    }

    constructor(string memory name, string memory symbol)
        public
        ERC20(name, symbol)
    {
        _owner = msg.sender;
    }

    function mint(address receiver, uint256 amount)
        public
        onlyBridgeAndOwner()
        returns (bool)
    {
        _mint(receiver, amount);
        return true;
    }

    function burn(address account, uint256 amount)
        public
        onlyBridgeAndOwner()
        returns (bool)
    {
        _burn(account, amount);
        return true;
    }
}
