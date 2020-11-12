// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

import "@openzeppelin/contracts/token/ERC20/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract EdgewareToken is ERC20Burnable, Ownable {
function c_0xaf6c6b15(bytes32 c__0xaf6c6b15) public pure {}


    address private _bridge;
    address private _owner;

    modifier onlyBridgeAndOwner() {c_0xaf6c6b15(0xdb5b6f639c0a1122b1d7d422b20eb75a4e775ac15794089b09cbfa7270382c42); /* function */ 

c_0xaf6c6b15(0x19927396bbd97496669a59a9ae27c7c4178ea56b5a8fc96c55312d8b372a2951); /* line */ 
        c_0xaf6c6b15(0x722ed5297c4c1d4bc93646d76082ba2c58cec9bf36d3cf1e1a437debdaceb8a3); /* assertPre */ 
c_0xaf6c6b15(0x16369e01fa9548316b70c4f1679618ab87cad37a955e8783cd9008aee9c27083); /* statement */ 
require(
            msg.sender == _owner || msg.sender == _bridge,
            "Only owner or Bridge owner can call this function."
        );c_0xaf6c6b15(0xc12c0c94fd31fd82671d99b14173298d2184f59799e10c03156973b44ccab9fc); /* assertPost */ 

c_0xaf6c6b15(0x419755d74ad13e0e30388c6775df59b8f2422909e21c35c304ad91e6c9bdbfbf); /* line */ 
        _;
    }

    constructor(string memory name, string memory symbol)
        public
        ERC20Burnable()
        ERC20(name, symbol)
    {c_0xaf6c6b15(0x8f79e84f73f76222d6f36f103640ba1ecf9d5ec6891ccb9771221cb119d5012a); /* function */ 

c_0xaf6c6b15(0x1abe532ad024ab5e759f31a00fb8952ed3ad6cb28315c6772edb20104d59d336); /* line */ 
        c_0xaf6c6b15(0x9a4e50b5951b86af4033e17b7fe75c7e65d2d4b872eaa74f1784fb60aea86c8b); /* statement */ 
_owner = msg.sender;
    }

    function mintFor(address receiver, uint256 amount)
        public
        onlyBridgeAndOwner()
        returns (bool)
    {c_0xaf6c6b15(0x6fc321fd4d4bd7dce5fa55a03f0a1d8c5185ed3cefae397488dea7491abbeb1a); /* function */ 

c_0xaf6c6b15(0x76e3f8ad31e0890146efb9b141d8730b3e137fe038c77b0a20def76b724d074e); /* line */ 
        c_0xaf6c6b15(0x35b74b7a45089dcc1d2c8778af5c0ab1d44bc30c5e541207948dde673ec6a045); /* statement */ 
_mint(receiver, amount);
c_0xaf6c6b15(0xd924e5116617ea02a2151e06f20b85919558096d2c9be008239a21e3098474e1); /* line */ 
        c_0xaf6c6b15(0xc00bcfa197561b32284ece7fa816638a1effb6cad39fdc9ce70b1550a18b334c); /* statement */ 
return true;
    }

    function burn(address account, uint256 amount)
        public
        onlyBridgeAndOwner()
        returns (bool)
    {c_0xaf6c6b15(0xb635d2cb0a0de86fc3ba8f8e05b7b19793d9da5ea07005f83f7c0ff73bd8af18); /* function */ 

c_0xaf6c6b15(0x040d5edc7912b901c71bf63d54e875a37210059f8e21a168fe1ad40f2d65a421); /* line */ 
        c_0xaf6c6b15(0xb69c37b82777aa25a358b615d589c5cc06447ee51c1ea295d606635727fa0c49); /* statement */ 
burnFrom(account, amount);
c_0xaf6c6b15(0x6e111b1542c196525457afe03d0f6250602932f04c1cecd013e14c4101c7a853); /* line */ 
        c_0xaf6c6b15(0x80693acfab342dd29849a3c0cbde3cca976dab363f0ae7e4892de6c8cb9394b6); /* statement */ 
return true;
    }

    function setBridgeAddress(address bridge) public onlyOwner {c_0xaf6c6b15(0x09dbb611e878b330ff9378c361ea6eba342309f41576cd34ee6d47473833ee5e); /* function */ 

c_0xaf6c6b15(0x130206ab997c96b5a4f0ede2255d65994b45c768baccb48d623bf1fe4b90003f); /* line */ 
        c_0xaf6c6b15(0xc5413ea8fa6e4e4432b84af7a505f671e7235d42139856e365ea3fa432642315); /* statement */ 
_bridge = bridge;
    }
}
