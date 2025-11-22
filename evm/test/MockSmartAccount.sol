// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MockSmartAccount is IERC1271 {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        if (msg.sender.code.length > 0) {
            return this.isValidSignature.selector;
        }
        return 0x00000000;
    }

    function approve(address token, address addr) public {
        IERC20(token).approve(addr, type(uint256).max);
    }
}
