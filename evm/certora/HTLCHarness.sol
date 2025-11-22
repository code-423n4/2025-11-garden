//SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "../src/swap/HTLC.sol";

contract HTLCHarness is HTLC {
    constructor(address token_, string memory name_, string memory version_) HTLC(token_, name_, version_) {}
    function _initiateExternal(address funder, address initiator, address redeemer, uint256 timelock, uint256 amount, bytes32 secretHash) external {
        _initiate(funder, initiator, redeemer, timelock, amount, secretHash);
    }
}