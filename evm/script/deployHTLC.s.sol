// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {HTLC} from "../src/swap/HTLC.sol";

contract DeployHTLCScript is Script {
    function run(address token) external {
        // uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast();

        bytes32 salt = keccak256(abi.encode("gardenfinance_eth_wbtc_100011"));
        // this is for sepolia testnet for aave
        address x = address(new HTLC{salt: salt}());
        console.log("The address is ", x);

        HTLC(x).initialise(token);
        vm.stopBroadcast();
    }
}
