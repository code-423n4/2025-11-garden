// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {NativeHTLC} from "../src/swap/NativeHTLC.sol";

contract DeployNativeHTLC is Script {
    function run() external {
        // uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast();

        bytes32 salt = keccak256(abi.encode("gardenfinance_eth_native_1_stage"));
        // this is for sepolia testnet for aave
        address x = address(new NativeHTLC{salt: salt}());
        console.log("The address is ", x);

        vm.stopBroadcast();
    }
}
