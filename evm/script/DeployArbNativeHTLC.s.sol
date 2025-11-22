// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ArbNativeHTLC} from "../src/swap/ArbNativeHTLC.sol";

contract DeployArbNativeHTLC is Script {
    function run(address token) external {
        // uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast();

        bytes32 salt = keccak256(abi.encode("arbNativeHTLC"));
        address x = address(new ArbNativeHTLC{salt: salt}());
        console.log("The address is ", x);

        vm.stopBroadcast();
    }
}
