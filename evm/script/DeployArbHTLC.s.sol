// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ArbHTLC} from "../src/swap/ArbHTLC.sol";

contract DeployArbHTLC is Script {
    function run(address token) external {
        // uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast();

        bytes32 salt = keccak256(abi.encode("gardenfinance_arb_wbtc_1_stage_registryTest"));
        address x = address(new ArbHTLC{salt: salt}());
        console.log("The address is ", x);

        ArbHTLC(x).initialise(token);
        vm.stopBroadcast();
    }
}
