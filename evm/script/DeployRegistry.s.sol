// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {HTLCRegistry} from "../src/swap/HTLCRegistry.sol";
import {NativeUniqueDepositAddress} from "../src/swap/UDA.sol";

contract DeployHTLCRegistryScript is Script {
    function run(address owner, address changeOwner) external {
        // uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast();

        bytes32 salt = keccak256(abi.encode("gardenfinance_eth_HTLCRegistry_2"));
        // this is for sepolia testnet for aave
        address x = address(new HTLCRegistry{salt: salt}(owner));
        console.log("The address of Registry is ", x);

        address nativeUDA = address(new NativeUniqueDepositAddress());
        HTLCRegistry(x).setImplNativeUDA(address(nativeUDA));

        HTLCRegistry(x).transferOwnership(changeOwner);

        console.log("The address of Native UDA is ", nativeUDA);

        vm.stopBroadcast();
    }
}
