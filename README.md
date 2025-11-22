

# Scope

*See [scope.txt](https://github.com/code-423n4/2025-11-garden/blob/main/scope.txt)*

### Files in scope


| File   | Logic Contracts | Interfaces | nSLOC | Purpose | Libraries used |
| ------ | --------------- | ---------- | ----- | -----   | ------------ |
| /evm/src/swap/ArbHTLC.sol | 1| 1 | 144 | |@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol<br>@openzeppelin/contracts/utils/cryptography/EIP712.sol<br>@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol|
| /evm/src/swap/ArbNativeHTLC.sol | 1| 1 | 127 | |@openzeppelin/contracts/utils/cryptography/EIP712.sol<br>@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol|
| /evm/src/swap/HTLC.sol | 1| **** | 142 | |@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol<br>@openzeppelin/contracts/utils/cryptography/EIP712.sol<br>@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol|
| /evm/src/swap/HTLCRegistry.sol | 1| **** | 112 | |@openzeppelin/contracts/proxy/Clones.sol<br>@openzeppelin/contracts/utils/Address.sol<br>@openzeppelin/contracts/access/Ownable.sol<br>@openzeppelin/contracts/token/ERC20/IERC20.sol|
| /evm/src/swap/NativeHTLC.sol | 1| **** | 125 | |@openzeppelin/contracts/utils/cryptography/EIP712.sol<br>@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol|
| /evm/src/swap/UDA.sol | 2| **** | 71 | |@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol<br>@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol<br>@openzeppelin/contracts/proxy/Clones.sol|
| /solana/solana-native/programs/solana-native-swaps/src/lib.rs | ****| **** | 260 | ||
| /solana/solana-spl-swaps/programs/solana-spl-swaps/src/lib.rs | ****| **** | 378 | ||
| /starknet/src/htlc.cairo | ****| **** | 328 | ||
| /starknet/src/interface/events.cairo | ****| **** | 27 | ||
| /starknet/src/interface/sn_domain.cairo | ****| **** | 23 | ||
| /starknet/src/interface/struct_hash.cairo | ****| **** | 87 | ||
| /starknet/src/interface.cairo | ****| **** | 60 | ||
| /starknet/src/lib.cairo | ****| **** | 2 | ||
| /sui/sources/main.move | ****| **** | 277 | ||
| **Totals** | **7** | **2** | **2163** | | |

### Files out of scope

*See [out_of_scope.txt](https://github.com/code-423n4/2025-11-garden/blob/main/out_of_scope.txt)*

| File         |
| ------------ |
| ./evm/certora/HTLCHarness.sol |
| ./evm/script/DeployArbHTLC.s.sol |
| ./evm/script/DeployArbNativeHTLC.s.sol |
| ./evm/script/DeployNativeHTLC.s.sol |
| ./evm/script/DeployRegistry.s.sol |
| ./evm/script/deployHTLC.s.sol |
| ./evm/test/HTLC.t.sol |
| ./evm/test/HTLCRegistry.t.sol |
| ./evm/test/MockSmartAccount.sol |
| ./evm/test/NativeHTLC.t.sol |
| ./sui/tests/test.move |
| Totals: 11 |

