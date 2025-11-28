_Note: Not all issues are guaranteed to be correct._

# Denial-of-Service: Fixed-Gas Stipend Transfers Can Permanently Lock Funds

## Targets
- recover (UniqueDepositAddress)
- refund (NativeHTLC)
- instantRefund (NativeHTLC)
- redeem (ArbNativeHTLC)
- refund and instantRefund (ArbNativeHTLC)
- recover (NativeUniqueDepositAddress)
- redeem, refund, instantRefund (ArbNativeHTLC)
- instantRefund (ArbNativeHTLC)
- instantRefund, redeem, refund (NativeHTLC)

## Description

Multiple contracts (UniqueDepositAddress, NativeUniqueDepositAddress, NativeHTLC, ArbNativeHTLC) use Solidity’s address.transfer to push ETH to user-specified addresses (refundAddress, initiator, redeemer). Because .transfer enforces a 2,300-gas stipend and reverts on any failure, a recipient contract with a gas-hungry or reverting fallback/receive function will cause the transfer (and its enclosing function) to revert. No alternative pull, rescue, or fallback mechanism exists to recover locked ETH.

## Root cause

Reliance on Solidity’s .transfer, which forwards only a fixed 2,300 gas stipend and automatically reverts on failure, without validating recipient compatibility or providing a pull-pattern or rescue mechanism for failed transfers.

## Impact

An attacker (or even an unwitting user) can deploy or use a recipient contract whose fallback/receive logic consumes more than 2,300 gas or explicitly reverts. This will cause any push-style transfer (recover, refund, instantRefund, redeem) to revert, resulting in permanent denial-of-service and trapping of ETH within the contract with no path for recovery.