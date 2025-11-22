# Known Issues  
### EVM  
- In `ArbHTLC` and `HTLC` contracts, user can redeem after `block.number + timelock` value expires.  
- Unused parameter `destinationData` in `HTLC` and `ArbHTLC` contracts. It is required for event logs for off-chain verification of destination swap information.    
- Centralization risk in `HTLCRegistry` contract. The ownership is present only to set implementation contract addresses for the UDAs and to set valid HTLC addresses.
- No timelock validation provided: timelock can be set to an unreasonably large value, risking indefinite fund locks    
  
### Solana  
- The PDA for the swap data is closed after the swap is complete, so creating a duplicate order will be possible  
- User can redeem after `expiry_slot` has been reached    
- Missing validation for zero values: No checks prevent swap_amount from being set to 0 or zero-address values from being passed  
- No timelock validation provided: timelock can be set to an unreasonably large value, risking indefinite fund locks  
  
### Sui  
- The chain ID is hardcoded in the `create_order_id` function. To avoid same order ID generation in testnet and mainnet, we manually change it before deployment.  
  
### Starknet  
- User can redeem after the timelock expires, similar to EVM.
- No timelock validation provided: timelock can be set to an unreasonably large value, risking indefinite fund locks  