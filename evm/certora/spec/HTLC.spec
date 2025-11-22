methods {
    function _initiateExternal(address funder, address initiator, address redeemer, uint256 timelock, uint256 amount, bytes32 secretHash) external;
}

rule noDuplicateOrders(address funder, address initiator, address redeemer, uint256 timelock, uint256 amount, bytes32 secretHash) {
    env e;
    require(e.msg.value == 0);
    require(funder != 0 && initiator != 0 && redeemer != 0);
    _initiateExternal(e, funder, initiator, redeemer, timelock, amount, secretHash);

    _initiateExternal@withrevert(e, funder, initiator, redeemer, timelock, amount, secretHash);

    assert lastReverted;
}

rule noDuplicateSecretHash(address funder, address initiator, address redeemer, uint256 timelock, uint256 amount, bytes32 secretHash, address initiator2) {
    env e1; env e2;
    require amount < max_uint128;
    require e1.msg.value == 0;
    require e2.msg.value == 0;
    require funder != 0 && initiator != 0 && redeemer != 0 && initiator2 != 0 && initiator != initiator2 && initiator != redeemer && initiator2 != redeemer;
    _initiateExternal(e1, funder, initiator, redeemer, timelock, amount, secretHash);

    _initiateExternal@withrevert(e2, funder, initiator2, redeemer, timelock, amount, secretHash);

    assert !lastReverted;
}