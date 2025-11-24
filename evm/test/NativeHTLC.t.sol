// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {NativeHTLC} from "../src/swap/NativeHTLC.sol";

contract NativeHTLCTest is Test {
    NativeHTLC public htlc;
    address public initiator;
    address public redeemer;
    uint256 public timelock;
    uint256 public amount;
    bytes32 public secretHash;
    bytes public secret;
    address payable alice;
    uint256 keyAlice;
    address payable bob;
    uint256 keyBob;
    address payable david;
    uint256 keyDavid;

    function setUp() public {
        // Deploy NativeHTLC contract
        htlc = new NativeHTLC();
        address addrAlice;
        address addrBob;
        address addrDavid;
        (addrAlice, keyAlice) = makeAddrAndKey("alice");
        (addrBob, keyBob) = makeAddrAndKey("bob");
        (addrDavid, keyDavid) = makeAddrAndKey("david");
        alice = payable(addrAlice);
        bob = payable(addrBob);
        david = payable(addrDavid);
        vm.deal(addrAlice, 1000);
        vm.deal(addrBob, 1000);
        vm.deal(addrDavid, 1000);
        secret = abi.encodePacked(keccak256("secret"));
        secretHash = sha256(secret);
        timelock = 100;
        amount = 10;
    }

    function test_RevertWithZeroAddressRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAddressRedeemer.selector);
        htlc.initiate{value: amount}(payable(address(0)), timelock, amount, secretHash);
    }

    function test_RevertWithZeroTimelock() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroTimelock.selector);
        htlc.initiate{value: amount}(bob, 0, amount, secretHash);
    }

    function test_RevertWithZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAmount.selector);
        htlc.initiate{value: 0}(bob, timelock, 0, secretHash);
    }

    function test_RevertWithNoMsgAmount() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__IncorrectFundsRecieved.selector);
        htlc.initiate(bob, timelock, amount, secretHash);
    }

    function test_RevertWithSameInitiatorAndRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__SameInitiatorAndRedeemer.selector);
        htlc.initiate{value: amount}(alice, timelock, amount, secretHash);
    }

    function test_RevertInitiateOnBehalfWithZeroAddressInitiator() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAddressInitiator.selector);
        htlc.initiateOnBehalf{value: amount}(
            payable(address(0)), bob, timelock, amount, secretHash, abi.encode("HELLO TRX 1")
        );
    }

    function test_RevertInitiateOnBehalfWithZeroAddressRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAddressRedeemer.selector);
        htlc.initiateOnBehalf{value: amount}(
            alice, payable(address(0)), timelock, amount, secretHash, abi.encode("HELLO TRX 1")
        );

        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAddressRedeemer.selector);
        htlc.initiateOnBehalf{value: amount}(alice, payable(address(0)), timelock, amount, secretHash);
    }

    function test_RevertInitiateOnBehalfWithZeroTimelock() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroTimelock.selector);
        htlc.initiateOnBehalf{value: amount}(alice, bob, 0, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_RevertInitiateOnBehalfWithZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAmount.selector);
        htlc.initiateOnBehalf{value: 0}(alice, bob, timelock, 0, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_RevertInitiateOnBehalfWithNoMsgAmount() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__IncorrectFundsRecieved.selector);
        htlc.initiateOnBehalf{value: 10}(alice, bob, timelock, 1, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_RevertInitiateOnBehalfWithSameInitiatorAndRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__SameInitiatorAndRedeemer.selector);
        htlc.initiateOnBehalf{value: amount}(alice, alice, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_RevertInitiateOnBehalfWithSameFunderAndRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__SameFunderAndRedeemer.selector);
        htlc.initiateOnBehalf{value: amount}(bob, alice, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));

        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__SameFunderAndRedeemer.selector);
        htlc.initiateOnBehalf{value: amount}(bob, alice, timelock, amount, secretHash);
    }

    function test_shouldRevertWhenInitiatorIsZeroAddress() public {
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAddressInitiator.selector);
        htlc.initiateOnBehalf{value: amount}(
            payable(address(0)), bob, timelock, amount, secretHash, abi.encode("HELLO TRX 1")
        );

        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__ZeroAddressInitiator.selector);
        htlc.initiateOnBehalf{value: amount}(payable(address(0)), bob, timelock, amount, secretHash);
    }

    function test_InitiateCorrectly() public {
        vm.startPrank(alice);
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectEmit(true, true, true, true);
        emit NativeHTLC.Initiated(orderID, secretHash, amount);
        htlc.initiate{value: amount}(bob, timelock, amount, secretHash);
        vm.stopPrank();
    }

    function test_InitiateCorrectlyWithDestinationData() public {
        vm.startPrank(alice);
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectEmit(true, true, true, true);
        emit NativeHTLC.InitiatedWithDestinationData(orderID, secretHash, amount, abi.encode("HELLO TRX 1"));
        htlc.initiate{value: amount}(bob, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
        vm.stopPrank();
    }

    function test_RevertInitiateForDuplicateOrder() public {
        test_InitiateCorrectly();
        vm.expectRevert(NativeHTLC.NativeHTLC__DuplicateOrder.selector);
        vm.prank(alice);
        htlc.initiateOnBehalf{value: amount}(alice, bob, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_InitiateOnBehalfCorrectly() public {
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit NativeHTLC.Initiated(orderID, secretHash, amount);
        htlc.initiateOnBehalf{value: amount}(alice, bob, timelock, amount, secretHash);
    }

    function test_RevertRedeemForUninitiatedOrder() public {
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectRevert(NativeHTLC.NativeHTLC__OrderNotInitiated.selector);
        htlc.redeem(orderID, secret);
    }

    function test_RevertRedeemWithInvalidSecret() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        bytes memory wrongSecret = "wrong secret";
        vm.expectRevert(NativeHTLC.NativeHTLC__IncorrectSecret.selector);
        htlc.redeem(orderID, wrongSecret);
    }

    function test_RevertRedeemForInsufficientBalance() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.deal(address(htlc), amount - 1);
        vm.expectRevert();
        htlc.redeem(orderID, secret);
    }

    function test_RedeemCorrectly() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectEmit(true, true, false, true);
        emit NativeHTLC.Redeemed(orderID, secretHash, secret);
        htlc.redeem(orderID, secret);
    }

    function test_RevertRedeemForFulfilledOrder() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        htlc.redeem(orderID, secret);
        vm.expectRevert(NativeHTLC.NativeHTLC__OrderFulfilled.selector);
        htlc.redeem(orderID, secret);
        vm.stopPrank();
    }

    function test_RevertDuplicateOrder() public {
        test_InitiateCorrectly();
        vm.prank(alice);
        vm.expectRevert(NativeHTLC.NativeHTLC__DuplicateOrder.selector);
        htlc.initiate{value: amount}(bob, timelock, amount, secretHash);
    }

    function test_RevertRefundForUninitiatedOrder() public {
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectRevert(NativeHTLC.NativeHTLC__OrderNotInitiated.selector);
        htlc.refund(orderID);
    }

    function test_RevertRefundForFulfilledOrder() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(bob);
        htlc.redeem(orderID, secret);
        vm.stopPrank();
        vm.expectRevert(NativeHTLC.NativeHTLC__OrderFulfilled.selector);
        htlc.refund(orderID);
    }

    function test_RevertRefundIfOrderNotExpired() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.roll(block.number + timelock);
        vm.expectRevert(NativeHTLC.NativeHTLC__OrderNotExpired.selector);
        htlc.refund(orderID);
    }

    function test_RefundCorrectly() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.roll(block.number + timelock + 1);
        vm.expectEmit(true, false, false, true);
        emit NativeHTLC.Refunded(orderID);
        htlc.refund(orderID);
    }

    function test_RevertInstantRefundWithInvalidSignature() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        //using initiator's key to sign, ideally redeemer's required
        vm.startPrank(alice);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectRevert(NativeHTLC.NativeHTLC__InvalidRedeemerSignature.selector);
        htlc.instantRefund(orderID, signature);
        vm.stopPrank();
    }

    function test_RevertInstantRefundForAlreadyFulfilledOrder() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(bob);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyBob, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        htlc.redeem(orderID, secret);
        vm.expectRevert(NativeHTLC.NativeHTLC__OrderFulfilled.selector);
        htlc.instantRefund(orderID, signature);
        vm.stopPrank();
    }

    function test_InstantRefundCorrectly() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(bob);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyBob, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectEmit(true, false, false, true);
        emit NativeHTLC.Refunded(orderID);
        htlc.instantRefund(orderID, signature);
        vm.stopPrank();
    }

    function testFuzz_SuccessfulSwapNative(
        uint256 _redeemerGen,
        uint256 _timelock,
        uint256 _amount,
        bytes memory _secret,
        bytes calldata _destinationData
    ) public {
        vm.assume(_secret.length == 32);
        vm.assume(
            _redeemerGen > 0
                && _redeemerGen < 115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address payable _redeemer = payable(vm.addr(_redeemerGen));
        vm.assume(
            _redeemer != address(0x0) && _redeemer != msg.sender && _redeemer != address(this)
                && _redeemer.code.length == 0
        );
        vm.assume(_timelock > 0 && _timelock < type(uint64).max);
        vm.assume(_amount > 0);
        vm.deal(address(this), _amount);
        htlc.initiateOnBehalf{value: _amount}(
            payable(msg.sender), _redeemer, _timelock, _amount, sha256(_secret), _destinationData
        );

        bytes32 orderID =
            sha256(abi.encode(block.chainid, sha256(_secret), msg.sender, _redeemer, _timelock, _amount, address(htlc)));

        // Check whether the order is created properly
        (
            address oInitiator,
            address oRedeemer,
            uint256 initiatedAt,
            uint256 oTimelock,
            uint256 oAmount,
            uint256 ofulfilledAt
        ) = htlc.orders(orderID);
        assertEq(oInitiator, msg.sender);
        assertEq(oRedeemer, _redeemer);
        assertEq(oTimelock, _timelock);
        assertEq(initiatedAt, block.number);
        assertEq(oAmount, _amount);
        assert(ofulfilledAt == 0);

        // Check if the redeemer has recieved funds
        uint256 redeemerBalanceBefore = _redeemer.balance;
        htlc.redeem(orderID, _secret);
        uint256 redeemerBalanceAfter = _redeemer.balance;
        assertEq(redeemerBalanceAfter - redeemerBalanceBefore, _amount);

        // Verify order is fulfilled
        (,,,,, uint256 time) = htlc.orders(orderID);
        assert(time != 0);
    }

    function testFuzz_RefundedSwapNative(
        uint256 _initiatorGen,
        address payable _redeemer,
        uint256 _timelock,
        uint256 _amount,
        bytes memory _secret,
        bytes calldata _destinationData
    ) public {
        vm.assume(
            _initiatorGen > 0
                && _initiatorGen < 115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        address payable _initiator = payable(vm.addr(_initiatorGen));
        vm.assume(
            _initiator != address(0x0) && _initiator != _redeemer && _initiator.code.length == 0
                && _initiator != msg.sender && _redeemer != address(this)
        );
        vm.assume(_redeemer != address(0x0) && _redeemer != msg.sender);
        vm.assume(_timelock > 0 && _timelock < type(uint16).max / 2);
        vm.assume(_amount > 0);

        vm.deal(address(this), _amount);
        htlc.initiateOnBehalf{value: _amount}(
            payable(_initiator), _redeemer, _timelock, _amount, sha256(_secret), _destinationData
        );

        bytes32 orderID =
            sha256(abi.encode(block.chainid, sha256(_secret), _initiator, _redeemer, _timelock, _amount, address(htlc)));

        // Check whether the order is created properly
        (
            address oInitiator,
            address oRedeemer,
            uint256 initiatedAt,
            uint256 oTimelock,
            uint256 oAmount,
            uint256 ofulfilledAt
        ) = htlc.orders(orderID);
        assertEq(oInitiator, _initiator);
        assertEq(oRedeemer, _redeemer);
        assertEq(oTimelock, _timelock);
        assertEq(initiatedAt, block.number);
        assertEq(oAmount, _amount);
        assertEq(ofulfilledAt, 0);

        // Fast forward past timelock
        vm.roll(block.number + _timelock + 1);
        // Check if the initiator gets refunded
        uint256 initiatorBalanceBefore = payable(_initiator).balance;
        htlc.refund(orderID);
        uint256 initiatorBalanceAfter = payable(_initiator).balance;
        assertEq(initiatorBalanceAfter - initiatorBalanceBefore, _amount);

        // Verify order is fulfilled
        (,,,,, uint256 time) = htlc.orders(orderID);
        assert(time != 0);
    }

    function testFuzz_InstantRefundNative(
        uint256 _initiatorKey,
        uint256 _redeemerKey,
        uint256 _timelock,
        uint256 _amount,
        bytes memory _secret,
        bytes calldata _destinationData
    ) public {
        vm.assume(
            _redeemerKey > 0
                && _redeemerKey < 115792089237316195423570985008687907852837564279074904382605163141518161494337
        );
        vm.assume(
            _initiatorKey > 0
                && _initiatorKey < 115792089237316195423570985008687907852837564279074904382605163141518161494337
                && _initiatorKey != _redeemerKey
        );
        address payable _redeemer = payable(vm.addr(_redeemerKey));
        address payable _initiator = payable(vm.addr(_initiatorKey));
        vm.assume(_initiator != address(0x0) && _initiator != msg.sender);
        vm.assume(_redeemer != address(0x0) && _redeemer != msg.sender);
        vm.assume(_timelock > 0 && _timelock < type(uint64).max);
        vm.assume(_amount > 0 && _amount < 1000);

        vm.deal(address(this), _amount);
        htlc.initiateOnBehalf{value: _amount}(
            payable(_initiator), _redeemer, _timelock, _amount, sha256(_secret), _destinationData
        );

        bytes32 orderID =
            sha256(abi.encode(block.chainid, sha256(_secret), _initiator, _redeemer, _timelock, _amount, address(htlc)));

        // Generate redeemer signature for instant refund
        vm.startPrank(_redeemer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_redeemerKey, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        // Check if the initiator gets refunded instantly
        uint256 initiatorBalanceBefore = _initiator.balance;
        htlc.instantRefund(orderID, signature);
        uint256 initiatorBalanceAfter = _initiator.balance;
        assertEq(initiatorBalanceAfter - initiatorBalanceBefore, _amount);

        // Verify order is fulfilled
        (,,,,, uint256 time) = htlc.orders(orderID);
        assert(time != 0);
    }

    function test_instantrefund() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(bob);
        // (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyBob, htlc.instantRefundDigest(orderID));
        // bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectEmit(true, false, false, true);
        emit NativeHTLC.Refunded(orderID);
        htlc.instantRefund(orderID, abi.encodePacked("0x00"));
        vm.stopPrank();
    }

    function test_instantrefundShouldRevert() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(alice);
        // (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyBob, htlc.instantRefundDigest(orderID));
        // bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectRevert();
        htlc.instantRefund(orderID, abi.encodePacked("0x00"));
        vm.stopPrank();
    }

    function test_instantrefundShouldPassWithRedeemerSignature() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(alice);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyBob, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectEmit(true, false, false, true);
        emit NativeHTLC.Refunded(orderID);
        htlc.instantRefund(orderID, signature);
        vm.stopPrank();
    }
}
