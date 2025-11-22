// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {HTLC} from "../src/swap/HTLC.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MockSmartAccount} from "./MockSmartAccount.sol";

contract HTLCTest is Test, EIP712 {
    using ECDSA for bytes32;

    HTLC public htlc;
    SimpleMockERC20 token;
    address public initiataddress;
    address public redeemer;
    uint256 public timelock;
    uint256 public amount;
    bytes32 public secretHash;
    bytes public secret;

    MockSmartAccount mock;
    address public alice;
    uint256 keyAlice;
    address public bob;
    uint256 keyBob;
    address public david;
    uint256 keyDavid;
    bytes32 private constant _INITIATE_TYPEHASH =
        keccak256("Initiate(address redeemer,uint256 timelock,uint256 amount,bytes32 secretHash)");

    constructor() EIP712("WOW", "2") {}

    function setUp() public {
        token = new SimpleMockERC20();
        mock = new MockSmartAccount();
        htlc = new HTLC();
        htlc.initialise(address(token));
        (alice, keyAlice) = makeAddrAndKey("alice");
        (bob, keyBob) = makeAddrAndKey("bob");
        (david, keyDavid) = makeAddrAndKey("david");
        secret = "secret";
        secretHash = sha256(secret);
        timelock = 100;
        amount = 10;
        token.transfer(alice, 100);
        token.transfer(address(mock), 100);
        assert(token.balanceOf(alice) == 100);
        vm.prank(alice);
        token.approve(address(htlc), 10);
    }

    function test_tokenCantBeReinitialised() public {
        vm.expectRevert();
        htlc.initialise(address(token));
    }

    function test_RevertWithZeroAddressRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__ZeroAddressRedeemer.selector);
        htlc.initiate(address(0x0), timelock, amount, secretHash);
    }

    function test_RevertWithZeroAddressInitiator() public {
        // vm.prank(address(0x0));
        vm.expectRevert(HTLC.HTLC__ZeroAddressInitiator.selector);
        htlc.initiateOnBehalf(address(0x0), alice, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_RevertWithZeroTimelock() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__ZeroTimelock.selector);
        htlc.initiate(bob, 0, amount, secretHash);
    }

    function test_RevertWithZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__ZeroAmount.selector);
        htlc.initiate(bob, timelock, 0, secretHash);
    }

    function test_RevertWithSameInitiatorAndRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__SameInitiatorAndRedeemer.selector);
        htlc.initiate(alice, timelock, amount, secretHash);
    }

    function test_InitiateCorrectly() public {
        vm.startPrank(alice);
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectEmit(true, true, true, true);
        emit HTLC.Initiated(orderID, secretHash, amount);
        htlc.initiate(bob, timelock, amount, secretHash);
        vm.stopPrank();
    }

    function test_InitiateWithDestinationDataCorrectly() public {
        vm.startPrank(alice);
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectEmit(true, true, true, true);
        emit HTLC.InitiatedWithDestinationData(orderID, secretHash, amount, abi.encode("HELLO TRX 1"));
        htlc.initiate(bob, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
        vm.stopPrank();
    }

    function test_RevertInitiateForDuplicateOrder() public {
        test_InitiateCorrectly();
        vm.expectRevert(HTLC.HTLC__DuplicateOrder.selector);
        vm.prank(alice);
        htlc.initiate(bob, timelock, amount, secretHash);
    }

    function test_InitiateOnBehalfCorrectly() public {
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit HTLC.Initiated(orderID, secretHash, amount);
        htlc.initiateOnBehalf(alice, bob, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_InitiateOnBehalfShouldRevertWithZeroInitiator() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__ZeroAddressInitiator.selector);
        htlc.initiateOnBehalf(address(0x0), bob, timelock, amount, secretHash);
    }

    function test_InitiateOnBehalfShouldRevertwithCallerequalToRedeemer() public {
        vm.prank(alice);
        vm.expectRevert();
        htlc.initiateOnBehalf(bob, address(alice), timelock, amount, secretHash);
    }

    function test_InitiateOnBehalfCorrectlyWithoutDestData() public {
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.prank(alice);
        vm.expectEmit(true, true, true, true);
        emit HTLC.Initiated(orderID, secretHash, amount);
        htlc.initiateOnBehalf(alice, bob, timelock, amount, secretHash);
    }

    function test_InitiateOnBehalfShouldFailWhenRedeemerIsZero() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__ZeroAddressRedeemer.selector);
        htlc.initiateOnBehalf(alice, address(0x0), timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_InitiateOnBehalfRevertWithSameFunderAndRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__SameFunderAndRedeemer.selector);
        htlc.initiateOnBehalf(bob, alice, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_InitiateOnBehalfRevertWithSameInitiatorAndRedeemer() public {
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__SameInitiatorAndRedeemer.selector);
        htlc.initiateOnBehalf(bob, bob, timelock, amount, secretHash, abi.encode("HELLO TRX 1"));
    }

    function test_shouldRevertWhenTimeLockis0() public {
        vm.prank(alice);
        vm.expectRevert();
        htlc.initiateOnBehalf(alice, bob, 0, amount, secretHash, abi.encode("HELLO TRX 1"));

        vm.prank(alice);
        vm.expectRevert();
        htlc.initiateOnBehalf(alice, bob, 0, amount, secretHash);
    }

    function test_shouldRevertIfTheAmountIs0() public {
        vm.prank(alice);
        vm.expectRevert();
        htlc.initiateOnBehalf(alice, bob, timelock, 0, secretHash, abi.encode("HELLO TRX 1"));

        vm.prank(alice);
        vm.expectRevert();
        htlc.initiateOnBehalf(alice, bob, timelock, 0, secretHash);
    }

    function test_InitiateWithSignatureCorrectly() public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("HTLC")),
                keccak256(bytes("3")),
                block.chainid,
                address(htlc)
            )
        );
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        bytes32 structHash = keccak256(abi.encode(_INITIATE_TYPEHASH, bob, timelock, amount, secretHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        address signer = digest.recover(signature);
        assert(signer == alice);
        vm.expectEmit(true, true, true, true);
        emit HTLC.Initiated(orderID, secretHash, amount);
        htlc.initiateWithSignature(alice, bob, timelock, amount, secretHash, signature);
    }

    function test_signatureVerificationShouldFailAndNotInitiate() public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("HTLC")),
                keccak256(bytes("2")),
                block.chainid,
                address(htlc)
            )
        );
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        bytes32 structHash = keccak256(abi.encode(_INITIATE_TYPEHASH, bob, timelock, amount, secretHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        address signer = digest.recover(signature);
        // assert(signer == alice);
        vm.expectRevert(HTLC.HTLC__InvalidInitiatorSignature.selector);
        htlc.initiateWithSignature(alice, bob, timelock, amount, secretHash, signature);
    }

    function test_ShouldFailAndNotInitiateDueToRedeemerAddress0() public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("HTLC")),
                keccak256(bytes("3")),
                block.chainid,
                address(htlc)
            )
        );
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        bytes32 structHash = keccak256(abi.encode(_INITIATE_TYPEHASH, address(0), timelock, amount, secretHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        address signer = digest.recover(signature);
        // assert(signer == alice);
        vm.expectRevert();
        htlc.initiateWithSignature(alice, address(0), timelock, amount, secretHash, signature);
    }

    function test_shouldRevertWhenTimelockIs0() public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("HTLC")),
                keccak256(bytes("3")),
                block.chainid,
                address(htlc)
            )
        );
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, 0, amount, address(htlc)));
        bytes32 structHash = keccak256(abi.encode(_INITIATE_TYPEHASH, bob, 0, amount, secretHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        address signer = digest.recover(signature);
        // assert(signer == alice);
        vm.expectRevert();
        htlc.initiateWithSignature(alice, bob, 0, amount, secretHash, signature);
    }

    function test_shouldRevertWhenAmountis0() public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("HTLC")),
                keccak256(bytes("3")),
                block.chainid,
                address(htlc)
            )
        );
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, 0, address(htlc)));
        bytes32 structHash = keccak256(abi.encode(_INITIATE_TYPEHASH, bob, timelock, 0, secretHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        address signer = digest.recover(signature);
        // assert(signer == alice);
        vm.expectRevert();
        htlc.initiateWithSignature(alice, bob, timelock, 0, secretHash, signature);
    }

    function test_RevertInitiateWithSignatureWithSameInitiatorRedeemer() public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("HTLC")),
                keccak256(bytes("3")),
                block.chainid,
                address(htlc)
            )
        );
        bytes32 structHash = keccak256(abi.encode(_INITIATE_TYPEHASH, alice, timelock, amount, secretHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        address signer = digest.recover(signature);
        assert(signer == alice);
        vm.expectRevert(HTLC.HTLC__SameInitiatorAndRedeemer.selector);
        htlc.initiateWithSignature(alice, alice, timelock, amount, secretHash, signature);
    }

    function test_RevertRedeemForUninitiatedOrder() public {
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectRevert(HTLC.HTLC__OrderNotInitiated.selector);
        htlc.redeem(orderID, secret);
    }

    function test_RevertRedeemWithInvalidSecret() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        bytes memory wrongSecret = "wrong secret";
        vm.expectRevert(HTLC.HTLC__IncorrectSecret.selector);
        htlc.redeem(orderID, wrongSecret);
    }

    function test_RedeemCorrectly() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectEmit(true, true, false, true);
        emit HTLC.Redeemed(orderID, secretHash, secret);
        htlc.redeem(orderID, secret);
    }

    function test_RevertRedeemForFulfilledOrder() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        htlc.redeem(orderID, secret);
        vm.expectRevert(HTLC.HTLC__OrderFulfilled.selector);
        htlc.redeem(orderID, secret);
        vm.stopPrank();
    }

    function test_RevertDuplicateOrder() public {
        test_InitiateCorrectly();
        vm.prank(alice);
        vm.expectRevert(HTLC.HTLC__DuplicateOrder.selector);
        htlc.initiate(bob, timelock, amount, secretHash);
    }

    function test_RevertRefundForUninitiatedOrder() public {
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.expectRevert(HTLC.HTLC__OrderNotInitiated.selector);
        htlc.refund(orderID);
    }

    function test_RevertRefundForFulfilledOrder() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(bob);
        htlc.redeem(orderID, secret);
        vm.expectRevert(HTLC.HTLC__OrderFulfilled.selector);
        htlc.refund(orderID);
        vm.stopPrank();
    }

    function test_RevertRefundIfOrderNotExpired() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.roll(block.number + timelock);
        vm.expectRevert(HTLC.HTLC__OrderNotExpired.selector);
        htlc.refund(orderID);
    }

    function test_RefundCorrectly() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.roll(block.number + timelock + 1);
        vm.expectEmit(true, false, false, false);
        emit HTLC.Refunded(orderID);
        htlc.refund(orderID);
    }

    function test_RevertInstantRefundWithInvalidSignature() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        //using initiator's key to sign, ideally redeemer's required
        vm.startPrank(alice);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectRevert(HTLC.HTLC__InvalidRedeemerSignature.selector);
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
        vm.expectRevert(HTLC.HTLC__OrderFulfilled.selector);
        htlc.instantRefund(orderID, signature);
        vm.stopPrank();
    }

    function test_InstantRefundCorrectly() public {
        test_InitiateCorrectly();
        bytes32 orderID = sha256(abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(htlc)));
        vm.startPrank(bob);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyBob, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.expectEmit(true, false, false, false);
        emit HTLC.Refunded(orderID);
        htlc.instantRefund(orderID, signature);
        vm.stopPrank();
    }

    // function testFuzz_SuccessfulSwap(
    //     address _redeemer,
    //     uint256 _timelock,
    //     uint256 _amount,
    //     bytes memory _secret,
    //     bytes calldata _destinationData
    // ) public {
    //     vm.assume(
    //         _redeemer != address(0x0) && _redeemer != msg.sender && _redeemer != address(htlc)
    //             && _redeemer != address(this)
    //     );
    //     vm.assume(_timelock > 0 && _timelock < type(uint64).max);
    //     vm.assume(_amount > 0 && _amount < 1000);

    //     token.approve(address(htlc), _amount);
    //     htlc.initiateOnBehalf(msg.sender, _redeemer, _timelock, _amount, sha256(_secret), _destinationData);

    //     bytes32 orderID = sha256(abi.encode(block.chainid, sha256(_secret), msg.sender, _redeemer, _timelock, _amount));

    //     // Check whether the order is created properly
    //     (
    //         address oInitiator,
    //         address oRedeemer,
    //         uint256 initiatedAt,
    //         uint256 oTimelock,
    //         uint256 oAmount,
    //         uint256 ofulfilledAt
    //     ) = htlc.orders(orderID);
    //     assertEq(oInitiator, msg.sender);
    //     assertEq(oRedeemer, _redeemer);
    //     assertEq(oTimelock, _timelock);
    //     assertEq(initiatedAt, block.number);
    //     assertEq(oAmount, _amount);
    //     assert(ofulfilledAt == 0);

    //     // Check if the redeemer has recieved funds
    //     uint256 redeemerBalanceBefore = token.balanceOf(_redeemer);
    //     htlc.redeem(orderID, _secret);
    //     uint256 redeemerBalanceAfter = token.balanceOf(_redeemer);
    //     assertEq(redeemerBalanceAfter - redeemerBalanceBefore, _amount);

    //     // Verify order is fulfilled
    //     (,,,,, uint256 x) = htlc.orders(orderID);
    //     assert(x > 0);
    // }

    function testFuzz_RefundedSwap(
        address _redeemer,
        uint256 _timelock,
        uint256 _amount,
        bytes memory _secret,
        bytes calldata _destinationData
    ) public {
        vm.assume(_redeemer != address(0x0) && _redeemer != msg.sender);
        vm.assume(_timelock > 0 && _timelock < type(uint16).max / 2);
        vm.assume(_amount > 0 && _amount < 1000);
        vm.assume(_redeemer != msg.sender);
        vm.assume(_redeemer != address(this));

        token.approve(address(htlc), _amount);
        htlc.initiateOnBehalf(msg.sender, _redeemer, _timelock, _amount, sha256(_secret), _destinationData);

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
        assertEq(ofulfilledAt, 0);

        // Fast forward past timelock
        vm.roll(block.number + _timelock + 1);
        // Check if the initiator gets refunded
        uint256 initiatorBalanceBefore = token.balanceOf(msg.sender);
        htlc.refund(orderID);
        uint256 initiatorBalanceAfter = token.balanceOf(msg.sender);
        assertEq(initiatorBalanceAfter - initiatorBalanceBefore, _amount);

        // Verify order is fulfilled
        (,,,,, uint256 time) = htlc.orders(orderID);
        assert(time != 0);
    }

    function testFuzz_InstantRefund(
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
        address _redeemer = vm.addr(_redeemerKey);
        vm.assume(_redeemer != address(0x0) && _redeemer != msg.sender);
        vm.assume(_timelock > 0 && _timelock < type(uint64).max);
        vm.assume(_amount > 0 && _amount < 1000);

        token.approve(address(htlc), _amount);
        htlc.initiateOnBehalf(msg.sender, _redeemer, _timelock, _amount, sha256(_secret), _destinationData);

        bytes32 orderID =
            sha256(abi.encode(block.chainid, sha256(_secret), msg.sender, _redeemer, _timelock, _amount, address(htlc)));

        // Generate redeemer signature for instant refund
        vm.startPrank(_redeemer);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_redeemerKey, htlc.instantRefundDigest(orderID));
        bytes memory signature = abi.encodePacked(r, s, v);
        vm.stopPrank();

        // Check if the initiator gets refunded instantly
        uint256 initiatorBalanceBefore = token.balanceOf(msg.sender);
        htlc.instantRefund(orderID, signature);
        uint256 initiatorBalanceAfter = token.balanceOf(msg.sender);
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
        emit HTLC.Refunded(orderID);
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
        emit HTLC.Refunded(orderID);
        htlc.instantRefund(orderID, signature);
        vm.stopPrank();
    }

    function test_smartAccountIntegration() public {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("HTLC")),
                keccak256(bytes("1")),
                block.chainid,
                address(htlc)
            )
        );

        bytes32 orderID =
            sha256(abi.encode(block.chainid, secretHash, address(mock), bob, timelock, amount, address(htlc)));
        console.log(block.chainid);
        console.logBytes32(secretHash);
        console.log(address(mock));
        console.log(bob);
        console.log(timelock);
        console.log(amount);

        bytes32 structHash = keccak256(abi.encode(_INITIATE_TYPEHASH, bob, timelock, amount, secretHash));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(keyAlice, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        address signer = digest.recover(signature);
        assert(signer == alice);

        mock.approve(address(token), address(htlc));

        vm.expectEmit(true, false, false, true);
        emit HTLC.Initiated(orderID, secretHash, amount);
        htlc.initiateWithSignature(address(mock), bob, timelock, amount, secretHash, signature);
    }
}

contract SimpleMockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MTK") {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }
}
