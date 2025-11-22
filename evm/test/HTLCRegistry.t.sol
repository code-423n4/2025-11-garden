// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/swap/HTLCRegistry.sol";
import "../src/swap/HTLC.sol";
import {NativeHTLC} from "../src/swap/NativeHTLC.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "../src/swap/UDA.sol";

contract HTLCRegistryTest is Test {
    HTLCRegistry registry;
    SimpleMockERC20 token;

    address payable alice;
    address payable bob;
    address payable TheMan;
    uint256 keyAlice;
    uint256 keyBob;
    uint256 keyTheManAddr;
    uint256 timelock;
    bytes32 secretHash;
    uint256 amount;
    bytes secret;
    address payable addressUDA;
    address payable addressNativeUDA;
    UniqueDepositAddress UDA;
    NativeUniqueDepositAddress nativeUDA;
    HTLC htlc;

    function setUp() public {
        token = new SimpleMockERC20();
        address aliceAddr;
        address bobAddr;
        address theManAddr;
        (aliceAddr, keyAlice) = makeAddrAndKey("alice");
        (bobAddr, keyBob) = makeAddrAndKey("bob");
        (theManAddr, keyTheManAddr) = makeAddrAndKey("THE_MAN");
        alice = payable(aliceAddr);
        bob = payable(bobAddr);
        TheMan = payable(theManAddr);
        timelock = 1000;
        amount = 10;
        secret = "secret";
        secretHash = sha256(secret);
        token.transfer(alice, amount);
        token.transfer(TheMan, 1000);
        vm.deal(alice, 10);
        vm.deal(TheMan, 1000);
        registry = new HTLCRegistry(address(this));
        htlc = new HTLC();
    }

    function test_DeployHTLC() public {
        htlc.initialise(address(token));
        registry.addHTLC(address(htlc));
    }

    function test_DeployNativeHTLC() public {
        assert(registry.htlcs(address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)) == address(0));
        assert(registry.implNativeUDA() == address(0));

        NativeHTLC native = new NativeHTLC();
        registry.addHTLC(address(native));

        NativeUniqueDepositAddress nativeUda = new NativeUniqueDepositAddress();
        registry.setImplNativeUDA(address(nativeUda));

        assert(registry.htlcs(address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)) != address(0));
        assert(registry.implNativeUDA() != address(0));
    }

    function test_SetImplNativeUDA() public {
        test_DeployNativeHTLC();
        // address htlcAdd = registry.nativeHTLC();
        address impl = address(new NativeUniqueDepositAddress());
        vm.expectEmit(true, false, false, false);
        emit HTLCRegistry.NativeUDAImplUpdated(impl);
        registry.setImplNativeUDA(impl);
        assert(registry.implNativeUDA() == impl);
    }

    function test_RevertSetImplNativeUDAwithInvalidAddress() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddress.selector);
        registry.setImplNativeUDA(payable(address(23)));
    }

    function test_RevertSetImplNativeUDAwithInvalidOwner() public {
        vm.startPrank(alice);
        // address payable htlcAdd = payable(registry.nativeHTLC());
        address payable impl = payable(address(new NativeUniqueDepositAddress()));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(alice)));
        registry.setImplNativeUDA(impl);
        vm.stopPrank();
    }

    function test_SetImplUDA() public {
        address prev = registry.implNativeUDA();
        address newImplUDA = address(new UniqueDepositAddress());
        vm.expectEmit(true, false, false, false);
        emit HTLCRegistry.UDAImplUpdated(newImplUDA);
        registry.setImplUDA(newImplUDA);
        assert(registry.implUDA() == newImplUDA);
        assert(prev != newImplUDA);
    }

    function test_RevertSetImplUDAwithInvalidAddress() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddress.selector);
        registry.setImplUDA(payable(address(24)));
    }

    function test_RevertSetImplUDAwithInvalidOwner() public {
        vm.startPrank(alice);
        address newImplUDA = address(new UniqueDepositAddress());
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(alice)));
        registry.setImplUDA(payable(newImplUDA));
        vm.stopPrank();
    }

    function test_AddHTLC() public {
        HTLC _htlc = new HTLC();
        _htlc.initialise(address(token));
        vm.expectEmit(true, true, false, false);
        emit HTLCRegistry.HTLCAdded(address(_htlc), address(token));
        registry.addHTLC(address(_htlc));
        assert(registry.htlcs(address(token)) != address(0));
    }

    function test_AddNativeHTLC() public {
        NativeHTLC _htlc = new NativeHTLC();
        vm.expectEmit(true, true, false, false);
        emit HTLCRegistry.HTLCAdded(address(_htlc), address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE));
        registry.addHTLC(address(_htlc));
        assert(registry.htlcs(address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE)) != address(0));
    }

    function test_RevertAddHTLCIfNotOwner() public {
        vm.startPrank(alice);
        HTLC _htlc = new HTLC();
        _htlc.initialise(address(token));
        vm.deal(alice, 100);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(alice)));
        registry.addHTLC(address(_htlc));
        vm.stopPrank();
    }

    function test_RevertAddHTLCInvalidAddress() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddress.selector);
        registry.addHTLC(address(24));
    }

    function test_getERC20Address() public {
        test_DeployHTLC();
        addressUDA = payable(
            registry.getERC20Address(
                address(htlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
            )
        );
        UDA = UniqueDepositAddress(addressUDA);
    }

    function test_FundERC20UDA() public {
        test_getERC20Address();
        vm.prank(alice);
        token.transfer(addressUDA, amount);
        assert(ERC20(token).balanceOf(alice) == 0);
        assert(ERC20(token).balanceOf(addressUDA) == amount);
    }

    function test_RevertGetERC20SwapAddressZeroRefundAddress() public {
        test_DeployHTLC();
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddressParameters.selector);
        registry.getERC20Address(
            address(token), address(0), bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_RevertGetERC20SwapAddressZeroRedeemer() public {
        test_DeployHTLC();
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddressParameters.selector);
        registry.getERC20Address(
            address(htlc), alice, address(0), timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_RevertGetSwapAddressWithSameInitiatorRedeemer() public {
        test_DeployHTLC();
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddressParameters.selector);
        registry.getERC20Address(
            address(htlc), alice, alice, timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_RevertGetERC20SwapAddressIfZeroTimelock() public {
        test_DeployHTLC();
        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroTimelock.selector);
        registry.getERC20Address(address(htlc), alice, bob, 0, secretHash, amount, abi.encode("destinationData"));
    }

    function test_RevertGetERC20SwapAddressIfHtlcAddressIsIncorrect() public {
        test_DeployHTLC();
        HTLC newhtlc = new HTLC();
        newhtlc.initialise(address(token));
        vm.expectRevert(HTLCRegistry.HTLCRegistry__HTLCTokenMismatch.selector);
        registry.getERC20Address(
            address(newhtlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_RevertGetERC20SwapAddressIfZeroAmount() public {
        test_DeployHTLC();
        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroAmount.selector);
        registry.getERC20Address(address(htlc), alice, bob, timelock, secretHash, 0, abi.encode("destinationData"));
    }

    function test_RevertCreateERC20SwapAddressIfZeroBalance() public {
        test_getERC20Address();
        vm.prank(alice);
        token.transfer(addressUDA, amount - 1);
        assert(ERC20(token).balanceOf(alice) == 1);
        assert(ERC20(token).balanceOf(addressUDA) == amount - 1);
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InsufficientFundsDeposited.selector);
        registry.createERC20SwapAddress(
            address(htlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_CreateERC20SwapAddressIfInvalidToken() public {
        test_FundERC20UDA();
        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroHTLCAddress.selector);
        registry.createERC20SwapAddress(
            address(0), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_CreateERC20SwapAddressIfInvalidHTLCIsPassed() public {
        test_FundERC20UDA();
        HTLC newhtlc = new HTLC();
        newhtlc.initialise(address(token));
        vm.expectRevert(HTLCRegistry.HTLCRegistry__HTLCTokenMismatch.selector);
        registry.createERC20SwapAddress(
            address(newhtlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_CreateERC20SwapAddress() public {
        test_FundERC20UDA();
        vm.expectEmit(true, true, true, true);
        emit HTLCRegistry.UDACreated(addressUDA, address(alice), address(htlc));
        address fromCreate = registry.createERC20SwapAddress(
            address(htlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
        assert(fromCreate == addressUDA);
        assert(token.balanceOf(addressUDA) == 0);
        console.log(address(registry.htlcs(address(token))));
        bytes32 orderID = sha256(
            abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(registry.htlcs(address(token))))
        );
        vm.expectEmit(true, true, false, true);
        emit HTLC.Redeemed(orderID, secretHash, secret);
        HTLC(registry.htlcs(address(token))).redeem(orderID, secret);
        assert(token.balanceOf(bob) == amount);
    }

    function test_CreateERC20SwapAddressIfdestinationDataisNull() public {
        test_FundERC20UDA();
        vm.expectEmit(true, true, true, true);
        emit HTLCRegistry.UDACreated(addressUDA, address(alice), address(htlc));
        address fromCreate = registry.createERC20SwapAddress(
            address(htlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
        assert(fromCreate == addressUDA);
        assert(token.balanceOf(addressUDA) == 0);
        console.log(address(registry.htlcs(address(token))));
        bytes32 orderID = sha256(
            abi.encode(block.chainid, secretHash, alice, bob, timelock, amount, address(registry.htlcs(address(token))))
        );
        vm.expectEmit(true, true, false, true);
        emit HTLC.Redeemed(orderID, secretHash, secret);
        HTLC(registry.htlcs(address(token))).redeem(orderID, secret);
        assert(token.balanceOf(bob) == amount);
    }

    function test_multipleCreateER20Address() public {
        test_DeployHTLC();
        address payable addressUDA1 = payable(
            registry.getERC20Address(address(htlc), alice, bob, timelock, "ffff", amount, abi.encode("destinationData"))
        );
        address payable addressUDA2 = payable(
            registry.getERC20Address(address(htlc), bob, alice, timelock, "ssss", amount, abi.encode("destinationData"))
        );

        vm.prank(TheMan);
        token.transfer(addressUDA1, amount);
        token.transfer(addressUDA2, amount);
        assert(ERC20(token).balanceOf(addressUDA1) == amount);
        assert(ERC20(token).balanceOf(addressUDA2) == amount);

        registry.createERC20SwapAddress(
            address(htlc), alice, bob, timelock, "ffff", amount, abi.encode("destinationData")
        );
        registry.createERC20SwapAddress(
            address(htlc), bob, alice, timelock, "ssss", amount, abi.encode("destinationData")
        );
    }

    function test_ReinitializeIfInitializeFailed() public {
        test_CreateERC20SwapAddressIfInvalidToken();
        vm.expectEmit(true, true, true, true);
        emit HTLCRegistry.UDACreated(addressUDA, address(alice), address(htlc));
        address fromCreate = registry.createERC20SwapAddress(
            address(htlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
        assert(fromCreate == addressUDA);
    }

    function test_RecoverERC20() public {
        test_CreateERC20SwapAddress();
        token.transfer(alice, amount);
        assert(IERC20(token).balanceOf(alice) == amount);
        assert(IERC20(token).balanceOf(addressUDA) == 0);
        vm.prank(alice);
        token.transfer(addressUDA, amount);
        assert(IERC20(token).balanceOf(alice) == 0);
        assert(IERC20(token).balanceOf(addressUDA) == amount);
        UDA.recover(address(token));
        assert(IERC20(token).balanceOf(alice) == amount);
        assert(IERC20(token).balanceOf(addressUDA) == 0);
    }

    function test_RecoverNative() public {
        test_getERC20Address();
        vm.deal(alice, amount);
        assert(address(alice).balance == amount);
        assert(address(UDA).balance == 0);
        token.transfer(addressUDA, amount);
        vm.prank(alice);
        addressUDA.transfer(amount);
        assert(address(alice).balance == 0);
        assert(address(UDA).balance == amount);
        vm.expectEmit(true, true, false, false);
        emit HTLCRegistry.UDACreated(address(addressUDA), address(alice), address(htlc));
        registry.createERC20SwapAddress(
            address(htlc), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
        UDA.recover();
        assert(address(alice).balance == amount);
        assert(address(nativeUDA).balance == 0);
    }

    function test_GetNativeAdress() public {
        test_DeployNativeHTLC();
        addressNativeUDA =
            payable(registry.getNativeAddress(alice, bob, timelock, secretHash, amount, abi.encode("destinationData")));
        nativeUDA = NativeUniqueDepositAddress(addressNativeUDA);
    }

    function test_RevertGetERC20SwapAddressIfNoHTLCFound() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroHTLCAddress.selector);
        addressUDA = payable(
            registry.getERC20Address(
                address(0), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
            )
        );
        UDA = UniqueDepositAddress(addressUDA);
    }

    function test_RevertGetNativeSwapAddressIfNoHTLC() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__NoNativeHTLCFound.selector);
        addressNativeUDA =
            payable(registry.getNativeAddress(alice, bob, timelock, secretHash, amount, abi.encode("destinationData")));
        nativeUDA = NativeUniqueDepositAddress(addressNativeUDA);
    }

    function test_FundNativeUDA() public {
        test_GetNativeAdress();
        vm.prank(alice);
        addressNativeUDA.transfer(amount);
        assert(address(alice).balance == 0);
        assert(address(nativeUDA).balance == amount);
    }

    function test_RevertCreateNativeSwapAddressIfZeroBalance() public {
        test_GetNativeAdress();
        vm.prank(alice);
        addressNativeUDA.transfer(amount - 1);
        assert(address(alice).balance == 1);
        assert(address(nativeUDA).balance == amount - 1);
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InsufficientFundsDeposited.selector);
        registry.createNativeSwapAddress(alice, bob, timelock, secretHash, amount, abi.encode("destinationData"));
    }

    function test_CreateNativeSwapAddress() public {
        test_FundNativeUDA();
        vm.expectEmit(true, true, false, true);
        emit HTLCRegistry.NativeUDACreated(addressNativeUDA, address(alice));
        address fromCreate =
            registry.createNativeSwapAddress(alice, bob, timelock, secretHash, amount, abi.encode("destinationData"));
        assert(fromCreate == addressNativeUDA);
        assert(address(nativeUDA).balance == 0);
    }

    function test_RevertCreateNativeSwapAddressIfNoHTLC() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__NoNativeHTLCFound.selector);
        registry.createNativeSwapAddress(alice, bob, timelock, secretHash, amount, abi.encode("destinationData"));
    }

    function test_RevertCreateERC20SwapAddressIfNoHTLCFound() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroHTLCAddress.selector);
        registry.createERC20SwapAddress(
            address(0x0), alice, bob, timelock, secretHash, amount, abi.encode("destinationData")
        );
    }

    function test_RecoverERC20fromNativeUDA() public {
        test_CreateNativeSwapAddress();
        assert(IERC20(token).balanceOf(alice) == amount);
        assert(IERC20(token).balanceOf(addressNativeUDA) == 0);
        vm.prank(alice);
        token.transfer(addressNativeUDA, amount);
        assert(IERC20(token).balanceOf(alice) == 0);
        assert(IERC20(token).balanceOf(addressNativeUDA) == amount);
        nativeUDA.recover(address(token));
        assert(IERC20(token).balanceOf(alice) == amount);
        assert(IERC20(token).balanceOf(addressNativeUDA) == 0);
    }

    function test_RecoverNativeFromNativeUDA() public {
        test_GetNativeAdress();
        vm.deal(alice, amount * 2);
        assert(address(alice).balance == amount * 2);
        assert(address(nativeUDA).balance == 0);
        vm.prank(alice);
        addressNativeUDA.transfer(amount * 2);
        assert(address(alice).balance == 0);
        assert(address(nativeUDA).balance == amount * 2);
        vm.expectEmit(true, true, false, false);
        emit HTLCRegistry.NativeUDACreated(addressNativeUDA, address(alice));
        registry.createNativeSwapAddress(alice, bob, timelock, secretHash, amount, abi.encode("destinationData"));
        nativeUDA.recover();
        assert(address(alice).balance == amount);
        assert(address(nativeUDA).balance == 0);
    }

    function test_getERC20AddressAndGetNativeAddressShouldRevertIfTheTimelockis0() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroTimelock.selector);
        registry.getERC20Address(address(htlc), alice, bob, 0, secretHash, amount, abi.encode("destinationData"));

        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroTimelock.selector);
        registry.getNativeAddress(alice, bob, 0, secretHash, amount, abi.encode("destinationData"));
    }

    function test_getERC20AddressAndGetNativeAddressShouldRevertIfTheAmountis0() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroAmount.selector);
        registry.getERC20Address(address(htlc), alice, bob, timelock, secretHash, 0, abi.encode("destinationData"));

        vm.expectRevert(HTLCRegistry.HTLCRegistry__ZeroAmount.selector);
        registry.getNativeAddress(alice, bob, timelock, secretHash, 0, abi.encode("destinationData"));
    }

    function test_getERC20AddressAndGetNativeAddressShouldRevertIfrefundAddressIsSameAsRedeemer() public {
        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddressParameters.selector);
        registry.getERC20Address(
            address(htlc), alice, alice, timelock, secretHash, amount, abi.encode("destinationData")
        );

        vm.expectRevert(HTLCRegistry.HTLCRegistry__InvalidAddressParameters.selector);
        registry.getNativeAddress(alice, alice, timelock, secretHash, amount, abi.encode("destinationData"));
    }

    function testFuzz_CreateERC20SwapAddress(
        address _refundAddress,
        address _redeemer,
        uint256 _timelock,
        bytes32 _secretHash,
        uint256 _amount,
        bytes calldata _destinationData
    ) public {
        vm.assume(_refundAddress != address(0));
        vm.assume(_redeemer != address(0));
        vm.assume(_refundAddress != _redeemer);
        _timelock = bound(_timelock, 1 hours, 30 days);
        _amount = bound(_amount, 1, 1e6);

        test_DeployHTLC();
        address _uda = payable(
            registry.getERC20Address(
                address(htlc), _refundAddress, _redeemer, _timelock, _secretHash, _amount, _destinationData
            )
        );
        token.transfer(_refundAddress, _amount);
        // assert(token.balanceOf(_refundAddress) == _amount);
        console.log(token.balanceOf(_refundAddress));
        console.log(_amount);
        assert(token.balanceOf(_uda) == 0);
        vm.prank(_refundAddress);
        token.transfer(address(_uda), _amount);
        // assert(token.balanceOf(_refundAddress) == 0);
        assert(token.balanceOf(address(_uda)) == _amount);
        vm.expectEmit(true, true, true, true);
        emit HTLCRegistry.UDACreated(address(_uda), address(_refundAddress), address(htlc));
        address _addr = registry.createERC20SwapAddress(
            address(htlc), _refundAddress, _redeemer, _timelock, _secretHash, _amount, _destinationData
        );
        assert(_addr == _uda);
    }

    function testFuzz_CreateNativeSwapAddress(
        address refundAddress,
        address redeemer,
        uint256 _timelock,
        bytes32 _secretHash,
        uint256 _amount,
        bytes calldata _destinationData
    ) public {
        vm.assume(refundAddress != address(0));
        vm.assume(redeemer != address(0));
        vm.assume(refundAddress != redeemer);
        _timelock = bound(_timelock, 1 hours, 30 days);
        _amount = bound(_amount, 1, 1e6);
        test_DeployNativeHTLC();
        address nativeUda = payable(
            registry.getNativeAddress(refundAddress, redeemer, _timelock, _secretHash, _amount, _destinationData)
        );
        vm.deal(refundAddress, _amount);
        assert(address(refundAddress).balance == _amount);
        assert(address(nativeUda).balance == 0);
        vm.prank(refundAddress);
        payable(nativeUda).transfer(_amount);
        assert(address(refundAddress).balance == 0);
        assert(address(nativeUda).balance == _amount);
        vm.expectEmit(true, true, false, true);
        emit HTLCRegistry.NativeUDACreated(nativeUda, address(refundAddress));
        address addr =
            registry.createNativeSwapAddress(refundAddress, redeemer, _timelock, _secretHash, _amount, _destinationData);
        assert(addr == nativeUda);
    }
}

contract SimpleMockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MTK") {
        _mint(msg.sender, 1000000 * 10 ** decimals());
    }
}
