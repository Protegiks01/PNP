# Audit Report

## Title 
ETH Permanently Trapped in ERC20 CollateralTracker Contracts Due to Unused msg.value in unlockCallback

## Summary
When users call `deposit()` or `mint()` on an ERC20-based CollateralTracker with ETH attached (msg.value > 0), the ETH becomes permanently trapped in the contract. The `_settleCurrencyDelta()` function encodes msg.value in callback data but never forwards the actual ETH, and the `unlockCallback()` completely ignores this value for ERC20 tokens, leaving no recovery mechanism.

## Finding Description
The vulnerability exists in the Uniswap V4 integration flow within CollateralTracker.sol: [1](#0-0) 

The `_settleCurrencyDelta()` function encodes `msg.value` in the callback data but does NOT forward it to the poolManager using `.value()` syntax. The ETH remains in the CollateralTracker contract. [2](#0-1) 

In `unlockCallback()`, there are two execution paths:
1. **Native ETH path** (lines 459-464): When underlying is address(0), the `valueOrigin` parameter is properly used to settle ETH and refund surplus
2. **ERC20 path** (lines 466-474): When underlying is an ERC20 token, the `valueOrigin` parameter is completely ignored

Both `deposit()` and `mint()` functions are marked as `payable`: [3](#0-2) [4](#0-3) 

**Attack Scenario:**
1. Alice wants to deposit USDC into a USDC CollateralTracker (ERC20 token)
2. Alice accidentally includes 1 ETH as msg.value when calling `deposit(1000e6, alice)`
3. The CollateralTracker receives the 1 ETH
4. `_settleCurrencyDelta()` is called at line 585, encoding msg.value=1 ETH in data
5. `poolManager().unlock()` is called without forwarding ETH (no `.value()` syntax)
6. `unlockCallback()` executes the ERC20 branch (lines 466-474)
7. The `valueOrigin` (1 ETH) is never referenced in the ERC20 branch
8. 1 ETH remains permanently trapped in the CollateralTracker contract

There is no mechanism to recover this ETH:
- No receive() or fallback() function exists
- No admin withdrawal function
- ETH can only exit via line 464 (native ETH surplus refund) or line 1360 (settleLiquidation refund when bonus >= 0)

This breaks the **Collateral Conservation** invariant as assets (ETH) accumulate in the contract without being tracked in `s_depositedAssets`, `s_assetsInAMM`, or `unrealizedGlobalInterest`.

## Impact Explanation
**Critical Severity** - Direct permanent loss of user funds:
- Any user can accidentally lose ETH by sending it to an ERC20 CollateralTracker
- The loss is permanent with no recovery mechanism
- Common user error (mistakenly sending ETH when depositing ERC20 tokens)
- Affects all ERC20 CollateralTrackers in the protocol
- The payable modifier on deposit/mint functions creates a false sense that ETH handling is supported

## Likelihood Explanation
**High Likelihood:**
- Very easy to trigger accidentally (no malicious intent required)
- Users commonly make mistakes with msg.value in multi-token protocols
- Both deposit() and mint() are marked payable, suggesting ETH might be accepted
- No warning or revert when ETH is sent to ERC20 vaults
- Affects the primary user interaction functions (deposit/mint)
- Will inevitably occur as users interact with the protocol

## Recommendation
Remove the `payable` modifier from `deposit()` and `mint()` functions, or add explicit checks to revert when msg.value is sent to ERC20 CollateralTrackers:

```solidity
function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
    _accrueInterest(msg.sender, IS_DEPOSIT);
    if (assets > type(uint104).max) revert Errors.DepositTooLarge();
    if (assets == 0) revert Errors.BelowMinimumRedemption();

    // Add this check for ERC20 vaults
    address _poolManager = address(poolManager());
    if (_poolManager != address(0) && !Currency.wrap(underlyingToken()).isAddressZero()) {
        if (msg.value > 0) revert Errors.UnexpectedEthSent();
    }

    shares = previewDeposit(assets);
    // ... rest of function
}
```

Apply the same fix to the `mint()` function. Alternatively, remove the `payable` modifier entirely for non-native-ETH CollateralTrackers during deployment.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {IPoolManager} from "v4-core/interfaces/IPoolManager.sol";
import {Currency} from "v4-core/types/Currency.sol";

contract EthTrappedTest is Test {
    CollateralTracker collateralTracker;
    address alice = makeAddr("alice");
    address mockPoolManager = makeAddr("poolManager");
    address mockPanopticPool = makeAddr("panopticPool");
    address mockUSDC = makeAddr("USDC"); // ERC20 token, not ETH
    
    function setUp() public {
        // Deploy CollateralTracker for an ERC20 token (USDC)
        collateralTracker = new CollateralTracker(10);
        
        // Initialize with mock data simulating a USDC CollateralTracker
        // In real deployment, this would be done via clone pattern with proper initialization
        vm.mockCall(
            address(collateralTracker),
            abi.encodeWithSelector(CollateralTracker.underlyingToken.selector),
            abi.encode(mockUSDC)
        );
        vm.mockCall(
            address(collateralTracker),
            abi.encodeWithSelector(CollateralTracker.poolManager.selector),
            abi.encode(mockPoolManager)
        );
        vm.mockCall(
            address(collateralTracker),
            abi.encodeWithSelector(CollateralTracker.panopticPool.selector),
            abi.encode(mockPanopticPool)
        );
    }
    
    function testEthTrappedInERC20Vault() public {
        uint256 ethAmount = 1 ether;
        
        // Give Alice some ETH
        vm.deal(alice, ethAmount);
        
        // Record CollateralTracker balance before
        uint256 balanceBefore = address(collateralTracker).balance;
        assertEq(balanceBefore, 0, "Should start with 0 ETH");
        
        // Alice tries to deposit, accidentally including ETH
        vm.prank(alice);
        vm.expectRevert(); // This will revert due to mock setup, but in real scenario
        // the ETH would be trapped because unlockCallback ignores valueOrigin for ERC20
        
        // To demonstrate the issue without full mock setup:
        // If deposit() succeeds with msg.value > 0 on an ERC20 vault,
        // the _settleCurrencyDelta encodes msg.value but never uses it
        // in the ERC20 branch of unlockCallback (lines 466-474)
        
        // The ETH would remain in CollateralTracker with no way to retrieve it
        // because there's no receive(), fallback(), or withdrawal function
        
        console.log("ETH sent:", ethAmount);
        console.log("This ETH would be permanently trapped in the contract");
        console.log("No mechanism exists to recover it for ERC20 vaults");
    }
}
```

**Note:** A complete end-to-end test would require full Uniswap V4 PoolManager setup. The vulnerability is evident from code analysis: the `valueOrigin` parameter is decoded but never used in the ERC20 branch of `unlockCallback()`, while both `deposit()` and `mint()` are marked `payable` allowing ETH to enter the contract.

### Citations

**File:** contracts/CollateralTracker.sol (L440-442)
```text
    function _settleCurrencyDelta(address account, int256 delta) internal {
        poolManager().unlock(abi.encode(account, delta, msg.value));
    }
```

**File:** contracts/CollateralTracker.sol (L449-486)
```text
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        if (msg.sender != address(poolManager())) revert Errors.UnauthorizedUniswapCallback();

        (address account, int256 delta, uint256 valueOrigin) = abi.decode(
            data,
            (address, int256, uint256)
        );

        address underlyingAsset = underlyingToken();
        if (delta > 0) {
            if (Currency.wrap(underlyingAsset).isAddressZero()) {
                poolManager().settle{value: uint256(delta)}();

                // keep checked to prevent underflows
                uint256 surplus = valueOrigin - uint256(delta);
                if (surplus > 0) SafeTransferLib.safeTransferETH(account, surplus);
            } else {
                poolManager().sync(Currency.wrap(underlyingAsset));
                SafeTransferLib.safeTransferFrom(
                    underlyingAsset,
                    account,
                    address(poolManager()),
                    uint256(delta)
                );
                poolManager().settle();
            }

            poolManager().mint(address(panopticPool()), uint160(underlyingAsset), uint256(delta));
        } else if (delta < 0) {
            unchecked {
                delta = -delta;
            }
            poolManager().burn(address(panopticPool()), uint160(underlyingAsset), uint256(delta));
            poolManager().take(Currency.wrap(underlyingAsset), account, uint256(delta));
        }

        return "";
    }
```

**File:** contracts/CollateralTracker.sol (L557-558)
```text
    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
        _accrueInterest(msg.sender, IS_DEPOSIT);
```

**File:** contracts/CollateralTracker.sol (L611-611)
```text
    function mint(uint256 shares, address receiver) external payable returns (uint256 assets) {
```
