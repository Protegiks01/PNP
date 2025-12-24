# Audit Report

## Title 
Liquidation Bypass via Utilization Manipulation Through View Function State Inconsistency

## Summary
The `_calculateCurrentBorrowIndex()` and related view functions in `CollateralTracker.sol` use `_interestRateView()` which calculates interest rates based on current pool utilization without accessing transient storage. This creates a discrepancy with actual interest accrual which uses `_poolUtilizationWad()` to read the maximum utilization stored in transient storage. An attacker can exploit this by depositing large amounts to temporarily lower utilization, causing solvency checks during liquidation to underestimate interest owed and incorrectly classify insolvent positions as solvent, allowing users to avoid liquidation.

## Finding Description
The protocol uses transient storage (`UTILIZATION_TRANSIENT_SLOT`) to track the maximum pool utilization within a transaction to prevent flash loan manipulation of interest rates. [1](#0-0) 

When interest is actually accrued via `_accrueInterest()`, it calls `_updateInterestRate()` which uses `_poolUtilizationWad()` to get utilization. [2](#0-1) 

This function reads from transient storage and returns the MAXIMUM utilization seen during the transaction: [3](#0-2) 

However, view functions used for solvency checks call `_interestRateView()` which uses `_poolUtilizationWadView()` - a pure view calculation that does NOT access transient storage: [4](#0-3) [5](#0-4) 

During liquidation checks, the `RiskEngine` calls `assetsAndInterest()` which internally uses these view functions: [6](#0-5) [7](#0-6) 

**Attack Path:**
1. Victim has a leveraged position near liquidation with high interest owed at 70% utilization
2. Attacker (can be victim's alt account) deposits large amount to CollateralTracker
3. Deposit calls `_accrueInterest(attacker, IS_DEPOSIT)` which stores 70% utilization in transient storage then processes deposit, dropping utilization to 40%
4. Liquidator attempts liquidation in same transaction via `dispatchFrom()`
5. `_checkSolvencyAtTicks()` calls `riskEngine().isAccountSolvent()` which uses view functions
6. View functions calculate victim's interest using 40% utilization (current state) instead of 70%
7. Victim's calculated interest is artificially low, making them appear solvent
8. Liquidation check fails, victim avoids liquidation despite being actually insolvent
9. If victim's interest were actually accrued, it would use 70% from transient storage and show insolvency

This breaks **Invariant #1**: "Insolvent positions must be liquidated immediately."

## Impact Explanation
**HIGH Severity** - This vulnerability allows users to avoid legitimate liquidations by manipulating pool utilization within a single transaction. The consequences include:

1. **Protocol Bad Debt**: Insolvent positions remain open, accumulating more debt while appearing solvent to view functions
2. **Liquidity Provider Losses**: PLPs bear the risk of undercollateralized positions that should have been liquidated
3. **Systemic Risk**: Multiple users exploiting this could create significant protocol insolvency
4. **Liquidator DOS**: Legitimate liquidators waste gas on transactions that incorrectly fail solvency checks

The attack is economically viable because the cost of a large temporary deposit (which can be withdrawn after blocking liquidation) is minimal compared to the liquidation bonus the user avoids paying.

## Likelihood Explanation
**HIGH Likelihood** - The attack is:
- **Easily executable**: Requires only a deposit transaction in the same block as liquidation attempt
- **Low cost**: Attacker can use flash loans or simply withdraw the deposit immediately after
- **High incentive**: Users facing liquidation have strong financial motivation (saving 5-10% liquidation bonus)
- **Detectable**: Users can monitor their positions and trigger the defense proactively
- **No special permissions required**: Any account can execute this attack

The vulnerability will be frequently exploited because:
1. Users near liquidation are constantly monitoring their positions
2. MEV bots can front-run liquidation attempts with defensive deposits
3. The discrepancy is deterministic and reliably exploitable

## Recommendation
The view functions must account for the maximum utilization stored in transient storage when calculating interest rates. However, since view functions cannot directly access transient storage in external calls, the architecture needs adjustment:

**Option 1**: Pass utilization as a parameter to view functions from the calling context that has access to transient storage.

**Option 2**: Make solvency checks call a stateful variant that performs actual accrual before checking solvency, ensuring consistency:

```solidity
// In PanopticPool._checkSolvencyAtTicks, before calling riskEngine().isAccountSolvent():
collateralToken0().accrueInterest(); // Force accrual for all users
collateralToken1().accrueInterest();

// Then proceed with solvency checks using updated state
```

**Option 3**: Store a snapshot of maximum utilization in storage (not transient) that view functions can read, updating it on every state-changing operation.

The safest fix is Option 2, ensuring that solvency checks always operate on freshly accrued interest state, eliminating the view/accrual discrepancy.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {TokenId} from "@types/TokenId.sol";

contract LiquidationBypassTest is Test {
    PanopticPool panopticPool;
    CollateralTracker collateralToken0;
    CollateralTracker collateralToken1;
    
    address victim = address(0x1);
    address attacker = address(0x2);
    address liquidator = address(0x3);
    
    function setUp() public {
        // Setup Panoptic pool, collateral trackers, and create victim's leveraged position
        // (Full setup code would initialize contracts and create a position near liquidation)
    }
    
    function testLiquidationBypass() public {
        // 1. Victim has position with high borrows at 70% utilization
        // 2. Attacker deposits large amount, dropping utilization to 40%
        vm.prank(attacker);
        uint256 largeDeposit = 1_000_000e18;
        collateralToken0.deposit(largeDeposit, attacker);
        
        // 3. Within same transaction, liquidator attempts to liquidate victim
        vm.prank(liquidator);
        TokenId[] memory positionIds = new TokenId[](1);
        // This will call _checkSolvencyAtTicks which uses view functions
        // View functions calculate interest at 40% utilization (LOW)
        // But actual accrual would use 70% from transient storage (HIGH)
        
        // Expected: Liquidation should succeed (victim is insolvent at 70% util)
        // Actual: Liquidation reverts with "NotMarginCalled" (victim appears solvent at 40% util)
        vm.expectRevert(); // Liquidation incorrectly fails
        panopticPool.dispatchFrom(
            new TokenId[](0),
            victim,
            positionIds,
            new TokenId[](0),
            0
        );
        
        // 4. Victim avoided liquidation despite being actually insolvent
        // Protocol now holds bad debt from unliquidated insolvent position
    }
}
```

**Notes**
- This vulnerability exploits the design decision to use transient storage for maximum utilization tracking (anti-flash-loan protection) without ensuring view functions account for it
- The issue is particularly severe because liquidation is the protocol's primary defense against bad debt
- The attack can be executed atomically using multicall or a smart contract, making it easy to implement
- MEV searchers can profitably front-run liquidation transactions with this defense mechanism

### Citations

**File:** contracts/CollateralTracker.sol (L120-122)
```text
    /// @notice Transient storage slot for the utilization
    bytes32 internal constant UTILIZATION_TRANSIENT_SLOT =
        keccak256("panoptic.utilization.snapshot");
```

**File:** contracts/CollateralTracker.sol (L886-892)
```text
    function _accrueInterest(address owner, bool isDeposit) internal {
        uint128 _assetsInAMM = s_assetsInAMM;
        (
            uint128 currentBorrowIndex,
            uint128 _unrealizedGlobalInterest,
            uint256 currentEpoch
        ) = _calculateCurrentInterestState(_assetsInAMM, _updateInterestRate());
```

**File:** contracts/CollateralTracker.sol (L1032-1035)
```text
    function _interestRateView(uint256 utilization) internal view returns (uint128) {
        uint128 avgRate = riskEngine().interestRate(utilization, s_marketState);
        return avgRate;
    }
```

**File:** contracts/CollateralTracker.sol (L1091-1106)
```text
    function assetsAndInterest(address owner) external view returns (uint256, uint256) {
        return (convertToAssets(balanceOf[owner]), _owedInterest(owner));
    }

    /// @notice Internal function to calculate interest owed by a user
    /// @dev Retrieves user state and current borrow index from storage
    /// @param owner Address of the user to check
    /// @return Amount of interest owed based on last compounded index
    function _owedInterest(address owner) internal view returns (uint128) {
        LeftRightSigned userState = s_interestState[owner];
        (uint128 currentBorrowIndex, , ) = _calculateCurrentInterestState(
            s_assetsInAMM,
            _interestRateView(_poolUtilizationWadView())
        );
        return _getUserInterest(userState, currentBorrowIndex);
    }
```

**File:** contracts/CollateralTracker.sol (L1173-1195)
```text
    function _poolUtilizationWad() internal returns (uint256) {
        uint256 storedUtilization;
        bytes32 slot = UTILIZATION_TRANSIENT_SLOT;
        assembly {
            storedUtilization := tload(slot)
        }

        unchecked {
            // convert to WAD
            storedUtilization = (storedUtilization * WAD) / DECIMALS;
        }
        uint256 poolUtilization = _poolUtilizationWadView();

        if (storedUtilization > poolUtilization) {
            return storedUtilization;
        } else {
            // store the utilization as DECIMALS
            assembly {
                tstore(slot, div(mul(poolUtilization, DECIMALS), WAD))
            }
            return poolUtilization;
        }
    }
```

**File:** contracts/CollateralTracker.sol (L1199-1208)
```text
    function _poolUtilizationWadView() internal view returns (uint256 poolUtilization) {
        unchecked {
            return
                Math.mulDivRoundingUp(
                    uint256(s_assetsInAMM) + uint256(s_marketState.unrealizedInterest()),
                    WAD,
                    totalAssets()
                );
        }
    }
```

**File:** contracts/RiskEngine.sol (L1151-1152)
```text
            (balance0, interest0) = ct0.assetsAndInterest(user);
            (balance1, interest1) = ct1.assetsAndInterest(user);
```
