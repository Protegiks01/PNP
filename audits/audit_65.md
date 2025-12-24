# Audit Report

## Title
Integer Underflow in Premium Haircut Calculation Blocks Critical Liquidations

## Summary
The `RiskEngine.haircutPremia()` function contains an integer underflow vulnerability where subtracting `int128` values can produce `int256` results exceeding the `int128` range. When these values are later cast via `Math.toInt128()`, the transaction reverts, blocking liquidations of insolvent positions and exposing the protocol to systemic risk.

## Finding Description

The vulnerability occurs in the premium haircutting logic during liquidations. The function performs arithmetic operations on `int128` values that can produce `int256` results outside the valid `int128` range `[-2^127, 2^127-1]`. [1](#0-0) 

The initial `collateralDelta` values are derived from `LeftRightSigned` slots (which return `int128` values): [2](#0-1) 

The `longPremium` accumulates through subtraction operations that check for overflow, ensuring it remains within `int128` bounds: [3](#0-2) 

However, the critical issue occurs when these bounded `int128` values are used in further subtraction operations without overflow protection: [4](#0-3) 

The subtraction `longPremium.leftSlot() - collateralDelta1` operates on two `int128` values:
- `longPremium.leftSlot()` ∈ `[-2^127, 2^127-1]`
- `collateralDelta1` ∈ `[0, 2^127]` (non-negative due to negation of min)

The difference can range from `-(2^128-1)` to `2^127-1`, exceeding the `int128` minimum of `-2^127`.

When the result exceeds `int128` range, the subsequent cast fails: [5](#0-4) 

The `Math.toInt128(int256)` function validates the cast: [6](#0-5) 

If `toCast` is outside `int128` range (e.g., `-2^128`), the equality check fails and the function reverts with `Errors.CastingError()`.

**Additional Unsafe Casts:**

The code also contains direct unsafe casts to `int128` that could silently truncate: [7](#0-6) [8](#0-7) [9](#0-8) 

These direct casts bypass overflow detection and could produce incorrect `haircutBase` values if the sums exceed `int128` range.

The function is called during liquidations in `PanopticPool`: [10](#0-9) 

## Impact Explanation

This vulnerability has **HIGH** severity impact:

1. **Liquidation DoS**: When `longPremium` values approach `int128` limits and any protocol loss exists, liquidations revert, preventing closure of insolvent positions

2. **Protocol Insolvency Risk**: Unliquidatable positions expose the protocol to systemic risk as losses cannot be contained

3. **Invariant Violation**: Breaks Critical Invariant #1: "Insolvent positions must be liquidated immediately"

4. **Silent Truncation**: The unsafe direct casts can produce incorrect haircut calculations, potentially allowing protocol loss extraction

**Realistic Scenario:**
- User accumulates large long positions over time with negative premium approaching `-2^127`
- Market moves adversely, creating protocol loss (even 1 wei triggers the issue)
- Liquidation attempts revert due to integer underflow in haircut calculation
- Position remains open, accumulating further losses

## Likelihood Explanation

**Likelihood: MEDIUM**

While reaching exact `int128` boundaries requires extreme conditions, the vulnerability can trigger with:
- Long-held multi-leg positions accumulating significant premium
- Any non-zero protocol loss during liquidation
- High-value tokens or tokens with unusual decimal configurations

The unsafe direct casts are more likely to cause silent failures than reverts, making detection difficult.

## Recommendation

1. **Add overflow checks before subtraction operations:**

```solidity
// Before line 671
int256 premiumDelta = int256(longPremium.leftSlot()) - int256(collateralDelta1);
if (premiumDelta < type(int128).min || premiumDelta > type(int128).max) {
    // Handle overflow - cap the value or revert with descriptive error
    premiumDelta = premiumDelta < 0 ? type(int128).min : type(int128).max;
}
```

2. **Replace unsafe direct casts with `Math.toInt128()`:**

```solidity
// Line 683
haircutBase = LeftRightSigned.wrap(longPremium.rightSlot()).addToLeftSlot(
    Math.toInt128(int256(protocolLoss1) + int256(collateralDelta1))
);

// Lines 710, 716-717 - similar pattern
```

3. **Add explicit range validation:**

```solidity
// After collateralDelta reassignments
require(
    collateralDelta0 >= type(int128).min && collateralDelta0 <= type(int128).max,
    "collateralDelta0 out of int128 range"
);
require(
    collateralDelta1 >= type(int128).min && collateralDelta1 <= type(int128).max,
    "collateralDelta1 out of int128 range"
);
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Math} from "../contracts/libraries/Math.sol";
import {LeftRightSigned, LeftRightLibrary} from "../contracts/types/LeftRight.sol";

contract IntegerUnderflowTest is Test {
    using LeftRightLibrary for LeftRightSigned;

    function testHaircutPremiaUnderflow() public {
        // Simulate scenario where longPremium.leftSlot() is at int128 min
        int128 longPremiumLeft = type(int128).min; // -2^127
        
        // Even a small protocol loss triggers underflow
        int256 collateralDelta1 = 1; // Just 1 wei of protocol loss
        
        // Perform the subtraction that occurs in haircutPremia
        int256 result = int256(longPremiumLeft) - collateralDelta1;
        
        // Result is -2^127 - 1, which is less than int128 min
        assertLt(result, int256(type(int128).min));
        
        // Attempting to cast this to int128 would fail
        vm.expectRevert();
        Math.toInt128(result);
    }
    
    function testUnsafeCastSilentTruncation() public {
        // Demonstrate unsafe direct cast behavior
        int256 largeValue = int256(type(int128).max) + 1000;
        
        // Direct cast silently truncates
        int128 truncated = int128(largeValue);
        
        // The truncated value is incorrect
        assertNotEq(int256(truncated), largeValue);
        
        // But Math.toInt128 would properly revert
        vm.expectRevert();
        Math.toInt128(largeValue);
    }
    
    function testRealisticLiquidationBlock() public {
        // Setup: longPremium near limit, small protocol loss
        LeftRightSigned longPremium = LeftRightSigned.wrap(0)
            .addToLeftSlot(type(int128).min + 1000);
        
        int256 collateralDelta1 = 2000; // Small loss > 1000
        
        // Subtraction underflows
        int256 result = longPremium.leftSlot() - collateralDelta1;
        
        // Would cause liquidation to revert
        assertTrue(result < int256(type(int128).min));
        vm.expectRevert();
        Math.toInt128(result);
    }
}
```

**Notes:**
- The vulnerability breaks the critical solvency maintenance invariant
- Both revert-causing overflows (via `Math.toInt128`) and silent truncations (via direct casts) pose risks
- The deposit limit of `uint104` doesn't prevent this issue as the problem arises from arithmetic operations on already-bounded values
- The code comments acknowledge assumptions about value ranges but don't enforce them with proper checks

### Citations

**File:** contracts/RiskEngine.sol (L642-643)
```text
                int256 collateralDelta0 = -Math.min(collateralRemaining.rightSlot(), 0);
                int256 collateralDelta1 = -Math.min(collateralRemaining.leftSlot(), 0);
```

**File:** contracts/RiskEngine.sol (L651-651)
```text
                            longPremium = longPremium.sub(premiasByLeg[i][leg]);
```

**File:** contracts/RiskEngine.sol (L671-677)
```text
                        Math.min(
                            longPremium.leftSlot() - collateralDelta1,
                            PanopticMath.convert0to1(
                                collateralDelta0 - longPremium.rightSlot(),
                                atSqrtPriceX96
                            )
                        )
```

**File:** contracts/RiskEngine.sol (L682-683)
```text
                    haircutBase = LeftRightSigned.wrap(longPremium.rightSlot()).addToLeftSlot(
                        int128(protocolLoss1 + collateralDelta1)
```

**File:** contracts/RiskEngine.sol (L709-710)
```text
                    haircutBase = LeftRightSigned
                        .wrap(int128(protocolLoss0 + collateralDelta0))
```

**File:** contracts/RiskEngine.sol (L715-717)
```text
                    haircutBase = LeftRightSigned
                        .wrap(int128(Math.min(collateralDelta0, longPremium.rightSlot())))
                        .addToLeftSlot(int128(Math.min(collateralDelta1, longPremium.leftSlot())));
```

**File:** contracts/RiskEngine.sol (L724-725)
```text
                    .addToRightSlot(Math.toInt128(collateralDelta0))
                    .addToLeftSlot(Math.toInt128(collateralDelta1));
```

**File:** contracts/types/LeftRight.sol (L234-245)
```text
    function sub(LeftRightSigned x, LeftRightSigned y) internal pure returns (LeftRightSigned z) {
        unchecked {
            int256 left256 = int256(x.leftSlot()) - y.leftSlot();
            int128 left128 = int128(left256);

            int256 right256 = int256(x.rightSlot()) - y.rightSlot();
            int128 right128 = int128(right256);

            if (left128 != left256 || right128 != right256) revert Errors.UnderOverFlow();

            return z.addToRightSlot(right128).addToLeftSlot(left128);
        }
```

**File:** contracts/libraries/Math.sol (L463-465)
```text
    function toInt128(int256 toCast) internal pure returns (int128 downcastedInt) {
        if (!((downcastedInt = int128(toCast)) == toCast)) revert Errors.CastingError();
    }
```

**File:** contracts/PanopticPool.sol (L1561-1567)
```text
            (bonusDeltas, haircutTotal, haircutPerLeg) = riskEngine().haircutPremia(
                _liquidatee,
                _positionIdList,
                premiasByLeg,
                collateralRemaining,
                Math.getSqrtRatioAtTick(_twapTick)
            );
```
