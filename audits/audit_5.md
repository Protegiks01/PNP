# Audit Report

## Title 
Force Exercise Validation Bypass Allows Exercising In-Range Positions at 100x Higher Cost

## Summary
The `validateIsExercisable()` function in `TokenId.sol` was modified to remove the moneyness check that previously ensured at least one long leg was out-of-range. This allows attackers to craft positions with all long legs in-range that pass validation but charge exercisors 1.024% of notional (100x higher than the intended 0.01% for out-of-range positions), wasting the exercisor's fees on economically active positions that should not be force-exercisable.

## Finding Description
The force exercise mechanism in `PanopticPool.dispatchFrom()` validates positions using `tokenId.validateIsExercisable()` before allowing exercise. [1](#0-0) 

The current implementation of `validateIsExercisable()` only checks if a position has at least one long leg with non-zero width, without verifying if any leg is actually out-of-range (far-out-of-the-money). [2](#0-1) 

According to the diff file, the previous implementation correctly checked if at least one long leg was outside its price range before allowing exercise. [3](#0-2) 

The fee structure in `RiskEngine.exerciseCost()` charges drastically different rates based on whether legs are in-range:
- In-range positions: `FORCE_EXERCISE_COST = 102_400 / 10_000_000 = 1.024%` of notional
- Out-of-range positions: `ONE_BPS = 1000 / 10_000_000 = 0.01%` of notional [4](#0-3) [5](#0-4) [6](#0-5) 

The `exerciseCost()` function determines if legs are in-range by checking if the current tick falls within the strike price ranges. [7](#0-6) 

**Attack Vector:**
1. Attacker creates a position with all long legs positioned IN-RANGE (current tick within strike ± range)
2. This position passes `validateIsExercisable()` because it has long legs with `width != 0`
3. An exercisor calls `dispatchFrom()` to force exercise this position
4. The exercisor pays 1.024% of notional to the attacker (100x more than the 0.01% for legitimate out-of-range positions)
5. The exercisor receives no economic benefit because in-range positions are actively earning fees and should not be force-exercised

This breaks **Invariant #25** ("Force Exercise Validation: Only long legs contribute to force exercise costs, must account for token deltas. Incorrect validation enables forced exercise theft") and **Invariant #15** ("Force Exercise Costs: Base cost of 1.024% for in-range, 1 bps for out-of-range positions").

## Impact Explanation
**Severity: Medium**

This vulnerability enables economic manipulation where:
- Exercisors waste fees on positions that shouldn't be exercisable (1.024% vs 0.01%)
- Attackers receive 100x higher fees than intended for no legitimate service
- The high cost discourages legitimate force exercises, allowing truly problematic positions to remain open

The impact is limited to the exercise fees and doesn't directly drain protocol funds, but it creates a broken incentive structure where the force exercise mechanism becomes economically non-viable.

## Likelihood Explanation
**Likelihood: High**

- The vulnerability exists in the validation logic itself and affects all force exercise operations
- Any user can create in-range long positions that trigger this bug
- Automated bots or users attempting to exercise positions will unknowingly pay the inflated fee
- No special permissions or complex setup required
- The position passes all validation checks in the current implementation

## Recommendation
Restore the moneyness check in `validateIsExercisable()` to ensure at least one long leg is out-of-range before allowing force exercise:

```solidity
function validateIsExercisable(TokenId self, int24 currentTick) internal pure returns (uint256) {
    unchecked {
        uint256 numLegs = self.countLegs();
        for (uint256 i = 0; i < numLegs; ++i) {
            if (self.isLong(i) == 1 && self.width(i) != 0) {
                // Check if this long leg is out-of-range
                (int24 rangeDown, int24 rangeUp) = PanopticMath.getRangesFromStrike(
                    self.width(i),
                    self.tickSpacing()
                );
                
                int24 _strike = self.strike(i);
                // Check if the price is outside this chunk
                if ((currentTick >= _strike + rangeUp) || (currentTick < _strike - rangeDown)) {
                    return 1; // At least one out-of-range long leg found
                }
            }
        }
    }
    
    // No out-of-range long legs found
    return 0;
}
```

Update the function signature in `PanopticPool.sol` to pass `currentTick`:
```solidity
if (tokenId.countLongs() == 0 || tokenId.validateIsExercisable(currentTick) == 0)
    revert Errors.NoLegsExercisable();
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {TokenId} from "@types/TokenId.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {PositionBalance} from "@types/PositionBalance.sol";
import {LeftRightSigned} from "@types/LeftRight.sol";

contract ForceExerciseValidationBypassTest is Test {
    using TokenId for TokenId;
    
    function testForceExerciseInRangePositionHighFees() public {
        // Setup: Create a tokenId with a long leg IN-RANGE
        TokenId tokenId = TokenId.wrap(0);
        
        int24 currentTick = 100;
        int24 tickSpacing = 10;
        
        // Add poolId and tickSpacing
        tokenId = tokenId.addPoolId(1);
        tokenId = tokenId.addTickSpacing(tickSpacing);
        
        // Add a long leg (isLong=1) with width=10 centered at strike=100
        // This makes the range [90, 110], so currentTick=100 is IN-RANGE
        tokenId = tokenId.addLeg(
            0,        // legIndex
            1,        // optionRatio
            0,        // asset
            1,        // isLong (LONG position)
            0,        // tokenType
            0,        // riskPartner
            100,      // strike (centered at current tick)
            10        // width
        );
        
        // This position passes validateIsExercisable because it has a long leg with width != 0
        uint256 isExercisable = tokenId.validateIsExercisable();
        assertEq(isExercisable, 1, "Position should pass validation");
        
        // However, when calculating exercise cost, this will charge 1.024% (FORCE_EXERCISE_COST)
        // because the leg is in-range, not 0.01% (ONE_BPS) for out-of-range positions
        
        // The exercisor pays 100x more than intended for a position that shouldn't be exercisable
        
        // Expected behavior: validateIsExercisable should return 0 for in-range positions
        // Actual behavior: Returns 1, allowing expensive force exercise of active positions
    }
    
    function testCompareInRangeVsOutOfRangeFees() public {
        int24 currentTick = 100;
        int24 tickSpacing = 10;
        
        // IN-RANGE position: strike at currentTick
        TokenId inRangeTokenId = TokenId.wrap(0)
            .addPoolId(1)
            .addTickSpacing(tickSpacing)
            .addLeg(0, 1, 0, 1, 0, 0, 100, 10); // strike=100, width=10, range=[90,110]
        
        // OUT-OF-RANGE position: strike far from currentTick  
        TokenId outOfRangeTokenId = TokenId.wrap(0)
            .addPoolId(1)
            .addTickSpacing(tickSpacing)
            .addLeg(0, 1, 0, 1, 0, 0, 1000, 10); // strike=1000, width=10, far OTM
        
        // Both pass validation (BUG!)
        assertEq(inRangeTokenId.validateIsExercisable(), 1);
        assertEq(outOfRangeTokenId.validateIsExercisable(), 1);
        
        // But exerciseCost would charge:
        // - IN-RANGE: 1.024% of notional (FORCE_EXERCISE_COST = 102_400)
        // - OUT-OF-RANGE: 0.01% of notional (ONE_BPS = 1000)
        // Difference: 100x higher for in-range positions that shouldn't be exercisable!
    }
}
```

## Notes
The vulnerability stems from a refactoring that simplified `validateIsExercisable()` by removing the `currentTick` parameter and the moneyness check. While this may have been intended for gas optimization or code simplification, it breaks a critical invariant that force exercise should only apply to out-of-range positions. The outdated comment at line 531 ("Fail if position has no legs that is far-out-of-the-money") reveals the original intent that is no longer enforced. [8](#0-7)

### Citations

**File:** contracts/PanopticPool.sol (L1433-1434)
```text
                        if (tokenId.countLongs() == 0 || tokenId.validateIsExercisable() == 0)
                            revert Errors.NoLegsExercisable();
```

**File:** contracts/types/TokenId.sol (L517-533)
```text
    /// @notice Check whether a position `self` contains at least one exercisable long leg.
    /// @dev A leg is considered exercisable if it is:
    ///      - long (isLong == 1), and
    ///      - not a loan/credit leg (width != 0).
    /// @dev This function does NOT check moneyness or price ranges.
    /// @return hasExercisableLong Returns 1 if such a leg exists, 0 otherwise.
    function validateIsExercisable(TokenId self) internal pure returns (uint256) {
        unchecked {
            uint256 numLegs = self.countLegs();
            for (uint256 i = 0; i < numLegs; ++i) {
                if (self.isLong(i) == 1 && self.width(i) != 0) return 1; // validated
            }
        }

        // Fail if position has no legs that is far-out-of-the-money
        return 0;
    }
```

**File:** diff/TokenId.sol.diff (L197-231)
```text
-    /// @dev At least one long leg must be far-out-of-the-money (i.e. price is outside its range).
-    /// @dev Reverts if the position is not exercisable.
-    /// @param self The TokenId to validate for exercisability
-    /// @param currentTick The current tick corresponding to the current price in the Uniswap V4 pool
-    function validateIsExercisable(TokenId self, int24 currentTick) internal pure {
+    /// @notice Check whether a position `self` contains at least one exercisable long leg.
+    /// @dev A leg is considered exercisable if it is:
+    ///      - long (isLong == 1), and
+    ///      - not a loan/credit leg (width != 0).
+    /// @dev This function does NOT check moneyness or price ranges.
+    /// @return hasExercisableLong Returns 1 if such a leg exists, 0 otherwise.
+    function validateIsExercisable(TokenId self) internal pure returns (uint256) {
         unchecked {
             uint256 numLegs = self.countLegs();
             for (uint256 i = 0; i < numLegs; ++i) {
-                (int24 rangeDown, int24 rangeUp) = PanopticMath.getRangesFromStrike(
-                    self.width(i),
-                    self.tickSpacing()
-                );
-
-                int24 _strike = self.strike(i);
-                // check if the price is outside this chunk
-                if ((currentTick >= _strike + rangeUp) || (currentTick < _strike - rangeDown)) {
-                    // if this leg is long and the price beyond the leg's range:
-                    // this exercised ID, `self`, appears valid
-                    if (self.isLong(i) == 1) return; // validated
-                }
+                if (self.isLong(i) == 1 && self.width(i) != 0) return 1; // validated
             }
         }
 
         // Fail if position has no legs that is far-out-of-the-money
-        revert Errors.NoLegsExercisable();
+        return 0;
     }
```

**File:** contracts/RiskEngine.sol (L61-61)
```text
    uint256 internal constant ONE_BPS = 1000;
```

**File:** contracts/RiskEngine.sol (L138-138)
```text
    uint256 constant FORCE_EXERCISE_COST = 102_400;
```

**File:** contracts/RiskEngine.sol (L426-435)
```text
                (int24 rangeDown, int24 rangeUp) = PanopticMath.getRangesFromStrike(
                    tokenId.width(leg),
                    tokenId.tickSpacing()
                );

                int24 _strike = tokenId.strike(leg);

                if ((currentTick < _strike + rangeUp) && (currentTick >= _strike - rangeDown)) {
                    hasLegsInRange = true;
                }
```

**File:** contracts/RiskEngine.sol (L479-479)
```text
        int256 fee = hasLegsInRange ? -int256(FORCE_EXERCISE_COST) : -int256(ONE_BPS);
```
