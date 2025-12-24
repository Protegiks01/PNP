# Audit Report

## Title 
Force Exercise Cost Manipulation via CurrentTick Boundary Exploitation

## Summary
The `exerciseCost()` function in `RiskEngine.sol` uses the manipulable `currentTick` parameter to determine if a position's legs are in-range, rather than the manipulation-resistant `oracleTick`. This allows attackers to pay only 0.01% (ONE_BPS) instead of 1.024% (FORCE_EXERCISE_COST) to force exercise in-range positions by temporarily pushing `currentTick` outside the position range while staying within the 513-tick TWAP deviation limit.

## Finding Description
The vulnerability exists in the `exerciseCost()` function's in-range detection logic. [1](#0-0) 

The function determines whether to apply FORCE_EXERCISE_COST (1.024%) or ONE_BPS (0.01%) based on the `hasLegsInRange` flag, which is set by checking if `currentTick` falls within the position's range boundaries. [2](#0-1) 

However, `currentTick` is the instantaneous Uniswap pool tick (obtained from `slot0()`), which can be manipulated via swaps. The only protection is the MAX_TWAP_DELTA_LIQUIDATION check (513 ticks, ~5%) in `dispatchFrom()`. [3](#0-2) 

**The Attack Path:**

For a position with `width=10` and `tickSpacing=60`:
- Range calculation: [4](#0-3) 
- `rangeDown = (10 * 60) / 2 = 300 ticks`
- `rangeUp = ceil(600 / 2) = 300 ticks`
- Position range: `[strike - 300, strike + 300)` (600 ticks total)

If `twapTick = strike` (position is in-range at oracle price):
1. Attacker swaps to push `currentTick` to `strike + 300` (exactly at upper boundary, out of range)
2. Tick deviation: `|300| < 513` ✓ (passes TWAP check)
3. `hasLegsInRange = false` (currentTick is out of range)
4. Exercise cost: **0.01%** instead of **1.024%** (102.4x reduction)

This breaks Protocol Invariant #15: "Force Exercise Costs: Base cost of 1.024% for in-range, 1 bps for out-of-range positions." The exercisee receives only 1/102.4 of the intended compensation despite their position being in-range at the manipulation-resistant oracle price.

## Impact Explanation
**High Severity** - This represents a significant economic exploit that:

1. **Direct Financial Loss**: Exercisees lose 99% of their intended compensation (1.024% → 0.01%)
2. **Protocol Invariant Violation**: The force exercise pricing mechanism fails to protect in-range position holders
3. **Systemic Risk**: Any position with range < 513 ticks (common for concentrated liquidity strategies) is vulnerable
4. **No Capital Lock**: Unlike traditional price manipulation, the attacker doesn't need to maintain the manipulated price—only during the force exercise transaction

For a $100,000 notional position:
- Intended cost: $1,024
- Actual cost paid: $10
- **Exercisee loss: $1,014**

## Likelihood Explanation
**High Likelihood** due to:

1. **Common Attack Surface**: Positions with widths 1-8 on pools with tickSpacing=60 have ranges < 513 ticks
2. **Economic Viability**: The saved exercise cost often exceeds the cost of temporarily manipulating the pool price via atomic swaps
3. **No Special Privileges Required**: Any user can call `dispatchFrom()` to force exercise
4. **Atomic Execution**: The entire attack (swap → force exercise) occurs in a single transaction, minimizing risk and detection
5. **Repeatable**: Multiple vulnerable positions can be force exercised in sequence

The attack becomes profitable when:
```
Saved Exercise Cost (1.024% - 0.01%) > Price Manipulation Cost
```

For most pools with reasonable liquidity, manipulating the price by 300 ticks temporarily is achievable with flash loans or large swaps that are immediately reversed.

## Recommendation
Modify `exerciseCost()` to use `oracleTick` instead of `currentTick` for the in-range detection:

```solidity
function exerciseCost(
    int24 currentTick,
    int24 oracleTick,
    TokenId tokenId,
    PositionBalance positionBalance
) external view returns (LeftRightSigned exerciseFees) {
    // ... existing code ...
    
    for (uint256 leg = 0; leg < tokenId.countLegs(); ++leg) {
        // ... existing code ...
        
        {
            (int24 rangeDown, int24 rangeUp) = PanopticMath.getRangesFromStrike(
                tokenId.width(leg),
                tokenId.tickSpacing()
            );

            int24 _strike = tokenId.strike(leg);

            // FIX: Use oracleTick instead of currentTick
            if ((oracleTick < _strike + rangeUp) && (oracleTick >= _strike - rangeDown)) {
                hasLegsInRange = true;
            }
        }
        // ... existing code ...
    }
    // ... existing code ...
}
```

This ensures the in-range determination uses the manipulation-resistant TWAP/EMA oracle price, while still using `currentTick` for the value delta calculations (lines 450-472) which already account for price discrepancies.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {TokenId} from "@types/TokenId.sol";
import {PositionBalance} from "@types/PositionBalance.sol";
import {LeftRightSigned} from "@types/LeftRight.sol";

contract ForceExerciseCostManipulationTest is Test {
    RiskEngine riskEngine;
    
    function setUp() public {
        // Deploy RiskEngine with standard parameters
        riskEngine = new RiskEngine(
            5_000_000,  // CROSS_BUFFER_0
            5_000_000,  // CROSS_BUFFER_1
            address(this), // guardian
            address(0)  // builderFactory
        );
    }
    
    function testForceExerciseCostManipulation() public {
        // Create a position with narrow range (600 ticks)
        // strike = 10000, width = 10, tickSpacing = 60
        TokenId tokenId = TokenId.wrap(0)
            .addLeg(0, 1, 0, 0, 0, 0, 10, 10000); // Long position, width=10
        
        // Position balance with 1e18 position size
        PositionBalance memory positionBalance = PositionBalance.wrap(
            uint256(1e18) | (uint256(5_000_000) << 128)
        );
        
        // Scenario 1: Honest force exercise
        // oracleTick = 10000 (at strike, in-range)
        // currentTick = 10000 (also at strike, in-range)
        int24 currentTick1 = 10000;
        int24 oracleTick1 = 10000;
        
        LeftRightSigned honestCost = riskEngine.exerciseCost(
            currentTick1,
            oracleTick1,
            tokenId,
            positionBalance
        );
        
        // Scenario 2: Manipulated force exercise
        // oracleTick = 10000 (still at strike, position IS in-range at oracle price)
        // currentTick = 10300 (manipulated to upper boundary, OUT of range)
        // Tick deviation = 300, which is < 513 (MAX_TWAP_DELTA_LIQUIDATION)
        int24 currentTick2 = 10300;
        int24 oracleTick2 = 10000;
        
        LeftRightSigned manipulatedCost = riskEngine.exerciseCost(
            currentTick2,
            oracleTick2,
            tokenId,
            positionBalance
        );
        
        // The manipulated cost should be ~102.4x less than honest cost
        // (FORCE_EXERCISE_COST / ONE_BPS = 102400 / 1000 = 102.4)
        uint256 honestCostAbs = uint256(uint128(-honestCost.rightSlot()));
        uint256 manipulatedCostAbs = uint256(uint128(-manipulatedCost.rightSlot()));
        
        // Assert the attacker pays significantly less
        assertGt(honestCostAbs, manipulatedCostAbs * 100);
        
        // Calculate the exercisee's loss
        uint256 loss = honestCostAbs - manipulatedCostAbs;
        
        console.log("Honest exercise cost:", honestCostAbs);
        console.log("Manipulated exercise cost:", manipulatedCostAbs);
        console.log("Exercisee loss:", loss);
        console.log("Cost reduction factor:", honestCostAbs / manipulatedCostAbs);
    }
}
```

**Notes:**
The vulnerability stems from using the instantaneous `currentTick` for business logic decisions (in-range detection) rather than the manipulation-resistant `oracleTick`. While `currentTick` is appropriate for calculating actual token deltas between current and oracle prices (as done in lines 450-472), it should not determine the base fee tier. The 513-tick TWAP deviation limit, designed to prevent extreme price manipulation during liquidations, is insufficient protection here because many standard positions have ranges narrower than 513 ticks, making them vulnerable to boundary manipulation attacks that stay within the "safe" deviation threshold.

### Citations

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

**File:** contracts/PanopticPool.sol (L1385-1389)
```text
                int256 MAX_TWAP_DELTA_LIQUIDATION = int256(
                    uint256(riskParameters.tickDeltaLiquidation())
                );
                if (Math.abs(currentTick - twapTick) > MAX_TWAP_DELTA_LIQUIDATION)
                    revert Errors.StaleOracle();
```

**File:** contracts/libraries/PanopticMath.sol (L426-429)
```text
        return (
            (width * tickSpacing) / 2,
            int24(int256(Math.unsafeDivRoundingUp(uint24(width) * uint24(tickSpacing), 2)))
        );
```
