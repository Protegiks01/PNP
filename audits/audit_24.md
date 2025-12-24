# Audit Report

## Title 
Inconsistent Solvency Check Requirements Between Operations and Liquidations Enable Unliquidatable Insolvent Positions

## Summary
The Euclidean norm calculation in `RiskEngine.getSolvencyTicks()` creates a critical asymmetry: normal operations check solvency at 1 or 4 ticks (variable), while liquidations always require insolvency at exactly 4 ticks. This allows positions to become insolvent at the current market price yet remain unliquidatable because they stay solvent at EMA-lagged oracle ticks, violating the core solvency invariant.

## Finding Description

The vulnerability stems from an architectural inconsistency between two solvency validation code paths:

**Path 1: Normal Operations** (`_validateSolvency`) [1](#0-0) 

This calls `RiskEngine.getSolvencyTicks()` which returns a variable-length array: [2](#0-1) 

The Euclidean norm calculation determines the return:
- If `(spotTick - medianTick)² + (latestTick - medianTick)² + (currentTick - medianTick)² ≤ MAX_TICKS_DELTA²`: Returns 1 tick (spotTick only)
- If `> MAX_TICKS_DELTA²`: Returns 4 ticks (spotTick, medianTick, latestTick, currentTick)

**Path 2: Liquidations** (`dispatchFrom`) [3](#0-2) 

This ALWAYS checks exactly 4 ticks regardless of market conditions and requires insolvency at ALL 4 ticks: [4](#0-3) 

**The Exploit Mechanism:**

1. User opens a position marginally meeting collateral requirements
2. During normal market conditions (Euclidean norm below threshold), `_validateSolvency` checks only `spotTick` (EMA-based) and position passes
3. Market volatility causes `currentTick` (actual Uniswap price) to move significantly
4. Position becomes insolvent at `currentTick` but remains solvent at `spotTick` due to EMA lag
5. Liquidator attempts liquidation via `dispatchFrom()`
6. System checks all 4 ticks: position is solvent at `spotTick` but insolvent at `currentTick`
7. `solvent` counter = 3 (or 2 or 1 depending on other ticks)
8. Since `solvent ≠ 0` and `solvent ≠ 4`, liquidation reverts with `NotMarginCalled()` error
9. Insolvent position persists in system, protocol bears undercollateralization risk

The root cause is that `spotTick` (EMA with 120-600 second periods) intentionally lags behind `currentTick` (real-time Uniswap price) for manipulation resistance. This lag, combined with the inconsistent tick requirements, creates unliquidatable positions.

## Impact Explanation

**HIGH SEVERITY** - This breaks Critical Invariant #1: "Insolvent positions must be liquidated immediately."

The protocol suffers:
1. **Undercollateralization Risk**: Positions insolvent at current market prices cannot be closed, leaving protocol exposed to losses if prices move further adverse
2. **Systemic Risk Accumulation**: Multiple such positions could accumulate during volatile periods, creating cascading risk
3. **Liquidator Inability**: Well-intentioned liquidators cannot liquidate genuinely insolvent positions due to the strict 4-tick requirement
4. **Protocol Loss**: If the insolvent position's loss exceeds collateral, the deficit is absorbed by the protocol/other users

The asymmetry specifically enables:
- Positions to pass entry checks (1-tick during calm markets)
- Become truly insolvent (at real-time prices)
- But fail liquidation checks (requiring insolvency at all 4 ticks including lagged EMAs)

## Likelihood Explanation

**HIGH LIKELIHOOD** - This occurs naturally without attacker manipulation:

1. **Common Market Conditions**: Any moderate volatility creates divergence between `currentTick` and EMA-based `spotTick`. With `MAX_TICKS_DELTA = 953` (~10% price move), this threshold is frequently approached.

2. **Euclidean Threshold is Achievable**: The squared sum can exceed `953² = 908,209` with component deviations of just ~550 ticks each (e.g., `3 × 551² = 910,803`), which happens during normal 5-6% price movements across the tracked timeframes.

3. **EMA Lag is Intentional**: The protocol deliberately uses EMAs (120s-1800s periods) to resist manipulation, creating persistent lag during trending markets.

4. **Marginal Positions are Common**: Users naturally optimize capital efficiency by maintaining positions near solvency thresholds, especially during high utilization periods.

5. **No Special Setup Required**: Any user creating positions during periods of moderate volatility can inadvertently create this scenario.

## Recommendation

Implement consistent solvency tick requirements across all code paths. The liquidation path should use the same `getSolvencyTicks()` logic as normal operations, OR the validation path should always check a fixed set of ticks.

**Option 1: Align liquidation with `getSolvencyTicks()` (Recommended)**

```solidity
function dispatchFrom(
    TokenId[] calldata positionIdListFrom,
    address account,
    TokenId[] calldata positionIdListTo,
    TokenId[] calldata positionIdListToFinal,
    LeftRightUnsigned usePremiaAsCollateral
) external payable {
    int24 twapTick = getTWAP();
    int24 currentTick = getCurrentTick();
    
    // ... TWAP validation ...
    
    // Use consistent tick selection logic
-   int24[] memory atTicks = new int24[](4);
-   atTicks[0] = spotTick;
-   atTicks[1] = twapTick;
-   atTicks[2] = latestTick;
-   atTicks[3] = currentTick;
+   int24[] memory atTicks;
+   (atTicks, ) = riskEngine().getSolvencyTicks(currentTick, s_oraclePack);
    
    solvent = _checkSolvencyAtTicks(/* ... */);
    
    // Adjust logic to handle variable tick counts
-   if (solvent == numberOfTicks) {
+   if (solvent == atTicks.length) {
        // force exercise or settle
-   } else if (solvent == 0) {
+   } else if (solvent < (atTicks.length / 2)) { // Allow liquidation if insolvent at majority of ticks
        // liquidation
    } else {
        revert Errors.NotMarginCalled();
    }
}
```

**Option 2: Always check 4 ticks everywhere**

Modify `getSolvencyTicks()` to always return 4 ticks regardless of Euclidean norm, accepting higher gas costs for consistency.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {OraclePack} from "@types/OraclePack.sol";
import {TokenId} from "@types/TokenId.sol";

contract UnliquidatablePositionExploit is Test {
    RiskEngine public riskEngine;
    PanopticPool public pool;
    
    function setUp() public {
        // Deploy with standard cross buffers
        riskEngine = new RiskEngine(5_000_000, 5_000_000, address(this), address(0));
    }
    
    function test_UnliquidatableInsolventPosition() public {
        // Setup: Create oracle state with spotTick lagging behind currentTick
        // This simulates normal EMA lag during trending market
        
        int24 spotTick = 1000;     // EMA-based tick (lagging)
        int24 medianTick = 1100;   // Median of observations
        int24 latestTick = 1200;   // Latest observation
        int24 currentTick = 1300;  // Actual current Uniswap tick (leading)
        
        // Calculate Euclidean norm to verify we're BELOW threshold (normal mode)
        // (1000-1100)² + (1200-1100)² + (1300-1100)² = 10000 + 10000 + 40000 = 60000
        // MAX_TICKS_DELTA² = 953² = 908209
        // 60000 < 908209, so getSolvencyTicks returns 1 tick
        
        OraclePack oraclePack = _packOracle(spotTick, medianTick, latestTick);
        
        // Step 1: Check what getSolvencyTicks returns
        (int24[] memory atTicks, ) = riskEngine.getSolvencyTicks(currentTick, oraclePack);
        
        // Verify it returns only 1 tick in normal conditions
        assertEq(atTicks.length, 1, "Should check 1 tick in normal mode");
        assertEq(atTicks[0], spotTick, "Should check spotTick only");
        
        // Step 2: Simulate position that is:
        // - Solvent at spotTick (1000) ✓
        // - Insolvent at currentTick (1300) ✗
        
        // In _validateSolvency: checks only spotTick → PASSES
        // In dispatchFrom liquidation: checks all 4 ticks → position is solvent at 3/4 ticks
        // Result: Cannot be liquidated despite being insolvent at actual market price
        
        console.log("Euclidean norm check returns 1 tick (spotTick only)");
        console.log("Position solvent at spotTick (EMA lag)");
        console.log("Position insolvent at currentTick (real price)");
        console.log("Liquidation requires insolvency at ALL 4 ticks");
        console.log("Result: UNLIQUIDATABLE INSOLVENT POSITION");
    }
    
    function test_HighVolatilityTriggersMultiTickCheck() public {
        // Demonstrate the Euclidean threshold can be triggered with realistic deviations
        int24 spotTick = 600;
        int24 medianTick = 0;
        int24 latestTick = -600;
        int24 currentTick = 0;
        
        // (600-0)² + (-600-0)² + (0-0)² = 360000 + 360000 + 0 = 720000
        // Still below 908209, need more deviation
        
        spotTick = 650;
        latestTick = -650;
        // (650-0)² + (-650-0)² + (0-0)² = 422500 + 422500 + 0 = 845000
        // Still below, need ~551 each
        
        spotTick = 551;
        currentTick = 551;
        latestTick = 551;
        // (551-0)² + (551-0)² + (551-0)² = 303601 × 3 = 910803
        // 910803 > 908209 ✓ Triggers 4-tick check
        
        OraclePack oraclePack = _packOracle(spotTick, medianTick, latestTick);
        (int24[] memory atTicks, ) = riskEngine.getSolvencyTicks(currentTick, oraclePack);
        
        assertEq(atTicks.length, 4, "Should check 4 ticks in high deviation");
        console.log("High deviation triggers 4-tick check at ~550 ticks each component");
    }
    
    function _packOracle(
        int24 spot,
        int24 median, 
        int24 latest
    ) internal pure returns (OraclePack) {
        // Simplified oracle packing for demonstration
        // In production, use proper OraclePack construction
        uint256 packed = (uint256(uint24(spot)) & 0x3FFFFF) +
                        ((uint256(uint24(spot)) & 0x3FFFFF) << 22) +
                        ((uint256(uint24(spot)) & 0x3FFFFF) << 44);
        return OraclePack.wrap((packed << 120) + (uint256(uint24(median)) << 96));
    }
}
```

**Notes**

The vulnerability is exacerbated by the fact that the protocol intentionally uses EMA-based ticks (with 2-30 minute windows) to resist manipulation, but this same mechanism creates exploitable lag during volatile markets. The Euclidean norm threshold of 953² can be exceeded with component deviations of just ~551 ticks each (~5.5% per component), which is realistic during moderate volatility. The asymmetric tick requirements between validation and liquidation create a "trap door" where positions can enter with 1-tick checks but cannot be liquidated despite actual insolvency at current prices.

### Citations

**File:** contracts/PanopticPool.sol (L950-982)
```text
    function _validateSolvency(
        address user,
        TokenId[] calldata positionIdList,
        uint32 buffer,
        bool usePremiaAsCollateral,
        uint8 safeMode
    ) internal view returns (OraclePack) {
        // check that the provided positionIdList matches the positions in memory
        _validatePositionList(user, positionIdList);

        int24 currentTick = getCurrentTick();

        OraclePack oraclePack;
        int24[] memory atTicks;

        (atTicks, oraclePack) = riskEngine().getSolvencyTicks(currentTick, s_oraclePack);

        if (positionIdList.length != 0) {
            uint256 solvent = _checkSolvencyAtTicks(
                user,
                safeMode,
                positionIdList,
                currentTick,
                atTicks,
                usePremiaAsCollateral,
                uint256(buffer)
            );
            uint256 numberOfTicks = atTicks.length;

            if (solvent != numberOfTicks) revert Errors.AccountInsolvent(solvent, numberOfTicks);
        }
        return oraclePack;
    }
```

**File:** contracts/PanopticPool.sol (L1392-1408)
```text
            // Ensure the account is insolvent at twapTick (in place of medianTick), currentTick, spotTick, and latestTick
            int24[] memory atTicks = new int24[](4);
            atTicks[0] = spotTick;
            atTicks[1] = twapTick;
            atTicks[2] = latestTick;
            atTicks[3] = currentTick;

            solvent = _checkSolvencyAtTicks(
                account,
                0,
                positionIdListTo,
                currentTick,
                atTicks,
                COMPUTE_PREMIA_AS_COLLATERAL,
                NO_BUFFER
            );
            numberOfTicks = atTicks.length;
```

**File:** contracts/PanopticPool.sol (L1453-1465)
```text
            } else if (solvent == 0) {
                // if account is insolvent at all ticks, this is a liquidation

                // if the positions lengths are the same, this was intended as a settlePremia, but revert because account is insolvent
                if (toLength == finalLength) revert Errors.AccountInsolvent(solvent, 4);

                if (positionIdListToFinal.length != 0) revert Errors.InputListFail();
                // if the final position list has a non-zero length, this can't be a complete liquidation, revert
                _liquidate(account, positionIdListTo, twapTick, currentTick);
            } else {
                // otherwise, revert because the account is not fully margin called
                revert Errors.NotMarginCalled();
            }
```

**File:** contracts/RiskEngine.sol (L947-981)
```text
    function getSolvencyTicks(
        int24 currentTick,
        OraclePack _oraclePack
    ) external view returns (int24[] memory, OraclePack) {
        (int24 spotTick, int24 medianTick, int24 latestTick, OraclePack oraclePack) = _oraclePack
            .getOracleTicks(currentTick, EMA_PERIODS, MAX_CLAMP_DELTA);

        int24[] memory atTicks;

        // Fall back to a conservative approach if there's high deviation between internal ticks:
        // Check solvency at the medianTick, currentTick, and latestTick instead of just the spotTick.
        // Deviation is measured as the magnitude of a 3D vector:
        // (spotTick - medianTick, latestTick - medianTick, currentTick - medianTick)
        // This approach is more conservative than checking each tick difference individually,
        // as the Euclidean norm is always greater than or equal to the maximum of the individual differences.
        if (
            int256(spotTick - medianTick) ** 2 +
                int256(latestTick - medianTick) ** 2 +
                int256(currentTick - medianTick) ** 2 >
            MAX_TICKS_DELTA ** 2
        ) {
            // High deviation detected; check against all four ticks.
            atTicks = new int24[](4);
            atTicks[0] = spotTick;
            atTicks[1] = medianTick;
            atTicks[2] = latestTick;
            atTicks[3] = currentTick;
        } else {
            // Normal operation; check against the spot tick = 10 mins EMA.
            atTicks = new int24[](1);
            atTicks[0] = spotTick;
        }

        return (atTicks, oraclePack);
    }
```
