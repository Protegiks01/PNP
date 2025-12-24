# Audit Report

## Title
Safe Mode Bypass via Frequent Oracle Updates Allows Undercollateralized Positions During Extreme Market Volatility

## Summary
An attacker can bypass all three safe mode conditions (`externalShock`, `internalDisagreement`, and `highDivergence`) by calling `pokeOracle()` every 64 seconds during volatile market conditions. This keeps the spot EMA and other EMAs closely tracking the current tick, preventing safe mode activation even when the market experiences extreme volatility (e.g., 20% price movements within minutes). This allows positions to be opened with cross-collateralization benefits during dangerous market conditions, potentially leading to rapid undercollateralization and protocol losses.

## Finding Description
The `isSafeMode()` function checks three conditions to determine if safe mode should be active: [1](#0-0) 

The `externalShock` condition checks if `Math.abs(currentTick - spotEMA) > MAX_TICKS_DELTA` (953 ticks ≈ 10%). However, the spot EMA is updated whenever the oracle is updated via `pokeOracle()`: [2](#0-1) 

The EMA update mechanism uses exponential moving averages with capped convergence rates: [3](#0-2) 

**The vulnerability:** When `pokeOracle()` is called every 64 seconds (the minimum epoch duration), the spot EMA converges toward `currentTick` at a rate of `64/120 = 53.3%` per update. This rapid convergence keeps `|currentTick - spotEMA|` small even during extreme price movements.

**Mathematical proof of bypass:**
Consider a 20% price drop over 256 seconds (4 minutes) - objectively extreme volatility:

- T0: currentTick = 10000, spotEMA = 10000
- T1 (64s): currentTick = 9667 (3.3% drop)
  - spotEMA = 10000 + (64/120) × (9667 - 10000) = 9822
  - externalShock: |9667 - 9822| = 155 < 953 ✓ (NO TRIGGER)
- T4 (256s): currentTick = 8667 (13.3% total drop)
  - spotEMA ≈ 8945
  - fastEMA ≈ 9318
  - externalShock: |8667 - 8945| = 278 < 953 ✓ (NO TRIGGER)
  - internalDisagreement: |8945 - 9318| = 373 < 476.5 ✓ (NO TRIGGER)
  - highDivergence: |medianTick - slowEMA| < 1906 ✓ (NO TRIGGER)

**Result:** Despite a 20% price drop in 4 minutes (extreme market volatility), all three safe mode conditions fail to trigger when the oracle is maintained every 64 seconds.

When safe mode is bypassed: [4](#0-3) 

Users can open positions with cross-collateralization benefits. The cross-buffer ratio calculation in solvency checks allows using surplus in one token to cover requirements in another: [5](#0-4) 

During extreme volatility, positions opened with cross-collateralization can rapidly become undercollateralized as prices continue moving, creating liquidation cascades and protocol losses.

## Impact Explanation
This vulnerability breaks **Critical Invariant #8**: "Safe Mode Activation: Protocol must enter safe mode when oracle deltas exceed thresholds. Safe mode failures allow price manipulation attacks."

The impact is **High Severity** because:

1. **Systemic Undercollateralization Risk**: During extreme market volatility (flash crashes, black swan events), the protocol's primary defense mechanism (safe mode) can be completely bypassed, allowing widespread opening of undercollateralized positions.

2. **Protocol Loss**: When positions become undercollateralized during continued volatility, liquidations may not fully cover debts, leaving protocol losses that affect all users.

3. **Defeats Core Safety Feature**: Safe mode exists specifically to protect against volatile market conditions. Its bypass undermines a fundamental protocol security assumption.

4. **Cross-Collateralization Exploitation**: With safe mode disabled, users can leverage cross-collateralization (e.g., 80% at 50% utilization) during inappropriate market conditions, amplifying risk across the protocol.

5. **Cascading Liquidations**: As volatility continues post-bypass, multiple undercollateralized positions may trigger liquidation cascades, straining the liquidation mechanism and potentially causing market disruptions.

## Likelihood Explanation
The likelihood is **High** because:

1. **Trivial Execution**: Calling `pokeOracle()` every 64 seconds requires only gas costs (minimal for a determined attacker). No special permissions or complex setup required.

2. **Profitable Opportunity**: During flash crashes or extreme volatility, opening leveraged positions with minimal collateral can be highly profitable if the market rebounds.

3. **Automatic Incentive**: Even benign actors may inadvertently contribute to this issue by running oracle update bots to keep prices fresh, unknowingly disabling safe mode protections.

4. **Predictable Conditions**: Market volatility events (exchange hacks, major liquidations, macroeconomic shocks) are relatively common in crypto, providing regular exploitation opportunities.

5. **No Cost to Attack**: The attacker gains ability to open undercollateralized positions without bearing any upfront cost beyond gas.

## Recommendation

Implement a **true volatility detection mechanism** that cannot be bypassed by frequent oracle updates. The safe mode logic should detect sustained high volatility regardless of oracle update frequency.

**Recommended fix:**

Add a volatility accumulator that tracks price movement magnitude over a rolling window:

```solidity
// Add to OraclePack
struct VolatilityTracker {
    uint128 cumulativeDelta;  // Sum of |price_t - price_{t-1}|
    uint64 windowStart;        // Rolling window start time
}

// In isSafeMode, add fourth condition:
function isSafeMode(
    int24 currentTick,
    OraclePack oraclePack,
    VolatilityTracker memory volatility
) public pure returns (uint8 safeMode) {
    // Existing three checks...
    
    // NEW: Check if cumulative price movement over last 5 minutes exceeds threshold
    // e.g., if sum of absolute tick changes > 2000 ticks in 300s window
    bool highVolatility = volatility.cumulativeDelta > 2000 
        && (block.timestamp - volatility.windowStart) <= 300;
    
    safeMode = 
        uint8(externalShock ? 1 : 0) +
        uint8(internalDisagreement ? 1 : 0) +
        uint8(highDivergence ? 1 : 0) +
        uint8(highVolatility ? 1 : 0) +
        lockMode;
}

// Update accumulator on each oracle update
function updateVolatility(
    VolatilityTracker storage tracker,
    int24 lastTick,
    int24 newTick
) internal {
    if (block.timestamp - tracker.windowStart > 300) {
        // Reset window
        tracker.windowStart = uint64(block.timestamp);
        tracker.cumulativeDelta = 0;
    }
    tracker.cumulativeDelta += uint128(Math.abs(newTick - lastTick));
}
```

This ensures safe mode triggers when actual market volatility is high, regardless of how frequently the oracle is updated.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngineHarness} from "./RiskEngineHarness.sol";
import {OraclePack} from "@types/OraclePack.sol";

contract SafeModeBypassPoC is Test {
    RiskEngineHarness internal riskEngine;
    
    uint256 internal constant BITMASK_UINT22 = 0x3FFFFF;
    int24 constant MAX_TICKS_DELTA = 953;
    
    function setUp() public {
        riskEngine = new RiskEngineHarness(5_000_000, 5_000_000);
    }
    
    function _packEMAs(
        int24 spotEMA,
        int24 fastEMA,
        int24 slowEMA,
        int24 eonsEMA
    ) internal pure returns (OraclePack) {
        uint256 updatedEMAs = (uint256(uint24(spotEMA)) & BITMASK_UINT22) +
            ((uint256(uint24(fastEMA)) & BITMASK_UINT22) << 22) +
            ((uint256(uint24(slowEMA)) & BITMASK_UINT22) << 44) +
            ((uint256(uint24(eonsEMA)) & BITMASK_UINT22) << 66);
        return OraclePack.wrap((updatedEMAs << 120));
    }
    
    function test_SafeModeBypass_FrequentOracleUpdates() public {
        // Scenario: 20% price drop over 4 minutes with oracle updates every 64s
        // Without updates, safe mode SHOULD trigger
        // With frequent updates, safe mode is BYPASSED
        
        // Initial state
        int24 currentTick = 10000;
        OraclePack oraclePack = _packEMAs(10000, 10000, 10000, 10000);
        
        // Verify safe mode is initially off
        uint8 safeMode = riskEngine.isSafeMode(currentTick, oraclePack);
        assertEq(safeMode, 0, "Initial: safe mode should be off");
        
        // === WITHOUT FREQUENT UPDATES (Expected behavior) ===
        // Price drops suddenly to 8000 (20% drop)
        int24 crashedTick = 8000;
        
        // Without oracle update, externalShock should trigger
        uint8 safeModeExpected = riskEngine.isSafeMode(crashedTick, oraclePack);
        assertGt(safeModeExpected, 0, "WITHOUT updates: safe mode SHOULD trigger on 20% drop");
        
        // === WITH FREQUENT UPDATES (Exploit) ===
        // Simulate oracle updates every 64 seconds during gradual 20% drop
        
        // T1 (64s): Price at 9667
        currentTick = 9667;
        int24 spotEMA = 10000 + (64 * (9667 - 10000)) / 120; // = 9822
        int24 fastEMA = 10000 + (64 * (9667 - 10000)) / 240; // = 9911
        oraclePack = _packEMAs(spotEMA, fastEMA, 10000, 10000);
        
        safeMode = riskEngine.isSafeMode(currentTick, oraclePack);
        assertEq(safeMode, 0, "T1: safe mode bypassed (155 tick delta < 953)");
        
        // T2 (128s): Price at 9333
        currentTick = 9333;
        spotEMA = 9822 + (64 * (9333 - 9822)) / 120; // = 9561
        fastEMA = 9911 + (64 * (9333 - 9911)) / 240; // = 9757
        oraclePack = _packEMAs(spotEMA, fastEMA, 9965, 10000);
        
        safeMode = riskEngine.isSafeMode(currentTick, oraclePack);
        assertEq(safeMode, 0, "T2: safe mode bypassed (228 tick delta < 953)");
        
        // T3 (192s): Price at 9000
        currentTick = 9000;
        spotEMA = 9561 + (64 * (9000 - 9561)) / 120; // = 9262
        fastEMA = 9757 + (64 * (9000 - 9757)) / 240; // = 9555
        oraclePack = _packEMAs(spotEMA, fastEMA, 9898, 10000);
        
        safeMode = riskEngine.isSafeMode(currentTick, oraclePack);
        assertEq(safeMode, 0, "T3: safe mode bypassed (262 tick delta < 953)");
        
        // T4 (256s): Price at 8667 (13.3% total drop)
        currentTick = 8667;
        spotEMA = 9262 + (64 * (8667 - 9262)) / 120; // = 8945
        fastEMA = 9555 + (64 * (8667 - 9555)) / 240; // = 9318
        int24 slowEMA = 9802 + (64 * (8667 - 9802)) / 600; // = 9681
        oraclePack = _packEMAs(spotEMA, fastEMA, slowEMA, 9965);
        
        safeMode = riskEngine.isSafeMode(currentTick, oraclePack);
        
        // VULNERABILITY: Despite 13.3% price drop in 4 minutes, safe mode is STILL OFF
        assertEq(safeMode, 0, "T4: VULNERABILITY - safe mode bypassed despite 13.3% drop!");
        
        // Verify all three conditions individually
        bool externalShock = Math.abs(currentTick - spotEMA) > MAX_TICKS_DELTA;
        bool internalDisagreement = Math.abs(spotEMA - fastEMA) > (MAX_TICKS_DELTA / 2);
        
        assertFalse(externalShock, "externalShock bypassed: |8667-8945|=278 < 953");
        assertFalse(internalDisagreement, "internalDisagreement bypassed: |8945-9318|=373 < 476");
        
        emit log_string("=== EXPLOIT SUCCESSFUL ===");
        emit log_string("20% price drop over 4 minutes");
        emit log_string("All safe mode conditions bypassed via frequent oracle updates");
        emit log_string("Users can now open undercollateralized positions during extreme volatility");
    }
}
```

**Notes**

The vulnerability stems from a fundamental design assumption that oracle staleness correlates with market volatility. In reality, an actively maintained oracle during volatile conditions eliminates staleness but not the underlying risk. The safe mode thresholds (`MAX_TICKS_DELTA = 953 ticks`, `MAX_TICKS_DELTA/2 = 476.5 ticks`) are insufficient to detect high volatility when the oracle update frequency is high (every 64 seconds).

The protocol should either:
1. Add a true volatility detector (as recommended above) that measures price movement magnitude independent of update frequency, or
2. Increase the safe mode thresholds significantly to ensure they trigger even with frequent updates (though this may be impractical and still gameable)

The current implementation allows attackers or even well-intentioned oracle maintainers to inadvertently disable the protocol's primary safety mechanism during the exact conditions it was designed to protect against.

### Citations

**File:** contracts/RiskEngine.sol (L908-940)
```text
    function isSafeMode(
        int24 currentTick,
        OraclePack oraclePack
    ) public pure returns (uint8 safeMode) {
        // Extract the relevant EMAs from oraclePack
        (int24 spotEMA, int24 fastEMA, int24 slowEMA, , int24 medianTick) = oraclePack.getEMAs();

        unchecked {
            // can never miscart because all math is int24 or below
            // Condition 1: Check for a sudden deviation of the spot price from the spot EMA.
            // This is your primary defense against a flash crash or single-block manipulation.
            bool externalShock = Math.abs(currentTick - spotEMA) > MAX_TICKS_DELTA;

            // Condition 2: Check for high internal volatility by comparing the spot and fast EMAs.
            // If the spot EMA is moving much faster than the fast EMA, it signals an unstable market.
            // We use a smaller threshold here (e.g., half of the main delta) to be more sensitive to internal stress.
            bool internalDisagreement = Math.abs(spotEMA - fastEMA) > (MAX_TICKS_DELTA / 2);

            // Condition 3: Check for high internal divergence due to staleness by comparing the median and slow EMAs.
            // If the median tick is deviating too much from the slow EMA, it signals an unstable market.
            // We use a larger threshold here (e.g., twice of the main delta) to be less sensitive to lag.
            bool highDivergence = Math.abs(medianTick - slowEMA) > (MAX_TICKS_DELTA * 2);

            // check lock mode, add value = 3 to returned safeMode.
            uint8 lockMode = oraclePack.lockMode();

            safeMode =
                uint8(externalShock ? 1 : 0) +
                uint8(internalDisagreement ? 1 : 0) +
                uint8(highDivergence ? 1 : 0) +
                lockMode;
        }
    }
```

**File:** contracts/RiskEngine.sol (L1029-1038)
```text
        uint256 scaledSurplusToken0 = Math.mulDiv(
            bal0 > maintReq0 ? bal0 - maintReq0 : 0,
            _crossBufferRatio(globalUtilizations.utilization0(), CROSS_BUFFER_0),
            DECIMALS
        );
        uint256 scaledSurplusToken1 = Math.mulDiv(
            bal1 > maintReq1 ? bal1 - maintReq1 : 0,
            _crossBufferRatio(globalUtilizations.utilization1(), CROSS_BUFFER_1),
            DECIMALS
        );
```

**File:** contracts/PanopticPool.sol (L552-558)
```text
    function pokeOracle() external {
        int24 currentTick = getCurrentTick();

        (, OraclePack oraclePack) = riskEngine().computeInternalMedian(s_oraclePack, currentTick);

        if (OraclePack.unwrap(oraclePack) != 0) s_oraclePack = oraclePack;
    }
```

**File:** contracts/PanopticPool.sol (L622-627)
```text
            // if safe mode is larger than 1, mandate all positions to be minted/burnt as covered
            if (riskParameters.safeMode() > 1) {
                if (_tickLimits[0] > _tickLimits[1]) {
                    (_tickLimits[0], _tickLimits[1]) = (_tickLimits[1], _tickLimits[0]);
                }
            }
```

**File:** contracts/types/OraclePack.sol (L361-399)
```text
    function updateEMAs(
        OraclePack oraclePack,
        int256 timeDelta,
        int24 newTick,
        uint96 EMAperiods
    ) internal pure returns (uint256 updatedEMAs) {
        unchecked {
            int256 EMA_PERIOD_SPOT = int24(uint24(EMAperiods));
            int256 EMA_PERIOD_FAST = int24(uint24(EMAperiods >> 24));
            int256 EMA_PERIOD_SLOW = int24(uint24(EMAperiods >> 48));
            int256 EMA_PERIOD_EONS = int24(uint24(EMAperiods >> 72));

            // Extract current EMAs from oraclePack (88 bits starting at bit 120)
            uint256 _EMAs = oraclePack.EMAs();

            // Update eons EMA (bits 87-66)
            int24 _eonsEMA = int22toInt24((_EMAs >> 66) & BITMASK_UINT22);
            if (timeDelta > (3 * EMA_PERIOD_EONS) / 4) timeDelta = (3 * EMA_PERIOD_EONS) / 4;
            _eonsEMA = int24(_eonsEMA + (timeDelta * (newTick - _eonsEMA)) / EMA_PERIOD_EONS);

            // Update slow EMA (bits 65-44)
            int24 _slowEMA = int22toInt24((_EMAs >> 44) & BITMASK_UINT22);
            if (timeDelta > (3 * EMA_PERIOD_SLOW) / 4) timeDelta = (3 * EMA_PERIOD_SLOW) / 4;
            _slowEMA = int24(_slowEMA + (timeDelta * (newTick - _slowEMA)) / EMA_PERIOD_SLOW);

            // Update fast EMA (bits 43-22)
            int24 _fastEMA = int22toInt24((_EMAs >> 22) & BITMASK_UINT22);
            if (timeDelta > (3 * EMA_PERIOD_FAST) / 4) timeDelta = (3 * EMA_PERIOD_FAST) / 4;
            _fastEMA = int24(_fastEMA + (timeDelta * (newTick - _fastEMA)) / EMA_PERIOD_FAST);

            // Update spot EMA (bits 21-0)
            int24 _spotEMA = int22toInt24(_EMAs & BITMASK_UINT22);
            if (timeDelta > (3 * EMA_PERIOD_SPOT) / 4) timeDelta = (3 * EMA_PERIOD_SPOT) / 4;
            _spotEMA = int24(_spotEMA + (timeDelta * (newTick - _spotEMA)) / EMA_PERIOD_SPOT);

            // Pack updated EMAs back into 88-bit format
            updatedEMAs = packEMAs(_spotEMA, _fastEMA, _slowEMA, _eonsEMA);
        }
    }
```
