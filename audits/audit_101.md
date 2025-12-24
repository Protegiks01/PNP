# Audit Report

## Title 
Time-Of-Check-Time-Of-Use (TOCTOU) Vulnerability in SafeMode Determination Enables Undercollateralized Positions

## Summary
A TOCTOU vulnerability exists in `PanopticPool.dispatch()` where `safeMode` is determined at the start of the transaction but solvency is validated using price ticks from the end of the transaction. This inconsistency allows users to bypass safe mode collateral requirements during volatile market conditions, enabling systemically undercollateralized positions.

## Finding Description

The vulnerability occurs in the `dispatch()` function flow where risk parameters are retrieved only once at the beginning, but market conditions may change significantly during execution:

**Step 1: Initial Risk Parameter Retrieval** [1](#0-0) 

At the start of `dispatch()`, `getRiskParameters()` is called, which internally fetches the current tick from Uniswap and computes `safeMode`: [2](#0-1) [3](#0-2) 

The `safeMode` calculation depends on the current price tick: [4](#0-3) 

**Step 2: Position Operations**
Between lines 610-690 of `dispatch()`, positions are minted/burned which interact with Uniswap pools, potentially causing significant price movements through swaps.

**Step 3: Stale SafeMode Used in Solvency Validation** [5](#0-4) 

The `_validateSolvency()` function receives the OLD `safeMode` value but fetches a FRESH `currentTick`: [6](#0-5) 

**Step 4: Inconsistent Collateral Requirements**
The stale `safeMode` is used to determine collateral requirements: [7](#0-6) 

When `safeMode > 0`, the protocol forces 100% pool utilization assumptions, eliminating cross-margining benefits and requiring fully covered positions. When `safeMode = 0`, actual pool utilizations are used, allowing significant cross-margining.

**The Vulnerability:**
If price movements during `dispatch()` execution should trigger `safeMode > 0` (requiring >953 tick movement per `MAX_TICKS_DELTA`), but the cached `safeMode = 0` is used, users pass solvency checks with:
- Cross-margining benefits they shouldn't have
- Less strict collateral requirements than current market risk warrants
- Positions that are undercollateralized relative to actual volatility

This breaks **Invariant 10 (Price Consistency)**: "All operations in a single transaction must use consistent oracle tick(s)," **Invariant 5 (Cross-Collateral Limits)**, and **Invariant 8 (Safe Mode Activation)**.

## Impact Explanation

**Severity: HIGH**

1. **Systemic Undercollateralization**: Users can maintain positions with insufficient collateral during high volatility periods when safe mode should be active.

2. **Cross-Margining Exploitation**: The cross-buffer ratio calculation depends on pool utilization. During safe mode, this should be eliminated (100% utilization), but users bypass this restriction. [8](#0-7) 

3. **Protocol Loss Risk**: Undercollateralized positions during volatile periods increase liquidation losses and protocol bad debt, as cross-margining provides false solvency during price shocks.

4. **Cascading Failures**: Multiple users exploiting this during volatility could cause systemic undercollateralization, threatening protocol solvency.

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

**Preconditions:**
1. Market conditions near safe mode threshold (currentTick close to spotEMA ± 953 ticks)
2. User operations in `dispatch()` cause sufficient price movement (>953 ticks ~10%)
3. Volatile or illiquid pools where large position changes trigger significant swaps

**Exploitability:**
- Attackers can monitor oracle states and execute large operations when conditions are borderline
- In illiquid pools, position sizes can be calculated to cause the required price movement
- No special privileges required—any user can exploit via `dispatch()`

**Real-World Scenarios:**
- During high market volatility (flash crashes, major news events)
- In newly launched or low-liquidity Panoptic pools
- When multiple large positions are opened/closed simultaneously

## Recommendation

**Fix: Recalculate safeMode after operations complete**

Modify `dispatch()` to recalculate `safeMode` after all position operations and before the final solvency check:

```solidity
function dispatch(
    TokenId[] calldata positionIdList,
    TokenId[] calldata finalPositionIdList,
    uint128[] calldata positionSizes,
    int24[3][] calldata tickAndSpreadLimits,
    bool usePremiaAsCollateral,
    uint256 builderCode
) external {
    RiskParameters riskParameters;
    // ... existing code for position operations ...
    
    // AFTER all operations complete, recalculate risk parameters with current state
    int24 finalTick = getCurrentTick();
    RiskParameters finalRiskParameters = riskEngine().getRiskParameters(
        finalTick, 
        s_oraclePack, 
        builderCode
    );
    
    // Use the FRESH safeMode for solvency validation
    OraclePack oraclePack = _validateSolvency(
        msg.sender,
        finalPositionIdList,
        finalRiskParameters.bpDecreaseBuffer(),
        usePremiaAsCollateral,
        finalRiskParameters.safeMode()  // Use fresh safeMode
    );
    
    if (OraclePack.unwrap(oraclePack) != 0) s_oraclePack = oraclePack;
}
```

**Alternative: Pass fresh tick to validateSolvency**

Allow `_validateSolvency()` to recalculate `safeMode` internally based on the fresh `currentTick` it fetches, rather than accepting it as a parameter.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "../contracts/PanopticPool.sol";
import {RiskEngine} from "../contracts/RiskEngine.sol";
import {TokenId} from "../contracts/types/TokenId.sol";

contract SafeModeTOCTOUTest is Test {
    PanopticPool pool;
    RiskEngine riskEngine;
    
    function setUp() public {
        // Setup Panoptic pool and risk engine
        // Initialize with tick close to safe mode threshold
    }
    
    function testSafeModeTOCTOU() public {
        // 1. Initial state: currentTick is just below safe mode threshold
        //    safeMode = 0 (normal operation)
        int24 initialTick = getCurrentTick();
        assert(abs(initialTick - spotEMA) < 953); // Below MAX_TICKS_DELTA
        
        // 2. User calls dispatch() with large position that will move price
        TokenId[] memory positions = new TokenId[](1);
        positions[0] = createLargePosition(); // Position designed to move price >953 ticks
        
        uint128[] memory sizes = new uint128[](1);
        sizes[0] = calculateSizeToMovePrice(953); // Moves price to trigger safe mode
        
        // 3. Execute dispatch
        pool.dispatch(
            positions,
            positions,
            sizes,
            createTickLimits(),
            true, // usePremiaAsCollateral
            0 // builderCode
        );
        
        // 4. Verify exploit success:
        int24 finalTick = getCurrentTick();
        
        // Price moved significantly, should trigger safe mode
        assert(abs(finalTick - spotEMA) > 953);
        
        // But user's position was validated with safeMode=0 benefits
        // User has cross-margining when they shouldn't
        (uint256 balance0, uint256 required0) = pool.getMargin(user, positions);
        
        // Calculate what requirement SHOULD be with safeMode=1 (100% utilization)
        uint256 requiredWithSafeMode = calculateRequiredWithSafeMode(positions);
        
        // Demonstrate user is undercollateralized relative to safe mode requirements
        assert(balance0 < requiredWithSafeMode);
        // But they passed solvency check with safeMode=0 requirements
        assert(balance0 >= required0);
        
        console.log("Exploit successful: User undercollateralized by:", 
                   requiredWithSafeMode - balance0);
    }
}
```

**Notes:**
- The vulnerability stems from caching `safeMode` at transaction start while price conditions change during execution
- This creates a window where users can bypass safe mode restrictions during the exact conditions that warrant them
- The fix must ensure consistency between the price state used for solvency ticks and the safeMode used for collateral calculations

### Citations

**File:** contracts/PanopticPool.sol (L593-593)
```text
            (riskParameters, startTick) = getRiskParameters(builderCode);
```

**File:** contracts/PanopticPool.sol (L694-700)
```text
        OraclePack oraclePack = _validateSolvency(
            msg.sender,
            finalPositionIdList,
            riskParameters.bpDecreaseBuffer(),
            usePremiaAsCollateral,
            riskParameters.safeMode()
        );
```

**File:** contracts/PanopticPool.sol (L960-965)
```text
        int24 currentTick = getCurrentTick();

        OraclePack oraclePack;
        int24[] memory atTicks;

        (atTicks, oraclePack) = riskEngine().getSolvencyTicks(currentTick, s_oraclePack);
```

**File:** contracts/PanopticPool.sol (L1741-1750)
```text
        if (safeMode > 0) {
            unchecked {
                // cannot miscast because DECIMAL = 10_000
                uint32 maxUtilizations = uint32(DECIMALS + (DECIMALS << 16));
                positionBalanceArray[0] = PositionBalanceLibrary.storeBalanceData(
                    positionBalanceArray[0].positionSize(),
                    maxUtilizations,
                    0
                );
            }
```

**File:** contracts/PanopticPool.sol (L1811-1812)
```text
        currentTick = getCurrentTick();
        riskParameters = riskEngine().getRiskParameters(currentTick, s_oraclePack, builderCode);
```

**File:** contracts/RiskEngine.sol (L864-886)
```text
    function getRiskParameters(
        int24 currentTick,
        OraclePack oraclePack,
        uint256 builderCode
    ) external view returns (RiskParameters) {
        uint8 safeMode = isSafeMode(currentTick, oraclePack);

        uint128 feeRecipient = uint256(uint160(_computeBuilderWallet(builderCode))).toUint128();

        return
            RiskParametersLibrary.storeRiskParameters(
                safeMode,
                NOTIONAL_FEE,
                PREMIUM_FEE,
                PROTOCOL_SPLIT,
                BUILDER_SPLIT,
                MAX_TWAP_DELTA_LIQUIDATION,
                MAX_SPREAD,
                BP_DECREASE_BUFFER,
                MAX_OPEN_LEGS,
                feeRecipient
            );
    }
```

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
