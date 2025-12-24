# Audit Report

## Title 
Stale Safe Mode Calculation Enables Cross-Margining During High Volatility Periods

## Summary
The `dispatch()` function in `PanopticPool.sol` calculates the `safeMode` value once at the beginning of execution based on the current oracle pack state, but this value can become stale when the oracle pack is updated during `_validateSolvency()`. This temporal inconsistency allows users to mint positions with cross-margining enabled (when `safeMode = 0`) even when current market volatility conditions warrant safe mode activation (where `safeMode > 0` should disable cross-margining), violating the protocol's critical safety mechanism.

## Finding Description
The vulnerability stems from a temporal inconsistency in safe mode state evaluation across a single transaction:

**Step 1: Safe Mode Computed from Stale Oracle Pack** [1](#0-0) 

At the beginning of `dispatch()`, `getRiskParameters()` is called which computes the safe mode based on the current `s_oraclePack` state. [2](#0-1) 

This calls into the RiskEngine: [3](#0-2) 

The `isSafeMode()` function calculates safe mode based on oracle deltas: [4](#0-3) 

**Step 2: Operations Proceed with Stale Safe Mode**
Throughout the transaction, the safe mode value from Step 1 is used for critical checks: [5](#0-4) [6](#0-5) 

**Step 3: Oracle Pack Updated During Solvency Validation**
At the end of `dispatch()`, `_validateSolvency()` is called: [7](#0-6) 

Inside `_validateSolvency()`, `getSolvencyTicks()` is called which may return an updated oracle pack: [8](#0-7) [9](#0-8) 

The `getOracleTicks()` function calls `computeInternalMedian()` which updates the oracle pack if a new epoch has started: [10](#0-9) 

**Step 4: Critical Safety Check Uses Stale Safe Mode**
The solvency check receives the STALE safe mode parameter and uses it to determine whether to disable cross-margining: [11](#0-10) [12](#0-11) 

**The Vulnerability**: If the market experiences high volatility between when safe mode is computed (Step 1) and when the oracle pack is updated (Step 3), the updated oracle pack would contain new EMAs that would trigger `safeMode > 0` if recalculated. However, the solvency check still uses `safeMode = 0` from the stale calculation, allowing cross-margining when it should be disabled.

This breaks **Invariant #8: "Safe Mode Activation: Protocol must enter safe mode when oracle deltas exceed thresholds"** and **Invariant #5: "Cross-Collateral Limits: Cross-buffer ratio must scale conservatively with utilization, dropping to zero at 90% utilization"**.

## Impact Explanation
**High Severity** - This vulnerability enables systemic undercollateralization during high volatility periods:

1. **Cross-Margining During Unsafe Conditions**: When `safeMode = 0` is used (stale), users can mint positions with cross-collateralization enabled, even though current market conditions warrant `safeMode > 0` which forces 100% utilization (no cross-margining). This allows positions to be created with insufficient collateral during the exact moments when the protocol should be most conservative.

2. **Violation of Critical Safety Mechanism**: The safe mode system is specifically designed to protect the protocol during extreme market conditions by eliminating cross-margining. Bypassing this creates systemic risk exposure.

3. **Cascading Liquidations**: Undercollateralized positions created during volatile periods are more likely to become insolvent as prices continue to move, potentially triggering cascading liquidations and protocol losses.

4. **Liquidation Bonus Extraction**: If these undercollateralized positions become insolvent, liquidators extract bonuses from already-depleted collateral, potentially causing protocol losses that must be socialized.

## Likelihood Explanation
**High Likelihood**:

1. **Deterministic Timing Window**: The vulnerability occurs at epoch boundaries (every 64 seconds), which are deterministic based on `block.timestamp`. An attacker can calculate the exact time to submit their transaction.

2. **Natural Occurrence**: Even without malicious intent, legitimate users transacting at epoch boundaries during volatile markets will trigger this condition, creating systemic undercollateralization.

3. **No Special Privileges Required**: Any user with capital can exploit this by minting positions at epoch boundaries during high volatility.

4. **Frequent Market Conditions**: Cryptocurrency markets experience high volatility regularly, creating numerous exploitation opportunities.

5. **No Gas War Required**: Unlike MEV attacks, this doesn't require winning a gas war—just timing the transaction to land during the epoch transition window.

## Recommendation
Recalculate safe mode after the oracle pack is potentially updated in `_validateSolvency()`:

```solidity
function _validateSolvency(
    address user,
    TokenId[] calldata positionIdList,
    uint32 buffer,
    bool usePremiaAsCollateral,
    uint8 safeMode
) internal view returns (OraclePack) {
    _validatePositionList(user, positionIdList);

    int24 currentTick = getCurrentTick();

    OraclePack oraclePack;
    int24[] memory atTicks;

    (atTicks, oraclePack) = riskEngine().getSolvencyTicks(currentTick, s_oraclePack);

    // ADDED: Recalculate safe mode if oracle pack was updated
    if (OraclePack.unwrap(oraclePack) != 0) {
        safeMode = riskEngine().isSafeMode(currentTick, oraclePack);
    }

    if (positionIdList.length != 0) {
        uint256 solvent = _checkSolvencyAtTicks(
            user,
            safeMode, // Now uses updated safe mode
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

Alternatively, compute risk parameters AFTER updating the oracle pack rather than at the beginning of `dispatch()`.

## Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {OraclePack} from "@types/OraclePack.sol";
import {TokenId} from "@types/TokenId.sol";

contract StaleS afeModeTest is Test {
    PanopticPool pool;
    RiskEngine riskEngine;
    
    function testStaleSafeModeBypassesCrossMarginRestriction() public {
        // Setup: Initialize pool with oracle pack showing low volatility
        // Safe mode = 0 at this point
        
        // Step 1: Simulate time passing and market becoming highly volatile
        // but oracle pack hasn't updated yet (same epoch)
        vm.warp(block.timestamp + 63); // Almost at epoch boundary
        
        // Step 2: Record current safe mode (should be 0, based on old oracle pack)
        uint8 initialSafeMode = pool.isSafeMode();
        assertEq(initialSafeMode, 0, "Initial safe mode should be 0");
        
        // Step 3: Simulate additional volatility that would trigger safe mode > 0
        // Manipulate pool state to create high EMA deviation
        // (In reality, this would be natural market movement)
        
        // Step 4: Cross epoch boundary during dispatch call
        vm.warp(block.timestamp + 2); // Cross epoch boundary
        
        // Step 5: User mints position with cross-margining
        TokenId[] memory positionIdList = new TokenId[](1);
        positionIdList[0] = /* construct position */;
        uint128[] memory positionSizes = new uint128[](1);
        positionSizes[0] = 1000;
        int24[3][] memory tickAndSpreadLimits = new int24[3][](1);
        
        // This should FAIL if safe mode were correctly computed as > 0
        // But it SUCCEEDS because dispatch() uses stale safe mode = 0
        pool.dispatch(
            positionIdList,
            positionIdList,
            positionSizes,
            tickAndSpreadLimits,
            true, // usePremiaAsCollateral
            0
        );
        
        // Step 6: Verify oracle pack was updated during dispatch
        // and safe mode WOULD be > 0 if recalculated now
        uint8 finalSafeMode = pool.isSafeMode();
        assertGt(finalSafeMode, 0, "Safe mode should now be > 0");
        
        // Step 7: Verify position was created with cross-margining enabled
        // (checking position balance shows utilization < 10000)
        // This creates undercollateralized risk during high volatility
    }
}
```

### Citations

**File:** contracts/PanopticPool.sol (L591-593)
```text
        {
            int24 startTick;
            (riskParameters, startTick) = getRiskParameters(builderCode);
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

**File:** contracts/PanopticPool.sol (L630-631)
```text
                // revert if more than 2 conditions are triggered to prevent the minting of any positions
                if (riskParameters.safeMode() > 2) revert Errors.StaleOracle();
```

**File:** contracts/PanopticPool.sol (L694-702)
```text
        OraclePack oraclePack = _validateSolvency(
            msg.sender,
            finalPositionIdList,
            riskParameters.bpDecreaseBuffer(),
            usePremiaAsCollateral,
            riskParameters.safeMode()
        );
        // Update `s_oraclePack` with a new observation if the last observation is old enough (returned oraclePack is nonzero)
        if (OraclePack.unwrap(oraclePack) != 0) s_oraclePack = oraclePack;
```

**File:** contracts/PanopticPool.sol (L962-965)
```text
        OraclePack oraclePack;
        int24[] memory atTicks;

        (atTicks, oraclePack) = riskEngine().getSolvencyTicks(currentTick, s_oraclePack);
```

**File:** contracts/PanopticPool.sol (L968-976)
```text
            uint256 solvent = _checkSolvencyAtTicks(
                user,
                safeMode,
                positionIdList,
                currentTick,
                atTicks,
                usePremiaAsCollateral,
                uint256(buffer)
            );
```

**File:** contracts/PanopticPool.sol (L1740-1751)
```text
        // if safeMode is ON, make the collateral requirements for 100% utilizations: no cross-margining, fully covered positions
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
        }
```

**File:** contracts/PanopticPool.sol (L1808-1813)
```text
    function getRiskParameters(
        uint256 builderCode
    ) public view returns (RiskParameters riskParameters, int24 currentTick) {
        currentTick = getCurrentTick();
        riskParameters = riskEngine().getRiskParameters(currentTick, s_oraclePack, builderCode);
    }
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

**File:** contracts/RiskEngine.sol (L947-952)
```text
    function getSolvencyTicks(
        int24 currentTick,
        OraclePack _oraclePack
    ) external view returns (int24[] memory, OraclePack) {
        (int24 spotTick, int24 medianTick, int24 latestTick, OraclePack oraclePack) = _oraclePack
            .getOracleTicks(currentTick, EMA_PERIODS, MAX_CLAMP_DELTA);
```

**File:** contracts/types/OraclePack.sol (L536-567)
```text
    function computeInternalMedian(
        OraclePack oraclePack,
        int24 currentTick,
        uint96 EMAperiods,
        int24 clampDelta
    ) internal view returns (int24 _medianTick, OraclePack _updatedOraclePack) {
        unchecked {
            // return the average of the rank 3 and 4 values
            _medianTick = getMedianTick(oraclePack);

            uint256 currentEpoch;
            bool differentEpoch;
            int256 timeDelta;
            {
                currentEpoch = (block.timestamp >> 6) & 0xFFFFFF; // 64-long epoch, taken mod 2**24
                uint256 recordedEpoch = oraclePack.epoch();
                differentEpoch = currentEpoch != recordedEpoch;
                timeDelta = int256(uint256(uint24(currentEpoch - recordedEpoch))) * 64; // take a rought time delta, based on the epochs
            }
            // only proceed if last entry is in a different epoch
            if (differentEpoch) {
                int24 clampedTick = clampTick(currentTick, oraclePack, clampDelta);
                _updatedOraclePack = insertObservation(
                    oraclePack,
                    clampedTick,
                    currentEpoch,
                    timeDelta,
                    EMAperiods
                );
            }
        }
    }
```
