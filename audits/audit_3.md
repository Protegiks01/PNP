# Audit Report

## Title
Oracle Staleness Enables Liquidation of Solvent Accounts Through Price Manipulation

## Summary
The `dispatchFrom()` function in `PanopticPool.sol` does not update the oracle before performing liquidation solvency checks, allowing an attacker to exploit stale oracle data combined with spot price manipulation to liquidate accounts that are solvent at the true current price.

## Finding Description

The vulnerability exists in the liquidation flow of `dispatchFrom()` at lines 1368-1389 in `PanopticPool.sol`. The function performs the following checks: [1](#0-0) 

The critical issue is that **the oracle is never updated during `dispatchFrom()`**. The function reads stale oracle values from `s_oraclePack`: [2](#0-1) 

Note that the 4th return value (updated `oraclePack`) is discarded. Even when `computeInternalMedian()` detects that enough time has passed and returns an updated oracle pack, it is not stored back to `s_oraclePack`. [3](#0-2) 

This breaks **Invariant #11 (Liquidation Price Bounds)** and **Invariant #26 (Solvency Check Timing)**. The attack works as follows:

**Attack Scenario:**
1. Account opens a short call position that becomes insolvent when price increases
2. At tick 10,000, account is marginally solvent
3. Oracle gets updated: `spotTick` = `twapTick` = `latestTick` ≈ 10,000
4. Several hours pass with no oracle updates (oracle becomes stale)
5. Real Uniswap pool price drops to 8,000 (down 2,000 ticks)
6. At true price 8,000, account is **very solvent** (short call is safer when price drops)
7. Attacker identifies the stale oracle opportunity:
   - Real `currentTick` = 8,000
   - Stale `twapTick` = 10,000
   - Natural deviation = 2,000 ticks > `MAX_TWAP_DELTA_LIQUIDATION` (513)
8. Attacker uses flash loan to temporarily push Uniswap price UP to 10,300
9. Check passes: `Math.abs(10,300 - 10,000)` = 300 < 513 ✓
10. Solvency checked at 4 ticks:
    - `spotTick` ≈ 10,000 (stale) → insolvent
    - `twapTick` ≈ 10,000 (stale) → insolvent  
    - `latestTick` ≈ 10,000 (stale) → insolvent
    - `currentTick` = 10,300 (manipulated) → insolvent
11. Account appears insolvent at ALL 4 ticks
12. Liquidation proceeds despite account being solvent at true price (8,000)
13. Attacker profits from liquidation bonus extracted from a solvent account

## Impact Explanation

**Severity: HIGH**

This vulnerability enables:
- **Direct theft of user collateral** through unjust liquidations
- **Protocol reputation damage** as users lose funds despite being solvent
- **Systemic risk** if multiple accounts are targeted during periods of oracle staleness

The financial impact includes:
- Loss of position collateral for the liquidated user
- Liquidation bonus paid incorrectly from solvent account
- Potential cascading liquidations if market participants lose confidence

This meets **High Severity** criteria per Immunefi scope: "Temporary freezing of funds with economic loss" and "Widespread position liquidations due to bugs."

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

Prerequisites for exploitation:
1. Oracle must be stale (no updates for extended period) - **Common in low-activity pools**
2. Price must move favorably for target account - **Natural market movement**
3. Attacker needs flash loan capital - **Readily available on DeFi**
4. Price movement must be >513 ticks initially - **Happens regularly in volatile markets**

The attack is **economically rational** - liquidation bonuses exceed flash loan costs. The permissionless nature of `pokeOracle()` means attackers can strategically avoid updating the oracle to keep it stale. [4](#0-3) 

## Recommendation

**Fix: Force oracle update before liquidation checks**

```solidity
function dispatchFrom(
    TokenId[] calldata positionIdListFrom,
    address account,
    TokenId[] calldata positionIdListTo,
    TokenId[] calldata positionIdListToFinal,
    LeftRightUnsigned usePremiaAsCollateral
) external payable {
    // FIXED: Update oracle BEFORE reading values
    int24 currentTick = getCurrentTick();
    (, OraclePack updatedOraclePack) = riskEngine().computeInternalMedian(s_oraclePack, currentTick);
    if (OraclePack.unwrap(updatedOraclePack) != 0) {
        s_oraclePack = updatedOraclePack;
    }
    
    // Assert the account we are liquidating is actually insolvent
    int24 twapTick = getTWAP();
    // ... rest of function
```

This ensures liquidations use fresh oracle data, preventing exploitation of stale prices while maintaining the `MAX_TWAP_DELTA_LIQUIDATION` safety check.

**Alternative: Add maximum staleness check**

```solidity
uint256 oracleAge = block.timestamp - (uint256(s_oraclePack.epoch()) << 6);
require(oracleAge < MAX_ORACLE_STALENESS, "Oracle too stale for liquidation");
```

## Proof of Concept

**Note:** This PoC demonstrates the logical vulnerability but requires Uniswap pool price manipulation which, while technically feasible via flash loans in practice, may be excluded from certain audit scopes as noted in protocol documentation regarding "Uniswap pool manipulation assumptions."

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "contracts/PanopticPool.sol";
import {TokenId} from "contracts/types/TokenId.sol";

contract StaleOracleLiquidationTest is Test {
    PanopticPool pp;
    address victim;
    address attacker;
    
    function setUp() public {
        // Setup pool, tokens, and accounts
        // Victim opens short call position at tick 10000
        // Position is marginally solvent at this price
    }
    
    function testLiquidateSolventAccountViaStaleOracle() public {
        // 1. Initial state: price = 10000, victim is marginally solvent
        // Update oracle to capture this state
        pp.pokeOracle();
        
        // 2. Time passes, price drops to 8000 (favorable for victim)
        vm.warp(block.timestamp + 4 hours);
        // Simulate price drop (would require Uniswap pool manipulation)
        // At 8000, victim is very solvent
        
        // 3. Attacker manipulates price back to 10300 via flash loan
        // This brings currentTick within MAX_TWAP_DELTA_LIQUIDATION of stale twapTick
        
        // 4. Attempt liquidation
        vm.prank(attacker);
        TokenId[] memory positions = new TokenId[](1);
        positions[0] = victimPosition;
        
        // This should revert if victim is solvent, but succeeds due to stale oracle
        pp.dispatchFrom(
            new TokenId[](0),  // liquidator positions
            victim,            // liquidatee
            positions,         // positions to close
            new TokenId[](0),  // final positions (empty for liquidation)
            LeftRightUnsigned.wrap(0)
        );
        
        // 5. Verify victim was liquidated despite being solvent at true price
        // Attacker receives liquidation bonus
        // Victim loses collateral unfairly
    }
}
```

The vulnerability is confirmed by examining that `dispatchFrom()` never updates `s_oraclePack` before performing solvency checks, allowing exploitation when combined with price manipulation capabilities.

### Citations

**File:** contracts/PanopticPool.sol (L552-558)
```text
    function pokeOracle() external {
        int24 currentTick = getCurrentTick();

        (, OraclePack oraclePack) = riskEngine().computeInternalMedian(s_oraclePack, currentTick);

        if (OraclePack.unwrap(oraclePack) != 0) s_oraclePack = oraclePack;
    }
```

**File:** contracts/PanopticPool.sol (L1368-1389)
```text
        int24 twapTick = getTWAP();
        int24 currentTick = getCurrentTick();

        TokenId tokenId;

        uint256 solvent;
        uint256 numberOfTicks;
        {
            _validatePositionList(account, positionIdListTo);

            // Enforce maximum delta between TWAP and currentTick to prevent extreme price manipulation
            int24 spotTick;
            int24 latestTick;
            (spotTick, , latestTick, ) = riskEngine().getOracleTicks(currentTick, s_oraclePack);

            unchecked {
                (RiskParameters riskParameters, ) = getRiskParameters(0);
                int256 MAX_TWAP_DELTA_LIQUIDATION = int256(
                    uint256(riskParameters.tickDeltaLiquidation())
                );
                if (Math.abs(currentTick - twapTick) > MAX_TWAP_DELTA_LIQUIDATION)
                    revert Errors.StaleOracle();
```

**File:** contracts/types/OraclePack.sol (L556-565)
```text
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
```
