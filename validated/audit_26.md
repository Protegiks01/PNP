# VALIDATION RESULT: VALID HIGH/CRITICAL VULNERABILITY

## Title
Silent Division-by-Zero in Spread Collateral Calculation Enables Severe Undercollateralization

## Summary
The `Math.unsafeDivRoundingUp()` function returns 0 when both arguments are 0 instead of reverting. This is exploited in `RiskEngine._computeSpread()` where a comment incorrectly assumes "denominator is always nonzero". When both legs of a spread position are out-of-the-money in the same direction (a common scenario for vertical spreads), the collateral requirement calculation silently returns near-zero values instead of the proper amount, enabling positions to bypass collateral requirements and violating the protocol's solvency maintenance invariant.

## Impact
**Severity**: High/Critical
**Category**: Protocol Insolvency / Systemic Undercollateralization

**Concrete Impact:**
- Attackers can open spread positions with collateral requirements reduced from thousands/millions of wei to effectively 1 wei plus minimal calendar adjustment
- Protocol becomes systemically undercollateralized when these positions incur losses from price movements or forced exercises
- Liquidation mechanisms fail because insufficient collateral exists to cover losses and liquidation bonuses
- All users are affected - the capital efficiency mechanism designed to reduce requirements for hedged positions is instead exploited to eliminate requirements entirely

**Affected Parties:** All participants in Panoptic pools with spread positions, protocol solvency

## Finding Description

**Location**: [1](#0-0) [2](#0-1) 

**Intended Logic**: 
The spread collateral requirement should be calculated as the minimum of either (1) the spread's defined max loss or (2) the sum of individual leg requirements. The spread-specific calculation at lines 1877-1881 computes: `contracts * (notional1 - notional2) / max(notional1, notional2)` to determine risk-adjusted requirements.

**Actual Logic**: 
When both legs of a spread are out-of-the-money in the same direction (e.g., both call strikes above current price, or both put strikes below), both legs have zero notional amounts in one token. This causes:

1. **Division by Zero Returns 0**: [1](#0-0) 
   - Assembly `div(0, 0)` returns 0 instead of reverting
   - Assembly `mod(0, 0)` returns 0
   - Final result: `add(0, 0) = 0`

2. **False Safety Assumption**: [3](#0-2) 
   - Comment claims "denominator is always nonzero" - this is FALSE

3. **Zero Notional Scenario**: [4](#0-3) 
   - When `tokenType == 1` and both legs OTM below price: `notional = moved0 = 0`, `notionalP = moved0Partner = 0`
   - When `tokenType == 0` and both legs OTM above price: `notional = moved1 = 0`, `notionalP = moved1Partner = 0`
   - Division: `unsafeDivRoundingUp((0 - 0) * contracts, 0)` = `unsafeDivRoundingUp(0, 0)` = 0

4. **Incorrect Minimum Selection**: [5](#0-4) 
   - `spreadRequirement` = 1 wei (initial) + 0 (division result) + small_calendar_adjustment
   - Final = `min(splitRequirement_large_value, spreadRequirement_near_zero)` = near-zero
   - Should be: proper spread max loss calculation or individual leg sum

**Exploitation Path**:

1. **Preconditions**: Attacker has minimal collateral deposited (e.g., 1 ETH)

2. **Step 1**: Create vertical spread position with both strikes OTM in same direction
   - Example: Current price $2000, short $2500 call + long $3000 call
   - Both strikes above price → both legs completely OTM above current price
   - Position structure: 2-leg spread with same tokenType, one short + one long
   - [6](#0-5) 
   - Since `currentTick <= tickLower` for both: `amount1 = 0` for both legs

3. **Step 2**: Collateral calculation triggers division by zero
   - Code path: `PanopticPool.dispatch(MINT)` → `RiskEngine.isAccountSolvent()` → `_getTotalRequiredCollateral()` → `_getRequiredCollateralSingleLegPartner()` → `_computeSpread()`
   - [7](#0-6) 
   - Both legs have `moved1 = 0` when OTM above price
   - If `tokenType = 0`: `notional = moved1 = 0` for both
   - Result: `spreadRequirement` ≈ 1 wei instead of proper value

4. **Step 3**: Position approved with insufficient collateral
   - Solvency check passes with near-zero requirement
   - Position minted with 1 wei effective collateral for potentially large notional

5. **Step 4**: Protocol loss occurs
   - If price moves favorably: attacker profits massively with 1 wei capital
   - If price moves adversely: position incurs losses but only 1 wei collateral to cover
   - Protocol absorbs deficit when position is closed/liquidated

**Security Property Broken**: 
Invariant #1: Solvency Maintenance - "All accounts must satisfy margin requirements at all times. The RiskEngine must correctly calculate collateral requirements for all position types."

**Root Cause Analysis**:
- `Math.unsafeDivRoundingUp()` designed for performance optimization (unsafe = no revert on div-by-zero)
- Incorrect assumption in `_computeSpread()` that max(notional, notionalP) is always nonzero
- Missing validation for edge case where both spread legs have zero notional in calculation token
- The code fails to handle the scenario where spread legs are positioned such that both have zero amounts in one token (common for vertical spreads)

## Impact Explanation

**Affected Assets**: User collateral (ETH, USDC, other tokens), protocol reserves

**Damage Severity**:
- **Quantitative**: Attacker can open positions with notional value of millions with only 1 wei collateral. If 1000 contracts each worth $100 in collateral requirement are opened with 1 wei total, the undercollateralization is $100,000 per position.
- **Qualitative**: Complete breakdown of the risk management system for a common position type (vertical spreads). The capital efficiency mechanism that should provide 10-50% reduction becomes a 99.9999%+ reduction.

**User Impact**:
- **Who**: All protocol participants - PLPs lose when protocol absorbs undercollateralized losses; legitimate traders face systemic risk
- **Conditions**: Any time vertical spreads are created with both legs OTM in same direction (standard trading strategy)
- **Recovery**: Requires protocol upgrade and potential socialized losses

**Systemic Risk**:
- Automated trading bots could easily exploit this repeatedly
- Each undercollateralized position increases protocol deficit
- Detection difficulty: Appears as normal spread positions until price movement creates losses

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with basic options trading knowledge and minimal capital
- **Resources Required**: ~1 wei per position plus gas costs
- **Technical Skill**: Low - vertical spreads are standard options strategies

**Preconditions**:
- **Market State**: Any market condition (normal, volatile, stable)
- **Position Structure**: 2-leg vertical spread with both strikes OTM in same direction
- **Timing**: No special timing required

**Execution Complexity**:
- **Transaction Count**: Single `dispatch(MINT)` call
- **Coordination**: None required
- **Detection Risk**: Low - appears as normal trading activity

**Frequency**:
- **Repeatability**: Unlimited - can open many positions
- **Occurrence**: Vertical spreads with both legs OTM are extremely common in options trading

**Overall Assessment**: High likelihood - the vulnerable scenario (vertical spreads with both legs OTM) is not an edge case but rather a fundamental and frequently-used options strategy.

## Recommendation

**Immediate Mitigation**:
Add explicit check for zero denominator before unsafe division:

```solidity
// In RiskEngine.sol _computeSpread() around line 1877-1881
unchecked {
    uint256 notional;
    uint256 notionalP;
    uint128 contracts;
    if (tokenType == 1) {
        notional = moved0;
        notionalP = moved0Partner;
        contracts = moved1;
    } else {
        notional = moved1;
        notionalP = moved1Partner;
        contracts = moved0;
    }
    
    // FIX: Check for zero denominator case
    uint256 maxNotional = notional > notionalP ? notional : notionalP;
    if (maxNotional == 0) {
        // When both notionals are zero, use the split requirement instead
        // by setting spreadRequirement high enough that min() selects splitRequirement
        return splitRequirement;
    }
    
    spreadRequirement += (notional < notionalP)
        ? Math.unsafeDivRoundingUp((notionalP - notional) * contracts, notionalP)
        : Math.unsafeDivRoundingUp((notional - notionalP) * contracts, notional);
}
```

**Permanent Fix**:
The fundamental issue is that when both legs have zero notional in the calculation token, the spread requirement calculation is attempting to measure risk in the wrong dimension. The code should either:
1. Switch to calculating risk in the non-zero token dimension, OR
2. Fall back to using `splitRequirement` (sum of individual legs) when the spread-specific calculation cannot be performed

**Additional Measures**:
- Add invariant tests specifically for vertical spreads with both legs OTM
- Add runtime assertion that `spreadRequirement > 0` when `contracts > 0`
- Review all usages of `unsafeDivRoundingUp` for similar unsafe assumptions

**Validation Checklist**:
- [ ] Fix prevents division by zero in spread calculations
- [ ] Vertical spreads with both legs OTM now have proper collateral requirements
- [ ] splitRequirement fallback provides adequate protection
- [ ] No breaking changes to existing valid positions

## Notes

This vulnerability demonstrates a critical gap between code comments and actual behavior. The comment "denominator is always nonzero" at line 1878 is demonstrably false for a common and legitimate position type. The use of "unsafe" operations requires extreme caution and comprehensive validation of all assumptions - in this case, the assumption that one of two amounts must be nonzero when calculating spread requirements is incorrect for positions where both legs are out-of-the-money in the same direction, which occurs naturally with vertical spreads.

The severity is HIGH/CRITICAL because:
1. It affects a common position type (vertical spreads)
2. Enables severe undercollateralization (reduction from proper amount to ~1 wei)
3. Violates core protocol invariant (solvency maintenance)
4. Can be exploited with minimal capital and no special conditions
5. Causes protocol-wide systemic risk as losses are socialized

### Citations

**File:** contracts/libraries/Math.sol (L367-379)
```text
    function getAmountsForLiquidity(
        int24 currentTick,
        LiquidityChunk liquidityChunk
    ) internal pure returns (uint256 amount0, uint256 amount1) {
        if (currentTick <= liquidityChunk.tickLower()) {
            amount0 = getAmount0ForLiquidity(liquidityChunk);
        } else if (currentTick >= liquidityChunk.tickUpper()) {
            amount1 = getAmount1ForLiquidity(liquidityChunk);
        } else {
            amount0 = getAmount0ForLiquidity(liquidityChunk.updateTickLower(currentTick));
            amount1 = getAmount1ForLiquidity(liquidityChunk.updateTickUpper(currentTick));
        }
    }
```

**File:** contracts/libraries/Math.sol (L1176-1180)
```text
    function unsafeDivRoundingUp(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly ("memory-safe") {
            result := add(div(a, b), gt(mod(a, b), 0))
        }
    }
```

**File:** contracts/RiskEngine.sol (L1638-1650)
```text
                            // SPREADS: same token type, one is long and the other is short
                            return
                                // only return the requirement once for the first leg it encounters
                                index < partnerIndex
                                    ? _computeSpread(
                                        tokenId,
                                        positionSize,
                                        index,
                                        partnerIndex,
                                        atTick,
                                        poolUtilization
                                    )
                                    : 0;
```

**File:** contracts/RiskEngine.sol (L1864-1885)
```text
            unchecked {
                uint256 notional;
                uint256 notionalP;
                uint128 contracts;
                if (tokenType == 1) {
                    notional = moved0;
                    notionalP = moved0Partner;
                    contracts = moved1;
                } else {
                    notional = moved1;
                    notionalP = moved1Partner;
                    contracts = moved0;
                }
                // the required amount is the amount of contracts multiplied by (notional1 - notional2)/max(notional1, notional2)
                // can use unsafe because denominator is always nonzero
                spreadRequirement += (notional < notionalP)
                    ? Math.unsafeDivRoundingUp((notionalP - notional) * contracts, notionalP)
                    : Math.unsafeDivRoundingUp((notional - notionalP) * contracts, notional);
            }
        }

        spreadRequirement = Math.min(splitRequirement, spreadRequirement);
```
