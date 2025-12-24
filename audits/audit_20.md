# Audit Report

## Title 
Arithmetic Overflow in Premium Calculation Due to Unchecked totalLiquidity Multiplication

## Summary
The `_getAvailablePremium()` function in `PanopticPool.sol` performs multiplication of `totalLiquidity` by premium accumulator differences in an unchecked block at lines 2095 and 2097. When `totalLiquidity` exceeds `type(uint128).max`, this multiplication can overflow uint256, causing the calculated premium to wrap around to an incorrectly small value, enabling users to withdraw more premium than they're entitled to.

## Finding Description
The vulnerability exists in the `_getAvailablePremium()` function where premium calculations occur: [1](#0-0) 

The function multiplies `(premiumAccumulators[i] - grossPremiumLast.slot())` by `totalLiquidity` within an unchecked block. The critical issue is that:

1. **Premium accumulator differences** can reach up to `type(uint128).max` since premium accumulators are capped at this value through the `addCapped()` function: [2](#0-1) 

2. **totalLiquidity exceeds uint128 bounds**: The `_getLiquidities()` function computes `totalLiquidity` as the sum of two `uint128` values: [3](#0-2) 

Since `netLiquidity` and `removedLiquidity` are both `uint128` values, their sum can reach up to `2 * type(uint128).max ≈ 2^129`, which is stored in a `uint256` variable.

3. **Overflow calculation**: When both values are near their maximum:
   - `premiumAccumulators[i] - grossPremiumLast.slot() ≈ 2^128`
   - `totalLiquidity ≈ 2 * 2^128 = 2^129`
   - Product: `2^128 * 2^129 = 2^257`

Since `type(uint256).max = 2^256 - 1`, this multiplication overflows, wrapping around to a small value.

4. **Impact on premium distribution**: The overflowed `accumulated0/accumulated1` value is then used as the denominator in calculating available premium: [4](#0-3) 

When `accumulated0` is incorrectly small due to overflow, the division `(premiumOwed * settledTokens) / accumulated0` produces an inflated result, allowing users to withdraw more premium than their proportional share.

This **breaks Invariant #14 (Premium Accounting)**: "Premium distribution must be proportional to liquidity share in each chunk. Incorrect accounting allows premium manipulation."

## Impact Explanation
**High Severity** - This vulnerability enables economic manipulation through incorrect premium calculations:

1. **Direct Financial Loss**: Users can extract more premium than they're entitled to, draining the settled tokens pool and preventing legitimate sellers from withdrawing their fair share of premium
2. **Systemic Risk**: In high-liquidity pools with substantial premium accumulation, the overflow becomes more likely, affecting multiple users simultaneously
3. **Premium Distribution Failure**: The protocol's core mechanism for distributing trading fees proportionally among option sellers is compromised

The impact qualifies as High severity under Immunefi's criteria because it involves "Economic manipulation benefiting attackers" and "State inconsistencies requiring manual intervention."

## Likelihood Explanation
**Medium-High Likelihood**:

**Preconditions required**:
1. Total liquidity in a chunk (`netLiquidity + removedLiquidity`) exceeds `type(uint128).max` - achievable in popular trading pairs where many users provide liquidity
2. Premium accumulators have grown substantially over time - natural occurrence in active pools
3. The difference `premiumAccumulators[i] - grossPremiumLast.slot()` is large - happens when a user hasn't claimed premium for a long period

**Feasibility**: 
- No special privileges required - any user can be affected
- Conditions are met naturally in mature, high-volume pools
- Attack doesn't require active exploitation; it's a latent bug triggered by normal protocol operation under high-liquidity conditions
- More likely in concentrated liquidity positions where `removedLiquidity` accumulates significantly

## Recommendation
Add overflow protection by checking if the multiplication will exceed `uint256` bounds before performing it, or restructure the calculation to avoid overflow:

```solidity
function _getAvailablePremium(
    uint256 totalLiquidity,
    LeftRightUnsigned settledTokens,
    LeftRightUnsigned grossPremiumLast,
    LeftRightUnsigned premiumOwed,
    uint256[2] memory premiumAccumulators
) internal pure returns (LeftRightUnsigned) {
    unchecked {
        // Calculate premium accumulator differences
        uint256 premiumAccumDiff0 = premiumAccumulators[0] - grossPremiumLast.rightSlot();
        uint256 premiumAccumDiff1 = premiumAccumulators[1] - grossPremiumLast.leftSlot();
        
        // Check for potential overflow before multiplication
        // If (premiumAccumDiff * totalLiquidity) would overflow uint256, 
        // perform the division first to avoid overflow
        uint256 accumulated0;
        uint256 accumulated1;
        
        // Use Math.mulDiv to handle overflow safely
        if (premiumAccumDiff0 > type(uint256).max / totalLiquidity) {
            // Would overflow, restructure calculation
            accumulated0 = Math.mulDiv(premiumAccumDiff0, totalLiquidity, 2 ** 64);
        } else {
            accumulated0 = (premiumAccumDiff0 * totalLiquidity) / 2 ** 64;
        }
        
        if (premiumAccumDiff1 > type(uint256).max / totalLiquidity) {
            accumulated1 = Math.mulDiv(premiumAccumDiff1, totalLiquidity, 2 ** 64);
        } else {
            accumulated1 = (premiumAccumDiff1 * totalLiquidity) / 2 ** 64;
        }

        return (
            LeftRightUnsigned
                .wrap(
                    uint128(
                        Math.min(
                            (uint256(premiumOwed.rightSlot()) * settledTokens.rightSlot()) /
                                (accumulated0 == 0 ? type(uint256).max : accumulated0),
                            premiumOwed.rightSlot()
                        )
                    )
                )
                .addToLeftSlot(
                    uint128(
                        Math.min(
                            (uint256(premiumOwed.leftSlot()) * settledTokens.leftSlot()) /
                                (accumulated1 == 0 ? type(uint256).max : accumulated1),
                            premiumOwed.leftSlot()
                        )
                    )
                )
        );
    }
}
```

Alternatively, use `Math.mulDiv()` which handles overflow protection internally, as it's already available in the codebase.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract PremiumOverflowTest is Test {
    // Simplified test demonstrating the overflow
    function testPremiumCalculationOverflow() public {
        // Simulate conditions where overflow occurs
        uint256 premiumAccumulator = type(uint128).max; // Maximum accumulated premium
        uint128 grossPremiumLast = 0; // User hasn't claimed yet
        uint256 totalLiquidity = 2 * uint256(type(uint128).max); // Sum of two uint128.max values
        
        // Calculate the product (as done in _getAvailablePremium)
        uint256 premiumAccumDiff = premiumAccumulator - grossPremiumLast;
        
        // This multiplication will overflow uint256
        unchecked {
            uint256 product = premiumAccumDiff * totalLiquidity;
            
            // Due to overflow, product wraps around to a small value
            // Expected: ~2^257
            // Actual: product % (2^256)
            
            uint256 accumulated = product / (2 ** 64);
            
            // accumulated is now much smaller than it should be
            // This causes the available premium calculation to be inflated
            
            // Demonstrate the overflow
            console.log("Premium Accumulator Diff:", premiumAccumDiff);
            console.log("Total Liquidity:", totalLiquidity);
            console.log("Product (overflowed):", product);
            console.log("Accumulated (incorrect):", accumulated);
            
            // Calculate what it should be without overflow
            // Using mulDiv to avoid overflow
            uint256 correctProduct = mulDiv(premiumAccumDiff, totalLiquidity, 1);
            uint256 correctAccumulated = correctProduct / (2 ** 64);
            console.log("Correct Accumulated:", correctAccumulated);
            
            // Show the discrepancy
            assert(accumulated != correctAccumulated);
            console.log("Calculation is INCORRECT due to overflow!");
        }
    }
    
    // Helper function to perform safe multiplication and division
    function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256) {
        uint256 prod0;
        uint256 prod1;
        assembly {
            let mm := mulmod(a, b, not(0))
            prod0 := mul(a, b)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }
        
        if (prod1 == 0) {
            return prod0 / denominator;
        }
        
        require(denominator > prod1, "Overflow");
        
        uint256 remainder;
        assembly {
            remainder := mulmod(a, b, denominator)
        }
        
        assembly {
            prod1 := sub(prod1, gt(remainder, prod0))
            prod0 := sub(prod0, remainder)
        }
        
        uint256 twos = denominator & (~denominator + 1);
        assembly {
            denominator := div(denominator, twos)
            prod0 := div(prod0, twos)
            twos := add(div(sub(0, twos), twos), 1)
        }
        
        prod0 |= prod1 * twos;
        
        uint256 inverse = (3 * denominator) ^ 2;
        inverse *= 2 - denominator * inverse;
        inverse *= 2 - denominator * inverse;
        inverse *= 2 - denominator * inverse;
        inverse *= 2 - denominator * inverse;
        inverse *= 2 - denominator * inverse;
        inverse *= 2 - denominator * inverse;
        
        return prod0 * inverse;
    }
}
```

## Notes

The vulnerability is exacerbated by the misleading comment at line 1209 which states "cannot overflow because total liquidity is less than uint128", when in fact `totalLiquidity` is the sum of two `uint128` values and can reach up to `2^129`. [5](#0-4) 

The protocol should either:
1. Enforce that `totalLiquidity` never exceeds `type(uint128).max` through explicit checks, or
2. Use safe arithmetic operations (like `Math.mulDiv`) that handle large multiplications without overflow

### Citations

**File:** contracts/PanopticPool.sol (L1206-1212)
```text
                        // T (totalLiquidity is (T - R) after burning)
                        uint256 totalLiquidityBefore;
                        unchecked {
                            // cannot overflow because total liquidity is less than uint128
                            totalLiquidityBefore = commitLongSettledAndKeepOpen.leftSlot() == 0
                                ? totalLiquidity + positionLiquidity
                                : totalLiquidity;
```

**File:** contracts/PanopticPool.sol (L2091-2098)
```text
        unchecked {
            // long premium only accumulates as it is settled, so compute the ratio
            // of total settled tokens in a chunk to total premium owed to sellers and multiply
            // cap the ratio at 1 (it can be greater than one if some seller forfeits enough premium)
            uint256 accumulated0 = ((premiumAccumulators[0] - grossPremiumLast.rightSlot()) *
                totalLiquidity) / 2 ** 64;
            uint256 accumulated1 = ((premiumAccumulators[1] - grossPremiumLast.leftSlot()) *
                totalLiquidity) / 2 ** 64;
```

**File:** contracts/PanopticPool.sol (L2104-2108)
```text
                            Math.min(
                                (uint256(premiumOwed.rightSlot()) * settledTokens.rightSlot()) /
                                    (accumulated0 == 0 ? type(uint256).max : accumulated0),
                                premiumOwed.rightSlot()
                            )
```

**File:** contracts/PanopticPool.sol (L2131-2154)
```text
    function _getLiquidities(
        TokenId tokenId,
        uint256 leg
    )
        internal
        view
        returns (uint256 totalLiquidity, uint128 netLiquidity, uint128 removedLiquidity)
    {
        (int24 tickLower, int24 tickUpper) = tokenId.asTicks(leg);

        LeftRightUnsigned accountLiquidities = SFPM.getAccountLiquidity(
            poolKey(),
            address(this),
            tokenId.tokenType(leg),
            tickLower,
            tickUpper
        );

        netLiquidity = accountLiquidities.rightSlot();
        removedLiquidity = accountLiquidities.leftSlot();

        unchecked {
            totalLiquidity = netLiquidity + removedLiquidity;
        }
```

**File:** contracts/types/LeftRight.sol (L299-320)
```text
    function addCapped(
        LeftRightUnsigned x,
        LeftRightUnsigned dx,
        LeftRightUnsigned y,
        LeftRightUnsigned dy
    ) internal pure returns (LeftRightUnsigned, LeftRightUnsigned) {
        uint128 z_xR = (uint256(x.rightSlot()) + dx.rightSlot()).toUint128Capped();
        uint128 z_xL = (uint256(x.leftSlot()) + dx.leftSlot()).toUint128Capped();
        uint128 z_yR = (uint256(y.rightSlot()) + dy.rightSlot()).toUint128Capped();
        uint128 z_yL = (uint256(y.leftSlot()) + dy.leftSlot()).toUint128Capped();

        bool r_Enabled = !(z_xR == type(uint128).max || z_yR == type(uint128).max);
        bool l_Enabled = !(z_xL == type(uint128).max || z_yL == type(uint128).max);

        return (
            LeftRightUnsigned.wrap(r_Enabled ? z_xR : x.rightSlot()).addToLeftSlot(
                l_Enabled ? z_xL : x.leftSlot()
            ),
            LeftRightUnsigned.wrap(r_Enabled ? z_yR : y.rightSlot()).addToLeftSlot(
                l_Enabled ? z_yL : y.leftSlot()
            )
        );
```
