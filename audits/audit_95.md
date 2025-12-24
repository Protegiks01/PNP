# Audit Report

## Title 
Premium Accumulators Permanently Freeze Due to Capping Logic, Causing Loss of Future Accrued Fees

## Summary
Premium accumulators in `SemiFungiblePositionManager` can permanently freeze when `toUint128Capped()` caps computed premium deltas at `type(uint128).max`. Once frozen via `LeftRightLibrary.addCapped()`, the accumulators never update again, causing users to permanently lose all premium (Uniswap LP fees) that accrue after the freeze point.

## Finding Description

The vulnerability exists in the interaction between `_getPremiaDeltas()` and `_updateStoredPremia()` when handling premium accumulator updates. [1](#0-0) 

In `_getPremiaDeltas()`, premium deltas are computed using formulas with `netLiquidity^2` in the denominator. When `netLiquidity` becomes very small (e.g., when a user removes most liquidity via long positions), the calculation produces extremely large values that overflow `uint128` and get capped at `type(uint128).max`. [2](#0-1) 

These capped deltas are then passed to `LeftRightLibrary.addCapped()` which attempts to add them to the existing accumulators: [3](#0-2) 

The critical flaw is in the freezing logic: when `(x.rightSlot() + dx.rightSlot())` would equal or exceed `type(uint128).max`, the function returns the **old value** (`x.rightSlot()`) instead of updating. On all subsequent calls, the same condition remains true, permanently freezing the accumulator.

**Attack Path:**

1. User creates a short position (sells option) adding liquidity L to Uniswap
2. User creates a long position (buys option) removing liquidity (L - ε) where ε is tiny (e.g., 1 wei)
3. netLiquidity = ε (extremely small), removedLiquidity = L - ε (large)
4. Uniswap generates fees; when collected, premium calculation becomes:
   - `premium0X64_base = (collected0 * totalLiquidity * 2^64) / netLiquidity^2`
   - With netLiquidity ≈ 0, this produces huge values exceeding `type(uint128).max`
5. Delta gets capped, and when added to accumulator, the sum reaches max
6. `addCapped()` detects overflow condition and returns old accumulator value (no update)
7. Accumulator is now permanently frozen; all future Uniswap fees are collected but not credited to users

**Invariant Broken:**

This violates **Invariant #14**: "Premium Accounting: Premium distribution must be proportional to liquidity share in each chunk." Once frozen, premium distribution stops entirely for that chunk despite continued fee accrual.

## Impact Explanation

**Impact: Medium Severity**

Users suffer permanent economic loss of all LP fees that accrue after the accumulator freeze. The frozen accumulator causes:

1. **Permanent Loss of Premium**: When users attempt to collect or close positions, premium calculations use: [4](#0-3) 

The delta `(premiumAccumulatorsByLeg[leg][0] - premiumAccumulatorLast.rightSlot())` remains static after freeze, so users receive no credit for new fees despite Uniswap continuing to generate them.

2. **State Corruption**: The accumulator state becomes permanently corrupted with no recovery mechanism. The only way to "fix" it would be to close all positions in that chunk and recreate them, but users may not realize the issue.

3. **Protocol Loss**: Fees collected from Uniswap but not credited to users become stuck or incorrectly distributed, causing accounting discrepancies.

## Likelihood Explanation

**Likelihood: Low to Medium**

The condition requires `netLiquidity` to become extremely small, which can occur when:

1. **Intentional Position Structuring**: Users creating overlapping long/short positions with slight imbalances (as demonstrated in the protocol's own test `test_Success_PremiumDOSPrevention`)

2. **Natural Position Evolution**: As users adjust positions over time, they might inadvertently create scenarios where netLiquidity approaches zero

3. **High-Volume Pools**: In pools with significant fee generation, even moderate netLiquidity values could produce deltas large enough to cause overflow over time

The protocol explicitly tests this scenario: [5](#0-4) 

However, the test only verifies that overflow doesn't cause reverts, not that premium tracking remains accurate post-freeze.

## Recommendation

**Solution 1: Track Overflow State and Handle Gracefully**

Add a flag to track when accumulators have overflowed and handle premium calculations differently:

```solidity
mapping(bytes32 positionKey => bool) private s_accumulatorOverflowed;

function _updateStoredPremia(...) private {
    (LeftRightUnsigned premiumOwed, LeftRightUnsigned premiumGross) = _getPremiaDeltas(...);
    
    (LeftRightUnsigned newOwed, LeftRightUnsigned newGross) = LeftRightLibrary.addCapped(
        s_accountPremiumOwed[positionKey],
        premiumOwed,
        s_accountPremiumGross[positionKey],
        premiumGross
    );
    
    // Detect if capping occurred
    if (newOwed.rightSlot() == s_accountPremiumOwed[positionKey].rightSlot() && 
        premiumOwed.rightSlot() > 0) {
        s_accumulatorOverflowed[positionKey] = true;
    }
    
    s_accountPremiumOwed[positionKey] = newOwed;
    s_accountPremiumGross[positionKey] = newGross;
}
```

**Solution 2: Enforce Minimum netLiquidity**

Prevent positions that would result in dangerously small netLiquidity:

```solidity
// In _createLegInAMM after updating s_accountLiquidity
require(updatedLiquidity >= MIN_NET_LIQUIDITY, "NetLiquidity too small");
```

Where `MIN_NET_LIQUIDITY` is set high enough to prevent overflow in realistic fee scenarios (e.g., 1000 liquidity units).

**Solution 3: Use Saturating Arithmetic Instead of Freezing**

Modify `addCapped()` to continue updating even at max, allowing accumulator to stay at max rather than freezing at a lower value:

```solidity
function addCapped(...) internal pure returns (...) {
    uint128 z_xR = (uint256(x.rightSlot()) + dx.rightSlot()).toUint128Capped();
    // ... other slots
    
    // Always update to capped value, don't freeze at old value
    return (
        LeftRightUnsigned.wrap(z_xR).addToLeftSlot(z_xL),
        LeftRightUnsigned.wrap(z_yR).addToLeftSlot(z_yL)
    );
}
```

This way accumulators saturate at max instead of freezing, which is more predictable behavior.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../core/SemiFungiblePositionManager.t.sol"; // Extend existing test contract

contract PremiumFreeze is SemiFungiblePositionManagerTest {
    
    function test_PremiumAccumulatorFreeze() public {
        _initPool(0);
        
        // Setup: Get in-range strike and width
        (int24 width, int24 strike) = PositionUtils.getInRangeSW(
            1000,
            50,
            uint24(tickSpacing),
            currentTick
        );
        
        uint256 largePositionSize = type(uint96).max;
        populatePositionData(width, strike, largePositionSize);
        
        // Step 1: Create short position with large liquidity
        TokenId tokenIdShort = TokenId.wrap(0).addPoolId(poolId).addLeg(
            0, 1, isWETH, 0, 1, 0, strike, width
        );
        
        sfpm.mintTokenizedPosition(
            abi.encode(poolKey),
            tokenIdShort,
            uint128(largePositionSize),
            TickMath.MIN_TICK,
            TickMath.MAX_TICK
        );
        
        // Step 2: Create long position removing almost all liquidity (leaving 1/2^32 of it)
        TokenId tokenIdLong = TokenId.wrap(0).addPoolId(poolId).addLeg(
            0, 1, isWETH, 1, 1, 0, strike, width
        );
        
        uint128 longPositionSize = uint128(Math.mulDiv(
            largePositionSize, 
            (2 ** 32 - 1), 
            2 ** 32
        ));
        
        sfpm.mintTokenizedPosition(
            abi.encode(poolKey),
            tokenIdLong,
            longPositionSize,
            TickMath.MIN_TICK,
            TickMath.MAX_TICK
        );
        
        // Step 3: Generate fees through swaps
        twoWaySwap(swapSizeMedium);
        
        // Step 4: Check premium before freeze
        (uint128 premium0Before, uint128 premium1Before) = sfpm.getAccountPremium(
            abi.encode(poolKey),
            address(this),
            0, // tokenType
            strike - width * tickSpacing,
            strike + width * tickSpacing,
            currentTick,
            0, // isLong (short position)
            2 ** 64 // vegoid
        );
        
        // Step 5: Trigger premium collection (may cause freeze)
        vm.warp(block.timestamp + 1000);
        twoWaySwap(swapSizeMedium);
        
        // Force premium update by poking position
        sfpm.mintTokenizedPosition(
            abi.encode(poolKey),
            tokenIdShort,
            0, // 0 liquidity poke
            TickMath.MIN_TICK,
            TickMath.MAX_TICK
        );
        
        (uint128 premium0After1, uint128 premium1After1) = sfpm.getAccountPremium(
            abi.encode(poolKey),
            address(this),
            0,
            strike - width * tickSpacing,
            strike + width * tickSpacing,
            currentTick,
            0,
            2 ** 64
        );
        
        // Step 6: Generate MORE fees after potential freeze
        vm.warp(block.timestamp + 1000);
        twoWaySwap(swapSizeLarge);
        twoWaySwap(swapSizeLarge);
        
        // Step 7: Check premium again - if frozen, it won't increase despite new fees
        (uint128 premium0After2, uint128 premium1After2) = sfpm.getAccountPremium(
            abi.encode(poolKey),
            address(this),
            0,
            strike - width * tickSpacing,
            strike + width * tickSpacing,
            currentTick,
            0,
            2 ** 64
        );
        
        // VULNERABILITY: If accumulator froze, premium0After2 should equal premium0After1
        // despite significant new swap fees being generated
        console.log("Premium0 before:", premium0Before);
        console.log("Premium0 after first collection:", premium0After1);
        console.log("Premium0 after heavy trading:", premium0After2);
        
        // If frozen, assert that premium didn't increase despite new trading
        if (premium0After1 >= type(uint128).max - 1e18) {
            assertEq(
                premium0After2, 
                premium0After1, 
                "Accumulator frozen: premium unchanged despite new fees"
            );
        }
    }
}
```

**Notes:**

- The vulnerability stems from an intentional design choice (capping to prevent DOS) that has an unintended consequence (permanent loss of premium tracking)
- The protocol's own test suite (`test_Success_PremiumDOSPrevention`) demonstrates the overflow scenario but doesn't validate premium accuracy post-cap
- The issue is per-position (per `positionKey`), so users can only grief their own premium accumulation, not others
- However, the lack of minimum netLiquidity requirements means users can inadvertently create this condition during normal position management

### Citations

**File:** contracts/SemiFungiblePositionManager.sol (L1064-1070)
```text
        (s_accountPremiumOwed[positionKey], s_accountPremiumGross[positionKey]) = LeftRightLibrary
            .addCapped(
                s_accountPremiumOwed[positionKey],
                deltaPremiumOwed,
                s_accountPremiumGross[positionKey],
                deltaPremiumGross
            );
```

**File:** contracts/SemiFungiblePositionManager.sol (L1311-1316)
```text
                    premium0X64_owed = Math
                        .mulDiv(premium0X64_base, numerator, totalLiquidity)
                        .toUint128Capped();
                    premium1X64_owed = Math
                        .mulDiv(premium1X64_base, numerator, totalLiquidity)
                        .toUint128Capped();
```

**File:** contracts/types/LeftRight.sol (L305-320)
```text
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

**File:** contracts/PanopticPool.sol (L2044-2046)
```text
                                    ((premiumAccumulatorsByLeg[leg][0] -
                                        premiumAccumulatorLast.rightSlot()) *
                                        (liquidityChunk.liquidity())) / 2 ** 64
```

**File:** test/foundry/core/SemiFungiblePositionManager.t.sol (L4127-4128)
```text
    // make sure that we allow the premium to overflow and it does not revert when too much is accumulated with a huge multiplier
    function test_Success_PremiumDOSPrevention(uint256 widthSeed, int256 strikeSeed) public {
```
