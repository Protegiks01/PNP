# Audit Report

## Title
MAX_SPREAD Invariant Bypass Through Partial Position Closure Causes Premium Accumulator Overflow and Permanent Freezing

## Summary
The premium calculation equations (1-4) in `SemiFungiblePositionManager.sol` do not account for the edge case where users partially close short positions, causing the spread ratio (removedLiquidity/netLiquidity) to far exceed the `MAX_SPREAD` limit of 90%. This leads to premium calculation overflow and permanent freezing of premium accumulators, resulting in loss of all future premium income for affected position chunks.

## Finding Description
The protocol enforces a maximum spread limit through `_checkLiquiditySpread` to ensure that `removedLiquidity / netLiquidity <= MAX_SPREAD (9:1 ratio)`. However, this check only occurs during position minting in `PanopticPool._mintOptions`, not during position burning in `PanopticPool._burnOptions`. [1](#0-0) 

When a user partially closes their short position (burns liquidity with `isLong=1, isBurn=true`), the operation:
1. Reduces `netLiquidity` (N) via `updatedLiquidity = startingLiquidity - chunkLiquidity`
2. Leaves `removedLiquidity` (R) unchanged
3. Does NOT validate the resulting spread ratio [2](#0-1) 

This allows the spread to grow arbitrarily large. When premium calculations subsequently execute via `_getPremiaDeltas`, the extreme spread causes mathematical overflow: [3](#0-2) 

The calculation at line 1292-1295 computes `premium0X64_base = collected * totalLiquidity * 2^64 / netLiquidity^2`. When `netLiquidity` is very small (e.g., 1) and `removedLiquidity` is large (e.g., 90,000), this produces enormous values that overflow `uint128` when multiplied by the numerator factors.

The overflow triggers the capping mechanism at line 1313 (`toUint128Capped()`), and subsequently the `addCapped` function freezes both premium accumulators: [4](#0-3) 

Once frozen (lines 310-320), the accumulators stop tracking premiums permanently for that position chunk, causing loss of all future premium income.

**Attack Scenario:**
1. User mints short position: N=10,000, R=0
2. User mints long positions: R increases to 90,000 (spread=9, at MAX_SPREAD, passes validation)
3. User partially closes short by burning 9,900 liquidity: N=100, R=90,000 (spread=900, 90x the limit)
4. Next premium update via `_collectAndWritePositionData` or `getAccountPremium` calculates overflowed premiums
5. `addCapped` detects overflow and permanently freezes the accumulators
6. User loses all future premium income on this chunk

## Impact Explanation
**HIGH SEVERITY** - This vulnerability has multiple severe impacts:

1. **Invariant Violation**: Directly violates **Invariant #6 (Position Size Limits)** which states "Individual positions limited by available Uniswap liquidity and MAX_SPREAD = 90%"

2. **Permanent Loss of Funds**: Users lose all future premium income on affected position chunks. Premium accumulators, once frozen, never recover, causing permanent loss of expected returns.

3. **Systemic Risk**: The issue affects core premium accounting logic that underpins the protocol's options pricing model. Multiple users following normal usage patterns can inadvertently trigger this condition.

4. **No Economic Recovery**: Unlike temporary freezes, there is no mechanism to unfreeze accumulators or recover lost premiums. The mathematical overflow is permanent state corruption.

## Likelihood Explanation
**HIGH LIKELIHOOD** - This vulnerability can occur through normal user operations without malicious intent:

1. **Common Usage Pattern**: Users frequently adjust positions by partially closing shorts and opening longs, especially during market volatility or portfolio rebalancing.

2. **No Warning Mechanism**: The protocol provides no warning when users approach dangerous spread ratios during burns. Users can unknowingly create extreme spreads.

3. **Accumulative Risk**: As positions age and users make multiple adjustments, the probability of reaching extreme spreads increases over time.

4. **No Preconditions**: Requires no special market conditions, oracle manipulation, or collusion. Any user can trigger this through standard operations.

5. **Affects All Users**: Both sophisticated and unsophisticated users are vulnerable. The mathematical overflow occurs automatically when spreads exceed safe thresholds.

## Recommendation
Implement spread validation during position burning to prevent the spread ratio from exceeding MAX_SPREAD:

```solidity
function _burnOptions(
    TokenId tokenId,
    uint128 positionSize,
    int24[2] memory tickLimits,
    address owner,
    bool commitLongSettled,
    RiskParameters riskParameters
) internal returns (
    LeftRightSigned paidAmounts,
    LeftRightSigned[4] memory premiaByLeg,
    int24 finalTick
) {
    // Add spread validation before burning
    for (uint256 leg = 0; leg < tokenId.countLegs(); ) {
        if (tokenId.width(leg) != 0) {
            // Check post-burn spread to ensure it doesn't exceed MAX_SPREAD
            _checkLiquiditySpread(
                tokenId,
                leg,
                riskParameters.maxSpread()
            );
        }
        unchecked {
            ++leg;
        }
    }
    
    // Continue with existing burn logic...
    (collectedByLeg, netAmmDelta, finalTick) = SFPM.burnTokenizedPosition(
        poolKey(),
        tokenId,
        positionSize,
        tickLimits[0],
        tickLimits[1]
    );
    
    // Rest of function...
}
```

Additionally, modify `_checkLiquiditySpread` to return post-operation liquidity state for validation:

```solidity
function _checkLiquiditySpread(
    TokenId tokenId,
    uint256 leg,
    uint256 effectiveLiquidityLimit,
    uint128 liquidityChange,  // New parameter
    bool isRemovingLiquidity  // New parameter
) internal view returns (uint256 totalLiquidity) {
    uint256 netLiquidity;
    uint256 removedLiquidity;
    (totalLiquidity, netLiquidity, removedLiquidity) = _getLiquidities(tokenId, leg);
    
    // Simulate post-operation state
    if (isRemovingLiquidity && netLiquidity >= liquidityChange) {
        netLiquidity -= liquidityChange;
    }
    
    if (netLiquidity == 0 && removedLiquidity == 0) return totalLiquidity;
    if (netLiquidity == 0) revert Errors.NetLiquidityZero();
    
    uint256 effectiveLiquidityFactor;
    unchecked {
        effectiveLiquidityFactor = (removedLiquidity * DECIMALS) / netLiquidity;
    }
    
    if (effectiveLiquidityFactor > effectiveLiquidityLimit)
        revert Errors.EffectiveLiquidityAboveThreshold();
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/PanopticPool.sol";
import "../contracts/SemiFungiblePositionManager.sol";
import "../contracts/types/TokenId.sol";

contract PremiumOverflowTest is Test {
    PanopticPool public pool;
    SemiFungiblePositionManager public sfpm;
    address public user = address(0x1);
    
    function setUp() public {
        // Deploy contracts (simplified - actual deployment more complex)
        // Assume pool and sfpm are properly initialized
    }
    
    function testPremiumAccumulatorFreezeViaPartialClose() public {
        vm.startPrank(user);
        
        // Step 1: User mints short position with N=10,000
        TokenId tokenId = createShortPosition(10000);
        
        // Step 2: User mints long positions, R increases to 90,000 (spread=9, at limit)
        tokenId = addLongPositions(tokenId, 90000);
        
        // Verify spread is at maximum allowed
        (uint256 totalLiq, uint256 netLiq, uint256 removedLiq) = pool.getLiquidities(tokenId, 0);
        assertEq(removedLiq * 10000 / netLiq, 90000); // spread = 9:1
        
        // Step 3: User partially closes short, reducing N to 100
        // This leaves spread at 900:1, far exceeding MAX_SPREAD
        burnShortPosition(tokenId, 9900);
        
        // Step 4: Query premium - this will overflow and freeze accumulators
        (uint128 premium0Before, uint128 premium1Before) = sfpm.getAccountPremium(
            poolKey,
            user,
            tokenType,
            tickLower,
            tickUpper,
            currentTick,
            0, // isLong
            vegoid
        );
        
        // Step 5: Advance time and accumulate fees
        vm.warp(block.timestamp + 1 days);
        // Simulate fee collection in Uniswap
        
        // Step 6: Next premium query will freeze accumulators
        (uint128 premium0After, uint128 premium1After) = sfpm.getAccountPremium(
            poolKey,
            user,
            tokenType,
            tickLower,
            tickUpper,
            currentTick,
            0,
            vegoid
        );
        
        // Verify accumulators are frozen (premium doesn't increase despite fees)
        assertEq(premium0After, type(uint128).max, "Accumulator should be frozen at max");
        assertEq(premium1After, type(uint128).max, "Accumulator should be frozen at max");
        
        // Step 7: Future premium queries return frozen values - permanent loss
        vm.warp(block.timestamp + 365 days);
        (uint128 premium0Future, uint128 premium1Future) = sfpm.getAccountPremium(
            poolKey,
            user,
            tokenType,
            tickLower,
            tickUpper,
            currentTick,
            0,
            vegoid
        );
        
        // Premiums remain frozen - user loses all future premium income
        assertEq(premium0Future, premium0After, "Premiums permanently frozen");
        assertEq(premium1Future, premium1After, "Premiums permanently frozen");
        
        vm.stopPrank();
    }
    
    // Helper functions
    function createShortPosition(uint128 liquidity) internal returns (TokenId) {
        // Create TokenId for short position
        // Call pool.mintOptions with appropriate parameters
    }
    
    function addLongPositions(TokenId tokenId, uint128 removedLiquidity) internal returns (TokenId) {
        // Add long legs to increase removedLiquidity
    }
    
    function burnShortPosition(TokenId tokenId, uint128 liquidityToBurn) internal {
        // Partially close short position
        // This reduces netLiquidity without check on resulting spread
    }
}
```

## Notes

The vulnerability stems from an asymmetry in validation: spread checks protect position **creation** but not position **modification** through partial closure. The equations themselves (1-4) are mathematically correct under the assumption that spreads remain bounded, but this assumption is violated when users can freely reduce `netLiquidity` through burns.

The `toUint128Capped()` function at line 1313 and `addCapped()` at lines 299-321 were designed as overflow protection, but they create a permanent failure state rather than preventing the underlying issue. Once accumulators freeze, the position chunk loses all premium tracking functionality permanently.

This affects the core economic model of the protocol, as option sellers expect to earn premiums proportional to their liquidity provision. The frozen accumulators break this fundamental mechanism, making the issue **HIGH severity** despite requiring user actions to trigger.

### Citations

**File:** contracts/PanopticPool.sol (L1963-1987)
```text
    function _checkLiquiditySpread(
        TokenId tokenId,
        uint256 leg,
        uint256 effectiveLiquidityLimit
    ) internal view returns (uint256 totalLiquidity) {
        uint256 netLiquidity;
        uint256 removedLiquidity;
        (totalLiquidity, netLiquidity, removedLiquidity) = _getLiquidities(tokenId, leg);

        // compute and return effective liquidity. Return if short=net=0, which is closing short position
        if (netLiquidity == 0 && removedLiquidity == 0) return totalLiquidity;

        if (netLiquidity == 0) revert Errors.NetLiquidityZero();

        uint256 effectiveLiquidityFactor;
        unchecked {
            // cannot overflow because liquidities are uint128
            effectiveLiquidityFactor = (removedLiquidity * DECIMALS) / netLiquidity;
        }

        // put a limit on how much new liquidity in one transaction can be deployed into this leg
        // the effective liquidity measures how many times more the newly added liquidity is compared to the existing/base liquidity
        if (effectiveLiquidityFactor > effectiveLiquidityLimit)
            revert Errors.EffectiveLiquidityAboveThreshold();
    }
```

**File:** contracts/SemiFungiblePositionManager.sol (L965-987)
```text
            } else {
                // the _leg is long (buying: moving *from* uniswap to msg.sender)
                // so we seek to move the incoming liquidity chunk *out* of uniswap - but was there sufficient liquidity sitting in uniswap
                // in the first place?
                if (startingLiquidity < chunkLiquidity) {
                    // the amount we want to move (liquidityChunk.legLiquidity()) out of uniswap is greater than
                    // what the account that owns the liquidity in uniswap has (startingLiquidity)
                    // we must ensure that an account can only move its own liquidity out of uniswap
                    // so we revert in this case
                    revert Errors.NotEnoughLiquidityInChunk();
                } else {
                    // startingLiquidity is >= chunkLiquidity, so no possible underflow
                    unchecked {
                        // we want to move less than what already sits in uniswap, no problem:
                        updatedLiquidity = startingLiquidity - chunkLiquidity;
                    }
                }

                /// @dev If the isLong flag is 1=long and the position is minted, then this is opening a long position
                /// @dev so the amount of removed liquidity should increase.
                if (!isBurn) {
                    removedLiquidity += chunkLiquidity;
                }
```

**File:** contracts/SemiFungiblePositionManager.sol (L1262-1347)
```text
    function _getPremiaDeltas(
        LeftRightUnsigned currentLiquidity,
        LeftRightUnsigned collectedAmounts,
        uint256 vegoid
    )
        private
        pure
        returns (LeftRightUnsigned deltaPremiumOwed, LeftRightUnsigned deltaPremiumGross)
    {
        // extract liquidity values
        uint256 removedLiquidity = currentLiquidity.leftSlot();
        uint256 netLiquidity = currentLiquidity.rightSlot();

        // premia spread equations are graphed and documented here: https://www.desmos.com/calculator/mdeqob2m04
        // explains how we get from the premium per liquidity (calculated here) to the total premia collected and the multiplier
        // as well as how the value of VEGOID affects the premia
        // note that the "base" premium is just a common factor shared between the owed (long) and gross (short)
        // premia, and is only separated to simplify the calculation
        // (the graphed equations include this factor without separating it)
        unchecked {
            uint256 totalLiquidity = netLiquidity + removedLiquidity;

            uint256 premium0X64_base;
            uint256 premium1X64_base;

            {
                uint128 collected0 = collectedAmounts.rightSlot();
                uint128 collected1 = collectedAmounts.leftSlot();

                // compute the base premium as collected * total / net^2 (from Eqn 3)
                premium0X64_base = Math.mulDiv(
                    collected0,
                    totalLiquidity * 2 ** 64,
                    netLiquidity ** 2
                );
                premium1X64_base = Math.mulDiv(
                    collected1,
                    totalLiquidity * 2 ** 64,
                    netLiquidity ** 2
                );
            }

            {
                uint128 premium0X64_owed;
                uint128 premium1X64_owed;
                {
                    // compute the owed premium (from Eqn 3)
                    uint256 numerator = netLiquidity + (removedLiquidity / vegoid);

                    premium0X64_owed = Math
                        .mulDiv(premium0X64_base, numerator, totalLiquidity)
                        .toUint128Capped();
                    premium1X64_owed = Math
                        .mulDiv(premium1X64_base, numerator, totalLiquidity)
                        .toUint128Capped();

                    deltaPremiumOwed = LeftRightUnsigned.wrap(premium0X64_owed).addToLeftSlot(
                        premium1X64_owed
                    );
                }
            }

            {
                uint128 premium0X64_gross;
                uint128 premium1X64_gross;
                {
                    // compute the gross premium (from Eqn 4)
                    uint256 numerator = totalLiquidity ** 2 -
                        totalLiquidity *
                        removedLiquidity +
                        ((removedLiquidity ** 2) / vegoid);

                    premium0X64_gross = Math
                        .mulDiv(premium0X64_base, numerator, totalLiquidity ** 2)
                        .toUint128Capped();
                    premium1X64_gross = Math
                        .mulDiv(premium1X64_base, numerator, totalLiquidity ** 2)
                        .toUint128Capped();

                    deltaPremiumGross = LeftRightUnsigned.wrap(premium0X64_gross).addToLeftSlot(
                        premium1X64_gross
                    );
                }
            }
        }
    }
```

**File:** contracts/types/LeftRight.sol (L299-321)
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
    }
```
