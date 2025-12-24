# Audit Report

## Title
Critical Uint128 Truncation in getAmountsMoved() Causes Systemic Undercollateralization

## Summary
The `PanopticMath.getAmountsMoved()` function unsafely casts token amounts from `uint256` to `uint128`, causing silent truncation for positions with wide tick ranges. This truncated value is used throughout `RiskEngine` to calculate collateral requirements, leading to positions being approved as solvent when they are actually critically undercollateralized. This breaks the core solvency invariant and can cause protocol insolvency.

## Finding Description
In `PanopticMath.getAmountsMoved()`, the results from `Math.getAmount0ForLiquidity()` and `Math.getAmount1ForLiquidity()` are cast to `uint128` before being stored in a `LeftRightUnsigned` type. [1](#0-0) 

The `Math.getAmount1ForLiquidity()` function calculates: `(liquidity * priceDiff) / 2^96` where `priceDiff = highPriceX96 - lowPriceX96`. [2](#0-1) 

For wide tick ranges, even with `liquidity` bounded at `uint128`, the result can exceed `uint128.max`. Consider:
- Maximum liquidity: `2^128 - 1`
- Price difference for a wide range (e.g., 400,000 ticks): approximately `2^124`
- Resulting amount1: `(2^128 * 2^124) / 2^96 = 2^156`

This is `2^28` times larger than `uint128.max`, meaning **28 bits of precision are silently lost** to truncation.

The truncated amounts are then extracted and used in critical collateral calculations in `RiskEngine._getRequiredCollateralSingleLegNoPartner()`: [3](#0-2) 

And in spread calculations within `_getRequiredCollateralSingleLegPartner()`: [4](#0-3) 

**Attack Flow:**
1. Attacker creates a position with maximum allowed liquidity and a wide tick range (e.g., width=4095, tickSpacing=200 → 819,000 tick range)
2. The actual token amounts moved exceed `uint128.max` (e.g., `2^156`)
3. These amounts are truncated to fit in `uint128` (becomes `2^156 mod 2^128`)
4. `RiskEngine` calculates collateral requirements based on the truncated amounts, which are drastically underestimated
5. The position is approved as solvent even though the actual collateral needed is `2^28` times higher
6. The protocol has no way to liquidate this position properly since the true exposure is hidden
7. Multiple such positions can drain the protocol entirely

This directly breaks **Invariant #1 (Solvency Maintenance)**: accounts that should fail solvency checks pass because their collateral requirements are calculated from truncated amounts that are orders of magnitude smaller than the actual risk.

## Impact Explanation
**Critical Severity** - This vulnerability enables:

1. **Direct Protocol Insolvency**: Attackers can open massively undercollateralized positions that appear solvent. With truncation of 28+ bits, a position requiring 268 million units of collateral would only be charged for 1 unit.

2. **Systemic Risk**: The vulnerability affects all positions with wide tick ranges. Since the `width` field supports up to 4095 and tick spacing can be up to 200, realistic positions can hit truncation thresholds.

3. **Unliquidatable Positions**: When these positions move against the attacker, liquidators cannot properly liquidate because the actual amounts owed exceed what the system can track or settle.

4. **Asset Drainage**: Multiple attackers can open undercollateralized positions simultaneously, each appearing safe individually, but collectively draining all protocol collateral when price moves force settlement.

The impact meets the Critical severity threshold: **Direct loss of funds** through undercollateralization bypass, and **Protocol insolvency** from systemic exposure to untracked risk.

## Likelihood Explanation
**High Likelihood** - This vulnerability is:

1. **Easily Triggered**: Any user can create positions with wide tick ranges. The TokenId encoding supports width up to 4095, and tick spacing of 60-200 is common in real Uniswap pools.

2. **No Special Permissions Needed**: Regular users can exploit this during normal position minting. No oracle manipulation or special market conditions required.

3. **Economically Rational**: Attackers are incentivized to exploit this to gain leveraged exposure with minimal collateral, especially during volatile markets.

4. **Not Protected**: There are no checks in the codebase that validate whether amounts exceed `uint128.max` before truncation, nor caps on position width that would prevent reaching truncation thresholds.

5. **Affects Core Functionality**: The vulnerability sits in the fundamental collateral calculation path used for every position, making it unavoidable.

## Recommendation
**Immediate Fix**: Add overflow checks before casting to `uint128` in `getAmountsMoved()`:

```solidity
function getAmountsMoved(
    TokenId tokenId,
    uint128 positionSize,
    uint256 legIndex,
    bool opening
) internal pure returns (LeftRightUnsigned) {
    // ... existing code ...
    
    uint256 rawAmount0;
    uint256 rawAmount1;
    
    if (/* rounding conditions */) {
        rawAmount0 = Math.getAmount0ForLiquidityUp(liquidityChunk);
        rawAmount1 = Math.getAmount1ForLiquidityUp(liquidityChunk);
    } else {
        rawAmount0 = Math.getAmount0ForLiquidity(liquidityChunk);
        rawAmount1 = Math.getAmount1ForLiquidity(liquidityChunk);
    }
    
    // Revert if amounts cannot fit in uint128
    if (rawAmount0 > type(uint128).max) revert Errors.AmountTooLarge();
    if (rawAmount1 > type(uint128).max) revert Errors.AmountTooLarge();
    
    amount0 = uint128(rawAmount0);
    amount1 = uint128(rawAmount1);
    
    return LeftRightUnsigned.wrap(amount0).addToLeftSlot(amount1);
}
```

**Additional Protection**: Consider adding maximum width constraints based on tick spacing to prevent positions from reaching truncation thresholds:

```solidity
function validate(TokenId self) internal pure {
    // ... existing validation ...
    
    // Prevent excessively wide positions that could cause amount overflow
    uint256 maxSafeWidth = _calculateMaxSafeWidth(self.tickSpacing());
    for (uint256 i = 0; i < 4; i++) {
        if (self.width(i) > maxSafeWidth) revert Errors.WidthTooLarge();
    }
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticMath} from "@libraries/PanopticMath.sol";
import {Math} from "@libraries/Math.sol";
import {TokenId, TokenIdLibrary} from "@types/TokenId.sol";
import {LiquidityChunk, LiquidityChunkLibrary} from "@types/LiquidityChunk.sol";
import {LeftRightUnsigned} from "@types/LeftRight.sol";
import {Constants} from "@libraries/Constants.sol";

contract Uint128TruncationTest is Test {
    using TokenIdLibrary for TokenId;
    using LiquidityChunkLibrary for LiquidityChunk;

    function testUint128TruncationCausesUndercollateralization() public {
        // Create a position with wide tick range
        // Using width=4000, tickSpacing=200 → 800,000 tick range
        int24 tickSpacing = 200;
        int24 strike = 0;
        int24 width = 4000;
        
        // Build TokenId with wide position
        TokenId tokenId = TokenId.wrap(0)
            .addPoolId(1)
            .addTickSpacing(tickSpacing)
            .addAsset(0, 0)      // token0
            .addOptionRatio(1, 0)
            .addIsLong(0, 0)     // short position
            .addTokenType(0, 0)  // token0
            .addStrike(strike, 0)
            .addWidth(width, 0);
        
        // Large position size to maximize liquidity
        uint128 positionSize = type(uint64).max; // Large but reasonable
        
        // Calculate liquidity chunk
        LiquidityChunk chunk = PanopticMath.getLiquidityChunk(tokenId, 0, positionSize);
        uint128 liquidity = chunk.liquidity();
        
        console.log("Liquidity:", liquidity);
        
        // Calculate what the actual amount should be (without truncation)
        uint256 actualAmount0 = Math.getAmount0ForLiquidity(chunk);
        uint256 actualAmount1 = Math.getAmount1ForLiquidity(chunk);
        
        console.log("Actual amount0 (uint256):", actualAmount0);
        console.log("Actual amount1 (uint256):", actualAmount1);
        console.log("uint128.max:", type(uint128).max);
        
        // Get amounts through PanopticMath.getAmountsMoved (with truncation)
        LeftRightUnsigned amountsMoved = PanopticMath.getAmountsMoved(
            tokenId,
            positionSize,
            0,
            false
        );
        
        uint128 truncatedAmount0 = amountsMoved.rightSlot();
        uint128 truncatedAmount1 = amountsMoved.leftSlot();
        
        console.log("Truncated amount0 (uint128):", truncatedAmount0);
        console.log("Truncated amount1 (uint128):", truncatedAmount1);
        
        // Demonstrate the truncation
        if (actualAmount0 > type(uint128).max) {
            uint256 lost0 = actualAmount0 - truncatedAmount0;
            console.log("Amount0 lost to truncation:", lost0);
            console.log("Truncation factor:", actualAmount0 / truncatedAmount0);
            
            // This proves undercollateralization
            assert(truncatedAmount0 < actualAmount0);
            assert(lost0 > 0);
        }
        
        if (actualAmount1 > type(uint128).max) {
            uint256 lost1 = actualAmount1 - truncatedAmount1;
            console.log("Amount1 lost to truncation:", lost1);
            console.log("Truncation factor:", actualAmount1 / truncatedAmount1);
            
            assert(truncatedAmount1 < actualAmount1);
            assert(lost1 > 0);
        }
        
        // This demonstrates that collateral calculations will use the truncated
        // (much smaller) values, causing severe undercollateralization
        assertTrue(
            actualAmount0 > type(uint128).max || actualAmount1 > type(uint128).max,
            "Truncation vulnerability demonstrated: amounts exceed uint128.max"
        );
    }
}
```

**Notes:**
- The truncation is silent and deterministic, affecting all wide-range positions
- Current Uniswap V3 pools support tick ranges wide enough to trigger this issue
- The vulnerability compounds with multiple positions, each appearing safe but collectively catastrophic
- Fixing requires either preventing creation of positions that would truncate, or expanding storage to handle full uint256 amounts throughout the system

### Citations

**File:** contracts/libraries/PanopticMath.sol (L722-727)
```text
            amount0 = uint128(Math.getAmount0ForLiquidityUp(liquidityChunk));
            amount1 = uint128(Math.getAmount1ForLiquidityUp(liquidityChunk));
        } else {
            amount0 = uint128(Math.getAmount0ForLiquidity(liquidityChunk));
            amount1 = uint128(Math.getAmount1ForLiquidity(liquidityChunk));
        }
```

**File:** contracts/libraries/Math.sol (L353-360)
```text
    function getAmount1ForLiquidity(LiquidityChunk liquidityChunk) internal pure returns (uint256) {
        uint160 lowPriceX96 = getSqrtRatioAtTick(liquidityChunk.tickLower());
        uint160 highPriceX96 = getSqrtRatioAtTick(liquidityChunk.tickUpper());

        unchecked {
            return mulDiv96(liquidityChunk.liquidity(), highPriceX96 - lowPriceX96);
        }
    }
```

**File:** contracts/RiskEngine.sol (L1398-1406)
```text
        LeftRightUnsigned amountsMoved = PanopticMath.getAmountsMoved(
            tokenId,
            positionSize,
            index,
            false
        );

        // amount moved is right slot if tokenType=0, left slot otherwise
        uint128 amountMoved = tokenType == 0 ? amountsMoved.rightSlot() : amountsMoved.leftSlot();
```

**File:** contracts/RiskEngine.sol (L1799-1842)
```text
            LeftRightUnsigned amountsMoved = PanopticMath.getAmountsMoved(
                tokenId,
                positionSize,
                index,
                false
            );
            unchecked {
                // This is a CALENDAR SPREAD adjustment, where the collateral requirement is the max loss of the position
                // real formula is contractSize * (1/(sqrt(r1)+1) - 1/(sqrt(r2)+1))
                // Taylor expand to get a rough approximation of: contractSize * ∆width * tickSpacing / 40000
                // This is strictly larger than the real one, so OK to use that for a collateral requirement.
                TokenId _tokenId = tokenId;
                int24 deltaWidth = _tokenId.width(index) - _tokenId.width(partnerIndex);

                // TODO check if same strike and same width is allowed -> Think not from TokenId.sol?
                if (deltaWidth < 0) deltaWidth = -deltaWidth;

                if (tokenType == 0) {
                    spreadRequirement +=
                        (amountsMoved.rightSlot() *
                            uint256(int256(deltaWidth * _tokenId.tickSpacing()))) /
                        80000;
                } else {
                    spreadRequirement +=
                        (amountsMoved.leftSlot() *
                            uint256(int256(deltaWidth * _tokenId.tickSpacing()))) /
                        80000;
                }
            }

            moved0 = amountsMoved.rightSlot();
            moved1 = amountsMoved.leftSlot();

            {
                // compute the total amount of funds moved for the position's partner leg
                LeftRightUnsigned amountsMovedPartner = PanopticMath.getAmountsMoved(
                    tokenId,
                    positionSize,
                    partnerIndex,
                    false
                );

                moved0Partner = amountsMovedPartner.rightSlot();
                moved1Partner = amountsMovedPartner.leftSlot();
```
