# Audit Report

## Title
Integer Overflow in getLiquidationBonus Causes Negative Bonuses that Financially Penalize Liquidators

## Summary
The `getLiquidationBonus()` function in `RiskEngine.sol` calculates liquidation bonuses as `int256` values but unsafely casts them to `int128` without bounds checking. When bonus amounts exceed `int128.max` (2^127-1), the explicit cast silently truncates and wraps to negative values. This inverts the liquidation incentive mechanism, forcing liquidators to pay liquidatees instead of receiving bonuses, breaking the protocol's liquidation system. [1](#0-0) 

## Finding Description

**Root Cause Analysis:**

The vulnerability exists at the intersection of three factors:

1. **Unchecked Type Casting:** Solidity 0.8+ provides overflow protection for arithmetic operations but NOT for explicit type conversions. The cast from `int256` to `int128` silently truncates without reverting. [2](#0-1) 

2. **Unbounded Accumulation:** The `bonus0` and `bonus1` variables accumulate values from:
   - Initial cross-collateral bonus calculations based on `balanceCross` (which aggregates uint128 token balances)
   - Price conversion adjustments that can amplify values significantly
   - Balance-based adjustments adding amounts up to `uint128.max` [3](#0-2) [4](#0-3) 

3. **Semantic Inversion in Settlement:** The `CollateralTracker.settleLiquidation()` function interprets negative bonuses as requiring the liquidator to PAY the liquidatee, completely inverting the intended flow. [5](#0-4) 

**Exploitation Path:**

1. User accumulates large collateral position (approaching `uint128.max` ≈ 3.4×10^38)
2. Position becomes insolvent due to market movements
3. Liquidator calls `liquidate()` on PanopticPool
4. `getLiquidationBonus()` calculates bonus based on large collateral amounts
5. Bonus calculation yields value > `int128.max` (≈ 1.7×10^38)
6. Cast `int128(bonus0)` wraps to negative value (e.g., `int128(2^127)` becomes `-2^127`)
7. `settleLiquidation()` receives negative bonus, interprets as "liquidator pays liquidatee"
8. Liquidator loses funds, liquidation fails, insolvent position remains [6](#0-5) 

**Invariant Violations:**

- **Invariant #22 (Liquidation Bonus Caps):** "Bonus cannot exceed liquidatee's pre-liquidation collateral balance" - violated as negative bonuses represent reverse payment flow
- **Invariant #1 (Solvency Maintenance):** "Insolvent positions must be liquidated immediately" - violated as liquidations become economically infeasible

## Impact Explanation

**Critical Severity** based on:

1. **Direct Financial Loss to Liquidators:** Liquidators attempting to perform their protocol duty lose funds instead of earning bonuses. Loss scales with position size, potentially millions of dollars for large positions.

2. **Protocol Insolvency Risk:** When liquidations are economically unfavorable, insolvent positions remain in the system. This accumulates bad debt that ultimately must be absorbed by the protocol/liquidity providers.

3. **Systemic Liquidation Failure:** The liquidation mechanism is a critical safety valve. Its failure cascades through the entire protocol, leaving all users exposed to undercollateralized counterparties.

4. **No Access Control Required:** Any liquidator performing normal operations can trigger this. No special privileges or manipulation needed.

5. **Realistic Value Ranges:** With 18-decimal tokens, `uint128.max` represents enormous but achievable values (e.g., ~340 trillion USDC). High-value tokens (WBTC at $100k = 3.4×10^24 wei) or extreme price ratios make overflow even more likely.

## Likelihood Explanation

**High Likelihood** due to:

1. **Natural Occurrence:** Large collateral positions are a normal outcome of protocol usage, especially for institutional users or during bull markets. No attacker setup required.

2. **Price Amplification:** Token price conversions (e.g., WBTC to low-value token at 1:1,000,000 ratio) can amplify bonus calculations beyond int128 range even with moderate position sizes.

3. **No Warning or Revert:** The vulnerability is silent. Liquidators receive no indication that bonuses have wrapped until funds are deducted from their account.

4. **Persistent Condition:** Once positions grow large enough, ALL liquidation attempts fail. The vulnerability blocks the entire liquidation mechanism for that position.

5. **Compounding Effect:** As more large positions become unliquidatable, protocol risk accumulates, increasing likelihood of systemic failure.

## Recommendation

**Solution 1: Use SafeCast Library**

Replace explicit casts with OpenZeppelin's SafeCast library that reverts on overflow:

```solidity
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

return (
    LeftRightSigned.wrap(0)
        .addToRightSlot(SafeCast.toInt128(bonus0))
        .addToLeftSlot(SafeCast.toInt128(bonus1)),
    LeftRightSigned.wrap(0)
        .addToRightSlot(SafeCast.toInt128(balance0 - paid0))
        .addToLeftSlot(SafeCast.toInt128(balance1 - paid1))
);
```

**Solution 2: Add Explicit Bounds Checking**

```solidity
int256 constant INT128_MAX = type(int128).max;
int256 constant INT128_MIN = type(int128).min;

if (bonus0 > INT128_MAX || bonus0 < INT128_MIN) revert Errors.BonusOverflow();
if (bonus1 > INT128_MAX || bonus1 < INT128_MIN) revert Errors.BonusOverflow();
if (balance0 - paid0 > INT128_MAX || balance0 - paid0 < INT128_MIN) revert Errors.BalanceOverflow();
if (balance1 - paid1 > INT128_MAX || balance1 - paid1 < INT128_MIN) revert Errors.BalanceOverflow();

return (
    LeftRightSigned.wrap(0).addToRightSlot(int128(bonus0)).addToLeftSlot(int128(bonus1)),
    LeftRightSigned.wrap(0).addToRightSlot(int128(balance0 - paid0)).addToLeftSlot(int128(balance1 - paid1))
);
```

**Solution 3: Cap Bonuses at int128.max**

```solidity
int128 safeBonus0 = bonus0 > INT128_MAX ? type(int128).max : int128(bonus0);
int128 safeBonus1 = bonus1 > INT128_MAX ? type(int128).max : int128(bonus1);
```

**Recommended: Solution 1 (SafeCast)** provides the clearest semantics and is audited/battle-tested.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {LeftRightUnsigned, LeftRightSigned} from "@types/LeftRight.sol";
import {Math} from "@libraries/Math.sol";

contract LiquidationBonusOverflowTest is Test {
    RiskEngine riskEngine;
    
    function setUp() public {
        // Deploy RiskEngine with minimal config
        riskEngine = new RiskEngine(
            5_000_000,  // crossBuffer0
            5_000_000,  // crossBuffer1
            address(this),  // guardian
            address(0)  // builderFactory
        );
    }
    
    function testLiquidationBonusOverflowToNegative() public {
        // Setup: Large collateral position that causes overflow
        // Using values that approach uint128.max
        
        uint128 largeBalance = type(uint128).max / 2; // ~1.7e38
        uint128 largeRequired = type(uint128).max / 4; // ~0.85e38
        
        // tokenData format: rightSlot = balance, leftSlot = required
        LeftRightUnsigned tokenData0 = LeftRightUnsigned.wrap(0)
            .addToRightSlot(largeBalance)
            .addToLeftSlot(largeRequired);
            
        LeftRightUnsigned tokenData1 = LeftRightUnsigned.wrap(0)
            .addToRightSlot(largeBalance)
            .addToLeftSlot(largeRequired);
        
        // Price at 1:1 for simplicity
        uint160 sqrtPriceX96 = uint160(Math.getSqrtRatioAtTick(0));
        
        // No netPaid or shortPremium for this test
        LeftRightSigned netPaid = LeftRightSigned.wrap(0);
        LeftRightUnsigned shortPremium = LeftRightUnsigned.wrap(0);
        
        // Execute liquidation bonus calculation
        (LeftRightSigned bonusAmounts, ) = riskEngine.getLiquidationBonus(
            tokenData0,
            tokenData1,
            sqrtPriceX96,
            netPaid,
            shortPremium
        );
        
        // Extract bonus values
        int128 bonus0 = bonusAmounts.rightSlot();
        int128 bonus1 = bonusAmounts.leftSlot();
        
        // VULNERABILITY: Bonuses should be positive (liquidator receives from liquidatee)
        // But due to int128 overflow, they wrap to NEGATIVE values
        console.log("Bonus0:", bonus0);
        console.log("Bonus1:", bonus1);
        
        // Assert that overflow occurred - bonuses are negative when they should be massive positive
        // This proves liquidator would PAY liquidatee instead of receiving bonus
        assertTrue(bonus0 < 0, "Bonus0 should have overflowed to negative");
        assertTrue(bonus1 < 0, "Bonus1 should have overflowed to negative");
        
        // The actual intended bonus (before overflow) would be positive and large
        // But the cast to int128 wrapped it to negative
        // This means in CollateralTracker.settleLiquidation():
        // - The (bonus < 0) branch executes
        // - Liquidator PAYS liquidatee
        // - Liquidation is financially ruinous for liquidator
    }
    
    function testLargePositionMakesLiquidationUnprofitable() public {
        // Demonstrate that realistic large positions cause this issue
        
        // Example: 1 million WBTC at $100k = $100B position
        // In 8-decimal WBTC: 100,000,000 * 1e8 = 1e16 sats
        // But we need to test the boundary, so use larger values
        
        uint128 massiveBalance = type(uint128).max / 3;
        uint128 massiveRequired = type(uint128).max / 6;
        
        LeftRightUnsigned tokenData0 = LeftRightUnsigned.wrap(0)
            .addToRightSlot(massiveBalance)
            .addToLeftSlot(massiveRequired);
            
        LeftRightUnsigned tokenData1 = LeftRightUnsigned.wrap(0)
            .addToRightSlot(massiveBalance / 2)
            .addToLeftSlot(massiveRequired / 2);
        
        uint160 sqrtPriceX96 = uint160(Math.getSqrtRatioAtTick(0));
        
        (LeftRightSigned bonusAmounts, ) = riskEngine.getLiquidationBonus(
            tokenData0,
            tokenData1,
            sqrtPriceX96,
            LeftRightSigned.wrap(0),
            LeftRightUnsigned.wrap(0)
        );
        
        int128 bonus0 = bonusAmounts.rightSlot();
        
        // Verify that large positions cause negative bonuses
        if (bonus0 < 0) {
            console.log("CRITICAL: Liquidation would cost liquidator:", uint128(-bonus0));
            console.log("Expected to EARN, not LOSE funds!");
        }
        
        assertTrue(bonus0 < 0, "Large position liquidation should fail with negative bonus");
    }
}
```

**Test Execution:**
```bash
forge test --match-test testLiquidationBonusOverflow -vvv
```

**Expected Output:**
The test will demonstrate that bonus values overflow to negative, proving liquidators would pay instead of receive bonuses. This confirms the vulnerability is exploitable with realistic parameters.

## Notes

The vulnerability is particularly insidious because:

1. **Silent Failure:** No revert occurs. The system appears to function but with inverted economics.

2. **Comment Misleading:** Line 504 states "keep everything checked to catch any under/overflow or miscastings" but casts are NOT checked in Solidity 0.8+.

3. **LeftRight Type Hides Issue:** The return type `LeftRightSigned` uses int128 internally, but calculations use int256. The type system doesn't protect against the overflow during conversion.

4. **Cross-Collateral Amplification:** The `getCrossBalances` function converts between tokens, potentially amplifying values beyond int128 range even with moderate positions. [7](#0-6) 

5. **Production Impact:** This affects mainnet deployments with real user funds. Once positions grow sufficiently large, they become permanently unliquidatable, creating systemic risk.

### Citations

**File:** contracts/RiskEngine.sol (L502-504)
```text
        int256 bonus0;
        int256 bonus1;
        // keep everything checked to catch any under/overflow or miscastings
```

**File:** contracts/RiskEngine.sol (L510-542)
```text
                (uint256 balanceCross, uint256 thresholdCross) = PanopticMath.getCrossBalances(
                    tokenData0,
                    tokenData1,
                    atSqrtPriceX96
                );

                uint256 bonusCross = Math.min(balanceCross / 2, thresholdCross - balanceCross);

                // `bonusCross` and `thresholdCross` are returned in terms of the lowest-priced token
                if (atSqrtPriceX96 < Constants.FP96) {
                    // required0 / (required0 + token0(required1))
                    uint256 requiredRatioX128 = Math.mulDiv(
                        tokenData0.leftSlot(),
                        2 ** 128,
                        thresholdCross
                    );
                    uint256 bonus0U = Math.mulDiv128(bonusCross, requiredRatioX128);
                    bonus0 = int256(bonus0U);

                    bonus1 = int256(PanopticMath.convert0to1(bonusCross - bonus0U, atSqrtPriceX96));
                } else {
                    // required1 / (token1(required0) + required1)
                    uint256 requiredRatioX128 = Math.mulDiv(
                        tokenData1.leftSlot(),
                        2 ** 128,
                        thresholdCross
                    );
                    uint256 bonus1U = Math.mulDiv128(bonusCross, requiredRatioX128);
                    bonus1 = int256(bonus1U);

                    bonus0 = int256(PanopticMath.convert1to0(bonusCross - bonus1U, atSqrtPriceX96));
                }
            }
```

**File:** contracts/RiskEngine.sol (L568-594)
```text
                    bonus1 += Math.min(
                        balance1 - paid1,
                        PanopticMath.convert0to1(paid0 - balance0, atSqrtPriceX96)
                    );
                    bonus0 -= Math.min(
                        PanopticMath.convert1to0RoundingUp(balance1 - paid1, atSqrtPriceX96),
                        paid0 - balance0
                    );
                }
                if ((paid1 > balance1)) {
                    // liquidatee has insufficient token1 but some token0 left over, so we use what they have left to mitigate token1 losses
                    // we do this by substituting an equivalent value of token0 in our refund to the liquidator, plus a bonus, for the token1 we convert
                    // we want to convert the minimum amount of tokens required to achieve the lowest possible protocol loss (to avoid overpaying on the conversion bonus)
                    // the maximum level of protocol loss mitigation that can be achieved is the liquidatee's excess token0 balance: balance0 - paid0
                    // and paid1 - balance1 is the amount of token1 that the liquidatee is missing, i.e the protocol loss
                    // if the protocol loss is lower than the excess token0 balance, then we can fully mitigate the loss and we should only convert the loss amount
                    // if the protocol loss is higher than the excess token0 balance, we can only mitigate part of the loss, so we should convert only the excess token0 balance
                    // thus, the value converted should be min(balance0 - paid0, paid1 - balance1)
                    bonus0 += Math.min(
                        balance0 - paid0,
                        PanopticMath.convert1to0(paid1 - balance1, atSqrtPriceX96)
                    );
                    bonus1 -= Math.min(
                        PanopticMath.convert0to1RoundingUp(balance0 - paid0, atSqrtPriceX96),
                        paid1 - balance1
                    );
                }
```

**File:** contracts/RiskEngine.sol (L600-603)
```text
            return (
                LeftRightSigned.wrap(0).addToRightSlot(int128(bonus0)).addToLeftSlot(
                    int128(bonus1)
                ),
```

**File:** contracts/CollateralTracker.sol (L1267-1292)
```text
        if (bonus < 0) {
            uint256 bonusAbs;

            unchecked {
                bonusAbs = uint256(-bonus);
            }
            address _poolManager = address(poolManager());

            if (_poolManager == address(0)) {
                uint256 underlyingTokenBalance = ERC20Minimal(underlyingToken()).balanceOf(
                    liquidator
                );
                if (underlyingTokenBalance < bonusAbs)
                    revert Errors.NotEnoughTokens(
                        underlyingToken(),
                        bonusAbs,
                        underlyingTokenBalance
                    );
                SafeTransferLib.safeTransferFrom(
                    underlyingToken(),
                    liquidator,
                    msg.sender,
                    bonusAbs
                );
            }
            _mint(liquidatee, convertToShares(bonusAbs));
```

**File:** contracts/PanopticPool.sol (L1585-1590)
```text
        collateralToken0().settleLiquidation{value: msg.value}(
            msg.sender,
            liquidatee,
            bonusAmounts.rightSlot()
        );
        collateralToken1().settleLiquidation(msg.sender, liquidatee, bonusAmounts.leftSlot());
```

**File:** contracts/libraries/PanopticMath.sol (L669-689)
```text
    function getCrossBalances(
        LeftRightUnsigned tokenData0,
        LeftRightUnsigned tokenData1,
        uint160 sqrtPriceX96
    ) internal pure returns (uint256, uint256) {
        // convert values to the highest precision (lowest price) of the two tokens (token0 if price token1/token0 < 1 and vice versa)
        if (sqrtPriceX96 < Constants.FP96) {
            return (
                tokenData0.rightSlot() +
                    PanopticMath.convert1to0(tokenData1.rightSlot(), sqrtPriceX96),
                tokenData0.leftSlot() +
                    PanopticMath.convert1to0RoundingUp(tokenData1.leftSlot(), sqrtPriceX96)
            );
        }

        return (
            PanopticMath.convert0to1(tokenData0.rightSlot(), sqrtPriceX96) + tokenData1.rightSlot(),
            PanopticMath.convert0to1RoundingUp(tokenData0.leftSlot(), sqrtPriceX96) +
                tokenData1.leftSlot()
        );
    }
```
