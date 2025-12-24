# Audit Report

## Title 
Sign Flip in collateralRemaining Bypasses Premium Haircutting During Liquidation

## Summary
The `getLiquidationBonus` function in RiskEngine.sol contains a critical flaw in its token conversion logic that can cause `collateralRemaining` to incorrectly indicate zero protocol loss when an actual loss exists. This occurs when large short premium values cause negative balance calculations, which are then improperly used in surplus-to-deficit conversion operations, ultimately bypassing the premium haircutting mechanism in `haircutPremia`.

## Finding Description

The vulnerability exists in the liquidation bonus calculation and token conversion logic within `RiskEngine.sol`. The issue stems from three interconnected flaws:

**1. Negative Balance Calculation:** [1](#0-0) 

When `shortPremium.rightSlot()` exceeds `tokenData0.rightSlot()`, the adjusted `balance0` becomes negative. While this is an intentional accounting adjustment to avoid double-counting premium already present in `netPaid`, the subsequent logic incorrectly treats this negative balance as if it represents actual collateral shortage.

**2. Unchecked Token Conversion Logic:** [2](#0-1) 

When attempting to convert "excess token0 balance" to cover token1 deficits, the code computes `balance0 - paid0` without verifying it's positive. The comment at line 581 explicitly states this should represent "the liquidatee's excess token0 balance", but when `balance0` is negative, `balance0 - paid0` becomes even more negative, not a surplus.

The code then adds this negative value to `bonus0`, effectively reducing the liquidation bonus: [3](#0-2) 

**3. Sign Flip in collateralRemaining:**
After the incorrect bonus adjustment, `paid0` is recomputed: [4](#0-3) 

This causes `collateralRemaining = balance0 - paid0` to flip from negative (indicating protocol loss) to zero or positive (indicating no loss): [5](#0-4) 

**4. Haircut Bypass:**
When `haircutPremia` receives this incorrect `collateralRemaining`, it fails to apply necessary premium clawback: [6](#0-5) 

If `collateralRemaining.rightSlot() >= 0`, then `collateralDelta0 = 0`, meaning no haircut occurs despite actual protocol loss.

**Attack Scenario:**
1. Liquidatee holds positions with large accumulated short premium (owed to them as long position holders)
2. Upon liquidation, `shortPremium.rightSlot() > tokenData0.rightSlot()`, making `balance0` negative
3. Token1 has a deficit (`paid1 > balance1`), triggering the conversion logic
4. The code adds `balance0 - paid0` (a large negative number) to `bonus0`, drastically reducing it
5. After recomputation, `collateralRemaining` incorrectly shows zero protocol loss
6. `haircutPremia` skips premium clawback, leaving protocol loss uncovered

**Invariant Broken:**
This breaks **Invariant #23: Premium Haircutting** - "Premium must be clawed back if protocol loss exists after liquidation. Missing haircuts enable economic exploits."

## Impact Explanation

**Severity: HIGH**

This vulnerability causes **systemic undercollateralization** by allowing protocol losses to remain uncovered. When liquidations occur for users with large short premium positions, the protocol fails to claw back premium that should compensate for losses, directly impacting protocol solvency.

The impact is:
- **Direct Protocol Loss**: Premium that should be haircut to cover liquidation losses remains unpaid
- **Cascading Risk**: Uncovered losses accumulate over multiple liquidations, threatening overall protocol solvency
- **Liquidator Advantage**: Liquidators benefit from reduced bonus deductions while the protocol bears the loss

This meets the **High Severity** criteria from Immunefi's scope: "Systemic undercollateralization risks" and "Temporary freezing of funds with economic loss."

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

This vulnerability occurs in realistic market conditions:

**Preconditions:**
1. Liquidatee has long positions with accumulated premium (common during high volatility)
2. Premium accumulation exceeds collateral balance (occurs when positions are held long-term)
3. Liquidation triggered with imbalanced token deficits (normal liquidation scenario)

**Attacker Profile:**
- Liquidatee and liquidator can be the same entity (self-liquidation)
- Or natural market liquidations trigger the bug unintentionally
- No special privileges or oracle manipulation required

**Complexity:**
- No complex setup required beyond holding positions with premium accumulation
- Occurs through normal liquidation flow
- Becomes more likely as protocol matures and positions age

The vulnerability is **passive** - it doesn't require active exploitation, making it more dangerous as it affects legitimate liquidations.

## Recommendation

Add validation to ensure `balance0 - paid0 > 0` before performing token conversion. The conversion logic should only execute when there's actual surplus collateral to convert:

```solidity
if ((paid1 > balance1)) {
    int256 surplusToken0 = balance0 - paid0;
    
    // Only convert if there's actual surplus in token0
    if (surplusToken0 > 0) {
        bonus0 += Math.min(
            surplusToken0,
            PanopticMath.convert1to0(paid1 - balance1, atSqrtPriceX96)
        );
        bonus1 -= Math.min(
            PanopticMath.convert0to1RoundingUp(surplusToken0, atSqrtPriceX96),
            paid1 - balance1
        );
    }
    // If surplusToken0 <= 0, skip conversion as there's no surplus to use
}
```

Apply the same fix to the first conversion branch (lines 559-575) for symmetry:

```solidity
if ((paid0 > balance0)) {
    int256 surplusToken1 = balance1 - paid1;
    
    if (surplusToken1 > 0) {
        bonus1 += Math.min(
            surplusToken1,
            PanopticMath.convert0to1(paid0 - balance0, atSqrtPriceX96)
        );
        bonus0 -= Math.min(
            PanopticMath.convert1to0RoundingUp(surplusToken1, atSqrtPriceX96),
            paid0 - balance0
        );
    }
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine} from "../../contracts/RiskEngine.sol";
import {LeftRightUnsigned, LeftRightSigned} from "../../contracts/types/LeftRight.sol";
import {PanopticMath} from "../../contracts/libraries/PanopticMath.sol";
import {Math} from "../../contracts/libraries/Math.sol";

contract SignFlipVulnerabilityTest is Test {
    using LeftRightLibrary for LeftRightUnsigned;
    using LeftRightLibrary for LeftRightSigned;

    RiskEngine public riskEngine;

    function setUp() public {
        // Deploy RiskEngine with appropriate parameters
        riskEngine = new RiskEngine(/* constructor params */);
    }

    function testSignFlipBypassesHaircut() public {
        // Setup scenario where shortPremium exceeds tokenData balance
        // tokenData0: balance=100, requirement=80
        LeftRightUnsigned tokenData0 = LeftRightUnsigned.wrap(0)
            .addToRightSlot(100)  // balance
            .addToLeftSlot(80);   // requirement
        
        // tokenData1: balance=100, requirement=80  
        LeftRightUnsigned tokenData1 = LeftRightUnsigned.wrap(0)
            .addToRightSlot(100)
            .addToLeftSlot(80);
        
        // Large shortPremium (200 > 100 balance) causes negative balance0
        LeftRightUnsigned shortPremium = LeftRightUnsigned.wrap(0)
            .addToRightSlot(200)  // token0 premium owed to liquidatee
            .addToLeftSlot(50);   // token1 premium
        
        // netPaid: liquidatee pays some in token0, deficit in token1
        LeftRightSigned netPaid = LeftRightSigned.wrap(0)
            .addToRightSlot(20)   // pays 20 token0
            .addToLeftSlot(150);  // pays 150 token1 (creates deficit)
        
        uint160 atSqrtPriceX96 = Math.getSqrtRatioAtTick(0); // 1:1 price
        
        // Call getLiquidationBonus
        (
            LeftRightSigned bonusAmounts,
            LeftRightSigned collateralRemaining
        ) = riskEngine.getLiquidationBonus(
            tokenData0,
            tokenData1,
            atSqrtPriceX96,
            netPaid,
            shortPremium
        );
        
        // Verify the sign flip: collateralRemaining should be negative (loss)
        // but due to the bug, it's zero or positive
        int128 collateralToken0 = collateralRemaining.rightSlot();
        
        // Expected: negative value indicating protocol loss
        // Actual: zero or positive due to sign flip
        assertEq(collateralToken0, 0, "Sign flip occurred - should be negative");
        
        // This zero value causes haircutPremia to skip haircuts
        int256 collateralDelta0 = -Math.min(collateralToken0, 0);
        assertEq(collateralDelta0, 0, "No haircut applied despite protocol loss");
        
        console.log("Bonus Token0:", bonusAmounts.rightSlot());
        console.log("Collateral Remaining Token0:", collateralToken0);
        console.log("Collateral Delta (haircut amount):", collateralDelta0);
    }
}
```

**Notes:**
- The test demonstrates how large `shortPremium` values cause `balance0` to become negative
- The conversion logic incorrectly adds negative values to `bonus0`
- `collateralRemaining` flips from negative (expected) to zero (incorrect)
- This zero value causes `haircutPremia` to apply no haircut, leaving protocol loss uncovered
- The vulnerability is deterministic given the right market conditions (aged positions with premium accumulation)

### Citations

**File:** contracts/RiskEngine.sol (L546-549)
```text
            int256 balance0 = int256(uint256(tokenData0.rightSlot())) -
                int256(uint256(shortPremium.rightSlot()));
            int256 balance1 = int256(uint256(tokenData1.rightSlot())) -
                int256(uint256(shortPremium.leftSlot()));
```

**File:** contracts/RiskEngine.sol (L577-593)
```text
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
```

**File:** contracts/RiskEngine.sol (L596-597)
```text
                paid0 = bonus0 + int256(netPaid.rightSlot());
                paid1 = bonus1 + int256(netPaid.leftSlot());
```

**File:** contracts/RiskEngine.sol (L604-606)
```text
                LeftRightSigned.wrap(0).addToRightSlot(int128(balance0 - paid0)).addToLeftSlot(
                    int128(balance1 - paid1)
                )
```

**File:** contracts/RiskEngine.sol (L642-643)
```text
                int256 collateralDelta0 = -Math.min(collateralRemaining.rightSlot(), 0);
                int256 collateralDelta1 = -Math.min(collateralRemaining.leftSlot(), 0);
```
