# VALIDATION RESULT: VALID VULNERABILITY

## Title
Liquidation Bonus Calculation Uses Inflated Balances Including Unsettled Short Premium Leading to Protocol Loss

## Summary
The `getLiquidationBonus()` function in `RiskEngine.sol` calculates liquidation bonuses using collateral balances that incorrectly include accumulated but unsettled short premium (`shortPremium`). This inflated balance is used to determine the bonus amount, but shortPremium is then subtracted afterwards to check against the "real" balance. When the bonus (calculated on inflated balance) exceeds the liquidatee's actual deposited collateral, `CollateralTracker.settleLiquidation()` mints new shares to cover the deficit, causing direct protocol loss through share dilution. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

## Impact
**Severity**: Critical  
**Category**: Direct Fund Loss / Protocol Insolvency

**Affected Assets**: All CollateralTracker vaults (token0 and token1)

**Damage Severity**:
- **Direct Protocol Loss**: Liquidators extract bonuses exceeding liquidatee's actual deposited collateral
- **Share Dilution**: New shares are minted to cover the deficit, diluting all existing PLPs
- **Unlimited Scale**: Loss magnitude scales with accumulated shortPremium, which can grow arbitrarily large for long-term option sellers
- **Protocol-Wide Impact**: Every liquidation of a user with significant accumulated shortPremium triggers this vulnerability

**User Impact**:
- **Who**: All Panoptic Liquidity Providers (PLPs) holding shares in CollateralTracker vaults
- **Conditions**: Occurs during normal liquidations when liquidatee has accumulated shortPremium
- **Recovery**: Requires protocol upgrade to fix bonus calculation logic

**Systemic Risk**: Repeated liquidations of users with accumulated premium steadily drain protocol reserves, undermining collateral system integrity. No cap exists on individual or cumulative losses.

## Finding Description

**Location**: `contracts/RiskEngine.sol:495-609`, function `getLiquidationBonus()`; `contracts/RiskEngine.sol:1120-1190`, function `_getMargin()`

**Intended Logic**: Liquidation bonuses should be capped at the liquidatee's pre-liquidation **deposited collateral balance** (excluding unsettled premium), as stated in the protocol invariant. [8](#0-7) 

**Actual Logic**: The bonus calculation uses an inflated balance that includes `shortPremium` (unsettled premium owed to the user), then only subtracts it afterwards to check against the real balance. By that point, the excessive bonus has already been calculated and will be paid out, with protocol minting shares to cover any shortfall.

**Code Evidence - Balance Inflation**:

In `_getMargin()`, shortPremium is added to the user's balance: [1](#0-0) 

This inflated balance is then stored in `tokenData.rightSlot()`: [2](#0-1) 

**Code Evidence - Bonus Calculation on Inflated Balance**:

When `getLiquidationBonus()` is called, it receives these inflated `tokenData` values: [9](#0-8) 

The function calculates `balanceCross` using `getCrossBalances()`, which operates directly on the inflated `tokenData.rightSlot()`: [3](#0-2) [4](#0-3) 

**Code Evidence - Subtraction After Bonus Calculation**:

Only AFTER calculating `bonusCross`, the code subtracts shortPremium to determine the "real" balance. The comment explicitly states this is "to avoid double-counting": [5](#0-4) 

**Code Evidence - Mitigation Logic Bypass**:

When both tokens are insufficient (`paid0 > balance0 AND paid1 > balance1`), mitigation is skipped: [10](#0-9) 

**Code Evidence - Protocol Loss via Share Minting**:

When `settleLiquidation()` is called with a bonus exceeding the liquidatee's actual balance, it mints shares to cover the deficit: [11](#0-10) 

**Security Property Broken**: Violates Invariant #479 from protocol documentation: "Liquidation bonus paid to liquidator must not exceed the liquidatee's pre-liquidation collateral balance" [8](#0-7) 

**Root Cause Analysis**:
1. **Design Flaw**: The bonus is calculated using `balanceCross` which includes shortPremium, but shortPremium represents unsettled premium (not deposited collateral)
2. **Timing Error**: shortPremium is subtracted AFTER the bonus calculation, not before
3. **Comment Confirms Bug**: The explicit comment about removing shortPremium "to avoid double-counting" confirms it should not be part of the collateral balance used for bonus calculation
4. **Missing Validation**: No cap or check prevents the calculated bonus from exceeding actual deposited collateral before it's returned

## Exploitation Path

**Preconditions**: 
- Alice is an option seller with 100 tokens of actual deposited collateral
- Alice has accumulated 900 tokens of unsettled `shortPremium` from selling options over time
- Market moves against Alice's positions, making her account insolvent

**Step 1**: Liquidator calls `PanopticPool.dispatchFrom()` to liquidate Alice
- Code path: `dispatchFrom()` → `_liquidate()` → `riskEngine.getMargin()`

**Step 2**: In `_getMargin()`, balance is inflated with shortPremium
- Initial balance: `balance0 = 100` (actual deposited collateral)
- After inflation: `balance0 = 100 + 900 = 1000`
- Stored in: `tokenData0.rightSlot() = 1000` [1](#0-0) 

**Step 3**: `getLiquidationBonus()` calculates bonus using inflated balance
- `getCrossBalances()` returns: `balanceCross = 1000` (includes shortPremium)
- Bonus calculated: `bonusCross = min(1000/2, threshold - 1000)` = large value (~250-500 depending on insolvency)
- Distributed to: `bonus0 ≈ 250 tokens` [3](#0-2) 

**Step 4**: Real balance calculated by subtracting shortPremium
- `balance0 = 1000 - 900 = 100` (actual deposited collateral)
- `paid0 = bonus0 + netPaid = 250`
- Result: `paid0 (250) > balance0 (100)` → shortfall of 150 tokens [12](#0-11) 

**Step 5**: If both tokens are insufficient, mitigation is skipped
- Condition: `!(paid0 > balance0 && paid1 > balance1)` evaluates to `false`
- Mitigation logic at lines 557-598 does not execute
- Bonus of 250 tokens is returned as-is [6](#0-5) 

**Step 6**: Protocol loss realized in `settleLiquidation()`
- Liquidator receives `bonusShares = 250 tokens`
- Liquidatee only has `liquidateeBalance = 100 tokens`
- Since `250 > 100`, protocol mints `150 tokens` worth of shares to liquidator
- Protocol loss: 150 tokens through share dilution [7](#0-6) 

## Likelihood Explanation

**Attacker Profile**: Any liquidator monitoring for undercollateralized positions (standard protocol operation)

**Preconditions**:
- **Market State**: Normal operation - no special market conditions required
- **User State**: Liquidatee has accumulated shortPremium and becomes insolvent (common scenario)
- **No Manipulation Needed**: Occurs through normal protocol operations

**Execution Complexity**: 
- **Single Transaction**: Standard liquidation call via `dispatchFrom()`
- **No Coordination Required**: Liquidator follows normal liquidation procedure
- **Automatic Exploitation**: Any liquidation automatically extracts excessive bonus when conditions exist

**Frequency**:
- **Common Scenario**: Option sellers naturally accumulate shortPremium over time as buyers pay premium
- **Regular Occurrence**: Market volatility regularly causes liquidations
- **High Probability**: Users with long-term short positions commonly have large accumulated premium relative to deposited collateral

**Economic Incentive**: Liquidators receive bonuses exceeding liquidatee's actual collateral, making liquidations more profitable at protocol's expense

**Overall Assessment**: High likelihood - occurs naturally during normal protocol operation without requiring any attack or manipulation

## Recommendation

**Immediate Mitigation**:
Calculate bonus based on real balance (excluding shortPremium) instead of inflated balance:

```solidity
// In RiskEngine.getLiquidationBonus()
// Subtract shortPremium BEFORE calculating bonus, not after

int256 balance0 = int256(uint256(tokenData0.rightSlot())) - int256(uint256(shortPremium.rightSlot()));
int256 balance1 = int256(uint256(tokenData1.rightSlot())) - int256(uint256(shortPremium.leftSlot()));

// Create new tokenData with real balances for bonus calculation
LeftRightUnsigned realTokenData0 = LeftRightUnsigned.wrap(uint256(balance0).toUint128()).addToLeftSlot(tokenData0.leftSlot());
LeftRightUnsigned realTokenData1 = LeftRightUnsigned.wrap(uint256(balance1).toUint128()).addToLeftSlot(tokenData1.leftSlot());

(uint256 balanceCross, uint256 thresholdCross) = PanopticMath.getCrossBalances(
    realTokenData0,  // Use real balance
    realTokenData1,  // Use real balance  
    atSqrtPriceX96
);
```

**Permanent Fix**:
Restructure `_getMargin()` to return both inflated balance (for solvency checks) and real balance (for liquidation bonus calculations) separately, or modify `getLiquidationBonus()` to accept shortPremium separately and subtract it before calculating the bonus.

**Additional Measures**:
- Add invariant test verifying: `liquidationBonus ≤ actualDepositedCollateral`
- Add assertion in `getLiquidationBonus()`: `require(bonus ≤ realBalance, "Bonus exceeds real balance")`
- Implement circuit breaker to halt liquidations if cumulative protocol loss exceeds threshold

## Notes

This vulnerability directly contradicts the protocol's documented invariant that "Liquidation bonus paid to liquidator must not exceed the liquidatee's pre-liquidation collateral balance" [8](#0-7) . The code comment at lines 544-545 explicitly acknowledges that shortPremium should be removed "to avoid double-counting" [13](#0-12) , confirming this is a bug rather than intentional design.

The vulnerability is NOT listed in the "Publicly known issues" section [14](#0-13) . While the README mentions that "It's known that liquidators sometimes have a limited capacity to force liquidations to execute at a less favorable price and extract some additional profit" [15](#0-14) , this refers to price manipulation profits, not calculation errors that allow bonuses to exceed deposited collateral in violation of the stated invariant.

### Citations

**File:** contracts/RiskEngine.sol (L510-516)
```text
                (uint256 balanceCross, uint256 thresholdCross) = PanopticMath.getCrossBalances(
                    tokenData0,
                    tokenData1,
                    atSqrtPriceX96
                );

                uint256 bonusCross = Math.min(balanceCross / 2, thresholdCross - balanceCross);
```

**File:** contracts/RiskEngine.sol (L544-549)
```text
            // negative premium (owed to the liquidatee) is credited to the collateral balance
            // this is already present in the netPaid amount, so to avoid double-counting we remove it from the balance
            int256 balance0 = int256(uint256(tokenData0.rightSlot())) -
                int256(uint256(shortPremium.rightSlot()));
            int256 balance1 = int256(uint256(tokenData1.rightSlot())) -
                int256(uint256(shortPremium.leftSlot()));
```

**File:** contracts/RiskEngine.sol (L557-598)
```text
            if (!(paid0 > balance0 && paid1 > balance1)) {
                // liquidatee cannot pay back the liquidator fully in either token, so no protocol loss can be avoided
                if ((paid0 > balance0)) {
                    // liquidatee has insufficient token0 but some token1 left over, so we use what they have left to mitigate token0 losses
                    // we do this by substituting an equivalent value of token1 in our refund to the liquidator, plus a bonus, for the token0 we convert
                    // we want to convert the minimum amount of tokens required to achieve the lowest possible protocol loss (to avoid overpaying on the conversion bonus)
                    // the maximum level of protocol loss mitigation that can be achieved is the liquidatee's excess token1 balance: balance1 - paid1
                    // and paid0 - balance0 is the amount of token0 that the liquidatee is missing, i.e the protocol loss
                    // if the protocol loss is lower than the excess token1 balance, then we can fully mitigate the loss and we should only convert the loss amount
                    // if the protocol loss is higher than the excess token1 balance, we can only mitigate part of the loss, so we should convert only the excess token1 balance
                    // thus, the value converted should be min(balance1 - paid1, paid0 - balance0)
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
                // recompute netPaid based on new bonus amounts
                paid0 = bonus0 + int256(netPaid.rightSlot());
                paid1 = bonus1 + int256(netPaid.leftSlot());
            }
```

**File:** contracts/RiskEngine.sol (L1174-1175)
```text
            balance0 += shortPremia.rightSlot();
            balance1 += shortPremia.leftSlot();
```

**File:** contracts/RiskEngine.sol (L1183-1189)
```text
        tokenData0 = LeftRightUnsigned.wrap(balance0.toUint128()).addToLeftSlot(
            tokensRequired.rightSlot()
        );

        tokenData1 = LeftRightUnsigned.wrap(balance1.toUint128()).addToLeftSlot(
            tokensRequired.leftSlot()
        );
```

**File:** contracts/libraries/PanopticMath.sol (L676-680)
```text
            return (
                tokenData0.rightSlot() +
                    PanopticMath.convert1to0(tokenData1.rightSlot(), sqrtPriceX96),
                tokenData0.leftSlot() +
                    PanopticMath.convert1to0RoundingUp(tokenData1.leftSlot(), sqrtPriceX96)
```

**File:** contracts/CollateralTracker.sol (L1322-1354)
```text
            uint256 bonusShares = convertToShares(uint256(bonus));

            // if requested amount is larger than user balance, transfer their balance and mint the remaining shares
            if (bonusShares > liquidateeBalance) {
                _transferFrom(liquidatee, liquidator, liquidateeBalance);

                // this is paying out protocol loss, so correct for that in the amount of shares to be minted
                // X: total assets in vault
                // Y: total supply of shares
                // Z: desired value (assets) of shares to be minted
                // N: total shares corresponding to Z
                // T: transferred shares from liquidatee which are a component of N but do not contribute toward protocol loss
                // Z = N * X / (Y + N - T)
                // Z * (Y + N - T) = N * X
                // ZY + ZN - ZT = NX
                // ZY - ZT = N(X - Z)
                // N = (ZY - ZT) / (X - Z)
                // N = Z(Y - T) / (X - Z)
                // subtract delegatee balance from N since it was already transferred to the delegator
                uint256 _totalSupply = totalSupply();

                // keep checked to catch any casting/math errors
                _mint(
                    liquidator,
                    Math.min(
                        Math.mulDivCapped(
                            uint256(bonus),
                            _totalSupply - liquidateeBalance,
                            uint256(Math.max(1, int256(totalAssets()) - bonus))
                        ) - liquidateeBalance,
                        _totalSupply * DECIMALS
                    )
                );
```

**File:** README.md (L53-125)
```markdown
## Publicly known issues

_Anything included in this section and its subsection is considered a publicly known issue and is therefore ineligible for awards._

**System & Token Limitations**

- Transfers of ERC1155 SFPM tokens has been disabled.
- Construction helper functions (prefixed with add) in the TokenId library and other types do not perform extensive input validation. Passing invalid or nonsensical inputs into these functions or attempting to overwrite already filled slots may yield unexpected or invalid results. This is by design, so it is expected that users of these functions will validate the inputs beforehand.
- Tokens with a supply exceeding 2^127 - 1 are not supported.
- If one token on a pool is broken/does not meet listed criteria/is malicious there are no guarantees as to the security of the other token in that pool, as long as other pools with two legitimate and compliant tokens are not affected.

**Oracle & Price Manipulation**

- Price/oracle manipulation that is not atomic or requires attackers to hold a price across more than one block is not in scope -i.e., to manipulate the internal exponential moving averages (EMAs), you need to set the manipulated price and then keep it there for at least 1 minute until it can be updated again.
- Attacks that stem from the EMA oracles being extremely stale compared to the market price within its period (currently between 2-30 minutes)
- As a general rule, only price manipulation issues that can be triggered by manipulating the price atomically from a normal pool/oracle state are valid

**Protocol Parameters**

- The constants VEGOID, EMA_PERIODS, MAX_TICKS_DELTA, MAX_TWAP_DELTA_LIQUIDATION, MAX_SPREAD, BP_DECREASE_BUFFER, MAX_CLAMP_DELTA, NOTIONAL_FEE, PREMIUM_FEE, PROTOCOL_SPLIT, BUILDER_SPLIT, SELLER_COLLATERAL_RATIO, BUYER_COLLATERAL_RATIO, MAINT_MARGIN_RATE, FORCE_EXERCISE_COST, TARGET_POOL_UTIL, SATURATED_POOL_UTIL, MAX_OPEN_LEGS, and the IRM parameters (CURVE_STEEPNESS, TARGET_UTILIZATION, etc.) are all parameters and subject to change, but within reasonable levels.

**Premium & Liquidation Issues**

- Given a small enough pool and low seller diversity, premium manipulation by swapping back and forth in Uniswap is a known risk. As long as it's not possible to do it between two of your own accounts profitably and doesn't cause protocol loss, that's acceptable
- It's known that liquidators sometimes have a limited capacity to force liquidations to execute at a less favorable price and extract some additional profit from that. This is acceptable even if it causes some amount of unnecessary protocol loss.
- It's possible to leverage the rounding direction to artificially inflate the total gross premium and significantly decrease the rate of premium option sellers earn/are able to withdraw (but not the premium buyers pay) in the future (only significant for very-low-decimal pools, since this must be done one token at a time).
- It's also possible for options buyers to avoid paying premium by calling settleLongPremium if the amount of premium owed is sufficiently small.
- Premium accumulation can become permanently capped if the accumulator exceeds the maximum value; this can happen if a low amount of liquidity earns a large amount of (token) fees

**Gas & Execution Limitations**

- The liquidator may not be able to execute a liquidation if MAX_POSITIONS is too high for the deployed chain due to an insufficient gas limit. This parameter is not final and will be adjusted by deployed chain such that the most expensive liquidation is well within a safe margin of the gas limit.
- It's expected that liquidators may have to sell options, perform force exercises, and deposit collateral to perform some liquidations. In some situations, the liquidation may not be profitable.
- In some situations (stale oracle tick), force exercised users will be worse off than if they had burnt their position.

**Share Supply Issues**

- It is feasible for the share supply of the CollateralTracker to approach 2**256 - 1 (given the token supply constraints, this can happen through repeated protocol-loss-causing liquidations), which can cause various reverts and overflows. Generally, issues with an extremely high share supply as a precondition (delegation reverts due to user's balance being too high, other DoS caused by overflows in calculations with share supply or balances, etc.) are not valid unless that share supply can be created through means other than repeated liquidations/high protocol loss.

**Constructor Assumptions**

- For the purposes of this competition, assume the constructor arguments to the RiskEngine are: 10_000_000, 10_000_000, address(0), address(0)

**Out of Scope**

- Front-running via insufficient slippage specification is not in scope

### Additional Findings from Nethermind pre-contest

1. **Double Penalty / Index Update**

   Users pay the interest penalty even when using phantom shares for interest payment. In force exercise scenarios, the user pays in `delegate(...)` and their borrow index is also updated in `_accrueInterest`. In the regular penalty case, the index is not updated.

2. **Masking Insolvency Magnitude**

   While the else cases in `_getMargin(...)` correctly resolve the staleness issue, the if statement (where interest owed > balance) masks the true deficit magnitude. Since `_getMargin(...)` is used in `isAccountSolvent(...)`, setting interest (requirement) to the balance value hides the actual funds shortage.
   
   **Example:** Alice owes 100 interest with a balance of 20. Setting interest to 20 and balance to 0 shows a deficit of 20 instead of the actual deficit of 80.

3. **Broken Bonus Calculations**

   The if statement logic in `_getMargin(...)` breaks bonus calculations by hiding the true deficit. The values of bonus cross and threshold cross are calculated based on the masked deficit rather than the actual shortage.

4. **Orphan Shares in Delegate/Revoke**

   The `delegate(...)` to `revoke(...)` interaction creates shares not owned by anyone, breaking the supply invariant. In force exercise scenarios:

   1. User starts with balance X.
   2. **Delegate:** User balance inflates to inflation + X, then decrements by X due to insufficient interest payment. Balance = inflation.
   3. **Settle Burn / Accrue Interest:** Y shares are burned to cover interest (sufficient phantom balance). Total supply decreases by Y. User balance = inflation - Y.
   4. **Revoke:** Since inflation > balance, user balance is zeroed and total supply is restored by adding Y (inflation - (inflation - Y)).
   5. **Result:** Net change in total supply is 0 (-Y burn +Y restore). The original X shares remain in total supply but are owned by no one.

```

**File:** README.md (L479-479)
```markdown
- Liquidation bonus paid to liquidator must not exceed the liquidatee's pre-liquidation collateral balance
```

**File:** contracts/PanopticPool.sol (L1540-1546)
```text
            (bonusAmounts, collateralRemaining) = riskEngine().getLiquidationBonus(
                tokenData0,
                tokenData1,
                Math.getSqrtRatioAtTick(twapTick),
                netPaid,
                shortPremium
            );
```
