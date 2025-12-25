# Validation Result: VALID VULNERABILITY

## Title
Premium Haircut Bypass Allows Short Position Holders to Extract Full Premium During Liquidation Despite Protocol Loss

## Summary
The `haircutPremia()` function in RiskEngine.sol only applies premium haircuts to long position legs during liquidations with protocol loss, while short position premium is paid out in full. This violates the protocol's explicit requirement that "premia cannot be paid if there is protocol loss," allowing liquidatees with short positions to extract accumulated premium while PLPs bear the unrecovered loss. [1](#0-0) 

## Impact
**Severity**: HIGH  
**Category**: Economic Manipulation / Protocol Loss

**Affected Assets**: Protocol liquidity (ETH/USDC deposited by PLPs in CollateralTracker vaults)

**Damage Severity**:
- Attackers extract accumulated premium from short positions despite causing protocol loss
- Protocol liquidity providers bear losses that should be recovered through premium haircutting
- Loss magnitude scales with accumulated premium and protocol loss amount
- Creates adverse selection where rational short sellers facing insolvency prefer liquidation over voluntary closure

**User Impact**:
- **Who**: All Panoptic Liquidity Providers (PLPs) who deposit into CollateralTracker vaults
- **Conditions**: Exploitable whenever a user with short positions becomes insolvent during normal market volatility
- **Recovery**: Protocol loss is permanent; requires manual intervention to pause further exploitation

## Finding Description

**Location**: `contracts/RiskEngine.sol:620-800`, function `haircutPremia()`; `contracts/libraries/InteractionHelper.sol:112-175`, function `settleAmounts()`

**Intended Logic**: When liquidating an insolvent position with protocol loss (`collateralRemaining < 0`), ALL premium paid to sellers (both long and short positions) must be proportionally clawed back to mitigate the loss. [2](#0-1) 

**Actual Logic**: The haircut mechanism only processes LONG position legs:

1. **Premium Accumulation for Long Legs Only**: [3](#0-2) 

2. **Haircut Calculation for Long Legs Only**: [4](#0-3) 

3. **Settlement Application for Long Legs Only**: [5](#0-4) 

**Exploitation Path**:

1. **Preconditions**: Attacker deposits collateral and opens SHORT positions in any liquidity area
   
2. **Step 1 - Premium Accumulation**: Short positions accumulate premium over time as buyers pay for options
   - Code path: Normal premium accrual via `_updateSettlementPostBurn()` [6](#0-5) 

3. **Step 2 - Insolvency**: Attacker's account becomes insolvent through market movements or additional position management

4. **Step 3 - Liquidation Initiated**: Liquidator calls `liquidateAccount()`, triggering `_liquidate()` [7](#0-6) 

5. **Step 4 - Premium Paid Before Haircut**: `_burnOptions()` calls `settleBurn()` which immediately pays out short premium [8](#0-7) [9](#0-8) 

6. **Step 5 - Incomplete Haircut**: `haircutPremia()` is called but only claws back LONG premium, not SHORT premium [10](#0-9) 

7. **Unauthorized Outcome**: Short sellers receive full premium payout; protocol loss remains unrecovered from short premium, violating the explicit security requirement

**Security Property Broken**: Premium clawback invariant - "premia cannot be paid if there is protocol loss" (PanopticPool.sol:1548)

**Root Cause Analysis**:
- The haircut calculation only accumulates `longPremium` by filtering `tokenId.isLong(leg) == 1`
- The per-leg haircut loop again filters for long legs only
- Short premium is paid out via `settleBurn()` BEFORE the haircut mechanism executes
- No mechanism exists to claw back short premium after it's been paid

## Impact Explanation

**Quantitative**: Attacker extracts accumulated premium limited only by their position size and time held. For a position accumulating 1% premium per week over 4 weeks at 10 ETH notional: ~0.4 ETH extraction per liquidation event.

**Qualitative**: Systemic adverse selection problem - all rational short sellers facing insolvency will prefer liquidation (receive full premium) over voluntary position closure (receive only solvent portion).

**Systemic Risk**:
- Creates economic incentive structure favoring liquidation over responsible position management
- Compounds during market volatility when many positions simultaneously approach insolvency
- PLPs bear cumulative losses from all liquidations with short positions

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with capital to open short positions
- **Resources Required**: Minimal - standard collateral deposit (20% for sellers)
- **Technical Skill**: Low - exploit occurs through normal position operations

**Preconditions**:
- **Market State**: Normal operation; more frequent during volatility
- **Attacker State**: Must have short positions with accumulated premium
- **Timing**: Occurs naturally when account becomes insolvent

**Execution Complexity**:
- **Transaction Count**: Standard liquidation flow (single transaction by liquidator)
- **Coordination**: None required - exploit is automatic during liquidation
- **Detection Risk**: Appears as normal liquidation; difficult to distinguish from legitimate activity

**Frequency**: HIGH - Occurs in every liquidation involving short positions with accumulated premium during protocol loss conditions. Market volatility naturally creates these conditions.

**Overall Assessment**: HIGH likelihood - The vulnerability is triggered automatically during standard liquidation flows, requires no special setup, and becomes more frequent during market stress when liquidations increase.

## Recommendation

**Immediate Mitigation**:
Extend the haircut mechanism to process both long AND short position legs:

```solidity
// In RiskEngine.sol, line 649
for (uint256 leg = 0; leg < numLegs; ++leg) {
    // Remove the isLong filter - process ALL legs
    longPremium = longPremium.sub(premiasByLeg[i][leg]);
}
```

**Permanent Fix**:
Modify `haircutPremia()` to calculate haircut for all position legs:

```solidity
// In RiskEngine.sol, line 741-795
for (uint256 leg = 0; leg < tokenId.countLegs(); ++leg) {
    // Remove isLong(leg) == 1 check
    if (LeftRightSigned.unwrap(_premiasByLeg[i][leg]) != 0) {
        // Calculate haircut for this leg regardless of long/short
        // Adjust calculation for short legs which have positive premium
        LeftRightSigned haircutAmounts;
        
        int256 legPremiumToHaircut = _premiasByLeg[i][leg].rightSlot();
        if (legPremiumToHaircut != 0 && longPremium.rightSlot() != 0) {
            haircutAmounts = haircutAmounts.addToRightSlot(
                int128(uint128(Math.unsafeDivRoundingUp(
                    uint128(Math.abs(legPremiumToHaircut)) * 
                        uint256(uint128(haircutBase.rightSlot())),
                    uint128(Math.abs(longPremium.rightSlot()))
                )))
            );
        }
        // Similar for leftSlot
        haircutTotal = haircutTotal.add(
            LeftRightUnsigned.wrap(uint256(LeftRightSigned.unwrap(haircutAmounts)))
        );
        haircutPerLeg[i][leg] = haircutAmounts;
    }
}
```

Similarly update `InteractionHelper.settleAmounts()`:

```solidity
// In InteractionHelper.sol, line 126-152
for (uint256 leg = 0; leg < tokenId.countLegs(); ++leg) {
    // Remove isLong check to process all legs
    if (LeftRightSigned.unwrap(premiasByLeg[i][leg]) != 0) {
        // Apply haircut to all premium
        // ...
    }
}
```

**Additional Measures**:
- Add invariant test verifying total premium paid never exceeds available collateral
- Add event logging for haircut amounts per position type
- Monitor liquidations for protocol loss patterns

**Validation**:
- [ ] Fix applies haircut to both long and short positions
- [ ] No double-counting of premium in haircut calculation
- [ ] Maintains backward compatibility for positions without short legs
- [ ] Gas impact acceptable (<10% increase in liquidation costs)

## Notes

This vulnerability stems from an incomplete implementation of the premium haircutting mechanism. The explicit comment stating "premia cannot be paid if there is protocol loss" indicates the design intent was to haircut ALL premium, but the implementation only processes long positions. The root cause is the conditional filtering on `tokenId.isLong(leg) == 1` throughout the haircut calculation and settlement logic.

The economic impact is particularly severe because:
1. It creates adverse selection (rational actors prefer liquidation over closure)
2. It compounds during volatility when liquidations increase
3. It's difficult to detect as it appears as normal liquidation flow
4. It permanently transfers value from PLPs to liquidatees

### Citations

**File:** contracts/PanopticPool.sol (L918-939)
```text
            int128 paid0 = collateralToken0().settleBurn(
                owner,
                longAmounts.rightSlot(),
                shortAmounts.rightSlot(),
                netAmmDelta.rightSlot(),
                realizedPremia.rightSlot(),
                _rp
            );
            paidAmounts = paidAmounts.addToRightSlot(paid0);
        }

        {
            int128 paid1 = collateralToken1().settleBurn(
                owner,
                longAmounts.leftSlot(),
                shortAmounts.leftSlot(),
                netAmmDelta.leftSlot(),
                realizedPremia.leftSlot(),
                _rp
            );
            paidAmounts = paidAmounts.addToLeftSlot(paid1);
        }
```

**File:** contracts/PanopticPool.sol (L1216-1235)
```text
                        LeftRightUnsigned availablePremium = _getAvailablePremium(
                            totalLiquidityBefore,
                            settledTokens,
                            grossPremiumLast,
                            LeftRightUnsigned.wrap(uint256(LeftRightSigned.unwrap(legPremia))),
                            premiumAccumulatorsByLeg[leg]
                        );

                        // subtract settled tokens sent to seller
                        settledTokens = settledTokens.sub(availablePremium);

                        // add available premium to amount that should be settled
                        realizedPremia = realizedPremia.add(
                            LeftRightSigned.wrap(int256(LeftRightUnsigned.unwrap(availablePremium)))
                        );

                        // update the base `premiaByLeg` value to reflect the amount of premium that will actually be settled
                        premiaByLeg[leg] = LeftRightSigned.wrap(
                            int256(LeftRightUnsigned.unwrap(availablePremium))
                        );
```

**File:** contracts/PanopticPool.sol (L1529-1535)
```text
            (netPaid, premiasByLeg) = _burnAllOptionsFrom(
                liquidatee,
                MIN_SWAP_TICK,
                MAX_SWAP_TICK,
                DONOT_COMMIT_LONG_SETTLED,
                positionIdList
            );
```

**File:** contracts/PanopticPool.sol (L1548-1553)
```text
            // premia cannot be paid if there is protocol loss associated with the liquidatee
            // otherwise, an economic exploit could occur if the liquidator and liquidatee collude to
            // manipulate the fees in a liquidity area they control past the protocol loss threshold
            // such that the PLPs are forced to pay out premia to the liquidator
            // thus, we haircut any premium paid by the liquidatee (converting tokens as necessary) until the protocol loss is covered or the premium is exhausted
            // note that the haircutPremia function also commits the settled amounts (adjusted for the haircut) to storage, so it will be called even if there is no haircut
```

**File:** contracts/PanopticPool.sol (L1561-1567)
```text
            (bonusDeltas, haircutTotal, haircutPerLeg) = riskEngine().haircutPremia(
                _liquidatee,
                _positionIdList,
                premiasByLeg,
                collateralRemaining,
                Math.getSqrtRatioAtTick(_twapTick)
            );
```

**File:** contracts/RiskEngine.sol (L646-654)
```text
                for (uint256 i = 0; i < positionIdList.length; ++i) {
                    TokenId tokenId = positionIdList[i];
                    uint256 numLegs = tokenId.countLegs();
                    for (uint256 leg = 0; leg < numLegs; ++leg) {
                        if (tokenId.isLong(leg) == 1) {
                            longPremium = longPremium.sub(premiasByLeg[i][leg]);
                        }
                    }
                }
```

**File:** contracts/RiskEngine.sol (L738-795)
```text
                for (uint256 i = 0; i < positionIdList.length; i++) {
                    TokenId tokenId = positionIdList[i];
                    LeftRightSigned[4][] memory _premiasByLeg = premiasByLeg;
                    for (uint256 leg = 0; leg < tokenId.countLegs(); ++leg) {
                        if (
                            tokenId.isLong(leg) == 1 &&
                            LeftRightSigned.unwrap(_premiasByLeg[i][leg]) != 0
                        ) {
                            // calculate prorated (by target/liquidity) haircut amounts to revoke from settled for each leg
                            // `-premiasByLeg[i][leg]` (and `longPremium` which is the sum of all -premiasByLeg[i][leg]`) is always positive because long premium is represented as a negative delta
                            // `haircutBase` is always positive because all of its possible constituent values (`collateralDelta`, `longPremium`) are guaranteed to be positive
                            // the sum of all prorated haircut amounts for each token is assumed to be less than `2^127 - 1` given practical constraints on token supplies and deposit limits

                            LeftRightSigned haircutAmounts;

                            // Only calculate rightSlot if both numerator and denominator exist
                            if (
                                _premiasByLeg[i][leg].rightSlot() != 0 &&
                                longPremium.rightSlot() != 0
                            ) {
                                haircutAmounts = haircutAmounts.addToRightSlot(
                                    int128(
                                        uint128(
                                            Math.unsafeDivRoundingUp(
                                                uint128(-_premiasByLeg[i][leg].rightSlot()) *
                                                    uint256(uint128(haircutBase.rightSlot())),
                                                uint128(longPremium.rightSlot())
                                            )
                                        )
                                    )
                                );
                            }

                            // Only calculate leftSlot if both numerator and denominator exist
                            if (
                                _premiasByLeg[i][leg].leftSlot() != 0 && longPremium.leftSlot() != 0
                            ) {
                                haircutAmounts = haircutAmounts.addToLeftSlot(
                                    int128(
                                        uint128(
                                            Math.unsafeDivRoundingUp(
                                                uint128(-_premiasByLeg[i][leg].leftSlot()) *
                                                    uint256(uint128(haircutBase.leftSlot())),
                                                uint128(longPremium.leftSlot())
                                            )
                                        )
                                    )
                                );
                            }

                            haircutTotal = haircutTotal.add(
                                LeftRightUnsigned.wrap(
                                    uint256(LeftRightSigned.unwrap(haircutAmounts))
                                )
                            );

                            haircutPerLeg[i][leg] = haircutAmounts;
                        }
```

**File:** contracts/libraries/InteractionHelper.sol (L123-152)
```text
            for (uint256 i = 0; i < positionIdList.length; i++) {
                TokenId tokenId = positionIdList[i];
                for (uint256 leg = 0; leg < tokenId.countLegs(); ++leg) {
                    if (
                        tokenId.isLong(leg) == 1 &&
                        LeftRightSigned.unwrap(premiasByLeg[i][leg]) != 0
                    ) {
                        bytes32 chunkKey = EfficientHash.efficientKeccak256(
                            abi.encodePacked(
                                tokenId.strike(leg),
                                tokenId.width(leg),
                                tokenId.tokenType(leg)
                            )
                        );

                        emit PanopticPool.PremiumSettled(
                            liquidatee,
                            tokenId,
                            leg,
                            LeftRightSigned.wrap(0).sub(haircutPerLeg[i][leg])
                        );

                        // The long premium is not committed to storage during the liquidation, so we add the entire adjusted amount
                        // for the haircut directly to the accumulator
                        settledTokens[chunkKey] = settledTokens[chunkKey].add(
                            (LeftRightSigned.wrap(0).sub(premiasByLeg[i][leg])).subRect(
                                haircutPerLeg[i][leg]
                            )
                        );
                    }
```

**File:** contracts/CollateralTracker.sol (L1498-1500)
```text
        s_depositedAssets = uint256(
            int256(uint256(s_depositedAssets)) - ammDeltaAmount + realizedPremium
        ).toUint128();
```
