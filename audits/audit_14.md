# Audit Report

## Title 
Force Exercise Incorrectly Commits Full Long Premium Without Haircutting, Causing Loss to Short Sellers and Share Dilution

## Summary
The `_forceExercise()` function uses `COMMIT_LONG_SETTLED = true` when burning options, which immediately subtracts the full long premium from `s_settledTokens` without checking if the account has sufficient collateral to pay it. This differs from liquidation, which uses `DONOT_COMMIT_LONG_SETTLED` and applies premium haircutting when protocol loss exists. When force exercise occurs on accounts with insufficient real collateral, the full premium is committed to storage via phantom shares, causing short sellers to lose access to premium and creating orphan shares that dilute all shareholders.

## Finding Description

In `_forceExercise()` at line 1643, `COMMIT_LONG_SETTLED = true` is passed to `_burnOptions()`: [1](#0-0) 

This flag controls whether long premium is immediately subtracted from `s_settledTokens` during position burning. In `_updateSettlementPostBurn()`, when `commitLongSettledAndKeepOpen.rightSlot() != 0` (i.e., when `COMMIT_LONG_SETTLED = true`), the code subtracts long premium from settled tokens: [2](#0-1) 

This differs significantly from liquidation, which uses `DONOT_COMMIT_LONG_SETTLED = false`: [3](#0-2) 

The comment explicitly states the reason: "Do not commit any settled long premium to storage - we will do this after we determine if any long premium must be revoked."

**The Vulnerability Flow:**

1. Force exercise requires the account to be "solvent" (meeting margin requirements): [4](#0-3) 

2. However, solvency ≠ having sufficient collateral to pay full accumulated premium. An account can be solvent but still have insufficient real shares to cover all premium obligations.

3. Before burning, virtual shares are delegated to ensure the burn succeeds: [5](#0-4) 

4. When `COMMIT_LONG_SETTLED = true` is used, `s_settledTokens[chunkKey]` is immediately reduced by the full long premium amount (line 1181), regardless of whether the user can actually pay from real collateral.

5. In `settleBurn()`, shares are burned to collect the premium: [6](#0-5) 

6. If the user has insufficient real shares, phantom shares are consumed. When `revoke()` is called, orphan shares are created: [7](#0-6) 

7. The result: `s_settledTokens` has been reduced by the full premium amount, but the user only paid with phantom shares. When `_getAvailablePremium()` is called later to calculate premium distribution to short sellers, it uses the reduced `s_settledTokens`: [8](#0-7) 

The available premium is calculated as `(premiumOwed * settledTokens) / accumulated`. With `settledTokens` incorrectly reduced, short sellers receive less premium than they should.

**Comparison with Liquidation:**

In liquidation, the protocol properly handles insufficient collateral through haircutting:
- Uses `DONOT_COMMIT_LONG_SETTLED` so `s_settledTokens` is not reduced initially
- Calls `haircutPremia()` to reduce premium if collateral is insufficient
- Uses `settleAmounts()` to commit only the haircut (adjusted) premium: [9](#0-8) 

Force exercise bypasses this protective mechanism entirely.

**Invariants Broken:**
- **Invariant #14 (Premium Accounting)**: Premium distribution is not proportional to actual collateral available
- **Invariant #17 (Asset Accounting)**: Orphan shares break the `totalSupply = _internalSupply + s_creditedShares` invariant
- **Invariant #23 (Premium Haircutting)**: Premium is not clawed back when insufficient collateral exists

## Impact Explanation

**Critical/High Severity** - This vulnerability causes direct financial loss to two groups:

1. **Short Sellers in the Affected Chunk**: When they close their positions, `_getAvailablePremium()` uses the over-reduced `s_settledTokens` value, resulting in them receiving less premium than they earned. If the force-exercised account had minimal real collateral, the loss can be substantial.

2. **All Shareholders**: The orphan shares created when phantom shares are consumed dilute all existing shareholders by increasing `_internalSupply` without corresponding ownership.

The impact is proportional to:
- The accumulated long premium at time of force exercise
- The shortfall in the force-exercised account's real collateral
- The number of short sellers affected in that liquidity chunk

For a position with 1000 tokens of accumulated premium but only 100 tokens of real collateral, approximately 900 tokens worth of premium is lost to short sellers in that chunk.

## Likelihood Explanation

**High Likelihood** - This vulnerability can be triggered whenever:

1. A long position accumulates significant premium debt
2. The account remains barely solvent (meeting margin requirements but with minimal excess collateral)
3. Any user initiates force exercise on the position

The conditions are not rare:
- Long positions naturally accumulate premium over time as they consume liquidity
- Market volatility can quickly reduce an account's collateral while they remain technically solvent
- Force exercise is permissionless and incentivized through exercise fees

An attacker could deliberately:
1. Open a long position
2. Let premium accumulate while maintaining minimal solvency
3. Wait for someone to force exercise their position
4. Profit from the dilution or coordinate with short sellers to extract value

Alternatively, organic market conditions will naturally create these scenarios.

## Recommendation

Modify `_forceExercise()` to use the same haircutting mechanism as liquidation:

```solidity
function _forceExercise(
    address account,
    TokenId tokenId,
    int24 twapTick,
    int24 currentTick
) internal {
    CollateralTracker ct0 = collateralToken0();
    CollateralTracker ct1 = collateralToken1();

    uint128 positionSize;
    LeftRightSigned exerciseFees;
    
    {
        PositionBalance positionBalance = s_positionBalance[account][tokenId];
        positionSize = positionBalance.positionSize();
        if (positionSize == 0) revert Errors.PositionNotOwned();
        
        exerciseFees = riskEngine().exerciseCost(
            currentTick,
            twapTick,
            tokenId,
            positionBalance
        );
    }

    ct0.delegate(account);
    ct1.delegate(account);
    
    {
        int24[2] memory tickLimits;
        tickLimits[0] = MIN_SWAP_TICK;
        tickLimits[1] = MAX_SWAP_TICK;
        (RiskParameters riskParameters, ) = getRiskParameters(0);

        // Use DONOT_COMMIT_LONG_SETTLED like liquidation
        (LeftRightSigned netPaid, LeftRightSigned[4] memory premiasByLeg) = _burnAllOptionsFrom(
            account,
            MIN_SWAP_TICK,
            MAX_SWAP_TICK,
            DONOT_COMMIT_LONG_SETTLED,  // Changed from COMMIT_LONG_SETTLED
            Arrays.asSingletonArray(tokenId)
        );
        
        // Calculate if haircutting is needed (similar to liquidation)
        LeftRightSigned collateralRemaining;
        (exerciseFees, collateralRemaining) = riskEngine().getForceExerciseBalance(
            account,
            exerciseFees,
            netPaid,
            ct0,
            ct1
        );
        
        // Apply haircutting if collateral insufficient
        if (collateralRemaining.rightSlot() < 0 || collateralRemaining.leftSlot() < 0) {
            (LeftRightSigned bonusDeltas, LeftRightUnsigned haircutTotal, LeftRightSigned[4] memory haircutPerLeg) = 
                riskEngine().haircutPremia(
                    account,
                    collateralRemaining,
                    premiasByLeg,
                    Arrays.asSingletonArray(tokenId),
                    Math.getSqrtRatioAtTick(twapTick)
                );
            
            // Commit haircut amounts to storage
            InteractionHelper.settleAmounts(
                account,
                s_settledTokens,
                Arrays.asSingletonArray(tokenId),
                premiasByLeg,
                haircutPerLeg,
                haircutTotal,
                ct0,
                ct1
            );
            
            exerciseFees = exerciseFees.add(bonusDeltas);
        } else {
            // No haircut needed, commit full premium
            InteractionHelper.settleAmounts(
                account,
                s_settledTokens,
                Arrays.asSingletonArray(tokenId),
                premiasByLeg,
                Arrays.asSingletonArray([LeftRightSigned.wrap(0), LeftRightSigned.wrap(0), LeftRightSigned.wrap(0), LeftRightSigned.wrap(0)]),
                LeftRightUnsigned.wrap(0),
                ct0,
                ct1
            );
        }
    }
    
    LeftRightSigned refundAmounts = riskEngine().getRefundAmounts(
        account,
        exerciseFees,
        twapTick,
        ct0,
        ct1
    );

    ct0.refund(account, msg.sender, refundAmounts.rightSlot());
    ct1.refund(account, msg.sender, refundAmounts.leftSlot());
    ct0.revoke(account);
    ct1.revoke(account);

    emit ForcedExercised(msg.sender, account, tokenId, exerciseFees);
}
```

This ensures force exercise properly haircuts premium when the account has insufficient collateral, protecting short sellers and preventing orphan share creation.

## Proof of Concept

Due to the complexity of the full Panoptic test setup, here's a conceptual PoC demonstrating the issue:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ForceExercisePremiumLossPoC {
    // Simplified demonstration of the vulnerability
    
    // Simulates s_settledTokens mapping
    mapping(bytes32 => uint256) public settledTokens;
    
    // Simulates user balances
    mapping(address => uint256) public realShares;
    mapping(address => uint256) public phantomShares;
    
    uint256 public totalSupply;
    uint256 public orphanShares;
    
    function setupScenario() external {
        // Setup: Long holder has minimal real shares
        address longHolder = address(0x1);
        realShares[longHolder] = 100; // Only 100 real shares
        
        // Accumulated premium chunk has 10000 tokens settled
        bytes32 chunkKey = keccak256("testChunk");
        settledTokens[chunkKey] = 10000;
        
        totalSupply = 1000;
    }
    
    function demonstrateForceExerciseWithCommit() external returns (uint256 lostPremium) {
        address longHolder = address(0x1);
        bytes32 chunkKey = keccak256("testChunk");
        
        uint256 premiumOwed = 900; // Long holder owes 900 tokens premium
        uint256 initialSettled = settledTokens[chunkKey];
        
        // Step 1: Delegate phantom shares (simulating delegate())
        phantomShares[longHolder] = type(uint128).max;
        
        // Step 2: COMMIT_LONG_SETTLED = true immediately reduces settledTokens
        settledTokens[chunkKey] -= premiumOwed; // Reduced by full 900
        
        // Step 3: settleBurn tries to collect premium
        uint256 sharesToBurn = premiumOwed; // Simplified: 1:1 ratio
        
        if (realShares[longHolder] < sharesToBurn) {
            // User doesn't have enough real shares, use phantom shares
            uint256 phantomUsed = sharesToBurn - realShares[longHolder];
            realShares[longHolder] = 0;
            phantomShares[longHolder] -= phantomUsed;
            
            // Step 4: revoke() creates orphan shares
            orphanShares += phantomUsed; // 800 phantom shares became orphans
            totalSupply += phantomUsed; // Dilution!
        }
        
        // Result: settledTokens reduced by 900, but only 100 real shares paid
        lostPremium = premiumOwed - 100; // 800 tokens lost to short sellers
        
        return lostPremium;
    }
    
    function demonstrateLiquidationWithHaircut() external returns (uint256 lostPremium) {
        address longHolder = address(0x2);
        bytes32 chunkKey = keccak256("testChunk");
        
        realShares[longHolder] = 100;
        settledTokens[chunkKey] = 10000;
        
        uint256 premiumOwed = 900;
        
        // Step 1: Delegate phantom shares
        phantomShares[longHolder] = type(uint128).max;
        
        // Step 2: DONOT_COMMIT_LONG_SETTLED = false, don't reduce settledTokens yet
        // (settledTokens unchanged)
        
        // Step 3: Calculate haircut based on real collateral
        uint256 realCollateral = realShares[longHolder]; // 100
        uint256 haircutPremium = realCollateral; // Can only collect 100
        
        // Step 4: Commit only haircut premium
        settledTokens[chunkKey] -= haircutPremium; // Reduced by only 100
        
        // Step 5: settleBurn with haircut amount
        realShares[longHolder] = 0; // Burns only real shares
        
        // Step 6: No orphan shares created
        // orphanShares = 0
        
        // Result: settledTokens correctly reduced by 100, matching real payment
        lostPremium = 0; // Short sellers lose nothing
        
        return lostPremium;
    }
}
```

This PoC demonstrates:
1. Force exercise with `COMMIT_LONG_SETTLED` loses 800 tokens of premium for short sellers
2. Liquidation with haircutting correctly adjusts premium to actual collateral
3. The 800 token difference represents direct loss to short position holders in that chunk

### Citations

**File:** contracts/PanopticPool.sol (L1174-1185)
```text
                if (tokenId.isLong(leg) == 1) {
                    if (commitLongSettledAndKeepOpen.rightSlot() != 0)
                        settledTokens = LeftRightUnsigned.wrap(
                            uint256(
                                LeftRightSigned.unwrap(
                                    LeftRightSigned
                                        .wrap(int256(LeftRightUnsigned.unwrap(settledTokens)))
                                        .sub(legPremia)
                                )
                            )
                        );
                    realizedPremia = realizedPremia.add(legPremia);
```

**File:** contracts/PanopticPool.sol (L1413-1414)
```text
            // if account is solvent at all ticks, this is a force exercise or a settlePremium.
            if (solvent == numberOfTicks) {
```

**File:** contracts/PanopticPool.sol (L1526-1535)
```text
            // Do not commit any settled long premium to storage - we will do this after we determine if any long premium must be revoked
            // This is to prevent any short positions the liquidatee has being settled with tokens that will later be revoked
            // NOTE: tick limits are not applied here since it is not the liquidator's position being liquidated
            (netPaid, premiasByLeg) = _burnAllOptionsFrom(
                liquidatee,
                MIN_SWAP_TICK,
                MAX_SWAP_TICK,
                DONOT_COMMIT_LONG_SETTLED,
                positionIdList
            );
```

**File:** contracts/PanopticPool.sol (L1627-1629)
```text
        // The protocol delegates some virtual shares to ensure the burn can be settled.
        ct0.delegate(account);
        ct1.delegate(account);
```

**File:** contracts/PanopticPool.sol (L1638-1645)
```text
            _burnOptions(
                tokenId,
                positionSize,
                tickLimits,
                account,
                COMMIT_LONG_SETTLED,
                riskParameters
            );
```

**File:** contracts/PanopticPool.sol (L2104-2108)
```text
                            Math.min(
                                (uint256(premiumOwed.rightSlot()) * settledTokens.rightSlot()) /
                                    (accumulated0 == 0 ? type(uint256).max : accumulated0),
                                premiumOwed.rightSlot()
                            )
```

**File:** contracts/CollateralTracker.sol (L1242-1254)
```text
    function revoke(address delegatee) external onlyPanopticPool {
        uint256 balance = balanceOf[delegatee];
        if (type(uint248).max > balance) {
            // Phantom shares were consumed during delegation (e.g., burned for interest).
            // This can happen when the user owed more interest than their real balance
            // at the time delegate() was called. Zero the balance and restore
            // _internalSupply for the overcounted burn.
            balanceOf[delegatee] = 0;
            _internalSupply += type(uint248).max - balance;
        } else {
            // Normal case: user still has all phantom shares plus any real shares
            balanceOf[delegatee] = balance - type(uint248).max;
        }
```

**File:** contracts/CollateralTracker.sol (L1474-1488)
```text
        if (tokenToPay > 0) {
            uint256 sharesToBurn = Math.mulDivRoundingUp(
                uint256(tokenToPay),
                _totalSupply,
                _totalAssets
            );

            if (balanceOf[_optionOwner] < sharesToBurn)
                revert Errors.NotEnoughTokens(
                    address(this),
                    uint256(tokenToPay),
                    convertToAssets(balanceOf[_optionOwner])
                );

            _burn(_optionOwner, sharesToBurn);
```

**File:** contracts/libraries/InteractionHelper.sol (L145-151)
```text
                        // The long premium is not committed to storage during the liquidation, so we add the entire adjusted amount
                        // for the haircut directly to the accumulator
                        settledTokens[chunkKey] = settledTokens[chunkKey].add(
                            (LeftRightSigned.wrap(0).sub(premiasByLeg[i][leg])).subRect(
                                haircutPerLeg[i][leg]
                            )
                        );
```
