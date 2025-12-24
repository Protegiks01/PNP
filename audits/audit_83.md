# Audit Report

## Title 
Share Loss Vulnerability in `revoke()` Function Due to Incorrect Virtual Share Accounting When Minting During Delegation

## Summary
The `revoke()` function in `CollateralTracker.sol` incorrectly subtracts the full `type(uint248).max` from the delegatee's balance, even when `delegate()` added fewer virtual shares due to `balanceConsumedByInterest` being non-zero. This causes users to lose real shares equal to `balanceConsumedByInterest` when new shares are minted during the delegation period. [1](#0-0) [2](#0-1) 

## Finding Description

The vulnerability stems from an accounting mismatch between the `delegate()` and `revoke()` functions in the virtual share delegation mechanism.

**In `delegate()` function:**
When a user owes more interest than their current balance, the function calculates `balanceConsumedByInterest` to reduce the virtual shares granted, preventing virtual shares from being used for interest payment. The function adds `type(uint248).max - balanceConsumedByInterest` to the user's balance.

**In `revoke()` function (else branch):**
When `balance >= type(uint248).max`, the function unconditionally subtracts the full `type(uint248).max`, without accounting for the fact that only `type(uint248).max - balanceConsumedByInterest` virtual shares were actually added.

**The Issue:**
If new shares are minted to the delegatee during the delegation period (which occurs during liquidations with negative bonus via `settleLiquidation`), the user ends up losing exactly `balanceConsumedByInterest` amount of shares. [3](#0-2) 

**Attack Scenario:**
1. Liquidatee has 100 shares and owes 150 shares worth of interest
2. `delegate()` is called: `balanceConsumedByInterest = 100`, so `balanceOf[liquidatee] = 100 + type(uint248).max - 100 = type(uint248).max`
3. During liquidation, 100 shares are burned for interest: `balanceOf[liquidatee] = type(uint248).max - 100`
4. Liquidation settlement mints 200 shares as compensation (negative bonus): `balanceOf[liquidatee] = type(uint248).max + 100`
5. `revoke()` is called: `balanceOf[liquidatee] = type(uint248).max + 100 - type(uint248).max = 100`

**Expected Result:** User should have 100 (original) - 100 (interest) + 200 (minted) = 200 shares
**Actual Result:** User has 100 shares
**Loss:** 100 shares (equal to `balanceConsumedByInterest`)

This breaks **Invariant #2 (Collateral Conservation)** as the lost shares remain in `_internalSupply` but aren't assigned to any user, and **Invariant #17 (Asset Accounting)** as the share accounting becomes inconsistent. [4](#0-3) 

## Impact Explanation

**Severity: High**

This vulnerability causes direct loss of funds for users being liquidated or force-exercised when:
1. They owe significant interest relative to their balance
2. The liquidation/force exercise results in shares being minted to them (negative bonus scenarios)

The impact is:
- **Direct financial loss** to liquidatees equal to `balanceConsumedByInterest`, which can be up to their entire original balance
- **Broken liquidation economics** - users who should receive compensation lose part of it
- **Redistribution to other LPs** - the lost shares effectively increase share price for remaining liquidity providers, creating an unfair wealth transfer
- **Systematic exploitation potential** - attackers holding LP shares can profit by triggering liquidations on accounts with high `balanceConsumedByInterest`

The loss amount scales with the user's debt relative to their collateral - in extreme cases where a user owes far more than their balance, they could lose substantial portions of any compensation they should receive during liquidation.

## Likelihood Explanation

**Likelihood: Medium-High**

This vulnerability will occur in normal protocol operation under the following conditions:
1. **Common scenario**: Users with outstanding interest debt (which accumulates naturally over time)
2. **Liquidations with negative bonus**: Occurs when the liquidatee's position has sufficient value that they deserve compensation
3. **No special attacker setup required**: Happens as part of the standard delegate→burn/mint→revoke flow

The likelihood is elevated because:
- Interest debt naturally accumulates for all option sellers
- Users often have positions when they're close to liquidation thresholds
- Liquidations are routine protocol operations
- No special market conditions or oracle manipulation needed

Any liquidation where `interestShares > balance` at delegation time AND shares are minted during the process will trigger this loss.

## Recommendation

The `revoke()` function should subtract the actual amount of virtual shares that were added by `delegate()`, not the full `type(uint248).max`.

**Solution 1: Store the delegated amount**
Modify `delegate()` to store the actual virtual shares added in a mapping, then use that in `revoke()`:

```solidity
mapping(address => uint256) private s_delegatedShares;

function delegate(address delegatee) external onlyPanopticPool {
    uint256 interestShares = previewWithdraw(_owedInterest(delegatee));
    uint256 balance = balanceOf[delegatee];
    uint256 balanceConsumedByInterest = interestShares > balance ? balance : 0;
    
    uint256 virtualSharesAdded = type(uint248).max - balanceConsumedByInterest;
    s_delegatedShares[delegatee] = virtualSharesAdded;
    balanceOf[delegatee] += virtualSharesAdded;
}

function revoke(address delegatee) external onlyPanopticPool {
    uint256 balance = balanceOf[delegatee];
    uint256 virtualShares = s_delegatedShares[delegatee];
    delete s_delegatedShares[delegatee];
    
    if (virtualShares > balance) {
        balanceOf[delegatee] = 0;
        _internalSupply += virtualShares - balance;
    } else {
        balanceOf[delegatee] = balance - virtualShares;
    }
}
```

**Solution 2: Recalculate in revoke()**
Alternatively, recalculate the expected virtual shares in `revoke()` by checking if the balance indicates phantom share consumption occurred as expected.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "contracts/CollateralTracker.sol";
import {PanopticPool} from "contracts/PanopticPool.sol";

contract CollateralTrackerDelegateRevokeTest is Test {
    CollateralTracker collateralTracker;
    address panopticPool;
    address liquidatee;
    
    function setUp() public {
        // Deploy mock PanopticPool
        panopticPool = address(new MockPanopticPool());
        liquidatee = makeAddr("liquidatee");
        
        // Deploy and initialize CollateralTracker
        // Note: This is a simplified setup - actual deployment requires proper initialization
        collateralTracker = new CollateralTracker(100); // 100 bps commission
        
        // Setup initial state
        vm.startPrank(panopticPool);
        // Simulate liquidatee having 100 shares and owing 150 in interest
        // This would require proper setup with positions and interest accrual
    }
    
    function testShareLossDuringDelegationWithMinting() public {
        vm.startPrank(panopticPool);
        
        // Scenario: Liquidatee has 100 shares, owes 150 interest
        // 1. Initial balance: 100 shares
        uint256 initialBalance = 100e18;
        
        // Simulate initial balance (would normally come from deposit)
        // collateralTracker._mint(liquidatee, initialBalance);
        
        // 2. delegate() is called
        // With interestShares (150) > balance (100), balanceConsumedByInterest = 100
        // Virtual shares added = type(uint248).max - 100
        collateralTracker.delegate(liquidatee);
        
        uint256 balanceAfterDelegate = collateralTracker.balanceOf(liquidatee);
        // Should be type(uint248).max (approximately, accounting for the 100 consumed)
        
        // 3. During liquidation, 100 shares burned for interest
        // collateralTracker._burn(liquidatee, 100e18);
        
        // 4. 200 shares minted as liquidation compensation
        // collateralTracker._mint(liquidatee, 200e18);
        
        uint256 balanceBeforeRevoke = collateralTracker.balanceOf(liquidatee);
        
        // 5. revoke() is called
        collateralTracker.revoke(liquidatee);
        
        uint256 finalBalance = collateralTracker.balanceOf(liquidatee);
        
        // Expected: 100 - 100 + 200 = 200 shares
        // Actual: Will be 100 shares (loss of 100)
        
        // Assert the vulnerability
        uint256 expectedBalance = 200e18;
        assertEq(finalBalance, expectedBalance, "User lost shares due to incorrect revoke logic");
        
        vm.stopPrank();
    }
}

contract MockPanopticPool {
    // Minimal mock for testing
}
```

**Note:** The actual PoC would require full protocol setup with positions, interest accrual, and liquidation flow. The above demonstrates the logical flow of the vulnerability. A complete integration test would involve:
1. Deploying full Panoptic infrastructure
2. Creating positions that accrue interest
3. Triggering liquidation with negative bonus
4. Verifying the share loss matches `balanceConsumedByInterest`

## Notes

This vulnerability is particularly insidious because:
1. It only manifests when shares are minted during delegation (not just burned)
2. The lost shares are "silent" - they remain in `_internalSupply` but aren't assigned to anyone
3. It disproportionately affects users in financial distress (those with high debt ratios)
4. The loss is precisely calculable: always equals `balanceConsumedByInterest`
5. It breaks the intended protection mechanism that was designed to prevent virtual shares from being used for interest

The fix requires careful consideration of the delegation/revocation accounting to ensure virtual shares added equals virtual shares removed, regardless of what operations occur during the delegation period.

### Citations

**File:** contracts/CollateralTracker.sol (L1221-1233)
```text
    function delegate(address delegatee) external onlyPanopticPool {
        // Round up to match _accrueInterest's share calculation
        uint256 interestShares = previewWithdraw(_owedInterest(delegatee));
        uint256 balance = balanceOf[delegatee];

        // If user owes more interest than they have, their entire balance will be consumed
        // paying interest. Reduce delegation by this amount so virtual shares aren't used
        // for interest payment.
        uint256 balanceConsumedByInterest = interestShares > balance ? balance : 0;

        // keep checked to catch overflows
        balanceOf[delegatee] += type(uint248).max - balanceConsumedByInterest;
    }
```

**File:** contracts/CollateralTracker.sol (L1242-1255)
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
    }
```

**File:** contracts/CollateralTracker.sol (L1262-1309)
```text
    function settleLiquidation(
        address liquidator,
        address liquidatee,
        int256 bonus
    ) external payable onlyPanopticPool {
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

            s_depositedAssets += uint128(bonusAbs);

            uint256 liquidateeBalance = balanceOf[liquidatee];

            if (type(uint248).max > liquidateeBalance) {
                balanceOf[liquidatee] = 0;
                // keep checked to catch under/overflows
                _internalSupply += type(uint248).max - liquidateeBalance;
            } else {
                // keep checked to catch under/overflows
                balanceOf[liquidatee] = liquidateeBalance - type(uint248).max;
            }
            if (_poolManager != address(0)) {
                _settleCurrencyDelta(liquidator, int256(bonusAbs));
            }
        } else {
```

**File:** contracts/PanopticPool.sol (L1515-1590)
```text
        // The protocol delegates some virtual shares to ensure the burn can be settled.
        collateralToken0().delegate(liquidatee);
        collateralToken1().delegate(liquidatee);

        LeftRightSigned bonusAmounts;
        LeftRightUnsigned haircutTotal;
        {
            LeftRightSigned netPaid;
            LeftRightSigned[4][] memory premiasByLeg;
            // burn all options from the liquidatee

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

            LeftRightSigned collateralRemaining;

            // compute bonus amounts using latest tick data
            (bonusAmounts, collateralRemaining) = riskEngine().getLiquidationBonus(
                tokenData0,
                tokenData1,
                Math.getSqrtRatioAtTick(twapTick),
                netPaid,
                shortPremium
            );

            // premia cannot be paid if there is protocol loss associated with the liquidatee
            // otherwise, an economic exploit could occur if the liquidator and liquidatee collude to
            // manipulate the fees in a liquidity area they control past the protocol loss threshold
            // such that the PLPs are forced to pay out premia to the liquidator
            // thus, we haircut any premium paid by the liquidatee (converting tokens as necessary) until the protocol loss is covered or the premium is exhausted
            // note that the haircutPremia function also commits the settled amounts (adjusted for the haircut) to storage, so it will be called even if there is no haircut

            // if premium is haircut from a token that is not in protocol loss, some of the liquidation bonus will be converted into that token
            address _liquidatee = liquidatee;
            int24 _twapTick = twapTick;
            TokenId[] memory _positionIdList = positionIdList;
            LeftRightSigned bonusDeltas;
            LeftRightSigned[4][] memory haircutPerLeg;
            (bonusDeltas, haircutTotal, haircutPerLeg) = riskEngine().haircutPremia(
                _liquidatee,
                _positionIdList,
                premiasByLeg,
                collateralRemaining,
                Math.getSqrtRatioAtTick(_twapTick)
            );

            bonusAmounts = bonusAmounts.add(bonusDeltas);

            InteractionHelper.settleAmounts(
                _liquidatee,
                _positionIdList,
                haircutTotal,
                haircutPerLeg,
                premiasByLeg,
                collateralToken0(),
                collateralToken1(),
                s_settledTokens
            );
        }

        // revoke delegated virtual shares and settle any bonus deltas with the liquidator
        // native currency is represented as address(0), so it will always be currency0 alphanumerically
        collateralToken0().settleLiquidation{value: msg.value}(
            msg.sender,
            liquidatee,
            bonusAmounts.rightSlot()
        );
        collateralToken1().settleLiquidation(msg.sender, liquidatee, bonusAmounts.leftSlot());
```
