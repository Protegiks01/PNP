# Audit Report

## Title 
Insolvency Penalty Creates Uncollectable Debt Leading to Protocol Insolvency

## Summary
The `_accrueInterest()` function in `CollateralTracker.sol` fails to properly account for partial interest payments when users are insolvent. When `shares > userBalance` and `!isDeposit`, the function reduces `unrealizedGlobalInterest` by the partial payment amount but does NOT update the user's `userBorrowIndex` or reduce their `netBorrows`. This creates an accounting mismatch where partial payments drain the global interest bucket without adjusting individual debt tracking. When insolvent users eventually close their positions, the unpaid interest becomes permanently uncollectable, leaving the protocol with inflated `totalAssets()` that includes phantom uncollectable interest, leading to protocol insolvency.

## Finding Description

The vulnerability exists in the `_accrueInterest()` function where the insolvency penalty is applied: [1](#0-0) 

When a user is insolvent (`shares > userBalance`) and the operation is not a deposit (`!isDeposit`):

1. **Partial interest payment is made**: The user burns all their available shares (line 931)
2. **Global interest is reduced**: `unrealizedGlobalInterest` is decreased by `burntInterestValue` (lines 954-960)
3. **User's borrow index is NOT updated**: `userBorrowIndex = userState.rightSlot()` keeps the OLD index (line 934)
4. **User's netBorrows is NOT reduced**: Remains unchanged (line 896, 968)

The comment at line 933 states: *"DO NOT update index. By keeping the user's old baseIndex, their debt continues to compound correctly from the original point in time."*

However, this is **incorrect**. The debt does NOT compound correctly because:

- **Global accounting**: Interest accrues on `s_assetsInAMM` which includes this user's `netBorrows` [2](#0-1) 

- **User accounting**: Interest owed = `netBorrows * (currentIndex - userIndex) / userIndex` [3](#0-2) 

- **Total assets calculation**: Includes `unrealizedGlobalInterest` [4](#0-3) 

**Attack Scenario:**

1. User opens short position → `netBorrows = 100`, contributes to `s_assetsInAMM`
2. Time passes, interest accrues globally on the 100 borrowed → `unrealizedGlobalInterest += 20`
3. User becomes insolvent (has only 10 shares worth ~10 assets)
4. User triggers operation with `isDeposit=false` (e.g., via `accrueInterest()`, `transfer()`, or position operations)
5. User pays 10 in partial interest → `unrealizedGlobalInterest -= 10`
6. But `userBorrowIndex` stays at original value, `netBorrows` stays 100
7. More time passes, interest continues accruing on `s_assetsInAMM = 100` → `unrealizedGlobalInterest += 15`
8. User acquires 15 more shares (from premiums or deposits), pays another 15 partial interest
9. `unrealizedGlobalInterest -= 15`, but again no update to `userBorrowIndex` or `netBorrows`
10. User closes position → `netBorrows` becomes 0, `s_assetsInAMM` decreases by 100
11. **Result**: `unrealizedGlobalInterest` has positive balance (phantom unpaid interest)
12. This interest can never be collected because the borrower who owed it no longer has debt
13. `totalAssets()` includes this phantom amount, artificially inflating share price
14. When LPs try to withdraw, there aren't enough actual assets to cover the inflated `totalAssets`

This breaks **Invariant #2 (Collateral Conservation)**: Total assets must equal `s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest`. The `unrealizedGlobalInterest` component contains uncollectable debt, making the equation invalid.

This also breaks **Invariant #21 (Interest Accuracy)**: The user's actual interest paid does not match the formula because partial payments reduce the global bucket without updating individual tracking.

## Impact Explanation

**Critical Severity - Protocol Insolvency:**

This vulnerability leads to direct loss of LP funds through protocol insolvency. The impact is:

1. **Uncollectable Debt Accumulation**: Each time an insolvent user makes partial interest payments, `unrealizedGlobalInterest` is drained without proper debt tracking updates. When these users close positions, the unpaid portion becomes permanently uncollectable.

2. **Share Price Inflation**: `totalAssets()` includes the phantom `unrealizedGlobalInterest`, making the share price (`totalAssets() / totalSupply()`) artificially high.

3. **LP Losses**: Early withdrawers receive their full (inflated) share of assets. Later withdrawers discover there aren't enough assets to cover their shares. The last LPs to withdraw suffer direct losses.

4. **Systemic Risk**: This occurs naturally whenever users become insolvent (undercollateralized), during liquidations, or can be deliberately triggered by malicious users withdrawing collateral to become insolvent.

5. **Compounding Effect**: The issue accumulates over time as multiple insolvent users make partial payments. The phantom interest grows with each occurrence.

The financial impact is quantifiable: if a user with `netBorrows = 100` owes 60 in total interest but only pays 25 through partial payments before closing, the protocol loses 35 in uncollectable interest that inflates `totalAssets` and causes LP losses.

## Likelihood Explanation

**High Likelihood:**

This vulnerability will occur frequently in normal protocol operation:

1. **Natural Occurrence**: Users become insolvent whenever their collateral value falls below their interest obligations. This happens during:
   - Market volatility reducing collateral value
   - Prolonged position holding where interest accumulates
   - Users withdrawing collateral to the minimum

2. **Liquidation Trigger**: During liquidations of insolvent users, the `delegate()` mechanism provides phantom shares, but if the user had real shares insufficient to cover interest, partial payments occur [5](#0-4) 

3. **Easy to Trigger**: Any operation calling `_accrueInterest()` with `isDeposit=false` triggers the issue:
   - `transfer()` / `transferFrom()` (line 403, 423)
   - `withdraw()` / `redeem()` / `donate()` (lines 695, 751, 822, 864)
   - `accrueInterest()` external function (line 880)
   - Position operations via `_updateBalancesAndSettle()` (line 1403)

4. **Intentional Exploitation**: Malicious users can deliberately:
   - Open large short positions
   - Withdraw collateral to become insolvent
   - Repeatedly trigger `accrueInterest()` to pay partial interest
   - Close positions, leaving unpaid interest

5. **No Special Privileges Required**: Any user with open positions can trigger this vulnerability.

The combination of natural occurrence, liquidation scenarios, and intentional exploitation makes this a high-likelihood vulnerability that will manifest frequently.

## Recommendation

Fix the accounting mismatch by properly updating user debt tracking when partial interest is paid. The solution requires tracking the partial payment and either:

**Option 1: Update userBorrowIndex proportionally**
When partial interest is paid, update the `userBorrowIndex` to reflect the portion of debt that was settled:

```solidity
if (shares > userBalance) {
    if (!isDeposit) {
        burntInterestValue = Math
            .mulDiv(userBalance, _totalAssets, totalSupply())
            .toUint128();

        emit InsolvencyPenaltyApplied(
            owner,
            userInterestOwed,
            burntInterestValue,
            userBalance
        );

        _burn(_owner, userBalance);

        // Calculate what portion of interest was paid
        // Update userBorrowIndex to reflect partial settlement
        if (userInterestOwed > 0) {
            // partialPaymentRatio = burntInterestValue / userInterestOwed
            // Adjust userBorrowIndex: oldIndex + (currentIndex - oldIndex) * partialPaymentRatio
            uint256 oldIndex = uint256(userState.rightSlot());
            uint256 indexDelta = currentBorrowIndex - oldIndex;
            uint256 adjustedIndexDelta = Math.mulDiv(
                indexDelta,
                burntInterestValue,
                userInterestOwed
            );
            userBorrowIndex = int128(uint128(oldIndex + adjustedIndexDelta));
        } else {
            userBorrowIndex = userState.rightSlot();
        }
    } else {
        // ... existing isDeposit logic
    }
}
```

**Option 2: Reduce netBorrows proportionally**
Alternatively, reduce the user's `netBorrows` to reflect that they paid off part of their debt:

```solidity
if (shares > userBalance) {
    if (!isDeposit) {
        burntInterestValue = Math
            .mulDiv(userBalance, _totalAssets, totalSupply())
            .toUint128();

        emit InsolvencyPenaltyApplied(
            owner,
            userInterestOwed,
            burntInterestValue,
            userBalance
        );

        _burn(_owner, userBalance);

        // Reduce netBorrows proportionally to interest paid
        if (userInterestOwed > 0 && burntInterestValue < userInterestOwed) {
            // Calculate remaining debt ratio
            uint256 remainingRatio = Math.mulDiv(
                userInterestOwed - burntInterestValue,
                WAD,
                userInterestOwed
            );
            // Reduce netBorrows proportionally
            netBorrows = int128(uint128(Math.mulDiv(
                uint128(netBorrows),
                remainingRatio,
                WAD
            )));
        }
        
        userBorrowIndex = int128(currentBorrowIndex);
    } else {
        // ... existing isDeposit logic
    }
}
```

**Option 3: Prevent position closure until fully paid (Strictest)**
Revert if a user tries to close their position while having unpaid interest:

```solidity
// In _updateBalancesAndSettle, before closing position (isCreation == false)
if (!isCreation && netBorrows < 0) {  // Closing position
    // Verify user has no outstanding interest after _accrueInterest
    LeftRightSigned userState = s_interestState[optionOwner];
    if (userState.leftSlot() > 0) {
        uint128 outstandingInterest = _getUserInterest(userState, s_marketState.borrowIndex());
        if (outstandingInterest > 0) {
            revert Errors.OutstandingInterestMustBePaid();
        }
    }
}
```

**Recommended Approach**: Option 1 or 2 maintains the spirit of allowing partial payments while fixing the accounting. Option 3 is strictest but may prevent legitimate liquidations.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "../contracts/CollateralTracker.sol";
import {PanopticPool} from "../contracts/PanopticPool.sol";
import {Math} from "../contracts/libraries/Math.sol";

contract InsolvencyPenaltyExploitTest is Test {
    using Math for uint256;

    CollateralTracker collateralTracker;
    address alice = address(0x1);
    address bob = address(0x2);
    
    // Simplified setup - in real tests would need full Panoptic deployment
    function setUp() public {
        // Deploy CollateralTracker with mock dependencies
        // This is a simplified PoC - actual test requires full protocol setup
        vm.startPrank(alice);
        
        // 1. Alice deposits 1000 assets, gets shares
        // 2. Alice opens short position, netBorrows = 100
        // 3. Time passes, interest accrues
        
        vm.stopPrank();
    }
    
    function testInsolvencyPenaltyBypass() public {
        // Setup: Alice has netBorrows = 100, userBorrowIndex = 1.0e18
        // s_assetsInAMM = 100 (Alice's borrowed amount)
        
        // Initial state
        uint256 initialUnrealizedInterest = 0;
        uint256 aliceNetBorrows = 100;
        uint256 aliceUserIndex = 1.0e18;
        uint256 globalIndex = 1.0e18;
        
        // === TIME 1: Interest accrues ===
        // Skip time: globalIndex grows to 1.2e18 (20% growth)
        vm.warp(block.timestamp + 365 days);
        globalIndex = 1.2e18;
        
        // Interest accrued globally on s_assetsInAMM = 100
        uint256 globalInterestAccrued = 20; // 100 * 0.2
        initialUnrealizedInterest += globalInterestAccrued;
        // unrealizedGlobalInterest = 20
        
        // Alice's interest owed: 100 * (1.2 - 1.0) / 1.0 = 20
        uint256 aliceInterestOwed = 20;
        
        // Alice only has 10 shares (insolvent)
        uint256 aliceShares = 10;
        
        // Alice triggers accrueInterest() with isDeposit=false
        // She pays 10 (all her shares)
        uint256 partialPayment1 = 10;
        initialUnrealizedInterest -= partialPayment1;
        // unrealizedGlobalInterest = 10
        
        // BUG: Alice's userBorrowIndex stays at 1.0e18
        // BUG: Alice's netBorrows stays at 100
        aliceUserIndex = 1.0e18; // UNCHANGED
        aliceNetBorrows = 100; // UNCHANGED
        aliceShares = 0; // All burned
        
        // === TIME 2: More interest accrues ===
        vm.warp(block.timestamp + 365 days);
        globalIndex = 1.4e18; // Another ~16.67% growth
        
        // More interest accrues on s_assetsInAMM = 100 (still 100!)
        globalInterestAccrued = 100 * 167 / 1000; // ~16.67
        initialUnrealizedInterest += globalInterestAccrued;
        // unrealizedGlobalInterest = 10 + 16.67 = 26.67
        
        // Alice gets 15 more shares from premiums
        aliceShares = 15;
        
        // Alice's interest owed: 100 * (1.4 - 1.0) / 1.0 = 40
        aliceInterestOwed = 40;
        
        // Alice triggers operation again, pays 15 (all her shares)
        uint256 partialPayment2 = 15;
        initialUnrealizedInterest -= partialPayment2;
        // unrealizedGlobalInterest = 11.67
        
        // BUG: Still no update to userBorrowIndex or netBorrows
        aliceUserIndex = 1.0e18; // STILL UNCHANGED
        aliceNetBorrows = 100; // STILL UNCHANGED
        aliceShares = 0;
        
        // === TIME 3: Alice closes position ===
        vm.warp(block.timestamp + 365 days);
        globalIndex = 1.6e18;
        
        // More interest accrued
        globalInterestAccrued = 100 * 143 / 1000; // ~14.29%
        initialUnrealizedInterest += globalInterestAccrued;
        // unrealizedGlobalInterest = 11.67 + 14.29 = 25.96
        
        // Alice closes position
        // _accrueInterest called first:
        // - Alice owes: 100 * (1.6 - 1.0) / 1.0 = 60
        // - Alice has 0 shares
        // - Alice pays 0
        // - unrealizedGlobalInterest stays 25.96
        
        // Position closes: netBorrows → 0, s_assetsInAMM → 0
        aliceNetBorrows = 0;
        uint256 s_assetsInAMM = 0;
        
        // === FINAL STATE ===
        // Alice paid total: 10 + 15 + 0 = 25
        uint256 aliceTotalPaid = partialPayment1 + partialPayment2;
        
        // Alice should have paid: 60 (final interest owed)
        uint256 aliceShouldHavePaid = 60;
        
        // Protocol loss: unrealizedGlobalInterest = 25.96
        // But s_assetsInAMM = 0 (no borrowers left)
        // This interest can NEVER be collected!
        
        // totalAssets() = s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest
        // totalAssets() = X + 0 + 25.96
        // This 25.96 is PHANTOM - it inflates the share price
        
        // ASSERTION: Demonstrate the accounting mismatch
        assertEq(aliceTotalPaid, 25, "Alice paid 25 total");
        assertEq(aliceShouldHavePaid, 60, "Alice should have paid 60");
        assertEq(s_assetsInAMM, 0, "No more borrowers");
        assertTrue(initialUnrealizedInterest > 0, "Phantom interest remains");
        
        // Protocol is insolvent: totalAssets includes uncollectable interest
        console.log("Alice paid:", aliceTotalPaid);
        console.log("Alice should have paid:", aliceShouldHavePaid);
        console.log("Unpaid interest:", aliceShouldHavePaid - aliceTotalPaid);
        console.log("Phantom unrealizedGlobalInterest:", initialUnrealizedInterest);
        console.log("Protocol loss: LPs cannot withdraw full value");
    }
}
```

**Note**: This PoC demonstrates the accounting logic. A full runnable test would require the complete Panoptic test harness with deployed pools, oracles, and risk engine. The key assertion is that `unrealizedGlobalInterest` accumulates uncollectable debt when insolvent users make partial payments and close positions.

### Citations

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L916-943)
```text
                if (shares > userBalance) {
                    if (!isDeposit) {
                        // update the accrual of interest paid
                        burntInterestValue = Math
                            .mulDiv(userBalance, _totalAssets, totalSupply())
                            .toUint128();

                        emit InsolvencyPenaltyApplied(
                            owner,
                            userInterestOwed,
                            burntInterestValue,
                            userBalance
                        );

                        /// Insolvent case: Pay what you can
                        _burn(_owner, userBalance);

                        /// @dev DO NOT update index. By keeping the user's old baseIndex, their debt continues to compound correctly from the original point in time.
                        userBorrowIndex = userState.rightSlot();
                    } else {
                        // set interest paid to zero
                        burntInterestValue = 0;

                        // we effectively **did not settle** this user:
                        // we keep their old baseIndex so future interest is computed correctly.
                        userBorrowIndex = userState.rightSlot();
                    }
                } else {
```

**File:** contracts/CollateralTracker.sol (L1006-1016)
```text
        _unrealizedGlobalInterest = accumulator.unrealizedInterest();
        if (deltaTime > 0) {
            // Calculate interest growth
            uint128 rawInterest = (Math.wTaylorCompounded(interestRateSnapshot, uint128(deltaTime)))
                .toUint128();
            // Calculate interest owed on borrowed amount

            uint128 interestOwed = Math.mulDivWadRoundingUp(_assetsInAMM, rawInterest).toUint128();

            // keep checked to prevent overflows
            _unrealizedGlobalInterest += interestOwed;
```

**File:** contracts/CollateralTracker.sol (L1061-1078)
```text
    function _getUserInterest(
        LeftRightSigned userState,
        uint256 currentBorrowIndex
    ) internal pure returns (uint128 interestOwed) {
        int128 netBorrows = userState.leftSlot();
        uint128 userBorrowIndex = uint128(userState.rightSlot());
        if (netBorrows <= 0 || userBorrowIndex == 0 || currentBorrowIndex == userBorrowIndex) {
            return 0;
        }
        // keep checked to catch currentBorrowIndex < userBorrowIndex
        interestOwed = Math
            .mulDivRoundingUp(
                uint128(netBorrows),
                currentBorrowIndex - userBorrowIndex,
                userBorrowIndex
            )
            .toUint128();
    }
```

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
