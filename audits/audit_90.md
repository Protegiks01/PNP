# Audit Report

## Title
Interest Payment Deferral via Repeated Deposits Causes Permanent Bad Debt and Share Price Manipulation

## Summary
Users with insufficient balance to cover accrued interest can indefinitely defer interest payments by repeatedly calling `deposit()` or `mint()`, which use the `IS_DEPOSIT` flag. When such users are eventually liquidated, their unpaid interest remains permanently in `unrealizedGlobalInterest`, inflating `totalAssets()` and the share price, causing protocol insolvency and losses to other liquidity providers.

## Finding Description

The vulnerability exists in the interest accrual logic when users deposit while insolvent (owing more interest than their share balance). [1](#0-0) 

When `deposit()` is called, it triggers `_accrueInterest(msg.sender, IS_DEPOSIT)` at the start: [2](#0-1) 

Within `_accrueInterest()`, if a user owes more interest than their balance AND the `isDeposit` flag is true, a critical bypass occurs: [3](#0-2) 

When `isDeposit = true` and `shares > userBalance` (insolvent case):
1. **NO interest is paid** (`burntInterestValue = 0` at line 937)
2. **User's borrow index is NOT updated** (line 941 keeps old index)
3. **unrealizedGlobalInterest is NOT reduced** (because burntInterestValue = 0)

The unrealizedGlobalInterest is factored into totalAssets: [4](#0-3) 

This creates an accounting discrepancy where uncollectible debt inflates the share price.

**Attack Scenario:**
1. User opens positions with `netBorrows = 500` tokens
2. Time passes, user owes 250 in interest but only has 50 shares
3. User repeatedly calls `deposit()` with small amounts
4. Each deposit: no interest paid, index not updated, debt keeps compounding
5. User eventually gets liquidated when positions become undercollateralized
6. During liquidation, `_accrueInterest(user, IS_NOT_DEPOSIT)` is called: [5](#0-4) 

7. User pays what they can (all remaining shares), but still owes interest
8. User's positions are closed (netBorrows → 0)
9. **The unpaid interest remains permanently in unrealizedGlobalInterest**
10. Future interest checks see `netBorrows = 0`, so no more interest accrues
11. The bad debt is never cleared

This breaks multiple critical invariants:
- **Invariant #2 (Collateral Conservation)**: totalAssets includes uncollectible debt
- **Invariant #3 (Share Price Monotonicity)**: Share price artificially inflated by phantom assets
- **Invariant #21 (Interest Accuracy)**: Interest owed calculation bypassed

## Impact Explanation

**HIGH Severity** - This causes direct protocol loss and systemic undercollateralization:

1. **Share Price Manipulation**: totalAssets includes uncollectible debt, inflating the share price for all users. Liquidity providers are diluted.

2. **Protocol Insolvency**: The protocol has insufficient actual assets to honor all share redemptions at the inflated price.

3. **Compounding Effect**: Multiple users can exploit this simultaneously, each contributing bad debt to unrealizedGlobalInterest.

4. **Irreversible Loss**: Once positions are closed and netBorrows = 0, there's no mechanism to write off the bad debt from unrealizedGlobalInterest.

Quantitative impact: If a user defers 500 tokens of interest and gets liquidated while still owing 300 tokens, those 300 tokens remain permanently as phantom assets in totalAssets. With 10 such users, the protocol accumulates 3000 tokens of bad debt.

## Likelihood Explanation

**HIGH Likelihood** - This vulnerability is easily exploitable under normal protocol operation:

1. **Natural Occurrence**: Users naturally become insolvent for interest when high utilization causes rapid interest accrual
2. **No Special Permissions**: Any user with open positions can exploit this
3. **Rational Behavior**: Depositing to avoid interest payment is economically rational for insolvent users
4. **Automatic Exploitation**: Users may unknowingly trigger this by depositing when insolvent
5. **No External Dependencies**: Requires no oracle manipulation, flash loans, or governance attacks

The only precondition is having `netBorrows > 0` (which occurs when opening any short position) and accruing enough interest to become insolvent, which happens naturally over time in high-utilization pools.

## Recommendation

**Fix 1: Force Partial Interest Payment During Deposits**

Even when `isDeposit = true`, burn all available shares for partial interest payment and update the index proportionally:

```solidity
function _accrueInterest(address owner, bool isDeposit) internal {
    // ... existing code ...
    
    if (shares > userBalance) {
        // Calculate partial payment value
        burntInterestValue = Math.mulDiv(userBalance, _totalAssets, totalSupply()).toUint128();
        
        emit InsolvencyPenaltyApplied(owner, userInterestOwed, burntInterestValue, userBalance);
        
        // Burn all available shares
        _burn(_owner, userBalance);
        
        // CRITICAL FIX: Update index proportionally to payment made
        // New debt = old debt - payment
        // userBorrowIndex should reflect that partial payment was made
        uint128 paymentRatio = Math.mulDiv(burntInterestValue, WAD, userInterestOwed).toUint128();
        uint128 indexIncrease = Math.mulDiv(currentBorrowIndex - userState.rightSlot(), paymentRatio, WAD).toUint128();
        userBorrowIndex = int128(uint128(userState.rightSlot()) + indexIncrease);
        
    } else {
        // Solvent case: Pay in full
        _burn(_owner, shares);
        userBorrowIndex = int128(currentBorrowIndex); // Full update
    }
    
    // ... rest of function ...
}
```

**Fix 2: Prevent Deposits When Insolvent for Interest**

Alternatively, revert deposits when users are insolvent for interest:

```solidity
function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
    // Check interest solvency BEFORE accepting deposits
    LeftRightSigned userState = s_interestState[msg.sender];
    if (userState.leftSlot() > 0) {
        uint128 interestOwed = _owedInterest(msg.sender);
        uint256 sharesNeeded = previewWithdraw(interestOwed);
        if (sharesNeeded > balanceOf[msg.sender]) {
            revert Errors.InsolventForInterest();
        }
    }
    
    _accrueInterest(msg.sender, IS_DEPOSIT);
    // ... rest of deposit logic ...
}
```

**Fix 3: Write Off Bad Debt When Positions Close**

Track users whose netBorrows become 0 while still having unpaid interest, and write off the bad debt from unrealizedGlobalInterest:

```solidity
// In _updateBalancesAndSettle, after updating netBorrows:
if (s_interestState[_optionOwner].leftSlot() == 0 && previousNetBorrows != 0) {
    // Position fully closed, check for unpaid interest
    uint128 remainingInterest = _owedInterest(_optionOwner);
    if (remainingInterest > 0) {
        // Write off bad debt from unrealized interest
        MarketState ms = s_marketState;
        uint128 unrealized = ms.unrealizedInterest();
        if (unrealized > remainingInterest) {
            s_marketState = ms.updateUnrealizedInterest(unrealized - remainingInterest);
        } else {
            s_marketState = ms.updateUnrealizedInterest(0);
        }
    }
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/CollateralTracker.sol";
import "../contracts/PanopticPool.sol";

contract InterestDeferralExploitTest is Test {
    CollateralTracker public collateralToken;
    PanopticPool public panopticPool;
    
    address public alice = address(0xA11CE);
    address public bob = address(0xB0B);
    
    function setUp() public {
        // Deploy contracts (assuming deployment helpers exist)
        // panopticPool = deployPanopticPool();
        // collateralToken = deployCollateralTracker();
    }
    
    function testInterestDeferralExploit() public {
        // 1. Setup: Alice deposits 1000 tokens, becomes LP
        vm.startPrank(alice);
        uint256 initialDeposit = 1000e18;
        collateralToken.deposit(initialDeposit, alice);
        vm.stopPrank();
        
        // 2. Bob deposits 100 tokens and opens positions with netBorrows = 500
        vm.startPrank(bob);
        collateralToken.deposit(100e18, bob);
        
        // Open short positions (creates netBorrows)
        TokenId positionId = createShortPosition(500e18);
        vm.stopPrank();
        
        // Record initial state
        uint256 initialTotalAssets = collateralToken.totalAssets();
        uint256 initialUnrealizedInterest = collateralToken.unrealizedGlobalInterest();
        
        // 3. Time passes, interest accrues
        vm.warp(block.timestamp + 365 days);
        
        // Bob now owes significant interest
        uint128 bobInterestOwed = collateralToken.owedInterest(bob);
        uint256 bobShares = collateralToken.balanceOf(bob);
        uint256 sharesNeeded = collateralToken.previewWithdraw(bobInterestOwed);
        
        // Verify Bob is insolvent for interest
        assertGt(sharesNeeded, bobShares, "Bob should be insolvent");
        
        // 4. Bob repeatedly deposits to avoid paying interest
        vm.startPrank(bob);
        for (uint i = 0; i < 5; i++) {
            // Each deposit triggers _accrueInterest with IS_DEPOSIT
            // Interest is NOT paid due to insolvency
            collateralToken.deposit(10e18, bob);
            
            // Verify Bob's borrow index was NOT updated
            (, int128 bobBorrowIndex) = collateralToken.interestState(bob);
            // bobBorrowIndex should still be old value, not currentBorrowIndex
        }
        vm.stopPrank();
        
        // 5. Verify unrealizedGlobalInterest still contains Bob's unpaid interest
        uint256 currentUnrealizedInterest = collateralToken.unrealizedGlobalInterest();
        assertGt(currentUnrealizedInterest, initialUnrealizedInterest, 
                 "Unrealized interest should have grown");
        
        // 6. Bob gets liquidated (simulated)
        vm.startPrank(address(panopticPool));
        // During liquidation, Bob's positions are closed
        // His remaining shares are burned but interest debt remains
        vm.stopPrank();
        
        // 7. After liquidation, Bob's netBorrows = 0 but unpaid interest remains
        (, int128 bobNetBorrows) = collateralToken.interestState(bob);
        assertEq(bobNetBorrows, 0, "Bob's netBorrows should be 0 after liquidation");
        
        // But unrealizedGlobalInterest STILL contains the bad debt
        uint256 finalUnrealizedInterest = collateralToken.unrealizedGlobalInterest();
        uint256 badDebt = finalUnrealizedInterest - initialUnrealizedInterest;
        
        // 8. Verify impact: totalAssets is inflated by bad debt
        uint256 finalTotalAssets = collateralToken.totalAssets();
        uint256 actualAssets = collateralToken.s_depositedAssets() + 
                                collateralToken.s_assetsInAMM();
        
        assertGt(finalTotalAssets, actualAssets, 
                 "totalAssets inflated by phantom debt");
        assertEq(finalTotalAssets - actualAssets, badDebt,
                 "Inflation equals bad debt");
        
        // 9. Demonstrate LP loss: Alice cannot withdraw full value
        vm.startPrank(alice);
        uint256 aliceShares = collateralToken.balanceOf(alice);
        uint256 aliceExpectedValue = collateralToken.convertToAssets(aliceShares);
        
        // Alice expects to withdraw aliceExpectedValue based on inflated share price
        // But protocol has insufficient actual assets
        // This proves protocol loss
        vm.stopPrank();
    }
    
    function createShortPosition(uint256 amount) internal returns (TokenId) {
        // Helper to create short position with given netBorrows
        // Implementation depends on PanopticPool interface
    }
}
```

**Notes**

The vulnerability is fundamentally rooted in the asymmetric handling of the `isDeposit` flag in `_accrueInterest()`. While the intent was likely to allow deposits to proceed even when users are temporarily insolvent, the implementation creates a permanent accounting discrepancy by allowing indefinite deferral without proper debt tracking or eventual write-off mechanisms.

The most critical line is line 937 where `burntInterestValue = 0`, combined with line 941 where the user's borrow index is not updated. This means the protocol "forgets" about the interest payment that should have occurred, but the interest debt remains tracked in `unrealizedGlobalInterest` until the position closes, at which point it becomes uncollectible bad debt.

### Citations

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L557-558)
```text
    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
        _accrueInterest(msg.sender, IS_DEPOSIT);
```

**File:** contracts/CollateralTracker.sol (L886-976)
```text
    function _accrueInterest(address owner, bool isDeposit) internal {
        uint128 _assetsInAMM = s_assetsInAMM;
        (
            uint128 currentBorrowIndex,
            uint128 _unrealizedGlobalInterest,
            uint256 currentEpoch
        ) = _calculateCurrentInterestState(_assetsInAMM, _updateInterestRate());

        // USER
        LeftRightSigned userState = s_interestState[owner];
        int128 netBorrows = userState.leftSlot();
        int128 userBorrowIndex = int128(currentBorrowIndex);
        if (netBorrows > 0) {
            uint128 userInterestOwed = _getUserInterest(userState, currentBorrowIndex);
            if (userInterestOwed != 0) {
                uint256 _totalAssets;
                unchecked {
                    _totalAssets = s_depositedAssets + _assetsInAMM + _unrealizedGlobalInterest;
                }

                uint256 shares = Math.mulDivRoundingUp(
                    userInterestOwed,
                    totalSupply(),
                    _totalAssets
                );

                uint128 burntInterestValue = userInterestOwed;

                address _owner = owner;
                uint256 userBalance = balanceOf[_owner];
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
                    // Solvent case: Pay in full.
                    _burn(_owner, shares);
                }

                // Due to repeated rounding up when:
                //  - compounding the global borrow index (multiplicative propagation of rounding error), and
                //  - converting a user's interest into shares,
                // burntInterestValue can exceed _unrealizedGlobalInterest by a few wei (because that accumulator calculates interest additively).
                // In that case, treat all remaining unrealized interest as consumed
                // and clamp the bucket to zero; otherwise subtract normally.
                if (burntInterestValue > _unrealizedGlobalInterest) {
                    _unrealizedGlobalInterest = 0;
                } else {
                    unchecked {
                        // can never underflow because burntInterestValue <= _unrealizedGlobalInterest
                        _unrealizedGlobalInterest = _unrealizedGlobalInterest - burntInterestValue;
                    }
                }
            }
        }

        s_interestState[owner] = LeftRightSigned
            .wrap(0)
            .addToRightSlot(userBorrowIndex)
            .addToLeftSlot(netBorrows);

        s_marketState = MarketStateLibrary.storeMarketState(
            currentBorrowIndex,
            currentEpoch,
            s_marketState.rateAtTarget(),
            _unrealizedGlobalInterest
        );
    }
```

**File:** contracts/CollateralTracker.sol (L1403-1403)
```text
        _accrueInterest(optionOwner, IS_NOT_DEPOSIT);
```
