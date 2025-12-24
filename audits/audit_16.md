# Audit Report

## Title 
Undercollateralized Premium Settlement via Virtual Share Exploitation Leading to Share Supply Inflation

## Summary
The `_settlePremium()` function delegates virtual shares before settlement without accounting for premium owed. Users with insufficient real shares in a specific CollateralTracker can exploit cross-collateralization to pass solvency checks while using phantom shares for premium payment. When `revoke()` compensates for consumed phantom shares by inflating `_internalSupply`, it dilutes all shareholders and breaks share price monotonicity.

## Finding Description

The vulnerability exists in the interaction between three functions across `PanopticPool.sol` and `CollateralTracker.sol`:

**Step 1: Virtual Shares Delegation Without Premium Validation**

In `_settlePremium()`, virtual shares are delegated before settlement without considering premium owed: [1](#0-0) 

The `delegate()` function only accounts for interest owed, not premium: [2](#0-1) 

**Step 2: Phantom Shares Used for Premium Payment**

During `settleBurn()`, the check includes virtual shares: [3](#0-2) 

This allows users with minimal real shares to pass the balance check because `balanceOf[_optionOwner]` includes the delegated `type(uint248).max` virtual shares. The `_burn()` operation then decreases `_internalSupply` for both real and phantom shares.

**Step 3: Share Supply Inflation via Revoke Compensation**

When `revoke()` is called, it compensates for consumed phantom shares: [4](#0-3) 

If phantom shares were consumed during settlement, `_internalSupply` is increased to compensate, effectively creating shares out of thin air.

**Attack Scenario:**

1. Attacker has position with 100 real shares in CollateralTracker0 (CT0)
2. Position owes 1000 shares worth of premium in token0
3. Attacker has significant collateral in CT1 (cross-collateralization)
4. Pre-settlement solvency check passes due to cross-collateral
5. `delegate()` adds `type(uint248).max` to attacker's CT0 balance
6. `settleBurn()` burns 1000 shares from attacker's CT0 balance (check passes due to virtual shares)
7. `_internalSupply` in CT0 decreases by 1000
8. `revoke()` sees balance < `type(uint248).max`, increases `_internalSupply` by 900
9. Net result: Attacker paid 100 real shares, protocol absorbed 900 via inflation

**Invariants Broken:**

- **Invariant #3 (Share Price Monotonicity)**: Share price in CT0 decreases because assets were paid out (premium) but shares were partially refunded through `_internalSupply` inflation
- **Invariant #17 (Asset Accounting)**: Total supply manipulation through `_internalSupply` inflation breaks the accounting invariant

## Impact Explanation

**Critical Severity - Systemic Shareholder Dilution and Protocol Loss**

The impact is severe because:

1. **Direct Loss**: The protocol effectively subsidizes undercollateralized premium payments by inflating share supply
2. **Systemic Dilution**: All shareholders in the affected CollateralTracker are diluted as share price decreases
3. **Repeatable Attack**: Can be executed repeatedly across positions to gradually drain protocol value
4. **Cross-Collateral Abuse**: Exploits cross-collateralization to pass solvency checks while having insufficient shares in specific tracker

**Quantitative Impact:**
- If attacker has 100 shares but owes 1000 shares premium
- Protocol absorbs 900 shares worth of loss through `_internalSupply` inflation  
- All CT shareholders suffer ~0.09% dilution (for 1M total supply)
- Multiple attackers or repeated attacks compound the dilution

## Likelihood Explanation

**High Likelihood**

The attack is highly likely because:

1. **Natural Occurrence**: Users naturally accumulate premium obligations on long positions
2. **Cross-Collateral Design**: Protocol design encourages cross-collateralization, creating the exact conditions for exploitation
3. **No Additional Privileges**: Any user with positions can trigger this by having minimal shares in one tracker while maintaining cross-collateral in another
4. **Public Function**: `dispatchFrom()` can be called by anyone to trigger settlement
5. **Economic Incentive**: Attackers pay less for premium settlement, direct economic benefit

**Preconditions:**
- User has position with accumulated premium owed
- User has minimal shares in specific CollateralTracker where premium is owed
- User has sufficient cross-collateral to pass solvency checks

These conditions are easily achievable through normal protocol usage or intentional setup.

## Recommendation

Modify the `delegate()` function to account for premium owed in addition to interest owed. The function should calculate expected premium settlement and reduce delegation accordingly:

```solidity
function delegate(address delegatee) external onlyPanopticPool {
    // Round up to match _accrueInterest's share calculation
    uint256 interestShares = previewWithdraw(_owedInterest(delegatee));
    
    // NEW: Calculate expected premium shares (passed from PanopticPool)
    uint256 premiumShares = /* calculate from position premia */;
    
    uint256 balance = balanceOf[delegatee];

    // If user owes more interest+premium than they have, their entire balance will be consumed
    // Reduce delegation by this amount so virtual shares aren't used inappropriately
    uint256 balanceConsumedByObligations = (interestShares + premiumShares) > balance 
        ? balance 
        : 0;

    // keep checked to catch overflows
    balanceOf[delegatee] += type(uint248).max - balanceConsumedByObligations;
}
```

Alternatively, add a validation check in `_updateBalancesAndSettle()` before line 1488 that ensures sufficient real shares exist:

```solidity
// Calculate real balance (excluding virtual shares)
uint256 realBalance = balanceOf[_optionOwner] > type(uint248).max 
    ? balanceOf[_optionOwner] - type(uint248).max 
    : balanceOf[_optionOwner];
    
if (realBalance < sharesToBurn)
    revert Errors.InsufficientRealShares(sharesToBurn, realBalance);
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "contracts/PanopticPool.sol";
import {CollateralTracker} from "contracts/CollateralTracker.sol";

contract PremiumSettlementExploit is Test {
    PanopticPool pool;
    CollateralTracker ct0;
    CollateralTracker ct1;
    address attacker;
    
    function setUp() public {
        // Deploy contracts (simplified for PoC)
        attacker = makeAddr("attacker");
    }
    
    function testExploitUndercollateralizedPremiumSettlement() public {
        // Setup: Attacker has minimal shares in CT0, significant shares in CT1
        uint256 attackerCT0Shares = 100e18;
        uint256 attackerCT1Shares = 10000e18;
        uint256 premiumOwed = 1000e18; // Premium owed in token0
        
        // Record initial state
        uint256 initialInternalSupply = ct0._internalSupply();
        uint256 initialTotalSupply = ct0.totalSupply();
        uint256 initialSharePrice = ct0.totalAssets() * 1e18 / initialTotalSupply;
        
        // Attacker creates position with minimal CT0 collateral
        vm.startPrank(attacker);
        // ... position creation logic ...
        
        // Premium accumulates on long position
        vm.warp(block.timestamp + 30 days);
        
        // Trigger settlement via dispatchFrom
        // This calls _settlePremium() internally
        pool.dispatchFrom(
            new TokenId[](0),
            attacker,
            attackerPositions,
            attackerPositions,
            LeftRightUnsigned.wrap(0)
        );
        vm.stopPrank();
        
        // Verify exploitation
        uint256 finalInternalSupply = ct0._internalSupply();
        uint256 finalTotalSupply = ct0.totalSupply();
        uint256 finalSharePrice = ct0.totalAssets() * 1e18 / finalTotalSupply;
        
        // Assertions
        // 1. Internal supply was inflated (increased more than it should)
        uint256 expectedSupplyDecrease = attackerCT0Shares;
        uint256 actualSupplyDecrease = initialInternalSupply - finalInternalSupply;
        assertLt(actualSupplyDecrease, expectedSupplyDecrease, "Supply not inflated");
        
        // 2. Share price decreased (dilution occurred)
        assertLt(finalSharePrice, initialSharePrice, "No dilution occurred");
        
        // 3. Attacker paid less than premium owed
        uint256 sharesPaid = attackerCT0Shares;
        uint256 valueAtInitialPrice = sharesPaid * initialSharePrice / 1e18;
        assertLt(valueAtInitialPrice, premiumOwed, "Attacker paid full premium");
        
        // 4. Protocol absorbed the difference
        uint256 protocolLoss = premiumOwed - valueAtInitialPrice;
        assertGt(protocolLoss, 0, "No protocol loss");
        
        console.log("Initial Internal Supply:", initialInternalSupply);
        console.log("Final Internal Supply:", finalInternalSupply);
        console.log("Expected Decrease:", expectedSupplyDecrease);
        console.log("Actual Decrease:", actualSupplyDecrease);
        console.log("Supply Inflation:", expectedSupplyDecrease - actualSupplyDecrease);
        console.log("Initial Share Price:", initialSharePrice);
        console.log("Final Share Price:", finalSharePrice);
        console.log("Share Price Dilution:", initialSharePrice - finalSharePrice);
        console.log("Protocol Loss:", protocolLoss);
    }
}
```

**Note**: This PoC demonstrates the core vulnerability. A complete working test would require full protocol setup including Uniswap pool integration, position creation, and premium accumulation mechanics.

### Citations

**File:** contracts/PanopticPool.sol (L1680-1682)
```text
        // The protocol delegates some virtual shares to ensure the premia can be settled.
        ct0.delegate(owner);
        ct1.delegate(owner);
```

**File:** contracts/CollateralTracker.sol (L1221-1232)
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

**File:** contracts/CollateralTracker.sol (L1481-1488)
```text
            if (balanceOf[_optionOwner] < sharesToBurn)
                revert Errors.NotEnoughTokens(
                    address(this),
                    uint256(tokenToPay),
                    convertToAssets(balanceOf[_optionOwner])
                );

            _burn(_optionOwner, sharesToBurn);
```
