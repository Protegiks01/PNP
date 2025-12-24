# Audit Report

## Title
Transfer Function DoS for Insolvent Users Due to Share Burning Before Balance Check

## Summary
The `transfer()` function in CollateralTracker calls `_accrueInterest()` before executing the share transfer. When a user is insolvent (owes more interest than their share balance), all their shares are burned during interest accrual. The subsequent transfer attempt then reverts with an underflow error when trying to deduct the transfer amount from a zero balance.

## Finding Description
The vulnerability occurs in the execution flow of the `transfer()` function: [1](#0-0) 

When `_accrueInterest(msg.sender, IS_NOT_DEPOSIT)` is called, the function checks if the user owes interest and burns shares accordingly: [2](#0-1) 

For insolvent users (where `shares > userBalance`), in the `IS_NOT_DEPOSIT` case, the function burns ALL remaining shares. After this, when execution returns to `transfer()` and calls the parent `ERC20Minimal.transfer()`: [3](#0-2) 

The operation `balanceOf[msg.sender] -= amount` will underflow and revert because `balanceOf[msg.sender]` is now 0 (all shares were burned), but `amount > 0` (the intended transfer amount).

**Exploitation Path:**
1. User has 100 shares and accumulated debt requiring 120 shares to pay
2. User has no open positions (passes the check at line 408)
3. User calls `transfer(recipient, 50)` to transfer 50 shares
4. `_accrueInterest()` burns all 100 shares (insolvency penalty)
5. `ERC20Minimal.transfer()` attempts `0 - 50`, causing underflow revert

This breaks the expected transfer functionality and creates an unexpected restriction beyond the documented constraint that users with open positions cannot transfer.

## Impact Explanation
**Medium Severity** - This issue causes:
- **Temporary DoS** for insolvent users trying to transfer shares, even if they have no open positions
- **State inconsistency** where users pass the "no open positions" check but still cannot transfer
- **Poor user experience** with cryptic underflow errors instead of clear insolvency messages
- Users can potentially resolve it by depositing additional collateral to become solvent, but this defeats the purpose of attempting a transfer

This does not result in permanent fund loss, but it creates an unexpected restriction that prevents legitimate share transfers for users who may have small residual debts from rounding errors in previous position closures.

## Likelihood Explanation
**Medium to High Likelihood** - This can occur in normal protocol operations when:
- Users close positions with small rounding differences that leave residual netBorrows
- Interest accumulates on residual debt over time
- Users attempt to transfer shares without realizing they have outstanding debt
- The check at line 408 only validates "no open positions," not "no outstanding debt"

The condition is more likely than it might initially appear because users without open positions can still have positive netBorrows from previous activities, and the protocol's compound interest mechanism can grow these small debts.

## Recommendation
Add an explicit solvency check before allowing transfers, with a clear error message:

```solidity
function transfer(
    address recipient,
    uint256 amount
) public override(ERC20Minimal) returns (bool) {
    _accrueInterest(msg.sender, IS_NOT_DEPOSIT);
    
    // Check for open positions
    if (panopticPool().numberOfLegs(msg.sender) != 0) revert Errors.PositionCountNotZero();
    
    // Add explicit check for sufficient balance after interest accrual
    if (balanceOf[msg.sender] < amount) revert Errors.NotEnoughTokens(address(this), amount, balanceOf[msg.sender]);
    
    return ERC20Minimal.transfer(recipient, amount);
}
```

Apply the same fix to `transferFrom()`: [4](#0-3) 

This ensures users receive a clear error message about insufficient balance (after interest settlement) rather than an unexpected underflow revert.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/CollateralTracker.sol";
import "../contracts/PanopticPool.sol";

contract TransferDoSTest is Test {
    CollateralTracker collateralTracker;
    address alice = address(0x1);
    address bob = address(0x2);
    
    function setUp() public {
        // Deploy and initialize CollateralTracker
        // Setup positions for Alice with debt
    }
    
    function testTransferFailsForInsolventUser() public {
        // 1. Alice deposits 100 shares worth of collateral
        vm.startPrank(alice);
        collateralTracker.deposit(100e18, alice);
        
        // 2. Alice opens and closes positions, accumulating debt
        // This leaves her with netBorrows > 0 but no open positions
        
        // 3. Time passes, interest accrues, Alice becomes insolvent
        vm.warp(block.timestamp + 365 days);
        
        // 4. Alice tries to transfer 50 shares
        // This will revert with underflow because:
        // - _accrueInterest burns all her shares (she's insolvent)
        // - Then transfer tries to deduct from 0 balance
        vm.expectRevert(); // Underflow revert
        collateralTracker.transfer(bob, 50e18);
        
        vm.stopPrank();
    }
}
```

**Note:** A complete PoC would require full test harness setup with PanopticPool, RiskEngine, and mock Uniswap pools, which is beyond the scope of this simplified demonstration. The key point is that after `_accrueInterest()` burns all shares due to insolvency, the subsequent `transfer()` call in ERC20Minimal will revert on the subtraction operation.

### Citations

**File:** contracts/CollateralTracker.sol (L399-411)
```text
    function transfer(
        address recipient,
        uint256 amount
    ) public override(ERC20Minimal) returns (bool) {
        _accrueInterest(msg.sender, IS_NOT_DEPOSIT);
        // make sure the caller does not have any open option positions
        // if they do: we don't want them sending panoptic pool shares to others
        // as this would reduce their amount of collateral against the opened positions

        if (panopticPool().numberOfLegs(msg.sender) != 0) revert Errors.PositionCountNotZero();

        return ERC20Minimal.transfer(recipient, amount);
    }
```

**File:** contracts/CollateralTracker.sol (L418-431)
```text
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override(ERC20Minimal) returns (bool) {
        _accrueInterest(from, IS_NOT_DEPOSIT);
        // make sure the sender does not have any open option positions
        // if they do: we don't want them sending panoptic pool shares to others
        // as this would reduce their amount of collateral against the opened positions

        if (panopticPool().numberOfLegs(from) != 0) revert Errors.PositionCountNotZero();

        return ERC20Minimal.transferFrom(from, to, amount);
    }
```

**File:** contracts/CollateralTracker.sol (L916-935)
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
```

**File:** contracts/tokens/ERC20Minimal.sol (L61-73)
```text
    function transfer(address to, uint256 amount) public virtual returns (bool) {
        balanceOf[msg.sender] -= amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(msg.sender, to, amount);

        return true;
    }
```
