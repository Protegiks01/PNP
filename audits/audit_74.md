# Audit Report

## Title 
Withdrawal DoS When `s_depositedAssets` Equals Virtual Asset Threshold

## Summary
The `maxWithdraw()` function in `CollateralTracker.sol` calculates available withdrawal liquidity as `depositedAssets - 1` to preserve the virtual asset. When `s_depositedAssets == 1`, this makes `available = 0`, blocking ALL withdrawals even when the vault holds significant value in `s_assetsInAMM` or `unrealizedGlobalInterest`. Innocent liquidity providers with no open positions cannot withdraw their shares despite having real collateral value.

## Finding Description
The CollateralTracker implements an ERC4626 vault with three asset buckets tracked separately: [1](#0-0) 

The protocol initializes with 1 virtual asset to prevent inflation attacks: [2](#0-1) 

The `maxWithdraw()` function ensures at least 1 asset always remains by calculating: [3](#0-2) 

**The Issue:** When `s_depositedAssets == 1` (only the virtual asset remains), `available = 1 - 1 = 0`, causing `maxWithdraw()` to return 0 for ALL users regardless of their share balance or whether they have open positions.

**Attack Scenario:**
1. Pool initialized: `s_depositedAssets = 1`, `s_assetsInAMM = 0`
2. Alice deposits 1000 tokens: `s_depositedAssets = 1001`
3. Alice opens positions moving 500 to AMM: `s_depositedAssets = 501`, `s_assetsInAMM = 500` (via `settleMint()`)
4. Alice withdraws 500: `s_depositedAssets = 1`, leaving only the virtual asset
5. Bob (passive LP with no positions) tries to withdraw
6. `maxWithdraw(Bob)` returns `min(0, Bob's balance) = 0`
7. Bob's withdrawal reverts with `ExceedsMaximumRedemption` even though:
   - `totalAssets() = 1 + 500 = 501` (real value exists)
   - Bob has shares worth real assets
   - Bob has NO open positions

The withdrawal check enforces this limit: [4](#0-3) 

**Broken Invariant:** This violates Invariant #18 which states withdrawals must leave ≥1 asset, but doesn't account for the case where only the virtual asset remains while real value exists elsewhere in the vault. The `-1` logic fails to distinguish between "preserve virtual asset" and "last real asset" scenarios.

## Impact Explanation
**Severity: Medium**

This creates a temporary denial-of-service on withdrawals affecting innocent users:

1. **No Direct Fund Loss**: Funds remain in the protocol and are not stolen
2. **Temporary Freezing**: Users cannot access their collateral until positions close and assets return to `s_depositedAssets`
3. **Unfair State**: One user's legitimate actions (opening positions + withdrawing available balance) blocks other users' withdrawals
4. **Scale**: Affects all LPs when the condition triggers, not just individual users
5. **No Attacker Profit**: The user causing the state doesn't gain financially, making this a protocol design flaw rather than an economic exploit

The impact is Medium rather than High because:
- Funds are not permanently locked (positions can be closed)
- No protocol insolvency or loss occurs
- Requires specific state (`s_depositedAssets = 1` with `s_assetsInAMM > 0`)

## Likelihood Explanation
**Likelihood: Medium-High**

This condition can occur naturally through normal protocol operations:

1. **Common Flow**: Users frequently open positions (deploying assets to AMM) and withdraw available liquidity
2. **No Privileged Access**: Any user can trigger this state through standard `deposit()`, `settleMint()`, and `withdraw()` operations
3. **Predictable**: The state is deterministic based on asset movements
4. **No Manipulation Required**: No oracle manipulation, flash loans, or complex attack vectors needed

The likelihood is elevated because:
- Active option traders regularly move assets between `s_depositedAssets` and `s_assetsInAMM`
- Withdrawing maximum available balance is standard behavior
- The virtual asset threshold of 1 is easy to reach unintentionally

## Recommendation

Modify the available calculation to account for whether assets in AMM can be liquidated or if only the virtual asset remains:

```solidity
function maxWithdraw(address owner) public view returns (uint256 maxAssets) {
    uint256 depositedAssets = s_depositedAssets;
    unchecked {
        // If depositedAssets > 1, preserve 1 asset as before
        // If depositedAssets == 1 (virtual asset only), allow withdrawal 
        // proportional to other vault assets if they exist
        uint256 available;
        if (depositedAssets > 1) {
            available = depositedAssets - 1;
        } else {
            // When only virtual asset remains, allow proportional withdrawals
            // from other buckets if they have value
            uint256 otherAssets = s_assetsInAMM + s_marketState.unrealizedInterest();
            available = otherAssets > 0 ? otherAssets : 0;
        }
        uint256 balance = convertToAssets(balanceOf[owner]);
        return panopticPool().numberOfLegs(owner) == 0 ? Math.min(available, balance) : 0;
    }
}
```

**Alternative:** Add explicit handling to allow fractional withdrawals when `totalAssets() > s_depositedAssets` but `s_depositedAssets == 1`, or require minimum deposit amounts that keep `s_depositedAssets > 1`.

## Proof of Concept

Add this test to `test/foundry/coreV3/CollateralTracker.t.sol`:

```solidity
function test_WithdrawalDoS_WhenDepositedAssetsEqualsOne() public {
    // Initialize world state
    _initWorld(0);
    
    vm.startPrank(Alice);
    _grantTokens(Alice);
    IERC20Partial(token0).approve(address(collateralToken0), type(uint256).max);
    
    // Alice deposits 1000 tokens
    collateralToken0.deposit(1000, Alice);
    uint256 aliceShares = collateralToken0.balanceOf(Alice);
    
    // Simulate Alice opening a position that moves 500 assets to AMM
    collateralToken0.setPoolAssets(501); // 1 (virtual) + 500 (real)
    collateralToken0.setInAMM(500);
    
    // Verify total assets includes both buckets
    assertEq(collateralToken0.totalAssets(), 1001); // 501 deposited + 500 in AMM
    
    // Alice withdraws 500, leaving only virtual asset in s_depositedAssets
    collateralToken0.withdraw(500, Alice, Alice);
    assertEq(collateralToken0._poolAssets(), 1); // Only virtual asset remains
    assertEq(collateralToken0._inAMM(), 500); // Real assets in AMM
    
    vm.stopPrank();
    
    // Bob is a passive LP with no positions
    vm.startPrank(Bob);
    _grantTokens(Bob);
    IERC20Partial(token0).approve(address(collateralToken0), type(uint256).max);
    collateralToken0.deposit(100, Bob);
    
    uint256 bobShares = collateralToken0.balanceOf(Bob);
    uint256 bobAssets = collateralToken0.convertToAssets(bobShares);
    
    // Bob has real asset value but cannot withdraw
    assertGt(bobAssets, 0);
    assertEq(collateralToken0.maxWithdraw(Bob), 0); // maxWithdraw returns 0!
    
    // Bob's withdrawal reverts even though he has no positions
    vm.expectRevert(Errors.ExceedsMaximumRedemption.selector);
    collateralToken0.withdraw(1, Bob, Bob); // Cannot withdraw even 1 wei
    
    vm.stopPrank();
}
```

**Notes**

The vulnerability stems from the `-1` logic treating all `s_depositedAssets == 1` states identically without considering whether this represents only the virtual asset (legitimate) or the last real asset (problematic). The fix should distinguish between these cases or ensure withdrawals can tap into `s_assetsInAMM` when `s_depositedAssets` reaches the virtual threshold while maintaining the collateral conservation invariant.

### Citations

**File:** contracts/CollateralTracker.sol (L296-296)
```text
        s_depositedAssets = 1;
```

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L651-658)
```text
    function maxWithdraw(address owner) public view returns (uint256 maxAssets) {
        uint256 depositedAssets = s_depositedAssets;
        unchecked {
            uint256 available = depositedAssets > 0 ? depositedAssets - 1 : 0;
            uint256 balance = convertToAssets(balanceOf[owner]);
            return panopticPool().numberOfLegs(owner) == 0 ? Math.min(available, balance) : 0;
        }
    }
```

**File:** contracts/CollateralTracker.sol (L696-696)
```text
        if (assets > maxWithdraw(owner)) revert Errors.ExceedsMaximumRedemption();
```
