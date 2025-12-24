# Audit Report

## Title 
Incorrect Share Minting Formula in settleLiquidation() Causes Extreme Shareholder Dilution When Vault is Insolvent

## Summary
When `totalAssets() < bonus` in `settleLiquidation()`, the denominator is clamped to 1, breaking the mathematical formula for share minting. This allows minting up to `totalSupply * 10,000` shares, causing extreme dilution (up to 10,000x) of existing shareholders and violating share price stability invariants.

## Finding Description
The `settleLiquidation()` function in `CollateralTracker.sol` uses a formula to calculate how many shares to mint when the liquidation bonus exceeds the liquidatee's balance: [1](#0-0) 

The formula `N = Z(Y - T) / (X - Z)` is designed to mint N shares such that after minting, they're worth Z (the bonus) in assets. However, when `X < Z` (totalAssets < bonus), the denominator becomes negative. The code handles this by clamping the denominator to 1: [2](#0-1) 

With denominator = 1, the formula becomes: `N = Z(Y - T) - T`, which is mathematically incorrect for the intended purpose. This can result in minting up to `totalSupply * 10,000` shares (the cap at line 1352), causing extreme dilution.

**How This Breaks Invariants:**

1. **Invariant #3 (Share Price Monotonicity)**: Share price drops dramatically from `X/Y` to approximately `X/(Y + Y*10000) = X/(10001*Y)`, a ~10,000x dilution.

2. **Invariant #22 (Liquidation Bonus Caps)**: The mechanism fails to properly cap dilution. While the liquidator doesn't receive more than available assets, existing shareholders suffer disproportionate losses.

**When This Occurs:**

The condition `totalAssets() < bonus` can happen when:
- The vault is severely insolvent (liquidatee's required collateral >> actual collateral)
- Liquidation bonus calculated by RiskEngine (line 516 in RiskEngine.sol) is large: `min(balanceCross/2, thresholdCross - balanceCross)`
- Cross-collateralization means one token's bonus can exceed that CollateralTracker's totalAssets [3](#0-2) 

**Example Scenario:**
- CollateralTracker has: `totalSupply = 100,000 shares`, `totalAssets = 100,000 tokens` (1:1 ratio)
- Liquidatee with `liquidateeBalance = 50 shares` owes `bonus = 150,000 tokens` (exceeds totalAssets)
- Denominator = `max(1, 100,000 - 150,000) = 1`
- Shares minted = `min((150,000 * 99,950 / 1) - 50, 100,000 * 10,000)` = `min(14,992,499,950, 1,000,000,000)` = `1,000,000,000 shares`
- After minting: total supply ≈ 1,000,100,000, share price ≈ 0.0001 tokens/share
- Original shareholders' 100,000 shares: worth ~10,000 tokens → ~10 tokens (99.99% loss)
- Liquidator receives: ~99,990 tokens out of 100,000 total

## Impact Explanation
**High Severity** - This causes systemic undercollateralization risk through extreme dilution:

1. **Existing Shareholders**: Suffer up to 10,000x dilution, losing nearly all value even though they weren't involved in the insolvent position
2. **Protocol Stability**: Share price collapses, breaking the ERC4626 invariant that share price should be relatively stable
3. **Liquidator Extraction**: While bounded by available assets, liquidators can extract nearly 100% of vault assets during insolvency events
4. **Cascading Effect**: If multiple liquidations occur during market stress, sequential 10,000x dilutions compound the damage

This affects all passive liquidity providers who have deposited into the CollateralTracker, not just the insolvent liquidatee.

## Likelihood Explanation
**Medium to High Likelihood**:

- **Trigger Condition**: Requires vault insolvency where `bonus > totalAssets`. This can occur during:
  - Market volatility causing large position losses
  - Liquidation cascades where multiple users become insolvent
  - Cross-collateralization scenarios where one token bears outsized liquidation costs
  
- **No Privilege Required**: Any liquidator can trigger this by liquidating an insolvent position

- **Realistic Scenarios**: 
  - High utilization (90%+) with significant assets in AMM reduces `totalAssets` in CollateralTracker
  - Large positions with 2x leverage can generate bonuses up to 50% of collateral value
  - In extreme moves (>50%), required collateral can exceed balance by 10x+, making `bonus` very large

While severe insolvency is not constant, it's a realistic occurrence during market stress when liquidations are most needed.

## Recommendation

Fix the formula to correctly handle the insolvency case when `totalAssets() < bonus`:

```solidity
if (bonusShares > liquidateeBalance) {
    _transferFrom(liquidatee, liquidator, liquidateeBalance);
    
    uint256 _totalSupply = totalSupply();
    uint256 _totalAssets = totalAssets();
    
    // When insolvent (totalAssets < bonus), liquidator should receive at most totalAssets
    // Calculate shares to mint such that liquidator gets remaining value without excessive dilution
    uint256 sharesToMint;
    
    if (_totalAssets < uint256(bonus)) {
        // Vault is insolvent - give liquidator proportional share of remaining assets
        // without causing 10,000x dilution
        // Target: liquidator gets ~totalAssets worth, with reasonable dilution (e.g., 10x max)
        uint256 remainingAssetValue = _totalAssets > convertToAssets(liquidateeBalance) 
            ? _totalAssets - convertToAssets(liquidateeBalance) 
            : 0;
        
        // Mint shares worth remainingAssetValue with max 10x dilution
        sharesToMint = Math.min(
            convertToShares(remainingAssetValue),
            _totalSupply * 10  // Cap at 10x dilution instead of 10,000x
        );
    } else {
        // Original formula works correctly when totalAssets >= bonus
        sharesToMint = Math.min(
            Math.mulDivCapped(
                uint256(bonus),
                _totalSupply - liquidateeBalance,
                _totalAssets - uint256(bonus)
            ) - liquidateeBalance,
            _totalSupply * 10  // Reduce cap from 10,000x to 10x
        );
    }
    
    _mint(liquidator, sharesToMint);
}
```

The key changes:
1. Explicitly handle the insolvency case separately
2. Reduce the dilution cap from 10,000x to 10x
3. When insolvent, mint shares worth the remaining assets rather than using the broken formula

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";

contract SettleLiquidationTest is Test {
    CollateralTrackerHarness collateralTracker;
    address liquidator = address(0x1);
    address liquidatee = address(0x2);
    address plp1 = address(0x3);
    address plp2 = address(0x4);
    
    function setUp() public {
        collateralTracker = new CollateralTrackerHarness();
        // Initialize with virtual shares
        collateralTracker.initialize();
    }
    
    function test_ExcessiveDilutionWhenBonusExceedsTotalAssets() public {
        // Setup: PLPs deposit 100,000 tokens
        vm.deal(plp1, 60000 ether);
        vm.deal(plp2, 40000 ether);
        
        vm.prank(plp1);
        collateralTracker.deposit{value: 60000 ether}(60000 ether, plp1);
        
        vm.prank(plp2);
        collateralTracker.deposit{value: 40000 ether}(40000 ether, plp2);
        
        // Initial state
        uint256 initialTotalSupply = collateralTracker.totalSupply();
        uint256 initialTotalAssets = collateralTracker.totalAssets();
        uint256 initialSharePrice = (initialTotalAssets * 1e18) / initialTotalSupply;
        
        console.log("Initial totalSupply:", initialTotalSupply);
        console.log("Initial totalAssets:", initialTotalAssets);
        console.log("Initial share price:", initialSharePrice);
        
        // Simulate liquidatee with small balance
        collateralTracker.mintShares(liquidatee, 50);
        collateralTracker.delegate(liquidatee);  // Add virtual shares
        
        // Liquidation with bonus (150,000) > totalAssets (100,000)
        int256 bonus = 150000 ether;
        
        vm.prank(address(collateralTracker.panopticPool()));
        collateralTracker.settleLiquidation(liquidator, liquidatee, bonus);
        
        // Check results
        uint256 finalTotalSupply = collateralTracker.totalSupply();
        uint256 finalTotalAssets = collateralTracker.totalAssets();
        uint256 finalSharePrice = (finalTotalAssets * 1e18) / finalTotalSupply;
        
        uint256 plp1Value = collateralTracker.convertToAssets(collateralTracker.balanceOf(plp1));
        uint256 plp2Value = collateralTracker.convertToAssets(collateralTracker.balanceOf(plp2));
        uint256 liquidatorValue = collateralTracker.convertToAssets(collateralTracker.balanceOf(liquidator));
        
        console.log("\nAfter liquidation:");
        console.log("Final totalSupply:", finalTotalSupply);
        console.log("Final totalAssets:", finalTotalAssets);
        console.log("Final share price:", finalSharePrice);
        console.log("PLP1 value:", plp1Value, "(lost", 60000 ether - plp1Value, ")");
        console.log("PLP2 value:", plp2Value, "(lost", 40000 ether - plp2Value, ")");
        console.log("Liquidator value:", liquidatorValue);
        
        // Assertions
        uint256 dilutionFactor = finalTotalSupply / initialTotalSupply;
        console.log("Dilution factor:", dilutionFactor, "x");
        
        // Demonstrate extreme dilution
        assertGt(dilutionFactor, 1000, "Dilution should be > 1000x");
        assertLt(plp1Value, 600 ether, "PLP1 lost > 99% of value");
        assertLt(plp2Value, 400 ether, "PLP2 lost > 99% of value");
        assertGt(liquidatorValue, 99000 ether, "Liquidator extracted > 99% of assets");
    }
}

contract CollateralTrackerHarness is CollateralTracker {
    constructor() CollateralTracker(10) {}
    
    function mintShares(address to, uint256 shares) external {
        _mint(to, shares);
    }
    
    // Mock PanopticPool
    function panopticPool() public pure override returns (address) {
        return address(this);
    }
}
```

**Notes:**
- The PoC demonstrates how a 150k token bonus against 100k totalAssets causes >1000x dilution
- PLPs lose >99% of their value while liquidator extracts nearly all assets  
- The cap at `totalSupply * 10,000` allows this extreme minting
- This violates share price stability and fair loss distribution

### Citations

**File:** contracts/CollateralTracker.sol (L1328-1354)
```text
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

**File:** contracts/RiskEngine.sol (L516-516)
```text
                uint256 bonusCross = Math.min(balanceCross / 2, thresholdCross - balanceCross);
```
