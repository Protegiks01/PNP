# Audit Report

## Title 
Critical Interest Calculation Drift: Multiplicative vs Additive Mismatch Causes Systemic Undercollateralization

## Summary
The CollateralTracker contract uses multiplicative compounding for `borrowIndex` but additive accumulation for `unrealizedGlobalInterest`, creating a fundamental mathematical divergence that grows exponentially over time. This causes users to owe significantly more interest than the protocol accounts for, leading to insolvency for late position closures and violation of core accounting invariants.

## Finding Description

The protocol calculates interest using two different methods that are mathematically incompatible: [1](#0-0) 

The `borrowIndex` compounds multiplicatively: `borrowIndex = borrowIndex_old × (1 + rawInterest)`. After N periods with rate r, this produces: `(1 + r)^N`. [2](#0-1) 

The `unrealizedGlobalInterest` accumulates additively: `unrealizedInterest += assetsInAMM × rawInterest`. After N periods, this produces: `N × r` (assuming constant borrowed amount).

**Mathematical Proof of Divergence:**
For r = 10% interest rate over N = 10 compounding periods:
- Multiplicative (borrowIndex): `(1.1)^10 - 1 = 1.594 = 159.4%`
- Additive (unrealizedInterest): `10 × 0.1 = 1.0 = 100%`
- **Divergence: 59.4% understatement in unrealizedGlobalInterest**

User interest is calculated from the multiplicative borrowIndex: [3](#0-2) 

So users owe: `netBorrows × (currentBorrowIndex - userBorrowIndex) / userBorrowIndex`, which uses the multiplicatively compounded borrowIndex.

The protocol attempts to handle this with clamping logic: [4](#0-3) 

The comment claims this difference is "a few wei" due to rounding, but it's actually a systemic mathematical error that grows exponentially. The code treats a fundamental formula mismatch as a rounding error.

**Impact on Core Invariants:**

The `totalAssets()` function includes `unrealizedGlobalInterest`: [5](#0-4) 

When `unrealizedGlobalInterest` systematically underestimates true interest owed:
1. `totalAssets()` becomes understated relative to actual obligations
2. Share price (`totalAssets / totalSupply`) is artificially low
3. When borrowers pay interest, they must burn: `shares = mulDivRoundingUp(interestOwed, totalSupply, totalAssets)`
4. With understated `totalAssets`, borrowers burn **excessive shares**
5. Early borrowers deplete `unrealizedGlobalInterest` below what later borrowers owe
6. Late borrowers face insolvency despite having adequate initial collateral

**Exploitation Scenario:**
1. High utilization market with 50-100% annual interest rates
2. Multiple borrowers open positions over 6-12 months
3. Each accrual period widens the multiplicative/additive gap
4. Early borrowers close positions, paying full interest but depleting `unrealizedGlobalInterest` disproportionately
5. `unrealizedGlobalInterest` approaches zero while late borrowers still owe substantial interest
6. Late borrowers cannot pay interest (insufficient shares at artificially low share price)
7. Protocol enters inconsistent state violating Invariant #2 (Collateral Conservation)

## Impact Explanation

**Severity: CRITICAL**

This vulnerability breaks multiple critical invariants:

- **Invariant #2 (Collateral Conservation)**: Total assets equation `s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest` becomes incorrect as `unrealizedGlobalInterest` systematically underestimates true obligations.

- **Invariant #21 (Interest Accuracy)**: The interest calculation formula fails because borrowIndex (multiplicative) and unrealizedGlobalInterest (additive) use incompatible mathematics.

**Financial Impact:**
For a pool with 1,000 ETH borrowed at 50% annual rate over 12 months with monthly compounding:
- True compound interest: `(1.041667)^12 - 1 = 63.21%`
- Additive accumulation: `12 × 4.1667% = 50%`
- **Gap: 13.21% = 132.1 ETH unaccounted interest**

Late borrowers attempting to close positions would need to burn shares worth 632.1 ETH of interest, but `totalAssets` only reflects 500 ETH, requiring them to burn 26% more shares than they should. Those lacking sufficient shares become insolvent despite proper initial collateralization.

**Systemic Risk:**
- Protocol accounting becomes fundamentally incorrect over time
- Cannot accurately track liabilities vs assets
- Cascading insolvencies as `unrealizedGlobalInterest` depletes
- Loss of confidence requiring emergency shutdown

## Likelihood Explanation

**Likelihood: HIGH**

This is not a theoretical edge case but a **guaranteed mathematical outcome** of the protocol's design:

1. **Automatic Occurrence**: No attacker action required - happens naturally whenever:
   - Interest rates exceed ~10% annually (common in volatile crypto markets)
   - Positions remain open through multiple compounding periods
   - Multiple users interact with the pool over time

2. **Real-World Conditions**: The question specifically describes a scenario reaching 2^80 borrowIndex over 1.75 years at 800% interest - extreme but within protocol design limits as noted in: [6](#0-5) 

3. **No Prevention**: The clamping logic doesn't prevent the divergence, it only masks symptoms by setting `unrealizedGlobalInterest` to zero, exacerbating the accounting mismatch.

4. **Increasing Severity**: The divergence compounds over time - longer positions and higher rates worsen the gap exponentially.

## Recommendation

**Fix: Change `unrealizedGlobalInterest` to use multiplicative compounding consistent with `borrowIndex`:**

```solidity
// In _calculateCurrentInterestState(), replace lines 1013-1016 with:

// Calculate the multiplicative growth factor for assets in AMM
uint256 growthFactor = Math.mulDivWadRoundingUp(
    currentBorrowIndex, 
    WAD
) - WAD; // This gives (currentBorrowIndex / previousBorrowIndex - 1)

// Apply the same multiplicative compounding to unrealized interest
uint128 additionalInterest = Math.mulDivWadRoundingUp(
    _unrealizedGlobalInterest + _assetsInAMM,
    growthFactor
).toUint128();

_unrealizedGlobalInterest += additionalInterest;
```

**Alternative Fix: Track the previous borrowIndex and calculate:**

```solidity
uint256 previousBorrowIndex = accumulator.borrowIndex();
uint256 indexGrowth = currentBorrowIndex - previousBorrowIndex;

// Calculate interest based on the borrowed amount's compound growth
uint128 interestOwed = Math.mulDivRoundingUp(
    _assetsInAMM,
    indexGrowth,
    previousBorrowIndex
).toUint128();

_unrealizedGlobalInterest += interestOwed;
```

This ensures both `borrowIndex` and `unrealizedGlobalInterest` use the same compound growth model, maintaining consistency.

## Proof of Concept

The following calculation demonstrates the divergence:

```solidity
// Scenario: 100 ETH borrowed, 10% interest rate, 10 compounding periods

// Current Implementation:
uint256 borrowIndex = 1e18; // Start at 1.0
uint256 unrealizedInterest = 0;
uint256 assetsInAMM = 100e18;
uint256 rate = 0.1e18; // 10%

for (uint256 i = 0; i < 10; i++) {
    // Multiplicative borrowIndex update (current code)
    borrowIndex = borrowIndex * (1e18 + rate) / 1e18;
    
    // Additive unrealizedInterest update (current code)
    unrealizedInterest += assetsInAMM * rate / 1e18;
}

// Final values:
// borrowIndex = 2.594e18 (259.4% total)
// unrealizedInterest = 100e18 (100 ETH, representing 100% total)

// User with netBorrows = 100e18, userBorrowIndex = 1e18 owes:
uint256 userOwes = 100e18 * (borrowIndex - 1e18) / 1e18;
// userOwes = 100e18 * 1.594e18 / 1e18 = 159.4e18

// But unrealizedInterest only has 100e18!
// Gap: 59.4 ETH unaccounted (59.4% of original borrow)

// When user tries to pay 159.4 ETH interest but unrealizedInterest only has 100 ETH:
// - First 100 ETH paid normally
// - Remaining 59.4 ETH causes unrealizedInterest to clamp to 0
// - User burns excessive shares due to understated totalAssets
// - Protocol accounting becomes permanently corrupted
```

**Test Scenario:**
1. Deploy CollateralTracker with 1000 ETH initial liquidity
2. User borrows 100 ETH (opens short position)
3. Simulate 10 interest accrual periods at 10% each
4. Verify `unrealizedGlobalInterest` = 100 ETH (additive)
5. Verify user's calculated interest = 159.4 ETH (multiplicative)
6. Attempt to close position - observe insolvency or excessive share burn
7. Verify `unrealizedGlobalInterest` clamps to 0 while debt remains
8. Subsequent users cannot pay interest due to depleted accounting

**Notes**

The protocol's comment describing this as "a few wei" rounding error fundamentally mischaracterizes the issue. This is not floating-point precision loss but a mathematical incompatibility between compound interest formulas:
- Compound interest: `A = P(1+r)^n`
- Simple interest sum: `A = P(1+nr)`

These formulas are only approximately equal for small r×n, but diverge exponentially as the product increases. The security question specifically asks about scenarios (800% over 1.75 years) where this divergence becomes catastrophic. The protocol design does not account for this mathematical reality, treating it as negligible rounding when it's actually a core accounting flaw that violates the fundamental invariant that liabilities must equal tracked obligations.

### Citations

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L948-961)
```text
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
```

**File:** contracts/CollateralTracker.sol (L1013-1016)
```text
            uint128 interestOwed = Math.mulDivWadRoundingUp(_assetsInAMM, rawInterest).toUint128();

            // keep checked to prevent overflows
            _unrealizedGlobalInterest += interestOwed;
```

**File:** contracts/CollateralTracker.sol (L1019-1024)
```text
            unchecked {
                uint128 _borrowIndex = (WAD + rawInterest).toUint128();
                currentBorrowIndex = Math
                    .mulDivWadRoundingUp(currentBorrowIndex, _borrowIndex)
                    .toUint128();
            }
```

**File:** contracts/CollateralTracker.sol (L1071-1077)
```text
        interestOwed = Math
            .mulDivRoundingUp(
                uint128(netBorrows),
                currentBorrowIndex - userBorrowIndex,
                userBorrowIndex
            )
            .toUint128();
```

**File:** contracts/types/MarketState.sol (L14-14)
```text
// (0) borrowIndex          80 bits : Global borrow index in WAD (starts at 1e18). 2**80 = 1.75 years at 800% interest
```
