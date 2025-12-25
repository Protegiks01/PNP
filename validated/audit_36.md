# Vulnerability Validation: VALID - Critical Severity

## Title
Partial Interest Payments Create Uncollectable Phantom Debt Leading to Protocol Insolvency

## Summary
The `_accrueInterest()` function in `CollateralTracker.sol` incorrectly handles partial interest payments for insolvent users. When users pay partial interest, the function reduces the global `unrealizedGlobalInterest` bucket but fails to update the user's `userBorrowIndex` checkpoint or reduce their `netBorrows`. This accounting mismatch creates phantom uncollectable debt that permanently inflates `totalAssets()`, causing LP losses through share price manipulation.

## Impact
**Severity**: Critical
**Category**: Protocol Insolvency

The vulnerability creates uncollectable debt that inflates the share price, leading to direct LP losses:

- **Phantom Debt Accumulation**: Each partial payment reduces global interest tracking without updating individual user debt records. When positions close, unpaid interest remains in `unrealizedGlobalInterest` despite the borrower being gone.

- **LP Fund Drainage**: `totalAssets() = s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest` [1](#0-0)  includes phantom debt, artificially inflating share price. Early LPs withdraw at inflated prices while later LPs face insufficient assets.

- **Systemic Impact**: Affects all users with borrowed positions. Accumulates over time as multiple users make partial payments during normal protocol operation.

## Finding Description

**Location**: `contracts/CollateralTracker.sol:886-976`, function `_accrueInterest()`

**Intended Logic**: When users pay interest, both global tracking (`unrealizedGlobalInterest`) and individual tracking (`userBorrowIndex`, `netBorrows`) should update proportionally to reflect payment.

**Actual Logic**: The insolvency penalty path incorrectly handles partial payments: [2](#0-1) 

When `shares > userBalance` and `!isDeposit`:
1. User burns all available shares (line 931)
2. Global interest bucket reduces by payment amount (lines 954-960)
3. **Critical Bug**: User's `userBorrowIndex` keeps OLD value (line 934)
4. **Critical Bug**: User's `netBorrows` remains unchanged (line 896, 968)

The comment states the debt "continues to compound correctly" but this is **incorrect** because:

**Interest Calculation Formula**: [3](#0-2) 

The formula calculates: `interestOwed = netBorrows * (currentIndex - userIndex) / userIndex`

Since `userIndex` never updates after partial payments, future interest calculations include periods already paid for, creating double-counting.

**Exploitation Path**:

1. **Preconditions**: User opens short position with `netBorrows = 100`, contributing to `s_assetsInAMM`
   - State: `userBorrowIndex = 1.0e18`, `netBorrows = 100`, `unrealizedGlobalInterest = 0`

2. **Step 1**: Time passes, global interest accrues [4](#0-3) 
   - Interest calculation: `100 * 0.2 = 20` tokens
   - State: `unrealizedGlobalInterest = 20`, `currentBorrowIndex = 1.2e18`

3. **Step 2**: User becomes insolvent (has only 10 shares worth ~10 tokens), triggers `_accrueInterest()` via `transfer()` [5](#0-4) 
   - Partial payment: burns 10 shares worth 10 tokens
   - `unrealizedGlobalInterest -= 10` → now `10`
   - But `userBorrowIndex` stays `1.0e18`, `netBorrows` stays `100`

4. **Step 3**: More time passes, index compounds to `1.5e18`
   - Additional interest accrues on `s_assetsInAMM` (still contains 100)
   - User's calculated debt: `100 * (1.5 - 1.0) / 1.0 = 50` (includes already-paid period!)

5. **Step 4**: User closes position [6](#0-5) 
   - `netBorrows` becomes 0, `s_assetsInAMM -= 100`
   - User has 0 shares left, cannot pay remaining interest
   - **Result**: `unrealizedGlobalInterest` contains ~30-40 tokens of uncollectable debt
   - The borrower generating this interest is gone, making it permanently uncollectable

**Security Property Broken**: Collateral Conservation Invariant

The protocol assumes: `totalAssets() = s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest` represents actual recoverable value. However, `unrealizedGlobalInterest` contains phantom uncollectable debt, invalidating this invariant.

**Root Cause Analysis**:
- **Asymmetric Accounting**: Global interest accumulates additively based on current `s_assetsInAMM`, while user interest calculates multiplicatively from personal checkpoint
- **Missing Checkpoint Update**: Line 934 intentionally preserves old `userBorrowIndex`, but this creates tracking mismatch when combined with partial payment
- **No Debt Reduction**: `netBorrows` never decreases during partial payments, causing interest to continue accruing on "paid" amounts
- **Design Flaw**: The comment suggests intentional behavior, but the design fundamentally breaks accounting invariants

## Impact Explanation

**Affected Assets**: All collateral tokens (ETH, USDC, etc.) in CollateralTracker vaults

**Damage Severity**:
- **Quantitative**: If 10 users with average `netBorrows = 100` each make partial payments of 50% before closing, protocol accumulates ~500 tokens of phantom debt. With $2000 ETH price, that's $1M in inflated assets causing LP losses.
- **Qualitative**: Complete breakdown of interest accounting integrity. Share price becomes unreliable indicator of vault value.

**User Impact**:
- **Who**: All Panoptic Liquidity Providers (PLPs) depositing collateral
- **Conditions**: Occurs naturally during normal operation whenever borrowers become insolvent
- **Recovery**: Requires emergency pause and manual debt reconciliation across all positions

**Systemic Risk**:
- **Accumulation**: Each partial payment adds to phantom debt pool
- **Cascading Failure**: As share price inflates, solvency calculations become unreliable
- **Detection Difficulty**: Requires forensic analysis comparing sum of individual debts vs global tracking

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with open short positions
- **Resources Required**: Minimal - just need to open position and become insolvent
- **Technical Skill**: Low - occurs naturally during normal operations

**Preconditions**:
- **Market State**: Any - happens during normal operation, worse during volatility
- **User State**: Must have open position with accumulated interest
- **Timing**: No special timing required

**Execution Complexity**:
- **Transaction Count**: Single transaction triggering `_accrueInterest()` with `isDeposit=false`
- **Coordination**: None required - automatic during transfers, withdrawals, position updates
- **Detection Risk**: Low - appears as normal interest payment

**Frequency**:
- **Natural Occurrence**: High - users naturally become insolvent during market downturns
- **Deliberate Exploitation**: Trivial - withdraw collateral to become insolvent, trigger accrual, close position
- **Scale**: Affects every CollateralTracker instance

**Overall Assessment**: High likelihood - occurs automatically during normal protocol operation, easily exploitable deliberately, no special privileges required

## Recommendation

**Immediate Mitigation**:
Track partial payments and update user checkpoint proportionally: [7](#0-6) 

**Permanent Fix**:
When partial payment occurs, update `userBorrowIndex` proportionally:

```solidity
// Calculate proportion of interest paid
uint256 paymentRatio = (burntInterestValue * WAD) / userInterestOwed;
// Update index to reflect partial payment
uint256 indexDelta = (currentBorrowIndex - userBorrowIndex) * paymentRatio / WAD;
userBorrowIndex = userBorrowIndex + indexDelta;
```

**Additional Measures**:
- Add invariant tests verifying `unrealizedGlobalInterest` never exceeds sum of individual user debts
- Implement debt reconciliation mechanism to detect and correct phantom debt
- Add monitoring alerts when global vs individual interest tracking diverges

## Proof of Concept

The vulnerability can be demonstrated by:
1. User opens position with short amount creating `netBorrows`
2. Time passes allowing interest to accrue
3. User transfers shares triggering `_accrueInterest()` while insolvent
4. Observe `unrealizedGlobalInterest` decreases but `userBorrowIndex` unchanged
5. User closes position - phantom debt remains in `unrealizedGlobalInterest`

Expected behavior: Protocol accumulates uncollectable debt inflating `totalAssets()`.

---

## Notes

This vulnerability stems from a fundamental design flaw in the partial payment mechanism. The code comment suggests the behavior is intentional ("DO NOT update index"), but this creates an accounting inconsistency where the global interest tracking becomes disconnected from individual user debt tracking. The phantom debt accumulates over the protocol's lifetime, causing increasing LP losses as the divergence grows.

The issue is particularly insidious because it occurs during normal operations - any user becoming insolvent and making transfers or withdrawals will trigger the bug. The damage accumulates silently until LPs attempt withdrawals and discover insufficient assets.

### Citations

**File:** contracts/CollateralTracker.sol (L403-403)
```text
        _accrueInterest(msg.sender, IS_NOT_DEPOSIT);
```

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L916-942)
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
```

**File:** contracts/CollateralTracker.sol (L1012-1016)
```text

            uint128 interestOwed = Math.mulDivWadRoundingUp(_assetsInAMM, rawInterest).toUint128();

            // keep checked to prevent overflows
            _unrealizedGlobalInterest += interestOwed;
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

**File:** contracts/CollateralTracker.sol (L1514-1514)
```text
            s_interestState[_optionOwner] = s_interestState[_optionOwner].addToLeftSlot(netBorrows);
```
