# Validation Result: VALID VULNERABILITY

## Title
View Function State Inconsistency Enables Temporary Liquidation Bypass via Utilization Manipulation

## Summary
The `CollateralTracker.sol` contract uses different utilization calculation paths for view functions versus actual interest accrual. View functions call `_poolUtilizationWadView()` which returns current utilization, while actual accrual uses `_poolUtilizationWad()` which reads maximum utilization from transient storage. This discrepancy allows depositors to temporarily suppress interest calculations in liquidation solvency checks, enabling insolvent positions to avoid liquidation within the same transaction.

## Impact
**Severity**: Medium  
**Category**: State Inconsistency / Economic Manipulation

The vulnerability enables temporary denial-of-service on liquidations through state inconsistency:

- **Affected Parties**: Passive Liquidity Providers (PLPs) bear increased risk from delayed liquidations; liquidators waste gas on failed attempts
- **Protocol Risk**: Insolvent positions remain open longer than intended, potentially accumulating additional bad debt before eventual liquidation
- **Attack Cost**: Requires significant capital to materially shift utilization (e.g., depositing >100% of current `assetsInAMM` to drop utilization from 70% to 40%), but can be executed by the position holder themselves to defend against liquidation

## Finding Description

**Location**: 
- `contracts/CollateralTracker.sol` lines 1099-1106 (`_owedInterest`)
- `contracts/CollateralTracker.sol` lines 1173-1195 (`_poolUtilizationWad`)
- `contracts/CollateralTracker.sol` lines 1199-1208 (`_poolUtilizationWadView`)
- `contracts/RiskEngine.sol` lines 1151-1152 (`_getMargin`)

**Intended Logic**: The transient storage mechanism in `_poolUtilizationWad()` is designed to prevent flash deposit attacks by storing the maximum utilization during a transaction. [1](#0-0) 

This protection ensures that when interest is actually accrued via `_accrueInterest()`, it uses the maximum utilization value. [2](#0-1) 

**Actual Logic**: However, view functions used during liquidation solvency checks bypass this protection entirely by calling `_poolUtilizationWadView()` which is a pure calculation that does NOT access transient storage. [3](#0-2) 

The `_owedInterest()` function, which is called via `assetsAndInterest()` during liquidation checks, uses this view-only path. [4](#0-3) 

This creates a critical divergence: liquidation checks calculate interest using current (potentially manipulated) utilization, while actual accrual would use the maximum utilization stored in transient storage.

**Exploitation Path**:

1. **Preconditions**: Victim has leveraged position near liquidation threshold with ongoing interest accumulation

2. **Step 1**: Attacker (or victim via alternate account) deposits large collateral amount
   - Call path: `CollateralTracker.deposit()` → `_accrueInterest(depositor, IS_DEPOSIT)` → `_updateInterestRate()` → `_poolUtilizationWad()`
   - Transient storage stores high utilization (e.g., 70%) before deposit is processed
   - Deposit processes, current utilization drops significantly (e.g., to 40%)

3. **Step 2**: Liquidator attempts liquidation in same transaction
   - Call path: `PanopticPool.dispatchFrom()` → `_checkSolvencyAtTicks()` → `_isAccountSolvent()` → `RiskEngine.isAccountSolvent()` → `_getMargin()` [5](#0-4) 
   - `_getMargin()` calls `ct.assetsAndInterest(victim)` [6](#0-5) 
   - Uses view path with current 40% utilization → calculates artificially low interest rate → computes lower borrow index growth → underestimates interest owed

4. **Step 3**: Solvency check incorrectly passes
   - Victim appears solvent due to understated interest obligations
   - Liquidation attempt reverts with `NotMarginCalled` error [7](#0-6) 

5. **Step 4**: Attacker withdraws deposit after transaction
   - Transient storage clears at transaction boundary
   - Victim's position remains open despite actual insolvency
   - Can be repeated to continuously block liquidation attempts

**Security Property Broken**: Protocol invariant that "insolvent positions must be liquidated immediately" is violated through state inconsistency between view and non-view execution paths.

**Root Cause Analysis**: The fundamental issue is that Solidity view functions cannot access transient storage (EIP-1153), creating an architectural limitation. The protocol implements transient storage protection for actual operations but has no mechanism to extend this protection to read-only solvency checks, resulting in a state consistency gap that can be exploited for liquidation avoidance.

## Impact Explanation

**Affected Assets**: User collateral across both token0 and token1 CollateralTracker vaults

**Damage Severity**:
- **Quantitative**: Temporary DOS on specific liquidations. Capital required scales with utilization delta needed (depositing X to shift utilization by Y requires deposit ≈ X * assetsInAMM where X = f(Y, current_util))
- **Qualitative**: Delays risk management, allows undercollateralized positions to persist beyond intended timeframes

**User Impact**:
- **PLPs**: Bear extended tail risk from positions that should be liquidated
- **Liquidators**: Waste gas attempting liquidations that fail solvency checks
- **Position Holders**: Can defend against liquidation by depositing collateral or having allied parties do so

**Systemic Risk**:
- Limited to single-transaction delays (transient storage clears)
- Requires repeated execution to maintain protection
- Most impactful during high volatility when liquidations are most critical

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Position holder facing liquidation, or allied party
- **Resources Required**: Capital proportional to pool size (must deposit enough to materially shift utilization)
- **Technical Skill**: Low (simple deposit transaction timing)

**Preconditions**:
- Position near liquidation threshold
- Time elapsed since victim's last interaction (>4 seconds for new epoch, enabling interest calculation divergence) [8](#0-7) 
- Sufficient capital to significantly lower utilization

**Execution Complexity**:
- **Transaction Count**: Single transaction with deposit front-running liquidation attempt
- **Coordination**: Moderate (requires monitoring for liquidation attempts or proactive defense)
- **Economic Viability**: Cost is temporary capital lockup during transaction vs. liquidation bonus saved (5-10%)

**Frequency**: Moderate - requires capital and monitoring, but strong economic incentive for positions facing liquidation

**Overall Assessment**: Medium likelihood - technically straightforward but requires significant capital and only provides temporary protection

## Recommendation

**Immediate Mitigation**:
The fundamental issue cannot be fully resolved without making `assetsAndInterest()` non-view, which would break external integrations. However, consider:

1. Document this known limitation in protocol documentation
2. Add liquidation buffer parameters to make positions liquidatable before reaching exact threshold
3. Implement multi-block liquidation checks to reduce single-transaction manipulation effectiveness

**Permanent Fix**:
Consider refactoring to make solvency checks state-modifying (non-view) so they can access transient storage:

```solidity
// Change signature from view to non-view
function assetsAndInterest(address owner) external returns (uint256, uint256) {
    _accrueInterest(owner, IS_NOT_DEPOSIT); // Accrue interest using transient storage protection
    return (convertToAssets(balanceOf[owner]), 0); // Interest already accrued and deducted
}
```

However, this breaks the view interface and has significant integration implications.

**Alternative Approach**:
Implement a "pre-liquidation" function that accrues interest for the target before solvency checks:

```solidity
function liquidateWithAccrual(address target, ...) external {
    // Force interest accrual before solvency check
    collateralToken0().accrueInterestFor(target);
    collateralToken1().accrueInterestFor(target);
    // Now proceed with normal liquidation
    _liquidate(target, ...);
}
```

**Additional Measures**:
- Add monitoring for large deposits immediately preceding failed liquidation attempts
- Consider implementing cooldown periods for withdrawals after large deposits
- Add explicit warnings in documentation about view function limitations

## Notes

This vulnerability represents a genuine architectural limitation stemming from the incompatibility between transient storage (EIP-1153) and view functions. While the transient storage mechanism successfully prevents flash deposit attacks on actual operations, it cannot protect read-only solvency checks that external callers and liquidators rely upon.

The severity is Medium rather than High because:
1. Impact is temporary (single transaction)
2. Requires significant capital to execute
3. Does not directly result in fund loss, but rather delayed risk management
4. Attacker must repeatedly execute to maintain protection

The vulnerability is valid and exploitable, but its practical impact is limited by capital requirements and temporary nature. It represents a state inconsistency between view and non-view execution paths that should be addressed, though fundamental constraints of the EVM may limit available solutions.

### Citations

**File:** contracts/CollateralTracker.sol (L886-892)
```text
    function _accrueInterest(address owner, bool isDeposit) internal {
        uint128 _assetsInAMM = s_assetsInAMM;
        (
            uint128 currentBorrowIndex,
            uint128 _unrealizedGlobalInterest,
            uint256 currentEpoch
        ) = _calculateCurrentInterestState(_assetsInAMM, _updateInterestRate());
```

**File:** contracts/CollateralTracker.sol (L999-1003)
```text
        currentEpoch = block.timestamp >> 2;
        uint256 previousEpoch = accumulator.marketEpoch();
        uint128 deltaTime;
        unchecked {
            deltaTime = uint32(currentEpoch - previousEpoch) << 2;
```

**File:** contracts/CollateralTracker.sol (L1099-1106)
```text
    function _owedInterest(address owner) internal view returns (uint128) {
        LeftRightSigned userState = s_interestState[owner];
        (uint128 currentBorrowIndex, , ) = _calculateCurrentInterestState(
            s_assetsInAMM,
            _interestRateView(_poolUtilizationWadView())
        );
        return _getUserInterest(userState, currentBorrowIndex);
    }
```

**File:** contracts/CollateralTracker.sol (L1170-1171)
```text
    /// @dev calling this function will also store the utilization in the UTILIZATION_TRANSIENT_SLOT as DECIMALS
    /// if the current one is higher than the one already stored. This ensures that flash deposits can't lower the utilization for a single tx
```

**File:** contracts/CollateralTracker.sol (L1199-1208)
```text
    function _poolUtilizationWadView() internal view returns (uint256 poolUtilization) {
        unchecked {
            return
                Math.mulDivRoundingUp(
                    uint256(s_assetsInAMM) + uint256(s_marketState.unrealizedInterest()),
                    WAD,
                    totalAssets()
                );
        }
    }
```

**File:** contracts/PanopticPool.sol (L1399-1408)
```text
            solvent = _checkSolvencyAtTicks(
                account,
                0,
                positionIdListTo,
                currentTick,
                atTicks,
                COMPUTE_PREMIA_AS_COLLATERAL,
                NO_BUFFER
            );
            numberOfTicks = atTicks.length;
```

**File:** contracts/PanopticPool.sol (L1462-1465)
```text
            } else {
                // otherwise, revert because the account is not fully margin called
                revert Errors.NotMarginCalled();
            }
```

**File:** contracts/RiskEngine.sol (L1151-1152)
```text
            (balance0, interest0) = ct0.assetsAndInterest(user);
            (balance1, interest1) = ct1.assetsAndInterest(user);
```
