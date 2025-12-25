# Validation Result: VALID HIGH Severity Vulnerability

## Title
Utilization Snapshot Reset via Burn-Remint Allows Collateral Requirement Bypass

## Summary
The `dispatch()` function fails to validate duplicate `tokenId` entries in `positionIdList`, allowing users to burn and immediately remint the same position within a single transaction. This resets the utilization snapshot stored in `PositionBalance`, enabling users to reduce collateral requirements by up to 5x when pool utilization has decreased, creating systemic undercollateralization risk.

## Impact
**Severity**: High
**Category**: Protocol Insolvency / Systemic Undercollateralization

**Affected Assets**: All user collateral positions across token0 and token1

**Damage Severity**:
- **Quantitative**: Collateral requirements can be reduced by 5x (from ~100% at 90% utilization to ~20% at 10% utilization), enabling withdrawal of up to 80% of initially required collateral
- **Scope**: Portfolio-wide impact since RiskEngine uses maximum utilization across all positions
- **Protocol Risk**: Users can artificially reduce collateral below safety thresholds, creating bad debt if markets move adversely

**User Impact**:
- **Who**: All option sellers with short positions minted during high utilization periods
- **Conditions**: Exploitable whenever pool utilization decreases after position mint
- **Recovery**: Requires emergency intervention to restore proper collateral levels

## Finding Description

**Location**: `contracts/PanopticPool.sol:629`, `contracts/PanopticPool.sol:1332`, function `dispatch()`

**Intended Logic**: The protocol should maintain conservative collateral requirements based on the utilization level at which positions were originally minted. Positions minted at high utilization (90%) should continue requiring ~100% collateral throughout their lifetime to protect against market volatility.

**Actual Logic**: The `dispatch()` function processes `positionIdList` in a loop without checking for duplicate `tokenId` entries. The duplicate validation only occurs on `finalPositionIdList` after all operations complete. This allows a burn-then-mint sequence within the same transaction that resets the utilization snapshot.

**Code Evidence**:

Zero balance check that treats burned position as new mint: [1](#0-0) 

Burning sets balance to zero and removes from positions hash: [2](#0-1) 

PositionBalance stores utilization at mint time: [3](#0-2) 

New mint stores current utilization: [4](#0-3) 

RiskEngine uses maximum utilization across all positions: [5](#0-4) 

Sell collateral ratio scales from 20% to 100% based on utilization: [6](#0-5) 

Constants showing 20% base and 90% saturation thresholds: [7](#0-6) 

Duplicate check only on finalPositionIdList (not positionIdList): [8](#0-7) 

**Exploitation Path**:

1. **Preconditions**: User has existing short position TokenIdX minted when pool utilization was 90%, requiring ~100% collateral

2. **Step 1**: Pool utilization drops to 10% over time due to market conditions
   - User's stored utilization remains 90% in `s_positionBalance[user][TokenIdX]`
   - User is locked into high collateral requirements

3. **Step 2**: User calls `dispatch(positionIdList=[TokenIdX, TokenIdX], finalPositionIdList=[TokenIdX], positionSizes=[0, newSize], ...)`
   - Code path: `PanopticPool.dispatch()` loop processes positionIdList without duplicate check

4. **Step 3**: First iteration (i=0)
   - `positionBalanceData = s_positionBalance[user][TokenIdX]` (non-zero)
   - `positionSize != 0 && positionSize != positionSizes[0]` (burn triggered)
   - `_burnOptions()` called → `_updateSettlementPostBurn()` → sets `s_positionBalance[user][TokenIdX] = PositionBalance.wrap(0)`

5. **Step 4**: Second iteration (i=1)
   - `positionBalanceData = s_positionBalance[user][TokenIdX]` (now zero!)
   - Line 629 check: `PositionBalance.unwrap(positionBalanceData) == 0` → TRUE
   - `_mintOptions()` called → stores current utilization (10%) instead of historical (90%)
   - Storage state: `s_positionBalance[user][TokenIdX]` now contains utilization0=10%, utilization1=10%

6. **Step 5**: Validation passes
   - `_validateSolvency()` called with `finalPositionIdList=[TokenIdX]` (no duplicates)
   - Hash validation passes: position still exists with same tokenId
   - Solvency check uses new 10% utilization for collateral calculation

7. **Step 6**: Collateral requirement reduced 5x
   - `_getGlobalUtilization()` now returns max(10%) across positions
   - `_sellCollateralRatio(10%)` returns 20% (vs previous 100%)
   - User can withdraw 80% of collateral or open 5x larger positions

8. **Step 7**: Protocol risk
   - If market moves adversely, position becomes undercollateralized
   - Liquidation may not cover losses, creating protocol bad debt

**Security Property Broken**: 
Conservative risk management - positions minted at high utilization should maintain higher collateral requirements throughout their lifetime. This design intent is documented in how `PositionBalance` stores utilization at mint time for use in ongoing risk calculations.

**Root Cause Analysis**:
- Missing duplicate tokenId validation on `positionIdList` before the processing loop
- Zero balance check at line 629 doesn't distinguish between "never minted" and "just burned in this transaction"
- No protection against sequential burn-mint operations resetting stored risk parameters
- Duplicate validation only occurs on `finalPositionIdList` after all operations complete

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user with existing short positions
- **Resources Required**: Existing position minted during high utilization period
- **Technical Skill**: Low (simple dispatch call with duplicate tokenId)

**Preconditions**:
- **Market State**: Pool utilization must have decreased since position was originally minted (common in volatile markets)
- **Attacker State**: Must have at least one existing short position
- **Timing**: No special timing requirements

**Execution Complexity**:
- **Transaction Count**: Single `dispatch()` call
- **Coordination**: None required
- **Detection Risk**: Very low (appears as normal burn-then-mint sequence)

**Frequency**:
- **Repeatability**: Unlimited (can be performed whenever utilization decreases)
- **Scale**: Per-position basis, but affects entire portfolio's global utilization

**Overall Assessment**: High likelihood - simple to execute, strong economic incentive during utilization decreases, no special requirements, not detectable as malicious

## Recommendation

**Immediate Mitigation**:
Add duplicate validation on `positionIdList` before processing loop: [9](#0-8) 

Insert before line 610:
```solidity
// Validate no duplicates in positionIdList to prevent utilization reset attacks
if (!PanopticMath.hasNoDuplicateTokenIds(positionIdList)) {
    revert Errors.DuplicateTokenId();
}
```

**Permanent Fix**:
The existing duplicate check should be applied to both `positionIdList` and `finalPositionIdList` to prevent sequential operations on the same tokenId within a single transaction.

**Additional Measures**:
- Add invariant test verifying utilization snapshots cannot be reset through burn-remint
- Add monitoring for suspicious burn-immediately-remint patterns
- Consider time-lock mechanism preventing reminting same tokenId within same block

## Notes

This vulnerability is **not** covered by the known issues in README.md. The known issues document various accepted risks, but do not mention duplicate tokenIds in positionIdList or utilization snapshot resets through burn-remint sequences.

The vulnerability specifically exploits the design choice to separate `positionIdList` (operations to perform) from `finalPositionIdList` (expected final state), where only the latter is validated for duplicates. This creates a window for sequential burn-mint operations that bypass the conservative risk management design.

The 5x collateral reduction is mathematically accurate based on the sell collateral ratio scaling from `SELLER_COLLATERAL_RATIO` (20%) at low utilization to `DECIMALS` (100%) at `SATURATED_POOL_UTIL` (90%).

### Citations

**File:** contracts/PanopticPool.sol (L610-614)
```text
        for (uint256 i = 0; i < positionIdList.length; ) {
            TokenId tokenId = positionIdList[i];

            // make sure the tokenId is for this Panoptic pool
            if (tokenId.poolId() != poolId()) revert Errors.WrongPoolId();
```

**File:** contracts/PanopticPool.sol (L629-640)
```text
            if (PositionBalance.unwrap(positionBalanceData) == 0) {
                // revert if more than 2 conditions are triggered to prevent the minting of any positions
                if (riskParameters.safeMode() > 2) revert Errors.StaleOracle();
                uint24 effectiveLiquidityLimit = uint24(tickAndSpreadLimits[i][2]);
                (, finalTick) = _mintOptions(
                    tokenId,
                    positionSizes[i],
                    effectiveLiquidityLimit,
                    msg.sender,
                    _tickLimits,
                    riskParameters
                );
```

**File:** contracts/PanopticPool.sol (L755-766)
```text
        {
            // update the users options balance of position `tokenId`
            // NOTE: user can't mint same position multiple times, so set the positionSize instead of adding
            PositionBalance balanceData = PositionBalanceLibrary.storeBalanceData(
                positionSize,
                poolUtilizations,
                0
            );
            s_positionBalance[owner][tokenId] = balanceData;

            emit OptionMinted(owner, tokenId, balanceData);
        }
```

**File:** contracts/PanopticPool.sol (L1330-1337)
```text
        if (commitLongSettledAndKeepOpen.leftSlot() == 0) {
            // reset balances and delete stored option data
            s_positionBalance[owner][tokenId] = PositionBalance.wrap(0);

            // REMOVE the current tokenId from the position list hash (hash = XOR of all keccak256(tokenId), remove by XOR'ing again)
            // and decrease the number of positions counter by 1.
            _updatePositionsHash(owner, tokenId, !ADD, riskParameters.maxLegs());
        }
```

**File:** contracts/PanopticPool.sol (L1829-1840)
```text
    function _validatePositionList(
        address account,
        TokenId[] calldata positionIdList
    ) internal view {
        uint256 pLength = positionIdList.length;

        uint256 fingerprintIncomingList;

        // verify it has no duplicated elements
        if (!PanopticMath.hasNoDuplicateTokenIds(positionIdList)) {
            revert Errors.DuplicateTokenId();
        }
```

**File:** contracts/types/PositionBalance.sol (L11-22)
```text
// PACKING RULES FOR A POSITIONBALANCE:
// =================================================================================================
//  From the LSB to the MSB:
// (1) positionSize     128bits : The size of this position (uint128).
// (2) poolUtilization0 16bits  : The pool utilization of token0, stored as (10000 * inAMM0)/totalAssets0 (uint16).
// (3) poolUtilization1 16bits  : The pool utilization of token1, stored as (10000 * inAMM1)/totalAssets1 (uint16).
// (4) currentTick      24bits  : The currentTick at mint (int24).
// (5) fastOracleTick   24bits  : The fastOracleTick at mint (int24).
// (6) slowOracleTick   24bits  : The slowOracleTick at mint (int24).
// (7) lastObservedTick 24bits  : The lastObservedTick at mint (int24).
// Total                256bits : Total bits used by a PositionBalance.
// ===============================================================================================
```

**File:** contracts/RiskEngine.sol (L125-147)
```text

    /// @notice Required collateral ratios for selling options, fraction of 1, scaled by 10_000_000.
    /// @dev i.e 20% -> 0.2 * 10_000_000 = 2_000_000.
    uint256 constant SELLER_COLLATERAL_RATIO = 2_000_000;

    /// @notice Required collateral ratios for buying options, fraction of 1, scaled by 10_000_000.
    /// @dev i.e 10% -> 0.1 * 10_000_000 = 1_000_000.
    uint256 constant BUYER_COLLATERAL_RATIO = 1_000_000;

    /// @notice Required collateral margin for loans in excess of notional, fraction of 1, scaled by 10_000_000.
    uint256 constant MAINT_MARGIN_RATE = 2_000_000;

    /// @notice Basal cost (in bps of notional) to force exercise an out-of-range position.
    uint256 constant FORCE_EXERCISE_COST = 102_400;

    // Targets a pool utilization (balance between buying and selling)
    /// @notice Target pool utilization below which buying+selling is optimal, fraction of 1, scaled by 10_000_000.
    /// @dev i.e 50% -> 0.5 * 10_000_000 = 5_000_000.
    uint256 constant TARGET_POOL_UTIL = 5_000_000;

    /// @notice Pool utilization above which selling is 100% collateral backed, fraction of 1, scaled by 10_000_000.
    /// @dev i.e 90% -> 0.9 * 10_000_000 = 9_000_000.
    uint256 constant SATURATED_POOL_UTIL = 9_000_000;
```

**File:** contracts/RiskEngine.sol (L1201-1227)
```text
        int256 utilization0;
        int256 utilization1;
        uint256 pLength = positionBalanceArray.length;

        for (uint256 i; i < pLength; ) {
            PositionBalance positionBalance = positionBalanceArray[i];

            int256 _utilization0 = positionBalance.utilization0();
            int256 _utilization1 = positionBalance.utilization1();

            // utilizations are always positive, so can compare directly here
            utilization0 = _utilization0 > utilization0 ? _utilization0 : utilization0;
            utilization1 = _utilization1 > utilization1 ? _utilization1 : utilization1;
            unchecked {
                ++i;
            }
        }

        unchecked {
            // can never miscast because utilization < 10_000
            globalUtilizations = PositionBalanceLibrary.storeBalanceData(
                0,
                uint32(uint256(utilization0) + (uint256(utilization1) << 16)),
                0
            );
        }
    }
```

**File:** contracts/RiskEngine.sol (L2047-2097)
```text
    function _sellCollateralRatio(
        int256 utilization
    ) internal view returns (uint256 sellCollateralRatio) {
        // the sell ratio is on a straight line defined between two points (x0,y0) and (x1,y1):
        //   (x0,y0) = (targetPoolUtilization,min_sell_ratio) and
        //   (x1,y1) = (saturatedPoolUtilization,max_sell_ratio)
        // the line's formula: y = a * (x - x0) + y0, where a = (y1 - y0) / (x1 - x0)
        /*
            SELL
            COLLATERAL
            RATIO
                          ^
                          |                  max ratio = 100%
                   100% - |                _------
                          |             _-¯
                          |          _-¯
                    20% - |---------¯
                          |         .       . .
                          +---------+-------+-+--->   POOL_
                                   50%    90% 100%     UTILIZATION
        */

        uint256 min_sell_ratio = SELLER_COLLATERAL_RATIO;
        /// if utilization is less than zero, this is the calculation for a strangle, which gets 2x the capital efficiency at low pool utilization
        if (utilization < 0) {
            unchecked {
                min_sell_ratio /= 2;
                utilization = -utilization;
            }
        }

        unchecked {
            utilization *= 1_000;
        }
        // return the basal sell ratio if pool utilization is lower than target
        if (uint256(utilization) < TARGET_POOL_UTIL) {
            return min_sell_ratio;
        }

        // return 100% collateral ratio if utilization is above saturated pool utilization
        if (uint256(utilization) > SATURATED_POOL_UTIL) {
            return DECIMALS;
        }

        unchecked {
            return
                min_sell_ratio +
                ((DECIMALS - min_sell_ratio) * (uint256(utilization) - TARGET_POOL_UTIL)) /
                (SATURATED_POOL_UTIL - TARGET_POOL_UTIL);
        }
    }
```
