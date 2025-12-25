# Validation Result: VALID CRITICAL VULNERABILITY

## Title
BorrowIndex Truncation After Exceeding 80-Bit Storage Limit Causes Permanent Interest Accounting Failure

## Summary
The `borrowIndex` in `CollateralTracker` is calculated as `uint128` but stored in an 80-bit field within the packed `MarketState` structure without validation. After approximately 1.75 years at maximum interest rates (800% APY), the index exceeds 2^80, causing silent truncation that breaks the documented monotonicity invariant and permanently corrupts interest accounting across the entire protocol.

## Impact
**Severity**: Critical  
**Category**: Protocol Insolvency + Permanent State Corruption

**Concrete Impact**:
- **Complete breakdown of interest accounting**: All users with `netBorrows > 0` will have their interest calculations revert or return zero when `currentBorrowIndex` (truncated) < `userBorrowIndex` (pre-overflow)
- **Protocol insolvency**: Lenders lose all unrealized interest accumulated over 1.75 years
- **Permanent state corruption**: The `borrowIndex` cannot be recovered without contract upgrades, and the protocol uses non-upgradeable Clone pattern
- **Secondary corruption**: Overflow bits corrupt the adjacent `marketEpoch` field (bits 80-111), breaking epoch-based calculations
- **Affected parties**: All users across all CollateralTracker instances once any single vault reaches the time threshold

## Finding Description

**Location**: Multiple files showing the vulnerability chain

**Storage Declaration**: [1](#0-0) 

**Calculation Path**: [2](#0-1) 

**Unsafe Storage Without Validation**: [3](#0-2) 

**Truncation on Retrieval**: [4](#0-3) 

**Interest Calculation Failure Point**: [5](#0-4) 

**Intended Logic**: The `borrowIndex` should monotonically increase from 1e18 (WAD) and track compound interest growth over time. The protocol documentation explicitly states this invariant: [6](#0-5) 

**Actual Logic**: The vulnerability exists in the storage path:

1. `_calculateCurrentInterestState()` calculates `currentBorrowIndex` as `uint128` without any bounds checking
2. The calculation uses `Math.mulDivWadRoundingUp(currentBorrowIndex, _borrowIndex)` which compounds the index
3. `_accrueInterest()` calls `storeMarketState(currentBorrowIndex, ...)` passing the `uint128` value
4. `storeMarketState()` accepts `uint256 _borrowIndex` and uses assembly addition without masking or validation
5. When `currentBorrowIndex > 2^80`, the high bits (bits 80-127) overflow into the `marketEpoch` field (bits 80-111)
6. When retrieved via `borrowIndex()`, the value is masked to 80 bits: `and(self, 0xFFFFFFFFFFFFFFFFFFFF)`
7. This returns a drastically smaller value, breaking monotonicity

**Test Suite Confirmation**: The protocol's own test suite validates this overflow occurs at the expected timeframe but includes no handling: [7](#0-6) 

**Exploitation Path**:

1. **Preconditions**: Protocol operates normally for 1.75 years with sustained high utilization (80-90%) maintaining ~800% interest rates
2. **Step 1 - Overflow Occurs**: 
   - Global `borrowIndex` compounds from 1e18 to exceed 2^80 (≈1.2089e24)
   - User Alice has `userBorrowIndex = 1.15e24` recorded from her last interaction
   - Storage: `currentBorrowIndex = 1.25e24` calculated but only lower 80 bits stored
3. **Step 2 - Retrieval Truncation**:
   - `borrowIndex()` masks to 80 bits, returning `currentBorrowIndex ≈ 4.2e22` (example truncated value)
   - Alice's stored `userBorrowIndex = 1.15e24` > retrieved `currentBorrowIndex = 4.2e22`
4. **Step 3 - Interest Calculation Failure**:
   - Any operation calling `_accrueInterest(Alice, ...)` attempts to calculate interest
   - `_getUserInterest()` computes `currentBorrowIndex - userBorrowIndex`
   - This underflows: `4.2e22 - 1.15e24` causes revert (kept checked at line 1074)
5. **Step 4 - Protocol-Wide Breakdown**:
   - Alice cannot withdraw, transfer, or close positions (all call `_accrueInterest`)
   - All users with `userBorrowIndex` from before overflow are similarly bricked
   - New deposits/withdrawals fail due to interest settlement requirements
   - Protocol enters permanent DoS state with trapped collateral

**Security Property Broken**: [8](#0-7) 

The invariant "The global `borrowIndex` must be monotonically increasing over time and start at 1e18 (WAD)" is violated when the truncated value appears to drastically decrease.

**Root Cause Analysis**:
- **Design flaw**: 80-bit storage chosen for gas optimization but insufficient for perpetual operation
- **Missing validation**: `storeMarketState()` accepts `uint256` but should enforce 80-bit limit or revert
- **Type safety bypass**: Safe `updateBorrowIndex(uint80)` function exists but is unused in production path
- **No upgrade mechanism**: Protocol uses Clone pattern without upgradeability, making recovery impossible
- **Acknowledged but unhandled**: Code comments acknowledge the limit but include no safeguards

## Impact Explanation

**Affected Assets**: All collateral assets (ETH, USDC, etc.) in every CollateralTracker vault

**Damage Severity**:
- **Quantitative**: For a protocol with $10M in borrowed assets at 800% APY over 1.75 years, theoretical compounded interest is massive. All becomes unrecoverable.
- **Qualitative**: Complete loss of protocol functionality. All interest accounting permanently corrupted. Users cannot interact with their positions.

**User Impact**:
- **Who**: All users with outstanding borrows, all lenders expecting interest, all LPs
- **Conditions**: Triggered deterministically after ~1.75 years at maximum rates, sooner at lower update frequencies
- **Recovery**: Impossible without contract replacement, but Clone pattern makes migration complex

**Systemic Risk**:
- **No graceful degradation**: Protocol instantly transitions from functional to completely broken
- **Cross-vault contamination**: Once time threshold reached, affects all operations protocol-wide
- **Detection difficulty**: Silent corruption - no events emitted, appears as normal operation until retrieval

## Likelihood Explanation

**Attacker Profile**: N/A - This is not an active exploit but a deterministic time-based failure

**Preconditions**:
- **Market State**: Sustained high utilization (80-90%) for extended period
- **Time Requirement**: Approximately 1.75 years at maximum 800% interest rate
- **Protocol State**: Normal operation with no intervention

**Execution Complexity**: N/A - Occurs automatically through time and compound interest

**Frequency**:
- **Inevitability**: WILL occur if protocol operates long enough at high rates
- **Timeframe variance**: Longer at lower rates/utilization, shorter at maximum rates
- **Update frequency impact**: More frequent interest updates slightly extend timeline

**Overall Assessment**: Medium-High likelihood. While requiring extended time, this is a **deterministic** failure mode for a protocol designed for perpetual operation. No mitigation exists, and the impact is catastrophic.

## Recommendation

**Immediate Mitigation**:
Add validation to prevent storing values exceeding 80 bits: [3](#0-2) 

Replace with:
```solidity
function storeMarketState(
    uint256 _borrowIndex,
    uint256 _marketEpoch,
    uint256 _rateAtTarget,
    uint256 _unrealizedInterest
) internal pure returns (MarketState result) {
    require(_borrowIndex <= type(uint80).max, "BorrowIndex exceeds 80-bit limit");
    // ... rest of function
}
```

**Permanent Fix**:
1. **Expand storage**: Increase `borrowIndex` to 128 bits by reorganizing `MarketState` packing
2. **Use type-safe setter**: Replace `storeMarketState` with `updateBorrowIndex(uint80)` in production path
3. **Add circuit breaker**: Implement emergency pause when approaching limit
4. **Migration path**: Design upgrade mechanism for CollateralTracker instances

**Additional Measures**:
- Monitoring: Alert when `borrowIndex` exceeds 75% of 2^80 limit
- Governance action: Protocol parameter adjustment before reaching limit
- Documentation: Clearly state operational time limits based on market conditions

**Validation**:
- ✓ Fix prevents overflow by reverting before corruption
- ✓ Provides clear error message for debugging
- ✓ Minimal gas overhead (single comparison)
- ⚠ Requires protocol redeployment or migration strategy

## Notes

This vulnerability is **exceptionally rare** in that it's:
1. **Documented but unmitigated**: Code comments acknowledge the 80-bit limit but include no validation
2. **Test-confirmed**: Protocol's own tests validate the overflow timeline
3. **Invariant-breaking**: Explicitly violates documented protocol invariants
4. **Time-deterministic**: Not an active exploit but inevitable protocol failure
5. **Unrecoverable**: Clone pattern prevents upgrades, making this a permanent limitation

The severity is Critical despite the long timeframe because:
- Protocol is designed for **perpetual operation**
- Failure is **deterministic and inevitable** at high utilization
- Impact is **total protocol breakdown**
- **No recovery mechanism** exists
- Breaks **explicitly documented invariants**

This represents a fundamental design limitation that should be addressed before mainnet deployment.

### Citations

**File:** contracts/types/MarketState.sol (L14-14)
```text
// (0) borrowIndex          80 bits : Global borrow index in WAD (starts at 1e18). 2**80 = 1.75 years at 800% interest
```

**File:** contracts/types/MarketState.sol (L59-71)
```text
    function storeMarketState(
        uint256 _borrowIndex,
        uint256 _marketEpoch,
        uint256 _rateAtTarget,
        uint256 _unrealizedInterest
    ) internal pure returns (MarketState result) {
        assembly {
            result := add(
                add(add(_borrowIndex, shl(80, _marketEpoch)), shl(112, _rateAtTarget)),
                shl(150, _unrealizedInterest)
            )
        }
    }
```

**File:** contracts/types/MarketState.sol (L155-159)
```text
    function borrowIndex(MarketState self) internal pure returns (uint80 result) {
        assembly {
            result := and(self, 0xFFFFFFFFFFFFFFFFFFFF)
        }
    }
```

**File:** contracts/CollateralTracker.sol (L985-1026)
```text
    function _calculateCurrentInterestState(
        uint128 _assetsInAMM,
        uint128 interestRateSnapshot
    )
        internal
        view
        returns (
            uint128 currentBorrowIndex,
            uint128 _unrealizedGlobalInterest,
            uint256 currentEpoch
        )
    {
        MarketState accumulator = s_marketState;

        currentEpoch = block.timestamp >> 2;
        uint256 previousEpoch = accumulator.marketEpoch();
        uint128 deltaTime;
        unchecked {
            deltaTime = uint32(currentEpoch - previousEpoch) << 2;
        }
        currentBorrowIndex = accumulator.borrowIndex();
        _unrealizedGlobalInterest = accumulator.unrealizedInterest();
        if (deltaTime > 0) {
            // Calculate interest growth
            uint128 rawInterest = (Math.wTaylorCompounded(interestRateSnapshot, uint128(deltaTime)))
                .toUint128();
            // Calculate interest owed on borrowed amount

            uint128 interestOwed = Math.mulDivWadRoundingUp(_assetsInAMM, rawInterest).toUint128();

            // keep checked to prevent overflows
            _unrealizedGlobalInterest += interestOwed;

            // Update borrow index
            unchecked {
                uint128 _borrowIndex = (WAD + rawInterest).toUint128();
                currentBorrowIndex = Math
                    .mulDivWadRoundingUp(currentBorrowIndex, _borrowIndex)
                    .toUint128();
            }
        }
    }
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

**File:** README.md (L380-384)
```markdown
- The global `borrowIndex` must be monotonically increasing over time and start at 1e18 (WAD)
- For any user with `netBorrows > 0`, their `userBorrowIndex` must be ≤ the current global `borrowIndex`
- Interest owed by a user must equal: `netBorrows * (currentBorrowIndex - userBorrowIndex) / userBorrowIndex`
- `unrealizedGlobalInterest` must never exceed the sum of all individual users' interest owed
- After `_accrueInterest()`, the user's `userBorrowIndex` must equal the current global `borrowIndex` (unless insolvent and unable to pay)
```

**File:** test/foundry/libraries/Math.t.sol (L396-404)
```text
        // update every block until it is larger than 2**80
        uint256 iterations;
        borrowIndex = 1e18;
        while (borrowIndex < 2 ** 80) {
            uint256 rawInterest = Math.wTaylorCompounded(x1, n1);
            borrowIndex = Math.mulDivWadRoundingUp(borrowIndex, 1e18 + rawInterest);
            iterations++;
        }
        assertEq(iterations, 4600723, "Update at every block"); // Overflow after 4600723/365/243600*12 = 1.75years at the max possible rate if the price is updated at every block
```
