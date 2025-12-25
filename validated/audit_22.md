# Security Validation Report

## Verdict: **VALID VULNERABILITY** (Medium Severity)

---

## Summary

The report identifies a **legitimate design flaw** in the `MarketStateLibrary.storeMarketState()` function that lacks bounds checking when storing `_unrealizedInterest`, while the parallel `updateUnrealizedInterest()` function includes proper 106-bit masking. This inconsistency creates a potential for silent data truncation when accumulated interest exceeds 2^106 - 1, violating the protocol's collateral conservation invariant.

However, the **practical exploitability is limited** due to extreme preconditions requiring either astronomical token amounts or multi-year accumulation periods at maximum interest rates.

---

## Technical Validation

### ✅ Code Evidence Confirmed

**1. Missing Bounds Check in `storeMarketState()`** [1](#0-0) 

The function directly shifts `_unrealizedInterest` left by 150 bits without masking to 106 bits. When input exceeds 2^106 - 1, bits beyond position 105 are shifted past position 255 and lost.

**2. Proper Masking in `updateUnrealizedInterest()`** [2](#0-1) 

This function correctly masks the input to 106 bits before shifting, showing clear inconsistency with `storeMarketState()`.

**3. Uncapped Interest Accumulation** [3](#0-2) 

Interest accumulates into a uint128 variable via checked addition without validation against the 106-bit storage limit.

**4. Storage Without Validation** [4](#0-3) 

The uint128 `_unrealizedGlobalInterest` is passed directly to `storeMarketState()` without bounds checking.

**5. Impact on `totalAssets()` Invariant** [5](#0-4) 

The function includes `unrealizedInterest()` in its calculation. Truncation would understate this value, breaking the documented invariant: `totalAssets() = s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest`.

**6. Truncated Read-Back** [6](#0-5) 

Reading returns only the lower 106 bits stored, permanently losing track of overflow amounts.

---

## Invariant Violation

The vulnerability breaks the **Collateral Conservation Invariant** documented in the protocol: [7](#0-6) 

The comment states "max deposit is 2**104" as context for the 106-bit allocation, suggesting 4x headroom. However, cumulative deposits from multiple users can exceed 2^104, and compound interest over time can push accumulated interest beyond 2^106.

---

## Scope Compliance

✅ **In-Scope Contracts:**
- `contracts/types/MarketState.sol` (65 nSLOC) - Type library
- `contracts/CollateralTracker.sol` (863 nSLOC) - Core protocol

✅ **Not a Known Issue:** 
The README acknowledges premium accumulation capping [8](#0-7) , but this refers to premium, not interest accumulation. The unrealizedInterest truncation issue is not listed in known issues.

✅ **No Trust Model Violations:** 
Does not require Uniswap pool or oracle compromise.

---

## Practical Exploitability Assessment

### Likelihood: **LOW**

While the code flaw is real, triggering it requires:

1. **Extreme Asset Accumulation**: Storage uses uint128 [9](#0-8) , supporting up to 2^128 wei. However, individual deposits are capped [10](#0-9)  at 2^104.

2. **Extended Time Horizon**: With maximum interest rates (800% per year per comments [11](#0-10) ), reaching 2^106 in accumulated interest requires either:
   - Cumulative deposits approaching 2^105 wei sustained over 1-2 years at 800% APR
   - Longer periods at lower rates

3. **Token Economics**: For standard 18-decimal tokens, 2^104 wei ≈ 2e13 tokens, which is astronomically large but technically within the uint128 design space.

### Impact: **MEDIUM** (if triggered)

If triggered, consequences include:
- **Permanent accounting corruption**: Lost interest cannot be recovered
- **Understated `totalAssets()`**: Share price calculations become incorrect
- **Protocol insolvency risk**: Actual liabilities exceed recorded values
- **No direct theft vector**: Existing users don't gain, but new depositors receive inflated shares

---

## Severity Justification: MEDIUM

**Rationale for downgrade from Critical:**

1. **Time-gated vulnerability**: Requires months to years of accumulation under sustained high utilization
2. **Detectable before critical**: Monitoring `unrealizedGlobalInterest` approaching 2^106 would provide early warning
3. **No immediate exploit**: Cannot be triggered atomically or through position manipulation
4. **Limited by economic reality**: Requires protocol TVL growth to extreme levels

**Why not downgrade further:**
1. **Clear code inconsistency**: Demonstrates oversight in implementation
2. **Invariant violation**: Breaks documented protocol guarantee
3. **Irreversible if triggered**: No recovery mechanism exists
4. **Design flaw**: 106-bit allocation insufficient for uint128 asset design

---

## Notes

This finding represents a **legitimate edge-case vulnerability** stemming from mismatched design assumptions:
- The protocol allocates 106 bits for unrealizedInterest storage
- Assets use uint128 storage (128 bits)
- Individual deposits limited to 2^104, providing only 4x headroom
- Compound interest over years can exceed this headroom

The inconsistency between `storeMarketState()` (no masking) and `updateUnrealizedInterest()` (proper masking) indicates this was likely an oversight rather than intentional design.

**Recommended Fix:** Add bounds checking in `storeMarketState()` or increase storage allocation for unrealizedInterest to match the uint128 asset scale. The simpler fix is to add masking to `storeMarketState()` consistent with `updateUnrealizedInterest()`.

The severity assessment balances the **real technical flaw** against the **extreme preconditions required** for practical exploitation, landing at Medium rather than Critical severity.

### Citations

**File:** contracts/types/MarketState.sol (L14-16)
```text
// (0) borrowIndex          80 bits : Global borrow index in WAD (starts at 1e18). 2**80 = 1.75 years at 800% interest
// (1) marketEpoch          32 bits : Last interaction epoch for that market (1 epoch = block.timestamp/4)
// (2) rateAtTarget         38 bits : The rateAtTarget value in WAD (2**38 = 800% interest rate)
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

**File:** contracts/types/MarketState.sol (L130-146)
```text
    function updateUnrealizedInterest(
        MarketState self,
        uint128 newInterest
    ) internal pure returns (MarketState result) {
        assembly {
            // 1. Clear bits 150-255
            let cleared := and(self, not(UNREALIZED_INTEREST_MASK))

            // 2. Safety: Mask input to 106 bits
            //    (1 << 106) - 1
            let max106 := sub(shl(106, 1), 1)
            let safeInterest := and(newInterest, max106)

            // 3. Shift to 150 and combine
            result := or(cleared, shl(150, safeInterest))
        }
    }
```

**File:** contracts/types/MarketState.sol (L182-186)
```text
    function unrealizedInterest(MarketState self) internal pure returns (uint128 result) {
        assembly {
            result := shr(150, self)
        }
    }
```

**File:** contracts/CollateralTracker.sol (L129-132)
```text
    uint128 internal s_depositedAssets;

    /// @notice Amount of assets moved from the Panoptic Pool to the AMM.
    uint128 internal s_assetsInAMM;
```

**File:** contracts/CollateralTracker.sol (L233-233)
```text
    ///      - Left slot (106 bits): Accumulated unrealized interest that hasn't been distributed (max deposit is 2**104)
```

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L559-559)
```text
        if (assets > type(uint104).max) revert Errors.DepositTooLarge();
```

**File:** contracts/CollateralTracker.sol (L970-975)
```text
        s_marketState = MarketStateLibrary.storeMarketState(
            currentBorrowIndex,
            currentEpoch,
            s_marketState.rateAtTarget(),
            _unrealizedGlobalInterest
        );
```

**File:** contracts/CollateralTracker.sol (L1006-1026)
```text
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

**File:** README.md (L80-80)
```markdown
- Premium accumulation can become permanently capped if the accumulator exceeds the maximum value; this can happen if a low amount of liquidity earns a large amount of (token) fees
```
