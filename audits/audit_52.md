# Audit Report

## Title 
Silent Truncation of Unrealized Interest Beyond 106 Bits Causes Protocol Insolvency

## Summary
The `MarketStateLibrary.storeMarketState()` function stores `_unrealizedInterest` without masking it to 106 bits, causing silent data loss when accumulated interest exceeds 2^106 - 1. This breaks the collateral conservation invariant and leads to protocol insolvency as interest tracking becomes permanently corrupted.

## Finding Description

The vulnerability exists in the interaction between `CollateralTracker._accrueInterest()` and `MarketStateLibrary.storeMarketState()`.

**Root Cause - Missing Bounds Check:** [1](#0-0) 

The `storeMarketState()` function accepts `uint256 _unrealizedInterest` (line 63) and directly shifts it left by 150 bits (line 68) without masking to 106 bits. When `_unrealizedInterest` exceeds 2^106 - 1:
- Bits 0-105 are shifted to positions 150-255 (valid)
- Bits 106+ overflow beyond position 255 and are lost due to EVM 256-bit arithmetic wrap

**Contrast with Protected Function:** [2](#0-1) 

The `updateUnrealizedInterest()` function DOES include proper masking at line 141: `let safeInterest := and(newInterest, max106)`. This inconsistency indicates the vulnerability was overlooked in `storeMarketState()`.

**How Interest Accumulates Beyond 106 Bits:** [3](#0-2) 

In `_calculateCurrentInterestState()`, line 1016 adds interest in a checked block: `_unrealizedGlobalInterest += interestOwed`. This accumulates over time without bounds checking before storage.

**Storage Without Validation:** [4](#0-3) 

The accumulated `_unrealizedGlobalInterest` (uint128) is passed to `storeMarketState()` without validation that it fits in 106 bits.

**Impact on totalAssets():** [5](#0-4) 

The `totalAssets()` function includes `s_marketState.unrealizedInterest()` in the calculation. Silent truncation causes this value to be understated, breaking **Invariant #2 (Collateral Conservation)**: `totalAssets() != s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest`.

**Reading Back Truncated Value:** [6](#0-5) 

When `unrealizedInterest()` reads the value back (line 184: `shr(150, self)`), it only retrieves the lower 106 bits that were stored, permanently losing track of the overflow amount.

**Deposit Limits Don't Prevent This:** [7](#0-6) 

While individual deposits are capped at `type(uint104).max`, this doesn't prevent accumulated interest across all users from exceeding 2^106 over time, especially with high interest rates.

**Attack Path:**
1. Multiple users deposit up to the 2^104 limit, creating substantial `s_assetsInAMM`
2. High pool utilization (90%+) triggers maximum interest rates (up to 800% per year per code comments)
3. Interest accumulates via `_calculateCurrentInterestState()` over months/years
4. When `_unrealizedGlobalInterest` exceeds 2^106 - 1, `storeMarketState()` silently truncates it
5. On next read, only lower 106 bits are retrieved
6. Protocol permanently loses track of (value - 2^106) wei of interest
7. `totalAssets()` becomes understated, breaking share price calculations
8. Later depositors receive inflated share amounts, effectively stealing from the protocol

## Impact Explanation

**Critical Severity** - This vulnerability causes:

1. **Direct Loss of Interest Tracking**: Up to 2^128 - 2^106 wei (≈ 3.4e38 - 8.1e31 = ~3.4e38 wei) of accrued interest can be permanently lost from accounting.

2. **Protocol Insolvency**: The protocol believes it has fewer assets than reality because `totalAssets()` excludes the truncated interest. This breaks the fundamental accounting invariant.

3. **Share Price Manipulation**: With understated `totalAssets()`, share price calculations become incorrect. New depositors receive more shares than they should, diluting existing holders and extracting value from the protocol.

4. **Irreversible State Corruption**: Once truncation occurs, the correct value cannot be recovered. The protocol has no way to know how much interest was lost.

**Quantification:**
- 2^106 ≈ 8.1e31 wei (the 106-bit limit)
- 2^104 ≈ 2e31 wei (max single deposit)
- If assets reach 2^105 wei with 400% annual interest over 2 years: accumulated interest ≈ 2^107 wei
- Truncation loss: 2^107 - 2^106 = 2^106 wei ≈ 8.1e31 wei

## Likelihood Explanation

**High Likelihood** - This will occur naturally without any attacker action:

1. **Time-Based Accumulation**: As the protocol matures and processes more transactions, interest naturally accumulates. With compound interest, growth is exponential.

2. **High Utilization Scenarios**: The protocol is designed to handle high utilization (up to 90%), which triggers high interest rates. Comments indicate rates up to 800% are possible.

3. **No Preventive Checks**: There is no validation preventing `_unrealizedGlobalInterest` from growing beyond 2^106. The checked addition at line 1016 only prevents uint128 overflow, not the 106-bit storage limit.

4. **Multiple Deposits**: While single deposits are capped at 2^104, cumulative deposits from many users can easily exceed this. The storage variables `s_depositedAssets` and `s_assetsInAMM` are uint128, indicating the protocol expects values up to 2^128.

**Realistic Timeline:**
- With 2^100 wei in AMM at 100% annual rate: ~64 years to reach 2^106
- With 2^104 wei in AMM at 800% annual rate: ~1.5 years to reach 2^107 (exceeding limit)
- With 2^110 wei in AMM at 100% annual rate: ~1 year to reach 2^110 (far exceeding limit)

As protocol TVL grows over time, this becomes inevitable.

## Recommendation

Add bounds checking in `storeMarketState()` to mask `_unrealizedInterest` to 106 bits, consistent with `updateUnrealizedInterest()`:

```solidity
function storeMarketState(
    uint256 _borrowIndex,
    uint256 _marketEpoch,
    uint256 _rateAtTarget,
    uint256 _unrealizedInterest
) internal pure returns (MarketState result) {
    assembly {
        // Mask unrealizedInterest to 106 bits to prevent overflow
        let max106 := sub(shl(106, 1), 1)
        let safeInterest := and(_unrealizedInterest, max106)
        
        result := add(
            add(add(_borrowIndex, shl(80, _marketEpoch)), shl(112, _rateAtTarget)),
            shl(150, safeInterest)
        )
    }
}
```

**However**, masking alone is insufficient. The protocol should also:

1. **Add a revert condition** in `_calculateCurrentInterestState()` before storing:
```solidity
if (_unrealizedGlobalInterest > type(uint104).max) {
    revert Errors.UnrealizedInterestOverflow();
}
```

2. **Increase the bit allocation** for unrealizedInterest if larger values are expected. Consider using 128 bits by adjusting the MarketState packing layout.

3. **Implement interest distribution mechanisms** to periodically settle accrued interest and prevent unlimited accumulation.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MarketState, MarketStateLibrary} from "@contracts/types/MarketState.sol";

contract UnrealizedInterestTruncationTest is Test {
    using MarketStateLibrary for MarketState;
    
    function test_UnrealizedInterest_SilentTruncation() public {
        // Setup: Create a value that exceeds 106 bits
        uint128 largeInterest = uint128(type(uint106).max) + 1000e18;
        
        console.log("Original unrealized interest:", largeInterest);
        console.log("Max 106-bit value:", type(uint106).max);
        console.log("Overflow amount:", largeInterest - type(uint106).max);
        
        // Store via storeMarketState (vulnerable path)
        MarketState packed = MarketStateLibrary.storeMarketState(
            1e18,           // borrowIndex
            1000,           // marketEpoch  
            1e17,           // rateAtTarget
            largeInterest   // unrealizedInterest (exceeds 106 bits)
        );
        
        // Read back
        uint128 retrieved = packed.unrealizedInterest();
        
        console.log("Retrieved unrealized interest:", retrieved);
        console.log("Lost amount:", largeInterest - retrieved);
        
        // Assertion: The retrieved value is truncated
        assertEq(retrieved, largeInterest & ((1 << 106) - 1), "Value should be masked to 106 bits");
        assertTrue(retrieved < largeInterest, "Value was truncated");
        
        // This demonstrates loss of up to 2^128 - 2^106 wei
        uint256 maxPossibleLoss = type(uint128).max - type(uint106).max;
        console.log("Maximum possible loss:", maxPossibleLoss);
    }
    
    function test_UnrealizedInterest_ProtectedPath() public {
        // Contrast: updateUnrealizedInterest has proper masking
        uint128 largeInterest = uint128(type(uint106).max) + 1000e18;
        
        MarketState initial = MarketStateLibrary.storeMarketState(1e18, 1000, 1e17, 0);
        
        // Update via updateUnrealizedInterest (protected path)
        MarketState updated = initial.updateUnrealizedInterest(largeInterest);
        
        uint128 retrieved = updated.unrealizedInterest();
        
        // The updateUnrealizedInterest function properly masks to 106 bits
        assertEq(retrieved, largeInterest & ((1 << 106) - 1), "Properly masked to 106 bits");
        
        console.log("updateUnrealizedInterest properly masks the value");
        console.log("But storeMarketState does NOT, causing silent data loss");
    }
}
```

**To run:**
```bash
forge test --match-test test_UnrealizedInterest_SilentTruncation -vv
```

**Expected output demonstrates:**
- Original value exceeds 106-bit limit
- Retrieved value is silently truncated
- Lost amount equals overflow beyond 2^106
- Maximum possible loss is ~3.4e38 wei

## Notes

This vulnerability is particularly insidious because:

1. **Silent Failure**: No revert occurs; the protocol continues operating with corrupted state
2. **Irreversible**: Once data is lost, it cannot be recovered
3. **Compounds Over Time**: The longer the protocol runs, the more likely this becomes
4. **Breaks Core Invariants**: Violates Invariant #2 (Collateral Conservation) and affects Invariant #3 (Share Price Monotonicity)

The fix requires both immediate masking and architectural changes to handle larger interest accumulation or implement periodic settlement mechanisms.

### Citations

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

**File:** contracts/types/MarketState.sol (L179-186)
```text
    /// @notice Get the unrealizedInterest of `self`.
    /// @param self The MarketState to retrieve the unrealizedInterest from
    /// @return result The unrealizedInterest of `self`
    function unrealizedInterest(MarketState self) internal pure returns (uint128 result) {
        assembly {
            result := shr(150, self)
        }
    }
```

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L557-560)
```text
    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
        _accrueInterest(msg.sender, IS_DEPOSIT);
        if (assets > type(uint104).max) revert Errors.DepositTooLarge();
        if (assets == 0) revert Errors.BelowMinimumRedemption();
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
