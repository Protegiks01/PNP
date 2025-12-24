# Audit Report

## Title 
BorrowIndex Overflow Corrupts MarketEpoch Leading to Negative Elapsed Time Calculations

## Summary
The `storeMarketState()` function in `MarketState.sol` does not mask input parameters before packing them into the 256-bit storage structure. When the global `borrowIndex` exceeds its 80-bit allocation after approximately 1.75 years at maximum interest rates, the overflow bits corrupt the adjacent `marketEpoch` field. This corrupted epoch causes `RiskEngine._borrowRate()` to calculate negative elapsed time, breaking interest rate calculations protocol-wide.

## Finding Description

The vulnerability stems from improper bit packing in the MarketState structure. [1](#0-0) 

The `borrowIndex` is documented to occupy 80 bits (bits 0-79) and is explicitly noted to overflow after 1.75 years at 800% interest rates. [2](#0-1) 

However, the `storeMarketState()` function accepts `uint256` parameters and performs no masking before packing: [3](#0-2) 

When `CollateralTracker._accrueInterest()` stores the market state, it passes a `uint128 currentBorrowIndex` that can grow beyond the 80-bit limit: [4](#0-3) 

The borrowIndex compounds continuously via: [5](#0-4) 

Once `borrowIndex` exceeds `2^80 - 1` (≈ 1.209e24), the excess bits (bits 80+) overflow into the `marketEpoch` field (bits 80-111) during the addition in `storeMarketState()`. This corrupts the stored epoch value.

When `RiskEngine._borrowRate()` later reads this corrupted epoch and converts it to timestamp: [6](#0-5) 

The inflated `previousTime` exceeds the current `block.timestamp`, causing the elapsed time calculation to produce a large negative value: [7](#0-6) 

The `Math.min()` function returns the negative value (since it's smaller than `IRM_MAX_ELAPSED_TIME`), allowing it to propagate into interest rate calculations: [8](#0-7) 

This breaks the fundamental assumption that elapsed time should be non-negative, as indicated by the comment: [9](#0-8) 

## Impact Explanation

**Severity: HIGH**

This vulnerability causes system-wide interest rate calculation failures affecting all protocol users:

1. **Broken Interest Rate Model**: Negative elapsed time causes `linearAdaptation = speed * elapsed` to become negative (line 2222 in RiskEngine.sol), fundamentally breaking the adaptive interest rate mechanism
2. **Unpredictable Interest Accrual**: Interest calculations become non-deterministic and potentially exploitable
3. **Collateral System Failure**: Since interest rates determine borrowing costs and collateral requirements, this affects liquidation thresholds and solvency checks
4. **No Recovery Path**: Once corrupted, the system has no mechanism to detect or recover from the invalid state

**Invariants Broken**:
- **Interest Index Monotonicity** (Invariant #4): The overflow breaks the monotonic increase assumption
- **Interest Accuracy** (Invariant #21): Interest calculations become incorrect due to negative elapsed time

## Likelihood Explanation

**Likelihood: MEDIUM-HIGH**

The overflow occurs after sustained high utilization:
- At maximum rate (200% at target = 800% effective): ~1.75 years
- At 400% rate: ~3.5 years
- At 100% rate: ~7 years

While 1.75 years seems long, consider:
1. Protocol is designed for long-term operation
2. High-utilization pools can sustain elevated rates for extended periods
3. Once triggered, it affects ALL users of that CollateralTracker
4. No warning or prevention mechanism exists
5. The developers acknowledged the 80-bit limit but implemented no safeguards

The trigger is inevitable given sufficient time at elevated rates, and the impact is catastrophic when it occurs.

## Recommendation

Implement proper input masking in `storeMarketState()`:

```solidity
function storeMarketState(
    uint256 _borrowIndex,
    uint256 _marketEpoch,
    uint256 _rateAtTarget,
    uint256 _unrealizedInterest
) internal pure returns (MarketState result) {
    assembly {
        // Mask inputs to their allocated bit widths
        let safeBorrowIndex := and(_borrowIndex, 0xFFFFFFFFFFFFFFFFFFFF) // 80 bits
        let safeEpoch := and(_marketEpoch, 0xFFFFFFFF) // 32 bits
        let safeRate := and(_rateAtTarget, 0x3FFFFFFFFF) // 38 bits
        let safeInterest := and(_unrealizedInterest, sub(shl(106, 1), 1)) // 106 bits
        
        result := add(
            add(add(safeBorrowIndex, shl(80, safeEpoch)), shl(112, safeRate)),
            shl(150, safeInterest)
        )
    }
}
```

Additionally, add overflow detection in `_accrueInterest()`:

```solidity
if (currentBorrowIndex > type(uint80).max) {
    revert BorrowIndexOverflow();
}
```

Consider a protocol-level migration mechanism or pausing when approaching the limit.

## Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MarketState, MarketStateLibrary} from "contracts/types/MarketState.sol";
import {RiskEngine} from "contracts/RiskEngine.sol";

contract BorrowIndexOverflowTest is Test {
    using MarketStateLibrary for MarketState;
    
    function test_BorrowIndexCorruptsMarketEpoch() public {
        // Simulate borrowIndex exceeding uint80 max after 1.75 years at 800% interest
        uint256 overflowedBorrowIndex = type(uint80).max + 1e18; // Slightly over limit
        uint256 currentEpoch = block.timestamp >> 2;
        
        // Store market state with overflowed borrowIndex
        MarketState state = MarketStateLibrary.storeMarketState(
            overflowedBorrowIndex,
            currentEpoch,
            1e17, // rateAtTarget
            0     // unrealizedInterest
        );
        
        // Extract marketEpoch
        uint32 storedEpoch = state.marketEpoch();
        
        // The stored epoch should be corrupted by overflow bits
        // borrowIndex bits 80+ overflow into marketEpoch field
        uint256 expectedCorruption = (overflowedBorrowIndex >> 80) & 0xFFFFFFFF;
        uint256 actualCorruption = (storedEpoch - uint32(currentEpoch)) & 0xFFFFFFFF;
        
        // Verify corruption occurred
        assertGt(actualCorruption, 0, "MarketEpoch should be corrupted");
        
        // Now simulate RiskEngine conversion
        uint256 previousTime = storedEpoch << 2;
        
        // Calculate elapsed time (will be negative since previousTime > block.timestamp)
        int256 elapsed = int256(block.timestamp) - int256(previousTime);
        
        // Verify negative elapsed time
        assertLt(elapsed, 0, "Elapsed time should be negative due to corrupted epoch");
        
        console.log("Overflowed borrowIndex:", overflowedBorrowIndex);
        console.log("Current epoch:", currentEpoch);
        console.log("Stored (corrupted) epoch:", storedEpoch);
        console.log("Elapsed time:", elapsed);
    }
}
```

**Notes**

The vulnerability is latent but inevitable given sufficient protocol lifespan at elevated interest rates. The developers documented awareness of the 80-bit limit but failed to implement protection against overflow corruption. The lack of input masking in `storeMarketState()` is the direct cause, allowing `borrowIndex` overflow to silently corrupt the `marketEpoch` field. This cascades into broken interest rate calculations when `RiskEngine` encounters negative elapsed time, violating the protocol's fundamental interest rate model assumptions.

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

**File:** contracts/CollateralTracker.sol (L236-236)
```text
    ///      - Lowest 80 bits: Global borrow index in WAD (starts at 1e18). 2**80 = 1.75 years at 800% interest
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

**File:** contracts/CollateralTracker.sol (L1018-1024)
```text
            // Update borrow index
            unchecked {
                uint128 _borrowIndex = (WAD + rawInterest).toUint128();
                currentBorrowIndex = Math
                    .mulDivWadRoundingUp(currentBorrowIndex, _borrowIndex)
                    .toUint128();
            }
```

**File:** contracts/RiskEngine.sol (L2203-2203)
```text
            uint256 previousTime = interestRateAccumulator.marketEpoch() << 2;
```

**File:** contracts/RiskEngine.sol (L2216-2216)
```text
                // Safe "unchecked" cast because block.timestamp - market.lastUpdate <= block.timestamp <= type(int256).max.
```

**File:** contracts/RiskEngine.sol (L2218-2221)
```text
                int256 elapsed = Math.min(
                    int256(block.timestamp) - int256(previousTime),
                    IRM_MAX_ELAPSED_TIME
                );
```

**File:** contracts/libraries/Math.sol (L66-68)
```text
    function min(int256 a, int256 b) internal pure returns (int256) {
        return a < b ? a : b;
    }
```
