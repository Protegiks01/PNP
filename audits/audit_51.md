# Audit Report

## Title
BorrowIndex Overflow Corrupts MarketState Causing Protocol-Wide Interest Calculation Errors

## Summary
The `storeMarketState()` function in `MarketState.sol` does not validate that input values fit within their allocated bit ranges before packing them into a single uint256. When the `borrowIndex` exceeds 2^80 (which occurs after ~1.75 years at maximum interest rate), the overflow bits corrupt the `marketEpoch` field, causing incorrect interest calculations across the entire protocol.

## Finding Description

The `storeMarketState()` function accepts four uint256 parameters and packs them into specific bit ranges without validation:
- `borrowIndex`: bits 0-79 (80 bits)
- `marketEpoch`: bits 80-111 (32 bits)  
- `rateAtTarget`: bits 112-149 (38 bits)
- `unrealizedInterest`: bits 150-255 (106 bits) [1](#0-0) 

The issue is that the function parameters are declared as `uint256` and no masking is applied before bit-packing via nested `add()` operations. This contrasts with the individual update functions like `updateRateAtTarget()` and `updateUnrealizedInterest()`, which explicitly mask their inputs to prevent corruption: [2](#0-1) [3](#0-2) 

In `CollateralTracker.sol`, the `_accrueInterest()` function calls `storeMarketState()` with `currentBorrowIndex` as a uint128: [4](#0-3) 

The `currentBorrowIndex` is calculated through compound interest multiplication and can legitimately grow beyond 2^80: [5](#0-4) 

According to the protocol's own documentation comment: "2**80 = 1.75 years at 800% interest" [6](#0-5) 

When `borrowIndex > 2^80-1`, the excess bits at positions 80+ will be added to the shifted `marketEpoch` value during the nested add operations, corrupting the epoch field.

**Corruption Mechanism:**
If `borrowIndex = 2^80 + K` where K > 0:
1. The nested add combines: `(2^80 + K) + (epoch * 2^80) = (epoch + 1) * 2^80 + K`
2. When `marketEpoch()` is extracted: `result >> 80 & 0xFFFFFFFF` returns `(epoch + 1)` instead of `epoch`
3. This corrupted epoch causes incorrect `deltaTime` calculation in interest accrual: [7](#0-6) 

If the corrupted `previousEpoch > currentEpoch`, the unchecked subtraction underflows, producing a massive `deltaTime` value, causing catastrophic over-accrual of interest.

## Impact Explanation

**Severity: HIGH**

This vulnerability causes protocol-wide state corruption affecting all users:

1. **Interest Calculation Corruption**: The corrupted epoch leads to incorrect `deltaTime`, causing wrong interest accrual for all borrowers and lenders
2. **Share Price Manipulation**: Incorrect interest affects `totalAssets()`, corrupting share prices in CollateralTracker vaults
3. **Systemic Undercollateralization**: Wrong interest calculations can make positions appear solvent when they're actually insolvent, or vice versa
4. **Protocol Insolvency Risk**: Over-accrual of interest could drain protocol reserves; under-accrual allows users to borrow without proper interest charges

**Invariants Broken:**
- **Invariant #4** (Interest Index Monotonicity): Corrupted state breaks borrowIndex tracking
- **Invariant #21** (Interest Accuracy): Incorrect deltaTime produces wrong interest calculations
- **Invariant #2** (Collateral Conservation): Asset accounting becomes incorrect due to wrong interest

## Likelihood Explanation

**Likelihood: HIGH**

This issue will occur with certainty given sufficient time:
- At maximum interest rate (800% APR), overflow occurs after ~1.75 years
- At 400% APR, overflow occurs after ~3.5 years  
- At 200% APR, overflow occurs after ~7 years
- The protocol is designed for long-term operation without migration paths
- No circuit breakers or checks prevent borrowIndex growth
- Once triggered, affects all users simultaneously until state is manually corrected

The maximum interest rate is hardcoded: [8](#0-7) 

## Recommendation

Add input validation and masking in `storeMarketState()` to match the safety measures in the update functions:

```solidity
function storeMarketState(
    uint256 _borrowIndex,
    uint256 _marketEpoch,
    uint256 _rateAtTarget,
    uint256 _unrealizedInterest
) internal pure returns (MarketState result) {
    assembly {
        // Mask inputs to their allocated bit ranges
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

Additionally, consider adding a check in `_accrueInterest()` to prevent borrowIndex from exceeding 2^80:

```solidity
if (currentBorrowIndex > type(uint80).max) {
    revert Errors.BorrowIndexOverflow();
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/types/MarketState.sol";

contract MarketStateBorrowIndexOverflowTest is Test {
    using MarketStateLibrary for MarketState;
    
    function testBorrowIndexOverflowCorruptsEpoch() public {
        // Simulate borrowIndex exceeding 80 bits after ~1.75 years at 800% rate
        uint256 borrowIndexOverflow = (uint256(1) << 80) + 1000; // 2^80 + 1000
        uint256 correctEpoch = 1000;
        uint256 rateAtTarget = 100;
        uint256 unrealizedInterest = 500;
        
        // Store market state with overflowing borrowIndex
        MarketState state = MarketStateLibrary.storeMarketState(
            borrowIndexOverflow,
            correctEpoch,
            rateAtTarget,
            unrealizedInterest
        );
        
        // Extract values
        uint80 storedBorrowIndex = state.borrowIndex();
        uint32 storedEpoch = state.marketEpoch();
        uint40 storedRate = state.rateAtTarget();
        uint128 storedInterest = state.unrealizedInterest();
        
        // Demonstrate corruption
        console.log("Expected borrowIndex (mod 2^80):", 1000);
        console.log("Stored borrowIndex:", storedBorrowIndex);
        console.log("Expected epoch:", correctEpoch);
        console.log("Stored epoch (CORRUPTED):", storedEpoch);
        
        // The epoch is corrupted by the overflow bit
        assertEq(storedBorrowIndex, 1000, "BorrowIndex truncated to lower 80 bits");
        assertEq(storedEpoch, 1001, "Epoch corrupted by borrowIndex overflow");
        assertNotEq(storedEpoch, correctEpoch, "Epoch does not match expected value");
        
        // This demonstrates the vulnerability: epoch is incremented by 1
        // due to the overflow bit from borrowIndex
    }
    
    function testCompareWithSafeUpdateFunction() public {
        // Show that update functions have safety measures
        MarketState initialState = MarketStateLibrary.storeMarketState(0, 0, 0, 0);
        
        // Try to update with oversized value - it gets masked
        uint40 oversizedRate = uint40(type(uint40).max); // 40 bits, but only 38 allocated
        MarketState updatedState = initialState.updateRateAtTarget(oversizedRate);
        
        uint40 storedRate = updatedState.rateAtTarget();
        console.log("Input rate (40 bits):", oversizedRate);
        console.log("Stored rate (masked to 38 bits):", storedRate);
        
        // The update function masks to 38 bits (0x3FFFFFFFFF)
        assertEq(storedRate, oversizedRate & 0x3FFFFFFFFF, "Rate properly masked in update function");
        
        // But storeMarketState has no such protection
    }
}
```

Run with: `forge test --match-test testBorrowIndexOverflowCorruptsEpoch -vv`

The test demonstrates that when `borrowIndex` exceeds 2^80, its overflow bits corrupt the `marketEpoch` field, causing the retrieved epoch value to differ from the intended value. This corruption will cause incorrect interest calculations throughout the protocol.

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

**File:** contracts/types/MarketState.sol (L109-124)
```text
    function updateRateAtTarget(
        MarketState self,
        uint40 newRate
    ) internal pure returns (MarketState result) {
        assembly {
            // 1. Clear bits 112-149
            let cleared := and(self, not(TARGET_RATE_MASK))

            // 2. Safety: Mask the input to ensure it fits in 38 bits (0x3FFFFFFFFF)
            //    This prevents 'newRate' from corrupting the neighbor if it > 38 bits.
            let safeRate := and(newRate, 0x3FFFFFFFFF)

            // 3. Shift to 112 and combine
            result := or(cleared, shl(112, safeRate))
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

**File:** contracts/CollateralTracker.sol (L970-975)
```text
        s_marketState = MarketStateLibrary.storeMarketState(
            currentBorrowIndex,
            currentEpoch,
            s_marketState.rateAtTarget(),
            _unrealizedGlobalInterest
        );
```

**File:** contracts/CollateralTracker.sol (L999-1004)
```text
        currentEpoch = block.timestamp >> 2;
        uint256 previousEpoch = accumulator.marketEpoch();
        uint128 deltaTime;
        unchecked {
            deltaTime = uint32(currentEpoch - previousEpoch) << 2;
        }
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

**File:** contracts/RiskEngine.sol (L169-171)
```text
    /// @notice Maximum rate at target per second (scaled by WAD).
    /// @dev Maximum rate at target = 200% (maximum rate = 800%).
    int256 public constant MAX_RATE_AT_TARGET = 2.0 ether / int256(365 days);
```
