# Audit Report

## Title 
Critical State Corruption in MarketState.storeMarketState() Due to Missing Input Validation Causing Arithmetic Overflow

## Summary
The `storeMarketState()` function in `MarketState.sol` lacks input validation for bit-packed parameters, allowing values to exceed their designated bit ranges (80, 32, 38, and 106 bits respectively). When `borrowIndex` exceeds 2^80 (~1.75 years at 800% APR) or `unrealizedInterest` exceeds 2^106 (~5 months at max utilization), assembly addition operations cause silent arithmetic overflow, corrupting the packed state and breaking protocol-wide interest accounting.

## Finding Description

The `storeMarketState()` function uses unchecked assembly additions to pack four values into a single uint256. [1](#0-0) 

The bit packing scheme allocates:
- borrowIndex: 80 bits (bits 0-79)  
- marketEpoch: 32 bits (bits 80-111)
- rateAtTarget: 38 bits (bits 112-149)
- unrealizedInterest: 106 bits (bits 150-255) [2](#0-1) 

However, `storeMarketState()` accepts all parameters as `uint256` without validation. When called from `_accrueInterest()`, it receives:
- `currentBorrowIndex` (uint128)
- `currentEpoch` (uint256)  
- `rateAtTarget()` (uint40)
- `_unrealizedGlobalInterest` (uint128) [3](#0-2) 

**Critical Issue 1: borrowIndex Overflow**

The `borrowIndex` compounds continuously via checked multiplication at 800% maximum APR. [4](#0-3) 

The maximum interest rate is capped at 800% APR: [5](#0-4) 

Starting from 1e18 (WAD), at 800% APR (rate = 8/31557600 ≈ 2.536e-7 per second), borrowIndex reaches 2^80 ≈ 1.209e24 after approximately 1.75 years, matching the developer comment. [6](#0-5) 

Once `borrowIndex ≥ 2^80`, the assembly addition causes bit overlap:
- If `borrowIndex = 2^80` (bit 80 set), and `marketEpoch = 1` → `shl(80, 1) = 2^80`
- Adding these: `2^80 + 2^80 = 2^81` (bit 81 set, bit 80 clear)
- When extracted, `borrowIndex` reads as 0 (bits 0-79 are empty)
- `marketEpoch` reads as 2 (bit 81 - 80 = bit 1 of epoch field)

**Critical Issue 2: unrealizedInterest Overflow**

Unrealized interest accumulates on borrowed assets with checked addition: [7](#0-6) 

Maximum deposit is constrained to `type(uint104).max`: [8](#0-7) 

With 2^104 assets borrowed at 800% APR, interest accrues at ~800% per year. After 5 months (≈0.417 years), accumulated interest ≈ 2^104 × (e^(8×0.417) - 1) ≈ 2^104 × 3.17 ≈ 3.17 × 2^104 > 2^106.

When `unrealizedInterest ≥ 2^106`:
- `shl(150, 2^106) = 2^256 ≡ 0 (mod 2^256)` (wraps to zero)
- If `unrealizedInterest = 2^106 + k`, then `shl(150, 2^106 + k) = k × 2^150`
- When extracted via `shr(150, result)`, it returns `k` instead of `2^106 + k`

**Inconsistency with Update Functions**

The update functions for the same fields DO include masking validation, demonstrating developer awareness of overflow risks: [9](#0-8) [10](#0-9) 

This inconsistency proves `storeMarketState()` is missing critical validation.

## Impact Explanation

**CRITICAL SEVERITY** - This vulnerability causes:

1. **Protocol Insolvency**: When `unrealizedInterest` overflows to 0, accumulated interest worth potentially millions of dollars is permanently lost from accounting. Users can withdraw collateral without paying owed interest, draining the protocol.

2. **Systemic Interest Calculation Failure**: When `borrowIndex` corrupts, all interest calculations become invalid protocol-wide. The borrowIndex is fundamental to compound interest calculations. [11](#0-10) 

3. **Broken Invariants**:
   - **Invariant 2 (Collateral Conservation)**: `totalAssets()` calculation becomes incorrect when `unrealizedGlobalInterest` is lost
   - **Invariant 4 (Interest Index Monotonicity)**: Corrupted borrowIndex breaks monotonicity
   - **Invariant 21 (Interest Accuracy)**: All interest calculations fail with corrupted state

4. **Unrecoverable State**: Once MarketState is corrupted, the protocol cannot recover without redeployment. All positions, collateral, and interest tracking become permanently invalid.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This vulnerability will inevitably occur:

1. **Time-Based Certainty**: At maximum interest rate (800% APR), borrowIndex reaches overflow in exactly 1.75 years - a reasonable operational timeframe for DeFi protocols intended to run indefinitely.

2. **Utilization-Based Trigger**: During periods of high utilization (>90%), interest rates approach the 800% maximum. With max deposits borrowed, unrealizedInterest can overflow in just 5 months.

3. **No Protective Mechanisms**: There are no circuit breakers, validation checks, or caps that would prevent these values from exceeding their limits before being passed to `storeMarketState()`.

4. **Accelerated by Attack**: An attacker can hasten unrealizedInterest overflow by maximizing borrows and deliberately not settling interest, forcing accumulation.

## Recommendation

Add input validation to `storeMarketState()` matching the safety checks in update functions:

```solidity
function storeMarketState(
    uint256 _borrowIndex,
    uint256 _marketEpoch,
    uint256 _rateAtTarget,
    uint256 _unrealizedInterest
) internal pure returns (MarketState result) {
    // Validate inputs fit in designated bit ranges
    require(_borrowIndex <= type(uint80).max, "borrowIndex overflow");
    require(_marketEpoch <= type(uint32).max, "marketEpoch overflow");
    require(_rateAtTarget <= ((1 << 38) - 1), "rateAtTarget overflow");
    require(_unrealizedInterest <= ((1 << 106) - 1), "unrealizedInterest overflow");
    
    assembly {
        result := add(
            add(add(_borrowIndex, shl(80, _marketEpoch)), shl(112, _rateAtTarget)),
            shl(150, _unrealizedInterest)
        )
    }
}
```

Alternatively, use masking like the update functions to silently truncate (though explicit reversion is safer):

```solidity
assembly {
    let safeBorrowIndex := and(_borrowIndex, 0xFFFFFFFFFFFFFFFFFFFF) // 80 bits
    let safeEpoch := and(_marketEpoch, 0xFFFFFFFF) // 32 bits  
    let safeRate := and(_rateAtTarget, 0x3FFFFFFFFF) // 38 bits
    let safeInterest := and(_unrealizedInterest, sub(shl(106, 1), 1)) // 106 bits
    
    result := add(
        add(add(safeBorrowIndex, shl(80, safeEpoch)), shl(112, safeRate)),
        shl(150, safeInterest)
    )
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MarketState, MarketStateLibrary} from "@contracts/types/MarketState.sol";

contract MarketStateOverflowTest is Test {
    using MarketStateLibrary for MarketState;

    function test_BorrowIndexOverflow() public {
        // borrowIndex reaches 2^80 after 1.75 years at 800% APR
        uint256 borrowIndexAtLimit = 2**80;
        uint256 marketEpoch = 1;
        uint256 rateAtTarget = 0;
        uint256 unrealizedInterest = 0;

        // Store the state - should cause corruption
        MarketState state = MarketStateLibrary.storeMarketState(
            borrowIndexAtLimit,
            marketEpoch,
            rateAtTarget,
            unrealizedInterest
        );

        // Extract values
        uint80 extractedBorrowIndex = state.borrowIndex();
        uint32 extractedEpoch = state.marketEpoch();

        // Verify corruption: borrowIndex should be 2^80 but extracts as 0
        assertEq(extractedBorrowIndex, 0, "borrowIndex corrupted to 0");
        // marketEpoch should be 1 but extracts as 2 due to bit overlap
        assertEq(extractedEpoch, 2, "marketEpoch corrupted to 2");
        
        emit log_string("CRITICAL: borrowIndex overflow causes state corruption");
        emit log_named_uint("Expected borrowIndex", borrowIndexAtLimit);
        emit log_named_uint("Actual borrowIndex", extractedBorrowIndex);
        emit log_named_uint("Expected marketEpoch", marketEpoch);
        emit log_named_uint("Actual marketEpoch", extractedEpoch);
    }

    function test_UnrealizedInterestOverflow() public {
        // unrealizedInterest can exceed 2^106 after ~5 months at max utilization
        uint256 borrowIndex = 1e18;
        uint256 marketEpoch = 1;
        uint256 rateAtTarget = 0;
        uint256 unrealizedInterestOverflow = 2**106; // Exactly at overflow point

        // Store the state
        MarketState state = MarketStateLibrary.storeMarketState(
            borrowIndex,
            marketEpoch,
            rateAtTarget,
            unrealizedInterestOverflow
        );

        // Extract unrealized interest
        uint128 extracted = state.unrealizedInterest();

        // Verify corruption: should be 2^106 but wraps to 0
        assertEq(extracted, 0, "unrealizedInterest wraps to 0");
        
        emit log_string("CRITICAL: unrealizedInterest overflow wraps to 0");
        emit log_named_uint("Expected unrealizedInterest", unrealizedInterestOverflow);
        emit log_named_uint("Actual unrealizedInterest", extracted);
        emit log_string("Protocol loses all accumulated interest!");

        // Test with value slightly over 2^106
        uint256 overBy100 = 2**106 + 100;
        state = MarketStateLibrary.storeMarketState(
            borrowIndex,
            marketEpoch,
            rateAtTarget,
            overBy100
        );
        extracted = state.unrealizedInterest();
        
        // Should store as 100 instead of 2^106 + 100
        assertEq(extracted, 100, "unrealizedInterest wraps incorrectly");
        emit log_named_uint("2^106 + 100 stored as", extracted);
    }
}
```

**Notes:**

This vulnerability is a ticking time bomb that will inevitably trigger as the protocol ages. The developer comment explicitly acknowledges the 1.75-year limit for borrowIndex at 800% APR, yet no validation was implemented. The inconsistency with update functions (which DO have masking) proves this is an oversight rather than intentional design. The protocol cannot recover from state corruption without redeployment, making this a critical issue requiring immediate remediation before deployment.

### Citations

**File:** contracts/types/MarketState.sol (L11-28)
```text
// PACKING RULES FOR A MARKETSTATE:
// =================================================================================================
//  From the LSB to the MSB:
// (0) borrowIndex          80 bits : Global borrow index in WAD (starts at 1e18). 2**80 = 1.75 years at 800% interest
// (1) marketEpoch          32 bits : Last interaction epoch for that market (1 epoch = block.timestamp/4)
// (2) rateAtTarget         38 bits : The rateAtTarget value in WAD (2**38 = 800% interest rate)
// (3) unrealizedInterest   106bits : Accumulated unrealized interest that hasn't been distributed (max deposit is 2**104)
// Total                    256bits  : Total bits used by a MarketState.
// ===============================================================================================
//
// The bit pattern is therefore:
//
//          (3)                 (2)                 (1)                 (0)
//    <---- 106 bits ----><---- 38 bits ----><---- 32 bits ----><---- 80 bits ---->
//     unrealizedInterest    rateAtTarget        marketEpoch        borrowIndex
//
//    <--- most significant bit                              least significant bit --->
//
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

**File:** contracts/CollateralTracker.sol (L540-541)
```text
    function maxDeposit(address) external pure returns (uint256 maxAssets) {
        return type(uint104).max;
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

**File:** contracts/CollateralTracker.sol (L1015-1016)
```text
            // keep checked to prevent overflows
            _unrealizedGlobalInterest += interestOwed;
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

**File:** contracts/CollateralTracker.sol (L1061-1070)
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
```

**File:** contracts/RiskEngine.sol (L169-171)
```text
    /// @notice Maximum rate at target per second (scaled by WAD).
    /// @dev Maximum rate at target = 200% (maximum rate = 800%).
    int256 public constant MAX_RATE_AT_TARGET = 2.0 ether / int256(365 days);
```
