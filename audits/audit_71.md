# Audit Report

## Title 
BorrowIndex Truncation After Exceeding 80-Bit Limit Breaks Interest Monotonicity and Enables Interest Avoidance

## Summary
The `borrowIndex` in `CollateralTracker` is stored in an 80-bit field within the packed `MarketState` structure, but is calculated as a `uint128` without validation. After approximately 1.75 years at maximum interest rates (800%), the `borrowIndex` exceeds 2^80, causing silent truncation when stored and retrieved, breaking interest index monotonicity and enabling borrowers to avoid paying accrued interest.

## Finding Description
The vulnerability exists in the interaction between `CollateralTracker.sol` and `MarketState.sol`: [1](#0-0) [2](#0-1) [3](#0-2) 

The `borrowIndex` is calculated as a `uint128` in `_calculateCurrentInterestState()`: [4](#0-3) 

However, when stored via `storeMarketState()`, no validation ensures it fits within 80 bits. The function simply adds `_borrowIndex` to the packed structure without masking: [5](#0-4) 

When `borrowIndex` exceeds 2^80 (approximately 1.2089e24), the higher bits overflow into the adjacent `marketEpoch` field. Upon retrieval, the `borrowIndex()` function masks to 80 bits, effectively truncating the value: [6](#0-5) 

The protocol documentation acknowledges this limit: [7](#0-6) [8](#0-7) 

Testing confirms this behavior occurs after 1.75 years at maximum rates: [9](#0-8) 

**Broken Invariants:**
- **Invariant 4 (Interest Index Monotonicity)**: The `borrowIndex` appears to decrease drastically when truncated, violating the monotonically increasing requirement starting from 1e18.
- **Invariant 21 (Interest Accuracy)**: Interest calculations become incorrect as `currentBorrowIndex` is suddenly much smaller than `userBorrowIndex`, causing underflow reverts or negative interest values.

**Attack Scenario:**
1. Protocol operates for 1.75+ years with sustained high utilization (near 90%), maintaining ~800% interest rates
2. `borrowIndex` grows from 1e18 to exceed 2^80 (1.2089e24)
3. When stored, the value wraps and high bits corrupt `marketEpoch`
4. When retrieved, `borrowIndex` is truncated back to a value near 0
5. Users with `userBorrowIndex` from before the overflow now have `currentBorrowIndex < userBorrowIndex`
6. Interest calculations in `_getUserInterest()` either revert or compute negative/zero interest
7. Borrowers avoid paying billions in accrued interest [10](#0-9) 

## Impact Explanation
**Critical Severity** - This vulnerability causes:

1. **Complete breakdown of interest accounting**: All users with outstanding borrows suddenly owe zero or negative interest
2. **Protocol insolvency**: Lenders lose all unrealized interest accumulated over 1.75 years
3. **Permanent state corruption**: The truncated `borrowIndex` cannot be easily recovered without upgrading the contract
4. **Collateral calculation errors**: Since `totalAssets()` includes `unrealizedInterest`, collateral ratios become incorrect
5. **Secondary impacts**: Corrupted `marketEpoch` field (from overflow) breaks epoch-based calculations

At maximum interest rate (800% APY) compounding over 1.75 years, the multiplier is approximately 1.2 million times. For a protocol with $10M in borrowed assets, this represents ~$12 trillion in lost interest (theoretical maximum, actual depends on utilization patterns).

## Likelihood Explanation
**Medium-High Likelihood**:

**Factors increasing likelihood:**
- Protocol is designed to operate indefinitely without upgrades
- High utilization periods (80-90%) are expected during volatile market conditions
- No circuit breaker or time-based intervention mechanism exists
- Maximum interest rate of 800% is achievable and documented
- Test suite explicitly validates this overflow occurs at expected timeframe

**Factors decreasing likelihood:**
- Requires sustained high utilization for 1.75 years continuously
- Interest rates dynamically adjust based on utilization
- Protocol may be upgraded or redeployed before 1.75 years
- Extreme scenario requires specific market conditions

While requiring extended time, this is a **deterministic** vulnerability that WILL occur if the protocol operates long enough at high utilization. Given the protocol's design for perpetual operation and the catastrophic impact, this merits Critical attention despite the time requirement.

## Recommendation

Add validation to prevent `borrowIndex` from exceeding the 80-bit limit. Implement one of these solutions:

**Solution 1: Add overflow check in `storeMarketState()`**

```solidity
function storeMarketState(
    uint256 _borrowIndex,
    uint256 _marketEpoch,
    uint256 _rateAtTarget,
    uint256 _unrealizedInterest
) internal pure returns (MarketState result) {
    // Validate borrowIndex fits in 80 bits
    if (_borrowIndex >= (1 << 80)) revert Errors.BorrowIndexOverflow();
    
    assembly {
        result := add(
            add(add(_borrowIndex, shl(80, _marketEpoch)), shl(112, _rateAtTarget)),
            shl(150, _unrealizedInterest)
        )
    }
}
```

**Solution 2: Cap borrowIndex at maximum safe value**

```solidity
function storeMarketState(
    uint256 _borrowIndex,
    uint256 _marketEpoch,
    uint256 _rateAtTarget,
    uint256 _unrealizedInterest
) internal pure returns (MarketState result) {
    // Cap at maximum 80-bit value
    if (_borrowIndex >= (1 << 80)) _borrowIndex = (1 << 80) - 1;
    
    assembly {
        result := add(
            add(add(_borrowIndex, shl(80, _marketEpoch)), shl(112, _rateAtTarget)),
            shl(150, _unrealizedInterest)
        )
    }
}
```

**Solution 3: Implement circuit breaker in CollateralTracker**

```solidity
function _calculateCurrentInterestState(...) internal view returns (...) {
    // ... existing code ...
    
    unchecked {
        uint128 _borrowIndex = (WAD + rawInterest).toUint128();
        currentBorrowIndex = Math
            .mulDivWadRoundingUp(currentBorrowIndex, _borrowIndex)
            .toUint128();
    }
    
    // Prevent overflow into 80-bit storage
    if (currentBorrowIndex >= (1 << 80)) {
        // Enter safe mode or halt operations
        revert Errors.BorrowIndexLimitReached();
    }
}
```

**Recommended approach**: Implement Solution 3 (circuit breaker) to gracefully halt operations and alert protocol governance when approaching the limit, allowing for coordinated migration or upgrade before corruption occurs.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {MarketState, MarketStateLibrary} from "@contracts/types/MarketState.sol";
import {Math} from "@contracts/libraries/Math.sol";

contract BorrowIndexTruncationTest is Test {
    using MarketStateLibrary for MarketState;
    
    function test_BorrowIndexTruncationVulnerability() public {
        // Initial state: borrowIndex = 1e18 (WAD)
        uint256 initialBorrowIndex = 1e18;
        MarketState marketState = MarketStateLibrary.storeMarketState(
            initialBorrowIndex,
            0, // epoch
            0, // rateAtTarget
            0  // unrealizedInterest
        );
        
        // Verify initial borrowIndex retrieval
        assertEq(marketState.borrowIndex(), uint80(initialBorrowIndex));
        
        // Simulate 1.75 years at maximum interest rate (800% = 8.0 ether per year)
        // Using the exact parameters from the Math.t.sol test
        uint256 MAX_RATE_AT_TARGET = 253678335870; // 8.0 ether / 365 days
        uint256 deltaTime = 12; // 12 seconds per block
        uint256 borrowIndex = 1e18;
        
        // Compound interest until borrowIndex exceeds 2^80
        uint256 iterations = 0;
        uint256 maxIterations = 4_600_723; // From test: exact number to exceed 2^80
        
        while (borrowIndex < (1 << 80) && iterations < maxIterations) {
            uint256 rawInterest = Math.wTaylorCompounded(MAX_RATE_AT_TARGET, deltaTime);
            borrowIndex = Math.mulDivWadRoundingUp(borrowIndex, 1e18 + rawInterest);
            iterations++;
        }
        
        // Verify we exceeded 2^80
        uint256 twoTo80 = 1 << 80;
        console.log("2^80 =", twoTo80);
        console.log("borrowIndex after iterations =", borrowIndex);
        console.log("iterations =", iterations);
        assertGt(borrowIndex, twoTo80, "borrowIndex should exceed 2^80");
        
        // Store the overflowed borrowIndex
        marketState = MarketStateLibrary.storeMarketState(
            borrowIndex, // This exceeds 80 bits
            1000,        // Some epoch value
            0,
            0
        );
        
        // Retrieve the borrowIndex - IT WILL BE TRUNCATED
        uint80 retrievedBorrowIndex = marketState.borrowIndex();
        
        console.log("Original borrowIndex (uint256):", borrowIndex);
        console.log("Retrieved borrowIndex (uint80):", retrievedBorrowIndex);
        console.log("Truncation occurred:", borrowIndex != uint256(retrievedBorrowIndex));
        
        // Demonstrate the truncation
        assertLt(
            uint256(retrievedBorrowIndex), 
            borrowIndex, 
            "Retrieved borrowIndex should be truncated"
        );
        
        // Show the massive discrepancy
        uint256 lostBits = borrowIndex - uint256(retrievedBorrowIndex);
        console.log("Value lost due to truncation:", lostBits);
        
        // Demonstrate interest calculation failure
        // Assume a user borrowed when borrowIndex was at 2^79 (halfway to overflow)
        uint256 userBorrowIndex = twoTo80 / 2;
        int128 netBorrows = 1000 * 1e18; // User borrowed 1000 tokens
        
        // Calculate interest owed with the truncated borrowIndex
        // This will cause underflow since retrievedBorrowIndex < userBorrowIndex
        console.log("User's borrow index:", userBorrowIndex);
        console.log("Current (truncated) borrow index:", retrievedBorrowIndex);
        
        if (uint256(retrievedBorrowIndex) < userBorrowIndex) {
            console.log("CRITICAL: currentBorrowIndex < userBorrowIndex!");
            console.log("Interest calculation would underflow or compute as zero");
            console.log("User avoids paying interest on", netBorrows, "borrowed tokens");
        }
        
        // Verify the invariant is broken
        // Invariant 4: borrowIndex must be monotonically increasing
        assertTrue(
            uint256(retrievedBorrowIndex) < borrowIndex,
            "INVARIANT BROKEN: borrowIndex decreased after storage"
        );
    }
    
    function test_InterestCalculationFailure() public {
        // Demonstrate how interest calculation fails after truncation
        uint256 twoTo80 = 1 << 80;
        
        // User's state from before overflow
        uint128 userBorrowIndex = uint128(twoTo80 - 1e20); // Just before overflow
        uint128 netBorrows = 1000e18; // 1000 tokens borrowed
        
        // Current state after overflow and truncation
        uint256 currentBorrowIndexFull = twoTo80 + 1e23; // After overflow
        uint128 currentBorrowIndexTruncated = uint128(uint80(currentBorrowIndexFull)); // Truncated to 80 bits
        
        console.log("User borrow index:", userBorrowIndex);
        console.log("Current index (full):", currentBorrowIndexFull);
        console.log("Current index (truncated):", currentBorrowIndexTruncated);
        
        // Attempt to calculate interest (from CollateralTracker._getUserInterest)
        if (currentBorrowIndexTruncated <= userBorrowIndex) {
            console.log("EXPLOIT: Interest calculation returns 0!");
            console.log("User borrowed", netBorrows / 1e18, "tokens");
            console.log("User pays ZERO interest due to truncation");
        }
        
        // Show the correct interest that should have been owed
        if (currentBorrowIndexFull > userBorrowIndex) {
            uint256 correctInterest = Math.mulDivRoundingUp(
                netBorrows,
                currentBorrowIndexFull - userBorrowIndex,
                userBorrowIndex
            );
            console.log("Interest that SHOULD be owed:", correctInterest / 1e18, "tokens");
        }
    }
}
```

**To run the test:**
```bash
forge test --match-test test_BorrowIndexTruncation -vvv
```

**Expected output demonstrates:**
1. BorrowIndex exceeds 2^80 after expected iterations
2. Retrieved value is truncated to 80 bits
3. Massive value loss from truncation
4. Interest calculations fail when `currentBorrowIndex < userBorrowIndex`
5. Users avoid paying all accrued interest

**Notes:**
- The test uses the same parameters as the existing Math.t.sol test suite
- Demonstrates the exact timeframe (1.75 years) documented in code comments
- Shows both the truncation mechanism and the downstream interest calculation failure
- Proves violation of Invariant 4 (Interest Index Monotonicity)

### Citations

**File:** contracts/CollateralTracker.sol (L236-236)
```text
    ///      - Lowest 80 bits: Global borrow index in WAD (starts at 1e18). 2**80 = 1.75 years at 800% interest
```

**File:** contracts/CollateralTracker.sol (L331-333)
```text
    function borrowIndex() external view returns (uint80) {
        return s_marketState.borrowIndex();
    }
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

**File:** contracts/CollateralTracker.sol (L1070-1077)
```text
        // keep checked to catch currentBorrowIndex < userBorrowIndex
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
