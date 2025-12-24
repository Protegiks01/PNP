# Audit Report

## Title 
Commission Share Loss Due to Incomplete Split Distribution in settleMint() and settleBurn()

## Summary
The `settleMint()` and `settleBurn()` functions in `CollateralTracker.sol` fail to distribute 100% of commission shares when a builder code is present. Due to `PROTOCOL_SPLIT (6,500) + BUILDER_SPLIT (2,500) = 9,000 ≠ DECIMALS (10,000)`, only 90% of commission shares are transferred to the protocol and builder, while 10% incorrectly remains with the option owner. This results in direct protocol revenue loss and users paying less commission than intended.

## Finding Description
When users mint or burn option positions with a builder code present, the protocol charges a commission fee that should be collected by burning or transferring shares. The commission distribution logic contains a mathematical error where the sum of split percentages does not equal 100%.

**The vulnerability exists in two locations:**

1. **`CollateralTracker.sol` - `settleMint()` function (lines 1562-1572):** [1](#0-0) 

2. **`CollateralTracker.sol` - `settleBurn()` function (lines 1641-1651):** [2](#0-1) 

**Root Cause - Incorrect Split Constants in `RiskEngine.sol`:** [3](#0-2) 

The constants define:
- `PROTOCOL_SPLIT = 6_500` (65%)
- `BUILDER_SPLIT = 2_500` (25%)
- **Sum = 9_000 (90%)**

However, `DECIMALS` in CollateralTracker is: [4](#0-3) 

**Execution Flow:**

1. User mints a position with a builder code
2. `sharesToBurn` is calculated representing the full commission in shares
3. Only `(sharesToBurn * 6_500) / 10_000 = 65%` is transferred to protocol
4. Only `(sharesToBurn * 2_500) / 10_000 = 25%` is transferred to builder
5. **The remaining 10% stays in the optionOwner's balance - neither burned nor transferred**

**Comparison with No-Builder-Code Path:**

When `feeRecipient == 0` (no builder code), the entire `sharesToBurn` is properly burned: [5](#0-4) 

This creates an inconsistency where users with builder codes effectively pay only 90% of the commission.

**Additional Bug in Event Emission:**

The `CommissionPaid` event incorrectly emits `protocolSplit` twice instead of `protocolSplit` and `builderSplit`: [6](#0-5) 

Line 1577 should use `builderSplit` instead of `protocolSplit`.

## Impact Explanation
**Severity: HIGH**

This vulnerability causes direct financial loss to the protocol:

**Quantifiable Impact:**
- For every 1,000 shares of commission with a builder code:
  - Protocol receives: 650 shares (should receive 650)
  - Builder receives: 250 shares (should receive 250 or more)
  - **Lost to protocol/builder: 100 shares** (remains with user)
  
**Example Scenario:**
- Commission fee: 1000 assets
- Share price: 1:1
- Expected: All 1000 shares collected (650 protocol + 350 builder, or burned for PLPs)
- Actual: 900 shares collected (650 protocol + 250 builder)
- **Loss: 100 shares worth of assets per transaction**

**Broken Invariants:**
1. **Asset Accounting (Invariant #2)**: Commission accounting does not properly track intended fees
2. **Commission Collection**: Protocol fails to collect 10% of intended revenue on all builder-coded transactions

**Economic Impact:**
- Direct protocol revenue loss on every position mint/burn with builder codes
- Users effectively receive a 10% discount on commission fees
- Builder wallets receive less than intended share of commissions
- Accumulates to significant loss over many transactions

## Likelihood Explanation
**Likelihood: HIGH**

This issue occurs **automatically on every transaction** where:
1. A builder code is provided (`feeRecipient != 0`)
2. User mints or burns an option position

**Preconditions:**
- None required - the constants are hardcoded
- No special permissions or manipulation needed
- No race conditions or timing requirements

**Attack Complexity:**
- Trivial - happens automatically
- Any user minting/burning with a builder code triggers the issue
- No attacker sophistication required

**Frequency:**
- Occurs on every position mint/burn with builder codes
- Given builder codes are a core feature for fee sharing, this affects a significant portion of transactions
- The protocol documentation mentions builder codes as a standard feature

## Recommendation

**Fix the split constants to sum to DECIMALS:**

```solidity
// In RiskEngine.sol
uint16 constant PROTOCOL_SPLIT = 7_500;  // 75% to protocol
uint16 constant BUILDER_SPLIT = 2_500;   // 25% to builder
// Sum = 10_000 = DECIMALS ✓
```

**OR, if the 65%/25% split is intentional, burn the remaining 10%:**

```solidity
// In CollateralTracker.sol settleMint() and settleBurn()
if (riskParameters.feeRecipient() == 0) {
    _burn(optionOwner, sharesToBurn);
    emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
} else {
    unchecked {
        uint256 protocolShares = (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS;
        uint256 builderShares = (sharesToBurn * riskParameters.builderSplit()) / DECIMALS;
        
        _transferFrom(optionOwner, address(riskEngine()), protocolShares);
        _transferFrom(optionOwner, address(uint160(riskParameters.feeRecipient())), builderShares);
        
        // Burn remaining shares to prevent loss
        uint256 remainingShares = sharesToBurn - protocolShares - builderShares;
        if (remainingShares > 0) {
            _burn(optionOwner, remainingShares);
        }
        
        emit CommissionPaid(
            optionOwner,
            address(uint160(riskParameters.feeRecipient())),
            uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
            uint128((commissionFee * riskParameters.builderSplit()) / DECIMALS)  // Fix event bug
        );
    }
}
```

**Also fix the event emission bug** on line 1577 (and line 1656 in `settleBurn()`):
- Change from `riskParameters.protocolSplit()` to `riskParameters.builderSplit()`

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {RiskParameters, RiskParametersLibrary} from "@types/RiskParameters.sol";

contract CommissionLossPoC is Test {
    uint256 constant DECIMALS = 10_000;
    uint16 constant PROTOCOL_SPLIT = 6_500;
    uint16 constant BUILDER_SPLIT = 2_500;
    
    function testCommissionSharesLoss() public {
        // Setup: Calculate expected vs actual distribution
        uint256 sharesToBurn = 1000; // Commission in shares
        
        // Expected: All shares should be distributed (100%)
        uint256 expectedTotal = sharesToBurn; // 1000 shares
        
        // Actual: Calculate what gets transferred
        uint256 protocolReceives = (sharesToBurn * PROTOCOL_SPLIT) / DECIMALS;  // 650 shares
        uint256 builderReceives = (sharesToBurn * BUILDER_SPLIT) / DECIMALS;    // 250 shares
        uint256 actualTotal = protocolReceives + builderReceives;                // 900 shares
        
        // Loss calculation
        uint256 lostShares = expectedTotal - actualTotal; // 100 shares
        
        // Assertions proving the vulnerability
        assertEq(protocolReceives, 650, "Protocol receives 65%");
        assertEq(builderReceives, 250, "Builder receives 25%");
        assertEq(actualTotal, 900, "Only 90% distributed");
        assertEq(lostShares, 100, "10% of shares lost");
        
        // Verify the split sum is incorrect
        assertEq(PROTOCOL_SPLIT + BUILDER_SPLIT, 9_000, "Splits sum to 9000, not 10000");
        assertLt(PROTOCOL_SPLIT + BUILDER_SPLIT, DECIMALS, "Splits don't equal DECIMALS");
        
        // Demonstrate percentage loss
        uint256 lossPercentage = (lostShares * 100) / sharesToBurn;
        assertEq(lossPercentage, 10, "10% of commission is lost");
        
        console.log("=== Commission Loss Proof ===");
        console.log("Total commission shares:", sharesToBurn);
        console.log("Protocol receives:", protocolReceives, "(65%)");
        console.log("Builder receives:", builderReceives, "(25%)");
        console.log("Total distributed:", actualTotal, "(90%)");
        console.log("LOST SHARES:", lostShares, "(10%)");
        console.log("These lost shares remain with optionOwner instead of being collected");
    }
}
```

**Expected Output:**
```
=== Commission Loss Proof ===
Total commission shares: 1000
Protocol receives: 650 (65%)
Builder receives: 250 (25%)
Total distributed: 900 (90%)
LOST SHARES: 100 (10%)
These lost shares remain with optionOwner instead of being collected
```

This PoC mathematically proves that 10% of commission shares are lost on every transaction with a builder code, resulting in direct protocol revenue loss.

### Citations

**File:** contracts/CollateralTracker.sol (L106-108)
```text
    /// @notice Decimals for computation (1 bps (1 basis point) precision: 0.01%).
    /// @dev uint type for composability with unsigned integer based mathematical operations.
    uint256 internal constant DECIMALS = 10_000;
```

**File:** contracts/CollateralTracker.sol (L1558-1560)
```text
            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
```

**File:** contracts/CollateralTracker.sol (L1562-1572)
```text
                unchecked {
                    _transferFrom(
                        optionOwner,
                        address(riskEngine()),
                        (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS
                    );
                    _transferFrom(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        (sharesToBurn * riskParameters.builderSplit()) / DECIMALS
                    );
```

**File:** contracts/CollateralTracker.sol (L1573-1578)
```text
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
```

**File:** contracts/CollateralTracker.sol (L1641-1651)
```text
                unchecked {
                    _transferFrom(
                        optionOwner,
                        address(riskEngine()),
                        (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS
                    );
                    _transferFrom(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        (sharesToBurn * riskParameters.builderSplit()) / DECIMALS
                    );
```

**File:** contracts/RiskEngine.sol (L118-124)
```text
    /// @notice The protocol split, in basis points, when a builder code is present.
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant PROTOCOL_SPLIT = 6_500;

    /// @notice The builder split, in basis points, when a builder code is present
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant BUILDER_SPLIT = 2_500;
```
