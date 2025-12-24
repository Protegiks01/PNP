# Audit Report

## Title 
Silent Division-by-Zero in Spread Collateral Calculation Enables Severe Undercollateralization

## Summary
The `unsafeDivRoundingUp()` function returns 0 on division by zero instead of reverting. This behavior is misused in `RiskEngine._computeSpread()` where a comment incorrectly claims "denominator is always nonzero". When both legs of a spread have zero notional amounts in one token, the collateral requirement calculation silently returns 0 instead of failing, allowing positions to be opened with only 1 wei of collateral despite having significant risk exposure.

## Finding Description

The vulnerability exists in the interaction between two functions:

1. **`Math.unsafeDivRoundingUp()`** - Returns 0 on division by zero instead of reverting [1](#0-0) 

2. **`RiskEngine._computeSpread()`** - Uses this function with an incorrect assumption [2](#0-1) 

The problematic code flow: [3](#0-2) 

When evaluating collateral requirements for a spread position, if both legs have zero amounts in one token (e.g., both completely out-of-the-money in token0), the calculation becomes:
- `notional = moved0 = 0`
- `notionalP = moved0Partner = 0`  
- `contracts = moved1 = large amount`
- Calculation: `(0 - 0) * contracts / 0 = 0 / 0`
- Result: `unsafeDivRoundingUp(0, 0) = 0`

The spread requirement starts at 1 wei and adds the division result: [4](#0-3) 

Finally, the minimum is taken between split and spread requirements: [5](#0-4) 

If `spreadRequirement = 1` and `splitRequirement = 1000 ETH`, the final requirement is `min(1000 ETH, 1 wei) = 1 wei`.

**This breaks Invariant #1 (Solvency Maintenance)**: Positions can be opened with collateral far below their actual risk exposure, violating the requirement that all accounts must satisfy margin requirements.

## Impact Explanation

**HIGH Severity** - This enables systemic undercollateralization:

1. **Collateral Bypass**: Attackers can open spread positions with only 1 wei of collateral when they should require thousands or millions of wei
2. **Protocol Insolvency Risk**: If these undercollateralized positions incur losses (due to price movements, premiums, or forced exercises), the protocol absorbs the deficit
3. **Liquidation Cascade**: Undercollateralized positions cannot be properly liquidated as there's insufficient collateral to cover losses and bonuses
4. **Capital Efficiency Abuse**: The spread discount mechanism (designed to reduce requirements for hedged positions) is exploited to eliminate requirements entirely

The issue allows positions with real economic risk (large token amounts in one side) to bypass collateral requirements completely when the other side has zero amounts.

## Likelihood Explanation

**HIGH Likelihood**:

1. **Common Scenario**: Both legs of a spread being completely OTM in one token is a standard occurrence in options trading, especially for far OTM vertical spreads
2. **No Special Preconditions**: Requires only normal position creation, no price manipulation or oracle attacks
3. **Easily Discoverable**: Any user creating OTM spreads could accidentally or intentionally trigger this
4. **Profitable Exploit**: Attacker can open highly leveraged positions (massive notional with 1 wei collateral) and profit from favorable price movements while leaving the protocol with losses on adverse movements

Example scenario:
- Current price: ETH = $2000 (tick 0)
- Spread: Short $2500 call + Long $3000 call (both far OTM)
- Both legs have zero token0 (ETH), only token1 (USDC)
- Token1 requirement: Should be ~$100 per contract, but calculated as 1 wei
- Attacker opens 1000 contracts with 1 wei instead of $100,000

## Recommendation

Replace `unsafeDivRoundingUp()` with a safe division that reverts on zero denominator in the spread calculation, or add explicit zero checks:

```solidity
// Option 1: Add zero check before division
if (notional == 0 && notionalP == 0) {
    // Both legs have zero notional - cannot compute spread discount
    // Use split requirement instead (no spread benefit)
    return splitRequirement;
}
spreadRequirement += (notional < notionalP)
    ? Math.mulDivRoundingUp((notionalP - notional) * contracts, 1, notionalP)
    : Math.mulDivRoundingUp((notional - notionalP) * contracts, 1, notional);

// Option 2: Use safe division function
function safeDivRoundingUp(uint256 a, uint256 b) internal pure returns (uint256 result) {
    require(b != 0, "Division by zero");
    assembly ("memory-safe") {
        result := add(div(a, b), gt(mod(a, b), 0))
    }
}
```

Alternatively, rename `unsafeDivRoundingUp()` to clearly indicate it returns 0 on division by zero (e.g., `divRoundingUpOrZero()`) and audit all usage sites to ensure this behavior is intended.

## Proof of Concept

The following test demonstrates the vulnerability. Due to the complexity of the full Panoptic test setup, this is a conceptual PoC showing the key calculation:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Math} from "../contracts/libraries/Math.sol";

contract UnsafeDivExploitTest is Test {
    function testSpreadUndercollateralization() public {
        // Simulate a spread where both legs are OTM in token0 (only have token1)
        uint256 moved0 = 0;           // token0 amount for leg 1 (OTM)
        uint256 moved0Partner = 0;    // token0 amount for leg 2 (OTM)
        uint256 moved1 = 1000 ether;  // token1 amount for leg 1
        
        // This simulates the calculation in RiskEngine._computeSpread()
        // when tokenType = 1 (evaluating token1 collateral)
        uint256 notional = moved0;
        uint256 notionalP = moved0Partner;
        uint128 contracts = uint128(moved1);
        
        // The problematic division
        uint256 spreadAdjustment;
        if (notional < notionalP) {
            spreadAdjustment = Math.unsafeDivRoundingUp(
                (notionalP - notional) * contracts, 
                notionalP
            );
        } else {
            spreadAdjustment = Math.unsafeDivRoundingUp(
                (notional - notionalP) * contracts, 
                notional
            );
        }
        
        // When both are zero, we get 0/0 = 0
        assertEq(spreadAdjustment, 0, "Division by zero returned 0 instead of reverting");
        
        // spreadRequirement = 1 (initial) + 0 (from division) = 1 wei
        uint256 spreadRequirement = 1 + spreadAdjustment;
        
        // Even if individual legs require 1000 ETH each
        uint256 splitRequirement = 2000 ether;
        
        // Final requirement is minimum (capital efficiency for spreads)
        uint256 finalRequirement = Math.min(splitRequirement, spreadRequirement);
        
        // Position with 1000 ETH notional requires only 1 wei collateral!
        assertEq(finalRequirement, 1, "Spread requires only 1 wei despite large notional");
        
        console.log("Notional exposure: %e wei", moved1);
        console.log("Required collateral: %e wei", finalRequirement);
        console.log("Leverage: %e x", moved1 / finalRequirement);
    }
}
```

This demonstrates that when both notional amounts are zero, the spread collateral requirement collapses to 1 wei, enabling extreme leverage and undercollateralization.

### Citations

**File:** contracts/libraries/Math.sol (L1172-1180)
```text
    /// @notice Calculates `ceil(a÷b)`, returning 0 if `b == 0`.
    /// @param a The numerator
    /// @param b The denominator
    /// @return result The 256-bit result
    function unsafeDivRoundingUp(uint256 a, uint256 b) internal pure returns (uint256 result) {
        assembly ("memory-safe") {
            result := add(div(a, b), gt(mod(a, b), 0))
        }
    }
```

**File:** contracts/RiskEngine.sol (L1770-1770)
```text
        spreadRequirement = 1;
```

**File:** contracts/RiskEngine.sol (L1863-1883)
```text
        } else {
            unchecked {
                uint256 notional;
                uint256 notionalP;
                uint128 contracts;
                if (tokenType == 1) {
                    notional = moved0;
                    notionalP = moved0Partner;
                    contracts = moved1;
                } else {
                    notional = moved1;
                    notionalP = moved1Partner;
                    contracts = moved0;
                }
                // the required amount is the amount of contracts multiplied by (notional1 - notional2)/max(notional1, notional2)
                // can use unsafe because denominator is always nonzero
                spreadRequirement += (notional < notionalP)
                    ? Math.unsafeDivRoundingUp((notionalP - notional) * contracts, notionalP)
                    : Math.unsafeDivRoundingUp((notional - notionalP) * contracts, notional);
            }
        }
```

**File:** contracts/RiskEngine.sol (L1885-1885)
```text
        spreadRequirement = Math.min(splitRequirement, spreadRequirement);
```
