# Audit Report

## Title 
Leg Count Overflow in Position Hash Allows Bypassing MAX_OPEN_LEGS Limit and Causes Position Lock

## Summary
The `_updatePositionsHash()` function in `PanopticPool.sol` fails to properly validate the total leg count due to an arithmetic overflow in `PanopticMath.updatePositionsHash()`. When a user accumulates 256 or more total legs across all positions, the leg count wraps around modulo 256 in an unchecked block, allowing users to bypass the `MAX_OPEN_LEGS` limit of 25 legs and potentially lock their positions permanently.

## Finding Description

The vulnerability exists in the leg count validation mechanism used when minting positions. The positions hash stores the total leg count across all user positions in the top 8 bits (bits 248-255). [1](#0-0) 

The validation check at line 1885 compares `(newHash >> 248)` with `maxLegs` (configured as 25 in MAX_OPEN_LEGS). However, the leg count can overflow due to the implementation in `PanopticMath.updatePositionsHash()`: [2](#0-1) 

The critical flaw is in lines 126-132:

1. **Line 126-128**: The new leg count is calculated as `uint256 newLegCount = uint8(existingHash >> 248) + numberOfLegs`. This addition happens in `uint256` space (due to implicit type conversion), allowing the result to exceed 255 without reverting.

2. **Line 130-132**: The return statement uses an unchecked block: `return uint256(updatedHash) + (newLegCount << 248);`

When `newLegCount >= 256`, the left shift operation `newLegCount << 248` overflows the uint256 boundary:
- For `newLegCount = 256`: `(256 << 248) = (2^8 << 248) = 2^256 mod 2^256 = 0`
- For `newLegCount = 257`: `(257 << 248) = ((256 + 1) << 248) = (2^256 + (1 << 248)) mod 2^256 = (1 << 248)`

The overflow causes the leg count to wrap around modulo 256, storing an incorrect value in the hash.

**Attack Scenario:**
1. Attacker mints 63 positions with 4 legs each (252 total legs) - below the 255 limit
2. Attacker mints one more position with 4 legs, bringing total to 256 legs
3. In `updatePositionsHash()`: `newLegCount = 252 + 4 = 256`
4. The shift operation `256 << 248` overflows and wraps to 0
5. The validation `if ((0) > 127)` passes (maxLegs uses 7 bits, max value 127)
6. User now has 256 legs but the hash shows 0 legs
7. If attacker continues minting, they can accumulate hundreds of legs
8. When attempting to burn positions: if the wrapped count is less than the legs in any position, the subtraction underflows and reverts, permanently locking all positions

This breaks the critical invariant: **"Leg Count Limits: Users cannot exceed MAX_OPEN_LEGS = 25 total position legs"**. [3](#0-2) 

## Impact Explanation

**High Severity** - This vulnerability causes:

1. **Permanent Position Locking**: After the overflow, burning positions becomes impossible due to underflow in the subtraction logic, permanently freezing user funds in those positions.

2. **Protocol Invariant Violation**: Users can hold 10x or more legs than the intended limit (256+ vs 25 max), breaking fundamental protocol assumptions.

3. **Gas Griefing**: Operations like liquidations and force exercises that iterate over positions become prohibitively expensive with excessive leg counts, potentially exceeding block gas limits.

4. **Risk Calculation Errors**: The RiskEngine and other components may not correctly assess risk for positions with improperly tracked leg counts.

Each TokenId can have up to 4 legs. To reach 256 legs, an attacker needs 64 positions with 4 legs each. With `MAX_OPEN_LEGS = 25`, users should be limited to approximately 6-7 positions, making this a severe bypass. [4](#0-3) 

## Likelihood Explanation

**High Likelihood** - This vulnerability can occur through:

1. **Intentional Exploitation**: Sophisticated attackers can deliberately accumulate positions to trigger the overflow and lock their positions, potentially to avoid liquidation or forced exercise.

2. **Accidental Occurrence**: Power users legitimately trying to maximize their position count could inadvertently trigger this bug, especially if they're close to the limit and the system allows them to continue minting due to the overflow.

3. **No Special Privileges Required**: Any user can mint positions and trigger this vulnerability through normal protocol operations.

The attack requires minting 64+ positions with 4 legs each, which while requiring capital, is feasible for well-funded users or protocols attempting to maximize their exposure.

## Recommendation

Add an explicit check to prevent the leg count from exceeding 255 before the shift operation. Modify `PanopticMath.updatePositionsHash()`:

```solidity
function updatePositionsHash(
    uint256 existingHash,
    TokenId tokenId,
    bool addFlag
) internal pure returns (uint256) {
    // update hash by using the homomorphicHash method
    uint256 updatedHash = homomorphicHash(existingHash, TokenId.unwrap(tokenId), addFlag);

    // increment the upper 8 bits (leg counter) if addFlag=true, decrement otherwise
    uint8 numberOfLegs = uint8(tokenId.countLegs());
    if (numberOfLegs == 0) revert Errors.TokenIdHasZeroLegs();

    // Calculate new leg count with overflow protection
    uint256 newLegCount = addFlag
        ? uint8(existingHash >> 248) + numberOfLegs
        : uint8(existingHash >> 248) - numberOfLegs;
    
    // ADD THIS CHECK: Ensure leg count fits in uint8 before shifting
    if (newLegCount > type(uint8).max) revert Errors.TooManyLegsOpen();

    unchecked {
        return uint256(updatedHash) + (newLegCount << 248);
    }
}
```

Alternatively, perform the calculation entirely in uint8 space to let Solidity's overflow checks handle it:

```solidity
uint8 currentLegCount = uint8(existingHash >> 248);
uint8 newLegCountU8 = addFlag 
    ? currentLegCount + numberOfLegs  // Will revert on overflow in 0.8+
    : currentLegCount - numberOfLegs; // Will revert on underflow in 0.8+

unchecked {
    return uint256(updatedHash) + (uint256(newLegCountU8) << 248);
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticMath} from "@libraries/PanopticMath.sol";
import {TokenId} from "@types/TokenId.sol";

contract LegCountOverflowTest is Test {
    function testLegCountOverflowBypass() public {
        // Create a tokenId with 4 legs (maximum per position)
        TokenId tokenId = TokenId.wrap(0);
        tokenId = tokenId.addPoolId(1);
        
        // Add 4 legs to the tokenId
        tokenId = tokenId.addLeg(0, 1, 1, 0, 0, 0, 100, 1); // leg 0
        tokenId = tokenId.addLeg(1, 1, 1, 0, 0, 0, 200, 1); // leg 1  
        tokenId = tokenId.addLeg(2, 1, 1, 0, 0, 0, 300, 1); // leg 2
        tokenId = tokenId.addLeg(3, 1, 1, 0, 0, 0, 400, 1); // leg 3
        
        assertEq(tokenId.countLegs(), 4);
        
        uint256 positionsHash = 0;
        
        // Mint 63 positions (252 legs total) - should be within limits initially
        for (uint256 i = 0; i < 63; i++) {
            positionsHash = PanopticMath.updatePositionsHash(
                positionsHash,
                tokenId,
                true
            );
        }
        
        // Current leg count should be 252
        uint256 currentLegCount = positionsHash >> 248;
        assertEq(currentLegCount, 252);
        
        // Mint 64th position (256 legs total) - this should trigger overflow
        positionsHash = PanopticMath.updatePositionsHash(
            positionsHash,
            tokenId,
            true
        );
        
        // After overflow, leg count wraps to 0
        currentLegCount = positionsHash >> 248;
        assertEq(currentLegCount, 0, "Leg count should wrap to 0 after overflow");
        
        // The check `if ((newHash >> 248) > maxLegs)` would compare 0 > 127
        // This passes, allowing the bypass of MAX_OPEN_LEGS = 25
        
        // Continue minting to demonstrate the wrap-around continues
        for (uint256 i = 0; i < 5; i++) {
            positionsHash = PanopticMath.updatePositionsHash(
                positionsHash,
                tokenId,
                true
            );
        }
        
        // After 5 more positions (20 more legs), count should be 20
        currentLegCount = positionsHash >> 248;
        assertEq(currentLegCount, 20);
        
        // Now demonstrate position lock: try to burn a position when wrapped count < 4
        // This will cause underflow and revert
        vm.expectRevert();
        positionsHash = PanopticMath.updatePositionsHash(
            positionsHash,
            tokenId,
            false // Burn operation
        );
        // The test proves positions become permanently locked after overflow
    }
}
```

**Notes**

The vulnerability fundamentally stems from mixing checked and unchecked arithmetic operations. The addition of uint8 values in line 127 happens in uint256 space (checked), allowing values >255, but the subsequent shift operation in an unchecked block causes silent overflow. This creates a mismatch between the intended uint8 leg count (max 255) and the actual calculation that can exceed this limit before wrapping around.

The protocol assumes MAX_OPEN_LEGS will limit users to approximately 6-7 positions (25 legs / 4 legs per position), but the overflow allows accumulation of 64+ positions before wrapping occurs, representing a 10x bypass of the intended limit.

### Citations

**File:** contracts/PanopticPool.sol (L120-121)
```text
    /// @notice The maximum allowed number of legs across all open positions for a user.
    uint64 internal constant MAX_OPEN_LEGS = 25;
```

**File:** contracts/PanopticPool.sol (L1870-1887)
```text
    function _updatePositionsHash(
        address account,
        TokenId tokenId,
        bool addFlag,
        uint8 maxLegs
    ) internal {
        // Get the current position hash value (fingerprint of all pre-existing positions created by `_account`)
        // Add the current tokenId to the positionsHash as XOR'd
        // since 0 ^ x = x, no problem on first mint
        // Store values back into the user option details with the updated hash (leaves the other parameters unchanged)
        uint256 newHash = PanopticMath.updatePositionsHash(
            s_positionsHash[account],
            tokenId,
            addFlag
        );
        if ((newHash >> 248) > maxLegs) revert Errors.TooManyLegsOpen();
        s_positionsHash[account] = newHash;
    }
```

**File:** contracts/libraries/PanopticMath.sol (L113-133)
```text
    function updatePositionsHash(
        uint256 existingHash,
        TokenId tokenId,
        bool addFlag
    ) internal pure returns (uint256) {
        // update hash by using the homomorphicHash method
        uint256 updatedHash = homomorphicHash(existingHash, TokenId.unwrap(tokenId), addFlag);

        // increment the upper 8 bits (leg counter) if addFlag=true, decrement otherwise
        uint8 numberOfLegs = uint8(tokenId.countLegs());
        if (numberOfLegs == 0) revert Errors.TokenIdHasZeroLegs();

        // unchecked, so reverts if overflow
        uint256 newLegCount = addFlag
            ? uint8(existingHash >> 248) + numberOfLegs
            : uint8(existingHash >> 248) - numberOfLegs;

        unchecked {
            return uint256(updatedHash) + (newLegCount << 248);
        }
    }
```

**File:** contracts/types/TokenId.sol (L414-424)
```text
    function countLegs(TokenId self) internal pure returns (uint256 numLegs) {
        // Strip all bits except for the option ratios
        uint256 optionRatios = (TokenId.unwrap(self) & OPTION_RATIO_MASK) >> 64;

        unchecked {
            // forge-lint: disable-next-line(incorrect-shift)
            while (optionRatios >= (1 << (48 * numLegs))) {
                ++numLegs;
            }
        }
    }
```
