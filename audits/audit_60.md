# Audit Report

## Title
Builder Code System Completely Non-Functional Due to Address Storage Limitation

## Summary
The builder code system fails for approximately 99.9999999767% of possible builder codes because Ethereum addresses (160 bits) cannot fit into the 128-bit storage allocated for `feeRecipient` in RiskParameters. This causes all transactions using non-zero builder codes to revert with a CastingError, rendering the builder fee distribution mechanism completely unusable.

## Finding Description
The vulnerability exists in the address storage and retrieval mechanism for builder fee recipients:

In `RiskEngine.sol`, the `getRiskParameters()` function attempts to store a CREATE2-computed address (160 bits) into a uint128 field (128 bits): [1](#0-0) 

The `_computeBuilderWallet()` function uses CREATE2 to deterministically compute an address from a builderCode, which produces uniformly distributed 160-bit addresses: [2](#0-1) 

The critical issue is that `toUint128()` in the Math library includes an overflow check that reverts if the value doesn't fit: [3](#0-2) 

Since CREATE2 addresses are uniformly distributed across the full 160-bit address space, the probability that an address fits within 128 bits is 2^128 / 2^160 = 1 / 2^32 ≈ 0.000000023% (approximately 1 in 4.3 billion).

This means when users call `dispatch()` with a builderCode: [4](#0-3) 

The transaction flow is:
1. `dispatch()` calls `getRiskParameters(builderCode)`
2. `getRiskParameters()` computes the CREATE2 address  
3. Address conversion to uint128 fails via `toUint128()` revert
4. Entire transaction reverts with CastingError

The RiskParameters packing allocates only 128 bits for feeRecipient in the most significant bits: [5](#0-4) 

And extracts it via right shift: [6](#0-5) 

While the extraction logic itself is correct, the fundamental design flaw is that Ethereum addresses require 160 bits of storage, not 128 bits.

Regarding the original question about address collisions: No collision occurs in practice because the system reverts before storing addresses that don't fit. However, if the overflow check were removed or bypassed, multiple different 160-bit addresses sharing the same lower 128 bits would indeed map to the same truncated recipient address when reconstructed via: [7](#0-6) 

## Impact Explanation
**Medium Severity** - This is a Denial of Service vulnerability affecting a core protocol feature:

- Builder code functionality is completely broken - builders cannot receive their allocated fee share
- All users attempting to specify a builder code (except for extremely rare cases where the computed address happens to be < 2^128) will have their transactions revert
- No direct fund loss or theft occurs
- No collateral calculations or protocol solvency is affected
- This breaks economic incentives for builders but doesn't create systemic risk

Per the Immunefi scope, this falls under Medium severity as a "DoS vulnerability" affecting protocol functionality without causing direct fund loss.

## Likelihood Explanation
**Very High Likelihood** - This issue occurs deterministically:

- Any user attempting to use a builder code has a 99.9999999767% chance of transaction failure
- Only builder codes that happen to generate addresses with numeric values < 2^128 will work (approximately 1 in 4.3 billion)
- The issue is not probabilistic or dependent on external conditions - it's a deterministic design flaw
- Every attempt to use the builder code feature (except for astronomically rare cases) will fail

## Recommendation
Increase the feeRecipient storage from 128 bits to 160 bits to accommodate full Ethereum addresses. This requires restructuring the RiskParameters packing:

**Option 1**: Reduce other fields or use a separate storage slot for feeRecipient
**Option 2**: Store feeRecipient separately outside of the packed RiskParameters struct

Recommended fix:
```solidity
// In RiskParameters.sol, change packing to allocate 160 bits for feeRecipient
// This may require using 320 bits total (two uint256 slots) or reducing other field sizes

// In RiskEngine.sol, remove the toUint128() conversion:
uint160 feeRecipient = uint160(_computeBuilderWallet(builderCode));

// Update storeRiskParameters to accept uint160 for feeRecipient
// Update feeRecipient() to return uint160 instead of uint128

// In CollateralTracker.sol, update to use uint160 directly:
address(riskParameters.feeRecipient()) // Now feeRecipient() returns uint160
```

## Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine} from "contracts/RiskEngine.sol";
import {PanopticPool} from "contracts/PanopticPool.sol";

contract BuilderCodeDoSTest is Test {
    RiskEngine riskEngine;
    PanopticPool panopticPool;
    
    function setUp() public {
        // Deploy contracts (constructor parameters omitted for brevity)
        riskEngine = new RiskEngine(1000, 1000, address(this), address(this));
    }
    
    function testBuilderCodeCausesRevert() public {
        // Try 100 random builder codes
        uint256 revertCount = 0;
        
        for (uint256 i = 1; i <= 100; i++) {
            uint256 builderCode = uint256(keccak256(abi.encode(i)));
            
            try riskEngine.getRiskParameters(0, OraclePack.wrap(0), builderCode) {
                // Success - address fits in uint128 (extremely rare)
            } catch {
                revertCount++;
            }
        }
        
        // Expect nearly all attempts to revert
        assertGe(revertCount, 99, "Builder codes should fail ~99.999999976% of the time");
        
        console.log("Reverts:", revertCount, "out of 100 builder codes");
    }
    
    function testSpecificBuilderCodeRevert() public {
        // Most builder codes will compute to addresses > 2^128
        uint256 builderCode = 12345;
        
        // This will revert with CastingError
        vm.expectRevert();
        riskEngine.getRiskParameters(0, OraclePack.wrap(0), builderCode);
    }
}
```

## Notes

While the original security question asks about "address collisions," the actual vulnerability is more severe - the system doesn't reach the point of potential collision because it fails completely for nearly all builder codes. The 128-bit storage limitation makes the builder code feature non-functional rather than causing collision issues. This represents a critical design flaw that requires protocol-level fixes to restore builder code functionality.

### Citations

**File:** contracts/RiskEngine.sol (L253-263)
```text
    function _computeBuilderWallet(uint256 builderCode) internal view returns (address wallet) {
        if (builderCode == 0) return address(0);

        bytes32 salt = bytes32(builderCode);

        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), BUILDER_FACTORY, salt, BUILDER_INIT_CODE_HASH)
        );

        wallet = address(uint160(uint256(h)));
    }
```

**File:** contracts/RiskEngine.sol (L871-871)
```text
        uint128 feeRecipient = uint256(uint160(_computeBuilderWallet(builderCode))).toUint128();
```

**File:** contracts/libraries/Math.sol (L440-442)
```text
    function toUint128(uint256 toDowncast) internal pure returns (uint128 downcastedInt) {
        if ((downcastedInt = uint128(toDowncast)) != toDowncast) revert Errors.CastingError();
    }
```

**File:** contracts/PanopticPool.sol (L572-579)
```text
    function dispatch(
        TokenId[] calldata positionIdList,
        TokenId[] calldata finalPositionIdList,
        uint128[] calldata positionSizes,
        int24[3][] calldata tickAndSpreadLimits,
        bool usePremiaAsCollateral,
        uint256 builderCode
    ) external {
```

**File:** contracts/types/RiskParameters.sol (L23-23)
```text
// (9) feeRecipient         128bits : The recipient of the commission fee split
```

**File:** contracts/types/RiskParameters.sol (L169-173)
```text
    function feeRecipient(RiskParameters self) internal pure returns (uint128 result) {
        assembly {
            result := shr(128, self)
        }
    }
```

**File:** contracts/CollateralTracker.sol (L1570-1570)
```text
                        address(uint160(riskParameters.feeRecipient())),
```
