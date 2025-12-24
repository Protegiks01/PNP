# Audit Report

## Title
Builder Fee System DoS Due to Insufficient Address Storage (uint128 vs uint160)

## Summary
The RiskParameters storage design allocates only 128 bits for the `feeRecipient` address field, while Ethereum addresses require 160 bits. This causes the `getRiskParameters()` function to revert for 99.9999999767% of possible builder addresses, effectively DoS'ing the builder fee distribution system.

## Finding Description
The protocol intends to support builder codes and distribute commission fees between the protocol and builders. However, a fundamental storage limitation prevents this system from functioning: [1](#0-0) 

The `feeRecipient` field is allocated 128 bits in the packed RiskParameters structure. When `getRiskParameters()` is called with a non-zero `builderCode`: [2](#0-1) 

The `_computeBuilderWallet()` function computes a CREATE2 address (160 bits): [3](#0-2) 

The address is then cast to uint128 using `toUint128()`, which includes a safety check: [4](#0-3) 

For any address where the upper 32 bits (bits 128-159) are non-zero, this check causes a revert with `CastingError`. Since CREATE2 addresses are derived from keccak256 hashes (uniformly distributed), the probability that an address fits in 128 bits is:

**P(address ≤ 2^128 - 1) = (1/2)^32 = 1 / 4,294,967,296 ≈ 0.00000002328%**

This means 99.9999999767% of builder addresses will cause the transaction to revert.

**Impact on Protocol Functionality:**

When users call `PanopticPool.dispatch()` with a non-zero `builderCode`: [5](#0-4) 

The call chain `dispatch()` → `getRiskParameters()` → `riskEngine().getRiskParameters()` → `toUint128()` will revert, preventing position minting/burning for any user attempting to use builder codes.

**Note on Original Security Question:**

The security question asked whether truncation could "redirect protocol fees to unintended addresses." The answer is **NO** - the `toUint128()` safety check prevents silent truncation and reverts instead. No fee redirection occurs. However, this reveals a more severe issue: the builder fee system is fundamentally broken due to insufficient storage allocation.

## Impact Explanation
**Severity: Medium (DoS Vulnerability)**

This issue causes a complete denial of service for the builder fee distribution system:

1. **Builder Fee System Non-Functional**: The protocol cannot distribute fees to builders for 99.9999999767% of possible addresses
2. **Limited Protocol Functionality**: Users can only use `builderCode = 0`, which directs all fees to the protocol with no builder split
3. **Business Logic Failure**: The entire builder incentive mechanism is broken
4. **No Workaround**: There is no way to use legitimate builder addresses within the current design

While no funds are directly at risk and users can still interact with the protocol using `builderCode = 0`, this represents a complete failure of a core protocol feature.

## Likelihood Explanation
**Likelihood: Certain (100%)**

This issue will occur with certainty for any attempt to use non-trivial builder codes:
- Any `builderCode` that generates a normal CREATE2 address will trigger the revert
- The probability of finding a compatible address is approximately 1 in 4.3 billion
- All current and future builder implementations are affected

## Recommendation
Increase the storage allocation for `feeRecipient` from 128 bits to 160 bits to accommodate full Ethereum addresses. This requires restructuring the RiskParameters packing:

**Current packing (256 bits total):**
- Bits 0-127: Various parameters (128 bits)
- Bits 128-255: feeRecipient (128 bits)

**Recommended packing:**
Reduce other fields or use a separate storage slot for `feeRecipient`. For example:
- Store `feeRecipient` as a separate storage variable in RiskEngine
- Reference it via an index in RiskParameters
- Or reduce the bit allocation of less critical parameters

**Alternative Fix:**
```solidity
// In RiskEngine.sol, change line 871 to:
address feeRecipient = _computeBuilderWallet(builderCode);

// Store the address separately, not in RiskParameters
// Access via riskEngine().getFeeRecipient(builderCode) when needed
```

This decouples address storage from the packed RiskParameters structure.

## Proof of Concept
```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract BuilderFeeDoSTest is Test {
    // Simplified demonstration of the issue
    
    function testBuilderAddressDoS() public {
        // Simulate a normal CREATE2 address computation
        bytes32 salt = bytes32(uint256(12345)); // Non-zero builderCode
        bytes32 h = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(0x1234), // Mock BUILDER_FACTORY
                salt,
                bytes32(0x5678) // Mock BUILDER_INIT_CODE_HASH
            )
        );
        
        address builderWallet = address(uint160(uint256(h)));
        
        // Demonstrate that this address requires more than 128 bits
        uint256 addressAsUint = uint256(uint160(builderWallet));
        
        console.log("Builder address:", builderWallet);
        console.log("Address as uint256:", addressAsUint);
        console.log("Max uint128:", type(uint128).max);
        console.log("Address fits in uint128:", addressAsUint <= type(uint128).max);
        
        // This will almost always be false for normal addresses
        assertFalse(
            addressAsUint <= type(uint128).max,
            "Normal addresses should NOT fit in uint128"
        );
        
        // Attempting to cast will lose data
        uint128 truncated = uint128(addressAsUint);
        assertNotEqual(
            uint256(truncated),
            addressAsUint,
            "Truncation loses upper 32 bits"
        );
        
        // The toUint128() function would revert here:
        // if ((downcastedInt = uint128(toDowncast)) != toDowncast) revert CastingError();
    }
    
    function testBuilderCodeZeroWorks() public {
        // builderCode = 0 returns address(0), which fits in uint128
        address zeroAddress = address(0);
        uint256 zeroAsUint = uint256(uint160(zeroAddress));
        
        assertTrue(
            zeroAsUint <= type(uint128).max,
            "address(0) fits in uint128"
        );
    }
}
```

**To run this test:**
```bash
forge test --match-test testBuilderAddressDoS -vv
```

This demonstrates that normal CREATE2-generated addresses will fail the `toUint128()` check, causing all `getRiskParameters()` calls with non-zero `builderCode` to revert with `CastingError`.

### Citations

**File:** contracts/types/RiskParameters.sol (L23-23)
```text
// (9) feeRecipient         128bits : The recipient of the commission fee split
```

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

**File:** contracts/PanopticPool.sol (L572-593)
```text
    function dispatch(
        TokenId[] calldata positionIdList,
        TokenId[] calldata finalPositionIdList,
        uint128[] calldata positionSizes,
        int24[3][] calldata tickAndSpreadLimits,
        bool usePremiaAsCollateral,
        uint256 builderCode
    ) external {
        // if safeMode, enforce covered at mint and exercise at burn
        RiskParameters riskParameters;

        LeftRightSigned cumulativeTickDeltas;
        {
            //assembly tload
            bytes32 slot = PRICE_TRANSIENT_SLOT;
            assembly {
                cumulativeTickDeltas := tload(slot)
            }
        }
        {
            int24 startTick;
            (riskParameters, startTick) = getRiskParameters(builderCode);
```
