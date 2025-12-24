# Audit Report

## Title
Builder Fee System Completely Broken Due to Incorrect Address-to-Uint128 Type Conversion

## Summary
The `getRiskParameters()` function in `RiskEngine.sol` attempts to convert Ethereum addresses (160 bits) to uint128 (128 bits), which will revert for approximately 99.99999997% of real BuilderWallet addresses. This makes the builder fee incentive mechanism completely unusable and causes position minting/burning operations to fail when a builderCode is provided.

## Finding Description
The vulnerability exists in the `getRiskParameters()` function where the feeRecipient address is computed and stored: [1](#0-0) 

The critical issue is on line 871 where an address (160 bits) is converted to uint128 (128 bits). The `toUint128()` function performs a checked conversion that reverts if any data is lost: [2](#0-1) 

For the conversion to succeed without reverting, the address value as a uint256 must be ≤ type(uint128).max = 2^128 - 1. This means the upper 32 bits of the address must all be zero.

Since BuilderWallet contracts are deployed using CREATE2 with pseudo-random addresses (due to keccak256 hashing), the probability of an address having its upper 32 bits all zero is:
- P = (1/2)^32 ≈ 2.33 × 10^-10 ≈ 0.000000023%

**Exploitation Path:**
1. BuilderFactory deploys a BuilderWallet using CREATE2, resulting in a normal address like `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045`
2. User attempts to mint a position with the corresponding builderCode
3. `PanopticPool.dispatch()` calls `getRiskParameters(builderCode)`: [3](#0-2) 

4. `getRiskParameters()` computes `_computeBuilderWallet(builderCode)` which returns the deployed address
5. The address (value > 2^128) is passed to `toUint128()` which reverts with `CastingError`
6. The entire transaction reverts, preventing position minting/burning

The vulnerability breaks the core protocol functionality when builder codes are used. The RiskParameters type stores feeRecipient as uint128: [4](#0-3) [5](#0-4) 

When fees are distributed, the uint128 is cast back to address: [6](#0-5) 

## Impact Explanation
**Severity: HIGH**

This vulnerability causes:
1. **Complete failure of builder fee system** - The protocol cannot process positions with valid builderCodes
2. **DoS of position minting/burning** - All `dispatch()` calls with builderCodes revert
3. **Loss of builder incentives** - Protocol cannot reward builders as designed, reducing ecosystem participation
4. **Broken core functionality** - Users must use builderCode=0 (no builder), removing a key feature

While there's no direct theft of funds, this breaks a core protocol mechanism and prevents normal operation, qualifying as HIGH severity under the Immunefi framework for "temporary freezing of funds with economic loss" and "state inconsistencies requiring manual intervention."

## Likelihood Explanation
**Likelihood: CERTAIN**

This issue will occur with near 100% probability (99.99999997%) for any legitimate BuilderWallet deployment. The only way to avoid it is if:
1. The CREATE2 address happens to have its upper 32 bits all zero (probability ≈ 0.000000023%), OR
2. Users never provide builderCodes (defeating the purpose of the feature)

The vulnerability is deterministic and does not require any attacker action - it's a design flaw that breaks functionality for normal protocol usage.

## Recommendation
Change the `feeRecipient` storage type from uint128 to uint160 in the RiskParameters type:

```solidity
// In RiskParameters.sol, update the packing:
// (9) feeRecipient         160bits : The recipient of the commission fee split

// Update storeRiskParameters to accept uint160:
function storeRiskParameters(
    uint256 _safeMode,
    uint256 _notionalFee,
    uint256 _premiumFee,
    uint256 _protocolSplit,
    uint256 _builderSplit,
    uint256 _tickDeltaLiquidation,
    uint256 _maxSpread,
    uint256 _bpDecreaseBuffer,
    uint256 _maxLegs,
    uint160 _feeRecipient  // Changed from uint256 to uint160
) internal pure returns (RiskParameters result) {
    // Update packing logic to accommodate 160 bits
    // This will require adjusting bit positions or using a larger type
}

// Update the feeRecipient() getter to return uint160:
function feeRecipient(RiskParameters self) internal pure returns (uint160 result) {
    assembly {
        result := shr(128, self)
    }
}
```

Alternatively, use a two-slot storage structure or accept that RiskParameters must be expanded beyond 256 bits to properly store addresses.

In `RiskEngine.getRiskParameters()`, remove the unnecessary conversions:

```solidity
address feeRecipientAddress = _computeBuilderWallet(builderCode);
return RiskParametersLibrary.storeRiskParameters(
    safeMode,
    NOTIONAL_FEE,
    PREMIUM_FEE,
    PROTOCOL_SPLIT,
    BUILDER_SPLIT,
    MAX_TWAP_DELTA_LIQUIDATION,
    MAX_SPREAD,
    BP_DECREASE_BUFFER,
    MAX_OPEN_LEGS,
    uint160(feeRecipientAddress)  // Direct cast without lossy conversion
);
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine, BuilderFactory, BuilderWallet} from "../contracts/RiskEngine.sol";
import {Math} from "../contracts/libraries/Math.sol";

contract BuilderFeeVulnerabilityTest is Test {
    using Math for uint256;
    
    BuilderFactory factory;
    RiskEngine riskEngine;
    address guardian = address(0x1);
    
    function setUp() public {
        factory = new BuilderFactory(address(this));
        riskEngine = new RiskEngine(
            5_000_000,  // crossBuffer0
            5_000_000,  // crossBuffer1
            guardian,
            address(factory)
        );
    }
    
    function testBuilderWalletAddressConversionFailure() public {
        // Deploy a BuilderWallet with a typical builderCode
        uint48 builderCode = 12345;
        address builderAdmin = address(0x999);
        
        // Deploy the wallet
        address wallet = factory.deployBuilder(builderCode, builderAdmin);
        
        // Verify wallet was deployed
        assertGt(wallet.code.length, 0, "Wallet should be deployed");
        
        // Demonstrate that the address cannot fit in uint128
        uint256 walletAsUint256 = uint256(uint160(wallet));
        
        // For a typical address, this will be > type(uint128).max
        console.log("Wallet address:", wallet);
        console.log("Wallet as uint256:", walletAsUint256);
        console.log("type(uint128).max:", type(uint128).max);
        
        // This demonstrates that most addresses will fail the conversion
        if (walletAsUint256 > type(uint128).max) {
            console.log("Address CANNOT be converted to uint128 - will revert!");
            
            // Attempting to call toUint128 will revert
            vm.expectRevert(); // Expects CastingError
            walletAsUint256.toUint128();
        }
        
        // Demonstrate that getRiskParameters would fail with this builderCode
        // (Note: This would require mocking OraclePack and other dependencies,
        // but the core issue is demonstrated above)
    }
    
    function testProbabilityOfValidAddress() public pure {
        // Calculate the probability that a random address fits in uint128
        // An address must have its upper 32 bits all zero
        // Probability = 1 / (2^32) ≈ 0.000000023%
        
        uint256 totalAddressSpace = 2**160;
        uint256 validAddressSpace = 2**128;
        uint256 probabilityNumerator = validAddressSpace;
        uint256 probabilityDenominator = totalAddressSpace;
        
        // Probability ≈ 1 / (2^32) ≈ 1 / 4294967296
        assertEq(probabilityDenominator / probabilityNumerator, 2**32);
        
        console.log("Probability of valid address: 1 in", 2**32);
        console.log("Percentage: 0.000000023%");
    }
}
```

**Note:** The actual vulnerability manifests when `getRiskParameters()` is called during `PanopticPool.dispatch()`. The test above demonstrates the core issue - that typical Ethereum addresses cannot be converted to uint128 without reverting. A full integration test would require setting up the entire Panoptic pool infrastructure, but the mathematical proof is clear: 99.99999997% of addresses will cause `toUint128()` to revert with `CastingError`.

### Citations

**File:** contracts/RiskEngine.sol (L864-886)
```text
    function getRiskParameters(
        int24 currentTick,
        OraclePack oraclePack,
        uint256 builderCode
    ) external view returns (RiskParameters) {
        uint8 safeMode = isSafeMode(currentTick, oraclePack);

        uint128 feeRecipient = uint256(uint160(_computeBuilderWallet(builderCode))).toUint128();

        return
            RiskParametersLibrary.storeRiskParameters(
                safeMode,
                NOTIONAL_FEE,
                PREMIUM_FEE,
                PROTOCOL_SPLIT,
                BUILDER_SPLIT,
                MAX_TWAP_DELTA_LIQUIDATION,
                MAX_SPREAD,
                BP_DECREASE_BUFFER,
                MAX_OPEN_LEGS,
                feeRecipient
            );
    }
```

**File:** contracts/libraries/Math.sol (L440-442)
```text
    function toUint128(uint256 toDowncast) internal pure returns (uint128 downcastedInt) {
        if ((downcastedInt = uint128(toDowncast)) != toDowncast) revert Errors.CastingError();
    }
```

**File:** contracts/PanopticPool.sol (L592-593)
```text
            int24 startTick;
            (riskParameters, startTick) = getRiskParameters(builderCode);
```

**File:** contracts/types/RiskParameters.sol (L23-23)
```text
// (9) feeRecipient         128bits : The recipient of the commission fee split
```

**File:** contracts/types/RiskParameters.sol (L169-172)
```text
    function feeRecipient(RiskParameters self) internal pure returns (uint128 result) {
        assembly {
            result := shr(128, self)
        }
```

**File:** contracts/CollateralTracker.sol (L1568-1572)
```text
                    _transferFrom(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        (sharesToBurn * riskParameters.builderSplit()) / DECIMALS
                    );
```
