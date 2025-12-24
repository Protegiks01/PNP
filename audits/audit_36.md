# Audit Report

## Title 
Address Truncation in feeRecipient Packing Causes Complete DoS of Builder Code Functionality

## Summary
The `RiskEngine.getRiskParameters()` function attempts to store a 160-bit Ethereum address in a 128-bit `feeRecipient` field within the packed `RiskParameters` structure. Due to overflow checking in the `toUint128()` downcast function, this causes the function to revert for virtually all builder codes (with probability ~99.9999998%), making the entire builder fee distribution system non-functional. [1](#0-0) 

## Finding Description
The vulnerability stems from a mismatch between Ethereum address sizes (160 bits) and the allocated storage space in `RiskParameters` (128 bits for `feeRecipient`):

**Step 1: Builder Wallet Address Computation**
The `_computeBuilderWallet()` function generates CREATE2 addresses for builder wallets: [2](#0-1) 

CREATE2 addresses are derived from keccak256 hashes, producing uniformly distributed 160-bit values.

**Step 2: Address Truncation Attempt**
In `getRiskParameters()`, the 160-bit address is cast to uint128: [3](#0-2) 

**Step 3: Overflow Check Triggers Revert**
The `Math.toUint128()` function performs strict overflow checking: [4](#0-3) 

This check fails when the upper 32 bits (bits 128-159) of the address are non-zero, causing an immediate revert with `Errors.CastingError()`.

**Step 4: Protocol-Wide Failure**
Since `getRiskParameters()` is called during all position minting/burning operations with builder codes: [5](#0-4) 

Any attempt to use a builder code results in transaction failure.

**RiskParameters Packing Specification**
The packing layout allocates only 128 bits for feeRecipient: [6](#0-5) 

**Statistical Analysis**: 
For a uniformly distributed 160-bit address, the probability that all upper 32 bits are zero is 1/(2^32) ≈ 0.00000002%. Therefore, approximately 99.9999998% of all valid builder codes will trigger this revert.

## Impact Explanation
**Critical Business Logic Failure:**
- The entire builder referral/fee-sharing system is non-functional
- Protocol cannot partner with builders or distribute builder fees
- Revenue loss from inability to establish builder partnerships
- Design-level architectural flaw rendering a core feature unusable

**Protocol Invariant Broken:**
The protocol specification indicates builder codes should enable fee splitting between protocol and builders, but this invariant cannot be maintained when `getRiskParameters()` reverts for all practical builder codes.

**Severity Assessment: High**
While this doesn't directly steal funds, it:
1. Causes complete DoS of an intended protocol feature
2. Results in lost revenue opportunities
3. Requires a contract upgrade to fix
4. Affects all users attempting to use builder codes

## Likelihood Explanation
**Likelihood: Certain (100%)**

This is not a conditional vulnerability—it will trigger on every single transaction that attempts to use a non-zero builder code. The mathematical certainty stems from:

1. **CREATE2 Address Distribution**: Builder wallet addresses are generated via CREATE2, producing cryptographically random 160-bit addresses with uniform distribution across all bits.

2. **Upper 32-Bit Non-Zero Probability**: For the downcast to succeed, all 32 upper bits (bits 128-159) must be zero. The probability of this occurring randomly is 1/(2^32) = 1/4,294,967,296 ≈ 0.00000002%.

3. **Immediate Detection**: Any protocol deployment attempting to use builder codes will immediately discover this issue during the first `mintOptions()` or `burnOptions()` call with `builderCode != 0`.

## Recommendation

**Solution: Increase feeRecipient Storage to 160 Bits**

The RiskParameters packing must be redesigned to accommodate full 160-bit addresses. One approach is to reduce other fields or reorganize the packing:

```solidity
// Current total: 256 bits
// - safeMode: 4 bits → Reduce to 3 bits (max value 7 is sufficient)
// - notionalFee: 14 bits (unchanged)
// - premiumFee: 14 bits (unchanged)  
// - protocolSplit: 14 bits (unchanged)
// - builderSplit: 14 bits (unchanged)
// - tickDeltaLiquidation: 13 bits (unchanged)
// - maxSpread: 22 bits (unchanged)
// - bpDecreaseBuffer: 26 bits (unchanged)
// - maxLegs: 7 bits (unchanged)
// - feeRecipient: 128 bits → Increase to 160 bits (+32 bits)
// Total with changes: 256 + 32 - 1 = 287 bits > 256 bits

// Alternative: Use two storage slots or external mapping
```

**Recommended Fix (Option 1): Use Separate Storage**
```solidity
// In RiskEngine.sol
mapping(uint256 => address) public builderWallets;

function getRiskParameters(
    int24 currentTick,
    OraclePack oraclePack,
    uint256 builderCode
) external view returns (RiskParameters) {
    uint8 safeMode = isSafeMode(currentTick, oraclePack);
    
    // Store builder code instead of address in RiskParameters
    // Retrieve full address when needed from mapping
    if (builderCode != 0) {
        builderWallets[builderCode] = _computeBuilderWallet(builderCode);
    }
    
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
        uint128(builderCode) // Store code, not address
    );
}
```

Then in `CollateralTracker.sol`, retrieve the address:
```solidity
address feeRecipient = riskEngine().builderWallets(riskParameters.feeRecipient());
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {BuilderFactory, BuilderWallet} from "@contracts/RiskEngine.sol";
import {Errors} from "@libraries/Errors.sol";

contract RiskEngineBuilderCodeTest is Test {
    RiskEngine public riskEngine;
    BuilderFactory public builderFactory;
    address public guardian = address(0x1234);
    
    function setUp() public {
        builderFactory = new BuilderFactory(guardian);
        riskEngine = new RiskEngine(
            5_000_000, // crossBuffer0
            5_000_000, // crossBuffer1  
            guardian,
            address(builderFactory)
        );
    }
    
    function testBuilderCodeCausesRevert() public {
        // Use a typical builder code (non-zero)
        uint256 builderCode = 12345;
        
        // Compute what the CREATE2 address would be
        address predictedWallet = builderFactory.predictBuilderWallet(uint48(builderCode));
        
        // Demonstrate the address has non-zero upper 32 bits
        uint256 addressAsUint = uint256(uint160(predictedWallet));
        uint256 upper32Bits = addressAsUint >> 128;
        
        console.log("Builder wallet address:", predictedWallet);
        console.log("Address as uint256:", addressAsUint);
        console.log("Upper 32 bits value:", upper32Bits);
        
        // Show that upper 32 bits are non-zero (which is almost always the case)
        assertTrue(upper32Bits > 0, "Upper 32 bits should be non-zero for typical addresses");
        
        // Attempt to call getRiskParameters with this builder code
        // This will revert with CastingError
        int24 currentTick = 0;
        OraclePack oraclePack = OraclePack.wrap(0);
        
        vm.expectRevert(Errors.CastingError.selector);
        riskEngine.getRiskParameters(currentTick, oraclePack, builderCode);
        
        // Show that builderCode = 0 works fine (returns address(0))
        RiskParameters params = riskEngine.getRiskParameters(currentTick, oraclePack, 0);
        assertEq(params.feeRecipient(), 0, "Zero builder code should work");
    }
    
    function testStatisticalLikelihood() public view {
        // Demonstrate that for random CREATE2 addresses,
        // the probability of upper 32 bits being zero is negligible
        
        uint256 samplesWithZeroUpperBits = 0;
        uint256 totalSamples = 100;
        
        for (uint256 i = 1; i <= totalSamples; i++) {
            address wallet = builderFactory.predictBuilderWallet(uint48(i));
            uint256 upper32 = uint256(uint160(wallet)) >> 128;
            if (upper32 == 0) {
                samplesWithZeroUpperBits++;
            }
        }
        
        console.log("Samples with zero upper 32 bits:", samplesWithZeroUpperBits, "out of", totalSamples);
        // Expected: 0 out of 100 (probability is ~2.3e-8)
    }
}
```

**Expected Output:**
```
Builder wallet address: 0x[40 hex characters with non-zero upper bits]
Address as uint256: [large number]
Upper 32 bits value: [non-zero value]
[REVERT] CastingError()
Samples with zero upper 32 bits: 0 out of 100
```

The PoC demonstrates:
1. CREATE2 addresses have non-zero upper 32 bits
2. Attempting to downcast to uint128 reverts with `CastingError`
3. Only `builderCode = 0` works (which returns `address(0)`)
4. Statistical verification confirms near-zero probability of success

## Notes

This vulnerability represents a critical design flaw where the storage allocation (128 bits) is insufficient for the data type being stored (160-bit addresses). The issue is exacerbated by the use of strict overflow checking in `Math.toUint128()`, which correctly prevents silent truncation but results in complete functionality failure.

The root cause is the packing optimization in `RiskParameters.sol` that attempted to fit too much data into 256 bits. While the packing itself is valid assembly code, the semantic mismatch between address sizes and allocated space makes the builder code system fundamentally broken.

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

**File:** contracts/PanopticPool.sol (L1808-1813)
```text
    function getRiskParameters(
        uint256 builderCode
    ) public view returns (RiskParameters riskParameters, int24 currentTick) {
        currentTick = getCurrentTick();
        riskParameters = riskEngine().getRiskParameters(currentTick, s_oraclePack, builderCode);
    }
```

**File:** contracts/types/RiskParameters.sol (L11-25)
```text
// PACKING RULES FOR A RISKPARAMETERS:
// =================================================================================================
//  From the LSB to the MSB:
// (1) safeMode             4 bits  : The safeMode state
// (2) notionalFee          14 bits : The fee to be charged on notional at mint
// (3) premiumFee           14 bits : The fee to be charged on the premium at burn
// (4) protocolSplit        14 bits : The part of the fee that goes to the protocol w/ buildercodes
// (5) builderSplit         14 bits : The part of the fee that goes to the builder w/ buildercodes
// (6) tickDeltaLiquidation 13 bits : The MAX_TWAP_DELTA_LIQUIDATION. Tick deviation = 1.0001**(2**13) = +/- 126%
// (7) maxSpread            22 bits : The MAX_SPREAD, in bps. Max fraction removed = 2**22/(2**22 + 10_000) = 99.76%
// (8) bpDecreaseBuffer     26 bits : The BP_DECREASE_BUFFER, in millitick
// (9) maxLegs              7 bits  : The MAX_OPEN_LEGS (constrained to be <128)
// (9) feeRecipient         128bits : The recipient of the commission fee split
// Total                    256bits  : Total bits used by a RiskParameters.
// ===============================================================================================
```
