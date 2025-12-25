# VALID VULNERABILITY - Builder Fee System Type Conversion Failure

## Title
Builder Fee System DoS Due to Address-to-Uint128 Type Conversion Error

## Summary
The `getRiskParameters()` function in `RiskEngine.sol` attempts to downcast Ethereum addresses (160 bits) to uint128 (128 bits), causing transaction reverts for 99.99999997% of valid BuilderWallet addresses. This completely breaks the builder fee incentive mechanism and causes all position minting/burning operations with builderCodes to fail.

## Impact

**Severity**: High

**Category**: Temporary Freezing with Economic Loss / State Inconsistency

The vulnerability causes:
- **Complete DoS of builder fee system** - Protocol cannot process any positions with non-zero builderCodes (99.99999997% failure rate)
- **Broken core functionality** - Users must always use builderCode=0, defeating the purpose of the builder incentive feature
- **Loss of ecosystem incentives** - Builders cannot receive fees as designed, reducing protocol adoption
- **Widespread transaction reverts** - All dispatch() operations with builderCodes will revert

This affects all users attempting to use the builder code feature. While there is no direct fund theft, this breaks a core protocol mechanism designed to incentivize ecosystem growth, qualifying as HIGH severity.

## Finding Description

**Location**: [1](#0-0) 

**Intended Logic**: The protocol should store builder wallet addresses as fee recipients and distribute builder fees to these addresses when positions are minted/burned with valid builderCodes.

**Actual Logic**: The code attempts to downcast a 160-bit Ethereum address to 128 bits, which mathematically fails for addresses whose upper 32 bits are non-zero. Since CREATE2 addresses are computed from keccak256 hashes (effectively random), the probability of success is (1/2)^32 ≈ 0.000000023%.

**Code Evidence**:
The vulnerable conversion occurs at: [1](#0-0) 

The `toUint128()` function performs checked conversion that reverts on overflow: [2](#0-1) 

The `_computeBuilderWallet()` function computes addresses using CREATE2: [3](#0-2) 

**Exploitation Path**:

1. **Precondition**: Guardian deploys a BuilderWallet using CREATE2 via BuilderFactory, resulting in a standard Ethereum address (e.g., `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045`)

2. **Step 1**: User attempts to mint/burn a position with the corresponding builderCode
   - Code path: User calls `PanopticPool.dispatch()` → [4](#0-3) 

3. **Step 2**: RiskEngine computes builder wallet and attempts conversion
   - `getRiskParameters()` calls `_computeBuilderWallet()` which returns the 160-bit address
   - The address value (> 2^128 for 99.99999997% of addresses) is passed to `toUint128()`

4. **Step 3**: Transaction reverts with CastingError
   - The `toUint128()` function checks if data is lost: `if ((downcastedInt = uint128(toDowncast)) != toDowncast) revert Errors.CastingError()`
   - For a typical address, the upper 32 bits are non-zero, causing the condition to trigger

5. **Step 4**: Position minting/burning fails completely
   - The entire dispatch transaction reverts
   - User cannot complete their intended operation
   - Builder fee system is non-functional

**Security Property Broken**: The RiskParameters type incorrectly stores feeRecipient as uint128 instead of uint160: [5](#0-4) 

When fees are distributed, the uint128 is cast back to address(uint160()): [6](#0-5)  and [7](#0-6) 

**Root Cause Analysis**:
- The RiskParameters type packing uses 128 bits for feeRecipient, but Ethereum addresses require 160 bits
- The CREATE2 deployment mechanism produces addresses with effectively random distribution across the full 160-bit space
- The probability of an address having its upper 32 bits all zero is (1/2)^32 ≈ 2.33 × 10^-10
- No validation exists to ensure BuilderWallet addresses are compatible with uint128 storage

## Impact Explanation

**Affected Assets**: No direct asset loss, but protocol functionality severely impaired

**Damage Severity**:
- **Quantitative**: 99.99999997% of legitimate BuilderWallet addresses will cause transaction reverts. Only ~1 in 4.3 billion addresses would succeed.
- **Qualitative**: Complete failure of the builder incentive mechanism, which is designed to drive ecosystem adoption and participation.

**User Impact**:
- **Who**: All users attempting to use builderCodes, all builders expecting fee distribution
- **Conditions**: Occurs during normal protocol operation with any realistic BuilderWallet deployment
- **Recovery**: Users must use builderCode=0 (no builder) for all operations, defeating the feature's purpose

**Systemic Risk**:
- Protocol cannot incentivize builders as designed
- Reduced ecosystem participation and growth
- Feature is effectively non-functional without code modification
- Requires protocol upgrade to fix

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Not an attack - this is a design flaw affecting normal users
- **Resources Required**: None - occurs during standard protocol usage
- **Technical Skill**: None - anyone using a builderCode triggers the issue

**Preconditions**:
- **Market State**: Normal operation
- **System State**: BuilderWallet deployed with standard CREATE2 address
- **Timing**: Occurs immediately when any user provides a non-zero builderCode

**Execution Complexity**:
- **Transaction Count**: Single dispatch() call
- **Coordination**: None required
- **Detection Risk**: Immediate (transaction reverts)

**Frequency**:
- **Repeatability**: Every transaction with non-zero builderCode from 99.99999997% of deployed BuilderWallets
- **Scale**: Affects all users attempting to use the builder code feature

**Overall Assessment**: CERTAIN (99.99999997% probability) - This is a deterministic failure, not an exploit. The issue will manifest during normal protocol usage with virtually any legitimate BuilderWallet deployment.

## Recommendation

**Immediate Mitigation**:
Deploy only BuilderWallets with addresses whose upper 32 bits are zero (impractical - requires ~4.3 billion deployment attempts per successful wallet).

**Permanent Fix**:
Modify RiskParameters type to store feeRecipient as uint160 instead of uint128:

```solidity
// File: contracts/types/RiskParameters.sol
// Modify the bit packing scheme:
// Change line 23 from:
// (9) feeRecipient         128bits : The recipient of the commission fee split
// To:
// (9) feeRecipient         160bits : The recipient of the commission fee split
```

Then update the packing logic in `storeRiskParameters()` and extraction logic in `feeRecipient()` to handle uint160.

In `RiskEngine.sol`, remove the unnecessary conversion:
```solidity
// File: contracts/RiskEngine.sol
// Line 871, change from:
// uint128 feeRecipient = uint256(uint160(_computeBuilderWallet(builderCode))).toUint128();
// To:
// uint160 feeRecipient = uint160(_computeBuilderWallet(builderCode));
```

**Additional Measures**:
- Add validation in BuilderFactory to verify deployed addresses are recordable
- Add integration tests verifying full dispatch flow with realistic builderCodes
- Document the address space requirements for BuilderWallet deployments

## Proof of Concept

**Note**: The report provided does not include a working PoC. However, the vulnerability is straightforward to demonstrate:

```solidity
// File: test/foundry/core/BuilderFeeRevert.t.sol
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";

contract BuilderFeeRevertTest is Test {
    RiskEngine riskEngine;
    PanopticPool pool;
    
    function testBuilderCodeCausesRevert() public {
        // Setup: Deploy contracts and initialize pool
        // ... (setup code)
        
        // Deploy a BuilderWallet with CREATE2
        // Most addresses will have non-zero upper 32 bits
        uint48 builderCode = 12345;
        
        // Attempt to call dispatch with builderCode
        // Expected: Transaction reverts with CastingError
        vm.expectRevert(); // Errors.CastingError()
        pool.dispatch(
            PanopticPool.MINT_ACTION,
            positionIdList,
            positionSize,
            builderCode // This will cause getRiskParameters to revert
        );
    }
}
```

**Expected Output** (when vulnerability exists):
```
[PASS] testBuilderCodeCausesRevert() (gas: ~200000)
Transaction reverted as expected due to CastingError
```

## Notes

This is a **HIGH severity** vulnerability because:

1. **Broken Core Functionality**: The builder code feature is completely non-functional for 99.99999997% of deployments
2. **DoS Impact**: All dispatch operations with builderCodes fail
3. **Economic Loss**: Protocol cannot incentivize builders, reducing ecosystem participation
4. **Deterministic Failure**: Not an exploit - this is a design flaw that breaks normal operations

The vulnerability is valid per the validation framework:
- ✅ Affects only in-scope contracts
- ✅ Not listed in known issues  
- ✅ Does not require trust model violations
- ✅ Has concrete impact (DoS of core feature)
- ✅ Technically feasible (occurs during normal use)
- ✅ Breaks protocol invariants (builder fee distribution)

However, the original report lacks a working PoC as required by audit guidelines for High/Medium submissions. Despite this procedural gap, the vulnerability itself is valid and requires immediate attention.

The root cause is a fundamental type mismatch: Ethereum addresses require 160 bits, but the RiskParameters packing uses only 128 bits for feeRecipient storage. This requires a protocol upgrade to fix properly.

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

**File:** contracts/PanopticPool.sol (L593-593)
```text
            (riskParameters, startTick) = getRiskParameters(builderCode);
```

**File:** contracts/types/RiskParameters.sol (L23-23)
```text
// (9) feeRecipient         128bits : The recipient of the commission fee split
```

**File:** contracts/CollateralTracker.sol (L1570-1570)
```text
                        address(uint160(riskParameters.feeRecipient())),
```

**File:** contracts/CollateralTracker.sol (L1649-1649)
```text
                        address(uint160(riskParameters.feeRecipient())),
```
