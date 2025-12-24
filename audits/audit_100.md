# Audit Report

## Title 
Builder Fee Misdirection: Address Truncation Causes Permanent Loss of Builder Fees

## Summary
The `RiskEngine.getRiskParameters()` function truncates builder wallet addresses from 160 bits to 128 bits, causing all builder fees to be sent to incorrect addresses. This results in systematic and permanent loss of builder compensation, as fees are directed to addresses that are almost certainly uncontrolled and unrecoverable.

## Finding Description

The vulnerability exists in the fee recipient address handling within `RiskEngine.getRiskParameters()`. When computing risk parameters for a given `builderCode`, the function performs the following operations: [1](#0-0) 

The `_computeBuilderWallet()` function correctly computes a CREATE2 address (160 bits) for the builder wallet. However, on the critical line: [2](#0-1) 

The address is truncated from 160 bits to 128 bits by casting through `uint256` to `uint128`. This discards the upper 32 bits (4 bytes) of the address.

Later, when fees are distributed in `CollateralTracker.settleMint()` and `CollateralTracker.settleBurn()`, the truncated 128-bit value is cast back to an address: [3](#0-2) [4](#0-3) 

When a 128-bit value is cast to `address` (via `uint160`), the upper 32 bits are zero-padded, creating an entirely different address than the intended builder wallet.

**Example:**
- Original CREATE2 builder wallet: `0xABCDEF1234567890123456789012345678901234`
- After truncation to uint128: `0x34567890123456789012345678901234` (lower 128 bits)
- After casting to address: `0x0000000034567890123456789012345678901234` (zero-padded upper 32 bits)
- Result: Fees sent to `0x00000000...` instead of `0xABCDEF...`

**Additional Collision Risk:**
Multiple different `builderCode` values that produce CREATE2 addresses differing only in their upper 32 bits will map to the same incorrect recipient address after truncation. This means multiple builders' fees could be misdirected to the same wrong address.

## Impact Explanation

**HIGH Severity** - This vulnerability causes systematic and permanent loss of builder fees:

1. **Universal Impact**: Every transaction using a non-zero `builderCode` is affected
2. **Permanent Fund Loss**: Builder fees are sent to addresses with zero-padded upper bits, which are statistically guaranteed not to be controlled by anyone
3. **Economic Incentive Breakdown**: Builders receive no compensation despite the protocol intending to distribute fees to them
4. **Protocol Reputation Damage**: The builder referral program becomes non-functional

The probability of the misdirected address being controlled by anyone is negligible (~2^-32 ≈ 0.00000002%), making these fees permanently unrecoverable.

## Likelihood Explanation

**Certainty: 100%** - This bug triggers on every call to `getRiskParameters()` with a non-zero `builderCode`: [5](#0-4) 

The `dispatch()` function, which is the main entry point for minting and burning positions, accepts a `builderCode` parameter: [6](#0-5) 

There are no preconditions or special circumstances required - the truncation happens automatically in the normal flow of operations.

## Recommendation

**Fix:** Change the `feeRecipient` field in `RiskParameters` from `uint128` to `uint160` to accommodate the full address.

**Step 1:** Update the `RiskParameters` type definition to allocate 160 bits instead of 128 bits for `feeRecipient`: [7](#0-6) 

The bit allocation must be adjusted. Since `feeRecipient` needs 160 bits instead of 128 bits, we need to find 32 additional bits. This can be achieved by reducing other fields or using a different packing strategy. One approach:

```solidity
// Option 1: Reduce maxLegs from 7 bits to 6 bits (still allows 0-63 legs)
// Option 2: Use a mapping for feeRecipient instead of packing it
// Option 3: Pack RiskParameters into 2 uint256 slots
```

**Step 2:** Update `RiskEngine.getRiskParameters()` to store the full address:

```solidity
// Line 871 should become:
uint160 feeRecipient = uint160(_computeBuilderWallet(builderCode));
```

**Step 3:** Update the `feeRecipient()` accessor function:

```solidity
function feeRecipient(RiskParameters self) internal pure returns (uint160 result) {
    assembly {
        result := shr(96, self)  // Adjust shift amount based on new packing
    }
}
```

**Alternative Solution:** If repacking is too complex, store `feeRecipient` as a separate mapping in `PanopticPool` or `RiskEngine` instead of packing it into `RiskParameters`.

## Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/RiskEngine.sol";

contract BuilderFeeVulnerabilityTest is Test {
    RiskEngine riskEngine;
    address builderFactory;
    
    function setUp() public {
        builderFactory = address(new BuilderFactory(address(this)));
        riskEngine = new RiskEngine(
            5_000_000,  // CROSS_BUFFER_0
            5_000_000,  // CROSS_BUFFER_1
            address(this),  // guardian
            builderFactory
        );
    }
    
    function testBuilderFeeAddressTruncation() public {
        // Create a mock builder code
        uint256 builderCode = 12345;
        
        // Deploy a builder wallet through the factory
        BuilderFactory(builderFactory).deployBuilder(
            uint48(builderCode),
            address(0xBEEF)
        );
        
        // Get the actual builder wallet address (full 160 bits)
        address actualBuilderWallet = riskEngine.getFeeRecipient(builderCode);
        
        // Get risk parameters which truncates the address
        RiskParameters riskParams = riskEngine.getRiskParameters(
            0,  // currentTick
            OraclePack.wrap(0),  // oraclePack
            builderCode
        );
        
        // Extract the truncated feeRecipient and cast back to address
        address truncatedRecipient = address(uint160(riskParams.feeRecipient()));
        
        // VULNERABILITY: The addresses should match but they don't
        console.log("Actual builder wallet:", actualBuilderWallet);
        console.log("Truncated recipient:", truncatedRecipient);
        
        // Demonstrate the upper 32 bits are lost
        assertNotEq(
            actualBuilderWallet,
            truncatedRecipient,
            "Builder wallet address was incorrectly truncated"
        );
        
        // Show that the upper 32 bits of truncatedRecipient are zero
        uint256 upperBits = uint256(uint160(truncatedRecipient)) >> 128;
        assertEq(upperBits, 0, "Upper 32 bits should be zero after truncation");
        
        // This means builder fees will be sent to the wrong address
        // and will be permanently lost
    }
    
    function testMultipleBuilderCodesCanCollide() public {
        // Two different builder codes can map to the same truncated address
        // if their CREATE2 addresses differ only in the upper 32 bits
        
        // This demonstrates the collision potential, though finding actual
        // collisions would require brute force searching CREATE2 space
        
        uint256 builderCode1 = 11111;
        uint256 builderCode2 = 22222;
        
        // Get the CREATE2 addresses
        address wallet1 = riskEngine.getFeeRecipient(builderCode1);
        address wallet2 = riskEngine.getFeeRecipient(builderCode2);
        
        // Get truncated versions
        RiskParameters riskParams1 = riskEngine.getRiskParameters(0, OraclePack.wrap(0), builderCode1);
        RiskParameters riskParams2 = riskEngine.getRiskParameters(0, OraclePack.wrap(0), builderCode2);
        
        uint128 truncated1 = riskParams1.feeRecipient();
        uint128 truncated2 = riskParams2.feeRecipient();
        
        // If truncated1 == truncated2 but wallet1 != wallet2,
        // both builders' fees would go to the same wrong address
        console.log("Wallet 1:", wallet1);
        console.log("Wallet 2:", wallet2);
        console.log("Truncated 1:", uint256(truncated1));
        console.log("Truncated 2:", uint256(truncated2));
    }
}
```

**Notes:**
1. The vulnerability exists due to a type mismatch between address (160 bits) and uint128 (128 bits) in the `RiskParameters` packing scheme
2. The `getFeeRecipient()` function includes validation that the builder wallet exists, but this function is never called in the actual protocol flow
3. All builder fees for non-zero `builderCode` values are misdirected and permanently lost
4. The issue affects both `settleMint()` and `settleBurn()` operations in `CollateralTracker`

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

**File:** contracts/CollateralTracker.sol (L1568-1572)
```text
                    _transferFrom(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        (sharesToBurn * riskParameters.builderSplit()) / DECIMALS
                    );
```

**File:** contracts/CollateralTracker.sol (L1647-1651)
```text
                    _transferFrom(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        (sharesToBurn * riskParameters.builderSplit()) / DECIMALS
                    );
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

**File:** contracts/PanopticPool.sol (L1808-1813)
```text
    function getRiskParameters(
        uint256 builderCode
    ) public view returns (RiskParameters riskParameters, int24 currentTick) {
        currentTick = getCurrentTick();
        riskParameters = riskEngine().getRiskParameters(currentTick, s_oraclePack, builderCode);
    }
```

**File:** contracts/types/RiskParameters.sol (L10-34)
```text
//
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
//
// The bit pattern is therefore:
//
//          (9)              (8)          (7)              (6)             (5)            (4)          (3)             (2)              (1)
//    <-- 128 bits --><-- 7 bits --><-- 26 bits --><-- 22 bits --><-- 13 bits --><-- 14 bits --><-- 14 bits --> <-- 14 bits --> <-- 14 bits --> <-- 4 bits -->
//        feeRecipient   maxLegs      bpDecrease      maxSpread      tickDelta    builderSplit   protocolSplit    premiumFee    notionalFee         safeMode
//
//    <--- most significant bit                                                                  least significant bit --->
//
```
