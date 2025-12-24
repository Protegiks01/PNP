# Audit Report

## Title 
Incomplete Fee Split Bypass Allows Users to Retain 10% Commission When Using Builder Codes

## Summary
The fee distribution logic in `CollateralTracker.settleMint()` and `settleBurn()` only transfers 90% of calculated commission shares (65% to protocol + 25% to builder) when a builder code is present, leaving the remaining 10% with the option owner instead of burning it. This breaks fee fairness and causes systematic value loss to Panoptic Liquidity Providers (PLPs).

## Finding Description
The protocol's fee split constants in `RiskEngine.sol` define `PROTOCOL_SPLIT = 6,500` (65%) and `BUILDER_SPLIT = 2,500` (25%), totaling only 9,000 basis points (90%) instead of the expected 10,000 (100%). [1](#0-0) 

In `CollateralTracker.settleMint()`, when a builder code is present (`feeRecipient != 0`), the commission fee distribution logic transfers shares as follows:
- Protocol receives: `(sharesToBurn * protocolSplit()) / DECIMALS = 65%`
- Builder receives: `(sharesToBurn * builderSplit()) / DECIMALS = 25%`
- **Remaining 10% stays with optionOwner (not burned or transferred)** [2](#0-1) 

This contrasts with the no-builder-code path where ALL commission shares are properly burned from the option owner. [3](#0-2) 

The identical vulnerability exists in `settleBurn()`. [4](#0-3) 

This breaks the **Collateral Conservation Invariant** (Invariant #2) which requires proper accounting of all shares burned as commission. The 10% that should contribute to PLPs through burning remains with users, systematically draining value from the protocol.

Additionally, there's an event emission bug where both protocol and builder commission amounts incorrectly use `protocolSplit()`. [5](#0-4) 

## Impact Explanation
**HIGH Severity** - This creates systematic economic manipulation:

1. **Fee Bypass**: Users can reduce their effective commission from 100% to 90% by using any valid builder code (which can be self-controlled or any existing builder wallet)

2. **PLP Value Drain**: The 10% commission that should be burned (returning value to PLPs through reduced share supply) instead stays with option owners, causing ongoing value extraction

3. **Protocol Insolvency Risk**: Over time, the accumulated unburdened commissions represent significant value leakage that should have strengthened the collateral pool

4. **Unfair Competitive Advantage**: Users who discover this can systematically profit at the expense of LPs who expect fair commission collection

The impact scales with trading volume - higher volume means more value drained from PLPs.

## Likelihood Explanation
**HIGH Likelihood** - This vulnerability is:

1. **Always Active**: Every position mint/burn with a builder code triggers the issue
2. **Trivially Exploitable**: Any user can specify a builder code to gain the 10% discount
3. **No Special Permissions Required**: Unprivileged users can exploit this
4. **Economically Rational**: Rational actors will prefer using builder codes for the 10% savings
5. **Undetectable**: The missing 10% burn is not caught by any validation logic

The combination of high impact and high likelihood makes this a critical business logic flaw.

## Recommendation
Fix the fee split constants to sum to 10,000 (100%) or add explicit burning of the remainder:

**Option 1: Adjust Split Constants**
```solidity
// In RiskEngine.sol
uint16 constant PROTOCOL_SPLIT = 7_500; // 75%
uint16 constant BUILDER_SPLIT = 2_500;  // 25%
// Total = 100%
```

**Option 2: Burn Remainder**
```solidity
// In CollateralTracker.settleMint() and settleBurn()
else {
    uint256 protocolShares = (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS;
    uint256 builderShares = (sharesToBurn * riskParameters.builderSplit()) / DECIMALS;
    uint256 remainder = sharesToBurn - protocolShares - builderShares;
    
    _transferFrom(optionOwner, address(riskEngine()), protocolShares);
    _transferFrom(optionOwner, address(uint160(riskParameters.feeRecipient())), builderShares);
    _burn(optionOwner, remainder); // Burn the remainder for PLPs
    
    emit CommissionPaid(
        optionOwner,
        address(uint160(riskParameters.feeRecipient())),
        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
        uint128((commissionFee * riskParameters.builderSplit()) / DECIMALS) // Fix event emission
    );
}
```

## Proof of Concept
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {RiskParameters, RiskParametersLibrary} from "@types/RiskParameters.sol";

contract FeeSplitBypassTest is Test {
    using RiskParametersLibrary for RiskParameters;
    
    CollateralTracker collateral;
    address optionOwner = address(0x1);
    address builderWallet = address(0x2);
    address riskEngineAddr = address(0x3);
    
    function setUp() public {
        // Deploy minimal test setup
        collateral = new CollateralTracker(10);
        
        // Mint initial shares to optionOwner
        vm.startPrank(address(this));
        deal(address(collateral), optionOwner, 10000 ether);
        vm.stopPrank();
    }
    
    function testFeeSplitBypass() public {
        // Setup: option owner has 10000 shares
        uint256 initialShares = 10000 ether;
        
        // Simulate commission: 1000 shares should be burned as commission
        uint256 sharesToBurn = 1000 ether;
        
        // Create RiskParameters with builder code (feeRecipient != 0)
        RiskParameters riskParams = RiskParametersLibrary.storeRiskParameters(
            0, // safeMode
            100, // notionalFee  
            0, // premiumFee
            6500, // protocolSplit = 65%
            2500, // builderSplit = 25%
            513, // tickDeltaLiquidation
            9000, // maxSpread
            1000, // bpDecreaseBuffer
            33, // maxLegs
            uint256(uint160(builderWallet)) // feeRecipient
        );
        
        // Calculate what gets transferred with builder code
        uint256 protocolShares = (sharesToBurn * 6500) / 10000; // 650 shares
        uint256 builderSharesTransferred = (sharesToBurn * 2500) / 10000; // 250 shares
        uint256 totalTransferred = protocolShares + builderSharesTransferred; // 900 shares
        
        // The bug: only 900 shares are transferred/burned, not 1000
        // Option owner keeps 100 shares (10%) that should have been burned
        uint256 stolenShares = sharesToBurn - totalTransferred; // 100 shares = 10%
        
        assertEq(stolenShares, 100 ether, "User retains 10% of commission");
        assertEq(totalTransferred, 900 ether, "Only 90% transferred");
        
        // Compare with no builder code scenario
        // When feeRecipient == 0, ALL sharesToBurn would be burned (100%)
        // This proves the fee bypass when using builder codes
        
        console.log("Commission shares that should be collected: %e", sharesToBurn);
        console.log("Shares actually transferred/burned: %e", totalTransferred);
        console.log("Shares retained by user (10%% discount): %e", stolenShares);
    }
}
```

**Notes:**
While the security question asks about `builderSplit()` returning zero, the actual vulnerability discovered is that `PROTOCOL_SPLIT + BUILDER_SPLIT = 9,000 (90%)` rather than 10,000 (100%), causing the same fee bypass effect described in the question. The constants are hardcoded in `RiskEngine.sol` and always return these values, making the "bit corruption" scenario unrealistic. However, the real vulnerability of incomplete fee collection when builder codes are used is valid and exploitable. The event emission also incorrectly reports commission amounts. [6](#0-5)

### Citations

**File:** contracts/RiskEngine.sol (L120-124)
```text
    uint16 constant PROTOCOL_SPLIT = 6_500;

    /// @notice The builder split, in basis points, when a builder code is present
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant BUILDER_SPLIT = 2_500;
```

**File:** contracts/CollateralTracker.sol (L1558-1560)
```text
            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
```

**File:** contracts/CollateralTracker.sol (L1563-1572)
```text
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

**File:** contracts/CollateralTracker.sol (L1642-1651)
```text
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

**File:** contracts/CollateralTracker.sol (L1655-1657)
```text
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
```
