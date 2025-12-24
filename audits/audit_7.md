# Audit Report

## Title 
Incomplete Commission Collection Allows Users to Avoid 10% of Commission Fees by Using Builder Codes

## Summary
When users mint or burn positions with a builder code (non-zero `feeRecipient`), only 90% of the calculated commission is actually collected from them, while the protocol collects 100% when no builder code is used. This allows users to save 10% of commission fees by simply using any valid builder code, resulting in direct financial loss to the protocol and PLPs.

## Finding Description

The commission payment mechanism in `CollateralTracker.settleMint()` and `settleBurn()` has a critical flaw in how commission shares are allocated when a builder code is present. [1](#0-0) 

The protocol defines commission split ratios in RiskEngine: [2](#0-1) 

With `DECIMALS = 10_000` representing 100%: [3](#0-2) 

The issue manifests in two scenarios:

**Scenario 1: No Builder Code (`feeRecipient == 0`)**
- Commission calculation: `sharesToBurn` represents 100% of commission
- Execution: `_burn(optionOwner, sharesToBurn)` - user pays **100%**

**Scenario 2: With Builder Code (`feeRecipient != 0`)**  
- Commission calculation: Same `sharesToBurn` amount
- Execution:
  - Transfer to RiskEngine: `sharesToBurn * 6_500 / 10_000 = 65%`
  - Transfer to Builder: `sharesToBurn * 2_500 / 10_000 = 25%`  
  - Total transferred: **90%**
  - Remaining in user balance: **10%**

Users can select their builder code via the `dispatch()` function: [4](#0-3) 

The `getRiskParameters()` call computes the `feeRecipient` from any user-provided `builderCode`: [5](#0-4) 

**Attack Path:**
1. Attacker calls `dispatch()` with a valid non-zero `builderCode`
2. `_mintOptions()` or `_burnOptions()` is executed
3. `settleMint()` or `settleBurn()` calculates commission
4. Only 90% of commission is transferred from the user (65% protocol + 25% builder)
5. User retains 10% of commission that should have been collected
6. This occurs on EVERY position mint/burn using a builder code

The same vulnerability exists in `settleBurn()`: [6](#0-5) 

## Impact Explanation

**HIGH SEVERITY** - This represents a direct and permanent loss of protocol revenue:

- **Magnitude**: 10% of all commission fees from users utilizing builder codes is not collected
- **Frequency**: Affects every position mint and burn operation when builder codes are used  
- **Exploitability**: Trivial - users simply need to provide any valid builder code
- **Systemic Risk**: As users discover they can save 10% commission by using builder codes, adoption will increase, amplifying losses
- **Unfair Advantage**: Creates two tiers of users - those paying 100% commission and those paying 90%
- **Protocol Loss**: If X% of users use builder codes and Y is total commission volume, protocol loses `0.10 * X * Y` in fees
- **No Compensation**: Unlike typical fee structures where reduced user fees might incentivize desired behavior, here the 10% simply disappears from protocol revenue with no offsetting benefit

This breaks the fundamental commission collection mechanism and creates perverse incentives for users to always use builder codes regardless of whether they actually want to support a specific builder.

## Likelihood Explanation

**Likelihood: HIGH**

- **No Preconditions**: Any user can exploit this immediately  
- **No Special Access**: Does not require privileged roles or complex setup
- **Trivial Exploitation**: User only needs to pass a non-zero `builderCode` parameter
- **Rational Behavior**: Users are economically incentivized to discover and use this to save 10% on every transaction
- **Discoverable**: Users experimenting with builder codes will notice reduced commission charges
- **Persistent**: Once discovered, will be widely adopted and shared among users
- **Continuous Impact**: Affects all future transactions, not a one-time exploit

## Recommendation

The protocol must ensure that 100% of commission is collected regardless of whether a builder code is used. Two approaches:

**Option 1: Adjust Split Ratios**
```solidity
// In RiskEngine.sol
uint16 constant PROTOCOL_SPLIT = 7_500;  // 75%
uint16 constant BUILDER_SPLIT = 2_500;   // 25%
// Total = 100%
```

**Option 2: Burn Remaining Amount**
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
        
        // Burn the remaining shares to ensure 100% commission collection
        uint256 remainingShares = sharesToBurn - protocolShares - builderShares;
        if (remainingShares > 0) {
            _burn(optionOwner, remainingShares);
        }
        
        emit CommissionPaid(...);
    }
}
```

**Recommended**: Option 1 is cleaner and more gas efficient. Adjust `PROTOCOL_SPLIT` to 7,500 to ensure total allocation equals 10,000 (100%).

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {TokenId} from "@types/TokenId.sol";

contract CommissionBypassTest is Test {
    PanopticPool public panopticPool;
    CollateralTracker public collateralToken0;
    CollateralTracker public collateralToken1;
    address public user = address(0x1234);
    
    function setUp() public {
        // Setup would initialize the PanopticPool, CollateralTrackers
        // and mint initial shares to user
    }
    
    function testCommissionBypass() public {
        // Record initial user balance
        uint256 initialBalance = collateralToken0.balanceOf(user);
        
        // Calculate expected commission for the position
        uint128 positionSize = 1000e18;
        uint128 expectedCommission = 10e18; // Assume 1% commission
        uint256 expectedShares = expectedCommission; // Simplified
        
        // Mint position WITHOUT builder code (builderCode = 0)
        vm.prank(user);
        TokenId[] memory positionIds = new TokenId[](1);
        // ... setup position minting with builderCode = 0
        panopticPool.dispatch(positionIds, positionIds, new uint128[](1), 
            new int24[3][](1), false, 0); // builderCode = 0
        
        uint256 balanceAfterNoBuilder = collateralToken0.balanceOf(user);
        uint256 paidWithoutBuilder = initialBalance - balanceAfterNoBuilder;
        
        // Reset balance
        vm.prank(user);
        collateralToken0.transfer(address(this), balanceAfterNoBuilder);
        deal(address(collateralToken0), user, initialBalance);
        
        // Mint same position WITH builder code (builderCode != 0)
        vm.prank(user);
        uint256 builderCode = 123456; // Non-zero builder code
        panopticPool.dispatch(positionIds, positionIds, new uint128[](1),
            new int24[3][](1), false, builderCode); // builderCode != 0
        
        uint256 balanceAfterWithBuilder = collateralToken0.balanceOf(user);
        uint256 paidWithBuilder = initialBalance - balanceAfterWithBuilder;
        
        // User pays 10% less commission when using builder code
        assertEq(paidWithoutBuilder, expectedShares); // 100% commission
        assertEq(paidWithBuilder, expectedShares * 90 / 100); // Only 90% commission
        assertEq(paidWithoutBuilder - paidWithBuilder, expectedShares / 10); // 10% saved
        
        console.log("Commission paid without builder:", paidWithoutBuilder);
        console.log("Commission paid with builder:", paidWithBuilder);
        console.log("Savings (10%):", paidWithoutBuilder - paidWithBuilder);
    }
}
```

**Notes**

1. The vulnerability affects both `settleMint()` (lines 1558-1580) and `settleBurn()` (lines 1637-1659) identically
2. There's an additional bug in the event emission at line 1576-1577 where both parameters use `protocolSplit` instead of one using `builderSplit`, but this is a separate logging issue
3. The CREATE2 address computation means users could potentially find builder codes that map to addresses with deployed code to bypass any whitelist checks, though legitimate builders already exist that users can utilize
4. The 10% stays in the user's `balanceOf`, increasing their collateral without having paid the full commission

### Citations

**File:** contracts/CollateralTracker.sol (L108-108)
```text
    uint256 internal constant DECIMALS = 10_000;
```

**File:** contracts/CollateralTracker.sol (L1552-1580)
```text
        {
            uint128 commission = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
            uint128 commissionFee = Math
                .mulDivRoundingUp(commission, riskParameters.notionalFee(), DECIMALS)
                .toUint128();
            uint256 sharesToBurn = Math.mulDivRoundingUp(commissionFee, _totalSupply, _totalAssets);
            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
            } else {
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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
```

**File:** contracts/CollateralTracker.sol (L1635-1659)
```text
            uint256 sharesToBurn = Math.mulDivRoundingUp(commissionFee, _totalSupply, _totalAssets);

            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
            } else {
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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
```

**File:** contracts/RiskEngine.sol (L120-124)
```text
    uint16 constant PROTOCOL_SPLIT = 6_500;

    /// @notice The builder split, in basis points, when a builder code is present
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant BUILDER_SPLIT = 2_500;
```

**File:** contracts/RiskEngine.sol (L864-885)
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
