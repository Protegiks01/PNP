# Audit Report

## Title
Cross-Transaction Pool Utilization Manipulation Enables Permanent Collateral Requirement Reduction for Short Positions

## Summary
Attackers can manipulate pool utilization across multiple transactions to mint short option positions with artificially low collateral requirements that remain locked-in permanently, creating systemic undercollateralization risk as pool utilization increases over time.

## Finding Description

The protocol stores pool utilization at the time of position minting in `PositionBalance` and uses these stored values for all future collateral requirement calculations. While transient storage protects against within-transaction manipulation, it does not prevent cross-transaction coordination attacks.

**Vulnerable Code Flow:**

In `PanopticPool._mintOptions()`, pool utilizations are computed and stored: [1](#0-0) 

The `settleMint()` function in CollateralTracker retrieves utilization: [2](#0-1) 

Which calls `_updateBalancesAndSettle()` to get the utilization: [3](#0-2) 

The `_poolUtilization()` function uses transient storage for protection: [4](#0-3) 

**The Critical Flaw:**

Transient storage (`tload`/`tstore`) is cleared between transactions. An attacker can manipulate utilization across separate transactions:

1. **Transaction 1**: Attacker deposits large amounts → utilization drops to 20%
2. **Transaction 2**: Attacker mints short positions → stores 20% utilization in PositionBalance
3. **Transaction 3**: Attacker withdraws deposits → utilization returns to 70%

**Future Collateral Calculations Use Stored Values:**

When checking solvency, the RiskEngine uses stored utilizations from PositionBalance: [5](#0-4) 

These stored utilizations determine collateral requirements via `_sellCollateralRatio()`: [6](#0-5) 

**Collateral Requirement Reduction:**

The `_sellCollateralRatio()` scales linearly:
- Below 50% utilization (TARGET_POOL_UTIL): requires 20% collateral (minimum)
- At 70% utilization: requires ~60% collateral  
- At 90% utilization (SATURATED_POOL_UTIL): requires 100% collateral

An attacker who mints at 20% utilization locks in 20% collateral requirements permanently, even when actual pool utilization reaches 70% (3x reduction in collateral needed).

## Impact Explanation

**HIGH SEVERITY** - Systemic Undercollateralization Risk

1. **Unfair Capital Efficiency**: Attackers gain 3x capital efficiency advantage over legitimate users, allowing much larger positions with same collateral

2. **Protocol Risk Accumulation**: As pool utilization increases naturally over time, positions minted during manipulated low-utilization periods remain undercollateralized relative to current risk

3. **Liquidation Threshold Manipulation**: Positions that should be liquidatable at higher utilization levels cannot be liquidated due to artificially low collateral requirements

4. **Cross-Collateral Impact**: The stored utilizations affect cross-collateralization calculations, further amplifying the systemic risk

This breaks **Invariant #5** (Cross-Collateral Limits) and creates conditions that violate **Invariant #1** (Solvency Maintenance) under stress scenarios.

## Likelihood Explanation

**MEDIUM to HIGH Likelihood**

**Preconditions:**
- Requires significant capital to meaningfully impact utilization (millions of dollars)
- Can be executed by single sophisticated attacker with multiple accounts
- Can also occur through timing attacks with legitimate large depositors

**Execution Complexity:**
- Low technical complexity (standard deposit/mint/withdraw operations)
- No special permissions required
- Can be repeated across multiple positions

**Economic Incentive:**
- Direct benefit: 3x capital efficiency for options selling
- Can earn significantly more premium with same capital
- Competitive advantage over other market participants

**Attack Cost vs Benefit:**
- Temporary capital lock for deposits (low opportunity cost)
- Gas costs negligible compared to capital efficiency gains
- Can amortize attack cost across multiple positions over time

The transient storage protection suggests developers were aware of manipulation concerns but implemented an incomplete defense.

## Recommendation

Implement one of the following solutions:

**Option 1 - Use Current Utilization for Collateral Calculations:**
```solidity
// In RiskEngine, instead of using stored utilization from PositionBalance,
// query current utilization from CollateralTracker when calculating collateral requirements
// This ensures requirements adjust dynamically with pool risk
```

**Option 2 - Store Maximum Utilization and Update Dynamically:**
```solidity
// Store initial utilization in PositionBalance
// On each solvency check, update to MAX(stored, current) utilization
// This prevents locked-in low requirements while maintaining historical high watermark
```

**Option 3 - Implement Cross-Transaction Manipulation Detection:**
```solidity
// Track large deposit/withdrawal patterns
// Require minimum time delay or utilization stability before allowing position minting
// Add utilization delta limits for position minting eligibility
```

**Recommended Approach: Option 1**

Modify `RiskEngine._getTotalRequiredCollateral()` to accept current CollateralTracker utilizations as parameters and use these for real-time calculations instead of stored PositionBalance values. This ensures collateral requirements always reflect current pool risk.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";

contract PoolUtilizationManipulationTest is Test {
    PanopticPool panopticPool;
    CollateralTracker collateralToken0;
    CollateralTracker collateralToken1;
    
    address attacker = address(0x1);
    address accomplice = address(0x2);
    
    function testUtilizationManipulation() public {
        // Setup: Initialize pool with normal utilization at 70%
        setupPoolAt70PercentUtilization();
        
        // Record initial collateral requirement at 70% utilization
        uint256 normalCollateralReq = getCollateralRequirementForShort();
        
        // Step 1: Attacker deposits $10M to both trackers (TX1)
        vm.startPrank(attacker);
        collateralToken0.deposit(10_000_000e6, attacker);
        collateralToken1.deposit(10_000_000e6, attacker);
        vm.stopPrank();
        
        // Utilization drops to ~20%
        uint256 manipulatedUtil = collateralToken0._poolUtilizationView();
        assertLt(manipulatedUtil, 2500); // Less than 25%
        
        // Step 2: Accomplice mints short position at low utilization (TX2)
        vm.startPrank(accomplice);
        // Mint short option position
        TokenId tokenId = createShortPosition();
        panopticPool.mintOptions(/* parameters */);
        vm.stopPrank();
        
        // Verify low utilization is stored in PositionBalance
        PositionBalance storedBalance = panopticPool.s_positionBalance(accomplice, tokenId);
        assertLt(storedBalance.utilization0(), 2500);
        
        // Step 3: Attacker withdraws deposits (TX3)
        vm.startPrank(attacker);
        collateralToken0.withdraw(10_000_000e6, attacker, attacker);
        collateralToken1.withdraw(10_000_000e6, attacker, attacker);
        vm.stopPrank();
        
        // Utilization returns to 70%
        uint256 currentUtil = collateralToken0._poolUtilizationView();
        assertGt(currentUtil, 7000); // Back to ~70%
        
        // Step 4: Verify accomplice has permanently reduced collateral requirements
        uint256 accompliceCollateralReq = getCollateralRequirementForPosition(accomplice, tokenId);
        
        // Accomplice needs 20% collateral (manipulated)
        // Normal users need 60% collateral (fair)
        assertLt(accompliceCollateralReq, normalCollateralReq / 3);
        
        // Accomplice has 3x capital efficiency advantage
        console.log("Normal collateral requirement:", normalCollateralReq);
        console.log("Manipulated collateral requirement:", accompliceCollateralReq);
        console.log("Capital efficiency advantage:", normalCollateralReq / accompliceCollateralReq);
    }
}
```

**Notes:**

The vulnerability exists because the protocol's transient storage protection only prevents within-transaction manipulation but not cross-transaction coordination. The stored pool utilization values in `PositionBalance` are used for lifetime collateral calculations, creating a permanent advantage for attackers who can temporarily manipulate utilization during minting. This represents an incomplete security measure that sophisticated actors can exploit for significant capital efficiency gains at the expense of protocol safety.

### Citations

**File:** contracts/PanopticPool.sol (L745-763)
```text
        uint32 poolUtilizations;

        (poolUtilizations, paidAmounts) = _payCommissionAndWriteData(
            tokenId,
            positionSize,
            owner,
            netAmmDelta,
            riskParameters
        );

        {
            // update the users options balance of position `tokenId`
            // NOTE: user can't mint same position multiple times, so set the positionSize instead of adding
            PositionBalance balanceData = PositionBalanceLibrary.storeBalanceData(
                positionSize,
                poolUtilizations,
                0
            );
            s_positionBalance[owner][tokenId] = balanceData;
```

**File:** contracts/CollateralTracker.sol (L1137-1154)
```text
    function _poolUtilization() internal returns (uint256 poolUtilization) {
        uint256 storedUtilization;
        bytes32 slot = UTILIZATION_TRANSIENT_SLOT;
        assembly {
            storedUtilization := tload(slot)
        }

        poolUtilization = _poolUtilizationView();

        if (storedUtilization > poolUtilization) {
            return storedUtilization;
        } else {
            assembly {
                tstore(slot, poolUtilization)
            }
            return poolUtilization;
        }
    }
```

**File:** contracts/CollateralTracker.sol (L1512-1520)
```text
        {
            // add new netBorrows to the left slot
            s_interestState[_optionOwner] = s_interestState[_optionOwner].addToLeftSlot(netBorrows);
        }

        // get the utilization, store the current one in transient storage
        uint32 utilization = uint32(_poolUtilization());

        return (utilization, int128(tokenToPay), _totalAssets, _totalSupply);
```

**File:** contracts/CollateralTracker.sol (L1531-1583)
```text
    function settleMint(
        address optionOwner,
        int128 longAmount,
        int128 shortAmount,
        int128 ammDeltaAmount,
        RiskParameters riskParameters
    ) external onlyPanopticPool returns (uint32, int128) {
        (
            uint32 utilization,
            int128 tokenPaid,
            uint256 _totalAssets,
            uint256 _totalSupply
        ) = _updateBalancesAndSettle(
                optionOwner,
                true, // isCreation = true
                longAmount,
                shortAmount,
                ammDeltaAmount,
                0 // realizedPremium not used
            );

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
        }

        return (utilization, tokenPaid);
```

**File:** contracts/RiskEngine.sol (L1198-1227)
```text
    function _getGlobalUtilization(
        PositionBalance[] calldata positionBalanceArray
    ) internal pure returns (PositionBalance globalUtilizations) {
        int256 utilization0;
        int256 utilization1;
        uint256 pLength = positionBalanceArray.length;

        for (uint256 i; i < pLength; ) {
            PositionBalance positionBalance = positionBalanceArray[i];

            int256 _utilization0 = positionBalance.utilization0();
            int256 _utilization1 = positionBalance.utilization1();

            // utilizations are always positive, so can compare directly here
            utilization0 = _utilization0 > utilization0 ? _utilization0 : utilization0;
            utilization1 = _utilization1 > utilization1 ? _utilization1 : utilization1;
            unchecked {
                ++i;
            }
        }

        unchecked {
            // can never miscast because utilization < 10_000
            globalUtilizations = PositionBalanceLibrary.storeBalanceData(
                0,
                uint32(uint256(utilization0) + (uint256(utilization1) << 16)),
                0
            );
        }
    }
```

**File:** contracts/RiskEngine.sol (L2047-2097)
```text
    function _sellCollateralRatio(
        int256 utilization
    ) internal view returns (uint256 sellCollateralRatio) {
        // the sell ratio is on a straight line defined between two points (x0,y0) and (x1,y1):
        //   (x0,y0) = (targetPoolUtilization,min_sell_ratio) and
        //   (x1,y1) = (saturatedPoolUtilization,max_sell_ratio)
        // the line's formula: y = a * (x - x0) + y0, where a = (y1 - y0) / (x1 - x0)
        /*
            SELL
            COLLATERAL
            RATIO
                          ^
                          |                  max ratio = 100%
                   100% - |                _------
                          |             _-¯
                          |          _-¯
                    20% - |---------¯
                          |         .       . .
                          +---------+-------+-+--->   POOL_
                                   50%    90% 100%     UTILIZATION
        */

        uint256 min_sell_ratio = SELLER_COLLATERAL_RATIO;
        /// if utilization is less than zero, this is the calculation for a strangle, which gets 2x the capital efficiency at low pool utilization
        if (utilization < 0) {
            unchecked {
                min_sell_ratio /= 2;
                utilization = -utilization;
            }
        }

        unchecked {
            utilization *= 1_000;
        }
        // return the basal sell ratio if pool utilization is lower than target
        if (uint256(utilization) < TARGET_POOL_UTIL) {
            return min_sell_ratio;
        }

        // return 100% collateral ratio if utilization is above saturated pool utilization
        if (uint256(utilization) > SATURATED_POOL_UTIL) {
            return DECIMALS;
        }

        unchecked {
            return
                min_sell_ratio +
                ((DECIMALS - min_sell_ratio) * (uint256(utilization) - TARGET_POOL_UTIL)) /
                (SATURATED_POOL_UTIL - TARGET_POOL_UTIL);
        }
    }
```
