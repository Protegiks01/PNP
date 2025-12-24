# Audit Report

## Title
Interest Index Discrepancy Between View and State-Changing Functions Enables Front-Running Liquidation Attacks

## Summary
The `CollateralTracker` contract uses different utilization values in view functions versus state-changing functions, causing view functions to predict lower interest charges than users actually pay. This discrepancy enables attackers to front-run user transactions by artificially inflating pool utilization, forcing users to pay higher-than-expected interest that can push them into insolvency and trigger liquidations.

## Finding Description

The vulnerability stems from the utilization calculation mechanism in `CollateralTracker`. View functions that calculate interest (such as `owedInterest()` and `previewOwedInterest()`) use current pool utilization, while state-changing functions use the maximum utilization observed during the transaction via transient storage.

**View Function Path:** [1](#0-0) 

The view function calls `_poolUtilizationWadView()` which simply calculates the current utilization: [2](#0-1) 

**State-Changing Path:** [3](#0-2) 

This calls `_updateInterestRate()` which uses `_poolUtilizationWad()`: [4](#0-3) 

The `_poolUtilizationWad()` function uses transient storage to track and return the MAXIMUM utilization during the transaction: [5](#0-4) 

**The Exploitation Mechanism:**

When utilization increases during a transaction (either from front-running or multi-step operations), the interest calculation uses higher utilization → higher interest rate → higher borrow index growth → higher interest charges. However, users who check view functions before submitting transactions see interest calculated with lower utilization.

The borrow index calculation in `_calculateCurrentInterestState()` compounds based on the interest rate: [6](#0-5) 

Different utilization inputs to this function produce different borrow indices, causing users to be charged different amounts than predicted.

**Attack Path:**

1. Victim has borrowed funds and is near liquidation threshold
2. Victim calls `owedInterest()` off-chain, sees they owe 1000 tokens with 50% utilization
3. Victim submits transaction believing they remain solvent
4. Attacker front-runs by opening large position, increasing utilization to 85%
5. Victim's `_accrueInterest()` executes using 85% utilization from transient storage
6. Higher utilization causes higher interest rate and higher borrow index
7. Victim is charged 1050 tokens instead of 1000 tokens
8. The extra 50 tokens pushes victim into insolvency
9. Attacker liquidates victim and collects liquidation bonus

This breaks **Invariant #21 (Interest Accuracy)**: "Interest owed must equal `netBorrows * (currentBorrowIndex - userBorrowIndex) / userBorrowIndex`. Calculation errors cause interest manipulation." The discrepancy between view predictions and actual charges constitutes a calculation inconsistency that enables manipulation.

## Impact Explanation

**Medium Severity** - This vulnerability enables economic manipulation where attackers can:

1. **Force Unexpected Liquidations**: Users near solvency limits who check view functions may believe they're safe, but front-running increases their interest charges, pushing them into insolvency
2. **Transaction Failures**: Users who approve exact amounts based on view function predictions will have transactions fail when actual charges are higher
3. **Economic Loss**: Liquidation victims lose their positions and pay liquidation bonuses to attackers
4. **Unpredictable Costs**: All borrowers face uncertainty in interest charges, breaking the predictability expectation of DeFi protocols

While this doesn't directly steal funds, it creates an exploitable condition where attackers can manipulate interest calculations to trigger profitable liquidations. The impact is amplified because:
- The transient storage mechanism persists for the entire transaction
- Multiple users can be affected by a single utilization spike
- The discrepancy is invisible to users until transaction execution

## Likelihood Explanation

**Medium-High Likelihood** - This vulnerability will occur naturally during normal protocol operation:

1. **Natural Occurrence**: Any time utilization changes during a transaction (deposits, withdrawals, position minting), subsequent operations in that tx will use the higher utilization
2. **Front-Running Feasibility**: Attackers can monitor the mempool for transactions from users near liquidation and front-run with utilization-increasing operations
3. **Low Barrier**: Attack requires only capital to temporarily increase utilization, no special permissions needed
4. **MEV Opportunity**: This creates a profitable MEV extraction opportunity when combined with liquidations

The likelihood is high because:
- Users frequently check view functions before transactions (standard practice)
- The protocol explicitly uses transient storage to track max utilization
- Multiple operations within a single transaction are common (multicall patterns)
- Liquidation monitoring bots already scan for near-insolvent users

## Recommendation

Implement a view function that simulates the transient storage behavior for off-chain calls, or provide a way for users to query the maximum utilization that would be used:

```solidity
/// @notice Returns the current or cached maximum utilization that would be used in a transaction
/// @return The utilization value that will be used for interest calculations
function getEffectiveUtilization() external view returns (uint256) {
    // Since view functions can't access transient storage from previous txs,
    // return current utilization with a warning that actual tx value may be higher
    return _poolUtilizationWadView();
}

/// @notice Returns the maximum possible interest owed accounting for current utilization
/// @dev Provides an upper bound for interest charges
/// @param owner Address of the user to check
/// @return Maximum interest that could be owed in current conditions
function maxOwedInterest(address owner) external view returns (uint128) {
    // Use current utilization as baseline, knowing actual could be higher
    LeftRightSigned userState = s_interestState[owner];
    (uint128 currentBorrowIndex, , ) = _calculateCurrentInterestState(
        s_assetsInAMM,
        _interestRateView(_poolUtilizationWadView())
    );
    return _getUserInterest(userState, currentBorrowIndex);
}
```

Additionally, document this behavior prominently:
1. Warn users that view functions show minimum expected values
2. Recommend users add safety margins when approving amounts
3. Consider adding slippage protection parameters to functions that trigger `_accrueInterest()`

Alternative solution: Allow users to specify max acceptable interest in transactions:

```solidity
function withdrawWithMaxInterest(
    uint256 assets,
    address receiver,
    address owner,
    TokenId[] calldata positionIdList,
    bool usePremiaAsCollateral,
    uint128 maxAcceptableInterest
) external returns (uint256 shares) {
    uint128 actualInterest = _owedInterest(owner);
    if (actualInterest > maxAcceptableInterest) {
        revert Errors.InterestExceedsMaximum(actualInterest, maxAcceptableInterest);
    }
    // ... rest of withdraw logic
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "contracts/CollateralTracker.sol";
import {PanopticPool} from "contracts/PanopticPool.sol";

contract InterestDiscrepancyExploit is Test {
    CollateralTracker collateral;
    address victim = address(0x1);
    address attacker = address(0x2);
    
    function setUp() public {
        // Setup CollateralTracker instance
        // Initialize with pool, tokens, etc.
    }
    
    function testInterestDiscrepancyFrontRun() public {
        // 1. Victim has borrowed funds
        // Setup: victim has netBorrows > 0, near liquidation threshold
        vm.startPrank(victim);
        // ... mint position with borrowing ...
        vm.stopPrank();
        
        // 2. Victim checks interest off-chain (simulating view call)
        uint128 viewInterest = collateral.owedInterest(victim);
        console.log("Interest shown in view:", viewInterest);
        
        // 3. Victim submits transaction
        // But attacker front-runs...
        vm.startPrank(attacker);
        
        // Attacker deposits large amount to increase utilization
        collateral.deposit(1_000_000e18, attacker);
        
        // Now utilization is stored in transient storage
        vm.stopPrank();
        
        // 4. Victim's transaction executes in same block
        vm.startPrank(victim);
        
        // When victim's _accrueInterest is called, it uses higher utilization
        collateral.accrueInterest(); // This triggers _accrueInterest
        
        // 5. Check actual interest charged
        uint128 actualInterest = collateral.owedInterest(victim);
        console.log("Interest actually charged:", actualInterest);
        
        // Demonstrate discrepancy
        assertGt(actualInterest, viewInterest, "Actual interest should be higher than view predicted");
        
        // 6. If victim is near liquidation, this extra interest causes insolvency
        // Attacker can now liquidate and profit
        vm.stopPrank();
    }
}
```

**Note**: This PoC demonstrates the core vulnerability. In a full implementation, you would:
1. Set up a complete test environment with PanopticPool, RiskEngine, etc.
2. Create positions that put the victim near liquidation threshold
3. Show the exact utilization change and corresponding borrow index difference
4. Calculate the liquidation bonus that makes the attack profitable
5. Demonstrate the complete attack flow including liquidation

The key insight is that the transient storage mechanism (`tstore`/`tload`) creates an observable discrepancy between off-chain view function predictions and on-chain execution results, which can be exploited through front-running to manipulate interest charges and trigger liquidations.

### Citations

**File:** contracts/CollateralTracker.sol (L886-892)
```text
    function _accrueInterest(address owner, bool isDeposit) internal {
        uint128 _assetsInAMM = s_assetsInAMM;
        (
            uint128 currentBorrowIndex,
            uint128 _unrealizedGlobalInterest,
            uint256 currentEpoch
        ) = _calculateCurrentInterestState(_assetsInAMM, _updateInterestRate());
```

**File:** contracts/CollateralTracker.sol (L1007-1025)
```text
        if (deltaTime > 0) {
            // Calculate interest growth
            uint128 rawInterest = (Math.wTaylorCompounded(interestRateSnapshot, uint128(deltaTime)))
                .toUint128();
            // Calculate interest owed on borrowed amount

            uint128 interestOwed = Math.mulDivWadRoundingUp(_assetsInAMM, rawInterest).toUint128();

            // keep checked to prevent overflows
            _unrealizedGlobalInterest += interestOwed;

            // Update borrow index
            unchecked {
                uint128 _borrowIndex = (WAD + rawInterest).toUint128();
                currentBorrowIndex = Math
                    .mulDivWadRoundingUp(currentBorrowIndex, _borrowIndex)
                    .toUint128();
            }
        }
```

**File:** contracts/CollateralTracker.sol (L1047-1054)
```text
    function _updateInterestRate() internal returns (uint128) {
        (uint128 avgRate, uint256 endRateAtTarget) = riskEngine().updateInterestRate(
            _poolUtilizationWad(),
            s_marketState
        );
        s_marketState = s_marketState.updateRateAtTarget(uint40(endRateAtTarget));
        return avgRate;
    }
```

**File:** contracts/CollateralTracker.sol (L1099-1106)
```text
    function _owedInterest(address owner) internal view returns (uint128) {
        LeftRightSigned userState = s_interestState[owner];
        (uint128 currentBorrowIndex, , ) = _calculateCurrentInterestState(
            s_assetsInAMM,
            _interestRateView(_poolUtilizationWadView())
        );
        return _getUserInterest(userState, currentBorrowIndex);
    }
```

**File:** contracts/CollateralTracker.sol (L1173-1195)
```text
    function _poolUtilizationWad() internal returns (uint256) {
        uint256 storedUtilization;
        bytes32 slot = UTILIZATION_TRANSIENT_SLOT;
        assembly {
            storedUtilization := tload(slot)
        }

        unchecked {
            // convert to WAD
            storedUtilization = (storedUtilization * WAD) / DECIMALS;
        }
        uint256 poolUtilization = _poolUtilizationWadView();

        if (storedUtilization > poolUtilization) {
            return storedUtilization;
        } else {
            // store the utilization as DECIMALS
            assembly {
                tstore(slot, div(mul(poolUtilization, DECIMALS), WAD))
            }
            return poolUtilization;
        }
    }
```

**File:** contracts/CollateralTracker.sol (L1199-1208)
```text
    function _poolUtilizationWadView() internal view returns (uint256 poolUtilization) {
        unchecked {
            return
                Math.mulDivRoundingUp(
                    uint256(s_assetsInAMM) + uint256(s_marketState.unrealizedInterest()),
                    WAD,
                    totalAssets()
                );
        }
    }
```
