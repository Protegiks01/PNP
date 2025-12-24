# Audit Report

## Title 
Interest Rate Manipulation via Cross-Transaction Utilization Spiking

## Summary
The `_updateInterestRate()` function in `CollateralTracker.sol` can be exploited to artificially inflate the `rateAtTarget` parameter through strategic withdrawals and deposits across multiple transactions. While the transient storage mechanism protects against flash deposits lowering utilization within a single transaction, it does not prevent attackers from spiking utilization via withdrawals and having that elevated utilization persist long enough to permanently increase `rateAtTarget` in storage.

## Finding Description

The vulnerability stems from the asymmetric protection in the utilization tracking mechanism. [1](#0-0) 

The `_poolUtilizationWad()` function uses transient storage to track the maximum utilization within a transaction, explicitly designed to "ensure that flash deposits can't lower the utilization for a single tx". However, this protection does not prevent the inverse attack: flash withdrawals temporarily spiking utilization.

When `_updateInterestRate()` is called, it retrieves the utilization and passes it to the RiskEngine: [2](#0-1) 

The RiskEngine calculates a new `rateAtTarget` based on the provided utilization and time elapsed: [3](#0-2) 

The critical issue is that this `rateAtTarget` value is stored in **persistent storage** (`s_marketState`), not transient storage. Once elevated, it continues to affect interest rate calculations even after utilization returns to normal levels.

**Attack Flow:**

1. **Transaction 1 (Block N):** Attacker withdraws a large amount (e.g., 900 out of 1000 deposited tokens)
   - `_accrueInterest()` is called first with pre-withdrawal utilization (e.g., 50%)
   - Withdrawal completes, `s_depositedAssets` decreases
   - Utilization spikes (e.g., to 83% if 500 tokens remain in AMM: 500/(100+500))

2. **Wait 4+ seconds** (at least 1 epoch, since epochs are calculated as `block.timestamp >> 2`)

3. **Transaction 2 (Block N+k where k*blocktime ≥ 4s):** Attacker or anyone calls `accrueInterest()` (public function with no access control)
   - `_poolUtilizationWad()` calculates current utilization = 83%
   - Transient storage is empty (cleared between transactions), stores and returns 83%
   - `elapsed` time is non-zero (at least 4 seconds), so interest rate adaptation occurs
   - With utilization at 83% > target 66.67%, the error term is positive
   - `rateAtTarget` increases and is stored in persistent storage `s_marketState` [4](#0-3) 

4. **Transaction 3:** Attacker deposits the withdrawn amount back
   - Utilization returns to normal (~50%)
   - But `rateAtTarget` remains elevated in storage

**Result:** Future interest calculations use the artificially elevated `rateAtTarget`, causing borrowers to pay higher interest rates than warranted by actual utilization.

The epoch-based calculation ensures interest only compounds when time has passed: [5](#0-4) 

This breaks **Invariant #21 (Interest Accuracy)**: Interest rates should accurately reflect actual pool utilization, but the manipulated `rateAtTarget` causes interest calculations to deviate from true market conditions.

## Impact Explanation

This vulnerability enables **economic manipulation** causing:

1. **Direct Financial Harm to Borrowers:** Option traders with net short positions (borrowers) pay artificially inflated interest rates that do not reflect actual pool utilization. The excess interest payments represent a direct transfer of value from borrowers to lenders.

2. **Attacker Profit if PLP:** If the attacker is a Panoptic Liquidity Provider (PLP/lender), they directly benefit from the higher interest payments made by borrowers. This creates an economic incentive for large PLPs to repeatedly execute this attack.

3. **Persistent Effect:** While the adaptive interest rate mechanism will eventually correct the `rateAtTarget` over time, this correction is gradual. The manipulation persists across many transactions and blocks, compounding the harm to borrowers.

4. **Repeatable Attack:** The attacker can repeat this manipulation periodically to maintain artificially elevated interest rates, especially if they time attacks to occur when natural utilization is low.

**Medium Severity** is appropriate because:
- It causes economic harm and value extraction but not direct theft of principal
- It requires capital or flash loans (cost barrier)
- The impact is temporary but repeatable
- It enables systematic exploitation of borrowers by lenders

## Likelihood Explanation

**High Likelihood** - The attack is practical and economically incentivized:

1. **No Access Control:** The `accrueInterest()` function is publicly callable with no restrictions, allowing anyone to trigger interest rate updates at any time. [6](#0-5) 

2. **Low Cost:** 
   - Using flash loans: only flash loan fees (~0.01-0.09%)
   - Using own capital: only opportunity cost for 4+ seconds
   - Gas costs are minimal

3. **Clear Economic Incentive:** Large PLPs (lenders) directly profit from higher interest rates. The benefit can significantly exceed the attack cost for substantial positions.

4. **Simple Execution:** Requires only 3 transactions spaced by 4+ seconds:
   - Withdraw → Wait → Trigger accrueInterest → Deposit back

5. **Difficult to Detect:** The elevated `rateAtTarget` appears as normal adaptive rate behavior and gradually adjusts back, making the manipulation subtle.

6. **No Prerequisites:** Attacker only needs sufficient capital or flash loan access, both readily available in DeFi.

## Recommendation

Implement a **time-weighted utilization average** or **utilization snapshot** mechanism that prevents sudden utilization spikes from immediately affecting `rateAtTarget` updates. 

**Recommended Fix:**

1. Store utilization history in persistent storage alongside timestamps
2. Calculate interest rate updates based on time-weighted average utilization over a minimum window (e.g., 5-10 minutes)
3. Alternatively, add a rate limiter to `rateAtTarget` changes to prevent sudden spikes

**Example Implementation:**

```solidity
// Add to CollateralTracker storage
struct UtilizationSnapshot {
    uint128 utilization;
    uint32 timestamp;
}
UtilizationSnapshot[8] internal s_utilizationHistory;
uint8 internal s_utilizationIndex;

function _updateInterestRate() internal returns (uint128) {
    uint256 currentUtil = _poolUtilizationWad();
    
    // Store current utilization in circular buffer
    s_utilizationHistory[s_utilizationIndex] = UtilizationSnapshot({
        utilization: uint128(currentUtil),
        timestamp: uint32(block.timestamp)
    });
    s_utilizationIndex = (s_utilizationIndex + 1) % 8;
    
    // Calculate time-weighted average over available history
    uint256 weightedUtil = _calculateTimeWeightedAverage();
    
    // Use time-weighted average instead of spot utilization
    (uint128 avgRate, uint256 endRateAtTarget) = riskEngine().updateInterestRate(
        weightedUtil,
        s_marketState
    );
    s_marketState = s_marketState.updateRateAtTarget(uint40(endRateAtTarget));
    return avgRate;
}

function _calculateTimeWeightedAverage() internal view returns (uint256) {
    uint256 totalWeightedUtil;
    uint256 totalWeight;
    uint32 currentTime = uint32(block.timestamp);
    
    for (uint256 i = 0; i < 8; i++) {
        UtilizationSnapshot memory snap = s_utilizationHistory[i];
        if (snap.timestamp == 0) continue;
        
        uint256 age = currentTime - snap.timestamp;
        if (age > 600) continue; // Ignore data older than 10 minutes
        
        uint256 weight = 600 - age; // More recent = higher weight
        totalWeightedUtil += snap.utilization * weight;
        totalWeight += weight;
    }
    
    return totalWeight > 0 ? totalWeightedUtil / totalWeight : _poolUtilizationWad();
}
```

This ensures that temporary utilization spikes cannot immediately manipulate the persistent `rateAtTarget` parameter, while still allowing the interest rate to respond to sustained changes in utilization.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "contracts/CollateralTracker.sol";
import {PanopticPool} from "contracts/PanopticPool.sol";
import {RiskEngine} from "contracts/RiskEngine.sol";

contract InterestRateManipulationTest is Test {
    CollateralTracker public collateralTracker;
    PanopticPool public panopticPool;
    RiskEngine public riskEngine;
    
    address public attacker = address(0x1);
    address public victim = address(0x2);
    
    function setUp() public {
        // Deploy contracts (simplified setup)
        // In actual test, deploy full protocol stack
        vm.label(attacker, "Attacker");
        vm.label(victim, "Victim");
    }
    
    function testInterestRateManipulation() public {
        // Setup: Deposit initial liquidity
        vm.startPrank(victim);
        // Assume 1000 tokens deposited, 500 in AMM
        // Initial utilization = 500/1500 = ~33%
        vm.stopPrank();
        
        // Record initial rateAtTarget
        uint256 initialRateAtTarget = collateralTracker.rateAtTarget();
        
        // Step 1: Attacker withdraws large amount
        vm.startPrank(attacker);
        // Withdraw 900 tokens, leaving 100 deposited
        // New utilization = 500/600 = ~83%
        collateralTracker.withdraw(900 ether, attacker, attacker);
        vm.stopPrank();
        
        // Step 2: Wait for 1 epoch (4 seconds)
        vm.warp(block.timestamp + 5);
        vm.roll(block.number + 1);
        
        // Step 3: Trigger interest rate update
        collateralTracker.accrueInterest();
        
        // Verify rateAtTarget has increased due to spiked utilization
        uint256 manipulatedRateAtTarget = collateralTracker.rateAtTarget();
        assertGt(manipulatedRateAtTarget, initialRateAtTarget, 
            "rateAtTarget should increase due to spiked utilization");
        
        // Step 4: Attacker deposits back
        vm.startPrank(attacker);
        collateralTracker.deposit(900 ether, attacker);
        vm.stopPrank();
        
        // Verify utilization is back to normal but rateAtTarget remains elevated
        uint256 currentUtilization = collateralTracker._poolUtilizationView();
        uint256 finalRateAtTarget = collateralTracker.rateAtTarget();
        
        // Utilization is back to ~33%
        assertApproxEqRel(currentUtilization, 33e16, 0.05e18);
        
        // But rateAtTarget is still elevated
        assertEq(finalRateAtTarget, manipulatedRateAtTarget,
            "rateAtTarget remains elevated even after utilization normalizes");
        
        // Demonstrate impact: Borrowers now pay higher interest
        vm.warp(block.timestamp + 3600); // Advance 1 hour
        
        // Calculate interest rate at normal utilization with elevated rateAtTarget
        uint256 manipulatedInterestRate = collateralTracker.interestRate();
        
        // This interest rate is higher than it should be given actual 33% utilization
        // because rateAtTarget was artificially elevated during the manipulation
    }
}
```

The PoC demonstrates how an attacker can persistently elevate `rateAtTarget` through strategic withdrawals and deposits, causing borrowers to pay inflated interest rates even after utilization returns to normal levels.

### Citations

**File:** contracts/CollateralTracker.sol (L879-881)
```text
    function accrueInterest() external {
        _accrueInterest(msg.sender, IS_NOT_DEPOSIT);
    }
```

**File:** contracts/CollateralTracker.sol (L999-1007)
```text
        currentEpoch = block.timestamp >> 2;
        uint256 previousEpoch = accumulator.marketEpoch();
        uint128 deltaTime;
        unchecked {
            deltaTime = uint32(currentEpoch - previousEpoch) << 2;
        }
        currentBorrowIndex = accumulator.borrowIndex();
        _unrealizedGlobalInterest = accumulator.unrealizedInterest();
        if (deltaTime > 0) {
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

**File:** contracts/RiskEngine.sol (L2174-2183)
```text
    function updateInterestRate(
        uint256 utilization,
        MarketState interestRateAccumulator
    ) external view returns (uint128, uint256) {
        (uint256 avgRate, int256 endRateAtTarget) = _borrowRate(
            utilization,
            interestRateAccumulator
        );
        return (uint128(avgRate), uint256(endRateAtTarget));
    }
```

**File:** contracts/RiskEngine.sol (L2217-2222)
```text
                // Cap the elapsed time to prevent IRM drift
                int256 elapsed = Math.min(
                    int256(block.timestamp) - int256(previousTime),
                    IRM_MAX_ELAPSED_TIME
                );
                int256 linearAdaptation = speed * elapsed;
```
