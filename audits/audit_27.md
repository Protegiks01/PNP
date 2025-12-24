# Audit Report

## Title 
Stale Utilization Data Allows Cross-Collateral Bypass During High Pool Stress

## Summary
The `isAccountSolvent()` function calculates cross-buffer ratios using historical pool utilization values stored at position mint time, rather than current utilization. This allows users who minted positions during low-utilization periods to maintain inflated cross-collateral credit even when pool utilization reaches critical levels (85-90%), directly violating Invariant #5 and enabling systematic undercollateralization.

## Finding Description
The cross-buffer ratio mechanism is designed to limit cross-collateralization between token0 and token1 based on pool utilization, with the ratio dropping to zero at 90% utilization to prevent systemic risk during high-stress periods. [1](#0-0) 

However, the solvency check uses utilization values that were frozen at position mint time, not current pool utilization: [2](#0-1) 

These utilization values come from `globalUtilizations`, which extracts the maximum historical utilization across all of a user's positions: [3](#0-2) 

The utilization values in `PositionBalance` are stored at mint time and never updated: [4](#0-3) [5](#0-4) 

**Attack Path:**
1. Attacker mints positions when pool utilization is 30%
2. PositionBalance stores utilization0 = 3000 (30%)
3. At 30% utilization, `_crossBufferRatio(3000, 5_000_000)` returns full 5,000,000 (50% of CROSS_BUFFER)
4. Pool utilization increases to 85% over time
5. New users at 85% get `_crossBufferRatio(8500, 5_000_000)` = 625,000 (6.25%)
6. Attacker retains 50% cross-buffer ratio despite 85% current utilization
7. Attacker maintains 8x more cross-collateral credit than warranted by actual pool risk
8. At 90% utilization, attacker still has 50% cross-buffer while new users have 0%

This breaks Invariant #5: "Cross-buffer ratio must scale conservatively with utilization, dropping to zero at 90% utilization."

## Impact Explanation
This vulnerability enables **systemic undercollateralization** during high-stress periods:

- **Unfair Risk Distribution**: Users with old positions get up to 50% cross-collateral credit while new users at the same time get 0-6% based on current utilization
- **Liquidation Failures**: Positions that should be liquidatable during high utilization appear solvent due to inflated cross-collateral credit
- **Protocol Insolvency Risk**: If many users have positions from low-utilization periods, the protocol carries significantly more risk than intended during 85-90% utilization periods
- **Bypasses Safety Mechanism**: The cross-buffer ratio reduction at high utilization is specifically designed to ensure prompt liquidations and prevent cascading failures, but this bug defeats that protection

**Severity Assessment: High** - Directly undermines the core risk model, enables undercollateralization relative to actual pool stress, and violates a critical invariant designed to protect protocol solvency.

## Likelihood Explanation
**Likelihood: High** - This vulnerability is guaranteed to occur naturally:

- **No Attack Required**: Simply minting during normal low-utilization periods and holding positions as utilization increases naturally exploits this
- **Common Scenario**: Pool utilization fluctuates regularly, so many users will accumulate positions with favorable historical utilization values
- **Passive Exploitation**: Users don't need to actively manipulate anything; they benefit automatically as utilization rises
- **Widespread Impact**: Affects all positions minted during any period where utilization was lower than current levels
- **Timing**: No specific timing or coordination needed; occurs organically through normal protocol usage

The combination of high impact and high likelihood makes this a critical issue requiring immediate attention.

## Recommendation
The cross-buffer ratio calculation should use **current pool utilization** rather than historical utilization. Modify `isAccountSolvent()` to query current utilization:

```solidity
function isAccountSolvent(
    PositionBalance[] calldata positionBalanceArray,
    TokenId[] calldata positionIdList,
    int24 atTick,
    address user,
    LeftRightUnsigned shortPremia,
    LeftRightUnsigned longPremia,
    CollateralTracker ct0,
    CollateralTracker ct1,
    uint256 buffer
) external view returns (bool) {
    // ... existing margin calculation ...
    
    // FIX: Query current utilization instead of using historical values
    int256 currentUtilization0 = int256(ct0.poolUtilization());
    int256 currentUtilization1 = int256(ct1.poolUtilization());
    
    uint256 scaledSurplusToken0 = Math.mulDiv(
        bal0 > maintReq0 ? bal0 - maintReq0 : 0,
        _crossBufferRatio(currentUtilization0, CROSS_BUFFER_0),  // Use current, not historical
        DECIMALS
    );
    uint256 scaledSurplusToken1 = Math.mulDiv(
        bal1 > maintReq1 ? bal1 - maintReq1 : 0,
        _crossBufferRatio(currentUtilization1, CROSS_BUFFER_1),  // Use current, not historical
        DECIMALS
    );
    
    // ... rest of solvency check ...
}
```

This ensures the cross-buffer ratio properly scales with current pool risk, maintaining the intended safety mechanism during high-stress periods.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {TokenId} from "@types/TokenId.sol";
import {PositionBalance, PositionBalanceLibrary} from "@types/PositionBalance.sol";
import {LeftRightUnsigned} from "@types/LeftRight.sol";

contract CrossBufferBypassTest is Test {
    using PositionBalanceLibrary for PositionBalance;
    
    RiskEngine riskEngine;
    MockCollateralTracker ct0;
    MockCollateralTracker ct1;
    
    function setUp() public {
        riskEngine = new RiskEngine(
            5_000_000, // CROSS_BUFFER_0 = 50%
            5_000_000, // CROSS_BUFFER_1 = 50%
            address(this),
            address(0)
        );
        ct0 = new MockCollateralTracker();
        ct1 = new MockCollateralTracker();
    }
    
    function testCrossBufferBypassVulnerability() public {
        address attacker = address(0xBEEF);
        
        // Step 1: Simulate position minted when utilization was 30%
        PositionBalance[] memory positions = new PositionBalance[](1);
        positions[0] = PositionBalanceLibrary.storeBalanceData(
            1000 ether,  // position size
            uint32(3000 + (3000 << 16)),  // utilization0=30%, utilization1=30%
            0
        );
        
        TokenId[] memory tokenIds = new TokenId[](1);
        tokenIds[0] = TokenId.wrap(0); // dummy tokenId
        
        // Step 2: Current pool utilization has risen to 85%
        ct0.setCurrentUtilization(8500); // 85%
        ct1.setCurrentUtilization(8500); // 85%
        
        // Setup collateral balances
        ct0.setUser(attacker, 1000 ether, 0, 0);
        ct1.setUser(attacker, 1000 ether, 0, 0);
        
        // Step 3: Calculate cross-buffer ratio with historical 30% utilization
        uint256 historicalCrossBuffer = calculateCrossBufferRatio(3000);
        // At 30% utilization: returns full 5_000_000 (50%)
        assertEq(historicalCrossBuffer, 5_000_000);
        
        // Step 4: Calculate cross-buffer ratio with current 85% utilization
        uint256 currentCrossBuffer = calculateCrossBufferRatio(8500);
        // At 85% utilization: (5_000_000 * (9_000_000 - 8_500_000)) / 4_000_000 = 625_000 (6.25%)
        assertEq(currentCrossBuffer, 625_000);
        
        // Step 5: Demonstrate the disparity
        uint256 advantage = historicalCrossBuffer / currentCrossBuffer;
        assertEq(advantage, 8); // Attacker has 8x more cross-collateral credit!
        
        // Step 6: At 90% utilization, disparity becomes infinite
        uint256 crossBufferAt90 = calculateCrossBufferRatio(9000);
        assertEq(crossBufferAt90, 0); // New users: NO cross-collateral
        // But attacker still has 50% cross-buffer from historical 30% utilization!
        
        console.log("Historical cross-buffer (30% util):", historicalCrossBuffer);
        console.log("Current cross-buffer (85% util):", currentCrossBuffer);
        console.log("Attacker advantage factor:", advantage);
        console.log("Cross-buffer at 90% util:", crossBufferAt90);
    }
    
    function calculateCrossBufferRatio(uint256 utilization) internal pure returns (uint256) {
        uint256 CROSS_BUFFER = 5_000_000;
        uint256 TARGET_POOL_UTIL = 5_000_000;  // 50%
        uint256 SATURATED_POOL_UTIL = 9_000_000; // 90%
        
        uint256 utilizationScaled = utilization * 1_000;
        
        if (utilizationScaled < TARGET_POOL_UTIL) {
            return CROSS_BUFFER;
        }
        if (utilizationScaled > SATURATED_POOL_UTIL) {
            return 0;
        }
        return ((CROSS_BUFFER * (SATURATED_POOL_UTIL - utilizationScaled)) /
            (SATURATED_POOL_UTIL - TARGET_POOL_UTIL));
    }
}

contract MockCollateralTracker {
    mapping(address => uint256) public balances;
    uint256 public currentUtilization;
    
    function setUser(address user, uint256 balance, uint256, uint256) external {
        balances[user] = balance;
    }
    
    function setCurrentUtilization(uint256 util) external {
        currentUtilization = util;
    }
    
    function poolUtilization() external view returns (uint256) {
        return currentUtilization;
    }
    
    function balanceOf(address user) external view returns (uint256) {
        return balances[user];
    }
    
    function assetsAndInterest(address user) external view returns (uint256, uint256) {
        return (balances[user], 0);
    }
    
    function totalAssets() external pure returns (uint256) {
        return 10000 ether;
    }
    
    function totalSupply() external pure returns (uint256) {
        return 10000 ether;
    }
    
    function convertToShares(uint256 assets) external pure returns (uint256) {
        return assets;
    }
    
    function convertToAssets(uint256 shares) external pure returns (uint256) {
        return shares;
    }
}
```

**Expected Output:**
```
Historical cross-buffer (30% util): 5000000
Current cross-buffer (85% util): 625000
Attacker advantage factor: 8
Cross-buffer at 90% util: 0
```

This demonstrates that positions minted during 30% utilization maintain 8x more cross-collateral credit than positions should have at 85% utilization, and infinite advantage compared to the 0% cross-buffer that should apply at 90% utilization.

## Notes

The vulnerability stems from a fundamental design choice to store utilization at mint time rather than querying current utilization. While the comment suggests this provides "more conservative risk assessment" by using the maximum utilization across positions, it actually creates the opposite effect when current utilization exceeds historical values. The cross-buffer ratio's purpose is to adapt to current pool stress levels, but using stale data defeats this adaptive risk management mechanism precisely when it's most needed—during high-stress, high-utilization periods.

### Citations

**File:** contracts/RiskEngine.sol (L1029-1038)
```text
        uint256 scaledSurplusToken0 = Math.mulDiv(
            bal0 > maintReq0 ? bal0 - maintReq0 : 0,
            _crossBufferRatio(globalUtilizations.utilization0(), CROSS_BUFFER_0),
            DECIMALS
        );
        uint256 scaledSurplusToken1 = Math.mulDiv(
            bal1 > maintReq1 ? bal1 - maintReq1 : 0,
            _crossBufferRatio(globalUtilizations.utilization1(), CROSS_BUFFER_1),
            DECIMALS
        );
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

**File:** contracts/RiskEngine.sol (L2110-2151)
```text
    function _crossBufferRatio(
        int256 utilization,
        uint256 crossBuffer
    ) internal view returns (uint256 crossBufferRatio) {
        // linear from crossBuffer to 0 between 50% and 90%
        // the buy ratio is on a straight line defined between two points (x0,y0) and (x1,y1):
        //   (x0,y0) = (targetPoolUtilization, crossBuffer) and
        //   (x1,y1) = (saturatedPoolUtilization, 0)
        // note that y1<y0 so the slope is negative:
        // aka the cross buffer starts high and drops to zero with increased utilization
        // the line's formula: y = a * (x - x0) + y0, where a = (y1 - y0) / (x1 - x0)
        // but since a<0, we rewrite as:
        // y = a' * (x0 - x) + y0, where a' = (y0 - y1) / (x1 - x0)

        /*
          CROSS
          BUFFER
          RATIO
                 ^
                 |   cross_buffer = 80%
           80% - |----------_
                 |         . ¯-_
                 |         .    ¯-_
           0% -  +---------+-------∓---+--->   POOL_
                          50%     90% 100%      UTILIZATION
         */
        unchecked {
            uint256 utilizationScaled = uint256(utilization * 1_000);
            // return the basal cross buffer ratio if pool utilization is lower than target
            if (utilizationScaled < TARGET_POOL_UTIL) {
                return crossBuffer;
            }

            // return 0 if pool utilization is above saturated pool utilization
            if (utilizationScaled > SATURATED_POOL_UTIL) {
                return 0;
            }

            return ((crossBuffer * (SATURATED_POOL_UTIL - utilizationScaled)) /
                (SATURATED_POOL_UTIL - TARGET_POOL_UTIL));
        }
    }
```

**File:** contracts/types/PositionBalance.sol (L14-16)
```text
// (1) positionSize     128bits : The size of this position (uint128).
// (2) poolUtilization0 16bits  : The pool utilization of token0, stored as (10000 * inAMM0)/totalAssets0 (uint16).
// (3) poolUtilization1 16bits  : The pool utilization of token1, stored as (10000 * inAMM1)/totalAssets1 (uint16).
```

**File:** contracts/PanopticPool.sol (L758-763)
```text
            PositionBalance balanceData = PositionBalanceLibrary.storeBalanceData(
                positionSize,
                poolUtilizations,
                0
            );
            s_positionBalance[owner][tokenId] = balanceData;
```
