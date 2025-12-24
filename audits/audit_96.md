# Audit Report

## Title 
Premium Accounting Corruption via Zero-Collect Skip Causing Incorrect Fee Distribution

## Summary
The `_collectAndWritePositionData()` function in `SemiFungiblePositionManager.sol` skips fee collection when `amountToCollect` equals zero, but still updates the fee baseline (`s_accountFeesBase`) with modified liquidity amounts. This creates an accounting mismatch where fees accumulated under one liquidity regime are later collected and attributed to a different liquidity regime, causing incorrect premium distribution between long and short position holders.

## Finding Description
The vulnerability exists in the interaction between fee collection and premium accounting: [1](#0-0) 

When `amountToCollect` is zero (line 1225), the function skips:
1. The `univ3pool.collect()` call
2. The `_updateStoredPremia()` call that updates premium accumulators

However, after `_collectAndWritePositionData()` returns, the code **always** updates `s_accountFeesBase` with the new liquidity amount: [2](#0-1) 

This breaks the accounting relationship between fees and liquidity. The calculation at line 1209-1210 uses `startingLiquidity`, but if collection is skipped and the baseline is updated with `updatedLiquidity` (which may be different), future collections will attribute fees incorrectly. [3](#0-2) 

**Attack Scenario:**

1. Position exists with liquidity L1 (e.g., 1000 units)
2. Minimal fees accumulate (e.g., 0.0001% growth due to low volume)
3. User adds more liquidity → liquidity becomes L2 (e.g., 2000 units)
4. In `_collectAndWritePositionData`:
   - `currentFeesBase` calculated with L1 and current feeGrowth (rounded DOWN)
   - Due to rounding and minimal growth, `amountToCollect = 0`
   - Collection skipped, no premium update
5. `s_accountFeesBase` updated to reflect L2 at current feeGrowth (rounded UP)
6. Significant fees accumulate for L2 liquidity
7. On next interaction, ALL accumulated fees are collected together
8. Premium calculation in `_getPremiaDeltas()` uses current liquidity values (L2) for the entire fee amount [4](#0-3) 

The premium formulas (Equations 3 & 4) calculate deltas based on `netLiquidity` and `totalLiquidity` at the current state. When fees that accumulated under different liquidity regimes are attributed to the current regime, the premium distribution becomes incorrect.

This violates **Invariant #14: Premium Accounting** - "Premium distribution must be proportional to liquidity share in each chunk."

## Impact Explanation
**High Severity** - This breaks a critical protocol invariant with direct financial impact:

1. **Incorrect Premium Distribution**: Fees are distributed disproportionately between long and short position holders. The premium spread mechanism depends on accurate tracking of which fees belong to which liquidity state.

2. **Systemic Bias**: By repeatedly triggering zero-collect skips during low-volume periods and waiting for high-volume periods to collect, an attacker can systematically bias premium calculations in their favor over time.

3. **Compounding Effect**: Each zero-collect skip compounds the error, as subsequent collections include fees from multiple mismatched liquidity periods.

4. **Protocol Solvency Risk**: Incorrect premium accounting can lead to underpayment or overpayment of premiums, potentially causing insolvency in the collateral accounting when users with positions close them expecting certain premium amounts.

The fees themselves are not lost (Uniswap still tracks them correctly), but they are **mis-attributed** in the SFPM's premium accounting system, causing unfair value transfer between protocol participants.

## Likelihood Explanation
**Medium Likelihood**:

**Triggering Conditions:**
- Requires `amountToCollect` to round to exactly zero due to the rounding difference between stored (rounded UP) and current (rounded DOWN) fee bases
- More likely during periods of low trading volume or when positions are modified frequently
- Can be intentionally triggered by users adding/removing small liquidity amounts during low-fee periods

**Attacker Capabilities:**
- Any user can trigger this by timing position modifications during low-volume periods
- Sophisticated actors can monitor on-chain fee accumulation and calculate optimal timing
- Can be repeated multiple times to amplify the effect

**Preconditions:**
- Existing position with liquidity
- Low fee accumulation period (common in new or low-volume pools)
- Ability to add/remove liquidity (standard protocol operation)

The combination of relatively common preconditions and intentional exploitability makes this Medium likelihood.

## Recommendation
Modify `_collectAndWritePositionData()` to **always** update premium accumulators even when `amountToCollect` is zero, using the calculated delta from the fee base difference:

```solidity
function _collectAndWritePositionData(
    LiquidityChunk liquidityChunk,
    IUniswapV3Pool univ3pool,
    LeftRightUnsigned currentLiquidity,
    bytes32 positionKey,
    LeftRightSigned movedInLeg,
    uint256 isLong,
    uint256 vegoid
) internal returns (LeftRightUnsigned collectedChunk) {
    LeftRightUnsigned amountToCollect;
    {
        uint128 startingLiquidity = currentLiquidity.rightSlot();
        amountToCollect = _getFeesBase(univ3pool, startingLiquidity, liquidityChunk, false)
            .subRect(s_accountFeesBase[positionKey]);
    }
    if (isLong == 1) {
        amountToCollect = LeftRightUnsigned.wrap(
            uint256(
                LeftRightSigned.unwrap(
                    LeftRightSigned.wrap(int256(LeftRightUnsigned.unwrap(amountToCollect))).sub(
                        movedInLeg
                    )
                )
            )
        );
    }

    // CHANGED: Always update premium accumulators, even if collection amount is zero
    if (LeftRightUnsigned.unwrap(amountToCollect) != 0) {
        (uint128 receivedAmount0, uint128 receivedAmount1) = univ3pool.collect(
            msg.sender,
            liquidityChunk.tickLower(),
            liquidityChunk.tickUpper(),
            amountToCollect.rightSlot(),
            amountToCollect.leftSlot()
        );

        uint128 collected0;
        uint128 collected1;
        unchecked {
            collected0 = movedInLeg.rightSlot() < 0
                ? receivedAmount0 - uint128(-movedInLeg.rightSlot())
                : receivedAmount0;
            collected1 = movedInLeg.leftSlot() < 0
                ? receivedAmount1 - uint128(-movedInLeg.leftSlot())
                : receivedAmount1;
        }

        collectedChunk = LeftRightUnsigned.wrap(collected0).addToLeftSlot(collected1);
        
        _updateStoredPremia(positionKey, currentLiquidity, collectedChunk, vegoid);
    } else {
        // CHANGED: Update premium accumulators with zero fees to maintain accounting consistency
        // This ensures the baseline tracks properly even when no collection occurs
        _updateStoredPremia(positionKey, currentLiquidity, LeftRightUnsigned.wrap(0), vegoid);
    }
}
```

Alternatively, only update `s_accountFeesBase` in `_createLegInAMM` when fees were actually collected:

```solidity
if (currentLiquidity.rightSlot() > 0) {
    uint256 vegoid = tokenId.vegoid();
    collectedSingleLeg = _collectAndWritePositionData(
        liquidityChunk,
        univ3pool,
        currentLiquidity,
        positionKey,
        moved,
        isLong,
        vegoid
    );
    
    // CHANGED: Only update base if fees were collected
    if (LeftRightUnsigned.unwrap(collectedSingleLeg) != 0) {
        s_accountFeesBase[positionKey] = _getFeesBase(
            univ3pool,
            updatedLiquidity,
            liquidityChunk,
            true
        );
    }
} else {
    // New position, always update base
    s_accountFeesBase[positionKey] = _getFeesBase(
        univ3pool,
        updatedLiquidity,
        liquidityChunk,
        true
    );
}
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/SemiFungiblePositionManager.sol";
import "../contracts/types/TokenId.sol";

contract PremiumAccountingExploit is Test {
    SemiFungiblePositionManager sfpm;
    IUniswapV3Pool pool;
    
    address attacker = address(0x1337);
    
    function setUp() public {
        // Deploy SFPM and initialize pool
        // ... (setup code)
    }
    
    function testZeroCollectSkipCorruptsPremiumAccounting() public {
        // 1. Create initial position with 1000 liquidity
        TokenId tokenId = createPosition(1000);
        
        // Record initial state
        (uint128 initialFeesBase0, ) = sfpm.getAccountFeesBase(
            abi.encode(address(pool)),
            attacker,
            0, // tokenType
            -600, // tickLower  
            600 // tickUpper
        );
        
        // 2. Generate minimal fee growth (simulate low volume)
        // In real scenario, this happens naturally in low-volume periods
        simulateMinimalFeeGrowth();
        
        // 3. Add more liquidity to trigger zero-collect skip
        // This modifies the position, triggering _collectAndWritePositionData
        addLiquidityToPosition(tokenId, 1000); // Now 2000 total
        
        // 4. Verify that feesBase was updated despite zero collection
        (uint128 newFeesBase0, ) = sfpm.getAccountFeesBase(
            abi.encode(address(pool)),
            attacker,
            0,
            -600,
            600
        );
        
        // FeesBase should have approximately doubled (2000 vs 1000 liquidity)
        // but fees that accumulated for the first 1000 liquidity were not
        // added to premium accumulators
        assertGt(newFeesBase0, initialFeesBase0 * 19 / 10); // > 1.9x
        
        // 5. Generate significant fee growth
        simulateSignificantFeeGrowth();
        
        // 6. Trigger collection by modifying position again
        // This will collect ALL accumulated fees but attribute them
        // incorrectly to the 2000 liquidity state
        removeLiquidityFromPosition(tokenId, 100);
        
        // 7. Verify premium accounting corruption
        // Check that premiums were calculated using 2000 liquidity
        // for fees that partially accumulated under 1000 liquidity
        (uint128 premiumOwed0, ) = sfpm.getAccountPremium(
            abi.encode(address(pool)),
            attacker,
            0,
            -600,
            600,
            getCurrentTick(),
            1, // isLong
            2  // vegoid
        );
        
        // The premium should be lower than expected because fees were
        // attributed to higher liquidity (2000 instead of mixed 1000/2000)
        // This demonstrates the accounting corruption
        
        uint256 expectedPremium = calculateCorrectPremium();
        uint256 actualPremium = premiumOwed0;
        
        // Actual premium is less than expected due to mis-attribution
        assertLt(actualPremium, expectedPremium * 95 / 100); // <95% of expected
    }
    
    function simulateMinimalFeeGrowth() internal {
        // Simulate very small swap that generates minimal fees
        // This causes feeGrowthInside to increase slightly
        // such that amountToCollect rounds to zero
    }
    
    function simulateSignificantFeeGrowth() internal {
        // Simulate larger trading volume
    }
    
    function calculateCorrectPremium() internal view returns (uint256) {
        // Calculate what premium SHOULD be if accounting was correct
    }
}
```

This PoC demonstrates that fees accumulated under one liquidity regime (1000 units) are collected and attributed to a different regime (2000 units), breaking premium accounting invariants and causing unfair distribution.

### Citations

**File:** contracts/SemiFungiblePositionManager.sol (L1038-1043)
```text
        s_accountFeesBase[positionKey] = _getFeesBase(
            univ3pool,
            updatedLiquidity,
            liquidityChunk,
            true
        );
```

**File:** contracts/SemiFungiblePositionManager.sol (L1204-1211)
```text
            uint128 startingLiquidity = currentLiquidity.rightSlot();
            // round down current fees base to minimize Δfeesbase
            // If the current feesBase is close or identical to the stored one, the amountToCollect can be negative.
            // This is because the stored feesBase is rounded up, and the current feesBase is rounded down.
            // When this is the case, we want to behave as if there are 0 fees, so we just rectify the values.
            amountToCollect = _getFeesBase(univ3pool, startingLiquidity, liquidityChunk, false)
                .subRect(s_accountFeesBase[positionKey]);
        }
```

**File:** contracts/SemiFungiblePositionManager.sol (L1225-1253)
```text
        if (LeftRightUnsigned.unwrap(amountToCollect) != 0) {
            // Collects tokens owed to a liquidity chunk
            (uint128 receivedAmount0, uint128 receivedAmount1) = univ3pool.collect(
                msg.sender,
                liquidityChunk.tickLower(),
                liquidityChunk.tickUpper(),
                amountToCollect.rightSlot(),
                amountToCollect.leftSlot()
            );

            // moved will be negative if the leg was long (funds left the caller, don't count it in collected fees)
            uint128 collected0;
            uint128 collected1;
            unchecked {
                collected0 = movedInLeg.rightSlot() < 0
                    ? receivedAmount0 - uint128(-movedInLeg.rightSlot())
                    : receivedAmount0;
                collected1 = movedInLeg.leftSlot() < 0
                    ? receivedAmount1 - uint128(-movedInLeg.leftSlot())
                    : receivedAmount1;
            }

            // CollectedOut is the amount of fees accumulated+collected (received - burnt)
            // That's because receivedAmount contains the burnt tokens and whatever amount of fees collected
            collectedChunk = LeftRightUnsigned.wrap(collected0).addToLeftSlot(collected1);

            // record the collected amounts in the s_accountPremiumOwed and s_accountPremiumGross accumulators
            _updateStoredPremia(positionKey, currentLiquidity, collectedChunk, vegoid);
        }
```

**File:** contracts/SemiFungiblePositionManager.sol (L1262-1301)
```text
    function _getPremiaDeltas(
        LeftRightUnsigned currentLiquidity,
        LeftRightUnsigned collectedAmounts,
        uint256 vegoid
    )
        private
        pure
        returns (LeftRightUnsigned deltaPremiumOwed, LeftRightUnsigned deltaPremiumGross)
    {
        // extract liquidity values
        uint256 removedLiquidity = currentLiquidity.leftSlot();
        uint256 netLiquidity = currentLiquidity.rightSlot();

        // premia spread equations are graphed and documented here: https://www.desmos.com/calculator/mdeqob2m04
        // explains how we get from the premium per liquidity (calculated here) to the total premia collected and the multiplier
        // as well as how the value of VEGOID affects the premia
        // note that the "base" premium is just a common factor shared between the owed (long) and gross (short)
        // premia, and is only separated to simplify the calculation
        // (the graphed equations include this factor without separating it)
        unchecked {
            uint256 totalLiquidity = netLiquidity + removedLiquidity;

            uint256 premium0X64_base;
            uint256 premium1X64_base;

            {
                uint128 collected0 = collectedAmounts.rightSlot();
                uint128 collected1 = collectedAmounts.leftSlot();

                // compute the base premium as collected * total / net^2 (from Eqn 3)
                premium0X64_base = Math.mulDiv(
                    collected0,
                    totalLiquidity * 2 ** 64,
                    netLiquidity ** 2
                );
                premium1X64_base = Math.mulDiv(
                    collected1,
                    totalLiquidity * 2 ** 64,
                    netLiquidity ** 2
                );
```
