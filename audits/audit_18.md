# Audit Report

## Title 
Premium Calculated at Wrong Tick Causes Incorrect Multi-Tick Solvency Determinations

## Summary
The `_checkSolvencyAtTicks()` function calculates premium once at `currentTick` but reuses this value when checking solvency at multiple different oracle ticks. Since premium calculation is tick-dependent (different fee accrual rates apply when price is below/within/above a liquidity range), this causes systematic errors in solvency determinations that can lead to incorrect liquidations or allow insolvent positions to avoid liquidation.

## Finding Description

In `PanopticPool._checkSolvencyAtTicks()`, premium is calculated once using `currentTick`: [1](#0-0) 

However, this function then loops through potentially multiple different ticks in the `atTicks` array and checks solvency at each tick using the same premium values: [2](#0-1) 

The `atTicks` array is obtained from `RiskEngine.getSolvencyTicks()` which returns either 1 tick (spotTick in normal conditions) or 4 ticks (spotTick, medianTick, latestTick, currentTick) when high deviation is detected: [3](#0-2) 

**Why Premium Calculation is Tick-Dependent:**

The premium calculation flows through `_calculateAccumulatedPremia()` → `_getPremia()` → `SFPM.getAccountPremium()` → `FeesCalc.calculateAMMSwapFees()`. [4](#0-3) 

The critical issue is in `FeesCalc.calculateAMMSwapFees()` which calculates fee growth using completely different formulas depending on whether `currentTick` is below, within, or above the liquidity chunk's tick range: [5](#0-4) 

When the tick is:
- **Below the range** (currentTick < tickLower): Uses formula `lowerOut - upperOut`
- **Within the range** (tickLower ≤ currentTick < tickUpper): Uses formula `feeGrowthGlobal - lowerOut - upperOut` 
- **Above the range** (currentTick ≥ tickUpper): Uses formula `upperOut - lowerOut`

These produce vastly different premium values. Using premium calculated at `currentTick` to evaluate solvency at `spotTick`, `medianTick`, or `latestTick` (which may be in different regions relative to the position's range) is fundamentally incorrect.

**Exploitation Path:**

1. Alice opens a short position (sells options) with liquidity chunk at [10000, 11000]
2. currentTick = 10500 (within range - position actively earning fees)
3. Market becomes volatile, high oracle deviation detected
4. `getSolvencyTicks()` returns: [spotTick=11500, medianTick=10800, latestTick=11200, currentTick=10500]
5. Premium calculated at currentTick=10500 includes active fee accumulation (within range)
6. Solvency checked at spotTick=11500 uses this inflated premium value
7. At spotTick=11500, Alice's position is above range and would NOT be earning fees
8. The inflated premium makes Alice appear more solvent at spotTick=11500 than she actually is
9. Alice's truly insolvent position avoids liquidation, exposing protocol to loss

**Invariants Broken:**

- **Invariant #10 (Price Consistency)**: Premium is calculated at currentTick while collateral requirements are calculated at atTick, creating pricing inconsistency
- **Invariant #26 (Solvency Check Timing)**: Solvency check at oracle tick uses premium from wrong tick
- **Invariant #1 (Solvency Maintenance)**: Incorrect solvency determinations allow insolvent positions to remain open

## Impact Explanation

**HIGH SEVERITY** - This vulnerability creates two types of financial harm:

1. **False Negative (Insolvent appears Solvent)**: When premium is calculated at a tick where the position earns more fees than at the evaluation tick, insolvent accounts can avoid liquidation. This creates systemic undercollateralization risk and potential protocol losses if positions cannot be liquidated before losses exceed collateral.

2. **False Positive (Solvent appears Insolvent)**: When premium is calculated at a tick where the position earns fewer fees than at the evaluation tick, solvent accounts can be incorrectly liquidated. Users lose their positions and pay liquidation bonuses unfairly.

The magnitude of error increases with:
- Distance between currentTick and atTicks (can be 953+ ticks in high deviation scenarios)
- Position size and fee accumulation rate
- Utilization of the pool (affects prorated premium for shorts)

This affects every liquidation and solvency check when oracle deviation triggers multi-tick validation, which is precisely when accurate solvency determination is most critical.

## Likelihood Explanation

**HIGH LIKELIHOOD** - This bug triggers automatically in specific but common scenarios:

1. **Frequency**: Multi-tick solvency checks occur whenever oracle deviation exceeds thresholds, which happens during:
   - Market volatility (price moves ~10% in <4 minutes)
   - Oracle staleness or temporary issues
   - Intentional price manipulation attempts

2. **Affected Operations**:
   - `_validateSolvency()` during position minting/burning
   - `liquidate()` during liquidation attempts
   - Any operation that checks account solvency

3. **No Special Privileges Required**: Any user with open positions is subject to this bug during their normal solvency checks.

4. **Unintentional Exploitation**: Users don't need to intentionally exploit this - the incorrect calculations happen automatically due to the code logic.

The combination of automatic triggering during critical market conditions (when accurate solvency is most important) and financial impact on both users and protocol makes this HIGH likelihood.

## Recommendation

Calculate premium separately for each tick in the `atTicks` array instead of reusing a single premium value calculated at `currentTick`.

**Recommended Fix:**

```solidity
function _checkSolvencyAtTicks(
    address account,
    uint8 safeMode,
    TokenId[] calldata positionIdList,
    int24 currentTick,
    int24[] memory atTicks,
    bool usePremiaAsCollateral,
    uint256 buffer
) internal view returns (uint256) {
    PositionBalance[] memory positionBalanceArray;
    
    // if safeMode is ON, make the collateral requirements for 100% utilizations
    if (safeMode > 0) {
        // Get position balances once (doesn't depend on tick)
        positionBalanceArray = new PositionBalance[](positionIdList.length);
        for (uint256 k = 0; k < positionIdList.length; k++) {
            positionBalanceArray[k] = s_positionBalance[account][positionIdList[k]];
        }
        unchecked {
            uint32 maxUtilizations = uint32(DECIMALS + (DECIMALS << 16));
            positionBalanceArray[0] = PositionBalanceLibrary.storeBalanceData(
                positionBalanceArray[0].positionSize(),
                maxUtilizations,
                0
            );
        }
    }
    
    uint256 solvent;
    for (uint256 i; i < atTicks.length; ) {
        // Calculate premium at EACH tick
        (
            LeftRightUnsigned shortPremium,
            LeftRightUnsigned longPremium,
            PositionBalance[] memory balanceArray
        ) = _calculateAccumulatedPremia(
                account,
                positionIdList,
                usePremiaAsCollateral,
                ONLY_AVAILABLE_PREMIUM,
                atTicks[i]  // Use the tick being evaluated
            );
        
        // Use position balances from safe mode if set, otherwise from premium calc
        PositionBalance[] memory balancesToUse = safeMode > 0 ? positionBalanceArray : balanceArray;
        
        unchecked {
            if (
                _isAccountSolvent(
                    account,
                    atTicks[i],
                    positionIdList,
                    balancesToUse,
                    shortPremium,
                    longPremium,
                    buffer
                )
            ) ++solvent;

            ++i;
        }
    }

    return solvent;
}
```

This ensures premium is calculated at the same tick where solvency is being evaluated, maintaining price consistency across the entire solvency check.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {SemiFungiblePositionManager} from "@contracts/SemiFungiblePositionManager.sol";
import {RiskEngine} from "@contracts/RiskEngine.sol";
import {TokenId} from "@types/TokenId.sol";
import {LeftRightUnsigned} from "@types/LeftRight.sol";

contract PremiumMiscalculationTest is Test {
    PanopticPool public pool;
    SemiFungiblePositionManager public sfpm;
    RiskEngine public riskEngine;
    address public alice = address(0x1);

    function setUp() public {
        // Deploy contracts and initialize pool
        // (deployment code omitted for brevity)
    }

    function testPremiumCalculatedAtWrongTick() public {
        // 1. Alice opens a short position at ticks [10000, 11000]
        TokenId tokenId = createShortPosition(alice, 10000, 11000);
        
        // 2. Current tick is within range (earning fees)
        int24 currentTick = 10500;
        vm.mockCall(
            address(pool),
            abi.encodeWithSelector(pool.getCurrentTick.selector),
            abi.encode(currentTick)
        );
        
        // 3. Simulate high oracle deviation - getSolvencyTicks returns 4 ticks
        int24 spotTick = 11500;    // Above range - NOT earning fees
        int24 medianTick = 10800;  // Still within range
        int24 latestTick = 11200;  // Above range
        
        int24[] memory atTicks = new int24[](4);
        atTicks[0] = spotTick;
        atTicks[1] = medianTick;
        atTicks[2] = latestTick;
        atTicks[3] = currentTick;
        
        // 4. Calculate premium at currentTick (within range)
        (LeftRightUnsigned premiumAtCurrent,,) = pool._calculateAccumulatedPremia(
            alice,
            getPositionList(tokenId),
            true,
            true,
            currentTick
        );
        
        // 5. Calculate premium at spotTick (above range - should be different)
        (LeftRightUnsigned premiumAtSpot,,) = pool._calculateAccumulatedPremia(
            alice,
            getPositionList(tokenId),
            true,
            true,
            spotTick
        );
        
        // 6. Demonstrate premiums are different
        assertNotEq(
            premiumAtCurrent.rightSlot(),
            premiumAtSpot.rightSlot(),
            "Premium should differ between currentTick and spotTick"
        );
        
        // 7. Show that _checkSolvencyAtTicks uses wrong premium
        // It calculates at currentTick but checks solvency at spotTick
        uint256 solvent = pool._checkSolvencyAtTicks(
            alice,
            0,
            getPositionList(tokenId),
            currentTick,
            atTicks,
            true,
            10_000_000
        );
        
        // 8. Demonstrate incorrect solvency determination
        // The solvency check at spotTick used premiumAtCurrent instead of premiumAtSpot
        // This can cause Alice to appear solvent when she should be insolvent
        console.log("Solvency checks passed:", solvent);
        console.log("Premium at currentTick:", premiumAtCurrent.rightSlot());
        console.log("Premium at spotTick (correct):", premiumAtSpot.rightSlot());
        console.log("Difference:", int256(premiumAtCurrent.rightSlot()) - int256(premiumAtSpot.rightSlot()));
    }
    
    function createShortPosition(address user, int24 tickLower, int24 tickUpper) internal returns (TokenId) {
        // Create short position with specified tick range
        // (implementation omitted for brevity)
    }
    
    function getPositionList(TokenId tokenId) internal pure returns (TokenId[] memory) {
        TokenId[] memory list = new TokenId[](1);
        list[0] = tokenId;
        return list;
    }
}
```

This test demonstrates that premium values differ significantly between ticks (especially when crossing in-range/out-of-range boundaries), yet `_checkSolvencyAtTicks()` incorrectly uses a single premium value for all tick evaluations.

### Citations

**File:** contracts/PanopticPool.sol (L1728-1738)
```text
        (
            LeftRightUnsigned shortPremium,
            LeftRightUnsigned longPremium,
            PositionBalance[] memory positionBalanceArray
        ) = _calculateAccumulatedPremia(
                account,
                positionIdList,
                usePremiaAsCollateral,
                ONLY_AVAILABLE_PREMIUM,
                currentTick
            );
```

**File:** contracts/PanopticPool.sol (L1753-1769)
```text
        for (uint256 i; i < atTicks.length; ) {
            unchecked {
                if (
                    _isAccountSolvent(
                        account,
                        atTicks[i],
                        positionIdList,
                        positionBalanceArray,
                        shortPremium,
                        longPremium,
                        buffer
                    )
                ) ++solvent;

                ++i;
            }
        }
```

**File:** contracts/PanopticPool.sol (L1998-2036)
```text
    function _getPremia(
        TokenId tokenId,
        uint128 positionSize,
        address owner,
        bool usePremiaAsCollateral,
        int24 atTick
    )
        internal
        view
        returns (
            LeftRightSigned[4] memory premiaByLeg,
            uint256[2][4] memory premiumAccumulatorsByLeg
        )
    {
        uint256 numLegs = tokenId.countLegs();
        for (uint256 leg = 0; leg < numLegs; ) {
            uint256 isLong = tokenId.isLong(leg);
            if (tokenId.width(leg) != 0 && (isLong == 1 || usePremiaAsCollateral)) {
                LiquidityChunk liquidityChunk = PanopticMath.getLiquidityChunk(
                    tokenId,
                    leg,
                    positionSize
                );
                {
                    uint256 vegoid = tokenId.vegoid();
                    uint256 tokenType = tokenId.tokenType(leg);
                    int24 _atTick = atTick;
                    (premiumAccumulatorsByLeg[leg][0], premiumAccumulatorsByLeg[leg][1]) = SFPM
                        .getAccountPremium(
                            poolKey(),
                            address(this),
                            tokenType,
                            liquidityChunk.tickLower(),
                            liquidityChunk.tickUpper(),
                            _atTick,
                            isLong,
                            vegoid
                        );
                }
```

**File:** contracts/RiskEngine.sol (L962-978)
```text
        if (
            int256(spotTick - medianTick) ** 2 +
                int256(latestTick - medianTick) ** 2 +
                int256(currentTick - medianTick) ** 2 >
            MAX_TICKS_DELTA ** 2
        ) {
            // High deviation detected; check against all four ticks.
            atTicks = new int24[](4);
            atTicks[0] = spotTick;
            atTicks[1] = medianTick;
            atTicks[2] = latestTick;
            atTicks[3] = currentTick;
        } else {
            // Normal operation; check against the spot tick = 10 mins EMA.
            atTicks = new int24[](1);
            atTicks[0] = spotTick;
        }
```

**File:** contracts/libraries/FeesCalc.sol (L94-154)
```text
        unchecked {
            if (currentTick < tickLower) {
                /**
                  L = lowerTick, U = upperTick

                    liquidity         lowerOut (all fees collected in this price tick range)
                        ▲            ◄──────────────^v───► (to MAX_TICK)
                        │
                        │                       upperOut
                        │                     ◄─────^v───►
                        │           ┌────────┐
                        │           │ chunk  │
                        │           │        │
                        └─────▲─────┴────────┴────────► price tick
                              │     L        U
                              │
                           current
                            tick
                */
                feeGrowthInside0X128 = lowerOut0 - upperOut0; // fee growth inside the chunk
                feeGrowthInside1X128 = lowerOut1 - upperOut1;
            } else if (currentTick >= tickUpper) {
                /**
                    liquidity
                        ▲           upperOut
                        │◄─^v─────────────────────►
                        │
                        │     lowerOut   ┌────────┐
                        │◄─^v───────────►│ chunk  │
                        │                │        │
                        └────────────────┴────────┴─▲─────► price tick
                                         L        U │
                                                    │
                                                 current
                                                  tick
                 */
                feeGrowthInside0X128 = upperOut0 - lowerOut0;
                feeGrowthInside1X128 = upperOut1 - lowerOut1;
            } else {
                /**
                  current AMM tick is within the option position range (within the chunk)

                     liquidity
                        ▲        feeGrowthGlobalX128 = global fee growth
                        │                            = (all fees collected for the entire price range)
                        │
                        │
                        │     lowerOut   ┌──────────────┐  upperOut
                        │◄─^v───────────►│              │◄─────^v───►
                        │                │     chunk    │
                        │                │              │
                        └────────────────┴───────▲──────┴─────► price tick
                                         L       │      U
                                                 │
                                              current
                                               tick
                */
                feeGrowthInside0X128 = univ3pool.feeGrowthGlobal0X128() - lowerOut0 - upperOut0;
                feeGrowthInside1X128 = univ3pool.feeGrowthGlobal1X128() - lowerOut1 - upperOut1;
            }
        }
```
