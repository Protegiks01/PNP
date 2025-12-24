# Audit Report

## Title 
Fee Bypass Through Zero Realized Premium on Multi-Leg Position Burns

## Summary
Users can exploit the commission fee structure to avoid burn fees entirely by structuring multi-leg positions where long and short legs have balanced premiums, resulting in zero net realized premium. This allows attackers to pay only mint fees while bypassing burn fees, reducing total commission by up to 33% or more compared to separate positions.

## Finding Description

The Panoptic Protocol charges commission fees at two points: position mint and position burn. The fee structure is defined in `CollateralTracker.sol`:

**At Mint** [1](#0-0) :
- Commission is based on total notional: `commission = shortAmount + longAmount`
- Fee charged: `commissionFee = commission * notionalFee / 10_000`

**At Burn** [2](#0-1) :
- Only charged if `realizedPremium != 0`
- Fee is the minimum of two calculations:
  - Premium-based: `|realizedPremium| * premiumFee / 10_000`
  - Notional-based: `notional * 10 * notionalFee / 10_000`

The critical vulnerability exists at the burn fee check. If `realizedPremium == 0`, the entire commission calculation block is skipped, resulting in **zero burn fees**.

The `realizedPremia` value is calculated in `PanopticPool._updateSettlementPostBurn()` [3](#0-2)  by aggregating premium across all position legs:
- Long legs contribute their premium (negative value - paying premium) at line 1185
- Short legs contribute available premium (positive value - collecting premium) at lines 1228-1230

**Exploitation Path:**
1. Attacker creates a multi-leg position (TokenId supports up to 4 legs [4](#0-3) )
2. Position includes both long legs (paying premium) and short legs (collecting premium)
3. Legs are sized such that premium paid ≈ premium collected
4. Net `realizedPremium` ≈ 0 when position is burned
5. Burn fee calculation is skipped entirely
6. Attacker pays only mint fee, avoiding burn fee

**Example with concrete numbers:**
- Position with 2 legs: Long 1000 notional + Short 1000 notional
- Assume `notionalFee = premiumFee = 100 bps (1%)`
- After holding period, Long pays 200 premium, Short collects 200 premium
- Net `realizedPremium = 0`

**Separate Positions (Expected):**
- Position 1 (Long): Mint fee = 10, Burn fee = min(2, 100) = 2, Total = 12
- Position 2 (Short): Mint fee = 10, Burn fee = min(2, 100) = 2, Total = 12
- **Combined Total: 24 tokens**

**Multi-Leg Position (Exploit):**
- Mint fee = 20 (for 2000 total notional)
- Burn fee = 0 (because realizedPremium = 0)
- **Total: 20 tokens**

**Savings: 4 tokens (16.7% reduction)**

For positions with higher premium accumulation (50% of notional), savings increase to **33% or more**.

This breaks **Invariant 14 (Premium Accounting)** by allowing users to structure positions that minimize protocol fee collection through strategic leg balancing, and violates the intended commission fee structure.

## Impact Explanation

**Impact: HIGH**

This vulnerability causes direct economic loss to the protocol:

1. **Revenue Loss**: Protocol loses burn fee revenue on all multi-leg positions where users balance premiums. For large positions or long holding periods, this represents significant lost fees (16-33%+ of expected total commission).

2. **Perverse Incentive**: Creates systematic incentive for all users to structure positions as multi-leg spreads rather than separate positions, amplifying the revenue loss across the entire protocol.

3. **Fee Structure Inconsistency**: Users pay different total fees based on position structure rather than economic exposure, violating fairness principles.

4. **Scalability**: The exploit scales with position size and holding period. Larger positions and longer durations result in proportionally greater savings for attackers.

The 10x multiplier on notional fee at burn [5](#0-4)  suggests the protocol intends to collect meaningful burn fees as a cap, making the zero-fee bypass particularly severe.

## Likelihood Explanation

**Likelihood: HIGH**

1. **No Prerequisites**: Any user can create multi-leg positions without special permissions
2. **Easy Execution**: TokenId encoding naturally supports multi-leg positions (up to 4 legs)
3. **Predictable**: Users can calculate expected premiums and structure positions accordingly
4. **No Detection**: The exploit uses legitimate protocol features (multi-leg positions) without triggering any warnings
5. **Economic Incentive**: Clear financial benefit (16-33%+ fee reduction) motivates exploitation
6. **Common Strategy**: Spread positions (balanced long/short legs) are standard in options trading, making this natural user behavior

The only friction is that users must balance leg sizing to target zero net premium, but this is easily achievable with basic calculation or trial-and-error.

## Recommendation

**Fix 1: Remove the zero-premium check**

Modify `CollateralTracker.settleBurn()` to always calculate and charge burn fees, even when `realizedPremium == 0`:

```solidity
function settleBurn(
    address optionOwner,
    int128 longAmount,
    int128 shortAmount,
    int128 ammDeltaAmount,
    int128 realizedPremium,
    RiskParameters riskParameters
) external onlyPanopticPool returns (int128) {
    (, int128 tokenPaid, uint256 _totalAssets, uint256 _totalSupply) = _updateBalancesAndSettle(
        optionOwner,
        false,
        longAmount,
        shortAmount,
        ammDeltaAmount,
        realizedPremium
    );

    // REMOVE: if (realizedPremium != 0) {
    uint128 commissionFee;
    {
        uint128 commissionP;
        unchecked {
            commissionP = realizedPremium > 0
                ? uint128(realizedPremium)
                : uint128(-realizedPremium);
        }
        uint128 commissionFeeP = Math
            .mulDivRoundingUp(commissionP, riskParameters.premiumFee(), DECIMALS)
            .toUint128();
        uint128 commissionN = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
        uint128 commissionFeeN;
        unchecked {
            commissionFeeN = Math
                .mulDivRoundingUp(commissionN, 10 * riskParameters.notionalFee(), DECIMALS)
                .toUint128();
        }
        commissionFee = Math.min(commissionFeeP, commissionFeeN).toUint128();
    }

    uint256 sharesToBurn = Math.mulDivRoundingUp(commissionFee, _totalSupply, _totalAssets);
    
    // ... rest of fee collection logic
    // }  // REMOVE: closing brace

    return tokenPaid;
}
```

**Fix 2: Alternative - Apply minimum burn fee**

Set a minimum burn fee equal to the mint fee to ensure consistent total commission:

```solidity
// After calculating commissionFee
uint128 minCommissionFee = Math
    .mulDivRoundingUp(commissionN, riskParameters.notionalFee(), DECIMALS)
    .toUint128();
commissionFee = Math.max(commissionFee, minCommissionFee).toUint128();
```

**Recommended Approach**: Fix 1 is preferred as it aligns with the comment "compute the minimum of the notionalFee and the premiumFee" and ensures fees are always charged based on the intended calculation. When `realizedPremium = 0`, the minimum would be 0 from the premium calculation, so the notional-based cap (10x multiplier) would be used.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {TokenId} from "@types/TokenId.sol";
import {RiskParameters} from "@types/RiskParameters.sol";

contract FeeBypassExploit is Test {
    CollateralTracker collateralTracker;
    PanopticPool panopticPool;
    
    function setUp() public {
        // Initialize protocol contracts
        // ... deployment code ...
    }
    
    function testFeeBypassThroughBalancedLegs() public {
        address attacker = address(0x1337);
        
        // Scenario A: Two separate positions
        // Position 1: Long with notional 1000
        TokenId longPosition = /* construct long position TokenId */;
        uint128 positionSize1 = 1000;
        
        // Mint position 1 - pays mint fee
        vm.prank(attacker);
        panopticPool.mintOptions(longPosition, positionSize1, type(uint64).max, 0, 0);
        
        // Position 2: Short with notional 1000  
        TokenId shortPosition = /* construct short position TokenId */;
        uint128 positionSize2 = 1000;
        
        // Mint position 2 - pays mint fee
        vm.prank(attacker);
        panopticPool.mintOptions(shortPosition, positionSize2, type(uint64).max, 0, 0);
        
        // Time passes, premium accumulates
        vm.warp(block.timestamp + 1 days);
        
        // Burn both positions - each pays burn fee based on realized premium
        vm.prank(attacker);
        panopticPool.burnOptions(longPosition, type(int24).min, type(int24).max);
        
        vm.prank(attacker);
        panopticPool.burnOptions(shortPosition, type(int24).min, type(int24).max);
        
        uint256 totalFeesScenarioA = /* calculate total fees paid */;
        
        // Scenario B: Single multi-leg position with balanced premium
        // Position with 2 legs: Long 1000 + Short 1000
        TokenId multiLegPosition = /* construct 2-leg position with long and short */;
        uint128 multiLegSize = 1000; // size applies to both legs
        
        // Mint multi-leg position - pays mint fee on total notional (2000)
        vm.prank(attacker);
        panopticPool.mintOptions(multiLegPosition, multiLegSize, type(uint64).max, 0, 0);
        
        // Time passes, premiums balance out
        vm.warp(block.timestamp + 1 days);
        
        // Burn position - realized premium ≈ 0, so NO burn fee charged
        vm.prank(attacker);
        panopticPool.burnOptions(multiLegPosition, type(int24).min, type(int24).max);
        
        uint256 totalFeesScenarioB = /* calculate total fees paid */;
        
        // Assert that Scenario B paid less total fees
        assertLt(totalFeesScenarioB, totalFeesScenarioA, "Multi-leg position should pay less fees");
        
        // Calculate savings
        uint256 savings = totalFeesScenarioA - totalFeesScenarioB;
        uint256 savingsPercent = (savings * 100) / totalFeesScenarioA;
        
        // Verify significant savings (expected 16-33%)
        assertGt(savingsPercent, 15, "Savings should be at least 15%");
        
        console.log("Total fees (separate positions):", totalFeesScenarioA);
        console.log("Total fees (multi-leg position):", totalFeesScenarioB);
        console.log("Savings:", savings);
        console.log("Savings percentage:", savingsPercent);
    }
}
```

**Note**: The full PoC would require complete test harness setup with deployed contracts, funded pools, and proper TokenId construction. The above demonstrates the attack logic - the key assertion is that `totalFeesScenarioB < totalFeesScenarioA` due to the zero burn fee when `realizedPremium == 0`.

### Citations

**File:** contracts/CollateralTracker.sol (L1552-1556)
```text
        {
            uint128 commission = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
            uint128 commissionFee = Math
                .mulDivRoundingUp(commission, riskParameters.notionalFee(), DECIMALS)
                .toUint128();
```

**File:** contracts/CollateralTracker.sol (L1612-1632)
```text
        if (realizedPremium != 0) {
            uint128 commissionFee;
            // compute the minimum of the notionalFee and the premiumFee
            {
                uint128 commissionP;
                unchecked {
                    commissionP = realizedPremium > 0
                        ? uint128(realizedPremium)
                        : uint128(-realizedPremium);
                }
                uint128 commissionFeeP = Math
                    .mulDivRoundingUp(commissionP, riskParameters.premiumFee(), DECIMALS)
                    .toUint128();
                uint128 commissionN = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
                uint128 commissionFeeN;
                unchecked {
                    commissionFeeN = Math
                        .mulDivRoundingUp(commissionN, 10 * riskParameters.notionalFee(), DECIMALS)
                        .toUint128();
                }
                commissionFee = Math.min(commissionFeeP, commissionFeeN).toUint128();
```

**File:** contracts/PanopticPool.sol (L1163-1230)
```text
        for (uint256 leg = 0; leg < tokenId.countLegs(); ) {
            if (tokenId.width(leg) != 0) {
                LeftRightSigned legPremia = premiaByLeg[leg];
                bytes32 chunkKey = PanopticMath.getChunkKey(tokenId, leg);

                // collected from Uniswap
                LeftRightUnsigned settledTokens = s_settledTokens[chunkKey].add(
                    collectedByLeg[leg]
                );

                // (will be) paid by long legs
                if (tokenId.isLong(leg) == 1) {
                    if (commitLongSettledAndKeepOpen.rightSlot() != 0)
                        settledTokens = LeftRightUnsigned.wrap(
                            uint256(
                                LeftRightSigned.unwrap(
                                    LeftRightSigned
                                        .wrap(int256(LeftRightUnsigned.unwrap(settledTokens)))
                                        .sub(legPremia)
                                )
                            )
                        );
                    realizedPremia = realizedPremia.add(legPremia);
                } else {
                    if (commitLongSettledAndKeepOpen.leftSlot() == 0 || msg.sender == owner) {
                        uint256 positionLiquidity;
                        uint256 totalLiquidity;
                        {
                            LiquidityChunk liquidityChunk = PanopticMath.getLiquidityChunk(
                                tokenId,
                                leg,
                                positionSize
                            );
                            positionLiquidity = liquidityChunk.liquidity();

                            // if position is short, ensure that removed liquidity does not deplete strike beyond MAX_SPREAD when closed
                            // new totalLiquidity (total sold) = removedLiquidity + netLiquidity (T - R)
                            totalLiquidity = _checkLiquiditySpread(
                                tokenId,
                                leg,
                                riskParameters.maxSpread()
                            );
                        }
                        // T (totalLiquidity is (T - R) after burning)
                        uint256 totalLiquidityBefore;
                        unchecked {
                            // cannot overflow because total liquidity is less than uint128
                            totalLiquidityBefore = commitLongSettledAndKeepOpen.leftSlot() == 0
                                ? totalLiquidity + positionLiquidity
                                : totalLiquidity;
                        }
                        LeftRightUnsigned grossPremiumLast = s_grossPremiumLast[chunkKey];

                        LeftRightUnsigned availablePremium = _getAvailablePremium(
                            totalLiquidityBefore,
                            settledTokens,
                            grossPremiumLast,
                            LeftRightUnsigned.wrap(uint256(LeftRightSigned.unwrap(legPremia))),
                            premiumAccumulatorsByLeg[leg]
                        );

                        // subtract settled tokens sent to seller
                        settledTokens = settledTokens.sub(availablePremium);

                        // add available premium to amount that should be settled
                        realizedPremia = realizedPremia.add(
                            LeftRightSigned.wrap(int256(LeftRightUnsigned.unwrap(availablePremium)))
                        );
```

**File:** contracts/types/TokenId.sol (L27-35)
```text
// ===== 4 times (one for each leg) ==============================================================
// (3) asset             1bit      0bits      : Specifies the asset (0: token0, 1: token1)
// (4) optionRatio       7bits     1bits      : number of contracts per leg
// (5) isLong            1bit      8bits      : long==1 means liquidity is removed, long==0 -> liquidity is added
// (6) tokenType         1bit      9bits      : put/call: which token is moved when deployed (0 -> token0, 1 -> token1)
// (7) riskPartner       2bits     10bits     : normally its own index. Partner in defined risk position otherwise
// (8) strike           24bits     12bits     : strike price; defined as (tickUpper + tickLower) / 2
// (9) width            12bits     36bits     : width; defined as (tickUpper - tickLower) / tickSpacing
// Total                48bits                : Each leg takes up this many bits
```
