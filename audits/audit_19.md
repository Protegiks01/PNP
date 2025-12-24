# Audit Report

## Title 
Premium Accumulator Underflow in _getAvailablePremium() When usePremiaAsCollateral=false

## Summary
When `usePremiaAsCollateral=false` is passed to the `dispatch()` function, short position premium accumulators are not populated in `_getPremia()`, remaining at their default value of 0. This causes an integer underflow in `_getAvailablePremium()` when computing `premiumAccumulators - grossPremiumLast`, resulting in massively inflated available premium values that break solvency calculations.

## Finding Description
The vulnerability occurs through the following execution path:

1. A user calls `dispatch()` with `usePremiaAsCollateral=false` [1](#0-0) 

2. This parameter flows through `_validateSolvency()` → `_checkSolvencyAtTicks()` → `_calculateAccumulatedPremia()` → `_getPremia()` [2](#0-1) 

3. In `_getPremia()`, the condition at line 2015 only populates `premiumAccumulatorsByLeg` when `isLong == 1 OR usePremiaAsCollateral == true` [3](#0-2) 

4. For short positions (`isLong == 0`) with `usePremiaAsCollateral == false`, the condition evaluates to false, so `premiumAccumulatorsByLeg[leg]` is never populated and remains `[0, 0]`

5. Back in `_calculateAccumulatedPremia()`, for short legs with `!includePendingPremium`, `_getAvailablePremium()` is called with the unpopulated accumulator array [4](#0-3) 

6. Inside `_getAvailablePremium()`, within an `unchecked` block, the code computes `premiumAccumulators[0] - grossPremiumLast.rightSlot()` [5](#0-4) 

7. When `premiumAccumulators[0] = 0` but `grossPremiumLast.rightSlot() > 0` (which happens after any premium has accumulated in the chunk), the subtraction underflows to `type(uint256).max - grossPremiumLast + 1`, which is then multiplied by `totalLiquidity` and divided by `2^64`

8. This produces a massively inflated `accumulated0` value, causing `_getAvailablePremium()` to return incorrect premium amounts

This breaks **Invariant #14** (Premium Accounting - premium distribution must be proportional to liquidity share) and **Invariant #1** (Solvency Maintenance - accounts must satisfy collateral requirements), as the inflated premium values feed into solvency calculations.

## Impact Explanation
**HIGH Severity** - This vulnerability has multiple critical impacts:

1. **Solvency Check Bypass**: Users can pass solvency checks when they should be insolvent by making the system believe they have massive available premium as collateral

2. **Incorrect Collateral Calculations**: The inflated premium values distort the true collateral position of accounts, potentially allowing undercollateralized positions

3. **Liquidation Evasion**: Accounts that should be liquidatable may appear solvent due to the inflated premium calculations

4. **Systemic Risk**: If multiple users exploit this, it could lead to widespread undercollateralization in the protocol

The vulnerability is categorized as HIGH because it enables systemic undercollateralization risks and can allow users to maintain positions that should be liquidated, though it doesn't directly cause immediate fund theft.

## Likelihood Explanation
**HIGH Likelihood** - The vulnerability is highly likely to occur because:

1. **No Special Privileges Required**: Any user can call `dispatch()` with `usePremiaAsCollateral=false` - it's a user-controlled parameter

2. **Natural Usage Pattern**: Users might legitimately pass `usePremiaAsCollateral=false` when they only want to check long premium for solvency calculations, not realizing it breaks short premium calculations

3. **Silent Failure**: The underflow occurs in an `unchecked` block, so there's no revert - the function silently returns incorrect values

4. **Common Scenario**: Any position with accumulated premium (`grossPremiumLast > 0`) will trigger the underflow, which is the normal state after a chunk has been active

5. **Immediate Exploitation**: An attacker can immediately exploit this to bypass solvency checks on every transaction

## Recommendation
Modify `_getPremia()` to always populate `premiumAccumulatorsByLeg` for all non-zero width legs when the function will be used in `_getAvailablePremium()` context. The condition should be:

```solidity
if (tokenId.width(leg) != 0 && (isLong == 1 || usePremiaAsCollateral)) {
```

Changed to:

```solidity
if (tokenId.width(leg) != 0) {
```

This ensures that premium accumulators are always populated for all legs, regardless of the `usePremiaAsCollateral` flag. The flag should only affect how the premium values are used in collateral calculations, not whether they are computed at all.

Alternatively, add a check in `_calculateAccumulatedPremia()` before calling `_getAvailablePremium()` to ensure the accumulators have been populated:

```solidity
if (!includePendingPremium) {
    // Only call _getAvailablePremium if accumulators were populated
    if (premiumAccumulatorsByLeg[leg][0] != 0 || premiumAccumulatorsByLeg[leg][1] != 0 || 
        s_grossPremiumLast[chunkKey].rightSlot() == 0) {
        bytes32 chunkKey = PanopticMath.getChunkKey(tokenId, leg);
        // ... rest of the code
    }
}
```

## Proof of Concept
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/PanopticPool.sol";
import "../contracts/SemiFungiblePositionManager.sol";

contract PremiumUnderflowTest is Test {
    PanopticPool pool;
    
    function testPremiumAccumulatorUnderflow() public {
        // Setup: Deploy pool with initial state
        // Assume a chunk has accumulated some premium, so grossPremiumLast > 0
        
        // Step 1: User creates a short position
        TokenId tokenId = TokenId.wrap(0);
        // Configure tokenId with a short leg (isLong=0)
        tokenId = tokenId.addWidth(0, 100); // Add width to leg 0
        tokenId = tokenId.addLeg(0, 0, 0, 0, 0, 0, 0, 100); // Short position
        
        TokenId[] memory positionList = new TokenId[](1);
        positionList[0] = tokenId;
        
        TokenId[] memory finalPositionList = new TokenId[](1);
        finalPositionList[0] = tokenId;
        
        uint128[] memory sizes = new uint128[](1);
        sizes[0] = 1000;
        
        int24[3][] memory tickLimits = new int24[3][](1);
        
        // Step 2: Call dispatch with usePremiaAsCollateral = false
        // This will trigger the vulnerability
        vm.expectRevert(); // Or check for incorrect solvency calculation
        pool.dispatch(
            positionList,
            finalPositionList,
            sizes,
            tickLimits,
            false, // usePremiaAsCollateral = false - triggers vulnerability
            0
        );
        
        // Step 3: Verify that _getAvailablePremium was called with premiumAccumulators = [0,0]
        // but grossPremiumLast > 0, causing underflow
        
        // Expected behavior: Should revert or handle gracefully
        // Actual behavior: Underflow occurs, massive premium value returned
        // This allows user to pass solvency checks when they shouldn't
    }
    
    function testCorrectBehaviorWithUsePremiaAsCollateralTrue() public {
        // Same setup as above
        
        // Call dispatch with usePremiaAsCollateral = true
        // This should work correctly as accumulators are populated for all legs
        pool.dispatch(
            positionList,
            finalPositionList,
            sizes,
            tickLimits,
            true, // usePremiaAsCollateral = true - works correctly
            0
        );
        
        // Verify correct premium calculations and solvency checks
    }
}
```

**Note**: The PoC above is a conceptual demonstration. A full working test would require proper setup of the PanopticPool, SemiFungiblePositionManager, Uniswap pool, and initial state with accumulated premium. The key insight is that calling `dispatch()` with `usePremiaAsCollateral=false` when there are short positions with `grossPremiumLast > 0` will trigger the underflow in `_getAvailablePremium()`.

### Citations

**File:** contracts/PanopticPool.sol (L487-496)
```text
            (
                LeftRightSigned[4] memory premiaByLeg,
                uint256[2][4] memory premiumAccumulatorsByLeg
            ) = _getPremia(
                    tokenId,
                    balances[k].positionSize(),
                    c_user,
                    usePremiaAsCollateral,
                    atTick
                );
```

**File:** contracts/PanopticPool.sol (L500-516)
```text
                if (tokenId.width(leg) != 0) {
                    if (tokenId.isLong(leg) == 0) {
                        if (!includePendingPremium) {
                            bytes32 chunkKey = PanopticMath.getChunkKey(tokenId, leg);

                            (uint256 totalLiquidity, , ) = _getLiquidities(tokenId, leg);
                            shortPremium = shortPremium.add(
                                _getAvailablePremium(
                                    totalLiquidity,
                                    s_settledTokens[chunkKey],
                                    s_grossPremiumLast[chunkKey],
                                    LeftRightUnsigned.wrap(
                                        uint256(LeftRightSigned.unwrap(premiaByLeg[leg]))
                                    ),
                                    premiumAccumulatorsByLeg[leg]
                                )
                            );
```

**File:** contracts/PanopticPool.sol (L572-579)
```text
    function dispatch(
        TokenId[] calldata positionIdList,
        TokenId[] calldata finalPositionIdList,
        uint128[] calldata positionSizes,
        int24[3][] calldata tickAndSpreadLimits,
        bool usePremiaAsCollateral,
        uint256 builderCode
    ) external {
```

**File:** contracts/PanopticPool.sol (L2014-2035)
```text
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
```

**File:** contracts/PanopticPool.sol (L2091-2098)
```text
        unchecked {
            // long premium only accumulates as it is settled, so compute the ratio
            // of total settled tokens in a chunk to total premium owed to sellers and multiply
            // cap the ratio at 1 (it can be greater than one if some seller forfeits enough premium)
            uint256 accumulated0 = ((premiumAccumulators[0] - grossPremiumLast.rightSlot()) *
                totalLiquidity) / 2 ** 64;
            uint256 accumulated1 = ((premiumAccumulators[1] - grossPremiumLast.leftSlot()) *
                totalLiquidity) / 2 ** 64;
```
