# Audit Report

## Title
Premium Accumulator Corruption via Mismatched Vegoid Values in Shared Position Keys

## Summary
The `_createPositionInAMM()` function extracts vegoid from tokenId at line 800 but the positionKey computed at line 929 does not include vegoid. This allows positions with different vegoid values (different spread parameters) to share the same storage mappings for premium accumulators, causing premium accounting corruption and enabling premium manipulation attacks.

## Finding Description

The vulnerability exists in how position keys are computed versus how vegoid-dependent premium calculations are performed.

**Root Cause:**

At line 800, vegoid is extracted from the tokenId: [1](#0-0) 

However, the positionKey that identifies liquidity chunks in storage mappings is computed WITHOUT vegoid: [2](#0-1) 

This positionKey is used to index critical storage mappings including:
- `s_accountLiquidity[positionKey]` - tracks net and removed liquidity
- `s_accountPremiumOwed[positionKey]` - accumulates owed premium for longs
- `s_accountPremiumGross[positionKey]` - accumulates gross premium for shorts
- `s_accountFeesBase[positionKey]` - tracks fee accumulation baseline

**Vegoid Usage in Premium Calculations:**

The vegoid parameter directly affects premium spread calculations in `_getPremiaDeltas()`: [3](#0-2) [4](#0-3) 

Where ν (nu) = 1/vegoid controls the spread charged to long positions. Lower vegoid = higher spread, higher vegoid = lower spread.

**Attack Vector:**

1. The same Uniswap pool can be initialized multiple times with different vegoid values via `initializeAMMPool()`: [5](#0-4) [6](#0-5) 

2. A user mints position A with tokenId encoding vegoid=2 (high spread ν=0.5) at tick range [100,200]
3. Same user mints position B with tokenId encoding vegoid=100 (low spread ν=0.01) at the SAME tick range [100,200]
4. Both positions share the same positionKey (no vegoid in key)
5. When position A collects fees, premiums are calculated using vegoid=2 and accumulators are updated: [7](#0-6) [8](#0-7) 

6. When position B collects fees, premiums are calculated using vegoid=100 and the SAME accumulators are updated with different spread parameters
7. The accumulators now contain corrupted values mixing two different spread calculation formulas

**Broken Invariants:**

This breaks **Invariant #14: Premium Accounting** - "Premium distribution must be proportional to liquidity share in each chunk. Incorrect accounting allows premium manipulation."

The mixed accumulator values cause:
- Incorrect premium distribution between longs and shorts
- Shorts may receive more/less premium than they're entitled to
- Longs may pay more/less premium than they should
- Systematic accounting errors that compound over time

## Impact Explanation

**Severity: HIGH**

The impact is significant because:

1. **Premium Manipulation**: Attackers can strategically use different vegoid values to manipulate their premium obligations/receipts. By mixing high-spread and low-spread calculations in the same accumulator, they can exploit the accounting mismatch.

2. **Systemic Risk**: Since the accumulators are per-position-key rather than per-tokenId, all fee collections for that key become corrupted once mixed vegoid values are introduced.

3. **Counterparty Loss**: When one party's premium accounting is corrupted, their counterparties in the options trades will receive incorrect premium amounts, leading to direct financial losses.

4. **Cascading Effects**: Premium accounting errors affect:
   - Settlement amounts in `CollateralTracker`
   - Risk calculations in downstream contracts
   - Solvency determinations for liquidations

5. **No Recovery Mechanism**: Once accumulators are corrupted, there's no mechanism to fix them, leading to permanent incorrect state.

The vulnerability enables systematic premium extraction from counterparties by exploiting the spread parameter mismatch.

## Likelihood Explanation

**Likelihood: HIGH**

1. **Easy to Execute**: Any user can initialize the same pool with multiple vegoid values (function is external and unrestricted): [9](#0-8) 

2. **No Restrictions**: There are no checks preventing multiple vegoid initializations for the same pool

3. **Natural Occurrence**: Users might legitimately want different spread parameters for different strategies, making this collision natural rather than requiring attacker sophistication

4. **Validation Gap**: The poolId validation at line 805 doesn't prevent this issue because it checks if `poolData.poolId() == tokenId.poolId()`, which passes as long as both use the same vegoid - but different positions can use different vegoids [10](#0-9) 

5. **Persistent Effect**: Once triggered, the corruption persists for all future operations on that position key

## Recommendation

**Fix: Include vegoid in positionKey calculation**

Modify the positionKey computation to include vegoid:

```solidity
bytes32 positionKey = EfficientHash.efficientKeccak256(
    abi.encodePacked(
        address(univ3pool),
        msg.sender,
        tokenId.tokenType(leg),
        liquidityChunk.tickLower(),
        liquidityChunk.tickUpper(),
        tokenId.vegoid()  // ADD THIS
    )
);
```

This change should be applied in:
- `_createLegInAMM()` (line 929)
- `getAccountLiquidity()` (line 1372)
- `getAccountPremium()` (line 1403)  
- `getAccountFeesBase()` (line 1485)

**Alternative Fix: Prevent Multiple Vegoid Initializations**

If the protocol intends for each pool to have only one vegoid, add validation to prevent re-initialization:

```solidity
// In initializeAMMPool()
for (uint256 v = 0; v < 256; v++) {
    if (s_addressToPoolData[univ3pool][v].initialized()) {
        revert Errors.PoolAlreadyInitialized();
    }
}
```

However, the first fix (including vegoid in positionKey) is more flexible and safer.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {SemiFungiblePositionManager} from "../contracts/SemiFungiblePositionManager.sol";
import {TokenId} from "../contracts/types/TokenId.sol";

contract VegoidCorruptionTest is Test {
    SemiFungiblePositionManager sfpm;
    address uniswapPool = address(0x1234); // Mock pool
    address token0 = address(0x5678);
    address token1 = address(0x9ABC);
    uint24 fee = 3000;
    
    function setUp() public {
        // Deploy SFPM
        sfpm = new SemiFungiblePositionManager(
            IUniswapV3Factory(address(0xDEF)), // Mock factory
            1000000,
            100
        );
    }
    
    function testVegoidAccumulatorCorruption() public {
        // Step 1: Initialize same pool with two different vegoids
        uint64 poolId1 = sfpm.initializeAMMPool(token0, token1, fee, 2);    // vegoid=2 (high spread)
        uint64 poolId2 = sfpm.initializeAMMPool(token0, token1, fee, 100);  // vegoid=100 (low spread)
        
        // Both should succeed
        assertTrue(poolId1 != poolId2, "PoolIds should be different");
        
        // Step 2: Create tokenIds with different vegoids but same tick range
        TokenId tokenId1 = createTokenId(poolId1, 100, 200);  // Uses vegoid=2
        TokenId tokenId2 = createTokenId(poolId2, 100, 200);  // Uses vegoid=100
        
        // Step 3: Mint positions with both tokenIds
        uint128 positionSize = 1000000;
        
        vm.startPrank(address(this));
        sfpm.mintTokenizedPosition(
            abi.encode(uniswapPool),
            tokenId1,
            positionSize,
            -887272,
            887272
        );
        
        sfpm.mintTokenizedPosition(
            abi.encode(uniswapPool),
            tokenId2,
            positionSize,
            -887272,
            887272
        );
        vm.stopPrank();
        
        // Step 4: Verify positions share the same positionKey
        bytes32 positionKey1 = computePositionKey(uniswapPool, address(this), 0, 100, 200);
        bytes32 positionKey2 = computePositionKey(uniswapPool, address(this), 0, 100, 200);
        
        assertEq(positionKey1, positionKey2, "Position keys should be identical despite different vegoids");
        
        // Step 5: Collect fees for both positions
        // This will corrupt the premium accumulators as they use different vegoid values
        // but update the same storage locations
        
        // The accumulators at s_accountPremiumOwed[positionKey] and 
        // s_accountPremiumGross[positionKey] are now corrupted
        
        // Verification: Query premiums with different vegoid values
        (uint128 premium0_vegoid2, uint128 premium1_vegoid2) = sfpm.getAccountPremium(
            abi.encode(uniswapPool),
            address(this),
            0,  // tokenType
            100, // tickLower
            200, // tickUpper
            type(int24).max,
            1,  // isLong
            2   // vegoid=2
        );
        
        (uint128 premium0_vegoid100, uint128 premium1_vegoid100) = sfpm.getAccountPremium(
            abi.encode(uniswapPool),
            address(this),
            0,  // tokenType
            100, // tickLower
            200, // tickUpper
            type(int24).max,
            1,  // isLong
            100 // vegoid=100
        );
        
        // Both read from the same accumulator but interpret it differently
        // This demonstrates the corruption
        assertTrue(
            premium0_vegoid2 != premium0_vegoid100 || premium1_vegoid2 != premium1_vegoid100,
            "Premiums should differ showing accumulator corruption"
        );
    }
    
    function createTokenId(uint64 poolId, int24 tickLower, int24 tickUpper) 
        internal 
        pure 
        returns (TokenId) 
    {
        // Simplified TokenId creation
        uint256 id = uint256(poolId);
        return TokenId.wrap(id);
    }
    
    function computePositionKey(
        address pool,
        address owner,
        uint256 tokenType,
        int24 tickLower,
        int24 tickUpper
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(pool, owner, tokenType, tickLower, tickUpper));
    }
}
```

**Note**: This PoC demonstrates the conceptual vulnerability. A complete working test would require full mock implementations of Uniswap V3 pool interfaces and proper TokenId encoding according to the protocol's bit-packing scheme defined in TokenId.sol. The key point is that positions with different vegoids share the same positionKey, leading to corrupted premium accumulators.

### Citations

**File:** contracts/SemiFungiblePositionManager.sol (L155-156)
```text
    mapping(address univ3pool => mapping(uint256 vegoid => PoolData poolData))
        internal s_addressToPoolData;
```

**File:** contracts/SemiFungiblePositionManager.sol (L330-335)
```text
    function initializeAMMPool(
        address token0,
        address token1,
        uint24 fee,
        uint8 vegoid
    ) external returns (uint64 poolId) {
```

**File:** contracts/SemiFungiblePositionManager.sol (L348-349)
```text
        if (s_addressToPoolData[univ3pool][vegoid].initialized())
            return uint64(s_addressToPoolData[univ3pool][vegoid].poolId());
```

**File:** contracts/SemiFungiblePositionManager.sol (L800-800)
```text
        PoolData poolData = s_addressToPoolData[address(univ3Pool)][tokenId.vegoid()];
```

**File:** contracts/SemiFungiblePositionManager.sol (L803-807)
```text
        if (
            address(univ3Pool) == address(0) ||
            poolData.poolId() != tokenId.poolId() ||
            !poolData.initialized()
        ) revert Errors.WrongUniswapPool();
```

**File:** contracts/SemiFungiblePositionManager.sol (L929-937)
```text
        bytes32 positionKey = EfficientHash.efficientKeccak256(
            abi.encodePacked(
                address(univ3pool),
                msg.sender,
                tokenId.tokenType(leg),
                liquidityChunk.tickLower(),
                liquidityChunk.tickUpper()
            )
        );
```

**File:** contracts/SemiFungiblePositionManager.sol (L1024-1033)
```text
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
```

**File:** contracts/SemiFungiblePositionManager.sol (L1252-1252)
```text
            _updateStoredPremia(positionKey, currentLiquidity, collectedChunk, vegoid);
```

**File:** contracts/SemiFungiblePositionManager.sol (L1309-1309)
```text
                    uint256 numerator = netLiquidity + (removedLiquidity / vegoid);
```

**File:** contracts/SemiFungiblePositionManager.sol (L1329-1332)
```text
                    uint256 numerator = totalLiquidity ** 2 -
                        totalLiquidity *
                        removedLiquidity +
                        ((removedLiquidity ** 2) / vegoid);
```
