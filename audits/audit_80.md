# Audit Report

## Title 
Commission Fee Bypass via Incomplete Fee Split When Using Builder Codes

## Summary
Users can avoid paying 10% of commission fees by providing any non-zero `builderCode` when minting or burning positions. The fee collection logic in `settleMint()` and `settleBurn()` only transfers 90% of the calculated commission when a builder code is present (65% to protocol + 25% to builder), leaving 10% with the user instead of collecting 100% as intended.

## Finding Description

The vulnerability exists in the commission payment logic within `CollateralTracker.settleMint()` and `CollateralTracker.settleBurn()`. When users mint or burn positions through `PanopticPool.dispatch()`, they can provide an arbitrary `builderCode` parameter that determines fee distribution. [1](#0-0) 

This `builderCode` is passed to `getRiskParameters()` which computes a `feeRecipient` address: [2](#0-1) 

The critical flaw is in how commission is collected. When `feeRecipient == 0` (no builder code), 100% of commission shares are burned from the user: [3](#0-2) 

However, when `feeRecipient != 0` (builder code provided), only two partial transfers occur: [4](#0-3) 

With the protocol split constants defined as: [5](#0-4) 

The math reveals the issue:
- First transfer: `sharesToBurn * 6500 / 10000 = 65%`
- Second transfer: `sharesToBurn * 2500 / 10000 = 25%`
- **Total collected: 90%**
- **Remaining with user: 10%**

The same vulnerability exists in `settleBurn()`: [6](#0-5) 

**Exploitation Path:**
1. Attacker calls `dispatch()` with `builderCode = 1` (or any non-zero value)
2. `getRiskParameters(1)` computes a CREATE2 address as `feeRecipient` 
3. Since `feeRecipient != 0`, the else branch executes in `settleMint()`/`settleBurn()`
4. Only 90% of commission shares are transferred from attacker
5. Attacker retains 10% of shares that should have been paid as commission

This breaks the protocol's commission collection invariant: users should pay the full `COMMISSION_FEE` rate, not 90% of it.

## Impact Explanation

**Financial Impact:**
- Direct loss of 10% of commission revenue on all position mints/burns using builder codes
- Scales with protocol trading volume and position sizes
- Affects both CollateralTracker vaults (token0 and token1)

**Affected Parties:**
- Protocol/RiskEngine: Loses intended commission revenue
- Liquidity Providers: Commission fees are meant to benefit LPs through burns or protocol treasury
- Builder ecosystem: The 10% gap undermines the builder incentive mechanism

**Scale:** If $1M in notional is traded with builder codes at 0.1% commission rate ($1,000 expected commission), protocol loses $100 per transaction to this bypass.

## Likelihood Explanation

**Likelihood: VERY HIGH**

**Ease of Exploitation:**
- Trivially exploitable: user simply provides `builderCode = 1` in any `dispatch()` call
- No special permissions, tokens, or setup required
- Works on every mint/burn operation
- No validation prevents arbitrary builder codes

**Incentive:**
- Every user has direct financial incentive (10% fee reduction)
- Rational actors will always use non-zero builder codes
- Bots and aggregators will automatically exploit this

**Detection:**
- Users will naturally discover this through testing or documentation
- Once one user exploits it, information spreads rapidly

## Recommendation

**Fix:** Ensure fee splits sum to 100% (10,000 basis points). Add the missing 10% to either `PROTOCOL_SPLIT` or `BUILDER_SPLIT`:

**Option 1 - Add to Protocol Split:**
```solidity
uint16 constant PROTOCOL_SPLIT = 7_500;  // 75% (was 65%)
uint16 constant BUILDER_SPLIT = 2_500;   // 25% (unchanged)
// Total: 100%
```

**Option 2 - Add to Builder Split:**
```solidity
uint16 constant PROTOCOL_SPLIT = 6_500;  // 65% (unchanged)
uint16 constant BUILDER_SPLIT = 3_500;   // 35% (was 25%)
// Total: 100%
```

**Additionally:** Fix the event emission bug in `settleMint()` line 1577 and `settleBurn()` line 1656 where both values incorrectly use `protocolSplit` instead of `builderSplit` for the second parameter.

**Validation:** Add assertion in constructor or tests:
```solidity
assert(PROTOCOL_SPLIT + BUILDER_SPLIT == DECIMALS);
```

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../contracts/PanopticPool.sol";
import "../contracts/CollateralTracker.sol";

contract CommissionBypassTest is Test {
    PanopticPool panopticPool;
    CollateralTracker collateralToken0;
    
    address attacker = address(0x1337);
    
    function setUp() public {
        // Deploy protocol contracts (simplified)
        // ... deployment code ...
    }
    
    function testCommissionBypass() public {
        // Setup: Attacker deposits collateral and gets shares
        uint256 initialShares = 10000e18;
        vm.startPrank(attacker);
        collateralToken0.deposit(10000e18, attacker);
        
        uint256 sharesBeforeMint = collateralToken0.balanceOf(attacker);
        
        // Scenario 1: Mint with builderCode = 0 (no builder)
        TokenId[] memory positions1 = new TokenId[](1);
        positions1[0] = createMockPosition();
        
        panopticPool.dispatch(
            positions1,
            positions1,
            createPositionSizes(),
            createTickLimits(),
            false,
            0  // builderCode = 0
        );
        
        uint256 sharesAfterMint1 = collateralToken0.balanceOf(attacker);
        uint256 commissionPaid1 = sharesBeforeMint - sharesAfterMint1;
        
        // Close position and reset
        // ... burn position ...
        
        // Scenario 2: Mint with builderCode = 1 (using builder)
        sharesBeforeMint = collateralToken0.balanceOf(attacker);
        
        panopticPool.dispatch(
            positions1,
            positions1,
            createPositionSizes(),
            createTickLimits(),
            false,
            1  // builderCode = 1 (non-zero)
        );
        
        uint256 sharesAfterMint2 = collateralToken0.balanceOf(attacker);
        uint256 commissionPaid2 = sharesBeforeMint - sharesAfterMint2;
        
        // Verify: With builder code, attacker pays only 90% of commission
        assertApproxEqRel(
            commissionPaid2,
            commissionPaid1 * 9000 / 10000,  // 90% of expected
            0.01e18  // 1% tolerance
        );
        
        // Attacker saves 10% commission = direct loss to protocol
        uint256 protocolLoss = commissionPaid1 - commissionPaid2;
        assertGt(protocolLoss, 0, "Protocol should lose 10% commission");
        
        console.log("Commission with builderCode=0:", commissionPaid1);
        console.log("Commission with builderCode=1:", commissionPaid2);
        console.log("Protocol loss (10%):", protocolLoss);
        
        vm.stopPrank();
    }
    
    // Helper functions
    function createMockPosition() internal pure returns (TokenId) {
        // Create valid TokenId for testing
        // ... implementation ...
    }
    
    function createPositionSizes() internal pure returns (uint128[] memory) {
        uint128[] memory sizes = new uint128[](1);
        sizes[0] = 1000e18;
        return sizes;
    }
    
    function createTickLimits() internal pure returns (int24[3][] memory) {
        int24[3][] memory limits = new int24[3][](1);
        limits[0][0] = -100;
        limits[0][1] = 100;
        limits[0][2] = 9000;
        return limits;
    }
}
```

**Notes:**
- The vulnerability affects both `settleMint()` and `settleBurn()` identically
- Users need only provide `builderCode = 1` (or any non-zero value) to exploit
- The computed `feeRecipient` address doesn't need to exist or have code for the exploit to work
- The `_transferFrom()` function succeeds regardless of whether the recipient is a contract or EOA
- This represents a systematic 10% revenue loss on all builder-enabled transactions

### Citations

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

**File:** contracts/RiskEngine.sol (L118-124)
```text
    /// @notice The protocol split, in basis points, when a builder code is present.
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant PROTOCOL_SPLIT = 6_500;

    /// @notice The builder split, in basis points, when a builder code is present
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant BUILDER_SPLIT = 2_500;
```

**File:** contracts/RiskEngine.sol (L864-886)
```text
    function getRiskParameters(
        int24 currentTick,
        OraclePack oraclePack,
        uint256 builderCode
    ) external view returns (RiskParameters) {
        uint8 safeMode = isSafeMode(currentTick, oraclePack);

        uint128 feeRecipient = uint256(uint160(_computeBuilderWallet(builderCode))).toUint128();

        return
            RiskParametersLibrary.storeRiskParameters(
                safeMode,
                NOTIONAL_FEE,
                PREMIUM_FEE,
                PROTOCOL_SPLIT,
                BUILDER_SPLIT,
                MAX_TWAP_DELTA_LIQUIDATION,
                MAX_SPREAD,
                BP_DECREASE_BUFFER,
                MAX_OPEN_LEGS,
                feeRecipient
            );
    }
```

**File:** contracts/CollateralTracker.sol (L1558-1561)
```text
            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
            } else {
```

**File:** contracts/CollateralTracker.sol (L1562-1572)
```text
                unchecked {
                    _transferFrom(
                        optionOwner,
                        address(riskEngine()),
                        (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS
                    );
                    _transferFrom(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        (sharesToBurn * riskParameters.builderSplit()) / DECIMALS
                    );
```

**File:** contracts/CollateralTracker.sol (L1637-1651)
```text
            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
            } else {
                unchecked {
                    _transferFrom(
                        optionOwner,
                        address(riskEngine()),
                        (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS
                    );
                    _transferFrom(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        (sharesToBurn * riskParameters.builderSplit()) / DECIMALS
                    );
```
