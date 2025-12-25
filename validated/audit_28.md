# Validation Result: VALID HIGH SEVERITY VULNERABILITY

## Title
Incomplete Commission Collection in CollateralTracker Allows 10% Fee Avoidance Through Builder Codes

## Summary
When users mint or burn options positions using builder codes, the `settleMint()` and `settleBurn()` functions in CollateralTracker only transfer 90% of calculated commission shares from users (65% to protocol + 25% to builder), while burning 100% when no builder code is used. This allows users to retain 10% of commission fees that should be collected, resulting in permanent loss of protocol revenue. [1](#0-0) 

## Impact

**Severity**: High
**Category**: Economic Manipulation / Direct Revenue Loss

The vulnerability causes direct and permanent loss of protocol revenue:

- **Affected Assets**: Protocol commission revenue from all CollateralTracker vaults (ETH, USDC, and other tokens)
- **Magnitude**: 10% of commission fees are not collected from users utilizing builder codes
- **Affected Parties**: Protocol and existing PLPs (Panoptic Liquidity Providers) who should benefit from burned commission shares
- **Frequency**: Occurs on every position mint and burn operation when builder codes are used
- **Systemic Impact**: Creates two-tier fee structure where users with builder codes pay 10% less commission than users without, incentivizing all users to adopt builder codes to minimize fees

## Finding Description

**Location**: `contracts/CollateralTracker.sol:1557-1580`, function `settleMint()` and lines 1635-1659 in `settleBurn()`

**Intended Logic**: 
The protocol should collect 100% of calculated commission from users in both scenarios:
- Without builder code: Burn all commission shares (benefits all PLPs)
- With builder code: Distribute commission among protocol (65%), builder (25%), and PLPs (10% burned)

**Actual Logic**:
The code calculates `sharesToBurn` representing the full commission amount, but when a builder code is present, only 90% is actually removed from the user's balance: [2](#0-1) 

The commission split constants only sum to 90% (6,500 + 2,500 = 9,000 basis points out of 10,000): [3](#0-2) 

Where DECIMALS = 10_000 represents 100%.

**Exploitation Path**:

1. **Precondition**: User has deposited collateral in CollateralTracker and wants to mint/burn a position
2. **Step 1**: User calls `PanopticPool.dispatch()` with a non-zero `builderCode` parameter [4](#0-3) 

3. **Step 2**: `dispatch()` calls `getRiskParameters(builderCode)` which computes a `feeRecipient` address from the builder code [5](#0-4) 

4. **Step 3**: During position settlement, `CollateralTracker.settleMint()` or `settleBurn()` calculates commission and checks if `feeRecipient != 0`
5. **Step 4**: Only 90% of `sharesToBurn` is transferred:
   - 65% to RiskEngine address: `(sharesToBurn * 6_500) / 10_000`
   - 25% to builder address: `(sharesToBurn * 2_500) / 10_000`
   - **10% remains in user's balance** (not burned, not transferred)

6. **Outcome**: User retains 10% of commission shares that should have been collected

The same vulnerability exists in `settleBurn()`: [6](#0-5) 

**Security Property Broken**: 
Commission collection integrity - Users should pay equal commission regardless of builder code usage. When commission is burned, all remaining shareholders benefit proportionally through reduced total supply. When only 90% is transferred, the individual user keeps 10% while other PLPs receive no benefit from that portion.

**Root Cause Analysis**:
- `PROTOCOL_SPLIT` and `BUILDER_SPLIT` constants sum to only 90% instead of 100%
- Missing third allocation for PLP benefit (should burn remaining 10%)
- Inconsistent behavior: burns 100% without builder, transfers only 90% with builder
- Variable named `sharesToBurn` suggests intention to collect full amount, but implementation is incomplete

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user minting or burning options positions
- **Resources**: Only requires normal collateral deposits and position operations
- **Technical Skill**: Minimal - only needs to provide a non-zero `builderCode` parameter

**Preconditions**:
- Normal protocol operation
- No special market conditions required
- No privileged access needed

**Execution Complexity**:
- Single `dispatch()` call with `builderCode` parameter
- No coordination or timing requirements
- Can be discovered through normal protocol usage

**Economic Incentive**:
- Users save 10% on every commission payment
- Rational actors will adopt this behavior once discovered
- Likely to be widely shared among users

**Overall Assessment**: High likelihood - trivially exploitable with strong economic incentive for adoption.

## Recommendation

**Immediate Fix**:
Add a third transfer to burn the remaining 10% for PLPs, or adjust the distribution logic to collect 100% of commission:

```solidity
// Option 1: Burn remaining 10% for PLPs
if (riskParameters.feeRecipient() != 0) {
    uint256 protocolAmount = (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS;
    uint256 builderAmount = (sharesToBurn * riskParameters.builderSplit()) / DECIMALS;
    uint256 plpAmount = sharesToBurn - protocolAmount - builderAmount;
    
    _transferFrom(optionOwner, address(riskEngine()), protocolAmount);
    _transferFrom(optionOwner, address(uint160(riskParameters.feeRecipient())), builderAmount);
    _burn(optionOwner, plpAmount); // Burn remaining 10% for PLPs
}

// Option 2: Update RiskEngine constants to sum to 100%
// And redistribute percentages (e.g., 70% protocol, 30% builder)
```

**Additional Measures**:
- Add invariant test verifying 100% commission collection regardless of builder code
- Update commission events to accurately reflect all three recipients
- Fix event emission bug on line 1577 where builder amount incorrectly uses `protocolSplit`

## Notes

This is a clear implementation bug where the commission collection mechanism is incomplete. The variable naming (`sharesToBurn`) and inconsistent behavior (100% vs 90% collection) indicate this was not intentional design. The vulnerability creates unfair advantage for users who discover they can save 10% by using any valid builder code, resulting in permanent loss of protocol revenue that should benefit all PLPs through reduced share supply.

The issue is NOT mentioned in the known issues section of the README, and affects core protocol revenue collection on every mint/burn operation with builder codes enabled.

### Citations

**File:** contracts/CollateralTracker.sol (L108-108)
```text
    uint256 internal constant DECIMALS = 10_000;
```

**File:** contracts/CollateralTracker.sol (L1557-1580)
```text
            uint256 sharesToBurn = Math.mulDivRoundingUp(commissionFee, _totalSupply, _totalAssets);
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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
```

**File:** contracts/CollateralTracker.sol (L1635-1659)
```text
            uint256 sharesToBurn = Math.mulDivRoundingUp(commissionFee, _totalSupply, _totalAssets);

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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
```

**File:** contracts/RiskEngine.sol (L120-124)
```text
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
