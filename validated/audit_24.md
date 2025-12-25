# Valid Security Finding - Medium Severity

## Title
Incomplete Fee Split Implementation Allows 10% Commission Retention When Using Builder Codes

## Summary
The fee distribution logic in `CollateralTracker.settleMint()` and `settleBurn()` contains a critical accounting error where only 90% of commission shares are transferred/burned when builder codes are present, while 100% are burned when no builder code is used. This inconsistency creates systematic value leakage from Panoptic Liquidity Providers (PLPs) to option owners who use builder codes.

## Impact
**Severity**: Medium
**Category**: Economic Manipulation / State Inconsistency

The vulnerability allows users to effectively reduce their commission payments by 10% by simply using any builder code (including self-controlled addresses). This creates:
- Systematic drainage of PLP value at 10% of commission volume for all builder-code transactions
- Unfair economic advantage for users who discover this behavior
- Inconsistent fee treatment across the protocol
- Cumulative impact scaling with trading volume

## Finding Description

**Location**: `contracts/CollateralTracker.sol` and `contracts/RiskEngine.sol`

**Root Cause**: Fee split constants incorrectly sum to 90% instead of 100%

The protocol defines fee split constants that fail to account for the full commission amount: [1](#0-0) 

These constants sum to only 9,000 basis points (90%), not 10,000 (100%).

**Vulnerability in settleMint()**: When a builder code is present, the commission distribution only transfers 90% of shares: [2](#0-1) 

The logic transfers:
- 65% to protocol: `(sharesToBurn * 6500) / 10000`
- 25% to builder: `(sharesToBurn * 2500) / 10000`
- **10% remains with option owner** (not transferred or burned)

In contrast, when no builder code is present (line 1559), ALL `sharesToBurn` are properly burned from the option owner.

**Identical Issue in settleBurn()**: [3](#0-2) 

**Additional Event Emission Bug**: Both event parameters incorrectly use `protocolSplit()` instead of the second using `builderSplit()` at lines 1576-1577 and 1655-1656.

## Exploitation Path

1. **Precondition**: User has collateral deposited and wants to mint/burn an option position
2. **Step 1**: User calls `PanopticPool.dispatch()` with `feeRecipient` set to any address (can be their own or any builder)
3. **Step 2**: `CollateralTracker.settleMint()` calculates commission: `sharesToBurn = Math.mulDivRoundingUp(commissionFee, _totalSupply, _totalAssets)`
4. **Step 3**: Instead of burning/transferring all `sharesToBurn`:
   - Only transfers 65% to RiskEngine
   - Only transfers 25% to builder
   - **Leaves 10% with user** (no burn or transfer)
5. **Result**: User effectively pays only 90% commission instead of 100%, retaining value that should have gone to PLPs

**Comparison**:
- **Without builder code**: User loses 100% of `sharesToBurn` (burned) → Share price increases for all PLPs
- **With builder code**: User loses only 90% of `sharesToBurn` (transferred) → User retains 10%, PLPs lose this value

## Impact Explanation

**Affected Parties**: 
- PLPs lose 10% of commission revenue on all transactions using builder codes
- Option owners gain unfair 10% discount on commissions
- Protocol fee distribution integrity compromised

**Economic Impact**:
- For a position with 1000 USDC commission, user keeps 100 USDC that should have burned/transferred
- Scales with trading volume - higher activity means greater cumulative loss to PLPs
- Creates incentive structure where ALL rational users should use builder codes

**Systemic Risk**:
- Breaks commission fairness invariant
- Predictable exploitation (any user can do this)
- No protection mechanisms in place

## Likelihood Explanation

**Exploitability**: HIGH
- **Attacker Profile**: Any user with basic protocol knowledge
- **Prerequisites**: None beyond normal position minting/burning
- **Execution**: Trivially simple - just set `feeRecipient` to any address
- **Detection**: Difficult to detect as it appears as normal builder code usage
- **Economic Incentive**: Clear 10% savings on all commission fees

**Frequency**: Every transaction using builder codes exhibits this behavior

## Recommendation

**Root Cause Fix**: Correct the fee split constants to sum to 100%

```solidity
// In contracts/RiskEngine.sol
uint16 constant PROTOCOL_SPLIT = 7_500;  // 75% (increased from 65%)
uint16 constant BUILDER_SPLIT = 2_500;   // 25% (unchanged)
// Total: 10,000 (100%)
```

**Alternative Fix**: Ensure remaining shares are burned

```solidity
// In contracts/CollateralTracker.sol - settleMint() and settleBurn()
if (riskParameters.feeRecipient() != 0) {
    uint256 protocolShares = (sharesToBurn * riskParameters.protocolSplit()) / DECIMALS;
    uint256 builderShares = (sharesToBurn * riskParameters.builderSplit()) / DECIMALS;
    
    _transferFrom(optionOwner, address(riskEngine()), protocolShares);
    _transferFrom(optionOwner, address(uint160(riskParameters.feeRecipient())), builderShares);
    
    // Burn remaining shares to ensure full commission is collected
    uint256 remainingShares = sharesToBurn - protocolShares - builderShares;
    if (remainingShares > 0) {
        _burn(optionOwner, remainingShares);
    }
}
```

**Event Fix**: Correct the event emission to properly report builder commission

```solidity
emit CommissionPaid(
    optionOwner,
    address(uint160(riskParameters.feeRecipient())),
    uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
    uint128((commissionFee * riskParameters.builderSplit()) / DECIMALS)  // Fixed: use builderSplit()
);
```

## Notes

This vulnerability breaks the commission accounting invariant by creating inconsistent fee treatment based on whether a builder code is present. The design intent appears to be that commission amounts should be constant regardless of builder participation, with builder codes only determining the distribution destination, not the total amount. The 10% discrepancy represents a systematic accounting error that advantages users at the expense of liquidity providers.

The issue is classified as Medium severity because while it creates systematic value leakage, it does not allow direct theft of existing funds, protocol insolvency, or permanent fund freezing. It represents an economic manipulation through incorrect fee calculation rather than a critical security breach.

### Citations

**File:** contracts/RiskEngine.sol (L118-124)
```text
    /// @notice The protocol split, in basis points, when a builder code is present.
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant PROTOCOL_SPLIT = 6_500;

    /// @notice The builder split, in basis points, when a builder code is present
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant BUILDER_SPLIT = 2_500;
```

**File:** contracts/CollateralTracker.sol (L1558-1580)
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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
```

**File:** contracts/CollateralTracker.sol (L1637-1659)
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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
```
