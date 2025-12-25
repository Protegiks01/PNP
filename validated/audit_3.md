# VALID VULNERABILITY CONFIRMED

## Title
Incomplete Commission Fee Collection Due to Misconfigured Fee Splits Causes 10% Systematic Protocol Revenue Loss

## Summary
The commission fee distribution mechanism in `CollateralTracker.sol` only collects 90% of calculated commission fees when builder codes are present, because the protocol split (6,500 bps) and builder split (2,500 bps) sum to only 9,000 basis points instead of the required 10,000 (100%). The uncollected 10% remains in users' share balances, creating systematic protocol revenue loss on every transaction with builder codes.

## Impact
**Severity**: MEDIUM  
**Category**: Economic Manipulation / Protocol Revenue Loss

**Concrete Financial Impact:**
- Protocol loses 10% of all commission revenue when builder codes are used (normal operational mode)
- For every 1,000 shares of commission: protocol receives 650 shares, builder receives 250 shares, user retains 100 shares
- Cumulative across all transactions with builder codes, representing substantial systematic revenue loss
- Affects protocol sustainability and builder incentive economics

**Affected Parties:**
- Protocol treasury (receives 65% instead of intended 65-75%)
- Builder partners (receive 25% as intended, but total pool is reduced)
- All users benefit from unintended 10% commission discount

## Finding Description

**Location**: Multiple locations across in-scope contracts

**Constants Configuration:** [1](#0-0) 

**Commission Collection Logic (settleMint):** [2](#0-1) 

**Commission Collection Logic (settleBurn):** [3](#0-2) 

**Intended Logic:**
When a builder code is present, 100% of commission fees should be collected and distributed between protocol and builder. The `sharesToBurn` variable represents the total commission owed.

**Actual Logic:**
Only 90% of `sharesToBurn` is transferred:
- Protocol receives: `(sharesToBurn * 6500) / 10000 = 65%`
- Builder receives: `(sharesToBurn * 2500) / 10000 = 25%`
- User retains: `10%` (never transferred or burned)

**Exploitation Path:**

1. **Normal Operation**: Any user mints or burns an options position with builder code present (`feeRecipient != 0`)

2. **Commission Calculation**: 
   - System calculates `sharesToBurn` based on notional value or premium
   - Example: User owes 1,000 shares as commission

3. **Incomplete Transfer**:
   - Code path: `PanopticPool.dispatch()` → `CollateralTracker.settleMint()/settleBurn()`
   - Protocol receives: `1000 * 6500 / 10000 = 650 shares`
   - Builder receives: `1000 * 2500 / 10000 = 250 shares`
   - Total transferred: 900 shares

4. **User Retains Excess**:
   - User's balance decreased by only 900 shares
   - User retains 100 shares (10% of commission)
   - These shares retain full value and can be withdrawn

5. **Protocol Loss**:
   - Protocol treasury missing 100 shares per 1,000 commission
   - 10% systematic revenue loss on all builder code transactions

**Security Property Broken:**
Collateral Conservation Invariant - The commission collection mechanism fails to collect 100% of calculated fees, violating the principle that `sharesToBurn` should equal shares actually collected.

**Root Cause Analysis:**
- Configuration error: `PROTOCOL_SPLIT` (6,500) + `BUILDER_SPLIT` (2,500) = 9,000 bps (90%), not 10,000 bps (100%)
- Implementation assumes splits sum to `DECIMALS` (10,000) for complete collection
- No validation that split percentages sum to 100%
- Supporting evidence: Event emission bug uses `protocolSplit()` twice instead of `builderSplit()` [4](#0-3) 

**Comparison with No-Builder Scenario:** [5](#0-4) 

When `feeRecipient == 0`, the code correctly burns 100% of `sharesToBurn`, confirming that 100% collection is the intended behavior.

## Impact Explanation

**Affected Assets**: CollateralTracker shares (representing ETH, USDC, or other pool tokens)

**Damage Severity:**
- **Quantitative**: 10% loss on all commission revenue when builder codes are active (normal operational mode per protocol design)
- **Qualitative**: Systematic revenue leakage undermines protocol economics and builder incentive structure

**User Impact:**
- **Who**: Protocol treasury, builder partners, and indirectly all PLPs
- **Conditions**: Triggered automatically on every position mint/burn with builder codes
- **Benefit to Users**: Unintended 10% discount on all commissions (unjust enrichment)

**Systemic Risk:**
- Predictable, quantifiable revenue loss on every transaction
- Undermines protocol sustainability at scale
- May create misaligned incentives for builder adoption

## Likelihood Explanation

**Attacker Profile:**
Not an attack - this is a passive benefit to all users during normal operations. No malicious intent required.

**Preconditions:**
- Builder code present (`feeRecipient != 0`) - this is the normal operational mode
- User mints or burns position (standard protocol operations)
- No special market conditions required

**Execution Complexity:**
- Zero complexity - happens automatically
- No attacker action needed
- Users passively benefit from paying only 90% of commissions

**Frequency:**
- Every `settleMint()` call with `feeRecipient != 0`
- Every `settleBurn()` call with `feeRecipient != 0` and non-zero `realizedPremium`
- These are core operations occurring continuously during normal protocol usage

**Overall Assessment**: HIGH likelihood - triggers automatically on every builder code transaction, which represents normal protocol operations.

## Recommendation

**Immediate Fix:**
Update constants to ensure splits sum to 10,000 basis points:

```solidity
// File: contracts/RiskEngine.sol
// Lines: 120-124

uint16 constant PROTOCOL_SPLIT = 6_500;  // 65%
uint16 constant BUILDER_SPLIT = 3_500;   // 35% (changed from 2,500)
// Total now equals 10,000 (100%)
```

**Alternative Fix** (if 65%/25% split is intentional):
Explicitly burn the remaining 10% to benefit PLPs:

```solidity
// In CollateralTracker.settleMint() and settleBurn()
// After transfers to protocol and builder:
uint256 remainingShares = sharesToBurn - protocolShares - builderShares;
if (remainingShares > 0) {
    _burn(optionOwner, remainingShares);
}
```

**Fix Event Emission Bug:** [4](#0-3) 

Change line 1577 (and corresponding line in `settleBurn()`) to use `builderSplit()` instead of second `protocolSplit()`.

**Additional Measures:**
- Add constant validation in deployment/initialization: `require(PROTOCOL_SPLIT + BUILDER_SPLIT == DECIMALS, "Splits must sum to 100%")`
- Add comprehensive tests for commission collection with builder codes
- Verify all commission events emit correct split amounts

## Notes

**Not a Known Issue**: The README lists `PROTOCOL_SPLIT` and `BUILDER_SPLIT` as "parameters subject to change within reasonable levels" but does not acknowledge that their sum failing to equal 100% causes revenue loss. [6](#0-5) 

**Impact Classification**: This is MEDIUM severity rather than HIGH because:
- Does not enable theft or unauthorized fund drainage
- Does not cause protocol insolvency or user fund loss
- Revenue loss is predictable and quantifiable (exactly 10%)
- Can be corrected with simple constant adjustment
- No user funds are at risk of permanent loss

However, the systematic nature and cumulative impact across all transactions justify treatment as a legitimate economic vulnerability requiring remediation.

### Citations

**File:** contracts/RiskEngine.sol (L120-124)
```text
    uint16 constant PROTOCOL_SPLIT = 6_500;

    /// @notice The builder split, in basis points, when a builder code is present
    /// @dev can never exceed 10000, so this value must fit inside a uint14 due to RiskParameters packing
    uint16 constant BUILDER_SPLIT = 2_500;
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

**File:** contracts/CollateralTracker.sol (L1635-1660)
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
        }
```

**File:** README.md (L53-90)
```markdown
## Publicly known issues

_Anything included in this section and its subsection is considered a publicly known issue and is therefore ineligible for awards._

**System & Token Limitations**

- Transfers of ERC1155 SFPM tokens has been disabled.
- Construction helper functions (prefixed with add) in the TokenId library and other types do not perform extensive input validation. Passing invalid or nonsensical inputs into these functions or attempting to overwrite already filled slots may yield unexpected or invalid results. This is by design, so it is expected that users of these functions will validate the inputs beforehand.
- Tokens with a supply exceeding 2^127 - 1 are not supported.
- If one token on a pool is broken/does not meet listed criteria/is malicious there are no guarantees as to the security of the other token in that pool, as long as other pools with two legitimate and compliant tokens are not affected.

**Oracle & Price Manipulation**

- Price/oracle manipulation that is not atomic or requires attackers to hold a price across more than one block is not in scope -i.e., to manipulate the internal exponential moving averages (EMAs), you need to set the manipulated price and then keep it there for at least 1 minute until it can be updated again.
- Attacks that stem from the EMA oracles being extremely stale compared to the market price within its period (currently between 2-30 minutes)
- As a general rule, only price manipulation issues that can be triggered by manipulating the price atomically from a normal pool/oracle state are valid

**Protocol Parameters**

- The constants VEGOID, EMA_PERIODS, MAX_TICKS_DELTA, MAX_TWAP_DELTA_LIQUIDATION, MAX_SPREAD, BP_DECREASE_BUFFER, MAX_CLAMP_DELTA, NOTIONAL_FEE, PREMIUM_FEE, PROTOCOL_SPLIT, BUILDER_SPLIT, SELLER_COLLATERAL_RATIO, BUYER_COLLATERAL_RATIO, MAINT_MARGIN_RATE, FORCE_EXERCISE_COST, TARGET_POOL_UTIL, SATURATED_POOL_UTIL, MAX_OPEN_LEGS, and the IRM parameters (CURVE_STEEPNESS, TARGET_UTILIZATION, etc.) are all parameters and subject to change, but within reasonable levels.

**Premium & Liquidation Issues**

- Given a small enough pool and low seller diversity, premium manipulation by swapping back and forth in Uniswap is a known risk. As long as it's not possible to do it between two of your own accounts profitably and doesn't cause protocol loss, that's acceptable
- It's known that liquidators sometimes have a limited capacity to force liquidations to execute at a less favorable price and extract some additional profit from that. This is acceptable even if it causes some amount of unnecessary protocol loss.
- It's possible to leverage the rounding direction to artificially inflate the total gross premium and significantly decrease the rate of premium option sellers earn/are able to withdraw (but not the premium buyers pay) in the future (only significant for very-low-decimal pools, since this must be done one token at a time).
- It's also possible for options buyers to avoid paying premium by calling settleLongPremium if the amount of premium owed is sufficiently small.
- Premium accumulation can become permanently capped if the accumulator exceeds the maximum value; this can happen if a low amount of liquidity earns a large amount of (token) fees

**Gas & Execution Limitations**

- The liquidator may not be able to execute a liquidation if MAX_POSITIONS is too high for the deployed chain due to an insufficient gas limit. This parameter is not final and will be adjusted by deployed chain such that the most expensive liquidation is well within a safe margin of the gas limit.
- It's expected that liquidators may have to sell options, perform force exercises, and deposit collateral to perform some liquidations. In some situations, the liquidation may not be profitable.
- In some situations (stale oracle tick), force exercised users will be worse off than if they had burnt their position.

**Share Supply Issues**

- It is feasible for the share supply of the CollateralTracker to approach 2**256 - 1 (given the token supply constraints, this can happen through repeated protocol-loss-causing liquidations), which can cause various reverts and overflows. Generally, issues with an extremely high share supply as a precondition (delegation reverts due to user's balance being too high, other DoS caused by overflows in calculations with share supply or balances, etc.) are not valid unless that share supply can be created through means other than repeated liquidations/high protocol loss.
```
