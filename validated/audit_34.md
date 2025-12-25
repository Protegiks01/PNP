# Validation Result: VALID HIGH SEVERITY VULNERABILITY

## Title
Incomplete Commission Distribution in settleMint() and settleBurn() Results in 10% Protocol Revenue Loss

## Summary
The `settleMint()` and `settleBurn()` functions in `CollateralTracker.sol` contain a critical accounting error where commission shares are incompletely distributed when builder codes are present. The protocol constants `PROTOCOL_SPLIT` (6,500 bps) and `BUILDER_SPLIT` (2,500 bps) sum to only 9,000 bps instead of 10,000 bps (100%), causing 10% of commission shares to remain with option owners rather than being collected by the protocol.

## Severity: HIGH
**Category**: Economic Loss / Accounting Inconsistency

**Rationale for HIGH severity:**
- Direct protocol revenue loss on every transaction with builder codes
- Automatic occurrence requiring no attacker action
- Affects core commission collection mechanism
- Cumulative loss across all transactions with builder codes
- Breaks commission collection invariants

## Finding Description

**Location**: `contracts/CollateralTracker.sol`
- `settleMint()`: Lines 1562-1580 [1](#0-0) 
- `settleBurn()`: Lines 1641-1659 [2](#0-1) 

**Root Cause Constants**: `contracts/RiskEngine.sol`, Lines 118-124 [3](#0-2) 

**Decimal Definition**: `contracts/CollateralTracker.sol`, Line 108 [4](#0-3) 

### Intended Logic
Commission fees should be 100% collected from option owners through either:
1. Burning shares (when no builder code present)
2. Transferring shares to protocol and builder (when builder code present)

The total amount collected should equal `sharesToBurn` in both scenarios.

### Actual Logic  
When a builder code is present (`feeRecipient != 0`):
- Only **65%** of `sharesToBurn` is transferred to protocol address
- Only **25%** of `sharesToBurn` is transferred to builder address  
- **10%** of `sharesToBurn` remains in the option owner's balance (neither burned nor transferred)

This creates an asymmetry: users without builder codes pay 100% commission, while users with builder codes pay only 90%.

### Mathematical Proof
From RiskEngine.sol constants:
- `PROTOCOL_SPLIT = 6_500` (65% in basis points)
- `BUILDER_SPLIT = 2_500` (25% in basis points)
- **Sum = 9_000 (90%)**

From CollateralTracker.sol:
- `DECIMALS = 10_000` (100% in basis points)
- **Gap = 1_000 (10%)**

### Code Evidence - settleMint()

The vulnerable transfer logic: [5](#0-4) 

Compare with the no-builder path which correctly burns 100%: [6](#0-5) 

### Additional Bug: Event Emission Error

The `CommissionPaid` event incorrectly emits `protocolSplit` for BOTH parameters instead of `protocolSplit` and `builderSplit`: [7](#0-6) 

Line 1577 should use `builderSplit()` instead of `protocolSplit()`. This same error exists in `settleBurn()` at line 1656: [8](#0-7) 

### Exploitation Path

**Preconditions**: None required - happens automatically during normal operations

**Step 1**: User calls `PanopticPool.dispatch()` to mint a position with a builder code
- Builder code results in `feeRecipient != 0`

**Step 2**: `PanopticPool._payCommissionAndWriteData()` calls `CollateralTracker.settleMint()`
- Commission calculated: `sharesToBurn = (commissionFee * totalSupply) / totalAssets`
- Example: 1000 shares need to be collected as commission

**Step 3**: Commission distribution executes
- Transfer to protocol: `1000 * 6500 / 10000 = 650 shares`
- Transfer to builder: `1000 * 2500 / 10000 = 250 shares`  
- **Remaining with user: 100 shares (10% of commission)**

**Step 4**: User effectively pays only 900 shares instead of intended 1000 shares
- Protocol receives 650 shares (should receive more)
- Builder receives 250 shares (should receive more or protocol should receive remainder)
- User keeps 100 shares (should pay full commission)

### Security Property Broken

**Commission Collection Invariant**: All commission fees should be collected from option owners. The protocol should not leave partial commission uncollected.

**Consistency Invariant**: Commission collection behavior should be consistent regardless of builder code presence. Currently:
- No builder: 100% collected (burned)
- With builder: 90% collected (transferred)
- **Inconsistency: 10% gap**

## Impact Explanation

**Affected Assets**: Protocol share balances, builder share balances

**Quantifiable Impact**:
For every 1,000 shares of commission:
- **Lost**: 100 shares remain with users instead of being collected
- **Protocol**: Receives 650 shares (correct amount per split)
- **Builder**: Receives 250 shares (possibly should receive more)
- **User savings**: Pays only 900 shares instead of 1,000

**Cumulative Effect**:
- Affects every `settleMint()` and `settleBurn()` transaction with builder codes
- If builder codes are used in 50% of transactions with average 1,000 share commission
- 100 transactions = 5,000 shares of lost revenue (50 transactions × 100 shares)

**Systemic Impact**:
- Protocol revenue model is compromised
- Builder incentive mechanism distributes less than intended
- Users with builder codes receive unintended 10% commission discount
- Asymmetric treatment between users with/without builder codes

## Likelihood Explanation

**Occurrence**: HIGH - Automatic on every transaction with builder codes

**Attacker Profile**: Not applicable - this is not an active exploit but a systematic accounting error

**Preconditions**: 
- User mints or burns position
- Builder code is provided (`feeRecipient != 0`)
- No other preconditions required

**Frequency**:
- Every transaction with builder codes affected
- Builder codes are documented as a core protocol feature for fee sharing
- Likely affects significant portion of protocol transactions

**Detection Difficulty**:
- Hard to detect without careful audit of share balances
- Event emission bug masks the issue (emits wrong values)
- Appears as normal protocol operation in transaction logs

## Evidence This is a Bug (Not Intentional Design)

1. **Event Emission Error**: Lines 1577 and 1656 emit `protocolSplit` twice instead of `protocolSplit` and `builderSplit`, indicating code was not properly reviewed [7](#0-6) 

2. **Asymmetric Behavior**: No-builder path burns 100%, builder path collects 90% - no documentation explains this discount as intentional

3. **No Discount Constant**: No constant defined for the missing 10% (e.g., no `BUILDER_CODE_DISCOUNT = 1_000`)

4. **README Context**: While README states `PROTOCOL_SPLIT` and `BUILDER_SPLIT` are "parameters subject to change," it doesn't acknowledge incomplete distribution as acceptable [9](#0-8) 

5. **No Documentation**: No comments or documentation explaining a 10% commission discount for users with builder codes

## Recommendation

**Immediate Fix**: Adjust split constants to sum to 100% in `RiskEngine.sol`:

**Option A** (If 10% should go to protocol):
```solidity
uint16 constant PROTOCOL_SPLIT = 7_500;  // 75%
uint16 constant BUILDER_SPLIT = 2_500;   // 25%
```

**Option B** (If splits should be 65/35):
```solidity
uint16 constant PROTOCOL_SPLIT = 6_500;  // 65%
uint16 constant BUILDER_SPLIT = 3_500;   // 35%
```

**Fix Event Emission Bug**: In both `settleMint()` and `settleBurn()`, change line using `protocolSplit()` to `builderSplit()`:

```solidity
emit CommissionPaid(
    optionOwner,
    address(uint160(riskParameters.feeRecipient())),
    uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
    uint128((commissionFee * riskParameters.builderSplit()) / DECIMALS)  // Fixed
);
```

**Validation**:
- Ensure `PROTOCOL_SPLIT + BUILDER_SPLIT = DECIMALS (10_000)`
- Add assertion in commission distribution: `assert(protocolShares + builderShares == sharesToBurn)`
- Add tests verifying 100% commission collection with builder codes

## Notes

**Why This is Valid Despite README Mentioning Parameters**:
The README states that `PROTOCOL_SPLIT` and `BUILDER_SPLIT` are "parameters and subject to change, but within reasonable levels." This acknowledges these are configurable parameters, NOT that incomplete distribution is acceptable. The statement means the protocol can adjust the split ratios (e.g., 60/40 vs 70/30), but the splits should still sum to 100%.

**Severity Justification**:
This is HIGH (not CRITICAL) because:
- It's direct protocol revenue loss, not fund theft
- Protocol continues to function normally
- No user funds are at risk of theft
- Loss is percentage of fees, not total collateral

But it's HIGH (not MEDIUM) because:
- Direct financial loss to protocol treasury
- Automatic and unavoidable occurrence
- Affects core economic mechanism
- Cumulative impact across all transactions

**Scope Compliance**: ✅
- `CollateralTracker.sol` - In scope
- `RiskEngine.sol` - In scope

**Not a Known Issue**: ✅  
README mentions parameters are configurable but does not list incomplete split distribution as known or acceptable.

### Citations

**File:** contracts/CollateralTracker.sol (L108-108)
```text
    uint256 internal constant DECIMALS = 10_000;
```

**File:** contracts/CollateralTracker.sol (L1558-1560)
```text
            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
```

**File:** contracts/CollateralTracker.sol (L1562-1580)
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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
```

**File:** contracts/CollateralTracker.sol (L1641-1659)
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
                    emit CommissionPaid(
                        optionOwner,
                        address(uint160(riskParameters.feeRecipient())),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS),
                        uint128((commissionFee * riskParameters.protocolSplit()) / DECIMALS)
                    );
                }
            }
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

**File:** README.md (L66-67)
```markdown
- Price/oracle manipulation that is not atomic or requires attackers to hold a price across more than one block is not in scope -i.e., to manipulate the internal exponential moving averages (EMAs), you need to set the manipulated price and then keep it there for at least 1 minute until it can be updated again.
- Attacks that stem from the EMA oracles being extremely stale compared to the market price within its period (currently between 2-30 minutes)
```
