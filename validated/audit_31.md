# Validation Result: VALID VULNERABILITY (HIGH Severity)

## Title
ETH Permanently Trapped in ERC20 CollateralTracker Due to Missing Input Validation

## Summary
When users call `deposit()` or `mint()` on an ERC20-based CollateralTracker with ETH attached (msg.value > 0), the ETH becomes permanently trapped in the contract. The functions accept ETH through the `payable` modifier to support native currency CollateralTrackers, but fail to validate that ETH should only be sent when the underlying token is address(0). For ERC20 tokens, the ETH is accepted but never used or refunded, with no recovery mechanism available. [1](#0-0) [2](#0-1) 

## Impact
**Severity**: High
**Category**: Direct Fund Loss (User's Own Funds)

**Affected Assets**: ETH sent by users to ERC20 CollateralTrackers

**Damage Severity**:
- Any user who accidentally sends ETH when depositing ERC20 tokens will permanently lose that ETH
- The loss is limited to the user's own mistake (not theft of other users' funds)
- Affects all Uniswap V4-integrated ERC20 CollateralTrackers in the protocol
- No recovery mechanism exists

**User Impact**:
- **Who**: Any user depositing collateral to ERC20 vaults
- **Conditions**: User accidentally includes msg.value when depositing ERC20 tokens
- **Recovery**: None - ETH is permanently trapped

**Systemic Risk**: Low - Only affects users who make this specific mistake; does not enable attacks on other users

## Finding Description

**Location**: `contracts/CollateralTracker.sol`

**Intended Logic**: 
- For native ETH CollateralTrackers (underlying = address(0)), users should send ETH as msg.value
- For ERC20 CollateralTrackers, users should only send ERC20 tokens via approval/transferFrom, not ETH

**Actual Logic**: 
Both `deposit()` and `mint()` are marked `payable` to support native ETH, but they don't validate that msg.value should only be non-zero when underlying is address(0). [3](#0-2) [4](#0-3) 

**Exploitation Path**:

1. **Preconditions**: 
   - CollateralTracker deployed for Uniswap V4 pool (poolManager != address(0))
   - Underlying token is an ERC20 (e.g., USDC)

2. **Step 1**: User calls `deposit(1000e6, alice)` with msg.value = 1 ETH
   - User intends to deposit USDC but accidentally includes ETH
   - Function executes normally because it's `payable`
   
3. **Step 2**: Line 585 calls `_settleCurrencyDelta(msg.sender, int256(assets))`
   - This encodes msg.value in callback data: [5](#0-4) 
   - But does NOT forward ETH using `.value()` syntax
   - ETH remains in CollateralTracker contract

4. **Step 3**: `unlockCallback()` is invoked
   - For ERC20 tokens, the code path at lines 466-474 executes
   - The `valueOrigin` parameter is completely ignored: [6](#0-5) 
   - Only the ERC20 transfer occurs

5. **Step 4**: 1 ETH remains permanently trapped
   - No `receive()` or `fallback()` function exists
   - No admin withdrawal function
   - Line 464 refunds only apply to native currency (address(0)): [7](#0-6) 
   - Line 1360 in `settleLiquidation()` only refunds NEW msg.value from that call: [8](#0-7) 

**Security Property Broken**: 
- **Input Validation**: Contract accepts invalid input (ETH for ERC20 vault) without reverting
- **Collateral Conservation**: ETH accumulates in contract without being tracked in `s_depositedAssets`, `s_assetsInAMM`, or `unrealizedGlobalInterest` [9](#0-8) 

**Root Cause Analysis**:
- Functions are `payable` to support native ETH CollateralTrackers (legitimate design choice)
- Missing validation: Should check `require(msg.value == 0 || Currency.wrap(underlyingToken()).isAddressZero())`
- For ERC20 vaults in V4 integration, `unlockCallback()` only handles ERC20 tokens and ignores `valueOrigin`

## Likelihood Explanation

**Attacker Profile**:
- **Identity**: Any user (no malicious intent required)
- **Resources Required**: None - simple user error
- **Technical Skill**: None - accidental mistake

**Preconditions**:
- **Market State**: Any time
- **User State**: User making a deposit with accidental msg.value
- **Timing**: Any time deposits are made

**Execution Complexity**:
- **Transaction Count**: Single deposit/mint call
- **Coordination**: None
- **Detection Risk**: N/A - user mistake, not attack

**Frequency**:
- **Repeatability**: Can happen to any user making deposits
- **Scale**: Isolated to individual users making mistakes

**Overall Assessment**: Moderate-to-High likelihood for occurrence (users commonly send wrong values), but this is user error rather than an exploitable vulnerability

## Recommendation

**Immediate Mitigation**:
Add input validation to reject ETH when depositing ERC20 tokens:

```solidity
// In deposit() and mint() functions, add after line 560 / 612:
if (msg.value > 0) {
    require(Currency.wrap(underlyingToken()).isAddressZero(), 
            "Cannot send ETH to ERC20 vault");
}
```

**Alternative Fix**:
Modify `unlockCallback()` to refund surplus ETH even for ERC20 tokens:

```solidity
// After line 474, before line 476:
if (valueOrigin > 0) {
    SafeTransferLib.safeTransferETH(account, valueOrigin);
}
```

**Additional Measures**:
- Add test case verifying ETH rejection for ERC20 vaults
- Add NatSpec warning that msg.value should only be used for native currency vaults
- Consider removing `payable` modifier and using separate functions for native vs ERC20

## Notes

**Severity Justification**: 
This is classified as **HIGH** (not CRITICAL) because:
1. Requires user error (sending ETH by mistake)
2. Only affects the user making the mistake (no theft of other users' funds)
3. Is an input validation issue rather than an exploitable vulnerability
4. Does not enable protocol insolvency or systemic risk

While it causes permanent loss of funds, it falls into the category of "missing input validation preventing honest user mistakes" rather than "exploitable vulnerability enabling fund theft."

**Comparison to Known Issues**: 
Not listed in the known issues section. [10](#0-9) 

**Scope Compliance**: 
Affects `CollateralTracker.sol` which is one of the 11 in-scope core contracts.

### Citations

**File:** contracts/CollateralTracker.sol (L440-442)
```text
    function _settleCurrencyDelta(address account, int256 delta) internal {
        poolManager().unlock(abi.encode(account, delta, msg.value));
    }
```

**File:** contracts/CollateralTracker.sol (L459-464)
```text
            if (Currency.wrap(underlyingAsset).isAddressZero()) {
                poolManager().settle{value: uint256(delta)}();

                // keep checked to prevent underflows
                uint256 surplus = valueOrigin - uint256(delta);
                if (surplus > 0) SafeTransferLib.safeTransferETH(account, surplus);
```

**File:** contracts/CollateralTracker.sol (L466-474)
```text
                poolManager().sync(Currency.wrap(underlyingAsset));
                SafeTransferLib.safeTransferFrom(
                    underlyingAsset,
                    account,
                    address(poolManager()),
                    uint256(delta)
                );
                poolManager().settle();
            }
```

**File:** contracts/CollateralTracker.sol (L503-507)
```text
    function totalAssets() public view returns (uint256) {
        unchecked {
            return uint256(s_depositedAssets) + s_assetsInAMM + s_marketState.unrealizedInterest();
        }
    }
```

**File:** contracts/CollateralTracker.sol (L557-588)
```text
    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
        _accrueInterest(msg.sender, IS_DEPOSIT);
        if (assets > type(uint104).max) revert Errors.DepositTooLarge();
        if (assets == 0) revert Errors.BelowMinimumRedemption();

        shares = previewDeposit(assets);

        address _poolManager = address(poolManager());

        if (_poolManager == address(0)) {
            // transfer assets (underlying token funds) from the user/the LP to the PanopticPool
            // in return for the shares to be minted
            SafeTransferLib.safeTransferFrom(
                underlyingToken(),
                msg.sender,
                address(panopticPool()),
                assets
            );
        }
        // mint collateral shares of the Panoptic Pool funds (this ERC20 token)
        _mint(receiver, shares);

        // update tracked asset balance
        s_depositedAssets += uint128(assets);

        if (_poolManager != address(0)) {
            // transfer assets from the user/the LP to the PanopticPool
            // in return for the shares to be minted
            _settleCurrencyDelta(msg.sender, int256(assets));
        }
        emit Deposit(msg.sender, receiver, assets, shares);
    }
```

**File:** contracts/CollateralTracker.sol (L611-644)
```text
    function mint(uint256 shares, address receiver) external payable returns (uint256 assets) {
        _accrueInterest(msg.sender, IS_DEPOSIT);
        assets = previewMint(shares);

        if (assets > type(uint104).max) revert Errors.DepositTooLarge();
        if (assets == 0) revert Errors.BelowMinimumRedemption();

        address _poolManager = address(poolManager());

        if (_poolManager == address(0)) {
            // transfer assets (underlying token funds) from the user/the LP to the PanopticPool
            // in return for the shares to be minted
            SafeTransferLib.safeTransferFrom(
                underlyingToken(),
                msg.sender,
                address(panopticPool()),
                assets
            );
        }

        // mint collateral shares of the Panoptic Pool funds (this ERC20 token)
        _mint(receiver, shares);

        // update tracked asset balance
        s_depositedAssets += uint128(assets);

        if (_poolManager != address(0)) {
            // transfer assets from the user/the LP to the PanopticPool
            // in return for the shares to be minted
            _settleCurrencyDelta(msg.sender, int256(assets));
        }

        emit Deposit(msg.sender, receiver, assets, shares);
    }
```

**File:** contracts/CollateralTracker.sol (L1360-1360)
```text
            if (msg.value > 0) SafeTransferLib.safeTransferETH(liquidator, msg.value);
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
