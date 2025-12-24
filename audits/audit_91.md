# Audit Report

## Title
Zero-Share Deposits Enable Unintended Asset Donation Through Rounding Down in convertToShares()

## Summary
The `deposit()` function in `CollateralTracker.sol` uses `Math.mulDiv()` which rounds down when converting assets to shares. When the share price exceeds 1:1 (totalAssets > totalSupply), users can deposit small amounts that round down to 0 shares, effectively donating assets to the protocol without receiving any shares.

## Finding Description
The vulnerability exists in the `deposit()` function's use of `convertToShares()` and `previewDeposit()`: [1](#0-0) [2](#0-1) 

The `Math.mulDiv()` function performs floor division: [3](#0-2) 

The `deposit()` function checks that `assets > 0` but does NOT verify that `shares > 0`: [4](#0-3) 

This breaks **Invariant #3: Share Price Monotonicity** by allowing unintended asset donations that inflate share price without proper validation.

**Exploitation Path:**

1. CollateralTracker initializes with virtual shares/assets: [5](#0-4) 

2. Normal operations occur, interest accrues through `unrealizedInterest`: [6](#0-5) 

3. When `totalAssets > totalSupply`, share price exceeds 1:1

4. User deposits amount where: `assets < totalAssets / totalSupply`

5. Calculation: `shares = mulDiv(assets, totalSupply, totalAssets) = 0` (rounds down)

6. Assets are transferred and added to `s_depositedAssets`, but 0 shares are minted: [7](#0-6) 

7. Result: User loses assets, existing shareholders benefit from increased share price

**Contrast with mint() function**, which uses rounding up and has protection: [8](#0-7) [9](#0-8) 

## Impact Explanation
**Medium Severity** - This vulnerability causes:

1. **User Fund Loss**: Users depositing small amounts when share price > 1:1 lose their deposits entirely
2. **Unintended Donations**: Assets are donated to the protocol without user consent
3. **Share Price Inflation**: Each zero-share deposit increases share price for existing holders
4. **Asymmetric Implementation**: `deposit()` lacks the protection that `mint()` has

While individual losses are typically small (< 1 full asset unit), this:
- Violates user expectations of ERC4626 standard behavior
- Can be triggered accidentally by legitimate users
- Could accumulate over many transactions
- Represents a state inconsistency requiring manual intervention to prevent

## Likelihood Explanation
**Medium Likelihood**:

**Preconditions:**
- Share price must exceed 1:1 (totalAssets > totalSupply)
- This occurs naturally through interest accrual as `unrealizedInterest` grows
- Users must attempt deposits smaller than the share price

**Triggering Scenarios:**
1. After significant interest accrual, legitimate users depositing dust amounts
2. Users testing with small amounts before larger deposits
3. Automated systems or bots depositing fixed small amounts

The virtual shares (10^6) provide initial protection, but as the vault matures and interest accrues, the share price can exceed 1:1, making this exploitable.

## Recommendation
Add a check in the `deposit()` function to prevent zero-share deposits:

```solidity
function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
    _accrueInterest(msg.sender, IS_DEPOSIT);
    if (assets > type(uint104).max) revert Errors.DepositTooLarge();
    if (assets == 0) revert Errors.BelowMinimumRedemption();

    shares = previewDeposit(assets);
    
    // ADD THIS CHECK:
    if (shares == 0) revert Errors.BelowMinimumRedemption();

    // ... rest of function
}
```

This mirrors the protection already present in the `mint()` function which uses `mulDivRoundingUp` and checks `assets > 0`.

## Proof of Concept

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

contract ZeroShareDepositTest is Test {
    CollateralTracker collateralTracker;
    
    function testZeroShareDeposit() public {
        // Setup: Deploy and initialize CollateralTracker
        // After initialization: totalSupply = 1_000_000, totalAssets = 1
        
        // Step 1: Large user deposits to establish normal state
        vm.prank(user1);
        uint256 largeDeposit = 1e18; // 1 token
        collateralTracker.deposit(largeDeposit, user1);
        // Now: totalSupply ≈ 1e24, totalAssets ≈ 1e18
        
        // Step 2: Simulate interest accrual
        // Manipulate unrealizedInterest to simulate time passing
        // This increases totalAssets without increasing totalSupply
        vm.warp(block.timestamp + 365 days);
        // Assume interest accrued: unrealizedInterest = 1e18
        // Now: totalSupply = 1e24, totalAssets = 2e18
        // Share price = 2e18 / 1e24 = 2:1
        
        // Step 3: Victim deposits small amount
        vm.prank(victim);
        uint256 smallDeposit = 1; // 1 wei
        
        uint256 victimBalanceBefore = underlyingToken.balanceOf(victim);
        uint256 sharesBefore = collateralTracker.balanceOf(victim);
        
        uint256 shares = collateralTracker.deposit(smallDeposit, victim);
        
        uint256 victimBalanceAfter = underlyingToken.balanceOf(victim);
        uint256 sharesAfter = collateralTracker.balanceOf(victim);
        
        // Assertions
        assertEq(shares, 0, "Should receive 0 shares");
        assertEq(victimBalanceBefore - victimBalanceAfter, smallDeposit, "Assets were transferred");
        assertEq(sharesAfter - sharesBefore, 0, "No shares were minted");
        
        // Victim lost their deposit
        console.log("Victim deposited:", smallDeposit);
        console.log("Victim received shares:", shares);
        console.log("Assets lost:", smallDeposit);
    }
}
```

### Citations

**File:** contracts/CollateralTracker.sol (L285-300)
```text
    function initialize() external {
        // fails if already initialized
        if (s_initialized) revert Errors.CollateralTokenAlreadyInitialized();
        s_initialized = true;

        // these virtual shares function as a multiplier for the capital requirement to manipulate the pool price
        // e.g. if the virtual shares are 10**6, then the capital requirement to manipulate the price to 10**12 is 10**18
        _internalSupply = 10 ** 6;

        // set total assets to 1
        // the initial share price is defined by 1/virtualShares
        s_depositedAssets = 1;

        // store the initial block and initialize the borrowIndex
        s_marketState = MarketStateLibrary.storeMarketState(WAD, block.timestamp >> 2, 0, 0);
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

**File:** contracts/CollateralTracker.sol (L520-522)
```text
    function convertToShares(uint256 assets) public view returns (uint256 shares) {
        return Math.mulDiv(assets, totalSupply(), totalAssets());
    }
```

**File:** contracts/CollateralTracker.sol (L547-549)
```text
    function previewDeposit(uint256 assets) public view returns (uint256 shares) {
        shares = Math.mulDiv(assets, totalSupply(), totalAssets());
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

**File:** contracts/CollateralTracker.sol (L599-603)
```text
    function previewMint(uint256 shares) public view returns (uint256 assets) {
        // round up depositing assets to avoid protocol loss
        // This prevents minting of shares where the assets provided is rounded down to zero
        assets = Math.mulDivRoundingUp(shares, totalAssets(), totalSupply());
    }
```

**File:** contracts/CollateralTracker.sol (L615-616)
```text
        if (assets > type(uint104).max) revert Errors.DepositTooLarge();
        if (assets == 0) revert Errors.BelowMinimumRedemption();
```

**File:** contracts/libraries/Math.sol (L479-489)
```text
    /// @notice Calculates `floor(a×b÷denominator)` with full precision. Throws if result overflows a uint256 or `denominator == 0`.
    /// @param a The multiplicand
    /// @param b The multiplier
    /// @param denominator The divisor
    /// @return result The 256-bit result
    /// @dev Credit to Remco Bloemen under MIT license https://xn--2-umb.com/21/muldiv for this and all following `mulDiv` functions.
    function mulDiv(
        uint256 a,
        uint256 b,
        uint256 denominator
    ) internal pure returns (uint256 result) {
```
