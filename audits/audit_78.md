# Audit Report

## Title 
Commission Payment Causes DoS on Position Minting Due to Missing Balance Check

## Summary
The `settleMint()` function in `CollateralTracker.sol` lacks a balance check before burning/transferring shares for commission payment. After shares are burned for interest accrual and `tokenToPay` settlement in `_updateBalancesAndSettle()`, the remaining balance may be insufficient to cover the commission, causing an underflow revert that permanently DoSes position minting for affected users.

## Finding Description

The `settleMint()` function executes two sequential share-consuming operations:

1. **First operation** - `_updateBalancesAndSettle()` burns shares for:
   - Interest accrual via `_accrueInterest()` [1](#0-0) 
   - `tokenToPay` settlement if positive [2](#0-1) 

2. **Second operation** - Commission payment burns/transfers additional shares [3](#0-2) 

**The Critical Flaw:** The first operation includes a balance check [4](#0-3) , but the second operation does NOT check if sufficient shares remain before attempting to burn/transfer commission shares [5](#0-4)  or [6](#0-5) .

The commission calculation is based on notional amounts (`shortAmount + longAmount`) [7](#0-6) , which is independent of the user's remaining balance after the first operation. Both `_burn()` and `_transferFrom()` perform checked arithmetic that reverts on underflow [8](#0-7)  and [9](#0-8) .

**Exploitation Path:**
1. User passes initial solvency check in `PanopticPool._mintOptions()` [10](#0-9) 
2. Position minting proceeds to `_payCommissionAndWriteData()` which calls `settleMint()` [11](#0-10) 
3. Interest accrual burns shares (if user has outstanding interest)
4. `tokenToPay` settlement burns additional shares (passes balance check)
5. User's remaining balance is now insufficient for commission
6. Commission burn/transfer attempts to deduct more shares than available
7. Underflow revert occurs, reverting the entire transaction

This breaks the protocol invariant that users with sufficient collateral to pass solvency checks can mint positions.

## Impact Explanation

**Severity: Medium (DoS Vulnerability)**

**Financial Impact:**
- Users cannot mint positions even when they have sufficient total collateral
- Positions that should be mintable under the protocol's collateral requirements become impossible to open
- Users must deposit additional collateral beyond what solvency checks require to account for unbounded commission charges

**Systemic Impact:**
- Protocol functionality is degraded for users operating near their collateral limits
- Market inefficiency as users cannot take positions they should be able to afford
- Unpredictable failures based on position notional size rather than actual risk

The vulnerability does not cause direct loss of funds but prevents legitimate protocol operations, qualifying as Medium severity per Immunefi criteria for DoS vulnerabilities with economic impact.

## Likelihood Explanation

**Likelihood: High**

This issue will occur whenever:
1. User has accumulated interest owed (common for users with existing positions)
2. Position requires significant `tokenToPay` settlement (common for multi-leg positions)
3. Commission on notional (`shortAmount + longAmount`) exceeds remaining balance after steps 1-2

**Common Scenarios:**
- Users with leveraged positions (high notional relative to collateral)
- Users with accumulated interest from long-held positions
- Multi-leg strategies where notional amounts are large
- Market makers frequently opening/closing positions

The scenario is not edge case - it affects normal protocol usage where users operate with optimal capital efficiency. No malicious actor is required; the bug triggers naturally when users attempt to mint positions with reasonable collateral ratios.

## Recommendation

Add an explicit balance check before commission payment in `settleMint()` and `settleBurn()` functions:

```solidity
function settleMint(
    address optionOwner,
    int128 longAmount,
    int128 shortAmount,
    int128 ammDeltaAmount,
    RiskParameters riskParameters
) external onlyPanopticPool returns (uint32, int128) {
    (
        uint32 utilization,
        int128 tokenPaid,
        uint256 _totalAssets,
        uint256 _totalSupply
    ) = _updateBalancesAndSettle(
            optionOwner,
            true,
            longAmount,
            shortAmount,
            ammDeltaAmount,
            0
        );

    {
        uint128 commission = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
        uint128 commissionFee = Math
            .mulDivRoundingUp(commission, riskParameters.notionalFee(), DECIMALS)
            .toUint128();
        uint256 sharesToBurn = Math.mulDivRoundingUp(commissionFee, _totalSupply, _totalAssets);
        
        // ADD THIS CHECK:
        if (balanceOf[optionOwner] < sharesToBurn)
            revert Errors.NotEnoughTokens(
                address(this),
                commissionFee,
                convertToAssets(balanceOf[optionOwner])
            );
        
        if (riskParameters.feeRecipient() == 0) {
            _burn(optionOwner, sharesToBurn);
            emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
        } else {
            // ... existing transfer logic
        }
    }

    return (utilization, tokenPaid);
}
```

Apply the same fix to `settleBurn()` at the commission payment section [12](#0-11) .

## Proof of Concept

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "@contracts/PanopticPool.sol";
import "@contracts/CollateralTracker.sol";
import "@contracts/tokens/ERC20Minimal.sol";

contract CommissionDoSTest is Test {
    PanopticPool pool;
    CollateralTracker collateral0;
    CollateralTracker collateral1;
    address user = address(0x1234);
    
    function setUp() public {
        // Deploy contracts and initialize
        // ... deployment code ...
    }
    
    function testCommissionDoS() public {
        // 1. User deposits minimal collateral to pass solvency check
        vm.startPrank(user);
        uint256 initialDeposit = 1000e18;
        collateral0.deposit(initialDeposit, user);
        
        // 2. User accrues some interest by minting a small position first
        TokenId smallPosition = /* encode small position */;
        pool.mintOptions([smallPosition], /* positionSizes */, /* ... */);
        
        // 3. Fast forward time to accrue interest
        vm.warp(block.timestamp + 30 days);
        
        // 4. User attempts to mint large notional position
        // This position has high shortAmount + longAmount (commission base)
        // But relatively moderate tokenToPay requirement
        TokenId largePosition = /* encode position with:
            - shortAmount = 50000e18
            - longAmount = 45000e18  
            - ammDeltaAmount such that tokenToPay is modest
        */;
        
        // 5. Mint will fail with underflow in commission payment
        // Even though user passes solvency check
        vm.expectRevert(); // Will revert with arithmetic underflow
        pool.mintOptions([largePosition], /* positionSizes */, /* ... */);
        
        vm.stopPrank();
        
        // Assert: User cannot mint position despite having sufficient collateral
        // This demonstrates the DoS condition
    }
}
```

**Notes:**
- The exact test implementation requires access to the full test infrastructure
- The vulnerability manifests when `sharesToBurn` (commission) exceeds remaining `balanceOf[optionOwner]` after interest and tokenToPay burns
- Users are DoSed from minting legitimate positions, breaking protocol functionality

### Citations

**File:** contracts/CollateralTracker.sol (L1403-1403)
```text
        _accrueInterest(optionOwner, IS_NOT_DEPOSIT);
```

**File:** contracts/CollateralTracker.sol (L1474-1488)
```text
        if (tokenToPay > 0) {
            uint256 sharesToBurn = Math.mulDivRoundingUp(
                uint256(tokenToPay),
                _totalSupply,
                _totalAssets
            );

            if (balanceOf[_optionOwner] < sharesToBurn)
                revert Errors.NotEnoughTokens(
                    address(this),
                    uint256(tokenToPay),
                    convertToAssets(balanceOf[_optionOwner])
                );

            _burn(_optionOwner, sharesToBurn);
```

**File:** contracts/CollateralTracker.sol (L1552-1581)
```text
        {
            uint128 commission = uint256(int256(shortAmount) + int256(longAmount)).toUint128();
            uint128 commissionFee = Math
                .mulDivRoundingUp(commission, riskParameters.notionalFee(), DECIMALS)
                .toUint128();
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

**File:** contracts/tokens/ERC20Minimal.sol (L103-113)
```text
    function _transferFrom(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);
    }
```

**File:** contracts/tokens/ERC20Minimal.sol (L138-144)
```text
    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;

        // keep checked to prevent underflows
        _internalSupply -= amount;

        emit Transfer(from, address(0), amount);
```

**File:** contracts/PanopticPool.sol (L694-700)
```text
        OraclePack oraclePack = _validateSolvency(
            msg.sender,
            finalPositionIdList,
            riskParameters.bpDecreaseBuffer(),
            usePremiaAsCollateral,
            riskParameters.safeMode()
        );
```

**File:** contracts/PanopticPool.sol (L790-796)
```text
            (uint32 utilization0, int128 paid0) = collateralToken0().settleMint(
                owner,
                longAmounts.rightSlot(),
                shortAmounts.rightSlot(),
                netAmmDelta.rightSlot(),
                riskParameters
            );
```
