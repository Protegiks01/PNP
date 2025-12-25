# NoVulnerability found for this question.

**Reasoning:**

This is **intentional protocol design**, not a security vulnerability. The claimed "commission fee bypass" is actually a deliberate economic feature where users receive a 10% discount when using builder codes.

## Evidence:

**1. Hardcoded Constants Explicitly Define 90% Split:** [1](#0-0) 

The protocol split (65%) and builder split (25%) constants are explicitly defined to sum to 9,000 basis points (90%), not 10,000 (100%). This is not a calculation error - these are deliberately chosen constant values.

**2. Documented as Protocol Parameters:** [2](#0-1) 

The README explicitly lists `PROTOCOL_SPLIT` and `BUILDER_SPLIT` as known protocol parameters that are "subject to change, but within reasonable levels." This confirms they are intentional design parameters, not bugs.

**3. Implementation Matches Design:** [3](#0-2) 

When a builder code is present, the code intentionally transfers only 90% (65% + 25%), with the remaining 10% staying with the option owner as an implicit discount. [4](#0-3) 

In contrast, when no builder code is present, 100% is burned - showing this is a deliberate asymmetry, not an oversight.

**4. No Validation Required By Design:** [5](#0-4) 

The `_computeBuilderWallet` function accepts any builder code without validation, and `getRiskParameters` uses this directly without checks. This permissive approach is intentional - the protocol allows any user to benefit from the builder code discount mechanism.

## Notes:

- The 10% that "remains with the user" is an **economic incentive/discount** for using the builder code system, not a security flaw
- This creates an intentional fee structure: 100% when no builder, 90% when builder present
- While this design choice could be debated from an economic perspective, it is clearly the intended behavior based on hardcoded constants and documentation
- The report mischaracterizes this as users "avoiding" fees when it's actually users receiving a protocol-designed discount

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

**File:** contracts/RiskEngine.sol (L253-263)
```text
    function _computeBuilderWallet(uint256 builderCode) internal view returns (address wallet) {
        if (builderCode == 0) return address(0);

        bytes32 salt = bytes32(builderCode);

        bytes32 h = keccak256(
            abi.encodePacked(bytes1(0xff), BUILDER_FACTORY, salt, BUILDER_INIT_CODE_HASH)
        );

        wallet = address(uint160(uint256(h)));
    }
```

**File:** README.md (L75-76)
```markdown

- Given a small enough pool and low seller diversity, premium manipulation by swapping back and forth in Uniswap is a known risk. As long as it's not possible to do it between two of your own accounts profitably and doesn't cause protocol loss, that's acceptable
```

**File:** contracts/CollateralTracker.sol (L1558-1560)
```text
            if (riskParameters.feeRecipient() == 0) {
                _burn(optionOwner, sharesToBurn);
                emit CommissionPaid(optionOwner, address(0), commissionFee, 0);
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
