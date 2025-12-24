import json

BASE_URL = "https://deepwiki.com/code-423n4/2025-12-panoptic"


def get_questions():
    try:
        with open("all_questions.json", "r") as f:
            return json.load(f)

    except:
        return []


questions = get_questions()

questions_generator = [
    "./contracts/PanopticPool.sol",
    "./contracts/RiskEngine.sol",
    "./contracts/types/OraclePack.sol",
    "./contracts/types/MarketState.sol",
    "./contracts/types/PoolData.sol",
    "./contracts/types/RiskParameters.sol",
    "./contracts/SemiFungiblePositionManager.sol",
    "./contracts/SemiFungiblePositionManagerV4.sol",
    "./contracts/CollateralTracker.sol",
    "./contracts/libraries/PanopticMath.sol",
    "./contracts/libraries/Math.sol",
    "./contracts/types/TokenId.sol",
]



def question_format(question: str) -> str:
    """
    Generates a comprehensive security audit prompt for Panoptic Protocol.

    Args:
        question: A specific security question to investigate

    Returns:
        A formatted prompt string for vulnerability analysis
    """
    prompt = f"""
You are an **Elite DeFi Security Auditor** specializing in 
options trading protocols, collateralized lending systems, oracle manipulation 
resistance, and automated market maker integrations. Your task is to analyze 
the **Panoptic Protocol** codebase—a permissionless options trading protocol 
built on Uniswap V3/V4 featuring fully collateralized positions, dynamic 
risk calculations, liquidation mechanisms, and premium settlement—through the 
lens of this single security question: 

**Security Question (scope for this run):** {question}

**PANOPTIC PROTOCOL CONTEXT:**

**Architecture**: Panoptic enables perpetual options trading on Uniswap pools by 
representing options as liquidity positions. Selling options adds liquidity to 
Uniswap (short positions), while buying options removes liquidity (long 
positions). The protocol maintains full collateralization through dynamic 
margin requirements calculated by the RiskEngine, with cross-collateralization 
between tokens and adaptive interest rates based on pool utilization. 

Think in invariant 
Check every logic entry that could affect the protocol base on the question provided 
Look at the exact file provided and other places also if it can cause a severe vuln 
Think in an elite way becasue there is always a logic vuln that could occur 

**Key Components**: 

* **Position Management**: `PanopticPool.sol` (1183 nSLOC - main orchestrator 
  with dispatch entry points), `SemiFungiblePositionManager.sol` (673 nSLOC - 
  position engine handling multi-leg TokenId encoding), 
  `SemiFungiblePositionManagerV4.sol` (631 nSLOC - V4 compatibility)

* **Risk & Collateral**: `RiskEngine.sol` (1294 nSLOC - solvency calculations, 
  liquidation bonuses, force exercise costs), `CollateralTracker.sol` (863 nSLOC - 
  ERC4626 vaults with share accounting, interest accrual, virtual shares)

* **Oracle & Math**: `OraclePack.sol` (291 nSLOC - multi-oracle system with EMA 
  safeguards), `PanopticMath.sol` (369 nSLOC - options pricing and conversions), 
  `Math.sol` (641 nSLOC - generic mathematical utilities)

* **Types & Parameters**: `RiskParameters.sol` (72 nSLOC - protocol parameters), 
  `MarketState.sol` (65 nSLOC - interest rate state), `PoolData.sol` (42 nSLOC - 
  pool configuration), `TokenId.sol` (232 nSLOC - position encoding)

**Files in Scope**: All 11 core contracts in the `contracts/` directory. 
**Test files** under `./test/` are **out of scope** for vulnerability analysis 
but may be referenced for understanding expected behavior.

**CRITICAL INVARIANTS (derived from protocol specification and code):**

1. **Solvency Maintenance**: All accounts must satisfy 
   `balance0 + convert(scaledSurplus1) >= maintReq0` AND 
   `balance1 + convert(scaledSurplus0) >= maintReq1` at oracle tick. 
   Insolvent positions must be liquidated immediately.

2. **Collateral Conservation**: Total assets must equal 
   `s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest` at all times. 
   Asset accounting errors can cause protocol insolvency.

3. **Share Price Monotonicity**: Share price (`totalAssets() / totalSupply()`) 
   must be non-decreasing except for protocol-favorable rounding. Share price 
   manipulation allows asset drainage.

4. **Interest Index Monotonicity**: Global `borrowIndex` must be monotonically 
   increasing starting from 1e18 (WAD). Interest calculation bugs enable 
   unlimited asset minting.

5. **Cross-Collateral Limits**: Cross-buffer ratio must scale conservatively 
   with utilization, dropping to zero at 90% utilization. Incorrect cross-collateral 
   causes systemic undercollateralization.

6. **Position Size Limits**: Individual positions limited by available Uniswap 
   liquidity and `MAX_SPREAD = 90%`. Position size bypasses enable market manipulation.

7. **Oracle Delta Limits**: Fast/slow oracle delta ≤ 953 ticks (~10%), median/slow 
   delta ≤ 2×MAX_TICKS_DELTA. Oracle manipulation enables profitable liquidations.

8. **Safe Mode Activation**: Protocol must enter safe mode when oracle deltas exceed 
   thresholds. Safe mode failures allow price manipulation attacks.

9. **TWAP Accuracy**: TWAP calculations must use sufficient time windows to prevent 
   manipulation. Inaccurate TWAP enables liquidation attacks.

10. **Price Consistency**: All operations in a single transaction must use consistent 
    oracle tick(s). Inconsistent pricing causes arbitrage losses.

11. **Liquidation Price Bounds**: Current tick must be within 513 ticks of TWAP during 
    liquidation (~5% deviation). TWAP manipulation enables forced liquidations.

12. **Position Encoding Validity**: TokenId encoding must produce valid tick ranges 
    and liquidity amounts. Invalid encoding can brick positions permanently.

13. **Leg Count Limits**: Users cannot exceed `MAX_OPEN_LEGS = 33` total position 
    legs. Limit bypasses cause gas griefing and state bloat.

14. **Premium Accounting**: Premium distribution must be proportional to liquidity 
    share in each chunk. Incorrect accounting allows premium manipulation.

15. **Force Exercise Costs**: Base cost of 1.024% for in-range, 1 bps for out-of-range 
    positions. Cost calculation errors enable forced exercise exploitation.

16. **Liquidation Completeness**: Liquidations must close all positions held by the 
    liquidatee. Partial liquidations leave residual risk.

17. **Asset Accounting**: `totalSupply()` must equal `_internalSupply + s_creditedShares` 
    at all times. Share supply manipulation enables unlimited minting.

18. **Deposit Limits**: Deposits must not exceed `type(uint104).max`, withdrawals must 
    leave ≥1 asset. Limit bypasses cause accounting overflow.

19. **Share Transfer Restrictions**: Users with open positions cannot transfer shares 
    via `transfer()` or `transferFrom()`. Restriction bypass enables collateral theft.

20. **Credited Shares Logic**: `s_creditedShares` only increases on position creation, 
    decreases on closure. Incorrect tracking breaks share supply invariants.

21. **Interest Accuracy**: Interest owed must equal 
    `netBorrows * (currentBorrowIndex - userBorrowIndex) / userBorrowIndex`. 
    Calculation errors cause interest manipulation.

22. **Liquidation Bonus Caps**: Bonus cannot exceed liquidatee's pre-liquidation 
    collateral balance. Excessive bonuses cause protocol loss.

23. **Premium Haircutting**: Premium must be clawed back if protocol loss exists 
    after liquidation. Missing haircuts enable economic exploits.

24. **Protocol Loss Limits**: Share supply approaching 2^256-1 can cause various 
    reverts and overflows. Supply overflow prevents all operations.

25. **Force Exercise Validation**: Only long legs contribute to force exercise costs, 
    must account for token deltas. Incorrect validation enables forced exercise theft.

26. **Solvency Check Timing**: Solvency must be checked at oracle tick, not current 
    tick, to prevent manipulation. Incorrect timing enables liquidation attacks.

**YOUR INVESTIGATION MISSION:**

Accept the premise of the security question and explore **all** relevant 
code paths, data structures, state transitions, and cross-contract 
interactions related to it. Do not settle for surface observations—trace 
execution flows through position minting → risk validation → collateral 
management → liquidation flows.

Your goal is to find **one** concrete, exploitable vulnerability tied to 
the question that an attacker, liquidator, or malicious user could exploit. 
Focus on: 

* Business-logic flaws (incorrect validation, missing checks)
* Mathematical errors (overflow, underflow, precision loss, rounding)
* Race conditions (concurrent position operations, share accounting)
* Oracle manipulation (price feeds, TWAP calculations)
* Collateral calculation bugs (margin requirements, cross-collateralization)
* Liquidation vulnerabilities (bonus extraction, premature liquidation)
* Premium settlement errors (distribution, haircutting)
* Interest accrual manipulation (index calculations, rate determination)
* Share supply attacks (minting, burning, virtual shares)
* Position encoding exploits (TokenId manipulation, leg bypass)

**ATTACK SURFACE EXPLORATION:**

1. **Position Minting/Burning** (`PanopticPool.sol`, `SemiFungiblePositionManager.sol`):
   - TokenId encoding with invalid tick ranges or liquidity amounts
   - Position size limits bypass through multi-leg strategies
   - Solvency check timing between oracle and current ticks
   - Commission calculation errors on mint/burn operations
   - Premium settlement race conditions during position closure
   - Force exercise cost calculation manipulation
   - Position balance tracking inconsistencies

2. **Risk Calculations** (`RiskEngine.sol`):
   - Collateral requirement calculation errors
   - Cross-collateralization buffer miscalculation
   - Liquidation bonus extraction beyond intended amounts
   - Solvency check failures at extreme price movements
   - Interest rate model manipulation through utilization attacks
   - Oracle delta threshold bypass enabling manipulation
   - Force exercise cost rounding errors

3. **Collateral Management** (`CollateralTracker.sol`):
   - Share price manipulation through asset accounting errors
   - Virtual share delegation/revoke race conditions
   - Interest accrual calculation bugs enabling unlimited minting
   - Share supply overflow preventing all operations
   - Premium settlement distribution errors
   - Liquidation bonus settlement vulnerabilities
   - Deposit/withdrawal limit bypasses

4. **Oracle System** (`OraclePack.sol`, `PanopticMath.sol`):
   - Price manipulation through EMA oracle attacks
   - TWAP calculation insufficient time windows
   - Safe mode activation failures
   - Price conversion rounding errors
   - Oracle tick inconsistency between operations
   - Median tick buffer manipulation

5. **Liquidation Mechanism** (`PanopticPool.sol`, `RiskEngine.sol`):
   - Premature liquidation through oracle manipulation
   - Liquidation bonus extraction exceeding collateral
   - Premium haircutting failures causing protocol loss
   - Partial liquidation leaving residual positions
   - Liquidatee collateral calculation errors
   - Force liquidation during stale oracle conditions

6. **Interest Rate System** (`MarketState.sol`, `RiskEngine.sol`):
   - Borrow index manipulation enabling interest theft
   - Utilization calculation errors affecting rates
   - Compound interest calculation overflow/underflow
   - Rate boundary violations (exceeding min/max)
   - Interest state corruption blocking withdrawals

7. **Premium Settlement** (`PanopticPool.sol`, `CollateralTracker.sol`):
   - Premium accumulation manipulation
   - Settled token accounting errors
   - Gross premium calculation inaccuracies
   - Premium distribution ratio errors
   - Long premium settlement failures

8. **Mathematical Operations** (`PanopticMath.sol`, `Math.sol`):
   - Price conversion rounding errors
   - Liquidity calculation overflow/underflow
   - Square root price calculation errors
   - Token amount conversion precision loss
   - Tick-to-price conversion manipulation

**PANOPTIC-SPECIFIC ATTACK VECTORS:**

- **Collateral Undercalculation**: Can attackers manipulate position parameters to 
  reduce collateral requirements below actual risk, enabling undercollateralized positions?
- **Oracle Manipulation**: Can attackers manipulate EMA or TWAP oracles to trigger 
  profitable liquidations or force exercises?
- **Liquidation Bonus Extraction**: Can liquidators extract bonuses exceeding the 
  liquidatee's collateral through calculation errors?
- **Share Price Manipulation**: Can attackers manipulate share price calculations 
  to drain assets from CollateralTracker vaults?
- **Interest Accrual Bugs**: Can interest calculation errors enable unlimited asset 
  minting or interest avoidance?
- **Premium Settlement Exploits**: Can attackers manipulate premium accumulation 
  or settlement to extract value from other users?
- **Position Encoding Attacks**: Can invalid TokenId encoding brick positions 
  permanently or bypass position limits?
- **Cross-Collateralization Bypass**: Can attackers exploit cross-collateral 
  calculations to become systemically undercollateralized?
- **Force Exercise Cost Errors**: Can incorrect cost calculations enable 
  profitable forced exercises at victims' expense?
- **Virtual Share Exploits**: Can delegation/revoke mechanisms be exploited to 
  manipulate share supply or bypass restrictions?
- **Protocol Loss Extraction**: Can attackers cause protocol loss and extract 
  value through premium haircutting failures?
- **Solvency Check Timing**: Can timing differences between oracle and current 
  ticks enable liquidation manipulation?
- **Interest Rate Manipulation**: Can utilization manipulation affect interest 
  rates to enable borrowing attacks?
- **Commission Calculation Errors**: Can commission calculation errors enable 
  fee avoidance or excessive charges?
- **TWAP Deviation Bypass**: Can attackers bypass TWAP deviation limits to 
  liquidate at manipulated prices?

**TRUST MODEL:**

**Trusted Roles**: Uniswap pools, oracle data providers, guardian addresses. 
Do **not** assume these actors behave maliciously unless the question explicitly 
explores compromised oracle or Uniswap scenarios.

**Untrusted Actors**: Any user minting/burning positions, liquidators, force 
exercisers, attackers attempting price manipulation. Focus your analysis on bugs 
exploitable by untrusted actors without requiring oracle compromise or Uniswap 
manipulation.

**KNOWN ISSUES / EXCLUSIONS:**

- Cryptographic primitives (ECDSA, SHA256) are assumed secure
- Uniswap pool manipulation (assumed resistant to flash loan attacks)
- Oracle data accuracy (oracles are trusted to provide correct data)
- Network-level attacks (DDoS, BGP hijacking, DNS poisoning)
- EVM runtime bugs unrelated to Panoptic code
- Social engineering, phishing, or key theft
- Gas optimization, code style, missing comments
- Precision loss <0.01% in fee calculations
- Test file issues (tests are out of scope)
- Market risk (price movements) unless caused by protocol bugs
- MEV or front-running attacks unless enabled by protocol vulnerabilities

**VALID IMPACT CATEGORIES (Immunefi Panoptic Bug Bounty):**

**Critical Severity**:
- Direct loss of funds (theft of user collateral or protocol assets)
- Permanent freezing of funds (fix requires hardfork)
- Protocol insolvency leading to systemic loss

**High Severity**:
- Temporary freezing of funds with economic loss
- Systemic undercollateralization risks
- Widespread position liquidations due to bugs

**Medium Severity**:
- Economic manipulation benefiting attackers
- State inconsistencies requiring manual intervention
- Premium or interest calculation errors
- Gas griefing or DoS vulnerabilities

**Low/QA (out of scope)**:
- Minor precision loss (<0.01%)
- Gas inefficiencies
- Event emission or logging issues
- Non-critical edge cases with no financial impact
- UI/UX issues

**OUTPUT REQUIREMENTS:**

If you discover a valid vulnerability related to the security question, 
produce a **full report** following the format below. Your report must include: 
- Exact file paths and function names
- Code quotations (actual snippets from the 11 in-scope contracts)
- Step-by-step exploitation path with realistic parameters
- Clear explanation of which invariant is broken
- Impact quantification (fund loss amount, collateral affected)
- Likelihood assessment (attacker profile, preconditions, complexity)
- Concrete recommendation with code fix
- Proof of Concept (Solidity test demonstrating the exploit)

If **no** valid vulnerability emerges after thorough investigation, state exactly: 
`#NoVulnerability found for this question.`

**Do not fabricate or exaggerate issues.** Only concrete, exploitable bugs with 
clear attack paths and realistic impact count.

**Do not** report: 
- Known issues from previous audits or documentation
- Out-of-scope problems (test files, EVM bugs, crypto primitive breaks)
- Theoretical vulnerabilities without clear attack path and PoC
- Issues requiring trusted roles to behave maliciously
- Minor optimizations, style issues, or low-severity findings

**Focus on one high-quality finding** rather than multiple weak claims.

**VALIDATION CHECKLIST (Before Reporting):**
- [ ] Vulnerability lies within one of the 11 in-scope contracts (not test/)
- [ ] Exploitable by unprivileged attacker (no oracle/Uniswap collusion required)
- [ ] Attack path is realistic with correct data types and feasible parameters
- [ ] Impact meets Critical, High, or Medium severity per Immunefi scope
- [ ] PoC can be implemented as Solidity test or transaction sequence
- [ ] Issue breaks at least one documented invariant
- [ ] Not a known exclusion
- [ ] Clear financial harm, collateral loss, or state divergence demonstrated

---

**AUDIT REPORT FORMAT** (if vulnerability found):

Audit Report

## Title 
The Title Of the Report 

## Summary
A short summary of the issue, keep it brief.

## Finding Description
A more detailed explanation of the issue. Poorly written or incorrect findings may result in rejection and a decrease of reputation score.

Describe which security guarantees it breaks and how it breaks them. If this bug does not automatically happen, showcase how a malicious input would propagate through the system to the part of the code where the issue occurs.

## Impact Explanation
Elaborate on why you've chosen a particular impact assessment.

## Likelihood Explanation
Explain how likely this is to occur and why.


## Recommendation
How can the issue be fixed or solved. Preferably, you can also add a snippet of the fixed code here.


## Proof of Concept
A proof of concept is normally required for Critical, High and Medium Submissions for reviewers under 80 reputation points. Please check the competition page for more details, otherwise your submission may be rejected by the judges.
Very important the test function using their test must bbe provided in here and pls it must be able to compile and run successfully

**Remember**: False positives harm credibility more than missed findings.  Assume claims are invalid until overwhelming evidence proves otherwise.

**Now perform STRICT validation of the claim above.**

**Output ONLY:**
- A full audit report (if genuinely valid after passing **all** checks above) following the specified format
                                                                                                      - `#NoVulnerability found for this question.` (if **any** check fails)

                                                                                                      **Be ruthlessly skeptical.  The bar for validity is EXTREMELY valid.**
"""
    return prompt


def validation_format(report: str) -> str:
    """
    Generates a comprehensive validation prompt for Panoptic Protocol security claims.

    Args:
        report: A security vulnerability report to validate

    Returns:
        A formatted validation prompt string for ruthless technical scrutiny
    """
    prompt = f"""
You are an **Elite DeFi Security Judge** with deep expertise in options trading protocols, collateralized lending systems, oracle manipulation resistance, Uniswap V3/V4 integrations, and Immunefi bug bounty validation. Your ONLY task is **ruthless technical validation** of security claims against the Panoptic codebase.

Note: Uniswap pools and oracle providers are trusted roles.

**SECURITY CLAIM TO VALIDATE:**
{report}

================================================================================
## **PANOPTIC PROTOCOL VALIDATION FRAMEWORK**

### **PHASE 1: IMMEDIATE DISQUALIFICATION CHECKS**
Reject immediately (`#NoVulnerability`) if **ANY** apply:

#### **A. Scope Violations**
- ❌ Affects files **not** in the 11 in-scope contracts from `contracts/` directory
- ❌ Targets any file under `./test/` directory (tests are out of scope)
- ❌ Claims about documentation, comments, code style, or logging (not security issues)
- ❌ Focuses on out-of-scope components: UI, wallets, SDKs, deployment scripts, or external dependencies

**In-Scope Files (11 total):**
- **Core Protocol**: `PanopticPool.sol` (1183 nSLOC), `RiskEngine.sol` (1294 nSLOC), `CollateralTracker.sol` (863 nSLOC)
- **Position Management**: `SemiFungiblePositionManager.sol` (673 nSLOC), `SemiFungiblePositionManagerV4.sol` (631 nSLOC)
- **Types**: `OraclePack.sol` (291 nSLOC), `MarketState.sol` (65 nSLOC), `PoolData.sol` (42 nSLOC), `RiskParameters.sol` (72 nSLOC), `TokenId.sol` (232 nSLOC)
- **Libraries**: `PanopticMath.sol` (369 nSLOC), `Math.sol` (641 nSLOC)

**Verify**: Check that every file path cited in the report matches exactly one of the 11 in-scope contracts.

#### **B. Threat Model Violations**
- ❌ Requires Uniswap pool manipulation or compromise (Uniswap pools are trusted)
- ❌ Assumes compromised oracle data feed providers (oracles are trusted to provide correct data)
- ❌ Needs guardian address to act maliciously (guardian is trusted role)
- ❌ Requires attacker to compromise EVM runtime or block consensus
- ❌ Assumes cryptographic primitives (ECDSA, SHA256) are broken
- ❌ Depends on network-level attacks: DDoS, BGP hijacking, DNS poisoning
- ❌ Relies on social engineering, phishing, key theft, or user operational security failures

**Trusted Roles**: Uniswap pools provide liquidity and price feeds; oracles provide signed data; guardian can lock/unlock pools in emergencies. Do **not** assume these actors behave maliciously.

**Untrusted Actors**: Any user minting/burning positions, liquidators, force exercisers, attackers attempting price manipulation.

#### **C. Known Issues / Accepted Risks** [1](#4-0) 
- ❌ Price/oracle manipulation that is not atomic or requires holding price across multiple blocks
- ❌ Attacks stemming from EMA oracles being stale compared to market price (2-30 minutes)
- ❌ Premium manipulation by swapping back and forth in Uniswap (if not profitable between own accounts)
- ❌ Liquidators extracting additional profit through less favorable force exercise prices
- ❌ Share supply approaching 2^256-1 causing reverts/overflows from repeated liquidations
- ❌ Rounding direction inflating gross premium and decreasing seller rates (low-decimal pools)
- ❌ Options buyers avoiding small premium payments via settleLongPremium
- ❌ Premium accumulation permanently capped due to low liquidity earning high fees

#### **D. Non-Security Issues**
- ❌ Gas optimizations, performance improvements, or micro-optimizations
- ❌ Code style, naming conventions, or refactoring suggestions
- ❌ Missing events, logs, error messages, or better user experience
- ❌ NatSpec comments, documentation improvements, or README updates
- ❌ "Best practices" recommendations with no concrete exploit scenario
- ❌ Input validation preventing honest user mistakes unless it allows theft
- ❌ Minor precision errors with negligible financial impact (<0.01%)

#### **E. Invalid Exploit Scenarios**
- ❌ Requires impossible inputs: negative liquidity, invalid tick ranges, timestamps beyond realistic bounds
- ❌ Cannot be triggered through any realistic dispatch() call or position operation
- ❌ Depends on calling internal functions not exposed through any public API
- ❌ Relies on race conditions that are prevented by reentrancy guards or atomic operations
- ❌ Needs multiple coordinated transactions with no economic incentive
- ❌ Requires attacker to already possess the collateral they seek to steal
- ❌ Depends on miner/validator controlling block timestamp beyond reasonable bounds

### **PHASE 2: PANOPTIC-SPECIFIC DEEP CODE VALIDATION**

#### **Step 1: TRACE COMPLETE EXECUTION PATH THROUGH OPTIONS ARCHITECTURE**

**Panoptic Flow Patterns:**

1. **Position Minting Flow**:
   User deposits collateral → `CollateralTracker.deposit()` → `PanopticPool.dispatch(MINT_ACTION)` → `RiskEngine.isAccountSolvent()` → `SemiFungiblePositionManager.mintTokenizedPosition()` → Uniswap pool liquidity added → `CollateralTracker.delegate()` → commission collected

2. **Position Burning Flow**:
   User calls `PanopticPool.dispatch(BURN_ACTION)` → `RiskEngine.isAccountSolvent()` → `SemiFungiblePositionManager.burnTokenizedPosition()` → Uniswap liquidity removed → `CollateralTracker._settlePremium()` → `CollateralTracker.revoke()` → collateral refunded

3. **Liquidation Flow**:
   Liquidator calls `PanopticPool.liquidateAccount()` → `RiskEngine.isAccountSolvent()` returns false → `RiskEngine.getLiquidationBonus()` → close all positions → liquidator receives bonus → protocol loss handled via share minting

4. **Force Exercise Flow**:
   Force exerciser calls `PanopticPool.forceExercise()` → `RiskEngine.exerciseCost()` calculated → payment to exercised user → liquidity added back to Uniswap → positions updated

For each claim, reconstruct the entire execution path:

1. **Identify Entry Point**: Which user-facing function is called? (`dispatch()`, `dispatchFrom()`, `liquidateAccount()`, `forceExercise()`, etc.)
2. **Follow Internal Calls**: Trace through all function calls, including:
   - Solvency checks in `RiskEngine.isAccountSolvent()`
   - Collateral calculations in `CollateralTracker`
   - Position operations in `SemiFungiblePositionManager`
   - Oracle reads from `OraclePack`
3. **State Before Exploit**: Document initial state (collateral balances, positions, oracle ticks, utilization)
4. **State Transitions**: Enumerate all changes (collateral movements, position updates, share minting/burning)
5. **Check Protections**: Verify if reentrancy guards, solvency checks, or mathematical constraints prevent the exploit
6. **Final State**: Show how the exploit results in unauthorized state (collateral loss, insolvency, share manipulation)

#### **Step 2: VALIDATE EVERY CLAIM WITH CODE EVIDENCE**

For **each assertion** in the report, demand:

**✅ Required Evidence:**
- Exact file path and line numbers (e.g., `RiskEngine.sol:450-475`) within the 11 in-scope contracts
- Direct Solidity code quotes showing the vulnerable logic
- Call traces with actual parameter values demonstrating how execution reaches the vulnerable line
- Calculations showing how collateral, shares, or positions change incorrectly
- References to specific invariant violations

**🚩 RED FLAGS (indicate INVALID):**

1. **"Missing Validation" Claims**:
   - ❌ Invalid unless report shows input bypasses *all* validation layers:
     - `PanopticPool.dispatch()` checks
     - `RiskEngine.isAccountSolvent()` checks
     - `CollateralTracker` balance checks
     - Uniswap pool constraints
   - ✅ Valid if a specific input type genuinely has no validation path

2. **"Collateral Undercalculation" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `RiskEngine` calculations produce insufficient collateral requirements
     - Attacker can open undercollateralized positions that pass solvency checks
     - Specific mathematical error in collateral calculation
   - ✅ Valid if collateral requirements can be bypassed through calculation errors

3. **"Share Price Manipulation" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `CollateralTracker.totalAssets()` or `totalSupply()` can be manipulated
     - Share price (`totalAssets() / totalSupply()`) decreases unexpectedly
     - Attacker can drain assets through share price manipulation
   - ✅ Valid if share accounting allows asset drainage

4. **"Oracle Manipulation" Claims**:
   - ❌ Invalid unless report demonstrates:
     - Protocol accepts manipulated oracle prices without safe mode activation
     - Attacker can profit from liquidations using manipulated prices
     - Bypass of oracle delta limits or TWAP constraints
   - ✅ Valid if oracle safeguards can be bypassed for profit

5. **"Liquidation Bonus Extraction" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `RiskEngine.getLiquidationBonus()` calculates excessive bonuses
     - Bonus exceeds liquidatee's collateral balance
     - Protocol loss occurs due to bonus overpayment
   - ✅ Valid if liquidation bonuses can be extracted beyond intended limits

6. **"Interest Accrual Bugs" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `CollateralTracker._accrueInterest()` miscalculates interest
     - `borrowIndex` fails to be monotonically increasing
     - Attacker can mint unlimited assets through interest manipulation
   - ✅ Valid if interest calculations enable unlimited asset minting

7. **"Position Encoding" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `TokenId` encoding allows invalid tick ranges or liquidity
     - Position size limits can be bypassed through encoding tricks
     - Invalid encoding bricks positions permanently
   - ✅ Valid if TokenId manipulation enables position bypasses

8. **"Premium Settlement" Claims**:
   - ❌ Invalid unless report demonstrates:
     - `_settlePremium()` incorrectly distributes premium
     - Premium accumulation can be manipulated for profit
     - Settled premium calculation errors cause fund loss
   - ✅ Valid if premium settlement allows value extraction

9. **"Cross-Collateralization" Claims**:
   - ❌ Invalid unless report demonstrates:
     - Cross-buffer ratio calculation is incorrect
     - Systemic undercollateralization can occur
     - Cross-collateral limits can be bypassed
   - ✅ Valid if cross-collateral calculations cause systemic risk

10. **"Mathematical Overflow" Claims**:
    - ❌ Invalid unless report demonstrates:
      - Specific arithmetic operation overflows/underflows
      - Overflow causes incorrect collateral or position calculations
      - Attacker can exploit overflow for fund theft
    - ✅ Valid if mathematical errors enable fund loss

#### **Step 3: CROSS-REFERENCE WITH TEST SUITE**

Panoptic's test suite includes comprehensive tests in `test/foundry/` directory (out of scope but informative). Ask:

1. **Existing Coverage**: Do current tests handle the scenario? Check tests like:
   - `test/foundry/core/PanopticPool.t.sol` - dispatch operations
   - `test/foundry/core/RiskEngine/` - solvency calculations
   - `test/foundry/core/CollateralTracker.t.sol` - share accounting
   - `test/foundry/libraries/PanopticMath.t.sol` - mathematical operations

2. **Test Gaps**: Is there an obvious gap that would allow the exploit? If scenario is untested, suggest adding test but do **not** assume vulnerability.

3. **Invariant Tests**: Would existing invariant checks catch the bug? Tests verify:
   - Solvency maintenance across all operations
   - Share price monotonicity
   - Interest index monotonicity
   - Collateral conservation
   - Position size limits

4. **PoC Feasibility**: Can the report's PoC be implemented as a Foundry test using existing contracts without modifying core code?

**Test Case Realism Check**: PoCs must use realistic position structures, valid TokenId encoding, proper collateral amounts, and respect protocol constraints.

### **PHASE 3: IMPACT & EXPLOITABILITY VALIDATION**

#### **Impact Must Be CONCRETE and ALIGN WITH IMMUNEFI SCOPE**

**✅ Valid CRITICAL Severity Impacts (per Immunefi Panoptic scope):**

1. **Direct Loss of Funds (Critical)**:
   - Theft of user collateral from CollateralTracker vaults
   - Theft of protocol assets through share manipulation
   - Unauthorized spending of user deposits
   - Collateral drainage through mathematical exploits
   - Example: "Share price manipulation allows attacker to drain 1000 ETH from CollateralTracker"

2. **Protocol Insolvency (Critical)**:
   - Systemic undercollateralization causing protocol-wide losses
   - Collateral requirements calculation errors enabling mass undercollateralization
   - Share supply overflow preventing all operations
   - Example: "Cross-collateralization bug allows all positions to become undercollateralized simultaneously"

3. **Permanent Freezing of Funds (Critical)**:
   - Funds locked with no transaction able to unlock them
   - Position encoding bricking addresses permanently
   - Share supply overflow preventing withdrawals
   - Invalid position structure locking collateral permanently
   - Example: "TokenId encoding bug locks 500 USDC collateral permanently"

**✅ Valid HIGH Severity Impacts:**

4. **Temporary Freezing with Economic Loss (High)**:
   - Funds temporarily frozen causing economic damage
   - Widespread position liquidations due to bugs
   - Systemic undercollateralization risks
   - Example: "Liquidation bug causes 100 positions to be liquidated unnecessarily"

**✅ Valid MEDIUM Severity Impacts:**

5. **Economic Manipulation (Medium)**:
   - Premium accumulation manipulation benefiting attackers
   - Interest rate manipulation through utilization attacks
   - Liquidation bonus extraction beyond intended amounts
   - State inconsistencies requiring manual intervention
   - Example: "Premium settlement bug allows attacker to extract 10 ETH in excess premiums"

6. **State Inconsistencies (Medium)**:
   - Premium or interest calculation errors
   - Gas griefing or DoS vulnerabilities
   - Oracle state divergence between components
   - Example: "Interest accrual bug causes 5% error in interest calculations"

**❌ Invalid "Impacts":**

- User withdraws their own funds (normal protocol operation)
- Attacker loses their own funds through self-draining (not an exploit)
- Theoretical cryptographic weaknesses without practical exploit
- General market risk (price movements) unless caused by protocol bugs
- "Could be problematic if..." statements without concrete exploit path
- Minor fee overpayment or underpayment (<0.1% of transaction value)
- Precision loss <0.01% across reasonable transaction volumes

#### **Likelihood Reality Check**

Assess exploit feasibility:

1. **Attacker Profile**:
   - Any user with ETH/USDC to deposit as collateral? ✅ Likely
   - Liquidator monitoring for undercollateralized positions? ✅ Possible
   - Force exerciser looking for profitable opportunities? ✅ Possible
   - Attacker with ability to manipulate Uniswap pools? ❌ Unlikely (trusted role)
   - Compromised oracle provider? ❌ Impossible (trusted role)

2. **Preconditions**:
   - Normal market operation? ✅ High likelihood
   - High pool utilization? ✅ Possible during volatile periods
   - Specific position structure (e.g., maximum legs)? ✅ Attacker-controlled
   - Specific oracle state (e.g., stale prices)? ✅ Attacker can time submission
   - Network congestion or high gas prices? ✅ Possible but not required

3. **Execution Complexity**:
   - Single dispatch call? ✅ Simple
   - Multiple coordinated transactions? ✅ Moderate (attacker controls)
   - Complex position with multiple legs? ✅ Attacker can deploy
   - Requires precise timing or front-running? ⚠️ Higher complexity
   - Requires mathematical precision? ✅ Attacker can calculate

4. **Economic Cost**:
   - Collateral deposit required? ✅ Attacker-determined (can be minimal)
   - Gas costs for transactions? ✅ Moderate
   - Potential profit vs. cost? ✅ Must be positive for valid exploit
   - Liquidation capital required? ✅ Varies by opportunity

5. **Combined Probability**:
   - Multiply probabilities of all conditions
   - If resulting likelihood <0.1% with no economic incentive → Invalid
   - If exploit is profitable and feasible → Valid

### **PHASE 4:

Wiki pages you might want to explore:
- [Panoptic Protocol Overview (code-423n4/2025-12-panoptic)](/wiki/code-423n4/2025-12-panoptic#1)

### Citations

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

## Panoptic Protocol Validation Output Requirements

### **OUTPUT REQUIREMENTS**

**If VALID (extremely rare—be ruthlessly sure):**

Produce a full audit report with these sections and please make it short:

#### **Title**
Precise vulnerability name (e.g., "Share Price Manipulation in CollateralTracker Allows Asset Drainage")

#### **Summary**
Two to three sentences summarizing:
- What goes wrong
- Where in the codebase (file and function)
- Why it's critical (impact category)

#### **Impact**
**Severity**: [Critical / High / Medium]
**Category**: [Direct Fund Loss / Permanent Fund Freeze / Protocol Insolvency / Economic Manipulation / State Inconsistency]

Describe:
- Concrete financial impact or protocol disruption
- Affected parties (all users, liquidators, PLPs, specific addresses)
- Quantify potential loss (amount of ETH/USDC, collateral affected)

#### **Finding Description**

**Location**: `contracts/[filename].sol:[line_start]-[line_end]`, function `[functionName]()`

**Intended Logic**: Expected behavior per protocol spec and invariants

**Actual Logic**: Describe the flawed logic with exact code quotes

**Code Evidence**:
```solidity
// Quote relevant code from the vulnerable file
// Include 5-10 lines of context
// Show the specific line(s) with the bug
```

**Exploitation Path**:
1. **Preconditions**: Initial state (e.g., "Attacker deposits 1 ETH collateral")
2. **Step 1**: Specific action (e.g., "Attacker mints position with manipulated TokenId")
    - Position structure (legs, strikes, width, token amounts)
    - Code path: `PanopticPool.dispatch()` → `RiskEngine.isAccountSolvent()` → `CollateralTracker.delegate()`
3. **Step 2**: State change (e.g., "Share price decreases due to accounting error")
    - Storage state: `totalAssets()`, `totalSupply()`, `s_depositedAssets`
    - Oracle observations: Price ticks, EMA values
4. **Step 3**: Follow-up action (e.g., "Attacker withdraws assets at inflated share price")
    - Timing: Executed after share price manipulation
5. **Step 4**: Unauthorized outcome (e.g., "Attacker drains 100 ETH from CollateralTracker")
    - Invariant broken: Share price monotonicity violated, collateral conservation failed

**Security Property Broken**: [Which of the 26 Panoptic invariants is violated]
- Example: "Invariant #3: Share Price Monotonicity - Share price must be non-decreasing except for protocol-favorable rounding"

**Root Cause Analysis**:
Deep dive into why the bug exists:
- Missing share price validation in `CollateralTracker.settleLiquidation()`
- Incorrect asset accounting in `totalAssets()` calculation
- Race condition between `delegate()` and `revoke()` operations
- No overflow protection in share supply calculations

#### **Impact Explanation**

**Affected Assets**: [ETH, USDC, custom tokens, user collateral, protocol assets]

**Damage Severity**:
- **Quantitative**: "Attacker can drain arbitrary amounts limited only by available liquidity. Protocol-wide impact: all CollateralTracker vaults vulnerable."
- **Qualitative**: "Complete loss of collateral integrity. Users cannot trust deposited funds."

**User Impact**:
- **Who**: All PLPs, options buyers/sellers, liquidators
- **Conditions**: Exploitable during normal operation, worse during high volatility
- **Recovery**: Requires emergency pause and manual intervention

**Systemic Risk**:
- Enables further attacks: Can be automated with bots
- Cascading effects: Share price manipulation affects all positions
- Detection difficulty: Requires forensic analysis of share accounting

#### **Likelihood Explanation**

**Attacker Profile**:
- **Identity**: Any user with ETH/USDC to deposit
- **Resources Required**: Minimal capital, ability to mint/burn positions
- **Technical Skill**: Medium (requires understanding of TokenId encoding and share accounting)

**Preconditions**:
- **Market State**: Normal operation or high volatility
- **Attacker State**: Needs collateral deposit and position minting capability
- **Timing**: Requires specific oracle state or price manipulation

**Execution Complexity**:
- **Transaction Count**: Multiple dispatch calls for position manipulation
- **Coordination**: Requires precise timing of mint/burn operations
- **Detection Risk**: Low initially (appears as normal trading), high after analysis

**Frequency**:
- **Repeatability**: Unlimited (attacker can repeat with different positions)
- **Scale**: Protocol-wide (affects all users in affected vaults)

**Overall Assessment**: High likelihood (accounting errors exist, low barrier to exploit, profitable)

#### **Recommendation**

**Immediate Mitigation**:
Add share price validation to prevent manipulation:
```solidity
// In CollateralTracker.sol
function _validateSharePrice() internal view {{
    require(totalAssets() * 1e18 >= totalSupply() * lastSharePrice, "Share price decreased");
    }}
```

**Permanent Fix**:
Implement proper asset accounting with overflow checks:

```solidity
// File: contracts/CollateralTracker.sol
// Function: totalAssets()

function totalAssets() public view override returns (uint256) {{
    // Fixed logic with proper validation
    uint256 assets = s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest;
    require(assets >= s_depositedAssets, "Asset accounting error");
    return assets;
}}
```

  **Additional Measures**:
- Add test case: `test/share_price_manipulation.t.sol` verifying share price protection
- Add monitoring: Alert when share price decreases unexpectedly
- Protocol upgrade: Implement enhanced share accounting with invariant checks

**Validation**:
- [ ] Fix prevents share price manipulation
- [ ] No new vulnerabilities introduced (gas costs, complexity)
- [ ] Backward compatible (existing positions remain valid)
- [ ] Performance impact acceptable (minimal gas overhead)

#### **Proof of Concept**
Note the proof of concept has to be a complete test using their test setup that must run so pls u must always a very good test function and dont go out of concept that must proove the issue if its valid,

```solidity
   // File: test/foundry/exploits/SharePriceDrain.t.sol
contract SharePriceDrainTest is Test {{
function testSharePriceManipulation() public {{
        // Setup: Deploy Panoptic contracts
        // Step 1: Attacker deposits collateral
        // Step 2: Manipulate share price through position operations
        // Step 3: Withdraw excess assets
                                                                                                                                                                                  // Step 4: Verify protocol loss
}}
}}
```

  **Expected Output** (when vulnerability exists):
```
[PASS] testSharePriceManipulation() (gas: 245000)
Attacker drained 100 ETH from protocol
```

  **Expected Output** (after fix applied):
```
[FAIL] testSharePriceManipulation() (gas: 245000)
Share price manipulation prevented
```

  **PoC Validation**:
- [ ] PoC runs against unmodified Panoptic codebase
- [ ] Demonstrates clear violation of share price invariant
- [ ] Shows measurable financial impact
- [ ] Fails gracefully after fix applied

**If INVALID (default when any condition fails):**

Output exactly:

```
#NoVulnerability found for this question.
```

### **CRITICAL VALIDATION CHECKLIST**

Before accepting any vulnerability, verify:

1. **Scope Compliance**: Vulnerability affects only the 11 in-scope contracts [1](#5-0)
2. **Not Known Issue**: Check against README known issues [2](#5-1)
    3. **Trust Model**: Exploit doesn't require Uniswap or oracle compromise
4. **Impact Severity**: Meets Critical/High/Medium per Immunefi Panoptic scope
5. **Economic Incentive**: Attack must be profitable for attacker
6. **Technical Feasibility**: Exploit can be implemented without protocol modifications
7. **Invariant Violation**: Clearly breaks one of the 26 documented invariants
8. **PoC Completeness**: Test runs successfully against unmodified codebase

**Remember**: False positives harm credibility. Assume claims are invalid until overwhelming evidence proves otherwise.
"""
    return prompt



def question_generator(target_file: str) -> str:
    """
    Generates targeted security audit questions for a specific Panoptic protocol file.

    Args:
        target_file: The specific file path to focus question generation on
                    (e.g., "contracts/PanopticPool.sol")

    Returns:
        A formatted prompt string for generating security questions
    """
    prompt = f"""
# **Generate 150+ Targeted Security Audit Questions for Panoptic Protocol**

## **Context**

The target project is **Panoptic**, a permissionless options trading protocol that enables perpetual options trading on top of any Uniswap V3 or V4 pool. Unlike traditional options protocols, Panoptic employs a **fully collateralized model** where options positions are represented as Uniswap liquidity positions, with selling options corresponding to adding liquidity and buying options corresponding to removing liquidity. The protocol features **PanopticPool** (orchestrator contract), **RiskEngine** (risk assessment and solvency calculator), **CollateralTracker** (ERC4626 vault for collateral), **SemiFungiblePositionManager** (position engine), and sophisticated **oracle management** with volatility safeguards.

Panoptic's architecture includes critical components for position minting/burning, collateral management, risk calculations, liquidation handling, premium settlement, and interest accrual. The protocol maintains solvency through dynamic collateral requirements, cross-collateralization between tokens, and adaptive interest rates based on pool utilization, while supporting complex features like multi-leg options strategies, force exercises, and protocol fee distribution.

## **Scope**

**CRITICAL TARGET FILE**: Focus question generation EXCLUSIVELY on `{target_file}`

Note: The questions must be generated from **`{target_file}`** only. If you cannot generate enough questions from this single file, provide as many quality questions as you can extract from the file's logic and interactions. **DO NOT return empty results** - give whatever questions you can derive from the target file.

If you cannot reach 150 questions from this file alone, generate as many high-quality questions as the file's complexity allows (minimum target: 50-100 questions for large critical files, 20-50 for smaller files).

**Full Context - 11 In-Scope Files (for reference only):**
If a file is more than a thousand u can generate as many as 300 plus questions as u can u cant but pls always generate as many as u can dont give other response, 
If there are maths logic also generate as many questions base on all the maths logic too among the questions u are giving to me cover all scope and entrypoints
### **Core Protocol Contracts - 11 files**

```python
core_files = [
    "contracts/PanopticPool.sol",              # 1183 nSLOC - Main orchestrator
    "contracts/RiskEngine.sol",                # 1294 nSLOC - Risk calculator
    "contracts/SemiFungiblePositionManager.sol", # 673 nSLOC - Position engine
    "contracts/SemiFungiblePositionManagerV4.sol", # 631 nSLOC - V4 position engine
    "contracts/CollateralTracker.sol",         # 863 nSLOC - ERC4626 vault
    "contracts/types/OraclePack.sol",          # 291 nSLOC - Oracle observations
    "contracts/types/MarketState.sol",         # 65 nSLOC - Interest rate state
    "contracts/types/PoolData.sol",            # 42 nSLOC - Pool configuration
    "contracts/types/RiskParameters.sol",      # 72 nSLOC - Risk parameters
    "contracts/libraries/PanopticMath.sol",    # 369 nSLOC - Options math
    "contracts/libraries/Math.sol",            # 641 nSLOC - Generic math
]
```

**Total: 11 files in full scope (but focus ONLY on `{target_file}` for this generation)**

---

## **Panoptic Protocol Architecture & Layers**

### **1. Position Management Layer** (`PanopticPool.sol`, `SemiFungiblePositionManager.sol`)

- **Position Orchestration**: PanopticPool coordinates all protocol interactions through `dispatch()` and `dispatchFrom()` entry points
- **TokenId Encoding**: Complex multi-leg positions encoded in 256-bit ERC1155 tokenIds with poolId, legs, strike, width, and option parameters
- **Liquidity Operations**: Mint positions add liquidity to Uniswap (short options), burn positions remove liquidity (long options)
- **Position Limits**: Users can mint up to 33 position legs total across all positions (`MAX_OPEN_LEGS`)
- **Commission Handling**: Fees split between protocol, builders, and PLPs according to `PROTOCOL_SPLIT` and `BUILDER_SPLIT`

### **2. Risk & Collateral Layer** (`RiskEngine.sol`, `CollateralTracker.sol`)

- **Solvency Verification**: RiskEngine calculates collateral requirements and verifies account solvency through `isAccountSolvent()`
- **Dynamic Collateral**: Requirements scale with pool utilization using utilization-based multipliers (`VEGOID` parameter)
- **Cross-Collateralization**: Token0 and Token1 balances can be used to collateralize each other with `crossBufferRatio`
- **Interest Accrual**: Compound interest model where borrowers pay rates determined by utilization-based IRM
- **Liquidation Bonuses**: Calculated via `getLiquidationBonus()` to incentivize liquidation of distressed accounts

### **3. Oracle & Price Layer** (`OraclePack.sol`, `PanopticMath.sol`)

- **Multi-Oracle System**: Fast oracle (current tick), slow oracle (EMA), and median tick for price manipulation resistance
- **Volatility Safeguards**: EMA filters and median buffers prevent price manipulation attacks
- **Safe Mode**: Protocol enters conservative mode when oracle deltas exceed thresholds (`MAX_TICKS_DELTA`)
- **TWAP Calculations**: Time-weighted average prices for accurate option pricing and settlement
- **Price Conversions**: Sophisticated math for converting between tokens based on oracle ticks

### **4. Asset & Token Layer** (`CollateralTracker.sol`, `Math.sol`)

- **ERC4626 Integration**: CollateralTrackers implement vault standard for deposits and withdrawals
- **Share Accounting**: `totalAssets()`, `totalSupply()`, `s_depositedAssets`, `s_assetsInAMM` tracking
- **Premium Settlement**: Collection and distribution of option premia between buyers and sellers
- **Balance Operations**: Deposit, withdraw, mint, redeem, delegate, and revoke share operations
- **Rounding Protection**: Share price must be non-decreasing except for protocol-favorable rounding

### **5. Interest Rate Layer** (`MarketState.sol`, `RiskEngine.sol`)

- **Adaptive IRM**: PID controller approach targeting 66.67% utilization (`TARGET_POOL_UTIL`)
- **Rate Boundaries**: Rates bounded between `MIN_RATE_AT_TARGET` and `MAX_RATE_AT_TARGET`
- **Borrow Index Tracking**: Global and per-user borrow indices for compound interest calculations
- **Utilization Calculations**: Real-time pool utilization affects interest rates and collateral requirements
- **Interest State Management**: Tracking of net borrows and last interaction timestamps per user

---

## **Critical Security Invariants**

### **Solvency & Collateral**

1. **Solvency Maintenance**: All accounts must satisfy `balance0 + convert(scaledSurplus1) >= maintReq0` AND `balance1 + convert(scaledSurplus0) >= maintReq1` at oracle tick
2. **Collateral Conservation**: Total assets must equal `s_depositedAssets + s_assetsInAMM + unrealizedGlobalInterest` at all times
3. **Share Price Monotonicity**: Share price (`totalAssets() / totalSupply()`) must be non-decreasing except for protocol-favorable rounding
4. **Interest Index Monotonicity**: Global `borrowIndex` must be monotonically increasing starting from 1e18 (WAD)
5. **Cross-Collateral Limits**: Cross-buffer ratio must scale conservatively with utilization, dropping to zero at 90% utilization
6. **Position Size Limits**: Individual positions limited by available Uniswap liquidity and `MAX_SPREAD = 90%`

### **Oracle & Price Integrity**

7. **Oracle Delta Limits**: Fast/slow oracle delta ≤ 953 ticks (~10%), median/slow delta ≤ 2×MAX_TICKS_DELTA
8. **Safe Mode Activation**: Protocol must enter safe mode when oracle deltas exceed thresholds
9. **TWAP Accuracy**: TWAP calculations must use sufficient time windows to prevent manipulation
10. **Price Consistency**: All operations in a single transaction must use consistent oracle tick(s)
11. **Liquidation Price Bounds**: Current tick must be within 513 ticks of TWAP during liquidation (~5% deviation)

### **Position & State Management**

12. **Position Encoding Validity**: TokenId encoding must produce valid tick ranges and liquidity amounts
13. **Leg Count Limits**: Users cannot exceed `MAX_OPEN_LEGS = 33` total position legs
14. **Premium Accounting**: Premium distribution must be proportional to liquidity share in each chunk
15. **Force Exercise Costs**: Base cost of 1.024% for in-range, 1 bps for out-of-range positions
16. **Liquidation Completeness**: Liquidations must close all positions held by the liquidatee

### **Asset & Share Integrity**

17. **Asset Accounting**: `totalSupply()` must equal `_internalSupply + s_creditedShares` at all times
18. **Deposit Limits**: Deposits must not exceed `type(uint104).max`, withdrawals must leave ≥1 asset
19. **Share Transfer Restrictions**: Users with open positions cannot transfer shares via `transfer()` or `transferFrom()`
20. **Credited Shares Logic**: `s_creditedShares` only increases on position creation, decreases on closure
21. **Interest Accuracy**: Interest owed must equal `netBorrows * (currentBorrowIndex - userBorrowIndex) / userBorrowIndex`

### **Liquidation & Protocol Safety**

22. **Liquidation Bonus Caps**: Bonus cannot exceed liquidatee's pre-liquidation collateral balance
23. **Premium Haircutting**: Premium must be clawed back if protocol loss exists after liquidation
24. **Protocol Loss Limits**: Share supply approaching 2^256-1 can cause various reverts and overflows
25. **Force Exercise Validation**: Only long legs contribute to force exercise costs, must account for token deltas
26. **Solvency Check Timing**: Solvency must be checked at oracle tick, not current tick, to prevent manipulation

---

## **In-Scope Vulnerability Categories** (from Immunefi)

Focus questions on vulnerabilities that lead to these impacts:

### **Critical Severity**

1. **Direct loss of funds**
   - Collateral calculation errors allowing undercollateralized positions
   - Double-spending or duplicate position minting
   - Share price manipulation allowing asset drainage
   - Interest accrual bugs causing unlimited minting
   - Oracle manipulation enabling profitable liquidations

2. **Permanent freezing of funds (fix requires hardfork)**
   - Position encoding bricking addresses permanently
   - Share supply overflow preventing all withdrawals
   - Interest state corruption blocking position closures
   - Invalid tokenIds locking positions permanently

3. **Protocol insolvency**
   - Collateral requirements calculation errors
   - Liquidation bonus calculation allowing protocol loss
   - Cross-collateralization bugs causing systemic undercollateralization
   - Premium settlement errors causing fund drainage

### **High Severity**

4. **Temporary freezing of funds**
   - Liquidation failures preventing position closures
   - Oracle stale prices blocking all operations
   - Interest accrual overflow preventing withdrawals
   - Share transfer restrictions bypassed incorrectly

5. **Incorrect protocol behavior**
   - Risk calculation errors producing wrong solvency results
   - Premium distribution bugs favoring certain users
   - Force exercise cost calculation errors
   - Position size limit bypasses

### **Medium Severity**

6. **Economic manipulation**
   - Premium accumulation manipulation
   - Interest rate manipulation through utilization attacks
   - Liquidation bonus extraction beyond intended amounts
   - Gas griefing through expensive operations

7. **State inconsistencies**
   - Oracle state divergence between components
   - Position balance tracking errors
   - Interest index calculation inaccuracies
   - Share/asset accounting mismatches

---

## **Valid Impact Categories (Restated for Panoptic)**

### **Critical**

- Direct theft of user funds or protocol assets
- Permanent fund freezing requiring hard fork
- Protocol insolvency leading to systemic loss
- Unlimited asset minting or share price collapse

### **High**

- Temporary fund freezing with economic loss
- Systemic undercollateralization risks
- Widespread position liquidations due to bugs
- Oracle manipulation enabling profitable attacks

### **Medium**

- Economic manipulation benefiting attackers
- State inconsistencies requiring manual intervention
- Premium or interest calculation errors
- Gas griefing or DoS vulnerabilities

### **Out of Scope**

- Gas optimization inefficiencies
- UI/UX issues in frontends
- Market risk (price movements)
- Third-party oracle failures (unless oracle protocol broken)
- MEV or front-running attacks
- Theoretical attacks without economic impact

---

## **Goals for Question Generation**

1. **Real Exploit Scenarios**: Each question describes a plausible attack an attacker, liquidator, or malicious user could perform
2. **Concrete & Actionable**: Reference specific functions, variables, or logic flows in `{target_file}`
3. **High Impact**: Prioritize questions leading to Critical/High/Medium impacts per Immunefi scope
4. **Deep Financial Logic**: Focus on subtle state transitions, cross-contract interactions, rounding errors, oracle manipulation, collateral calculation bugs
5. **Breadth Within Target File**: Cover all major functions, edge cases, and state-changing operations in `{target_file}`
6. **Respect Trust Model**: Uniswap pools and oracles are trusted; focus on attacks by regular users or attackers
7. **No Generic Questions**: Avoid "are there reentrancy issues?" → Instead: "In `{target_file}: functionName()`, if condition X occurs, can attacker exploit Y to cause Z impact?"

---

## **Question Format Template**

Each question MUST follow this Python list format:

```python
questions = [
    "[File: {target_file}] [Function: functionName()] [Vulnerability Type] Specific question describing attack vector, preconditions, and impact linking to Immunefi categories?",
    
    "[File: {target_file}] [Function: anotherFunction()] [Vulnerability Type] Another specific question with concrete exploit scenario?",
    
    # ... continue with all generated questions
]
```

**Example Format** (if target_file is `contracts/PanopticPool.sol`):
```python
questions = [
    "[File: contracts/PanopticPool.sol] [Function: dispatch()] [Solvency bypass] Can an attacker craft a malicious positionIdList that passes initial solvency checks but becomes insolvent after the first leg is minted, allowing them to open undercollateralized positions and potentially drain protocol funds?",
    
    "[File: contracts/PanopticPool.sol] [Function: _settlePremium()] [Premium manipulation] Does the premium settlement logic correctly handle edge cases where settled premium is less than owed premium, potentially allowing attackers to manipulate premium accumulation and extract excess value from sellers?",
    
    "[File: contracts/PanopticPool.sol] [Function: liquidateAccount()] [Liquidation bonus extraction] Can a liquidator manipulate the oracle tick between solvency check and liquidation execution to extract higher liquidation bonuses than intended, causing protocol loss?",
]
```

---

## **Output Requirements**

Generate security audit questions focusing EXCLUSIVELY on **`{target_file}`** that:

1. **Target ONLY `{target_file}`** - all questions must reference this file
2. **Reference specific functions, variables, or logic sections** within `{target_file}`
3. **Describe concrete attack vectors** (not "could there be a bug?" but "can attacker do X by exploiting Y in `{target_file}`?")
4. **Tie to Immunefi impact categories** (fund loss, freezing, insolvency, manipulation, DoS)
5. **Respect trust model** (Uniswap and oracles are trusted; focus on user/attacker actions)
6. **Cover diverse attack surfaces** within `{target_file}`: validation logic, state transitions, error handling, edge cases, interactions with other contracts
7. **Focus on high-severity bugs**: prioritize Critical > High > Medium impacts
8. **Avoid out-of-scope issues**: gas optimization, UI bugs, theoretical attacks without economic impact
9. **Use the exact Python list format** shown above
10. **Be detailed and technical**: assume auditor has deep DeFi knowledge; use precise terminology

**Target Question Count:**
- For large critical files (>1000 nSLOC like PanopticPool.sol, RiskEngine.sol): Aim for 100-150 questions
- For medium files (300-1000 nSLOC): Aim for 50-100 questions  
- For smaller files (<300 nSLOC): Aim for 20-50 questions
- **Provide as many quality questions as the file's complexity allows - do NOT return empty results**

**Begin generating questions for `{target_file}` now.
"""
    return prompt