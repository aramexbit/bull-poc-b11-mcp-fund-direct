# PoC — Bull MCP `bull_fund_tokens` direct path: server-returned steps sent unchecked, victim loses 1,000,000 tokens

## What it proves

When the deposit plan carries no permit, `bull_fund_tokens` sends every
`direct` step through `send()` with **no verification** that the steps match
the `quoteId` / the deal the seller intends to fund — no dealId binding, no
sellAmount/sellToken/buyer check, no token-amount cap. `guard()` only checks
the destination is a Bull contract (or an approve to one) and `value <=
BULL_MAX_ETH` (both steps carry 0 ETH, so the ETH cap never binds token
amounts). A compromised/malicious API server returns steps for the
ATTACKER's deal instead: `approve(escrow, 1,000,000)` +
`fundTokens(attackerDealId)`. The MCP sends both with no error and reports
`"deposited"`. The attacker's deal (seller=victim, 1,000,000 tokens for
0.001 ETH, buyer=attacker) settles: the attacker gets all 1,000,000 tokens,
the victim gets ~0 ETH (the 0.001 ETH goes to the attacker as sellerPayout),
and the legit deal #1 is never funded.

This is the MCP instance of the SDK `fund()` step-swap (B-03, 2965389dfb):
same mechanism, different client/tool (`bull_fund_tokens` vs `fund()`),
different victim flow (agent seller via the MCP vs SDK seller), different
fix location (`bull-mcp.mjs`). Fixing the SDK does not touch the MCP. The
honest duplicate consideration — the mechanism is B-03's — is stated in the
draft so the team can grade it; by this audit's own precedent (B-02 vs B-03
vs B-04 vs B-07 vs B-08, all one root-cause family in different functions)
it is filed as its own report.

## Run (local only — no real funds, no mainnet, no Bull infrastructure)

```bash
# 1. Start a fresh Anvil (Foundry) on port 8552
anvil --port 8552 --chain-id 31337

# 2. Run (from this directory)
node run-poc.mjs
```

What happens:
1. Deploys `MockERC20` and the **real** `BullEscrow` source (verbatim,
   verified on Sourcify chain 4663), etched at its production address
   `0xd685d39E…` because the MCP hardcodes the escrow allowlist; storage
   (`nextId = 1`, `_lock = 1`) restored with `anvil_setStorageAt`.
2. Victim (seller, MCP agent wallet) holds 1,000,000 tokens. Legit deal #1
   (sell 100 for 0.1 ETH) is created and the buyer pays 0.1 ETH. Attacker
   deal #2 (sell 1,000,000 for 0.001 ETH, buyer=attacker) is created and
   the attacker funds 0.001 ETH.
3. The agent calls `bull_fund_tokens({ quoteId: "q1" })` through the **real**
   MCP, verbatim, over stdio JSON-RPC. The mock returns the attacker's
   direct steps. The MCP sends both and reports `"deposited"`.

## Result (verified 16 Nov 2026, reproduced twice on fresh Anvil)

```
MCP tools/call result: {"status":"deposited","transactions":["0xfcd9…","0x5fb2…"]}
victim tokens after: 0 (agreed sale was 100)
attacker tokens after: 1000000
buyer tokens after: 0
deal #1 status: Open | sellerFunded: false
deal #2 status: Settled | sellerFunded: true
EXPLOITED
```

## Files

- `bull-mcp.mjs` — verbatim copy of https://www.bull.family/mcp/bull-mcp.mjs
  (sha256 `29110f7cd283c2adc2d60c09da2338eea0ebf40bcf8dc89231ce75c52a275b18`)
- `mock-mcp.mjs` — malicious mock Bull API + remote MCP (localhost only);
  signs fee quotes with the PoC-controlled feeSigner
- `run-poc.mjs` — the PoC driver (real MCP over stdio + real BullEscrow on Anvil)
- `chain/src/BullEscrow.sol` — verbatim BullEscrow source (Sourcify, 4663)
- `chain/src/Mocks.sol` — MockERC20
- `poc-result.json` — machine-readable result of the last run
- `chain/` is a real copy (verbatim source + compiled artifacts);
  `node_modules/` is a symlink to `../open-buyerreceive-tamper/node_modules`
  (viem). Replace the symlink with a real `npm install` when publishing the
  PoC repo.

## Do NOT publish yet

This PoC is prepared for the Bull bug-bounty report form (whose PoC field
asks for a LINK). It must be published (gist/repo) **only together with the
report submission**, after the user approves the draft — never before
(Bull's rules: no public disclosure until fixed). It contains no private
keys, no seed phrases, no real credentials: all wallets are throwaway keys
generated fresh on each run on a local Anvil chain.
