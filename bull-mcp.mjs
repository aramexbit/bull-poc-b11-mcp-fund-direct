// Bull MCP (local): lets an AI agent trade OTC on Bull with its OWN wallet key. The key never leaves this process.
// It signs every Bull API request for you and can send the escrow transactions (open deal, pay, deposit).
//
// Setup:   npm i viem      (Node 18+)
// Run:     BULL_AGENT_KEY=0x... node bull-mcp.mjs
// Claude Desktop / Cursor config:
//   { "mcpServers": { "bull": { "command": "node", "args": ["/path/to/bull-mcp.mjs"], "env": { "BULL_AGENT_KEY": "0x..." } } } }
// Use a dedicated wallet that holds only what you want to trade. The escrow contract is not audited yet.
import { createPublicClient, createWalletClient, defineChain, erc20Abi, formatEther, http, parseAbi, parseEventLogs } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const DEFAULT_BASE = "https://www.bull.family";
const BASE = (process.env.BULL_URL || DEFAULT_BASE).replace(/\/$/, "");
if (BASE !== DEFAULT_BASE) console.error(`Bull MCP WARNING: BULL_URL points to ${BASE}, not ${DEFAULT_BASE}. Only continue if you run this server yourself.`);

// Safety: the API server is not trusted with your wallet. Transactions it returns may only go to Bull's contracts (or approve them),
// and no single transaction may send more ETH than BULL_MAX_ETH (default 1). Signatures are only given for what the tool call needs.
const ESCROWS = ["0xd685d39e7a3def19e52b9ab09679b7452c23e20b", "0xd15dd54191d403156f7e29b6bd7637cece63e627"];
const AGREEMENT = "0xef9ceeb6594504ade1ec903a7a29a2bfe38efc8b";
const BULL_CONTRACTS = [...ESCROWS, AGREEMENT];
const MAX_WEI = BigInt(Math.round(Number(process.env.BULL_MAX_ETH || "1") * 1e18));
const low = (x) => String(x || "").toLowerCase();
const KEY = process.env.BULL_AGENT_KEY || "";
if (!/^0x[0-9a-fA-F]{64}$/.test(KEY)) { console.error("Set BULL_AGENT_KEY to a 0x... private key (64 hex characters)."); process.exit(1); }
const account = privateKeyToAccount(KEY);
const AUTH = new Set(["address", "timestamp", "signature"]);

let chainInfo = null;
async function chainClients() {
  if (!chainInfo) {
    const info = await (await fetch(BASE + "/api/v1")).json();
    const chain = defineChain({
      id: info.chain.id, name: info.chain.name, nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
      rpcUrls: { default: { http: [process.env.BULL_RPC || "https://rpc.mainnet.chain.robinhood.com"] } },
    });
    chainInfo = { chain, pub: createPublicClient({ chain, transport: http() }), wal: createWalletClient({ account, chain, transport: http() }), info };
  }
  return chainInfo;
}

// ---- remote Bull MCP (signing handled here) ----
let rid = 0;
async function remote(method, params) {
  const r = await fetch(BASE + "/api/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: ++rid, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}
const parse = (res) => { try { return JSON.parse(res.content[0].text); } catch { return { raw: res }; } };

// Calls a Bull tool; if the server asks for a signature, signs it with the agent key and calls again.
async function bull(name, args = {}) {
  const a = { ...args, address: account.address };
  let res = await remote("tools/call", { name, arguments: a });
  let out = parse(res);
  if (out.status === "signature_required") {
    // Only sign a Bull API request: "Bull API\nMETHOD /api/v1/...\n<timestamp>\n<body hash>", fresh, from our own address.
    const lines = String(out.message || "").split("\n");
    const fresh = Math.abs(Date.now() - Number(lines[2])) < 5 * 60 * 1000;
    if (lines.length !== 4 || lines[0] !== "Bull API" || !/^(GET|POST) \/api\/v1\//.test(lines[1]) || !fresh || lines[2] !== String(out.timestamp) || low(out.address) !== low(account.address) || !/^[0-9a-f]{64}$|^0x[0-9a-f]{64}$/i.test(lines[3]))
      throw new Error("Refusing to sign: the server asked for a message that is not a fresh Bull API request.");
    const signature = await account.signMessage({ message: out.message });
    res = await remote("tools/call", { name, arguments: { ...a, timestamp: out.timestamp, signature } });
    out = parse(res);
  }
  return { ok: !res.isError, data: out };
}

// ---- local tools (these use the wallet) ----
function guard(tx) {
  const to = low(tx?.to), data = String(tx?.data || "0x"), value = BigInt(tx?.value || "0");
  if (value > MAX_WEI) throw new Error(`Refusing to send ${value} wei: more than BULL_MAX_ETH.`);
  if (BULL_CONTRACTS.includes(to)) return;
  if (data.startsWith("0x095ea7b3")) {
    const spender = "0x" + data.slice(34, 74).toLowerCase();
    if (BULL_CONTRACTS.includes(spender) && BigInt("0x" + data.slice(74, 138)) < 2n ** 200n) return;
  }
  throw new Error(`Refusing to send a transaction to ${to}: not a Bull contract.`);
}

async function send(tx) {
  guard(tx);
  const { wal, pub } = await chainClients();
  const hash = await wal.sendTransaction({ to: tx.to, data: tx.data, value: BigInt(tx.value || "0") });
  const rc = await pub.waitForTransactionReceipt({ hash });
  if (rc.status !== "success") throw new Error("Transaction failed: " + hash);
  return rc;
}

const LOCAL = [
  {
    name: "bull_whoami",
    description: "Your agent wallet address and ETH balance on the Bull chain.",
    inputSchema: { type: "object", properties: {} },
    run: async () => { const { pub, info } = await chainClients(); return { address: account.address, chain: info.chain.name, eth: formatEther(await pub.getBalance({ address: account.address })) }; },
  },
  {
    name: "bull_open_deal",
    description: "BUYER, one step: accept the quote, open the escrow deal onchain, and pay your side into escrow. Needs ETH for the price plus gas. After this the seller deposits and the swap settles.",
    inputSchema: { type: "object", properties: { quoteId: { type: "string" }, payAsset: { type: "string", description: "\"base\" (ETH, default) or \"alt\" (stablecoin)." } }, required: ["quoteId"] },
    run: async (a) => {
      const { chain } = await chainClients();
      const acc = await bull("bull_accept_quote", { quoteId: a.quoteId, ...(a.payAsset ? { payAsset: a.payAsset } : {}) });
      if (!acc.ok) return acc.data;
      const rc = await send(acc.data.transaction);
      const ev = parseEventLogs({ abi: parseAbi(["event DealCreated(uint256 indexed id,address indexed buyer,address indexed seller,uint16 feeBps)"]), logs: rc.logs })[0];
      const dealId = ev.args.id.toString();
      const att = await bull("bull_attach_deal", { quoteId: a.quoteId, dealId });
      if (!att.ok) return att.data;
      const txs = [rc.transactionHash];
      for (const step of att.data.steps) txs.push((await send(step)).transactionHash);
      return { status: "paid_into_escrow", dealId, feeBps: acc.data.deal.feeQuote.feeBps, transactions: txs.map((h) => `${chain.blockExplorers?.default?.url || ""}/tx/${h}`), next: "Wait for the seller to deposit. Check bull_get_deal." };
    },
  },
  {
    name: "bull_fund_tokens",
    description: "SELLER, one step: deposit your tokens into escrow once the buyer has paid. Uses the gasless permit when the token supports it, otherwise approve + deposit (needs a little ETH for gas). The swap settles in that transaction.",
    inputSchema: { type: "object", properties: { quoteId: { type: "string" } }, required: ["quoteId"] },
    run: async (a) => {
      const plan = await bull("bull_deposit_plan", { quoteId: a.quoteId });
      if (!plan.ok) return plan.data;
      const d = plan.data;
      if (d.permit) {
        const m = d.permit.message;
        if (low(m.owner) !== low(account.address) || !ESCROWS.includes(low(m.spender)) || BigInt(m.value) >= 2n ** 200n || Number(m.deadline) > Date.now() / 1000 + 86400 || Number(m.deadline) < Date.now() / 1000)
          throw new Error("Refusing to sign the permit: the owner, spender, amount or deadline is not what a Bull deposit needs.");
        const sig = await account.signTypedData({ domain: d.permit.domain, types: d.permit.types, primaryType: d.permit.primaryType, message: { owner: m.owner, spender: m.spender, value: BigInt(m.value), nonce: BigInt(m.nonce), deadline: BigInt(m.deadline) } });
        const r = "0x" + sig.slice(2, 66), s = "0x" + sig.slice(66, 130);
        let v = parseInt(sig.slice(130, 132), 16); if (v < 27) v += 27;
        const dep = await bull("bull_deposit", { quoteId: a.quoteId, permitDeadline: m.deadline, v, r, s });
        return dep.ok ? { status: "deposited_gasless", ...dep.data } : dep.data;
      }
      const txs = [];
      for (const step of d.direct) txs.push((await send(step)).transactionHash);
      return { status: "deposited", transactions: txs };
    },
  },
];

// ---- MCP over stdio ----
async function tools() {
  const r = await remote("tools/list", {});
  const proxied = r.tools
    .map((t) => ({ ...t, description: t.description.replace(/ Signed call:.*$/, ""), inputSchema: { ...t.inputSchema, properties: Object.fromEntries(Object.entries(t.inputSchema.properties).filter(([k]) => !AUTH.has(k))), required: (t.inputSchema.required || []).filter((k) => !AUTH.has(k)) } }));
  return [...LOCAL.map(({ run, ...t }) => t), ...proxied];
}

async function handle(m) {
  switch (m.method) {
    case "initialize":
      return { protocolVersion: m.params?.protocolVersion || "2025-06-18", capabilities: { tools: {} }, serverInfo: { name: "bull-otc-local", version: "1.0.0" }, instructions: `Bull OTC with your own wallet ${account.address}. Start with bull_info and bull_whoami.` };
    case "ping": return {};
    case "tools/list": return { tools: await tools() };
    case "tools/call": {
      const { name, arguments: args = {} } = m.params;
      const local = LOCAL.find((t) => t.name === name);
      try {
        if (local) return { content: [{ type: "text", text: JSON.stringify(await local.run(args), null, 2) }] };
        const out = await bull(name, args);
        return { content: [{ type: "text", text: JSON.stringify(out.data, null, 2) }], ...(out.ok ? {} : { isError: true }) };
      } catch (e) {
        return { content: [{ type: "text", text: JSON.stringify({ error: String(e.message || e).slice(0, 400) }) }], isError: true };
      }
    }
    default: throw Object.assign(new Error("Method not found: " + m.method), { code: -32601 });
  }
}

let buf = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  buf += chunk;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
    if (!line) continue;
    let m; try { m = JSON.parse(line); } catch { continue; }
    if (m.id === undefined) continue; // notifications need no reply
    handle(m).then((result) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }) + "\n"))
      .catch((e) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: e.code || -32603, message: e.message } }) + "\n"));
  }
});
console.error(`Bull MCP ready for ${account.address}`);
