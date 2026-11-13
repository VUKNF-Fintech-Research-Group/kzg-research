/**
 * evalUtils.js — shared helpers for the EXP-001 sweeps (eval/scripts/*.js).
 *
 * Every transaction goes through `send`: it is a real transaction (never
 * eth_call or estimateGas), the receipt is checked against fee / gas price,
 * and the row records calldata statistics. `tracePrecompiles` sums the gas of
 * the calls to the EIP-2537 precompiles 0x0b–0x11 from debug_traceTransaction.
 */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { REPO_ROOT, check, gitCommit } = require("../../../scripts/lib/benchUtils");

const EVAL = path.join(REPO_ROOT, "eval");
const RAW = path.join(EVAL, "data", "raw");
const INPUTS = path.join(EVAL, "data", "inputs");

const PRECOMPILE_MIN = 0x0b;
const PRECOMPILE_MAX = 0x11;
// EIP-2929: precompiles are always warm, so a call to one costs 100 gas of access cost.
const WARM_ACCESS = 100;

function readJson(...parts) {
  return JSON.parse(fs.readFileSync(path.join(...parts), "utf8"));
}

function calldataStats(data) {
  const bytes = Buffer.from(data.slice(2), "hex");
  let zero = 0;
  for (const b of bytes) if (b === 0) zero += 1;
  const nonzero = bytes.length - zero;
  const tokens = zero + 4 * nonzero;
  return {
    calldata_bytes: bytes.length,
    zero_bytes: zero,
    nonzero_bytes: nonzero,
    calldata_gas: 4 * zero + 16 * nonzero, // EIP-2028 standard pricing (M3)
    floor_gas: 21_000 + 10 * tokens, // EIP-7623 floor (Prague)
  };
}

/** Raw JSONL writer: one header line, then one line per transaction. */
class RawLog {
  constructor(name, network, chainId) {
    fs.mkdirSync(RAW, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    this.runId = `${name}-${network}-${stamp}`;
    this.file = path.join(RAW, `${this.runId}.jsonl`);
    this.header = {
      type: "run", run_id: this.runId, script: name, network, chain_id: chainId,
      commit: gitCommit(), started_utc: new Date().toISOString(),
    };
    this.rows = [];
    this.firstBlock = null;
    this.lastBlock = null;
  }

  add(row) {
    const full = { run_id: this.runId, network: this.header.network, ...row };
    if (row.block_number !== undefined) {
      this.firstBlock = this.firstBlock === null ? row.block_number : Math.min(this.firstBlock, row.block_number);
      this.lastBlock = this.lastBlock === null ? row.block_number : Math.max(this.lastBlock, row.block_number);
    }
    this.rows.push(full);
    return full;
  }

  close(extra = {}) {
    const header = {
      ...this.header, ...extra, finished_utc: new Date().toISOString(),
      first_block: this.firstBlock, last_block: this.lastBlock, rows: this.rows.length,
    };
    const lines = [JSON.stringify(header), ...this.rows.map((r) => JSON.stringify(r, (k, v) => (typeof v === "bigint" ? v.toString() : v)))];
    fs.writeFileSync(this.file, lines.join("\n") + "\n");
    return this.file;
  }
}

/**
 * Send one transaction and wait for its receipt.
 * Returns { receipt, record }. Throws if the transaction failed.
 */
async function send(signer, txRequest, gasLimit) {
  const response = await signer.sendTransaction({ ...txRequest, gasLimit });
  const receipt = await response.wait(1);
  check(receipt && receipt.status === 1, `transaction ${response.hash} failed`);
  const price = receipt.gasPrice;
  check(price > 0n && receipt.fee / price === receipt.gasUsed && receipt.fee % price === 0n,
    `gasUsed does not reconcile with fee / price (tx ${receipt.hash})`);
  return {
    receipt,
    record: {
      tx_hash: receipt.hash,
      block_number: receipt.blockNumber,
      gas_used: Number(receipt.gasUsed),
      effective_gas_price_wei: price.toString(),
      fee_wei: receipt.fee.toString(),
      ...calldataStats(txRequest.data),
    },
  };
}

/**
 * Gas spent inside EIP-2537 precompiles, from an opcode trace.
 * For a CALL/STATICCALL to a precompile the callee runs in the same frame of the
 * trace, so gas consumed = gas before the call - gas at the next step at the
 * same depth. That includes 100 gas warm access (EIP-2929) and any memory
 * expansion; the memory expansion is reported separately when non-zero.
 */
async function tracePrecompiles(provider, txHash) {
  const trace = await provider.send("debug_traceTransaction", [txHash, { disableStorage: true, disableMemory: true }]);
  const logs = trace.structLogs;
  const calls = [];
  for (let i = 0; i < logs.length - 1; i++) {
    const s = logs[i];
    if (s.op !== "STATICCALL" && s.op !== "CALL") continue;
    const stack = s.stack;
    const addr = parseInt(stack[stack.length - 2].slice(-40), 16);
    if (addr < PRECOMPILE_MIN || addr > PRECOMPILE_MAX) continue;
    const next = logs[i + 1];
    check(next.depth === s.depth, `unexpected depth change after a precompile call in ${txHash}`);
    const consumed = s.gas - next.gas;
    calls.push({ address: "0x" + addr.toString(16).padStart(2, "0"), consumed, precompile_gas: consumed - WARM_ACCESS });
  }
  // Execution gas: gas available at the first opcode minus gas left after the last one.
  const last = logs[logs.length - 1];
  const execGas = logs.length ? logs[0].gas - (last.gas - last.gasCost) : 0;
  return {
    calls, precompile_gas: calls.reduce((sum, c) => sum + c.precompile_gas, 0), exec_gas: execGas, last_op: last && last.op,
    trace_failed: trace.failed,
  };
}

/** Run a view call; return { reverted, reason, value }. */
async function tryCall(fn) {
  try {
    return { reverted: false, value: await fn() };
  } catch (e) {
    const reason = (e.revert && e.revert.name) || e.shortMessage || e.message;
    return { reverted: true, reason };
  }
}

/** No contract code may sit at a precompile address (a planted mock would). */
async function assertNoMocks(provider) {
  for (let a = PRECOMPILE_MIN; a <= PRECOMPILE_MAX; a++) {
    const address = "0x" + a.toString(16).padStart(40, "0");
    check((await provider.getCode(address)) === "0x", `refusing to run: code found at precompile ${address}`);
  }
}

/** SHA-256 of a contract's runtime bytecode, for bytecode.json and Q9. */
async function runtimeHash(provider, address) {
  const code = await provider.getCode(address);
  return crypto.createHash("sha256").update(Buffer.from(code.slice(2), "hex")).digest("hex");
}

module.exports = {
  EVAL, RAW, INPUTS, readJson, calldataStats, RawLog, send, tracePrecompiles, tryCall, assertNoMocks, runtimeHash, check,
};
