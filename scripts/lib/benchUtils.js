/**
 * benchUtils.js – helpers shared by the gas benchmarks.
 */

const { execSync } = require("child_process");
const path = require("path");

const REPO_ROOT = path.join(__dirname, "..", "..");

class BenchmarkAssertionError extends Error {}

function check(condition, message) {
  if (!condition) throw new BenchmarkAssertionError(message);
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}

/**
 * Sends transactions from one signer in order, several per block.
 *
 * Nonces are assigned locally, so a group of transactions can be submitted
 * without waiting for each one to be mined; they still execute in the order
 * given. Every transaction gets an explicit gas limit (no estimation against a
 * state that earlier, still-pending transactions are about to change).
 *
 * For each mined transaction it asserts success and that
 * gasUsed == fee / effective gas price.
 */
class TxQueue {
  constructor(signer, { chunkSize = 12, timeoutMs = 15 * 60 * 1000 } = {}) {
    this.signer = signer;
    this.chunkSize = chunkSize;
    this.timeoutMs = timeoutMs;
    this.nonce = null;
  }

  /**
   * @param requests [{ tx, gasLimit, ...meta }]  tx is a populated transaction
   * @returns the same objects, each with `receipt` and `record` added
   */
  async run(requests) {
    if (this.nonce === null) this.nonce = await this.signer.getNonce("pending");
    for (let start = 0; start < requests.length; start += this.chunkSize) {
      const chunk = requests.slice(start, start + this.chunkSize);
      const responses = [];
      for (const request of chunk) {
        responses.push(await this.signer.sendTransaction({ ...request.tx, nonce: this.nonce, gasLimit: request.gasLimit }));
        this.nonce += 1;
      }
      for (let i = 0; i < chunk.length; i++) {
        const receipt = await responses[i].wait(1, this.timeoutMs);
        check(receipt && receipt.status === 1, `transaction ${responses[i].hash} failed`);
        const gasUsed = receipt.gasUsed;
        const price = receipt.gasPrice; // effective gas price
        const fee = receipt.fee;
        check(price > 0n && fee / price === gasUsed && fee % price === 0n,
          `gasUsed ${gasUsed} does not reconcile with fee ${fee} / effective gas price ${price} (tx ${receipt.hash})`);
        chunk[i].receipt = receipt;
        chunk[i].record = {
          tx_hash: receipt.hash,
          block_number: receipt.blockNumber,
          gas_used: Number(gasUsed),
          effective_gas_price_wei: price.toString(),
          fee_wei: fee.toString(),
        };
      }
    }
    return requests;
  }

  /** Deploy a contract through the queue and return the attached instance. */
  async deploy(factory, args, gasLimit) {
    const [done] = await this.run([{ tx: await factory.getDeployTransaction(...args), gasLimit }]);
    const contract = factory.attach(done.receipt.contractAddress);
    return { contract, record: done.record };
  }
}

/** Find and decode one event from a receipt. */
function findEvent(contract, receipt, name) {
  const log = receipt.logs.map((l) => contract.interface.parseLog(l)).find((l) => l && l.name === name);
  check(log, `no ${name} event in tx ${receipt.hash}`);
  return log;
}

/** Read a value that a just-mined transaction set, tolerating a lagging RPC node. */
async function readUntil(read, expected, what, attempts = 10) {
  let value;
  for (let i = 0; i < attempts; i++) {
    value = await read();
    if (value === expected) return;
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  check(false, `${what}: read ${value}, expected ${expected}`);
}

/**
 * gain = 1 - (batch gas / k) / single-update gas
 * Shown with its inputs in every result row.
 */
function batchGainPct(batchGas, k, singleUpdateGas) {
  return Number(((1 - batchGas / k / singleUpdateGas) * 100).toFixed(2));
}

/** Current commit hash, with "-dirty" if tracked files have uncommitted changes. */
function gitCommit() {
  try {
    const hash = execSync("git rev-parse HEAD", { cwd: REPO_ROOT }).toString().trim();
    const dirty = execSync("git status --porcelain --untracked-files=no", { cwd: REPO_ROOT }).toString().trim() !== "";
    return dirty ? `${hash}-dirty` : hash;
  } catch {
    return "unknown";
  }
}

module.exports = {
  REPO_ROOT, BenchmarkAssertionError, TxQueue, check, median, findEvent, readUntil, batchGainPct, gitCommit,
};
