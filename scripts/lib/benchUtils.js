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
 * Send a transaction and return its receipt plus a result record.
 * Asserts that gasUsed equals fee / effective gas price.
 */
async function send(txPromise) {
  const started = Date.now();
  const tx = await txPromise;
  const receipt = await tx.wait();
  const elapsedMs = Date.now() - started;
  const gasUsed = receipt.gasUsed;
  const price = receipt.gasPrice; // effective gas price
  const fee = receipt.fee;
  check(price > 0n && fee / price === gasUsed && fee % price === 0n,
    `gasUsed ${gasUsed} does not reconcile with fee ${fee} / effective gas price ${price} (tx ${receipt.hash})`);
  return {
    receipt,
    record: {
      tx_hash: receipt.hash,
      block_number: receipt.blockNumber,
      gas_used: Number(gasUsed),
      effective_gas_price_wei: price.toString(),
      fee_wei: fee.toString(),
      confirmation_ms: elapsedMs,
    },
  };
}

/** Find and decode one event from a receipt. */
function findEvent(contract, receipt, name) {
  const log = receipt.logs.map((l) => contract.interface.parseLog(l)).find((l) => l && l.name === name);
  check(log, `no ${name} event in tx ${receipt.hash}`);
  return log;
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

module.exports = { REPO_ROOT, BenchmarkAssertionError, check, median, send, findEvent, gitCommit };
