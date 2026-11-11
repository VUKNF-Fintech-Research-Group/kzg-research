/**
 * merkleHelper.js
 *
 * Off-chain tree builder for MerkleRevocation.sol (sorted "range leaf" tree
 * with real non-membership proofs).
 *
 * The revoked IDs are sorted and bracketed by the sentinels 0 and MAX_ID.
 * Leaf i is the gap between neighbours:
 *
 *     leaf = keccak256(keccak256(abi.encode(lo, hi)))
 *
 * `id` is not revoked exactly when some leaf has lo < id < hi; the proof is
 * the ordinary inclusion proof of that leaf.
 *
 * Tree: keccak256, sorted pairs (matches OpenZeppelin MerkleProof).
 */

const { MerkleTree } = require("merkletreejs");
const { ethers } = require("ethers");

/** r - 1 for the BLS12-381 scalar field order r. Must equal MerkleRevocation.MAX_ID. */
const MAX_ID = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000n;

const coder = ethers.AbiCoder.defaultAbiCoder();

function keccakBuf(data) {
  return Buffer.from(ethers.keccak256(data).slice(2), "hex");
}

/** Leaf hash of the range (lo, hi), as MerkleRevocation.rangeLeaf computes it. */
function rangeLeaf(lo, hi) {
  return keccakBuf(ethers.keccak256(coder.encode(["uint256", "uint256"], [lo, hi])));
}

/**
 * Build the revocation tree.
 *
 * @param {(bigint|number|string)[]} revokedIds  IDs in 1 .. MAX_ID - 1, no duplicates.
 * @returns {{ root: string, tree: MerkleTree, bounds: bigint[], depth: number }}
 *   bounds = [0, ...sorted revoked IDs, MAX_ID]; leaf i covers (bounds[i], bounds[i+1]).
 */
function buildRevocationTree(revokedIds) {
  const sorted = revokedIds.map((v) => BigInt(v)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (let i = 0; i < sorted.length; i++) {
    if (sorted[i] <= 0n || sorted[i] >= MAX_ID) throw new Error(`revoked ID ${sorted[i]} is outside 1 .. MAX_ID - 1`);
    if (i > 0 && sorted[i] === sorted[i - 1]) throw new Error(`duplicate revoked ID ${sorted[i]}`);
  }
  const bounds = [0n, ...sorted, MAX_ID];
  const leaves = [];
  for (let i = 0; i + 1 < bounds.length; i++) leaves.push(rangeLeaf(bounds[i], bounds[i + 1]));
  const tree = new MerkleTree(leaves, keccakBuf, { sortPairs: true });
  return { root: "0x" + tree.getRoot().toString("hex"), tree, bounds, depth: tree.getDepth() };
}

/** Index i of the last bound that is <= id (binary search). */
function lowerNeighbourIndex(bounds, id) {
  let lo = 0;
  let hi = bounds.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (bounds[mid] <= id) lo = mid; else hi = mid - 1;
  }
  return lo;
}

function isRevoked(revocationTree, id) {
  id = BigInt(id);
  const { bounds } = revocationTree;
  return bounds[lowerNeighbourIndex(bounds, id)] === id && id !== 0n && id !== MAX_ID;
}

/** Inclusion proof for the range leaf at index i. */
function proofForLeaf(revocationTree, i) {
  const { tree, bounds } = revocationTree;
  const lo = bounds[i];
  const hi = bounds[i + 1];
  const proof = tree.getProof(rangeLeaf(lo, hi), i).map((p) => "0x" + p.data.toString("hex"));
  return { lo, hi, proof };
}

/**
 * Non-revocation proof for `id`.
 *
 * @returns {{ lo: bigint, hi: bigint, proof: string[] }} arguments for
 *          MerkleRevocation.verifyNonRevocation(id, lo, hi, proof)
 * @throws if `id` is revoked or out of range: no such proof exists.
 */
function getNonRevocationProof(revocationTree, id) {
  id = BigInt(id);
  if (id <= 0n || id >= MAX_ID) throw new Error(`ID ${id} is outside 1 .. MAX_ID - 1`);
  if (isRevoked(revocationTree, id)) throw new Error(`ID ${id} is revoked: no non-revocation proof exists`);
  return proofForLeaf(revocationTree, lowerNeighbourIndex(revocationTree.bounds, id));
}

module.exports = { MAX_ID, rangeLeaf, buildRevocationTree, getNonRevocationProof, proofForLeaf, isRevoked };
