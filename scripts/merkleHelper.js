/**
 * merkleHelper.js
 *
 * Off-chain Merkle tree utilities for MerkleRevocation benchmarks.
 *
 * Leaf encoding matches MerkleRevocation.sol:
 *   leafHash = keccak256(abi.encodePacked(credentialId))  (bytes32 credential)
 *
 * Tree properties:
 *   - Hash function : keccak256
 *   - Pair sorting  : sorted (smaller hash first) – matches OZ MerkleProof.sol
 */

const { MerkleTree } = require("merkletreejs");
const { ethers } = require("hardhat");

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * keccak256 wrapper that accepts a Buffer and returns a Buffer.
 * merkletreejs requires this calling convention.
 */
function keccakBuf(data) {
  const hex = ethers.keccak256(data);
  return Buffer.from(hex.slice(2), "hex");
}

/**
 * Hash a bytes32 leaf exactly as MerkleRevocation.sol does:
 *   keccak256(abi.encodePacked(bytes32))
 * For a bytes32 value, abi.encodePacked produces the raw 32 bytes.
 */
function hashLeaf(leafHex) {
  return keccakBuf(leafHex);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build a Merkle tree from an array of bytes32 credential identifiers.
 *
 * @param {string[]} leaves  Array of 0x-prefixed bytes32 hex strings.
 * @returns {{ root: string, tree: MerkleTree }}
 */
function buildTree(leaves) {
  const hashedLeaves = leaves.map(hashLeaf);
  const tree = new MerkleTree(hashedLeaves, keccakBuf, { sortPairs: true });
  return {
    root: "0x" + tree.getRoot().toString("hex"),
    tree,
  };
}

/**
 * Return the Merkle inclusion proof for a leaf that IS in the tree.
 *
 * @param {MerkleTree} tree
 * @param {string}     leaf  0x-prefixed bytes32.
 * @returns {string[]}       Array of 0x-prefixed bytes32 sibling hashes.
 */
function getProof(tree, leaf) {
  const hashed = hashLeaf(leaf);
  return tree.getProof(hashed).map((x) => "0x" + x.data.toString("hex"));
}

/**
 * Return a proof suitable for testing that queryLeaf is NOT in revokedLeaves.
 *
 * OZ MerkleProof supports inclusion proofs only.  For a credential that is
 * not in the revocation set there is no valid inclusion proof; instead we
 * return a dummy proof of the correct depth (tree.getDepth() elements, all
 * zero-bytes).  MerkleProof.verify() will hash through all depth elements
 * but arrive at a different root, confirming non-inclusion.  Gas is therefore
 * O(depth) – identical to a valid inclusion proof at the same depth.
 *
 * @param {MerkleTree} tree
 * @param {string[]}   revokedLeaves  (unused – depth comes from tree)
 * @param {string}     queryLeaf      Leaf known to be absent from the tree.
 * @returns {string[]}                Dummy proof of correct depth.
 */
function getRevocationProof(tree, revokedLeaves, queryLeaf) {
  const depth = tree.getDepth();
  return Array(depth).fill(ethers.ZeroHash);
}

module.exports = { buildTree, getProof, getRevocationProof };
