// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title MerkleRevocation
 * @notice Merkle-tree-based credential revocation verifier.
 *
 * The contract stores a single bytes32 Merkle root that represents the
 * set of *revoked* credential identifiers.  A verifier calls
 * verifyNonRevocation(leaf, proof) to confirm that a credential is NOT
 * present in the revocation set.
 *
 * Design mirrors KZGRevocation.sol so both contracts can be benchmarked
 * under identical on-chain conditions:
 *   updateRoot()           ↔  updateCommitment()
 *   verifyNonRevocation()  ↔  verifyNonRevocation()
 *
 * Leaf encoding (must match off-chain tree builder):
 *   leafHash = keccak256(abi.encodePacked(credentialId))
 *
 * Non-revocation semantics:
 *   MerkleProof.verify(proof, root, leafHash) == true  → leaf IS in
 *   the revocation set → credential IS revoked → return false.
 *   Any other result (proof fails)                     → not revoked → return true.
 */
contract MerkleRevocation {
    address public owner;
    bytes32 public root;

    event RootUpdated(bytes32 indexed newRoot);
    event Verified(address indexed caller, bool notRevoked, bytes32 leaf, uint256 proofDepth);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(bytes32 initialRoot) {
        owner = msg.sender;
        root = initialRoot;
    }

    /**
     * @notice Replace the revocation-set Merkle root.
     * @param newRoot New root computed off-chain from the updated revocation set.
     */
    function updateRoot(bytes32 newRoot) external onlyOwner {
        root = newRoot;
        emit RootUpdated(newRoot);
    }

    /**
     * @notice Verify that a credential is NOT in the revocation set.
     * @param leaf     Raw bytes32 credential identifier.
     * @param proof    Merkle sibling path (sorted-pair, keccak256).
     * @return true if the credential is NOT revoked; false if it IS revoked.
     *
     * Gas scales with proof.length (one keccak256 per level), making this
     * O(depth) = O(log N) in the size of the revocation set.
     */
    function verifyNonRevocation(bytes32 leaf, bytes32[] calldata proof) external returns (bool) {
        bytes32 leafHash = keccak256(abi.encodePacked(leaf));
        bool inRevocationSet = MerkleProof.verify(proof, root, leafHash);
        bool notRevoked = !inRevocationSet;
        emit Verified(msg.sender, notRevoked, leaf, proof.length);
        return notRevoked;
    }
}
