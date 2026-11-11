// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title MerkleRevocation
 * @notice Merkle-tree baseline for credential revocation, with a sound
 *         non-membership proof. Mirrors KZGRevocation so both can be
 *         benchmarked the same way:
 *           updateRoot()           <->  updateCommitment()
 *           verifyNonRevocation()  <->  verifyNonRevocation()
 *
 * The issuer sorts the revoked IDs, adds the sentinels 0 and MAX_ID, and
 * builds the tree over the gaps between neighbours. For sorted values
 * v_0 = 0 < v_1 < ... < v_n < v_(n+1) = MAX_ID, leaf i is the range
 * (v_i, v_(i+1)):
 *
 *     leaf = keccak256(bytes.concat(keccak256(abi.encode(lo, hi))))
 *
 * A credential `id` is not revoked exactly when some leaf (lo, hi) has
 * lo < id < hi. The holder proves this with one ordinary inclusion proof of
 * that leaf. A revoked ID equals one of the v_i, so no leaf strictly contains
 * it and no proof can pass. A failed or missing proof never counts as
 * "not revoked".
 *
 * Valid credential IDs are 1 .. MAX_ID - 1. The double hash keeps a 64-byte
 * leaf preimage from being confused with an inner node (OpenZeppelin's
 * standard leaf encoding). Inner nodes hash sorted pairs, as MerkleProof does.
 */
contract MerkleRevocation {
    /// @dev Upper sentinel: r - 1, where r is the BLS12-381 scalar field order.
    ///      Gives the same ID space as the KZG scheme.
    uint256 public constant MAX_ID = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000;

    address public immutable owner;
    bytes32 public root;

    event RootUpdated(bytes32 indexed newRoot);
    event Verified(address indexed caller, bool notRevoked, uint256 id, uint256 proofDepth);

    error OnlyOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor(bytes32 initialRoot) {
        owner = msg.sender;
        root = initialRoot;
        emit RootUpdated(initialRoot);
    }

    /// @notice Replace the root after the revoked set changes.
    function updateRoot(bytes32 newRoot) external onlyOwner {
        root = newRoot;
        emit RootUpdated(newRoot);
    }

    /// @notice Leaf hash for the gap (lo, hi) between two neighbouring revoked IDs.
    function rangeLeaf(uint256 lo, uint256 hi) public pure returns (bytes32) {
        return keccak256(bytes.concat(keccak256(abi.encode(lo, hi))));
    }

    /**
     * @notice Check that credential `id` is not revoked.
     * @param id    Credential ID.
     * @param lo    Largest revoked ID (or sentinel 0) below `id`.
     * @param hi    Smallest revoked ID (or sentinel MAX_ID) above `id`.
     * @param proof Inclusion proof of the leaf (lo, hi), sorted-pair keccak256.
     * @return True only if lo < id < hi and the leaf (lo, hi) is in the tree.
     *
     * Gas grows with proof.length, one keccak256 per tree level.
     */
    function checkNonRevocation(uint256 id, uint256 lo, uint256 hi, bytes32[] calldata proof)
        public
        view
        returns (bool)
    {
        if (!(lo < id && id < hi)) return false;
        return MerkleProof.verifyCalldata(proof, root, rangeLeaf(lo, hi));
    }

    /// @notice Same as `checkNonRevocation`, as a transaction that logs the result.
    function verifyNonRevocation(uint256 id, uint256 lo, uint256 hi, bytes32[] calldata proof)
        external
        returns (bool notRevoked)
    {
        notRevoked = checkNonRevocation(id, lo, hi, proof);
        emit Verified(msg.sender, notRevoked, id, proof.length);
    }
}
