// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {KZGVerifier} from "./KZGVerifier.sol";

/**
 * @title KZGRevocation
 * @notice Credential revocation registry based on a KZG polynomial commitment.
 *
 * The issuer commits to f(x) = prod(x - id) over the revoked IDs and stores
 * the commitment C. A holder of credential z shows it is not revoked by
 * opening f at z to a value y != 0, with witness w. The opening is verified
 * on-chain against the stored C with the EIP-2537 precompiles.
 *
 * C is stored in the uncompressed EIP-2537 form (128 bytes), because the
 * precompiles do not accept compressed points. The compressed form is 48 bytes.
 */
contract KZGRevocation {
    address public immutable owner;

    /// @notice Current commitment C, 128-byte EIP-2537 G1 encoding.
    bytes public commitment;

    event CommitmentUpdated(bytes commitment);
    event Verified(address indexed caller, bool ok, uint256 z, uint256 y);

    error OnlyOwner();
    error BadCommitmentLength();

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    constructor(bytes memory initialCommitment) {
        if (initialCommitment.length != KZGVerifier.G1_BYTES) revert BadCommitmentLength();
        owner = msg.sender;
        commitment = initialCommitment;
        emit CommitmentUpdated(initialCommitment);
    }

    /// @notice Replace the commitment after the revoked set changes.
    function updateCommitment(bytes calldata newC) external onlyOwner {
        if (newC.length != KZGVerifier.G1_BYTES) revert BadCommitmentLength();
        commitment = newC;
        emit CommitmentUpdated(newC);
    }

    /**
     * @notice Check that credential z is not revoked.
     * @param w Witness (KZG proof), 128-byte EIP-2537 G1 encoding.
     * @param z Credential ID, a canonical scalar (z < r).
     * @param y Claimed value f(z), a canonical scalar (y < r).
     * @return True only if the opening verifies against the stored commitment
     *         and y != 0. A revoked ID has f(z) = 0, so it cannot pass.
     *
     * Reverts on non-canonical scalars, malformed points, or a failing
     * precompile call.
     */
    function checkNonRevocation(bytes calldata w, uint256 z, uint256 y) public view returns (bool) {
        bool opens = KZGVerifier.verify(commitment, w, z, y);
        return opens && y != 0;
    }

    /// @notice Same as `checkNonRevocation`, as a transaction that logs the result.
    function verifyNonRevocation(bytes calldata w, uint256 z, uint256 y) external returns (bool ok) {
        ok = checkNonRevocation(w, z, y);
        emit Verified(msg.sender, ok, z, y);
    }
}
