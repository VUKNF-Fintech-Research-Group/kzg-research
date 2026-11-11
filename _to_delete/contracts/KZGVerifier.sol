// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/**
 * @title KZGVerifier
 * @notice Thin on-chain wrapper that forwards a pre-serialized pairing-check input
 *         to an on-chain pairing precompile (address configured at deploy time).
 *
 * Rationale:
 * - KZG verification requires a pairing equation of the form
 *     e(A, B) == e(C, D)
 *   where A,C are G1 and B,D are G2 points (BLS12-381).
 * - Different EVM chains expose different precompiles / input encodings for pairings
 *   (and many do not expose BLS12-381 at all). This contract therefore does not
 *   attempt to parse/encode elliptic-curve points. Instead callers compute the
 *   correct input bytes for the chain's pairing precompile off-chain and supply
 *   them directly to the contract. The contract forwards the bytes to the
 *   configured precompile address and returns the boolean result.
 *
 * Usage (off-chain):
 * 1. Compute points required by the KZG check:
 *      A = C - y*G1
 *      B = G2
 *      C = proof
 *      D = srs_g2_1 - z*srs_g2_0
 * 2. Encode the pairing input bytes following the chain's precompile ABI.
 * 3. Call `verifyPairing(pairingInput)` on this contract.
 *
 * Note: This contract is intentionally tiny and gas-minimal. It only performs a
 * staticcall to the precompile and decodes the returned 32-byte boolean result.
 */
contract KZGVerifier {
    // Address of the pairing precompile on this chain
    address public immutable pairingPrecompile;

    constructor(address _pairingPrecompile) {
        require(_pairingPrecompile != address(0), "invalid precompile");
        pairingPrecompile = _pairingPrecompile;
    }

    /**
     * @notice Call the configured pairing precompile with raw, pre-encoded input bytes.
     * @param pairingInput The raw bytes formatted for the chain's pairing precompile.
     * @return ok True if the pairing check succeeded (non-zero return), false otherwise.
     */
    function verifyPairing(bytes calldata pairingInput) public view returns (bool ok) {
        (bool success, bytes memory ret) = pairingPrecompile.staticcall(pairingInput);
        require(success, "pairing precompile call failed");
        if (ret.length < 32) return false;
        uint256 v;
        assembly { v := mload(add(ret, 32)) }
        return v != 0;
    }

    /**
     * @notice Convenience function to verify a KZG pairing that has already been
     *         encoded into `pairingInput` by the caller.
     * @dev This is identical to `verifyPairing` and kept for semantic clarity.
     */
    function verifyKZGFromPairingInput(bytes calldata pairingInput) external view returns (bool) {
        return verifyPairing(pairingInput);
    }
}
