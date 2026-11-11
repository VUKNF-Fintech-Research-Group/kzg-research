// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.19;

/**
 * @title KZGVerifier
 * @notice Thin on-chain wrapper that forwards a pre-serialized pairing-check input
 *         to an on-chain pairing precompile (address configured at deploy time).
 */
contract KZGVerifier {
    // Address of the pairing precompile on this chain
    address public immutable pairingPrecompile;

    constructor(address _pairingPrecompile) {
        require(_pairingPrecompile != address(0), "invalid precompile");
        pairingPrecompile = _pairingPrecompile;
    }

    function verifyPairing(bytes calldata pairingInput) public view returns (bool ok) {
        (bool success, bytes memory ret) = pairingPrecompile.staticcall(pairingInput);
        require(success, "pairing precompile call failed");
        if (ret.length < 32) return false;
        uint256 v;
        assembly { v := mload(add(ret, 32)) }
        return v != 0;
    }

    function verifyKZGFromPairingInput(bytes calldata pairingInput) external view returns (bool) {
        return verifyPairing(pairingInput);
    }

    event VerifyResult(bool ok, uint256 gasUsed);

    /**
     * @notice Transactional variant that calls the precompile (non-static) so gas can be measured.
     * @return ok True if the precompile returned a non-zero 32-byte result.
     */
    function verifyKZGFromPairingInputTx(bytes calldata pairingInput) external returns (bool ok) {
        uint256 gasBefore = gasleft();
        (bool success, bytes memory ret) = pairingPrecompile.call(pairingInput);
        uint256 gasAfter = gasleft();
        uint256 used = gasBefore - gasAfter;
        bool res = false;
        if (success && ret.length >= 32) {
            uint256 v;
            assembly { v := mload(add(ret, 32)) }
            res = v != 0;
        }
        emit VerifyResult(res, used);
        return res;
    }
}