// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

/**
 * @title AlwaysTruePairing
 * @notice Gas-benchmark mock: accepts any input and returns abi.encode(true).
 *
 * Used in the updateCommitment / verifyNonRevocation gas sweep so that
 * verifyNonRevocation() executes all its own contract logic without
 * requiring the BLS12-381 pairing precompile, which is unavailable on
 * the Hardhat in-process network.
 *
 * The measured gas figures therefore reflect only the Solidity contract
 * overhead (calldata, keccak256 commitment check, call, event); the
 * precompile cost (~43 k gas on Hoodi) is intentionally excluded and
 * documented separately.
 */
contract AlwaysTruePairing {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(true);
    }
}
