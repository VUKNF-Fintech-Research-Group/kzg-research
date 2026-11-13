// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title PrecompileProbe
 * @notice Evaluation smoke test (eval/scripts/smoke.js). Calls an EIP-2537
 *         precompile with a caller-chosen gas allowance and reports whether the
 *         call succeeded and what it returned.
 *
 * A precompile succeeds exactly when it receives at least its price, so
 * probing with the formula price (must succeed) and the formula price minus
 * one (must fail) measures the price exactly, independent of call overhead.
 * Test-only: not used by any verifier.
 */
contract PrecompileProbe {
    error UnknownPrecompile(address precompile);

    function probe(address precompile, bytes calldata input, uint256 gasGiven)
        external
        view
        returns (bool success, bytes memory output)
    {
        if (uint160(precompile) < 0x0b || uint160(precompile) > 0x11) revert UnknownPrecompile(precompile);
        (success, output) = precompile.staticcall{gas: gasGiven}(input);
    }
}
