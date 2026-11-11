// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {KZGVerifier} from "../KZGVerifier.sol";

/// @notice Test-only wrapper that exposes both KZGVerifier variants.
contract KZGVerifierHarness {
    function verify(bytes calldata c, bytes calldata w, uint256 z, uint256 y) external view returns (bool) {
        return KZGVerifier.verify(c, w, z, y);
    }

    function verifyWithG2Msm(bytes calldata c, bytes calldata w, uint256 z, uint256 y) external view returns (bool) {
        return KZGVerifier.verifyWithG2Msm(c, w, z, y);
    }
}
