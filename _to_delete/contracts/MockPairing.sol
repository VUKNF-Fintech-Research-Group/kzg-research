// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/**
 * @title MockPairing
 * @notice Simple contract that stores an expected bytes payload and returns true
 * when `check(input)` is called with identical bytes. This is useful for end-to-end
 * testing of the `KZGVerifier` contract in environments that lack a native pairing precompile.
 */
contract MockPairing {
    address public owner;
    bytes public expected;

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setExpected(bytes calldata b) external onlyOwner {
        expected = b;
    }

    /**
     * @notice Emulate a pairing precompile by checking whether the supplied input
     *         equals the expected byte sequence.
     * @param input Raw bytes supplied by caller (intended to be pairing precompile input)
     * @return ok True if input == expected.
     */
    function check(bytes calldata input) external view returns (bool ok) {
        if (input.length != expected.length) return false;
        // compare 32-byte words for gas efficiency
        uint256 len = input.length;
        uint256 i = 0;
        for (; i + 32 <= len; i += 32) {
            bytes32 a;
            bytes32 b;
            assembly {
                a := calldataload(add(input.offset, i))
                b := calldataload(add(expected.offset, i))
            }
            if (a != b) return false;
        }
        // remaining tail
        for (uint256 j = i; j < len; j++) {
            if (input[j] != expected[j]) return false;
        }
        return true;
    }
}
