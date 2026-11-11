// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.19;

contract KZGRevocationFixed {
    address public owner;
    bytes public commitment; // stored commitment C (48 bytes)
    address public pairing;

    event CommitmentUpdated(bytes commitment);
    event Verified(address indexed caller, bool ok, bytes commitment, bytes proof, bytes z, bytes y);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor(address pairingAddr, bytes memory initialCommitment) {
        owner = msg.sender;
        pairing = pairingAddr;
        commitment = initialCommitment;
    }

    function updateCommitment(bytes memory newC) external onlyOwner {
        commitment = newC;
        emit CommitmentUpdated(newC);
    }

    // verify a single evaluation proof (compact form: commit||proof||z||y)
    // Returns true if proof verifies AND y != 0 (i.e., not revoked)
    // SECURITY FIX: Now verifies that payload commitment matches stored commitment
    function verifyNonRevocation(bytes calldata payload) external returns (bool) {
        // payload expected: commit(48) || proof(48) || z(32) || y(32)
        require(payload.length >= 160, "payload too small");
        
        // SECURITY FIX: Extract commitment from payload and verify it matches stored commitment
        require(keccak256(payload[0:48]) == keccak256(commitment), "commitment mismatch");
        
        // forward raw payload bytes to the pairing address
        (bool success, bytes memory ret) = pairing.call(payload);
        bool ok = success && ret.length >= 32 && abi.decode(ret, (bool));
        
        // extract y
        bytes32 y;
        assembly {
            y := calldataload(add(payload.offset, 128))
        }
        
        bool notRevoked = ok && (y != bytes32(0));
        
        // Emit event with extracted payload components
        emit Verified(msg.sender, notRevoked, commitment, payload[48:96], payload[96:128], payload[128:160]);
        
        return notRevoked;
    }
}