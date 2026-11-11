#!/usr/bin/env node
// ABI Encode Constructor Parameters for KZGVerifier Contract Verification
// Manual ABI encoding without external dependencies

function padHex(hex, length = 64) {
    // Remove 0x prefix if present
    hex = hex.replace(/^0x/, '');
    // Pad with zeros to reach desired length
    return hex.padStart(length, '0');
}

function encodeAddress(address) {
    // Addresses are encoded as 32-byte values with leading zeros
    return padHex(address, 64);
}

function main() {
    console.log('KZGVerifier Constructor ABI Encoding for Hoodi Network');
    console.log('='.repeat(70));
    console.log('');
    
    // Hoodi Network BLS12-381 pairing precompile address
    const pairingPrecompileAddress = '0x0000000000000000000000000000000000000012';
    
    console.log('Constructor Parameters:');
    console.log(`   Contract: KZGVerifier`);
    console.log(`   Constructor: constructor(address _pairingPrecompile)`);
    console.log(`   _pairingPrecompile: ${pairingPrecompileAddress}`);
    console.log('');
    
    // Manual ABI encoding for address parameter
    const encodedAddress = encodeAddress(pairingPrecompileAddress);
    const fullEncoded = '0x' + encodedAddress;
    
    console.log('ABI Encoded Constructor Parameters:');
    console.log(`   ${fullEncoded}`);
    console.log('');
    
    console.log('ABI Encoded (without 0x prefix):');
    console.log(`   ${encodedAddress}`);
    console.log('');
    
    // Verification breakdown
    console.log('Encoding Breakdown:');
    console.log(`   Address (${pairingPrecompileAddress}):`);
    console.log(`   └── Padded to 32 bytes: ${encodedAddress}`);
    console.log('');
    
    // Contract verification details
    console.log('Contract Verification Details:');
    console.log('   Contract Name: KZGVerifier');
    console.log('   Compiler Version: ^0.8.0 (match your deployment version)');
    console.log('   Constructor ABI: constructor(address _pairingPrecompile)');
    console.log('   Network: Hoodi Network');
    console.log('   Precompile: BLS12-381 Pairing at 0x12');
    console.log('   License: Apache-2.0');
    console.log('');
    
    // Usage instructions
    console.log('Verification Steps:');
    console.log('   1. Go to Hoodi Network block explorer');
    console.log('   2. Find your deployed contract address');
    console.log('   3. Click "Verify Contract" or similar');
    console.log('   4. Select compiler version matching deployment');
    console.log('   5. Paste contract source code');
    console.log('   6. Copy ABI encoded parameters above into constructor args');
    console.log('   7. Submit verification');
    console.log('');
    
    // Additional network examples
    console.log('Other Network Examples:');
    console.log('   Ethereum Mainnet: BLS12-381 pairing not available');
    console.log('   Polygon: Check if BLS12-381 precompile exists');
    console.log('   Custom Testnets: Use appropriate precompile address');
    console.log('');
    
    // Contract deployment info
    console.log('Deployment Context:');
    console.log('   This contract is part of KZG revocation performance testing');
    console.log('   Used for pure KZG verification via pairing precompile');
    console.log('   Enables constant-time verification (~33,380 gas)');
    console.log('   Supports polynomial degrees 2 to 1,000,000+');
    console.log('');
    
    console.log('Ready for contract verification on Hoodi Network!');
    
    return {
        fullEncoded: fullEncoded,
        withoutPrefix: encodedAddress,
        precompileAddress: pairingPrecompileAddress
    };
}

// Utility function for other precompile addresses
function encodeForAddress(address) {
    console.log(`🔧 Encoding for address: ${address}`);
    const encoded = encodeAddress(address);
    const full = '0x' + encoded;
    console.log(`   Full: ${full}`);
    console.log(`   Without 0x: ${encoded}`);
    return full;
}

// Run if called directly
if (require.main === module) {
    main();
    
    console.log('\nTesting with other common addresses:');
    console.log('   Hoodi 0x12:', encodeForAddress('0x12'));
    console.log('   Zero address:', encodeForAddress('0x0'));
}

module.exports = { main, encodeForAddress };