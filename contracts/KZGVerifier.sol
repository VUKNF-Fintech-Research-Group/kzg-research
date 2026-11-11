// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title KZGVerifier
 * @notice Verifies a KZG opening proof on BLS12-381 with the EIP-2537
 *         precompiles (available from the Prague/Pectra hardfork).
 *
 * Statement: the polynomial committed to by C evaluates to y at z, with
 * witness w. The check is
 *
 *     e(w, [tau]_2 - z*G2) == e(C - y*G1, G2)
 *
 * Points use the EIP-2537 encoding: G1 is 128 bytes (x || y), G2 is 256 bytes
 * (x.c0 || x.c1 || y.c0 || y.c1), each coordinate a 64-byte big-endian value.
 * The precompiles reject points that are off the curve or outside the
 * prime-order subgroup, in which case these functions revert.
 *
 * [tau]_2 is the second G2 point of the EIP-4844 trusted setup
 * (src/trusted_setup.txt). test/python/test_eip2537_constants.py checks the
 * constants below against that file.
 */
library KZGVerifier {
    // EIP-2537 precompile addresses.
    address internal constant G1MSM = address(0x0c);
    address internal constant G2MSM = address(0x0e);
    address internal constant PAIRING_CHECK = address(0x0f);

    /// @dev Order r of the BLS12-381 scalar field.
    uint256 internal constant R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001;

    uint256 internal constant G1_BYTES = 128;
    uint256 internal constant G2_BYTES = 256;

    /// @dev G1 generator.
    bytes internal constant G1_GEN =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
        hex"0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";

    /// @dev G2 generator.
    bytes internal constant G2_GEN =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
        hex"000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
        hex"000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";

    /// @dev [tau]_2 from the EIP-4844 trusted setup.
    bytes internal constant TAU_G2 =
        hex"00000000000000000000000000000000185cbfee53492714734429b7b38608e23926c911cceceac9a36851477ba4c60b087041de621000edc98edada20c1def2"
        hex"0000000000000000000000000000000015bfd7dd8cdeb128843bc287230af38926187075cbfbefa81009a2ce615ac53d2914e5870cb452d2afaaab24f3499f72"
        hex"00000000000000000000000000000000014353bdb96b626dd7d5ee8599d1fca2131569490e28de18e82451a496a9c9794ce26d105941f383ee689bfbbb832a99"
        hex"000000000000000000000000000000001666c54b0a32529503432fcae0181b4bef79de09fc63671fda5ed1ba9bfa07899495346f3d7ac9cd23048ef30d0a154f";

    error PrecompileFailed(address precompile);
    error NonCanonicalScalar();
    error BadPointLength();

    /**
     * @notice Check the opening (z, y) of commitment c with witness w.
     * @dev Uses the rearranged equation
     *          e(w, [tau]_2) * e(y*G1 - C - z*w, G2) == 1
     *      which needs one 3-term G1MSM and one 2-pair pairing check, and no
     *      G2 arithmetic. Equivalent to `verifyWithG2Msm`, and cheaper.
     */
    function verify(bytes memory c, bytes memory w, uint256 z, uint256 y) internal view returns (bool) {
        _checkInputs(c, w, z, y);
        bytes memory b = _call(G1MSM, abi.encodePacked(G1_GEN, y, c, R - 1, w, R - z), G1_BYTES);
        return _pairing(abi.encodePacked(w, TAU_G2, b, G2_GEN));
    }

    /**
     * @notice Same check in its textbook form:
     *          e(w, [tau]_2 - z*G2) * e(y*G1 - C, G2) == 1
     * @dev One 2-term G1MSM, one 2-term G2MSM and one 2-pair pairing check.
     *      Kept for cross-checking and for gas comparison.
     */
    function verifyWithG2Msm(bytes memory c, bytes memory w, uint256 z, uint256 y) internal view returns (bool) {
        _checkInputs(c, w, z, y);
        bytes memory a = _call(G1MSM, abi.encodePacked(G1_GEN, y, c, R - 1), G1_BYTES);
        bytes memory d = _call(G2MSM, abi.encodePacked(TAU_G2, uint256(1), G2_GEN, R - z), G2_BYTES);
        return _pairing(abi.encodePacked(w, d, a, G2_GEN));
    }

    function _checkInputs(bytes memory c, bytes memory w, uint256 z, uint256 y) private pure {
        if (c.length != G1_BYTES || w.length != G1_BYTES) revert BadPointLength();
        if (z >= R || y >= R) revert NonCanonicalScalar();
    }

    function _pairing(bytes memory input) private view returns (bool) {
        bytes memory out = _call(PAIRING_CHECK, input, 32);
        return abi.decode(out, (uint256)) == 1;
    }

    /// @dev Call a precompile and revert unless it succeeds with exactly `outLen` bytes.
    function _call(address precompile, bytes memory input, uint256 outLen) private view returns (bytes memory out) {
        bool success;
        (success, out) = precompile.staticcall(input);
        if (!success || out.length != outLen) revert PrecompileFailed(precompile);
    }
}
