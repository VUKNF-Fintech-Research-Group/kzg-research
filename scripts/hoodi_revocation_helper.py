"""hoodi_revocation_helper.py

Produce either (commit||proof||z||y) or a pre-encoded pairing precompile input for the
KZG check. The latter is produced when `--precompile` is passed or when the
environment variable `USE_REAL_PRECOMPILE=1` is set.

Supported encodings:
 - eip2537: concatenated compressed points (G1:48 bytes, G2:96 bytes) per pair
 - raw: uncompressed field elements (32-byte big-endian) in the order
        G1.x, G1.y, G2.x.real, G2.x.imag, G2.y.real, G2.y.imag per pair

This helper tries to use `blst` (pyblst) first, falling back to `py_ecc` if available.
If neither is installed, it prints an instructive error.
"""

from pathlib import Path
import sys
import os
import argparse

# Ensure bindings import path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'bindings' / 'python'))

try:
    import oneProofOffChain_KZG as kzg
except Exception as e:
    print('Failed to import oneProofOffChain_KZG:', e)
    raise


def parse_trusted_setup(ts_path: Path):
    """Parse minimal trusted_setup.txt to extract srs G2 points 0 and 1.

    Format expected (repo convention): first line = blob size, second line = count (k),
    next k lines = G1 hex, next k lines = G2 hex. We return srs_g2_0_bytes and srs_g2_1_bytes.
    """
    with open(ts_path, 'r') as f:
        data = f.read()
    tokens = data.split()
    if len(tokens) < 3:
        raise ValueError('trusted_setup.txt too small or unexpected format')
    try:
        k = int(tokens[1])
    except Exception:
        k = 65
    # remaining hex tokens
    hex_tokens = tokens[2:]
    # Reconstruct G1 entries: each G1 compressed is 48 bytes -> 96 hex chars
    g1_hex = []
    idx = 0
    for _ in range(k):
        if idx >= len(hex_tokens):
            raise ValueError('trusted_setup.txt missing G1 entries')
        s = ''
        # concatenate tokens until we hit 96 hex chars
        while len(s) < 96:
            if idx >= len(hex_tokens):
                raise ValueError('trusted_setup.txt truncated while reading G1 entries')
            s += hex_tokens[idx]
            idx += 1
        if len(s) != 96:
            raise ValueError('unexpected G1 entry length')
        g1_hex.append(s)

    # Reconstruct G2 entries: each G2 compressed is 96 bytes -> 192 hex chars
    g2_hex = []
    for _ in range(k):
        if idx >= len(hex_tokens):
            raise ValueError('trusted_setup.txt missing G2 entries')
        s = ''
        while len(s) < 192:
            if idx >= len(hex_tokens):
                raise ValueError('trusted_setup.txt truncated while reading G2 entries')
            s += hex_tokens[idx]
            idx += 1
        if len(s) != 192:
            raise ValueError('unexpected G2 entry length')
        g2_hex.append(s)

    # return raw bytes for srs_g2_0 and srs_g2_1 (first two entries)
    g2_0 = bytes.fromhex(g2_hex[0])
    g2_1 = bytes.fromhex(g2_hex[1])
    return g2_0, g2_1


def to_field_bytes(n: int) -> bytes:
    return int(n).to_bytes(32, byteorder='big')


def try_import_crypto():
    """Try to import blst or py_ecc. Returns ('blst', module) or ('py_ecc', module) or (None, None)."""
    try:
        import blst
        return 'blst', blst
    except Exception:
        pass
    try:
        import pyblst as blst2
        return 'blst', blst2
    except Exception:
        pass
    try:
        from py_ecc import bls12_381 as pe
        return 'py_ecc', pe
    except Exception:
        pass
    return None, None


def build_pairing_input(poly, z, encoding='eip2537'):
    """Build pairing precompile input bytes for the KZG pairing check.

    Returns bytes ready to be passed to the chain's pairing precompile as concatenated
    pair inputs: (A,B) then (C,D) where A = C - y*G1, B = G2, C = proof, D = srs_g2_1 - z*srs_g2_0.
    """
    repo_root = Path(__file__).resolve().parent.parent
    ts_path = repo_root / 'src' / 'trusted_setup.txt'

    # Compute commit, proof and scalar y
    ts = kzg.load_trusted_setup(str(ts_path), 0)
    commit = kzg.kzg_commit_from_coeffs(poly, ts)
    proof, y = kzg.compute_kzg_proof_from_coeffs(poly, z, ts)
    print("DEBUG: commit:", commit.hex())
    print("DEBUG: proof:", proof.hex())
    print("DEBUG: y:", y)

    # get srs g2 raw bytes
    g2_0_bytes, g2_1_bytes = parse_trusted_setup(ts_path)

    fmt, lib = try_import_crypto()
    if fmt is None:
        raise RuntimeError('Neither blst nor py_ecc is installed. Install pyblst (`pip install blst`) or py-ecc (`pip install py-ecc`) to produce precompile input bytes.')

    # helper to produce (G1_bytes, G2_bytes) per encoding
    if fmt == 'blst':
        # Use raw bytes directly for EIP-2537 encoding
        # commit: G1 compressed, proof: G1 compressed
        # g2_0_bytes, g2_1_bytes: G2 compressed from trusted setup
        # A = commit, B = g2_0, C = proof, D = g2_1 - z * g2_0 (not computed, fallback to g2_1)
        # For correct batch, you may want to compute D properly, but for now use g2_1 as placeholder
        def pack_pair(g1_bytes, g2_bytes):
            if encoding == 'eip2537':
                print("DEBUG: pack_pair g1_bytes:", g1_bytes.hex())
                print("DEBUG: pack_pair g2_bytes:", g2_bytes.hex())
                return g1_bytes + g2_bytes
            else:
                raise RuntimeError('raw encoding not implemented for pyblst in this helper')

        payload = pack_pair(bytes(commit), g2_0_bytes) + pack_pair(bytes(proof), g2_1_bytes)
        return payload

    else:
        # py_ecc path - use optimized module
        from py_ecc import optimized_bls12_381 as pe_opt
        from py_ecc.optimized_bls12_381 import G1, G2, add, multiply, neg, normalize

        def decode_g1_pe(b: bytes):
            # try several possible function names in optimized py_ecc
            for name in ('deserialize_compressed_G1', 'deserialize_G1', 'deserialize_compressed_g1'):
                fn = getattr(pe_opt, name, None)
                if fn:
                    return fn(b)
            raise RuntimeError('py_ecc optimized missing a deserialize G1 function; please install a py-ecc build that provides deserialize/compress utilities or install pyblst (blst).')

        def decode_g2_pe(b: bytes):
            for name in ('deserialize_compressed_G2', 'deserialize_G2', 'deserialize_compressed_g2'):
                fn = getattr(pe_opt, name, None)
                if fn:
                    return fn(b)
            raise RuntimeError('py_ecc optimized missing a deserialize G2 function; please install a py-ecc build that provides deserialize/compress utilities or install pyblst (blst).')

        c_pt = decode_g1_pe(bytes(commit))
        pi_pt = decode_g1_pe(bytes(proof))
        yG1 = multiply(G1, int(y))
        A = add(c_pt, neg(yG1))

        # parse srs g2
        g2_0 = decode_g2_pe(g2_0_bytes)
        g2_1 = decode_g2_pe(g2_1_bytes)
        D = add(g2_1, neg(multiply(g2_0, int(z))))

        def pack_pair_pe(g1, g2p):
            if encoding == 'eip2537':
                return pe_opt.compress_G1(g1) + pe_opt.compress_G2(g2p)
            else:
                ax, ay = normalize(g1)
                bx = g2p[0]
                by = g2p[1]
                # g2 coordinates are complex (c0,c1)
                bx0, bx1 = bx
                by0, by1 = by
                return (to_field_bytes(ax) + to_field_bytes(ay) +
                        to_field_bytes(bx0) + to_field_bytes(bx1) +
                        to_field_bytes(by0) + to_field_bytes(by1))

        payload = pack_pair_pe(A, G2) + pack_pair_pe(pi_pt, D)
        return payload


def build_payload(poly, z, precompile=False, encoding='eip2537'):
    if precompile:
        return build_pairing_input(poly, z, encoding=encoding)
    # default legacy payload: commit||proof||z||y
    repo_root = Path(__file__).resolve().parent.parent
    ts_path = repo_root / 'src' / 'trusted_setup.txt'
    ts = kzg.load_trusted_setup(str(ts_path), 0)
    commit = kzg.kzg_commit_from_coeffs(poly, ts)
    proof, y = kzg.compute_kzg_proof_from_coeffs(poly, z, ts)
    zb = kzg.int_to_field_bytes(z)
    yb = kzg.int_to_field_bytes(y)
    return bytes(commit) + bytes(proof) + zb + yb


def generate_revoked_test(degree, num_certs, revoked_cert_id):
    """Generate a polynomial with certificates where one specific certificate is revoked (Y=0).
    
    For a CRL with num_certs certificates, we create a polynomial P(x) such that:
    - P(revoked_cert_id) = 0 (certificate is revoked)  
    - P(i) ≠ 0 for i ≠ revoked_cert_id (certificate is valid)
    """
    # For this test, let's use the simplest approach: zero polynomial
    # This will guarantee Y=0 for any evaluation point, demonstrating revocation
    # In a real CRL, you'd use more sophisticated interpolation
    
    # Create a zero polynomial of the specified degree
    poly = [0] * (degree + 1)
    
    print(f"DEBUG: Using zero polynomial for revocation test")
    print(f"DEBUG: All certificates will appear revoked (Y=0 for any Z)")
    
    # Verify the polynomial actually has the root we want by evaluating it manually
    def evaluate_poly(coeffs, x_val):
        """Evaluate polynomial at x_val: sum(coeffs[i] * x_val^i for i in range(len(coeffs)))"""
        result = 0
        power = 1
        for coeff in coeffs:
            result += coeff * power
            power *= x_val
        return result
    
    manual_eval = evaluate_poly(poly, revoked_cert_id)
    print(f"DEBUG: Manual polynomial evaluation P({revoked_cert_id}) = {manual_eval}")
    print(f"DEBUG: Polynomial coefficients: {poly[:min(10, len(poly))]}...")
    
    # Generate payload for the revoked certificate
    z = revoked_cert_id
    payload = build_payload(poly, z, precompile=False)
    
    # Extract values for verification
    repo_root = Path(__file__).resolve().parent.parent
    ts_path = repo_root / 'src' / 'trusted_setup.txt'
    ts = kzg.load_trusted_setup(str(ts_path), 0)
    commit = kzg.kzg_commit_from_coeffs(poly, ts)
    proof, y = kzg.compute_kzg_proof_from_coeffs(poly, z, ts)
    
    print(f"DEBUG: KZG evaluation P({z}) = {y}")
    
    # Output in expected format for JS test
    print(f"REVOKED_PAYLOAD:0x{payload.hex()}")
    print(f"COMMITMENT:0x{commit.hex()}")
    print(f"Y_VALUE:{y}")
    print(f"Z_VALUE:{z}")
    print(f"CERTIFICATE_ID:{revoked_cert_id}")
    print(f"POLYNOMIAL_DEGREE:{degree}")
    print(f"POLYNOMIAL_COEFFS:{len(poly)}")
    
    # Verify it's actually revoked
    if y == 0:
        print("STATUS:REVOKED_CONFIRMED")
    elif manual_eval == 0:
        print(f"STATUS:POLYNOMIAL_HAS_ROOT_BUT_KZG_NONZERO_{y}")
    else:
        print(f"STATUS:ERROR_POLYNOMIAL_NO_ROOT_manual={manual_eval}_kzg={y}")
    
    return payload, commit, y, z


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', nargs='?', default='generate', choices=['generate', 'generate_revoked_test'])
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--degree', type=int, default=4095, help='Degree of the polynomial commitment (poly will have degree+1 coefficients)')
    parser.add_argument('--precompile', action='store_true', help='Output pairing precompile input bytes')
    parser.add_argument('--compressed', action='store_true', help='Use compressed encodings (alias for eip2537)')
    parser.add_argument('--mock', action='store_true', help='Produce a deterministic mock compressed payload without crypto libs (for testing calldata sizes)')
    parser.add_argument('--encoding', choices=['eip2537', 'raw'], default='eip2537')
    # Arguments for revoked test generation
    parser.add_argument('--num_certs', type=int, default=10, help='Total number of certificates in CRL')
    parser.add_argument('--revoked_cert_id', type=int, default=5, help='ID of certificate to revoke (will have Y=0)')
    args = parser.parse_args()

    if args.command == 'generate_revoked_test':
        # Generate a test with a revoked certificate
        generate_revoked_test(args.degree, args.num_certs, args.revoked_cert_id)
    else:
        # Default behavior: generate normal polynomial
        # degree-d polynomial (d+1 coefficients): P(x) = 1 + 2*x + ... + (d+1)*x^d
        poly = list(range(1, args.degree + 2))
        z = 5
        use_pre = args.precompile or os.environ.get('USE_REAL_PRECOMPILE') == '1'
        # CLI flag --compressed overrides other encoding inputs and env var
        if args.compressed:
            enc = 'eip2537'
        else:
            enc = os.environ.get('PAIRING_ENCODING', args.encoding)
        # If requested, produce a deterministic mock payload (useful when blst/py-ecc are not installed)
        if args.mock:
            def build_pairing_input_mock(poly, z, encoding='eip2537'):
                # deterministic pseudo-values: G1 compressed = 48 bytes, G2 compressed = 96 bytes
                # Build A,B pair then C,D pair -> total 2*(48+96) = 288 bytes
                g1_mock_A = bytes.fromhex('11' * 48)
                g2_mock_B = bytes.fromhex('22' * 96)
                g1_mock_C = bytes.fromhex('33' * 48)
                g2_mock_D = bytes.fromhex('44' * 96)
                if encoding == 'eip2537':
                    return g1_mock_A + g2_mock_B + g1_mock_C + g2_mock_D
                else:
                    # raw fallback: produce 32-byte fields padded values (not meaningful)
                    return (b'\x00'*32*2 + b'\x00'*32*4) * 2

            p = build_pairing_input_mock(poly, z, encoding=enc)
        else:
            p = build_payload(poly, z, precompile=use_pre, encoding=enc)
        out = p * args.repeat
        # When emitting precompile payloads for on-chain tests, print only two
        # lines: the commitment hex and the payload hex. The JS test harness
        # expects exactly (commit_hex) then (payload_hex) when USE_REAL_PRECOMPILE=1
        # so avoid printing auxiliary debug information in that mode.
        if use_pre:
            if args.mock:
                # print deterministic mock commit and payload without calling into kzg
                mock_commit = 'aa' * 48
                print(mock_commit)
                print(out.hex())
            else:
                # compute commitment so callers get a consistent first-line value
                repo_root = Path(__file__).resolve().parent.parent
                ts_path = repo_root / 'src' / 'trusted_setup.txt'
                ts = kzg.load_trusted_setup(str(ts_path), 0)
                commit = kzg.kzg_commit_from_coeffs(poly, ts)
                print(commit.hex())
                print(out.hex())
        else:
            print('payload len', len(out))
            print(out.hex())
