"""KZG Helper Functions for Public Research Repository

Provides KZG proof generation and verification utilities.
Note: Update paths and configurations for your environment.
"""

import sys
from pathlib import Path

# Add Python bindings to path
# Update this path to match your installation
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'bindings' / 'python'))

try:
    import oneProofOffChain_KZG as kzg
except ImportError as e:
    print(f'Error: Cannot import KZG bindings: {e}')
    print('Please ensure Python bindings are properly installed')
    sys.exit(1)

def load_trusted_setup(setup_path='../src/trusted_setup.txt'):
    """Load trusted setup from file."""
    return kzg.load_trusted_setup(str(Path(setup_path).resolve()), 0)

def generate_kzg_proof(polynomial_coeffs, evaluation_point, trusted_setup):
    """Generate KZG proof for polynomial at evaluation point."""
    proof, y_value = kzg.compute_kzg_proof_from_coeffs(
        polynomial_coeffs, evaluation_point, trusted_setup
    )
    return proof, y_value

def generate_commitment(polynomial_coeffs, trusted_setup):
    """Generate KZG commitment for polynomial."""
    return kzg.kzg_commit_from_coeffs(polynomial_coeffs, trusted_setup)

# Example usage
if __name__ == "__main__":
    print("KZG Helper Functions Loaded")
    print("Use these functions to generate proofs and commitments")
    print("Update paths and configurations for your environment")
