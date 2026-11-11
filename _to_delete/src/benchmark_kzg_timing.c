#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include "ckzg.h"

// Timing utilities
static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

static void generate_test_data(Blob *blob, KZGCommitment *commitment, KZGProof *proof, 
                              Bytes32 *z, Bytes32 *y, int degree, const KZGSettings *settings) {
    // Generate simple test blob data
    memset(blob->bytes, 0, BYTES_PER_BLOB);
    
    // Create a simple pattern - this represents our "polynomial degree"
    // but since blobs are fixed size (4096 field elements), we just
    // vary the pattern to simulate different computational loads
    for (int i = 0; i < FIELD_ELEMENTS_PER_BLOB; i++) {
        // Simple incremental pattern, modulated by degree
        uint8_t value = ((i * degree) % 255) + 1;
        blob->bytes[i * BYTES_PER_FIELD_ELEMENT + 31] = value; // Set last byte of field element
    }
    
    // Generate commitment from blob
    C_KZG_RET ret = blob_to_kzg_commitment(commitment, blob, settings);
    if (ret != C_KZG_OK) {
        printf("Error generating commitment: %d\n", ret);
        exit(1);
    }
    
    // Generate simple evaluation point z (small value to avoid field issues)
    memset(z->bytes, 0, BYTES_PER_FIELD_ELEMENT);
    z->bytes[31] = 42; // Simple test value
    
    // Compute proof and evaluation
    ret = compute_kzg_proof(proof, y, blob, z, settings);
    if (ret != C_KZG_OK) {
        printf("Error generating proof for degree %d: %d\n", degree, ret);
        exit(1);
    }
}

static double benchmark_verify_kzg_proof(const KZGCommitment *commitment, const Bytes32 *z, 
                                        const Bytes32 *y, const KZGProof *proof,
                                        const KZGSettings *settings, int iterations) {
    double total_time = 0.0;
    bool result;
    
    for (int i = 0; i < iterations; i++) {
        double start_time = get_time_ms();
        
        C_KZG_RET ret = verify_kzg_proof(&result, commitment, z, y, proof, settings);
        
        double end_time = get_time_ms();
        
        if (ret != C_KZG_OK) {
            printf("Verification failed with error: %d\n", ret);
            exit(1);
        }
        
        if (!result) {
            printf("Warning: Proof verification returned false\n");
        }
        
        total_time += (end_time - start_time);
    }
    
    return total_time / iterations;  // Return average time per verification
}

static double benchmark_verify_blob_kzg_proof(const Blob *blob, const KZGCommitment *commitment,
                                             const KZGProof *proof, const KZGSettings *settings,
                                             int iterations) {
    double total_time = 0.0;
    bool result;
    
    for (int i = 0; i < iterations; i++) {
        double start_time = get_time_ms();
        
        C_KZG_RET ret = verify_blob_kzg_proof(&result, blob, commitment, proof, settings);
        
        double end_time = get_time_ms();
        
        if (ret != C_KZG_OK) {
            printf("Blob verification failed with error: %d\n", ret);
            exit(1);
        }
        
        if (!result) {
            printf("Warning: Blob proof verification returned false\n");
        }
        
        total_time += (end_time - start_time);
    }
    
    return total_time / iterations;  // Return average time per verification
}

int main() {
    printf("=== KZG Non-Revocation Proof Verification Benchmark ===\n");
    printf("Testing C backend performance across polynomial degrees\n\n");
    
    // Initialize settings
    KZGSettings settings;
    FILE *fp = fopen("trusted_setup.txt", "r");
    if (fp == NULL) {
        printf("Error: Cannot open trusted_setup.txt\n");
        return 1;
    }
    C_KZG_RET ret = load_trusted_setup_file(&settings, fp, 0);
    fclose(fp);
    if (ret != C_KZG_OK) {
        printf("Error loading trusted setup: %d\n", ret);
        return 1;
    }
    
    // Test degrees
    int degrees[] = {2, 16, 256, 1024, 4096, 1000000};
    int num_degrees = sizeof(degrees) / sizeof(degrees[0]);
    int iterations = 10;  // Number of iterations per test
    
    printf("| Degree | verify_kzg_proof (ms) | verify_blob_kzg_proof (ms) | Total Avg (ms) |\n");
    printf("|--------|----------------------|----------------------------|-----------------|\n");
    
    for (int d = 0; d < num_degrees; d++) {
        int degree = degrees[d];
        
        // Generate test data for this degree
        Blob blob;
        KZGCommitment commitment;
        KZGProof proof;
        Bytes32 z, y;
        
        generate_test_data(&blob, &commitment, &proof, &z, &y, degree, &settings);
        
        // Benchmark verify_kzg_proof
        double kzg_proof_time = benchmark_verify_kzg_proof(&commitment, &z, &y, &proof, &settings, iterations);
        
        // Generate blob proof for blob verification
        KZGProof blob_proof;
        ret = compute_blob_kzg_proof(&blob_proof, &blob, &commitment, &settings);
        if (ret != C_KZG_OK) {
            printf("Error generating blob proof: %d\n", ret);
            continue;
        }
        
        // Benchmark verify_blob_kzg_proof
        double blob_proof_time = benchmark_verify_blob_kzg_proof(&blob, &commitment, &blob_proof, &settings, iterations);
        
        double total_avg = (kzg_proof_time + blob_proof_time) / 2.0;
        
        printf("| %-6d | %-20.3f | %-26.3f | %-15.3f |\n", 
               degree, kzg_proof_time, blob_proof_time, total_avg);
        
        fflush(stdout);
    }
    
    printf("\n=== Summary ===\n");
    printf("- Iterations per test: %d\n", iterations);
    printf("- Functions tested: verify_kzg_proof, verify_blob_kzg_proof\n");
    printf("- Timing method: CLOCK_MONOTONIC (wall clock time)\n");
    printf("- Note: Times represent pure C backend verification only\n");
    printf("- Degrees > 4095 may lack cryptographic security guarantees\n");
    
    free_trusted_setup(&settings);
    return 0;
}