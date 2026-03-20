#ifndef QUANTUM_KYBER_HPP
#define QUANTUM_KYBER_HPP

#include <oqs/oqs.h>
#include <vector>
#include <utility>
#include <stdexcept>
#include <cstdint>
#include <string>

// ============================================================================
// QuantumWrapper - ML-KEM (FIPS 203) key encapsulation
//   liboqs macro: OQS_KEM_alg_kyber_512 (pre-rename build)
//   NIST standard: ML-KEM-512
// ============================================================================
class QuantumWrapper {
private:
    OQS_KEM* kem;
    std::vector<uint8_t> stored_public_key;
    std::vector<uint8_t> stored_secret_key;
    
public:
    // Constructor: initializes ML-KEM with given algorithm (default: ML-KEM-512)
    QuantumWrapper(const char* alg_name = OQS_KEM_alg_kyber_512);
    
    // Destructor: cleans up KEM resources
    ~QuantumWrapper();
    
    // Generates a keypair and returns (public_key, secret_key)
    // FIPS 203 ML-KEM KeyGen
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_keypair();
    
    // Encapsulates: generates ciphertext and shared secret using public key
    // FIPS 203 ML-KEM Encaps
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(const std::vector<uint8_t>& public_key);
    
    // Decapsulates: recovers shared secret using ciphertext and secret key
    // FIPS 203 ML-KEM Decaps
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& secret_key);
    
    // Save keys to files (creates .pub and .priv files)
    bool save_keys(const std::string& filename_prefix);
    
    // Load keys from files (reads .pub and .priv files)
    bool load_keys(const std::string& filename_prefix);
    
    // Get stored public key
    std::vector<uint8_t> get_public_key() const { return stored_public_key; }
    
    // Get stored secret key
    std::vector<uint8_t> get_secret_key() const { return stored_secret_key; }
};

// ============================================================================
// DilithiumWrapper - ML-DSA (FIPS 204) Digital Signatures
//   liboqs macro: OQS_SIG_alg_ml_dsa_65
//   NIST standard: ML-DSA-65 (security level 3)
// ============================================================================
class DilithiumWrapper {
private:
    OQS_SIG* sig;
    std::vector<uint8_t> stored_public_key;
    std::vector<uint8_t> stored_secret_key;
    
public:
    // Constructor: initializes ML-DSA signature scheme (default: ML-DSA-65)
    DilithiumWrapper(const char* alg_name = OQS_SIG_alg_ml_dsa_65);
    
    // Destructor: cleans up signature resources
    ~DilithiumWrapper();
    
    // Generate an ML-DSA signature keypair and returns (public_key, secret_key)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_signature_keypair();
    
    // Sign a message using the stored secret key (ML-DSA Sign)
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message);
    
    // Sign a message using a provided secret key (ML-DSA Sign)
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message, const std::vector<uint8_t>& secret_key);
    
    // Verify a signature using the stored public key (ML-DSA Verify)
    bool verify_signature(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature);
    
    // Verify a signature using a provided public key (ML-DSA Verify)
    bool verify_signature(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, 
                          const std::vector<uint8_t>& public_key);
    
    // Save signature keys to files (creates .sig.pub and .sig.priv files)
    bool save_keys(const std::string& filename_prefix);
    
    // Load signature keys from files
    bool load_keys(const std::string& filename_prefix);
    
    // Get stored public key
    std::vector<uint8_t> get_public_key() const { return stored_public_key; }
    
    // Get stored secret key
    std::vector<uint8_t> get_secret_key() const { return stored_secret_key; }
    
    // Get maximum signature length
    size_t get_signature_length() const;
};

// ============================================================================
// SphincsPlusWrapper - SLH-DSA (FIPS 205) Stateless Hash-Based Signatures
//   liboqs algorithm: "SPHINCS+-SHA2-128f-simple" (fast, level 1)
//   NIST standard:    SLH-DSA (FIPS 205)
//
// Use case: stateless alternative to ML-DSA when side-channel resistance
// and conservative security assumptions (hash-based) are required.
// Trade-off: larger signatures (~17 KB) vs ML-DSA (~3 KB).
// ============================================================================
class SphincsPlusWrapper {
private:
    OQS_SIG* sig;
    std::vector<uint8_t> stored_public_key;
    std::vector<uint8_t> stored_secret_key;

public:
    // Constructor: initializes SLH-DSA signature scheme
    // Supported variants: "SPHINCS+-SHA2-128f-simple" (fast, level 1)
    //                     "SPHINCS+-SHA2-192f-simple" (fast, level 3)
    //                     "SPHINCS+-SHA2-256f-simple" (fast, level 5)
    //                     "SPHINCS+-SHA2-128s-simple" (small sigs, level 1)
    SphincsPlusWrapper(const char* alg_name = "SPHINCS+-SHA2-128f-simple");

    ~SphincsPlusWrapper();

    // Generate an SLH-DSA signature keypair → (public_key, secret_key)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_keypair();

    // Sign a message using the stored secret key (SLH-DSA Sign)
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message);

    // Sign a message using a provided secret key (SLH-DSA Sign)
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message,
                                      const std::vector<uint8_t>& secret_key);

    // Verify a signature (SLH-DSA Verify) using stored public key
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature);

    // Verify a signature with explicit public key
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature,
                          const std::vector<uint8_t>& public_key);

    // Save/load keys
    bool save_keys(const std::string& filename_prefix);
    bool load_keys(const std::string& filename_prefix);

    // Accessors
    std::vector<uint8_t> get_public_key() const { return stored_public_key; }
    std::vector<uint8_t> get_secret_key() const { return stored_secret_key; }
    size_t get_signature_length() const;
};

// ============================================================================
// HybridKemWrapper - X25519 + ML-KEM-768 Hybrid Key Encapsulation
//   Combines classical ECDH (X25519 via OpenSSL) with ML-KEM-768 (liboqs)
//   to provide transitional security: even if one primitive is broken,
//   the combined shared secret remains secure.
//
//   Combined shared secret: SHA-256(X25519_ss || ML-KEM_ss)
//
//   NIST guidance: hybrid modes are recommended during the PQC transition
//   period to maintain backward compatibility with classical systems.
//
//   Requires: OpenSSL 1.1.1+ (for EVP_PKEY X25519), liboqs (for ML-KEM-768)
// ============================================================================
class HybridKemWrapper {
public:
    struct HybridKeyPair {
        std::vector<uint8_t> x25519_public;    // 32 bytes
        std::vector<uint8_t> x25519_private;   // 32 bytes
        std::vector<uint8_t> mlkem_public;     // ML-KEM-768 public key
        std::vector<uint8_t> mlkem_secret;     // ML-KEM-768 secret key
    };

    struct HybridEncapResult {
        std::vector<uint8_t> x25519_public;    // sender's ephemeral X25519 public key
        std::vector<uint8_t> mlkem_ciphertext; // ML-KEM ciphertext
        std::vector<uint8_t> shared_secret;    // combined 32-byte secret
    };

    // Constructor: initializes ML-KEM component
    // Default: ML-KEM-768 (security level 3, recommended for hybrid)
    HybridKemWrapper(const char* mlkem_alg = "ML-KEM-768");

    ~HybridKemWrapper();

    // Generate a hybrid keypair (X25519 + ML-KEM-768)
    HybridKeyPair generate_keypair();

    // Encapsulate: sender creates shared secret using recipient's hybrid public keys
    HybridEncapResult encapsulate(const std::vector<uint8_t>& x25519_peer_public,
                                  const std::vector<uint8_t>& mlkem_peer_public);

    // Decapsulate: recipient recovers shared secret
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& x25519_sender_public,
                                     const std::vector<uint8_t>& mlkem_ciphertext,
                                     const std::vector<uint8_t>& x25519_private,
                                     const std::vector<uint8_t>& mlkem_secret);

private:
    OQS_KEM* kem_;
};

#endif // QUANTUM_KYBER_HPP
