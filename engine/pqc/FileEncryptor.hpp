#ifndef FILE_ENCRYPTOR_HPP
#define FILE_ENCRYPTOR_HPP

#include "QuantumKyber.hpp"
#include "AES.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <openssl/sha.h>

// Chunk size for streaming encryption/decryption (64 MB)
constexpr size_t CHUNK_SIZE = 64 * 1024 * 1024;

// File format (.qenc v2.1):
// [ciphertext_len (4B)] [ciphertext (Kyber KEM)]
// [iv (16B)]
// [encrypted_data (streamed AES-256-CBC)]
// [signature (Dilithium over SHA256 hash)] [signature_len (4B)]
//
// NOTE: Signature is computed over SHA256(header + encrypted_data),
//       NOT the raw file data. This allows O(1) memory signing/verification.

class FileEncryptor {
public:
    // Encrypt a file using Quantum-safe key exchange + AES-256 (streaming)
    // Signs the SHA256 hash of ciphertext with Dilithium for integrity
    static void encrypt_file(QuantumWrapper& quantum, 
                             DilithiumWrapper& dilithium,
                             const std::string& input_path, 
                             const std::string& output_path);
    
    // Decrypt a file using Quantum-safe key exchange + AES-256 (streaming)
    // Verifies Dilithium signature AFTER computing streaming hash
    // Deletes output file if verification fails (tampering detected)
    static void decrypt_file(QuantumWrapper& quantum, 
                             DilithiumWrapper& dilithium,
                             const std::string& input_path, 
                             const std::string& output_path);

private:
    // Generate random IV for AES (using OpenSSL CSPRNG)
    static std::vector<uint8_t> generate_iv();
    
    // Stream encrypt file content in chunks with SHA256 hashing
    static void stream_encrypt(std::ifstream& input, std::ofstream& output,
                               const std::vector<uint8_t>& key, 
                               const std::vector<uint8_t>& iv,
                               size_t input_size,
                               SHA256_CTX& hash_ctx);
    
    // Stream decrypt file content in chunks with SHA256 hashing
    static void stream_decrypt(std::ifstream& input, std::ofstream& output,
                               const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& iv,
                               size_t encrypted_size,
                               SHA256_CTX& hash_ctx);
};

#endif // FILE_ENCRYPTOR_HPP
