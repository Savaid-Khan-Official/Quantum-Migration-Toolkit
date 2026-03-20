#include "FileEncryptor.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

// Generate cryptographically secure random IV using OpenSSL
vector<uint8_t> FileEncryptor::generate_iv() {
    vector<uint8_t> iv(16);
    if (RAND_bytes(iv.data(), 16) != 1) {
        throw runtime_error("Failed to generate random IV");
    }
    return iv;
}

// Stream encrypt file content in 64MB chunks with SHA256 hashing for signature
void FileEncryptor::stream_encrypt(ifstream& input, ofstream& output,
                                    const vector<uint8_t>& key,
                                    const vector<uint8_t>& iv,
                                    size_t input_size,
                                    SHA256_CTX& hash_ctx) {
    // Create and initialize the cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }
    
    // Initialize encryption with AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptInit_ex failed");
    }
    
    // Allocate buffers for streaming
    vector<uint8_t> input_buffer(CHUNK_SIZE);
    vector<uint8_t> output_buffer(CHUNK_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    
    size_t bytes_processed = 0;
    int out_len = 0;
    
    cout << "  Streaming encryption (chunk size: " << (CHUNK_SIZE / (1024 * 1024)) << " MB)..." << endl;
    
    // Process file in chunks
    while (bytes_processed < input_size) {
        size_t bytes_to_read = min(CHUNK_SIZE, input_size - bytes_processed);
        input.read(reinterpret_cast<char*>(input_buffer.data()), bytes_to_read);
        
        if (!input && !input.eof()) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Error reading input file");
        }
        
        size_t bytes_read = input.gcount();
        
        // Encrypt this chunk
        if (EVP_EncryptUpdate(ctx, output_buffer.data(), &out_len, 
                              input_buffer.data(), static_cast<int>(bytes_read)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("EVP_EncryptUpdate failed");
        }
        
        // Update hash with encrypted chunk BEFORE writing to disk
        SHA256_Update(&hash_ctx, output_buffer.data(), out_len);
        
        // Write encrypted chunk to output
        output.write(reinterpret_cast<char*>(output_buffer.data()), out_len);
        
        bytes_processed += bytes_read;
        
        // Progress indicator for large files
        if (input_size > CHUNK_SIZE) {
            int progress = static_cast<int>((bytes_processed * 100) / input_size);
            cout << "\r  Encrypting: " << progress << "% (" 
                 << (bytes_processed / (1024 * 1024)) << " / " 
                 << (input_size / (1024 * 1024)) << " MB)" << flush;
        }
    }
    
    // Finalize encryption (handle padding)
    if (EVP_EncryptFinal_ex(ctx, output_buffer.data(), &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_EncryptFinal_ex failed");
    }
    
    if (out_len > 0) {
        // Update hash with final padding block
        SHA256_Update(&hash_ctx, output_buffer.data(), out_len);
        output.write(reinterpret_cast<char*>(output_buffer.data()), out_len);
    }
    
    if (input_size > CHUNK_SIZE) {
        cout << "\r  Encrypting: 100% completed                    " << endl;
    }
    
    EVP_CIPHER_CTX_free(ctx);
}

// Stream decrypt file content in 64MB chunks with SHA256 hashing for verification
void FileEncryptor::stream_decrypt(ifstream& input, ofstream& output,
                                    const vector<uint8_t>& key,
                                    const vector<uint8_t>& iv,
                                    size_t encrypted_size,
                                    SHA256_CTX& hash_ctx) {
    // Create and initialize the cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw runtime_error("Failed to create EVP_CIPHER_CTX");
    }
    
    // Initialize decryption with AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptInit_ex failed");
    }
    
    // Allocate buffers for streaming
    vector<uint8_t> input_buffer(CHUNK_SIZE);
    vector<uint8_t> output_buffer(CHUNK_SIZE + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    
    size_t bytes_processed = 0;
    int out_len = 0;
    
    cout << "  Streaming decryption (chunk size: " << (CHUNK_SIZE / (1024 * 1024)) << " MB)..." << endl;
    
    // Process file in chunks
    while (bytes_processed < encrypted_size) {
        size_t bytes_to_read = min(CHUNK_SIZE, encrypted_size - bytes_processed);
        input.read(reinterpret_cast<char*>(input_buffer.data()), bytes_to_read);
        
        if (!input && !input.eof()) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("Error reading encrypted file");
        }
        
        size_t bytes_read = input.gcount();
        
        // Update hash with encrypted chunk (input buffer) as we read it
        SHA256_Update(&hash_ctx, input_buffer.data(), bytes_read);
        
        // Decrypt this chunk
        if (EVP_DecryptUpdate(ctx, output_buffer.data(), &out_len,
                              input_buffer.data(), static_cast<int>(bytes_read)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw runtime_error("EVP_DecryptUpdate failed");
        }
        
        // Write decrypted chunk to output
        output.write(reinterpret_cast<char*>(output_buffer.data()), out_len);
        
        bytes_processed += bytes_read;
        
        // Progress indicator for large files
        if (encrypted_size > CHUNK_SIZE) {
            int progress = static_cast<int>((bytes_processed * 100) / encrypted_size);
            cout << "\r  Decrypting: " << progress << "% (" 
                 << (bytes_processed / (1024 * 1024)) << " / " 
                 << (encrypted_size / (1024 * 1024)) << " MB)" << flush;
        }
    }
    
    // Finalize decryption (handle padding removal)
    if (EVP_DecryptFinal_ex(ctx, output_buffer.data(), &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("EVP_DecryptFinal_ex failed - possibly incorrect key or corrupted data");
    }
    
    if (out_len > 0) {
        output.write(reinterpret_cast<char*>(output_buffer.data()), out_len);
    }
    
    if (encrypted_size > CHUNK_SIZE) {
        cout << "\r  Decrypting: 100% completed                    " << endl;
    }
    
    EVP_CIPHER_CTX_free(ctx);
}

void FileEncryptor::encrypt_file(QuantumWrapper& quantum, 
                                  DilithiumWrapper& dilithium,
                                  const string& input_path, 
                                  const string& output_path) {
    cout << "\n[FILE ENCRYPTOR v2.1] Starting quantum-safe encryption with streaming hash-then-sign..." << endl;
    
    // Step 1: Get public key from the quantum wrapper
    vector<uint8_t> public_key = quantum.get_public_key();
    if (public_key.empty()) {
        throw runtime_error("No public key available. Generate or load keys first.");
    }
    
    // Step 2: Encapsulate to get shared secret (this will be used as AES key)
    cout << "  Performing Kyber key encapsulation..." << endl;
    auto [ciphertext, shared_secret] = quantum.encapsulate(public_key);
    
    // Step 3: Derive AES-256 key from shared secret using SHA-256 KDF
    cout << "  Deriving AES key with SHA-256..." << endl;
    vector<uint8_t> aes_key(32);
    SHA256(shared_secret.data(), shared_secret.size(), aes_key.data());
    
    // Step 4: Generate random IV for AES
    vector<uint8_t> iv = generate_iv();
    
    // Step 5: Open input file and get size
    ifstream input(input_path, ios::binary);
    if (!input) {
        throw runtime_error("Failed to open input file: " + input_path);
    }
    
    input.seekg(0, ios::end);
    size_t input_size = input.tellg();
    input.seekg(0, ios::beg);
    cout << "  Input file: " << input_path << " (" << input_size << " bytes)" << endl;
    
    // Step 6: Open output file
    ofstream output(output_path, ios::binary);
    if (!output) {
        throw runtime_error("Failed to open output file: " + output_path);
    }
    
    // Step 7: Initialize SHA256 context for streaming hash
    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);
    
    // Step 8: Write header - Kyber ciphertext (no public key!)
    // File format: [ct_len(4B)][ciphertext][iv(16B)][encrypted_data][sig_len(4B)][signature]
    uint32_t ct_size = static_cast<uint32_t>(ciphertext.size());
    output.write(reinterpret_cast<const char*>(&ct_size), 4);
    output.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    
    // Update hash with header (ciphertext length + ciphertext)
    SHA256_Update(&hash_ctx, reinterpret_cast<const uint8_t*>(&ct_size), 4);
    SHA256_Update(&hash_ctx, ciphertext.data(), ciphertext.size());
    
    // Write IV (fixed 16 bytes)
    output.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    
    // Update hash with IV
    SHA256_Update(&hash_ctx, iv.data(), iv.size());
    
    // Step 9: Stream encrypt the file content (also updates hash_ctx)
    stream_encrypt(input, output, aes_key, iv, input_size, hash_ctx);
    
    input.close();
    output.flush();
    
    // Step 10: Finalize hash to get 32-byte digest
    vector<uint8_t> file_hash(SHA256_DIGEST_LENGTH);
    SHA256_Final(file_hash.data(), &hash_ctx);
    
    cout << "  Generating Dilithium signature over file hash..." << endl;
    
    // Step 11: Sign ONLY the 32-byte hash (not the entire file!)
    vector<uint8_t> signature = dilithium.sign_message(file_hash);
    cout << "  Signature size: " << signature.size() << " bytes (signing 32-byte hash)" << endl;
    
    // Step 12: Append signature to output file
    // File trailer format: [signature (N bytes)][sig_len (4B)]
    // sig_len is written LAST so decrypt can seekg(-4, end) to read it.
    uint32_t sig_size = static_cast<uint32_t>(signature.size());
    output.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    output.write(reinterpret_cast<const char*>(&sig_size), 4);
    
    output.close();
    
    // Get final file size
    ifstream final_check(output_path, ios::binary | ios::ate);
    size_t final_size = final_check.tellg();
    final_check.close();
    
    cout << "  Output file: " << output_path << " (" << final_size << " bytes)" << endl;
    cout << "\n[SUCCESS] File encrypted and signed successfully!" << endl;
}

void FileEncryptor::decrypt_file(QuantumWrapper& quantum,
                                  DilithiumWrapper& dilithium,
                                  const string& input_path, 
                                  const string& output_path) {
    cout << "\n[FILE DECRYPTOR v2.1] Starting quantum-safe decryption with streaming verification..." << endl;
    
    // Step 1: Open encrypted file and get size
    ifstream input(input_path, ios::binary);
    if (!input) {
        throw runtime_error("Failed to open encrypted file: " + input_path);
    }
    
    input.seekg(0, ios::end);
    size_t file_size = input.tellg();
    input.seekg(0, ios::beg);
    cout << "  Encrypted file: " << input_path << " (" << file_size << " bytes)" << endl;
    
    // Step 2: Initialize SHA256 context for streaming hash verification
    SHA256_CTX hash_ctx;
    SHA256_Init(&hash_ctx);
    
    // Step 3: Read Kyber ciphertext and update hash
    uint32_t ct_size;
    input.read(reinterpret_cast<char*>(&ct_size), 4);
    SHA256_Update(&hash_ctx, reinterpret_cast<const uint8_t*>(&ct_size), 4);
    
    vector<uint8_t> ciphertext(ct_size);
    input.read(reinterpret_cast<char*>(ciphertext.data()), ct_size);
    SHA256_Update(&hash_ctx, ciphertext.data(), ct_size);
    
    // Step 4: Read IV and update hash
    vector<uint8_t> iv(16);
    input.read(reinterpret_cast<char*>(iv.data()), 16);
    SHA256_Update(&hash_ctx, iv.data(), 16);
    
    // Step 5: Calculate where encrypted data ends and signature begins
    // File trailer: [signature (N bytes)][sig_len (4B)]
    // sig_len is the LAST 4 bytes of the file.
    
    streampos current_pos = input.tellg(); // Position after IV
    
    // Read sig_len from the last 4 bytes of the file
    input.seekg(-4, ios::end);
    uint32_t sig_size;
    input.read(reinterpret_cast<char*>(&sig_size), 4);
    
    // Bounds validation: reject malformed files
    size_t header_size = 4 + ct_size + 16; // ct_len + ciphertext + iv
    size_t footer_size = sig_size + 4;      // signature + sig_len
    if (header_size + footer_size > file_size) {
        throw runtime_error("Malformed .qenc file: header + footer exceed file size");
    }
    size_t encrypted_data_size = file_size - header_size - footer_size;
    
    cout << "  Kyber ciphertext: " << ct_size << " bytes" << endl;
    cout << "  Encrypted data: " << encrypted_data_size << " bytes" << endl;
    cout << "  Signature: " << sig_size << " bytes" << endl;
    
    // Step 6: Read the signature for later verification
    // Signature sits just before the trailing sig_len field
    input.seekg(file_size - footer_size, ios::beg);
    vector<uint8_t> signature(sig_size);
    input.read(reinterpret_cast<char*>(signature.data()), sig_size);
    
    // Step 7: Get secret key and decapsulate
    vector<uint8_t> secret_key = quantum.get_secret_key();
    if (secret_key.empty()) {
        throw runtime_error("No secret key available. Load keys first.");
    }
    
    cout << "  Recovering shared secret via Kyber decapsulation..." << endl;
    vector<uint8_t> shared_secret = quantum.decapsulate(ciphertext, secret_key);
    
    // Step 8: Derive AES-256 key from shared secret using SHA-256 KDF
    cout << "  Deriving AES key with SHA-256..." << endl;
    vector<uint8_t> aes_key(32);
    SHA256(shared_secret.data(), shared_secret.size(), aes_key.data());
    
    // Step 9: Open output file
    ofstream output(output_path, ios::binary);
    if (!output) {
        throw runtime_error("Failed to open output file: " + output_path);
    }
    
    // Step 10: Seek to encrypted data position and stream decrypt
    // (stream_decrypt will also update hash_ctx with encrypted chunks)
    input.seekg(header_size, ios::beg);
    stream_decrypt(input, output, aes_key, iv, encrypted_data_size, hash_ctx);
    
    input.close();
    output.close();
    
    // Step 11: Finalize hash to get 32-byte digest
    vector<uint8_t> computed_hash(SHA256_DIGEST_LENGTH);
    SHA256_Final(computed_hash.data(), &hash_ctx);
    
    // Step 12: Verify the signature against the computed hash
    cout << "  Verifying Dilithium signature over computed hash..." << endl;
    
    if (!dilithium.verify_signature(computed_hash, signature)) {
        // CRITICAL: Delete the potentially corrupted/tampered output file
        remove(output_path.c_str());
        throw runtime_error("TAMPERING DETECTED! Signature verification failed. "
                           "The encrypted file has been modified or corrupted. "
                           "Output file has been deleted for security.");
    }
    cout << "  Signature verified successfully!" << endl;
    
    // Get final file size
    ifstream final_check(output_path, ios::binary | ios::ate);
    size_t final_size = final_check.tellg();
    final_check.close();
    
    cout << "  Decrypted file: " << output_path << " (" << final_size << " bytes)" << endl;
    cout << "\n[SUCCESS] File decrypted and verified successfully!" << endl;
}
