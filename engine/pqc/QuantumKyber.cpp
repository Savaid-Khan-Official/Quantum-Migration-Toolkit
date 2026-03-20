#include "QuantumKyber.hpp"
#include <iostream>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>

using namespace std;

// ============================================================================
// QuantumWrapper Implementation (Kyber KEM)
// ============================================================================

// Thread-safe liboqs lifecycle: init once, destroy at exit
static void ensure_oqs_init() {
    static struct OqsGuard {
        OqsGuard()  { OQS_init(); }
        ~OqsGuard() { OQS_destroy(); }
    } guard;
}

// Constructor: Initialize the KEM with the specified algorithm
QuantumWrapper::QuantumWrapper(const char* alg_name) {
    ensure_oqs_init();
    
    // Check if the algorithm is enabled
    if (!OQS_KEM_alg_is_enabled(alg_name)) {
        throw runtime_error(string("Algorithm ") + alg_name + " is not enabled");
    }
    
    // Create the KEM object
    kem = OQS_KEM_new(alg_name);
    if (kem == nullptr) {
        OQS_destroy();
        throw runtime_error(string("Failed to create KEM for algorithm ") + alg_name);
    }
    
    cout << "QuantumWrapper initialized with algorithm: " << alg_name << endl;
}

// Destructor: Clean up KEM resources (OQS lifetime is managed by OqsGuard)
QuantumWrapper::~QuantumWrapper() {
    if (kem != nullptr) {
        OQS_KEM_free(kem);
        kem = nullptr;
    }
}

// Generate a keypair
pair<vector<uint8_t>, vector<uint8_t>> QuantumWrapper::generate_keypair() {
    if (kem == nullptr) {
        throw runtime_error("KEM is not initialized");
    }
    
    // Allocate memory for public and secret keys
    vector<uint8_t> public_key(kem->length_public_key);
    vector<uint8_t> secret_key(kem->length_secret_key);
    
    // Generate the keypair
    OQS_STATUS status = OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to generate keypair");
    }
    
    // Store keys internally
    stored_public_key = public_key;
    stored_secret_key = secret_key;
    
    return make_pair(public_key, secret_key);
}

// Encapsulate: Generate ciphertext and shared secret from public key
pair<vector<uint8_t>, vector<uint8_t>> QuantumWrapper::encapsulate(const vector<uint8_t>& public_key) {
    if (kem == nullptr) {
        throw runtime_error("KEM is not initialized");
    }
    
    // Allocate memory for ciphertext and shared secret
    vector<uint8_t> ciphertext(kem->length_ciphertext);
    vector<uint8_t> shared_secret(kem->length_shared_secret);
    
    // Perform encapsulation
    OQS_STATUS status = OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(), public_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to encapsulate");
    }
    
    return make_pair(ciphertext, shared_secret);
}

// Decapsulate: Recover shared secret from ciphertext using secret key
vector<uint8_t> QuantumWrapper::decapsulate(const vector<uint8_t>& ciphertext, const vector<uint8_t>& secret_key) {
    if (kem == nullptr) {
        throw runtime_error("KEM is not initialized");
    }
    
    // Allocate memory for shared secret
    vector<uint8_t> shared_secret(kem->length_shared_secret);
    
    // Perform decapsulation
    OQS_STATUS status = OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), secret_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to decapsulate");
    }
    
    return shared_secret;
}

// Save keys to files
bool QuantumWrapper::save_keys(const string& filename_prefix) {
    if (stored_public_key.empty() || stored_secret_key.empty()) {
        cerr << "No keys to save. Generate keys first." << endl;
        return false;
    }
    
    // Save public key
    string pub_filename = filename_prefix + ".pub";
    ofstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for writing" << endl;
        return false;
    }
    pub_file.write(reinterpret_cast<const char*>(stored_public_key.data()), stored_public_key.size());
    pub_file.close();
    
    // Save secret key
    string priv_filename = filename_prefix + ".priv";
    ofstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for writing" << endl;
        return false;
    }
    priv_file.write(reinterpret_cast<const char*>(stored_secret_key.data()), stored_secret_key.size());
    priv_file.close();
    
    cout << "Keys saved to " << pub_filename << " and " << priv_filename << endl;
    return true;
}

// Load keys from files
bool QuantumWrapper::load_keys(const string& filename_prefix) {
    if (kem == nullptr) {
        cerr << "KEM is not initialized" << endl;
        return false;
    }
    
    // Load public key
    string pub_filename = filename_prefix + ".pub";
    ifstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for reading" << endl;
        return false;
    }
    
    pub_file.seekg(0, ios::end);
    size_t pub_size = pub_file.tellg();
    pub_file.seekg(0, ios::beg);
    
    stored_public_key.resize(pub_size);
    pub_file.read(reinterpret_cast<char*>(stored_public_key.data()), pub_size);
    pub_file.close();
    
    // Load secret key
    string priv_filename = filename_prefix + ".priv";
    ifstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for reading" << endl;
        return false;
    }
    
    priv_file.seekg(0, ios::end);
    size_t priv_size = priv_file.tellg();
    priv_file.seekg(0, ios::beg);
    
    stored_secret_key.resize(priv_size);
    priv_file.read(reinterpret_cast<char*>(stored_secret_key.data()), priv_size);
    priv_file.close();
    
    cout << "Keys loaded from " << pub_filename << " and " << priv_filename << endl;
    return true;
}

// ============================================================================
// DilithiumWrapper Implementation (ML-DSA Digital Signatures)
// ============================================================================

// Constructor: Initialize the signature scheme
DilithiumWrapper::DilithiumWrapper(const char* alg_name) {
    ensure_oqs_init();
    
    // Check if the algorithm is enabled
    if (!OQS_SIG_alg_is_enabled(alg_name)) {
        throw runtime_error(string("Signature algorithm ") + alg_name + " is not enabled");
    }
    
    // Create the signature object
    sig = OQS_SIG_new(alg_name);
    if (sig == nullptr) {
        throw runtime_error(string("Failed to create signature scheme for algorithm ") + alg_name);
    }
    
    cout << "DilithiumWrapper initialized with algorithm: " << alg_name << endl;
}

// Destructor: Clean up resources
DilithiumWrapper::~DilithiumWrapper() {
    if (sig != nullptr) {
        OQS_SIG_free(sig);
        sig = nullptr;
    }
}

// Generate a signature keypair
pair<vector<uint8_t>, vector<uint8_t>> DilithiumWrapper::generate_signature_keypair() {
    if (sig == nullptr) {
        throw runtime_error("Signature scheme is not initialized");
    }
    
    // Allocate memory for public and secret keys
    vector<uint8_t> public_key(sig->length_public_key);
    vector<uint8_t> secret_key(sig->length_secret_key);
    
    // Generate the keypair
    OQS_STATUS status = OQS_SIG_keypair(sig, public_key.data(), secret_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to generate signature keypair");
    }
    
    // Store keys internally
    stored_public_key = public_key;
    stored_secret_key = secret_key;
    
    cout << "  Generated Dilithium keypair (public: " << public_key.size() 
         << " bytes, secret: " << secret_key.size() << " bytes)" << endl;
    
    return make_pair(public_key, secret_key);
}

// Sign a message using the stored secret key
vector<uint8_t> DilithiumWrapper::sign_message(const vector<uint8_t>& message) {
    if (stored_secret_key.empty()) {
        throw runtime_error("No secret key available. Generate or load keys first.");
    }
    return sign_message(message, stored_secret_key);
}

// Sign a message using a provided secret key
vector<uint8_t> DilithiumWrapper::sign_message(const vector<uint8_t>& message, 
                                                const vector<uint8_t>& secret_key) {
    if (sig == nullptr) {
        throw runtime_error("Signature scheme is not initialized");
    }
    
    // Allocate buffer for signature (maximum possible size)
    vector<uint8_t> signature(sig->length_signature);
    size_t signature_len = 0;
    
    // Sign the message
    OQS_STATUS status = OQS_SIG_sign(sig, signature.data(), &signature_len,
                                      message.data(), message.size(),
                                      secret_key.data());
    
    if (status != OQS_SUCCESS) {
        throw runtime_error("Failed to sign message");
    }
    
    // Resize to actual signature length
    signature.resize(signature_len);
    return signature;
}

// Verify a signature using the stored public key
bool DilithiumWrapper::verify_signature(const vector<uint8_t>& message, 
                                         const vector<uint8_t>& signature) {
    if (stored_public_key.empty()) {
        throw runtime_error("No public key available. Generate or load keys first.");
    }
    return verify_signature(message, signature, stored_public_key);
}

// Verify a signature using a provided public key
bool DilithiumWrapper::verify_signature(const vector<uint8_t>& message, 
                                         const vector<uint8_t>& signature,
                                         const vector<uint8_t>& public_key) {
    if (sig == nullptr) {
        throw runtime_error("Signature scheme is not initialized");
    }
    
    // Verify the signature
    OQS_STATUS status = OQS_SIG_verify(sig, message.data(), message.size(),
                                        signature.data(), signature.size(),
                                        public_key.data());
    
    return (status == OQS_SUCCESS);
}

// Save signature keys to files
bool DilithiumWrapper::save_keys(const string& filename_prefix) {
    if (stored_public_key.empty() || stored_secret_key.empty()) {
        cerr << "No signature keys to save. Generate keys first." << endl;
        return false;
    }
    
    // Save public key
    string pub_filename = filename_prefix + ".sig.pub";
    ofstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for writing" << endl;
        return false;
    }
    pub_file.write(reinterpret_cast<const char*>(stored_public_key.data()), stored_public_key.size());
    pub_file.close();
    
    // Save secret key
    string priv_filename = filename_prefix + ".sig.priv";
    ofstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for writing" << endl;
        return false;
    }
    priv_file.write(reinterpret_cast<const char*>(stored_secret_key.data()), stored_secret_key.size());
    priv_file.close();
    
    cout << "Signature keys saved to " << pub_filename << " and " << priv_filename << endl;
    return true;
}

// Load signature keys from files
bool DilithiumWrapper::load_keys(const string& filename_prefix) {
    if (sig == nullptr) {
        cerr << "Signature scheme is not initialized" << endl;
        return false;
    }
    
    // Load public key
    string pub_filename = filename_prefix + ".sig.pub";
    ifstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for reading" << endl;
        return false;
    }
    
    pub_file.seekg(0, ios::end);
    size_t pub_size = pub_file.tellg();
    pub_file.seekg(0, ios::beg);
    
    stored_public_key.resize(pub_size);
    pub_file.read(reinterpret_cast<char*>(stored_public_key.data()), pub_size);
    pub_file.close();
    
    // Load secret key
    string priv_filename = filename_prefix + ".sig.priv";
    ifstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for reading" << endl;
        return false;
    }
    
    priv_file.seekg(0, ios::end);
    size_t priv_size = priv_file.tellg();
    priv_file.seekg(0, ios::beg);
    
    stored_secret_key.resize(priv_size);
    priv_file.read(reinterpret_cast<char*>(stored_secret_key.data()), priv_size);
    priv_file.close();
    
    cout << "Signature keys loaded from " << pub_filename << " and " << priv_filename << endl;
    return true;
}

// Get maximum signature length
size_t DilithiumWrapper::get_signature_length() const {
    if (sig == nullptr) {
        throw runtime_error("Signature scheme is not initialized");
    }
    return sig->length_signature;
}

// ============================================================================
// SphincsPlusWrapper Implementation (SLH-DSA / FIPS 205 Stateless Signatures)
// ============================================================================

SphincsPlusWrapper::SphincsPlusWrapper(const char* alg_name) {
    ensure_oqs_init();

    if (!OQS_SIG_alg_is_enabled(alg_name)) {
        throw runtime_error(string("SPHINCS+ algorithm ") + alg_name + " is not enabled");
    }

    sig = OQS_SIG_new(alg_name);
    if (sig == nullptr) {
        throw runtime_error(string("Failed to create SPHINCS+ scheme for ") + alg_name);
    }

    cout << "SphincsPlusWrapper initialized with algorithm: " << alg_name << endl;
}

SphincsPlusWrapper::~SphincsPlusWrapper() {
    if (sig != nullptr) {
        OQS_SIG_free(sig);
        sig = nullptr;
    }
}

pair<vector<uint8_t>, vector<uint8_t>> SphincsPlusWrapper::generate_keypair() {
    if (sig == nullptr)
        throw runtime_error("SPHINCS+ scheme is not initialized");

    vector<uint8_t> public_key(sig->length_public_key);
    vector<uint8_t> secret_key(sig->length_secret_key);

    OQS_STATUS status = OQS_SIG_keypair(sig, public_key.data(), secret_key.data());
    if (status != OQS_SUCCESS)
        throw runtime_error("Failed to generate SPHINCS+ keypair");

    stored_public_key = public_key;
    stored_secret_key = secret_key;

    cout << "  Generated SPHINCS+ keypair (public: " << public_key.size()
         << " bytes, secret: " << secret_key.size() << " bytes)" << endl;

    return make_pair(public_key, secret_key);
}

vector<uint8_t> SphincsPlusWrapper::sign_message(const vector<uint8_t>& message) {
    if (stored_secret_key.empty())
        throw runtime_error("No secret key available. Generate or load keys first.");
    return sign_message(message, stored_secret_key);
}

vector<uint8_t> SphincsPlusWrapper::sign_message(const vector<uint8_t>& message,
                                                  const vector<uint8_t>& secret_key) {
    if (sig == nullptr)
        throw runtime_error("SPHINCS+ scheme is not initialized");

    vector<uint8_t> signature(sig->length_signature);
    size_t signature_len = 0;

    OQS_STATUS status = OQS_SIG_sign(sig, signature.data(), &signature_len,
                                      message.data(), message.size(),
                                      secret_key.data());
    if (status != OQS_SUCCESS)
        throw runtime_error("Failed to sign message with SPHINCS+");

    signature.resize(signature_len);
    return signature;
}

bool SphincsPlusWrapper::verify_signature(const vector<uint8_t>& message,
                                           const vector<uint8_t>& signature) {
    if (stored_public_key.empty())
        throw runtime_error("No public key available. Generate or load keys first.");
    return verify_signature(message, signature, stored_public_key);
}

bool SphincsPlusWrapper::verify_signature(const vector<uint8_t>& message,
                                           const vector<uint8_t>& signature,
                                           const vector<uint8_t>& public_key) {
    if (sig == nullptr)
        throw runtime_error("SPHINCS+ scheme is not initialized");

    OQS_STATUS status = OQS_SIG_verify(sig, message.data(), message.size(),
                                        signature.data(), signature.size(),
                                        public_key.data());
    return (status == OQS_SUCCESS);
}

bool SphincsPlusWrapper::save_keys(const string& filename_prefix) {
    if (stored_public_key.empty() || stored_secret_key.empty()) {
        cerr << "No SPHINCS+ keys to save. Generate keys first." << endl;
        return false;
    }

    string pub_filename = filename_prefix + ".sphincs.pub";
    ofstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for writing" << endl;
        return false;
    }
    pub_file.write(reinterpret_cast<const char*>(stored_public_key.data()),
                   stored_public_key.size());
    pub_file.close();

    string priv_filename = filename_prefix + ".sphincs.priv";
    ofstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for writing" << endl;
        return false;
    }
    priv_file.write(reinterpret_cast<const char*>(stored_secret_key.data()),
                    stored_secret_key.size());
    priv_file.close();

    cout << "SPHINCS+ keys saved to " << pub_filename << " and " << priv_filename << endl;
    return true;
}

bool SphincsPlusWrapper::load_keys(const string& filename_prefix) {
    if (sig == nullptr) {
        cerr << "SPHINCS+ scheme is not initialized" << endl;
        return false;
    }

    string pub_filename = filename_prefix + ".sphincs.pub";
    ifstream pub_file(pub_filename, ios::binary);
    if (!pub_file) {
        cerr << "Failed to open " << pub_filename << " for reading" << endl;
        return false;
    }

    pub_file.seekg(0, ios::end);
    size_t pub_size = pub_file.tellg();
    pub_file.seekg(0, ios::beg);
    stored_public_key.resize(pub_size);
    pub_file.read(reinterpret_cast<char*>(stored_public_key.data()), pub_size);
    pub_file.close();

    string priv_filename = filename_prefix + ".sphincs.priv";
    ifstream priv_file(priv_filename, ios::binary);
    if (!priv_file) {
        cerr << "Failed to open " << priv_filename << " for reading" << endl;
        return false;
    }

    priv_file.seekg(0, ios::end);
    size_t priv_size = priv_file.tellg();
    priv_file.seekg(0, ios::beg);
    stored_secret_key.resize(priv_size);
    priv_file.read(reinterpret_cast<char*>(stored_secret_key.data()), priv_size);
    priv_file.close();

    cout << "SPHINCS+ keys loaded from " << pub_filename << " and " << priv_filename << endl;
    return true;
}

size_t SphincsPlusWrapper::get_signature_length() const {
    if (sig == nullptr)
        throw runtime_error("SPHINCS+ scheme is not initialized");
    return sig->length_signature;
}

// ============================================================================
// HybridKemWrapper Implementation (X25519 + ML-KEM-768)
// ============================================================================

HybridKemWrapper::HybridKemWrapper(const char* mlkem_alg) {
    ensure_oqs_init();

    if (!OQS_KEM_alg_is_enabled(mlkem_alg)) {
        throw runtime_error(string("ML-KEM algorithm ") + mlkem_alg + " is not enabled");
    }

    kem_ = OQS_KEM_new(mlkem_alg);
    if (kem_ == nullptr) {
        throw runtime_error(string("Failed to create ML-KEM for ") + mlkem_alg);
    }

    cout << "HybridKemWrapper initialized: X25519 + " << mlkem_alg << endl;
}

HybridKemWrapper::~HybridKemWrapper() {
    if (kem_ != nullptr) {
        OQS_KEM_free(kem_);
        kem_ = nullptr;
    }
}

// Generate X25519 + ML-KEM hybrid keypair
HybridKemWrapper::HybridKeyPair HybridKemWrapper::generate_keypair() {
    HybridKeyPair kp;

    // --- X25519 keypair via OpenSSL EVP ---
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx)
        throw runtime_error("Failed to create X25519 PKEY context");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        throw runtime_error("X25519 keygen failed");
    }
    EVP_PKEY_CTX_free(pctx);

    // Extract raw X25519 keys
    size_t len = 32;
    kp.x25519_public.resize(32);
    kp.x25519_private.resize(32);
    EVP_PKEY_get_raw_public_key(pkey, kp.x25519_public.data(), &len);
    len = 32;
    EVP_PKEY_get_raw_private_key(pkey, kp.x25519_private.data(), &len);
    EVP_PKEY_free(pkey);

    // --- ML-KEM keypair via liboqs ---
    kp.mlkem_public.resize(kem_->length_public_key);
    kp.mlkem_secret.resize(kem_->length_secret_key);

    if (OQS_KEM_keypair(kem_, kp.mlkem_public.data(),
                         kp.mlkem_secret.data()) != OQS_SUCCESS)
        throw runtime_error("ML-KEM keypair generation failed");

    cout << "  Generated hybrid keypair (X25519: 32B + ML-KEM: "
         << kp.mlkem_public.size() << "B public)" << endl;

    return kp;
}

// Encapsulate: sender creates combined shared secret
HybridKemWrapper::HybridEncapResult HybridKemWrapper::encapsulate(
    const vector<uint8_t>& x25519_peer_public,
    const vector<uint8_t>& mlkem_peer_public)
{
    HybridEncapResult result;

    // --- X25519: ephemeral ECDH ---
    // Generate ephemeral keypair
    EVP_PKEY_CTX* gen_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* ephemeral = nullptr;
    if (!gen_ctx ||
        EVP_PKEY_keygen_init(gen_ctx) <= 0 ||
        EVP_PKEY_keygen(gen_ctx, &ephemeral) <= 0) {
        if (gen_ctx) EVP_PKEY_CTX_free(gen_ctx);
        throw runtime_error("X25519 ephemeral keygen failed");
    }
    EVP_PKEY_CTX_free(gen_ctx);

    // Extract ephemeral public key (sent to peer)
    size_t len = 32;
    result.x25519_public.resize(32);
    EVP_PKEY_get_raw_public_key(ephemeral, result.x25519_public.data(), &len);

    // Load peer's public key
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr,
        x25519_peer_public.data(), x25519_peer_public.size());
    if (!peer_key) {
        EVP_PKEY_free(ephemeral);
        throw runtime_error("Failed to load X25519 peer public key");
    }

    // Derive X25519 shared secret
    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(ephemeral, nullptr);
    vector<uint8_t> x25519_ss(32);
    size_t ss_len = 32;
    if (!derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, peer_key) <= 0 ||
        EVP_PKEY_derive(derive_ctx, x25519_ss.data(), &ss_len) <= 0) {
        if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(ephemeral);
        throw runtime_error("X25519 ECDH derivation failed");
    }
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(ephemeral);

    // --- ML-KEM: encapsulate ---
    result.mlkem_ciphertext.resize(kem_->length_ciphertext);
    vector<uint8_t> mlkem_ss(kem_->length_shared_secret);

    if (OQS_KEM_encaps(kem_, result.mlkem_ciphertext.data(),
                        mlkem_ss.data(), mlkem_peer_public.data()) != OQS_SUCCESS)
        throw runtime_error("ML-KEM encapsulation failed");

    // --- Combine: SHA-256(X25519_ss || ML-KEM_ss) ---
    vector<uint8_t> combined;
    combined.reserve(x25519_ss.size() + mlkem_ss.size());
    combined.insert(combined.end(), x25519_ss.begin(), x25519_ss.end());
    combined.insert(combined.end(), mlkem_ss.begin(), mlkem_ss.end());

    result.shared_secret.resize(32);
    SHA256(combined.data(), combined.size(), result.shared_secret.data());

    // Zeroize intermediates
    memset(x25519_ss.data(), 0, x25519_ss.size());
    memset(mlkem_ss.data(), 0, mlkem_ss.size());
    memset(combined.data(), 0, combined.size());

    return result;
}

// Decapsulate: recipient recovers combined shared secret
vector<uint8_t> HybridKemWrapper::decapsulate(
    const vector<uint8_t>& x25519_sender_public,
    const vector<uint8_t>& mlkem_ciphertext,
    const vector<uint8_t>& x25519_private,
    const vector<uint8_t>& mlkem_secret)
{
    // --- X25519: ECDH with sender's ephemeral public key ---
    EVP_PKEY* my_key = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr,
        x25519_private.data(), x25519_private.size());
    if (!my_key)
        throw runtime_error("Failed to load X25519 private key");

    EVP_PKEY* sender_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr,
        x25519_sender_public.data(), x25519_sender_public.size());
    if (!sender_key) {
        EVP_PKEY_free(my_key);
        throw runtime_error("Failed to load X25519 sender public key");
    }

    EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(my_key, nullptr);
    vector<uint8_t> x25519_ss(32);
    size_t ss_len = 32;
    if (!derive_ctx ||
        EVP_PKEY_derive_init(derive_ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(derive_ctx, sender_key) <= 0 ||
        EVP_PKEY_derive(derive_ctx, x25519_ss.data(), &ss_len) <= 0) {
        if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(sender_key);
        EVP_PKEY_free(my_key);
        throw runtime_error("X25519 ECDH derivation failed");
    }
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_PKEY_free(sender_key);
    EVP_PKEY_free(my_key);

    // --- ML-KEM: decapsulate ---
    vector<uint8_t> mlkem_ss(kem_->length_shared_secret);
    if (OQS_KEM_decaps(kem_, mlkem_ss.data(), mlkem_ciphertext.data(),
                        mlkem_secret.data()) != OQS_SUCCESS)
        throw runtime_error("ML-KEM decapsulation failed");

    // --- Combine: SHA-256(X25519_ss || ML-KEM_ss) ---
    vector<uint8_t> combined;
    combined.reserve(x25519_ss.size() + mlkem_ss.size());
    combined.insert(combined.end(), x25519_ss.begin(), x25519_ss.end());
    combined.insert(combined.end(), mlkem_ss.begin(), mlkem_ss.end());

    vector<uint8_t> shared_secret(32);
    SHA256(combined.data(), combined.size(), shared_secret.data());

    // Zeroize intermediates
    memset(x25519_ss.data(), 0, x25519_ss.size());
    memset(mlkem_ss.data(), 0, mlkem_ss.size());
    memset(combined.data(), 0, combined.size());

    return shared_secret;
}
