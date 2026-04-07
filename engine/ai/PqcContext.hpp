#pragma once
// ============================================================================
// PqcContext.hpp —- Context-Aware PQC API Injection for AI Remediation
// ============================================================================
// The CORE INNOVATION of the Quantum Migration Toolkit v2.1.
//
// Problem:  The LLM (Qwen2.5-Coder) knows about PQC concepts but has never
//           seen our actual QuantumKyber / Dilithium / FileEncryptor API.
//           Without grounding, it hallucinates function names like
//           "kyber_keygen()" or "pqc_encrypt()" that don't exist.
//
// Solution: PqcContext injects VERBATIM excerpts of the real API headers
//           into the system prompt, scoped to the rule category.
//
// All user-facing text uses NIST standard names:
//   ML-KEM  (FIPS 203) — formerly Kyber
//   ML-DSA  (FIPS 204) — formerly Dilithium
// The liboqs C macros (OQS_KEM_alg_kyber_512, OQS_SIG_alg_ml_dsa_65)
// are kept as-is for compile compatibility with pre-rename builds.
//
// Usage:
//   PqcContext ctx;
//   std::string api_ref  = ctx.get_api_reference(rule);
//   std::string example  = ctx.get_usage_example(rule, ".py");
//   std::string include  = ctx.get_include_directive(rule, ".cpp");
// ============================================================================

#include <string>
#include <map>

// Forward declare Rule from ScanTypes.hpp
struct Rule;

// ============================================================================
// Rule categories for API mapping
// ============================================================================
enum class PqcCategory {
    KEM,                // Key Encapsulation: RSA, DH, ECDH → ML-KEM (FIPS 203)
    HYBRID_KEM,         // Hybrid Key Exchange: X25519+ML-KEM-768 (transitional)
    SIGNATURE,          // Digital Signatures: DSA, ECDSA → ML-DSA (FIPS 204)
    SIGNATURE_STATELESS,// Stateless Signatures: → SLH-DSA (FIPS 205 / SPHINCS+)
    CIPHER,             // Symmetric: DES, 3DES, AES-128, ECB, RC4 → AES-256-GCM + ML-KEM
    HASH,               // Hash: MD5, SHA-1, SHA-224 → SHA-256 / SHA-3 (stdlib)
    CONFIG,             // Config: hardcoded secrets, HTTP, Telnet → env vars, TLS
    UNKNOWN
};

class PqcContext {
public:

    // -----------------------------------------------------------------------
    // Classify a rule ID into a PQC category
    // -----------------------------------------------------------------------
    static PqcCategory classify(const std::string& rule_id) {
        if (rule_id.find("RSA")  != std::string::npos ||
            rule_id.find("DH")   != std::string::npos ||
            rule_id.find("ECDH") != std::string::npos)
            return PqcCategory::KEM;

        if (rule_id.find("DSA")  != std::string::npos ||
            rule_id.find("ECC")  != std::string::npos)
            return PqcCategory::SIGNATURE;

        if (rule_id.find("DES")  != std::string::npos ||
            rule_id.find("3DES") != std::string::npos ||
            rule_id.find("AES128") != std::string::npos ||
            rule_id.find("ECB")  != std::string::npos ||
            rule_id.find("RC4")  != std::string::npos ||
            rule_id.find("BF")   != std::string::npos ||
            rule_id.find("PKCS1")!= std::string::npos)
            return PqcCategory::CIPHER;

        if (rule_id.find("MD5")  != std::string::npos ||
            rule_id.find("SHA1") != std::string::npos ||
            rule_id.find("SHA224")!= std::string::npos)
            return PqcCategory::HASH;

        if (rule_id.find("HARDCODE") != std::string::npos ||
            rule_id.find("HTTP") != std::string::npos ||
            rule_id.find("TELNET") != std::string::npos ||
            rule_id.find("RAND") != std::string::npos)
            return PqcCategory::CONFIG;

        return PqcCategory::UNKNOWN;
    }

    // -----------------------------------------------------------------------
    // Get the verbatim API reference to inject into the system prompt.
    // Returns the actual C++ class interface from QuantumKyber.hpp.
    // -----------------------------------------------------------------------
    static std::string get_api_reference(PqcCategory cat) {
        switch (cat) {
        case PqcCategory::KEM:
            return R"API(
=== QuantumWrapper API (ML-KEM / FIPS 203) ===
NOTE: The liboqs C macro is still OQS_KEM_alg_kyber_512 (pre-rename build).
The NIST standard name is ML-KEM-512. Use the QuantumWrapper C++ class.
#include "QuantumKyber.hpp"

class QuantumWrapper {
public:
    QuantumWrapper(const char* alg_name = OQS_KEM_alg_kyber_512);
    ~QuantumWrapper();

    // Generate an ML-KEM keypair → (public_key, secret_key)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_keypair();

    // Encapsulate: sender uses recipient's public_key → (ciphertext, shared_secret)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(const std::vector<uint8_t>& public_key);

    // Decapsulate: recipient recovers shared_secret from ciphertext + secret_key
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& secret_key);

    bool save_keys(const std::string& filename_prefix);
    bool load_keys(const std::string& filename_prefix);
    std::vector<uint8_t> get_public_key() const;
    std::vector<uint8_t> get_secret_key() const;
};
)API";

        case PqcCategory::SIGNATURE:
            return R"API(
=== DilithiumWrapper API (ML-DSA / FIPS 204) ===
NOTE: The liboqs C macro is OQS_SIG_alg_ml_dsa_65. The NIST standard name
is ML-DSA-65 (security level 3). Use the DilithiumWrapper C++ class.
#include "QuantumKyber.hpp"

class DilithiumWrapper {
public:
    DilithiumWrapper(const char* alg_name = OQS_SIG_alg_ml_dsa_65);
    ~DilithiumWrapper();

    // Generate an ML-DSA signature keypair → (public_key, secret_key)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_signature_keypair();

    // Sign a message using stored secret key → signature bytes
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message);

    // Sign with explicit secret key
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message,
                                       const std::vector<uint8_t>& secret_key);

    // Verify signature using stored public key → bool
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature);

    // Verify with explicit public key
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature,
                          const std::vector<uint8_t>& public_key);

    bool save_keys(const std::string& filename_prefix);
    bool load_keys(const std::string& filename_prefix);
    size_t get_signature_length() const;
};

=== Alternative: SphincsPlusWrapper API (SLH-DSA / FIPS 205) ===
For stateless hash-based signatures when ML-DSA is not suitable.
Larger signatures (~17 KB) but conservative hash-based security.

class SphincsPlusWrapper {
public:
    SphincsPlusWrapper(const char* alg_name = "SPHINCS+-SHA2-128f-simple");
    ~SphincsPlusWrapper();

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_keypair();
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message);
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message,
                                      const std::vector<uint8_t>& secret_key);
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature);
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature,
                          const std::vector<uint8_t>& public_key);
    size_t get_signature_length() const;
};
)API";

        case PqcCategory::SIGNATURE_STATELESS:
            return R"API(
=== SphincsPlusWrapper API (SLH-DSA / FIPS 205) ===
Stateless hash-based digital signatures. Use when ML-DSA is not suitable
(e.g., when conservative hash-based assumptions are preferred).
Trade-off: larger signatures (~17 KB) vs ML-DSA (~3 KB).
#include "QuantumKyber.hpp"

class SphincsPlusWrapper {
public:
    // Variants: "SPHINCS+-SHA2-128f-simple" (fast, level 1)
    //           "SPHINCS+-SHA2-192f-simple" (fast, level 3)
    //           "SPHINCS+-SHA2-256f-simple" (fast, level 5)
    //           "SPHINCS+-SHA2-128s-simple" (small sigs, level 1)
    SphincsPlusWrapper(const char* alg_name = "SPHINCS+-SHA2-128f-simple");
    ~SphincsPlusWrapper();

    // Generate an SLH-DSA keypair → (public_key, secret_key)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_keypair();

    // Sign: message → signature bytes
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message);
    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message,
                                      const std::vector<uint8_t>& secret_key);

    // Verify: (message, signature) → bool
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature);
    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature,
                          const std::vector<uint8_t>& public_key);

    size_t get_signature_length() const;
};
)API";

        case PqcCategory::HYBRID_KEM:
            return R"API(
=== HybridKemWrapper API (X25519 + ML-KEM-768 Hybrid) ===
Combines classical X25519 ECDH with ML-KEM-768 for transitional security.
Even if one primitive is broken, the combined shared secret remains secure.
Combined shared secret: SHA-256(X25519_ss || ML-KEM_ss)
#include "QuantumKyber.hpp"

class HybridKemWrapper {
public:
    struct HybridKeyPair {
        std::vector<uint8_t> x25519_public;    // 32 bytes
        std::vector<uint8_t> x25519_private;   // 32 bytes
        std::vector<uint8_t> mlkem_public;     // ML-KEM-768 public key
        std::vector<uint8_t> mlkem_secret;     // ML-KEM-768 secret key
    };
    struct HybridEncapResult {
        std::vector<uint8_t> x25519_public;    // sender's ephemeral pub key
        std::vector<uint8_t> mlkem_ciphertext; // ML-KEM ciphertext
        std::vector<uint8_t> shared_secret;    // combined 32-byte secret
    };

    HybridKemWrapper(const char* mlkem_alg = "ML-KEM-768");
    ~HybridKemWrapper();

    // Generate hybrid keypair
    HybridKeyPair generate_keypair();

    // Encapsulate: sender creates shared secret using peer's public keys
    HybridEncapResult encapsulate(const std::vector<uint8_t>& x25519_peer_public,
                                  const std::vector<uint8_t>& mlkem_peer_public);

    // Decapsulate: recipient recovers shared secret
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& x25519_sender_public,
                                     const std::vector<uint8_t>& mlkem_ciphertext,
                                     const std::vector<uint8_t>& x25519_private,
                                     const std::vector<uint8_t>& mlkem_secret);
};
)API";

        case PqcCategory::CIPHER:
            return R"API(
=== AES-256 + ML-KEM (FIPS 203) for Symmetric Encryption ===
#include "QuantumKyber.hpp"

// Step 1: Use QuantumWrapper (ML-KEM) for key exchange (replaces RSA/DH key wrapping)
class QuantumWrapper {
public:
    QuantumWrapper(const char* alg_name = OQS_KEM_alg_kyber_512);
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_keypair();
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(const std::vector<uint8_t>& public_key);
    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& secret_key);
};

// Step 2: Use AES-256-GCM (NOT ECB, NOT CBC without HMAC, NOT DES/3DES/RC4)
#include "AES.hpp"
class AES {
public:
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key,   // 32 bytes
                                         const std::vector<uint8_t>& iv);   // 16 bytes
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key,
                                         const std::vector<uint8_t>& iv);
};

// IMPORTANT: Replace DES/3DES/RC4/Blowfish/AES-128 with AES-256.
// Replace ECB mode with GCM. Use ML-KEM for key exchange instead of RSA.
)API";

        case PqcCategory::HASH:
            return R"API(
=== Hash Function Migration (No Custom API Needed) ===
Replace MD5/SHA-1/SHA-224 with SHA-256 or SHA-3 from the standard library.

C/C++ (OpenSSL):
    Replace: MD5(...) / SHA1(...)
    With:    SHA256(...) or EVP_DigestInit_ex(ctx, EVP_sha3_256(), NULL)

Python:
    Replace: hashlib.md5(...) / hashlib.sha1(...)
    With:    hashlib.sha3_256(...)

Java:
    Replace: MessageDigest.getInstance("MD5") / ("SHA-1")
    With:    MessageDigest.getInstance("SHA-256")

Go:
    Replace: md5.New() / sha1.New()
    With:    sha256.New()

No custom PQC API is needed — use standard library cryptographic hash functions.
)API";

        case PqcCategory::CONFIG:
            return R"API(
=== Configuration Security (No PQC API Needed) ===
- Move hardcoded secrets to environment variables or a vault:
    C/C++:    std::getenv("SECRET_KEY")
    Python:   os.environ.get("SECRET_KEY")
    Java:     System.getenv("SECRET_KEY")
    Node.js:  process.env.SECRET_KEY

- Replace http:// with https:// for all endpoints.
- Replace Telnet with SSH.
- Replace rand()/Math.random() with CSPRNG:
    C/C++:    RAND_bytes(buf, len)
    Python:   secrets.token_bytes(n)
    Node.js:  crypto.randomBytes(n)
    Java:     SecureRandom.getInstanceStrong()
)API";

        default:
            return "";
        }
    }

    // -----------------------------------------------------------------------
    // Get a working usage example for the given category and language
    // -----------------------------------------------------------------------
    static std::string get_usage_example(PqcCategory cat, const std::string& lang) {
        // C/C++ examples (default for all categories)
        if (lang == ".cpp" || lang == ".c" || lang == ".h" || lang == ".hpp") {
            switch (cat) {
            case PqcCategory::KEM:
                return R"EXAMPLE(
// Example: ML-KEM (FIPS 203) key exchange (replaces RSA key exchange)
#include "QuantumKyber.hpp"

void secure_key_exchange() {
    // Recipient generates ML-KEM keypair
    QuantumWrapper kyber;
    auto [pub_key, sec_key] = kyber.generate_keypair();

    // Sender encapsulates using recipient's public key
    QuantumWrapper sender_kyber;
    auto [ciphertext, shared_secret] = sender_kyber.encapsulate(pub_key);

    // Recipient decapsulates to recover the same shared secret
    auto recovered_secret = kyber.decapsulate(ciphertext, sec_key);
    // shared_secret == recovered_secret (use as AES-256 key)
}
)EXAMPLE";

            case PqcCategory::SIGNATURE:
                return R"EXAMPLE(
// Example: ML-DSA (FIPS 204) digital signature (replaces RSA/DSA/ECDSA signing)
#include "QuantumKyber.hpp"

bool sign_and_verify(const std::vector<uint8_t>& message) {
    DilithiumWrapper dil;
    auto [pub_key, sec_key] = dil.generate_signature_keypair();

    // Sign with ML-DSA
    auto signature = dil.sign_message(message);

    // Verify with ML-DSA
    return dil.verify_signature(message, signature);
}
)EXAMPLE";

            case PqcCategory::SIGNATURE_STATELESS:
                return R"EXAMPLE(
// Example: SLH-DSA (FIPS 205) stateless hash-based signature
#include "QuantumKyber.hpp"

bool sign_and_verify_sphincs(const std::vector<uint8_t>& message) {
    // SPHINCS+-SHA2-128f-simple: fast variant, security level 1
    SphincsPlusWrapper sphincs;
    auto [pub_key, sec_key] = sphincs.generate_keypair();

    // Sign with SLH-DSA (note: larger signature ~17KB)
    auto signature = sphincs.sign_message(message);

    // Verify with SLH-DSA
    return sphincs.verify_signature(message, signature);
}
)EXAMPLE";

            case PqcCategory::HYBRID_KEM:
                return R"EXAMPLE(
// Example: Hybrid X25519+ML-KEM-768 key exchange (transitional security)
#include "QuantumKyber.hpp"

void hybrid_key_exchange() {
    HybridKemWrapper hybrid;

    // Recipient generates hybrid keypair
    auto kp = hybrid.generate_keypair();

    // Sender encapsulates using recipient's public keys
    auto encap = hybrid.encapsulate(kp.x25519_public, kp.mlkem_public);
    // encap.shared_secret is SHA-256(X25519_ss || ML-KEM_ss)

    // Recipient decapsulates to recover the same shared secret
    auto recovered = hybrid.decapsulate(
        encap.x25519_public, encap.mlkem_ciphertext,
        kp.x25519_private, kp.mlkem_secret);
    // encap.shared_secret == recovered (use as AES-256 key)
}
)EXAMPLE";

            case PqcCategory::CIPHER:
                return R"EXAMPLE(
// Example: AES-256 with ML-KEM (FIPS 203) (replaces DES/AES-128/ECB)
#include "QuantumKyber.hpp"
#include "AES.hpp"
#include <openssl/rand.h>

std::vector<uint8_t> encrypt_data(const std::vector<uint8_t>& plaintext,
                                   QuantumWrapper& kyber) {
    // Generate AES-256 key via ML-KEM
    auto [ciphertext_kem, shared_secret] = kyber.encapsulate(kyber.get_public_key());

    // Derive 32-byte AES key from shared secret
    std::vector<uint8_t> aes_key(32);
    SHA256(shared_secret.data(), shared_secret.size(), aes_key.data());

    // Random IV (NEVER hardcode or reuse)
    std::vector<uint8_t> iv(16);
    RAND_bytes(iv.data(), 16);

    return AES::encrypt(plaintext, aes_key, iv);
}
)EXAMPLE";

            default:
                return "";
            }
        }

        // Python examples
        if (lang == ".py") {
            switch (cat) {
            case PqcCategory::KEM:
                return R"EXAMPLE(
# Example: ML-KEM (FIPS 203) key exchange in Python (replaces RSA)
import oqs

# Recipient
kem = oqs.KeyEncapsulation("ML-KEM-512")
public_key = kem.generate_keypair()

# Sender
sender = oqs.KeyEncapsulation("ML-KEM-512")
ciphertext, shared_secret_sender = sender.encap_secret(public_key)

# Recipient recovers
shared_secret_recipient = kem.decap_secret(ciphertext)
# shared_secret_sender == shared_secret_recipient
)EXAMPLE";

            case PqcCategory::SIGNATURE:
                return R"EXAMPLE(
# Example: ML-DSA (FIPS 204) signatures in Python (replaces DSA/ECDSA)
import oqs

sig = oqs.Signature("ML-DSA-65")
public_key = sig.generate_keypair()
message = b"data to sign"

signature = sig.sign(message)
is_valid = sig.verify(message, signature, public_key)
)EXAMPLE";

            case PqcCategory::SIGNATURE_STATELESS:
                return R"EXAMPLE(
# Example: SLH-DSA (FIPS 205) stateless signatures in Python
import oqs

sig = oqs.Signature("SPHINCS+-SHA2-128f-simple")
public_key = sig.generate_keypair()
message = b"data to sign"

signature = sig.sign(message)
is_valid = sig.verify(message, signature, public_key)
# Note: signature is ~17KB (larger than ML-DSA's ~3KB)
)EXAMPLE";

            default:
                return "";
            }
        }

        // Java/Kotlin examples
        if (lang == ".java" || lang == ".kt") {
            switch (cat) {
            case PqcCategory::KEM:
                return R"EXAMPLE(
// Example: ML-KEM (FIPS 203) in Java (replaces RSA KeyPairGenerator)
// Dependency: org.openquantumsafe:liboqs-java:0.10.0
import org.openquantumsafe.KEMs;
import org.openquantumsafe.KeyEncapsulation;

KeyEncapsulation kem = new KeyEncapsulation("ML-KEM-512");
byte[] publicKey = kem.generate_keypair();
// Sender encapsulates:
org.openquantumsafe.Pair pair = kem.encap_secret(publicKey);
byte[] ciphertext = pair.getLeft();
byte[] sharedSecret = pair.getRight();
)EXAMPLE";

            default:
                return "";
            }
        }

        // Go examples
        if (lang == ".go") {
            switch (cat) {
            case PqcCategory::KEM:
                return R"EXAMPLE(
// Example: ML-KEM (FIPS 203) in Go (replaces RSA/ECDH)
// go get github.com/niclas-2109/liboqs-go
import "github.com/niclas-2109/liboqs-go/oqs"

kem := oqs.KeyEncapsulation{}
kem.Init("ML-KEM-512", nil)
defer kem.Clean()
pubKey, _ := kem.GenerateKeyPair()
ciphertext, sharedSecret, _ := kem.EncapSecret(pubKey)
)EXAMPLE";

            default:
                return "";
            }
        }

        // Rust examples
        if (lang == ".rs") {
            switch (cat) {
            case PqcCategory::KEM:
                return R"EXAMPLE(
// Example: ML-KEM (FIPS 203) in Rust (replaces RSA/ECDH)
// Cargo.toml: oqs = "0.10"
use oqs::kem::{Kem, Algorithm};

let kem = Kem::new(Algorithm::MlKem512).unwrap();
let (pk, sk) = kem.keypair().unwrap();
let (ct, ss_sender) = kem.encapsulate(&pk).unwrap();
let ss_receiver = kem.decapsulate(&sk, &ct).unwrap();
)EXAMPLE";

            default:
                return "";
            }
        }

        return "";
    }

    // -----------------------------------------------------------------------
    // Get the include directive / dependency for the target language
    // -----------------------------------------------------------------------
    static std::string get_include_directive(PqcCategory cat, const std::string& lang) {
        if (cat == PqcCategory::HASH || cat == PqcCategory::CONFIG)
            return ""; // No custom include needed — stdlib only

        // SIGNATURE_STATELESS and HYBRID_KEM use the same header as KEM/SIGNATURE
        if (lang == ".cpp" || lang == ".c" || lang == ".h" || lang == ".hpp")
            return "#include \"vendor/quantum_migrate/QuantumKyber.hpp\"";
        if (lang == ".py")
            return "import oqs  # pip install liboqs-python";
        if (lang == ".java" || lang == ".kt")
            return "import org.openquantumsafe.*;  // Maven: org.openquantumsafe:liboqs-java";
        if (lang == ".go")
            return "import \"github.com/niclas-2109/liboqs-go/oqs\"";
        if (lang == ".rs")
            return "use oqs::kem::{Kem, Algorithm};  // Cargo.toml: oqs = \"0.10\"";
        if (lang == ".rb")
            return "require 'liboqs'  # gem install liboqs";
        if (lang == ".swift")
            return "// Link liboqs via Swift Package Manager or bridging header";
        if (lang == ".ts" || lang == ".js" || lang == ".tsx" || lang == ".jsx")
            return "// Note: PQC not available in browser JS. Use server-side liboqs proxy.";

        return "";
    }

    // -----------------------------------------------------------------------
    // Get a language-specific binding note
    // -----------------------------------------------------------------------
    static std::string get_language_binding_note(const std::string& lang) {
        if (lang == ".cpp" || lang == ".c" || lang == ".h" || lang == ".hpp")
            return "Use the QuantumKyber.hpp C++ API directly. Link with liboqs.";
        if (lang == ".py")
            return "Use the liboqs-python package: pip install liboqs-python. "
                   "API: oqs.KeyEncapsulation('ML-KEM-512'), oqs.Signature('ML-DSA-65').";
        if (lang == ".java" || lang == ".kt")
            return "Use liboqs-java: Maven artifact org.openquantumsafe:liboqs-java:0.10.0. "
                   "Classes: KeyEncapsulation, Signature.";
        if (lang == ".go")
            return "Use liboqs-go: go get github.com/niclas-2109/liboqs-go. "
                   "API: oqs.KeyEncapsulation{} (ML-KEM), oqs.Signature{} (ML-DSA).";
        if (lang == ".rs")
            return "Use oqs crate: oqs = \"0.10\" in Cargo.toml. "
                   "API: oqs::kem::Kem (ML-KEM), oqs::sig::Sig (ML-DSA).";
        if (lang == ".rb")
            return "Use liboqs Ruby bindings via FFI. gem install ffi, then bind liboqs C API.";
        if (lang == ".swift")
            return "Use liboqs via C interop bridging header. Add liboqs as a Swift Package dependency.";
        if (lang == ".ts" || lang == ".js" || lang == ".tsx" || lang == ".jsx")
            return "PQC is not directly available in browser JavaScript. "
                   "For server-side Node.js, use node-ffi-napi to bind liboqs. "
                   "For browser apps, proxy PQC operations through a server API endpoint.";
        return "Use liboqs C API via FFI for this language.";
    }
};
