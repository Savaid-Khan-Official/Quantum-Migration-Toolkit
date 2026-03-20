#pragma once
// ============================================================================
// DependencyInjector.hpp — PQC SDK Vendoring & Build-System Patching (v2.1)
// ============================================================================
//
// Architecture: Strategy-pattern build system patching.
//
//   Phase 1: vendor_headers()     — Copy the QuantumMigrate PQC SDK into target
//   Phase 2: patch_build_system() — Iterate registered BuildSystemPatcher
//                                   strategies to auto-detect & patch
//   Phase 3: write_manifest()     — Write quantum_migrate_manifest.json
//
// Adding a new build system (e.g. Bazel, Meson, Swift PM):
//   1. Define a struct inheriting BuildSystemPatcher
//   2. Register it in DependencyInjector::get_patchers()
//   That's it — no other code changes needed.
// ============================================================================

#include "../scan/ScanTypes.hpp"
#include "../SimpleJson.hpp"

#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <algorithm>

namespace fs = std::filesystem;

// Forward declarations
static bool file_contains(const fs::path& path, const std::string& needle);
static bool append_to_file(const fs::path& path, const std::string& text, bool dry_run);
static fs::path find_file_upward(const fs::path& root, const std::string& filename);

// ============================================================================
// BuildSystemPatcher — Strategy interface for build system patching
// ============================================================================
struct BuildSystemPatcher {
    virtual ~BuildSystemPatcher() = default;

    // Human-readable name for logging (e.g. "CMake", "pip", "Cargo")
    virtual std::string name() const = 0;

    // Filenames this patcher looks for (checked in order)
    virtual std::vector<std::string> detection_files() const = 0;

    // Apply the patch. Returns a human-readable description of what was done.
    // Empty string means "not applicable / already patched".
    virtual std::string apply(const fs::path& file_path,
                              const fs::path& target_root,
                              bool dry_run) = 0;
};

// ============================================================================
// Concrete patchers
// ============================================================================

struct CMakePatcher : BuildSystemPatcher {
    std::string name() const override { return "CMake"; }
    std::vector<std::string> detection_files() const override {
        return {"CMakeLists.txt"};
    }
    std::string apply(const fs::path& cmake_path,
                      const fs::path& target_root,
                      bool dry_run) override {
        const std::string marker = "# QuantumMigrate PQC SDK";
        if (file_contains(cmake_path, marker))
            return cmake_path.filename().string() + ": already patched (skipped)";

        fs::path rel_vendor = fs::relative(
            target_root / "vendor" / "quantum_migrate", cmake_path.parent_path());

        std::ostringstream patch;
        patch << "\n" << marker << "\n"
              << "list(APPEND CMAKE_MODULE_PATH "
              << "\"${CMAKE_CURRENT_SOURCE_DIR}/" << rel_vendor.string() << "\")\n"
              << "find_package(QuantumMigrate REQUIRED)\n"
              << "# Link to your targets:\n"
              << "#   target_link_libraries(your_target PRIVATE quantum_migrate::pqc)\n";

        if (append_to_file(cmake_path, patch.str(), dry_run))
            return cmake_path.filename().string()
                   + ": added FindQuantumMigrate + module path";
        return "";
    }
};

struct PythonPatcher : BuildSystemPatcher {
    std::string name() const override { return "Python"; }
    std::vector<std::string> detection_files() const override {
        return {"requirements.txt", "setup.py", "pyproject.toml"};
    }
    std::string apply(const fs::path& py_path,
                      const fs::path& /*target_root*/,
                      bool dry_run) override {
        const std::string marker = "# QuantumMigrate PQC";
        if (file_contains(py_path, marker))
            return py_path.filename().string() + ": already patched (skipped)";

        std::string filename = py_path.filename().string();
        std::string dep_line;
        if (filename == "requirements.txt") {
            dep_line = marker + "\nliboqs-python>=0.10.0\npycryptodome>=3.20.0\n";
        } else {
            dep_line = marker + "\n# Add to install_requires / dependencies:\n"
                       "#   'liboqs-python>=0.10.0',\n"
                       "#   'pycryptodome>=3.20.0',\n";
        }

        if (append_to_file(py_path, dep_line, dry_run))
            return filename + ": added liboqs-python, pycryptodome";
        return "";
    }
};

struct CargoPatcher : BuildSystemPatcher {
    std::string name() const override { return "Cargo"; }
    std::vector<std::string> detection_files() const override {
        return {"Cargo.toml"};
    }
    std::string apply(const fs::path& cargo_path,
                      const fs::path& /*target_root*/,
                      bool dry_run) override {
        const std::string marker = "# QuantumMigrate PQC";
        if (file_contains(cargo_path, marker))
            return "Cargo.toml: already patched (skipped)";

        std::string dep = marker + "\n"
            "[dependencies.oqs]\n"
            "version = \"0.10\"\n"
            "features = [\"ml-kem\", \"ml-dsa\"]\n\n"
            "[dependencies.aes-gcm]\n"
            "version = \"0.10\"\n";

        if (append_to_file(cargo_path, dep, dry_run))
            return "Cargo.toml: added oqs + aes-gcm crates";
        return "";
    }
};

struct GoModPatcher : BuildSystemPatcher {
    std::string name() const override { return "Go"; }
    std::vector<std::string> detection_files() const override {
        return {"go.mod"};
    }
    std::string apply(const fs::path& go_path,
                      const fs::path& /*target_root*/,
                      bool dry_run) override {
        const std::string marker = "// QuantumMigrate PQC";
        if (file_contains(go_path, marker))
            return "go.mod: already patched (skipped)";

        std::string dep = marker + "\n"
            "// Run: go get github.com/open-quantum-safe/liboqs-go@latest\n"
            "// Run: go get golang.org/x/crypto@latest\n";

        if (append_to_file(go_path, dep, dry_run))
            return "go.mod: added liboqs-go instructions";
        return "";
    }
};

struct MavenPatcher : BuildSystemPatcher {
    std::string name() const override { return "Maven"; }
    std::vector<std::string> detection_files() const override {
        return {"pom.xml"};
    }
    std::string apply(const fs::path& pom_path,
                      const fs::path& /*target_root*/,
                      bool dry_run) override {
        const std::string marker = "<!-- QuantumMigrate PQC -->";
        if (file_contains(pom_path, marker))
            return "pom.xml: already patched (skipped)";

        std::string dep =
            "\n" + marker + "\n"
            "<!-- Add inside <dependencies>: -->\n"
            "<!--\n"
            "<dependency>\n"
            "  <groupId>org.openquantumsafe</groupId>\n"
            "  <artifactId>liboqs-java</artifactId>\n"
            "  <version>0.10.0</version>\n"
            "</dependency>\n"
            "-->\n";

        if (append_to_file(pom_path, dep, dry_run))
            return "pom.xml: added liboqs-java dependency comment";
        return "";
    }
};

struct GradlePatcher : BuildSystemPatcher {
    std::string name() const override { return "Gradle"; }
    std::vector<std::string> detection_files() const override {
        return {"build.gradle", "build.gradle.kts"};
    }
    std::string apply(const fs::path& gradle_path,
                      const fs::path& /*target_root*/,
                      bool dry_run) override {
        const std::string marker = "// QuantumMigrate PQC";
        if (file_contains(gradle_path, marker))
            return gradle_path.filename().string()
                   + ": already patched (skipped)";

        std::string dep = marker + "\n"
            "// Add to dependencies { }:\n"
            "//   implementation 'org.openquantumsafe:liboqs-java:0.10.0'\n";

        if (append_to_file(gradle_path, dep, dry_run))
            return gradle_path.filename().string()
                   + ": added liboqs-java dependency";
        return "";
    }
};

struct NpmPatcher : BuildSystemPatcher {
    std::string name() const override { return "NPM"; }
    std::vector<std::string> detection_files() const override {
        return {"package.json"};
    }
    std::string apply(const fs::path& npm_path,
                      const fs::path& /*target_root*/,
                      bool dry_run) override {
        const std::string marker = "quantum_migrate_setup.md";
        fs::path setup_md = npm_path.parent_path() / marker;
        if (fs::exists(setup_md))
            return "package.json: already patched (skipped)";

        std::string content =
            "# QuantumMigrate PQC Setup for Node.js/TypeScript\n\n"
            "```bash\n"
            "npm install liboqs-node\n"
            "npm install node-forge\n"
            "```\n\n"
            "Then import:\n"
            "```typescript\n"
            "import { KEM } from 'liboqs-node';\n"
            "const kem = new KEM('ML-KEM-512');\n"
            "```\n";

        if (!dry_run) {
            std::ofstream out(setup_md);
            if (out) out << content;
        }
        return "package.json: created quantum_migrate_setup.md";
    }
};

// ============================================================================
// Shared utilities used by patchers (free functions, accessible via ADL)
// ============================================================================
static bool file_contains(const fs::path& path, const std::string& needle) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find(needle) != std::string::npos) return true;
    }
    return false;
}

static bool append_to_file(const fs::path& path, const std::string& text,
                            bool dry_run) {
    if (dry_run) return true;
    fs::path bak = path;
    bak += ".qm_backup";
    if (!fs::exists(bak))
        fs::copy_file(path, bak);

    std::ofstream out(path, std::ios::app);
    if (!out) return false;
    out << "\n" << text << "\n";
    return true;
}

static fs::path find_file_upward(const fs::path& root,
                                  const std::string& filename) {
    if (fs::exists(root / filename))
        return root / filename;
    if (fs::is_directory(root)) {
        for (const auto& entry : fs::directory_iterator(root)) {
            if (entry.is_directory()) {
                auto candidate = entry.path() / filename;
                if (fs::exists(candidate))
                    return candidate;
            }
        }
    }
    return {};
}

// ============================================================================
// DependencyInjector — Orchestrator
// ============================================================================
class DependencyInjector {
public:
    // -----------------------------------------------------------------------
    // Phase 1: Vendor PQC SDK headers into target project
    // -----------------------------------------------------------------------
    VendorManifest vendor_headers(const fs::path& target_root, bool dry_run = false) {
        VendorManifest manifest;
        manifest.migrated_at = iso8601_now();

        fs::path vendor_dir = target_root / "vendor" / "quantum_migrate";

        struct SdkFile {
            std::string filename;
            std::string content;
        };

        std::vector<SdkFile> sdk_files = {
            { "QuantumKyber.hpp", generate_kyber_header() },
            { "AES.hpp",          generate_aes_header() },
            { "FileEncryptor.hpp", generate_encryptor_header() },
            { "quantum_migrate.h", generate_unified_c_header() },
            { "FindQuantumMigrate.cmake", generate_cmake_find_module() },
            { "README.md",        generate_vendor_readme() },
        };

        for (const auto& f : sdk_files) {
            fs::path dest = vendor_dir / f.filename;
            std::string rel = fs::relative(dest, target_root).string();
            manifest.files_added.push_back(rel);

            if (!dry_run) {
                fs::create_directories(vendor_dir);
                std::ofstream out(dest);
                if (out) {
                    out << f.content;
                    std::cout << "[VENDOR] Written: " << rel << "\n";
                } else {
                    std::cerr << "[VENDOR-ERROR] Failed to write: " << dest.string() << "\n";
                }
            } else {
                std::cout << "[VENDOR] [DRY-RUN] Would write: " << rel << "\n";
            }
        }

        return manifest;
    }

    // -----------------------------------------------------------------------
    // Phase 2: Auto-detect & patch build systems via strategy registry
    // -----------------------------------------------------------------------
    std::vector<std::string> patch_build_system(const fs::path& target_root,
                                                 bool dry_run = false) {
        std::vector<std::string> patches;

        for (auto& patcher : get_patchers()) {
            for (const auto& filename : patcher->detection_files()) {
                auto found = find_file_upward(target_root, filename);
                if (!found.empty()) {
                    std::string result = patcher->apply(found, target_root, dry_run);
                    if (!result.empty())
                        patches.push_back(result);
                    break; // first matching file wins per patcher
                }
            }
        }

        if (patches.empty()) {
            patches.push_back("No recognized build system found — "
                              "manual integration required");
        }

        return patches;
    }

    // -----------------------------------------------------------------------
    // Phase 3: Write manifest JSON
    // -----------------------------------------------------------------------
    void write_manifest(const fs::path& target_root,
                        const VendorManifest& manifest) {
        fs::path manifest_path = target_root / "quantum_migrate_manifest.json";

        simple_json::JsonWriter w;
        w.start_object();
        w.key("schema_version"); w.value("2.1");
        w.key("version");        w.value(manifest.version);
        w.key("migrated_at");    w.value(manifest.migrated_at);

        w.key("files_added");
        w.start_array();
        for (const auto& f : manifest.files_added) w.value(f);
        w.end_array();

        w.key("build_patches");
        w.start_array();
        for (const auto& p : manifest.build_patches) w.value(p);
        w.end_array();

        w.key("migrated_files");
        w.start_array();
        for (const auto& m : manifest.migrated_files) w.value(m);
        w.end_array();

        if (!manifest.rollback_patch.empty()) {
            w.key("rollback_patch");
            w.value(manifest.rollback_patch);
        }

        w.end_object();

        std::ofstream out(manifest_path);
        if (out) {
            out << w.str();
            std::cout << "[VENDOR] Manifest written: " << manifest_path.string() << "\n";
        } else {
            std::cerr << "[VENDOR-ERROR] Cannot write manifest: "
                      << manifest_path.string() << "\n";
        }
    }

private:
    // -----------------------------------------------------------------------
    // Strategy registry — add new build systems here
    // -----------------------------------------------------------------------
    static std::vector<std::unique_ptr<BuildSystemPatcher>>& get_patchers() {
        static std::vector<std::unique_ptr<BuildSystemPatcher>> patchers;
        if (patchers.empty()) {
            patchers.push_back(std::make_unique<CMakePatcher>());
            patchers.push_back(std::make_unique<PythonPatcher>());
            patchers.push_back(std::make_unique<CargoPatcher>());
            patchers.push_back(std::make_unique<GoModPatcher>());
            patchers.push_back(std::make_unique<MavenPatcher>());
            patchers.push_back(std::make_unique<GradlePatcher>());
            patchers.push_back(std::make_unique<NpmPatcher>());
        }
        return patchers;
    }

    static std::string iso8601_now() {
        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf{};
#ifdef _WIN32
        gmtime_s(&tm_buf, &t);
#else
        gmtime_r(&t, &tm_buf);
#endif
        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%SZ");
        return oss.str();
    }

    // =======================================================================
    // Generated SDK file contents (vendored into target projects)
    // =======================================================================

    static std::string generate_kyber_header() {
        return R"(#pragma once
// QuantumKyber.hpp — PQC wrapper (vendored by QuantumMigrate)
//   ML-KEM  (FIPS 203) — Key Encapsulation
//   ML-DSA  (FIPS 204) — Digital Signatures (via DilithiumWrapper)
//   SLH-DSA (FIPS 205) — Stateless Hash-Based Signatures (via SphincsPlusWrapper)
//   Hybrid  X25519+ML-KEM-768 — Transitional Key Exchange
// Link against liboqs and OpenSSL.

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

// ---------------------------------------------------------------------------
// QuantumKyber — ML-KEM (FIPS 203) Key Encapsulation
// ---------------------------------------------------------------------------
class QuantumKyber {
public:
    explicit QuantumKyber(const std::string& variant = "Kyber512") {
        kem_ = OQS_KEM_new(variant.c_str());
        if (!kem_) throw std::runtime_error("Failed to init " + variant);
    }

    ~QuantumKyber() { if (kem_) OQS_KEM_free(kem_); }

    struct KeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> secret_key;
    };

    KeyPair generate_keypair() {
        KeyPair kp;
        kp.public_key.resize(kem_->length_public_key);
        kp.secret_key.resize(kem_->length_secret_key);
        if (OQS_KEM_keypair(kem_, kp.public_key.data(),
                            kp.secret_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("Keypair generation failed");
        return kp;
    }

    struct EncapResult {
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> shared_secret;
    };

    EncapResult encapsulate(const std::vector<uint8_t>& public_key) {
        EncapResult r;
        r.ciphertext.resize(kem_->length_ciphertext);
        r.shared_secret.resize(kem_->length_shared_secret);
        if (OQS_KEM_encaps(kem_, r.ciphertext.data(),
                           r.shared_secret.data(), public_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("Encapsulation failed");
        return r;
    }

    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& secret_key) {
        std::vector<uint8_t> shared(kem_->length_shared_secret);
        if (OQS_KEM_decaps(kem_, shared.data(), ciphertext.data(),
                           secret_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("Decapsulation failed");
        return shared;
    }

private:
    OQS_KEM* kem_ = nullptr;
};

// ---------------------------------------------------------------------------
// SphincsPlusVendored — SLH-DSA (FIPS 205) Stateless Signatures
// ---------------------------------------------------------------------------
class SphincsPlusVendored {
public:
    explicit SphincsPlusVendored(const std::string& variant = "SPHINCS+-SHA2-128f-simple") {
        sig_ = OQS_SIG_new(variant.c_str());
        if (!sig_) throw std::runtime_error("Failed to init " + variant);
    }

    ~SphincsPlusVendored() { if (sig_) OQS_SIG_free(sig_); }

    struct KeyPair {
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> secret_key;
    };

    KeyPair generate_keypair() {
        KeyPair kp;
        kp.public_key.resize(sig_->length_public_key);
        kp.secret_key.resize(sig_->length_secret_key);
        if (OQS_SIG_keypair(sig_, kp.public_key.data(),
                            kp.secret_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("SLH-DSA keypair generation failed");
        return kp;
    }

    std::vector<uint8_t> sign(const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& secret_key) {
        std::vector<uint8_t> sig(sig_->length_signature);
        size_t sig_len = 0;
        if (OQS_SIG_sign(sig_, sig.data(), &sig_len,
                          message.data(), message.size(),
                          secret_key.data()) != OQS_SUCCESS)
            throw std::runtime_error("SLH-DSA signing failed");
        sig.resize(sig_len);
        return sig;
    }

    bool verify(const std::vector<uint8_t>& message,
                const std::vector<uint8_t>& signature,
                const std::vector<uint8_t>& public_key) {
        return OQS_SIG_verify(sig_, message.data(), message.size(),
                              signature.data(), signature.size(),
                              public_key.data()) == OQS_SUCCESS;
    }

private:
    OQS_SIG* sig_ = nullptr;
};

// ---------------------------------------------------------------------------
// HybridKem — X25519 + ML-KEM-768 Hybrid Key Exchange
// Combined shared secret: SHA-256(X25519_ss || ML-KEM_ss)
// ---------------------------------------------------------------------------
class HybridKem {
public:
    explicit HybridKem(const std::string& mlkem_variant = "ML-KEM-768") {
        kem_ = OQS_KEM_new(mlkem_variant.c_str());
        if (!kem_) throw std::runtime_error("Failed to init " + mlkem_variant);
    }

    ~HybridKem() { if (kem_) OQS_KEM_free(kem_); }

    struct HybridKeyPair {
        std::vector<uint8_t> x25519_public;   // 32 bytes
        std::vector<uint8_t> x25519_private;  // 32 bytes
        std::vector<uint8_t> mlkem_public;
        std::vector<uint8_t> mlkem_secret;
    };

    struct HybridEncapResult {
        std::vector<uint8_t> x25519_public;   // sender ephemeral
        std::vector<uint8_t> mlkem_ciphertext;
        std::vector<uint8_t> shared_secret;   // 32 bytes
    };

    HybridKeyPair generate_keypair() {
        HybridKeyPair kp;
        // X25519 via OpenSSL
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY* pkey = nullptr;
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);

        size_t len = 32;
        kp.x25519_public.resize(32);
        kp.x25519_private.resize(32);
        EVP_PKEY_get_raw_public_key(pkey, kp.x25519_public.data(), &len);
        len = 32;
        EVP_PKEY_get_raw_private_key(pkey, kp.x25519_private.data(), &len);
        EVP_PKEY_free(pkey);

        // ML-KEM via liboqs
        kp.mlkem_public.resize(kem_->length_public_key);
        kp.mlkem_secret.resize(kem_->length_secret_key);
        if (OQS_KEM_keypair(kem_, kp.mlkem_public.data(),
                            kp.mlkem_secret.data()) != OQS_SUCCESS)
            throw std::runtime_error("ML-KEM keypair generation failed");
        return kp;
    }

    HybridEncapResult encapsulate(const std::vector<uint8_t>& x25519_peer_pub,
                                   const std::vector<uint8_t>& mlkem_peer_pub) {
        HybridEncapResult res;
        // X25519 ephemeral ECDH
        EVP_PKEY_CTX* gctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY* eph = nullptr;
        EVP_PKEY_keygen_init(gctx);
        EVP_PKEY_keygen(gctx, &eph);
        EVP_PKEY_CTX_free(gctx);
        size_t len = 32;
        res.x25519_public.resize(32);
        EVP_PKEY_get_raw_public_key(eph, res.x25519_public.data(), &len);
        EVP_PKEY* peer = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr, x25519_peer_pub.data(), 32);
        EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(eph, nullptr);
        std::vector<uint8_t> x_ss(32);
        size_t ss_len = 32;
        EVP_PKEY_derive_init(dctx);
        EVP_PKEY_derive_set_peer(dctx, peer);
        EVP_PKEY_derive(dctx, x_ss.data(), &ss_len);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer);
        EVP_PKEY_free(eph);
        // ML-KEM encapsulate
        res.mlkem_ciphertext.resize(kem_->length_ciphertext);
        std::vector<uint8_t> m_ss(kem_->length_shared_secret);
        OQS_KEM_encaps(kem_, res.mlkem_ciphertext.data(),
                        m_ss.data(), mlkem_peer_pub.data());
        // Combine
        std::vector<uint8_t> cat;
        cat.insert(cat.end(), x_ss.begin(), x_ss.end());
        cat.insert(cat.end(), m_ss.begin(), m_ss.end());
        res.shared_secret.resize(32);
        SHA256(cat.data(), cat.size(), res.shared_secret.data());
        std::memset(x_ss.data(), 0, 32);
        std::memset(m_ss.data(), 0, m_ss.size());
        return res;
    }

    std::vector<uint8_t> decapsulate(const std::vector<uint8_t>& x25519_sender_pub,
                                      const std::vector<uint8_t>& mlkem_ct,
                                      const std::vector<uint8_t>& x25519_priv,
                                      const std::vector<uint8_t>& mlkem_sk) {
        EVP_PKEY* my = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, nullptr, x25519_priv.data(), 32);
        EVP_PKEY* sender = EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr, x25519_sender_pub.data(), 32);
        EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(my, nullptr);
        std::vector<uint8_t> x_ss(32);
        size_t ss_len = 32;
        EVP_PKEY_derive_init(dctx);
        EVP_PKEY_derive_set_peer(dctx, sender);
        EVP_PKEY_derive(dctx, x_ss.data(), &ss_len);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(sender);
        EVP_PKEY_free(my);
        std::vector<uint8_t> m_ss(kem_->length_shared_secret);
        OQS_KEM_decaps(kem_, m_ss.data(), mlkem_ct.data(), mlkem_sk.data());
        std::vector<uint8_t> cat;
        cat.insert(cat.end(), x_ss.begin(), x_ss.end());
        cat.insert(cat.end(), m_ss.begin(), m_ss.end());
        std::vector<uint8_t> ss(32);
        SHA256(cat.data(), cat.size(), ss.data());
        std::memset(x_ss.data(), 0, 32);
        std::memset(m_ss.data(), 0, m_ss.size());
        return ss;
    }

private:
    OQS_KEM* kem_ = nullptr;
};
)";
    }

    static std::string generate_aes_header() {
        return R"(#pragma once
// AES.hpp — AES-256-GCM wrapper (vendored by QuantumMigrate)
// Uses OpenSSL EVP for AEAD encryption.

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstring>

class AES256GCM {
public:
    static constexpr size_t KEY_SIZE = 32;  // 256 bits
    static constexpr size_t IV_SIZE  = 12;  // 96 bits (GCM standard)
    static constexpr size_t TAG_SIZE = 16;  // 128-bit auth tag

    // Encrypt plaintext with AES-256-GCM.
    // Returns IV + ciphertext + tag.
    static std::vector<uint8_t> encrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& plaintext)
    {
        if (key.size() != KEY_SIZE)
            throw std::runtime_error("AES key must be 32 bytes");

        std::vector<uint8_t> iv(IV_SIZE);
        RAND_bytes(iv.data(), IV_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key.data(), iv.data());

        std::vector<uint8_t> ct(plaintext.size() + TAG_SIZE);
        int len = 0;
        EVP_EncryptUpdate(ctx, ct.data(), &len,
                          plaintext.data(), (int)plaintext.size());
        int ct_len = len;
        EVP_EncryptFinal_ex(ctx, ct.data() + len, &len);
        ct_len += len;

        uint8_t tag[TAG_SIZE];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
        EVP_CIPHER_CTX_free(ctx);

        // Output: IV || ciphertext || tag
        std::vector<uint8_t> out;
        out.reserve(IV_SIZE + ct_len + TAG_SIZE);
        out.insert(out.end(), iv.begin(), iv.end());
        out.insert(out.end(), ct.begin(), ct.begin() + ct_len);
        out.insert(out.end(), tag, tag + TAG_SIZE);
        return out;
    }

    // Decrypt IV+ciphertext+tag produced by encrypt().
    static std::vector<uint8_t> decrypt(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data)
    {
        if (key.size() != KEY_SIZE)
            throw std::runtime_error("AES key must be 32 bytes");
        if (data.size() < IV_SIZE + TAG_SIZE)
            throw std::runtime_error("Ciphertext too short");

        const uint8_t* iv  = data.data();
        const uint8_t* ct  = data.data() + IV_SIZE;
        int ct_len = (int)(data.size() - IV_SIZE - TAG_SIZE);
        const uint8_t* tag = data.data() + IV_SIZE + ct_len;

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv);

        std::vector<uint8_t> pt(ct_len);
        int len = 0;
        EVP_DecryptUpdate(ctx, pt.data(), &len, ct, ct_len);

        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                            (void*)tag);

        if (EVP_DecryptFinal_ex(ctx, pt.data() + len, &len) <= 0) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AES-GCM authentication failed");
        }
        EVP_CIPHER_CTX_free(ctx);
        return pt;
    }
};
)";
    }

    static std::string generate_encryptor_header() {
        return R"(#pragma once
// FileEncryptor.hpp — Hybrid Kyber+AES file encryption (vendored by QuantumMigrate)
// Combines Kyber KEM for key exchange with AES-256-GCM for data encryption.

#include "QuantumKyber.hpp"
#include "AES.hpp"
#include <fstream>
#include <iterator>

class FileEncryptor {
public:
    struct EncryptedPackage {
        std::vector<uint8_t> kem_ciphertext;  // Kyber encapsulated key
        std::vector<uint8_t> encrypted_data;  // AES-256-GCM(IV + ct + tag)
    };

    // Encrypt a file using hybrid Kyber+AES scheme.
    static EncryptedPackage encrypt_file(
        const std::string& filepath,
        const std::vector<uint8_t>& public_key,
        const std::string& kem_variant = "Kyber512")
    {
        // Read file
        std::ifstream in(filepath, std::ios::binary);
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());

        // KEM: derive shared secret
        QuantumKyber kem(kem_variant);
        auto [ciphertext, shared_secret] = kem.encapsulate(public_key);

        // Use shared secret as AES key (first 32 bytes)
        std::vector<uint8_t> aes_key(shared_secret.begin(),
                                      shared_secret.begin() + 32);

        // Encrypt data
        auto encrypted = AES256GCM::encrypt(aes_key, data);

        return { ciphertext, encrypted };
    }

    // Decrypt a file using hybrid Kyber+AES scheme.
    static void decrypt_file(
        const std::string& output_path,
        const EncryptedPackage& pkg,
        const std::vector<uint8_t>& secret_key,
        const std::string& kem_variant = "Kyber512")
    {
        // KEM: recover shared secret
        QuantumKyber kem(kem_variant);
        auto shared_secret = kem.decapsulate(pkg.kem_ciphertext, secret_key);

        // Derive AES key
        std::vector<uint8_t> aes_key(shared_secret.begin(),
                                      shared_secret.begin() + 32);

        // Decrypt data
        auto plaintext = AES256GCM::decrypt(aes_key, pkg.encrypted_data);

        // Write output
        std::ofstream out(output_path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(plaintext.data()),
                  plaintext.size());
    }
};
)";
    }

    static std::string generate_unified_c_header() {
        return R"(/* quantum_migrate.h — Unified C-compatible header (vendored by QuantumMigrate)
 *
 * For C++ projects: #include "QuantumKyber.hpp" directly.
 * For C projects or FFI: use this header with the static library.
 */
#ifndef QUANTUM_MIGRATE_H
#define QUANTUM_MIGRATE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Kyber KEM (ML-KEM / FIPS 203) */
int qm_kyber_keygen(unsigned char* pk, unsigned char* sk);
int qm_kyber_encaps(const unsigned char* pk,
                    unsigned char* ct, unsigned char* ss);
int qm_kyber_decaps(const unsigned char* sk,
                    const unsigned char* ct, unsigned char* ss);

/* SPHINCS+ / SLH-DSA (FIPS 205) */
int qm_sphincs_keygen(unsigned char* pk, unsigned char* sk);
int qm_sphincs_sign(const unsigned char* sk,
                    const unsigned char* msg, int msg_len,
                    unsigned char* sig, int* sig_len);
int qm_sphincs_verify(const unsigned char* pk,
                      const unsigned char* msg, int msg_len,
                      const unsigned char* sig, int sig_len);

/* Hybrid X25519+ML-KEM-768 */
int qm_hybrid_keygen(unsigned char* x_pk, unsigned char* x_sk,
                     unsigned char* m_pk, unsigned char* m_sk);
int qm_hybrid_encaps(const unsigned char* x_pk, const unsigned char* m_pk,
                     unsigned char* x_eph_pk, unsigned char* m_ct,
                     unsigned char* ss);
int qm_hybrid_decaps(const unsigned char* x_eph_pk,
                     const unsigned char* m_ct,
                     const unsigned char* x_sk,
                     const unsigned char* m_sk,
                     unsigned char* ss);

/* AES-256-GCM */
int qm_aes256gcm_encrypt(const unsigned char* key,
                          const unsigned char* pt, int pt_len,
                          unsigned char* ct, int* ct_len);
int qm_aes256gcm_decrypt(const unsigned char* key,
                          const unsigned char* ct, int ct_len,
                          unsigned char* pt, int* pt_len);

#ifdef __cplusplus
}
#endif

#endif /* QUANTUM_MIGRATE_H */
)";
    }

    static std::string generate_cmake_find_module() {
        return R"(# FindQuantumMigrate.cmake — CMake find module (vendored by QuantumMigrate)
#
# Usage:
#   list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/vendor/quantum_migrate")
#   find_package(QuantumMigrate REQUIRED)
#   target_link_libraries(your_target PRIVATE quantum_migrate::pqc)
#
# This module finds OpenSSL and liboqs, then creates an INTERFACE target
# that your project can link against.

find_package(OpenSSL REQUIRED)

# Try system liboqs first, fall back to FetchContent
find_library(OQS_LIBRARY NAMES oqs)
find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h)

if(OQS_LIBRARY AND OQS_INCLUDE_DIR)
    message(STATUS "QuantumMigrate: Found system liboqs: ${OQS_LIBRARY}")
else()
    message(STATUS "QuantumMigrate: System liboqs not found — using FetchContent")
    include(FetchContent)
    FetchContent_Declare(liboqs
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG        0.12.0
    )
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(liboqs)
    set(OQS_LIBRARY oqs)
    set(OQS_INCLUDE_DIR "${liboqs_SOURCE_DIR}/include")
endif()

# Create interface target
if(NOT TARGET quantum_migrate::pqc)
    add_library(quantum_migrate_pqc INTERFACE)
    add_library(quantum_migrate::pqc ALIAS quantum_migrate_pqc)

    target_include_directories(quantum_migrate_pqc INTERFACE
        "${CMAKE_CURRENT_LIST_DIR}"
        "${OQS_INCLUDE_DIR}"
    )
    target_link_libraries(quantum_migrate_pqc INTERFACE
        ${OQS_LIBRARY}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()

set(QuantumMigrate_FOUND TRUE)
)";
    }

    static std::string generate_vendor_readme() {
        return R"(# QuantumMigrate PQC SDK (Vendored)

This directory was auto-generated by the **QuantumMigrate** toolkit.

## Files

| File | Purpose |
|------|---------|
| `QuantumKyber.hpp` | ML-KEM (FIPS 203), SLH-DSA (FIPS 205), Hybrid X25519+ML-KEM |
| `AES.hpp` | AES-256-GCM authenticated encryption |
| `FileEncryptor.hpp` | Hybrid Kyber+AES file encryption |
| `quantum_migrate.h` | C-compatible FFI header |
| `FindQuantumMigrate.cmake` | CMake find-module |

## Quick Start (CMake)

```cmake
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/vendor/quantum_migrate")
find_package(QuantumMigrate REQUIRED)
target_link_libraries(your_target PRIVATE quantum_migrate::pqc)
```

## Dependencies

- **liboqs** (auto-fetched if not installed)
- **OpenSSL** >= 1.1.1

## Rollback

To undo all changes, check `quantum_migrate_manifest.json` for the list of
modified files and restore from the `.qm_backup` copies.
)";
    }
};
