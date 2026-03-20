# Quantum-Migration-Toolkit

**Enterprise PQC Auto-Migration Tool** — Scan, Remediate, Vendor, Ship.

> Detect quantum-vulnerable cryptography, rewrite it with AI, inject a working PQC SDK, and patch your build system — in one command.

---

## Why Quantum-Safe Cryptography?

The quantum computing revolution is approaching. When large-scale quantum computers arrive, current cryptographic algorithms (RSA, ECC, DES, MD5, SHA-1) will be broken in minutes. Organizations must act now to protect their data against **"harvest now, decrypt later"** attacks.

**Quantum-Migration-Toolkit** is a unified, enterprise-grade tool that:
- **Scans** 9+ languages for vulnerable cryptographic patterns (regex + AST)
- **Remediates** findings with a local LLM that outputs code grounded in real PQC APIs
- **Vendors** a working Kyber/AES SDK directly into your project
- **Patches** your build system (CMake, pip, Cargo, Maven, Gradle, Go, NPM)
- **Backs up** everything for safe rollback

---

## Architecture

```
quantum-migrate (CLI)
  └─ libquantum_migrate (static library)
       ├─ engine/scan/     — Regex + Tree-sitter AST detection
       ├─ engine/ai/       — PqcContext + AiRemediator (llama.cpp)
       ├─ engine/patch/    — AutoRemediator + DependencyInjector
       ├─ engine/pqc/      — QuantumKyber + AES-256 + FileEncryptor
       └─ engine/vendor/   — SDK files vendored into target projects
```

---

## Quick Start

### Prerequisites
- **C++17 compiler** (GCC 7+, Clang 5+, MSVC 2017+)
- **CMake 3.16+**
- **OpenSSL 1.1.1+**
- **liboqs** (auto-fetched via FetchContent if not installed)

### Build

```bash
git clone https://github.com/Savaid-KhanOfficial/Quantum-Migration-Toolkit.git
cd Quantum-Migration-Toolkit

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Optional features (all OFF by default):
```bash
cmake -S . -B build \
    -DUSE_RE2=ON          \  # Google RE2 regex engine
    -DUSE_TREESITTER=ON   \  # Tree-sitter AST engine (5 grammars)
    -DUSE_LLAMA=ON           # llama.cpp AI remediation
```

### Run

```bash
# Basic scan
./build/cli/quantum-migrate /path/to/code

# Full pipeline: scan + AI + vendor + patch + backup
./build/cli/quantum-migrate /path/to/code \
    --model models/qwen2.5-coder-7b-instruct-q4_k_m.gguf \
    --remediate \
    --vendor-into /path/to/code \
    --patch-build-system \
    --backup \
    --format=sarif \
    --output=results.sarif
```

### Docker

```bash
docker build -t quantum-migrate .

docker run --rm -v /path/to/code:/scan quantum-migrate \
    /scan --vendor-into /scan --patch-build-system --backup
```

---

## Key Features

### 1. Context-Aware AI Remediation
The LLM doesn't hallucinate API calls — it sees the **actual** QuantumKyber/AES API definitions injected into the prompt via `PqcContext`:

| Rule Category | Mapped API | Example |
|---------------|-----------|---------|
| KEM (RSA, DH, ECDH) | `QuantumKyber::generate_keypair()`, `encapsulate()`, `decapsulate()` | Replace `RSA_generate_key_ex()` with `QuantumKyber` |
| SIGNATURE (DSA, ECDSA) | `DilithiumWrapper::sign()`, `verify()` | Replace `EVP_DigestSign` with `DilithiumWrapper` |
| CIPHER (DES, 3DES, AES-128) | `AES256GCM::encrypt()`, `decrypt()` | Replace `DES_ecb_encrypt` with `AES256GCM` |
| HASH (MD5, SHA-1) | SHA-256 guidance | Replace `MD5()` with `SHA256()` |

### 2. Dependency Injection (Vendoring)
One flag drops a complete PQC SDK into your project:
```bash
--vendor-into ./my_project --patch-build-system
```
Creates `vendor/quantum_migrate/` with headers + `FindQuantumMigrate.cmake` and auto-patches your build system.

### 3. Multi-Language Support
Scans and generates remediations for: **C/C++, Python, Java, Kotlin, Go, Rust, Ruby, Swift, TypeScript/JavaScript**

### 4. Safety & Rollback
- `--backup` creates `.quantum_migrate_backup/` before any changes
- `--dry-run` previews all changes without modifying files
- `quantum_migrate_manifest.json` tracks every modification for rollback

---

## Scan Capabilities

| Feature | Flag | Description |
|---------|------|-------------|
| Regex detection | (default) | 15+ vulnerable patterns with CWE mapping |
| AST validation | `--ast` | Tree-sitter confirms findings in actual code |
| Entropy analysis | `--entropy` | Detect hardcoded secrets (keys, tokens) |
| Proximity analysis | `--proximity` | Cluster related vulnerabilities |
| Baseline diffing | `--baseline` | Track progress across scans |
| SARIF output | `--format=sarif` | IDE-compatible structured results |
| CI exit codes | `--fail-on` | `critical`, `high`, or `warning` threshold |

---

## Cryptographic Algorithms

| Component | Algorithm | Status | Key Size |
|-----------|-----------|--------|----------|
| Key Exchange | **Kyber-512** | NIST Selected (ML-KEM) | 1632 bytes (secret) |
| Symmetric Cipher | **AES-256-GCM** | NIST Approved (AEAD) | 256 bits |
| Digital Signature | **Dilithium** | NIST Selected (ML-DSA) | 2528 bytes (public) |
| Hashing | SHA-256 | Quantum-resistant | 256 bits |

---

## Project Structure

```
Quantum-Migration-Toolkit/
├── CMakeLists.txt              # Root build orchestrator
├── Dockerfile                  # Multi-stage Docker build
├── cli/
│   ├── CMakeLists.txt          # CLI executable target
│   └── main.cpp                # Thin dispatcher (~620 lines)
├── engine/
│   ├── CMakeLists.txt          # libquantum_migrate static library
│   ├── SimpleJson.hpp          # Lightweight JSON parser
│   ├── rules.json              # 15+ vulnerability rules
│   ├── ai/
│   │   ├── AiRemediator.hpp    # Context-aware LLM remediation
│   │   └── PqcContext.hpp      # Rule→API mapping (core innovation)
│   ├── patch/
│   │   ├── AutoRemediator.hpp  # Unified diff patch generation
│   │   ├── DependencyInjector.hpp  # SDK vendoring + build patching
│   │   └── OutputFormatter.hpp # Text/SARIF output
│   ├── pqc/
│   │   ├── AES.hpp             # AES-256 encryption
│   │   ├── FileEncryptor.*     # Hybrid Kyber+AES file encryption
│   │   └── QuantumKyber.*      # Kyber KEM wrapper (liboqs)
│   ├── scan/
│   │   ├── AstEngine.hpp       # Tree-sitter AST validation
│   │   ├── BaselineManager.hpp # Scan-to-scan diffing
│   │   ├── CommentStripper.hpp # Strip comments before scanning
│   │   ├── EntropyDetector.hpp # Hardcoded secret detection
│   │   ├── IgnoreHandler.hpp   # .quantumignore support
│   │   ├── ProximityAnalyzer.hpp # Vulnerability clustering
│   │   ├── RegexEngine.hpp     # std::regex / RE2 abstraction
│   │   ├── RuleEngine.hpp      # JSON rule loader
│   │   ├── ScanTypes.hpp       # Core data structures
│   │   └── ThreadPool.hpp      # Parallel file scanning
│   └── vendor/
│       ├── cmake/FindQuantumMigrate.cmake
│       ├── include/quantum_migrate.h
│       └── README.md
├── models/                     # GGUF model files for AI remediation
├── test_repo/                  # Multi-language test codebase
└── QuantumSaaS/                # Web platform (Express + Next.js)
```

---

## Contributing

We welcome contributions! Whether you're:
- Adding new vulnerability patterns
- Adding language grammars for Tree-sitter
- Implementing additional PQC algorithms
- Improving documentation

Please open an issue or submit a pull request.

---

## License

This project is open-source and available under the MIT License.

---

## Related Projects

- [liboqs](https://github.com/open-quantum-safe/liboqs) - Open Quantum Safe cryptographic library
- [NIST PQC Competition](https://csrc.nist.gov/projects/post-quantum-cryptography) - Official NIST post-quantum cryptography standards
- [llama.cpp](https://github.com/ggerganov/llama.cpp) - Local LLM inference engine
- [tree-sitter](https://github.com/tree-sitter/tree-sitter) - Incremental parsing library

---

**Start your quantum-safe migration today with a single command.**
