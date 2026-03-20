#pragma once
// ============================================================================
// ProximityAnalyzer.hpp - Cipher mode and parameter proximity analysis
// ============================================================================
// When a cryptographic keyword is found, this analyzer examines surrounding
// lines (configurable window, default +/- 3) to detect weak cipher modes,
// inadequate key sizes, and insecure parameter combinations.
//
// Examples:
//   - AES + ECB mode → CRITICAL (deterministic encryption)
//   - RSA + 1024-bit key → CRITICAL (facterable with current hardware)
//   - CBC without HMAC → HIGH (potential padding oracle)
//   - Static/hardcoded IV → HIGH (nonce reuse)
// ============================================================================

#include "ScanTypes.hpp"
#include "RegexEngine.hpp"
#include <string>
#include <vector>
#include <algorithm>

class ProximityAnalyzer {
public:
    // Analyze lines surrounding a vulnerability finding
    static void analyze(const std::vector<std::string>& lines,
                        int finding_line_index,  // 0-based
                        const Rule& rule,
                        ScanResult& result,
                        int window = 3) {
        int start = std::max(0, finding_line_index - window);
        int end = std::min(static_cast<int>(lines.size()) - 1, finding_line_index + window);

        for (int i = start; i <= end; i++) {
            if (i == finding_line_index) continue;  // Skip the finding line itself

            const std::string& line = lines[i];

            for (const auto& [pattern, desc, upgraded_severity] : get_weak_patterns()) {
                if (pattern.search(line)) {
                    ProximityFinding pf;
                    pf.line_number = i + 1;  // 1-based
                    pf.description = desc;
                    pf.line_content = line;
                    result.proximity_findings.push_back(pf);

                    // Upgrade severity if the proximity finding warrants it
                    if (!upgraded_severity.empty()
                        && severity_rank(upgraded_severity) < severity_rank(result.severity)) {
                        result.severity = upgraded_severity;
                    }
                }
            }
        }
    }

private:
    struct WeakPattern {
        qre::Regex pattern;
        std::string description;
        std::string upgraded_severity;  // if set, escalates the finding
    };

    static const std::vector<WeakPattern>& get_weak_patterns() {
        static const std::vector<WeakPattern> patterns = []() {
            std::vector<WeakPattern> p = {
                // ECB mode - always bad
                {qre::Regex(R"(\bECB\b|MODE_ECB|_ecb\(|AES\.MODE_ECB)", true),
                 "ECB cipher mode detected nearby - no diffusion, deterministic encryption",
                 "critical"},

                // CBC without HMAC (potential padding oracle)
                {qre::Regex(R"(\bCBC\b|MODE_CBC|_cbc\()", true),
                 "CBC mode detected nearby - ensure HMAC/MAC is used for integrity (use GCM instead)",
                 ""},

                // PKCS1v1.5 padding
                {qre::Regex(R"(PKCS1v1[._]?5|PKCS1_PADDING|pkcs1_v1_5)", true),
                 "PKCS#1 v1.5 padding detected nearby - vulnerable to Bleichenbacher attack",
                 "high"},

                // Weak RSA key sizes
                {qre::Regex(R"(\b(1024|512|768)\s*(bit|byte|key_?size|bits|modulus))", true),
                 "Weak key size detected nearby - use at least 3072 bits for RSA (or migrate to PQC)",
                 "critical"},
                {qre::Regex(R"(key_?size\s*[=:]\s*(512|768|1024)\b)", true),
                 "Weak key size assignment detected nearby",
                 "critical"},

                // Hardcoded/static IV
                {qre::Regex(R"(iv\s*=\s*["'\{]|IV\s*=\s*["'\{]|nonce\s*=\s*["'\{])", true),
                 "Potential hardcoded IV/nonce detected nearby - use random IV for each encryption",
                 "high"},
                {qre::Regex(R"(\b(static|const)\s+.*\b(iv|nonce|IV)\b)", true),
                 "Static IV/nonce declaration detected nearby - IVs must be random per encryption",
                 "high"},

                // No padding (potential issue)
                {qre::Regex(R"(NoPadding|no_padding|NONE.*padding)", true),
                 "No-padding mode detected nearby - may indicate manual block handling",
                 ""},

                // Deprecated OpenSSL functions
                {qre::Regex(R"(\b(EVP_MD_CTX_cleanup|EVP_MD_CTX_destroy)\b)", true),
                 "Deprecated OpenSSL function detected nearby",
                 ""},

                // Insecure random for crypto
                {qre::Regex(R"(\brand\(\)|srand\(|Math\.random\(\)|random\.random\(\))", true),
                 "Weak RNG used near cryptographic operation - use CSPRNG instead",
                 "high"},
            };
            return p;
        }();

        return patterns;
    }

    static int severity_rank(const std::string& s) {
        if (s == "critical") return 0;
        if (s == "high") return 1;
        if (s == "warning") return 2;
        return 3;
    }
};
