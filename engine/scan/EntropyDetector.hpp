#pragma once
// ============================================================================
// EntropyDetector.hpp - Shannon entropy calculator for secret detection
// ============================================================================
// Scans source code lines for high-entropy string literals that may indicate
// hardcoded secrets (API keys, encryption keys, tokens, passwords).
// Provides parity with enterprise tools like TruffleHog and GitGuardian.
//
// Shannon Entropy: H = -Σ p(x) * log2(p(x))
// Strings with H > 4.5 are likely encoded secrets (base64, hex, etc.)
//
// v2.1 — Character-set filtering to cut false positives:
//   Before computing entropy, the string must look like an encoded secret
//   (Base64, hex, URL-safe token). Natural-language strings, file paths,
//   SQL fragments, and other high-variety-but-not-secret strings are
//   filtered out before the expensive entropy calculation.
// ============================================================================

#include "ScanTypes.hpp"
#include "RegexEngine.hpp"
#include <string>
#include <vector>
#include <cmath>
#include <map>
#include <sstream>
#include <iomanip>

class EntropyDetector {
public:
    // Scan a single line for high-entropy string literals
    static std::vector<ScanResult> scan_line(const std::string& line,
                                              int line_number,
                                              const std::string& filename,
                                              double threshold = 4.5) {
        std::vector<ScanResult> results;

        // Extract string literals from the line
        std::vector<std::string> strings = extract_string_literals(line);

        for (const auto& s : strings) {
            // Skip short strings (too short for meaningful entropy)
            if (s.size() < 12) continue;

            // ---- Character-set filter (v2.1) ----
            // Only compute entropy for strings that look like encoded secrets:
            //   Base64:    [A-Za-z0-9+/=]
            //   Hex:       [0-9a-fA-F]
            //   URL-safe:  [A-Za-z0-9_\-.]
            // Skip strings containing spaces, newlines, or most punctuation
            // that indicate natural language, SQL, file paths, etc.
            if (!looks_like_encoded_secret(s)) continue;

            double entropy = calculate_entropy(s);

            if (entropy >= threshold) {
                // Additional check: is this near a suspicious variable name?
                bool near_secret_var = is_near_secret_context(line);

                // Only flag if entropy is very high OR if near a secret context
                if (entropy >= 5.0 || near_secret_var) {
                    ScanResult result;
                    result.filename = filename;
                    result.rule_id = "ENTROPY-001";
                    result.keyword = "High-Entropy-Secret";
                    result.severity = near_secret_var ? "critical" : "high";
                    result.line_number = line_number;
                    result.line_content = line;
                    result.description = "Potential hardcoded secret detected (Shannon entropy: " +
                                         format_double(entropy, 2) + ")";
                    result.remediation = "Move secrets to environment variables or a secure vault "
                                         "(e.g., AWS Secrets Manager, HashiCorp Vault, Azure Key Vault)";
                    result.is_entropy_finding = true;
                    result.entropy_value = entropy;
                    result.cwe_id = "CWE-798";
                    results.push_back(result);
                }
            }
        }

        return results;
    }

    // Calculate Shannon entropy of a string
    // H = -Σ p(x) * log2(p(x))
    static double calculate_entropy(const std::string& s) {
        if (s.empty()) return 0.0;

        // Count character frequencies
        std::map<char, int> freq;
        for (char c : s) {
            freq[c]++;
        }

        double entropy = 0.0;
        double len = static_cast<double>(s.size());

        for (const auto& [ch, count] : freq) {
            double p = static_cast<double>(count) / len;
            if (p > 0.0) {
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

private:
    // ---- Character-set filter (v2.1) ----
    // Returns true only if the string looks like it could be an encoded secret.
    // Rejects strings with spaces, common prose punctuation, path separators,
    // parentheses, etc. that indicate non-secret high-entropy text.
    static bool looks_like_encoded_secret(const std::string& s) {
        // Allowlist: characters found in Base64, hex, URL-safe tokens, JWTs
        //   A-Z  a-z  0-9  + / = _ - .
        // Everything else is a "red flag". If more than 10% of the string is
        // outside this allowlist, it's almost certainly not an encoded secret.
        int non_secret_chars = 0;
        for (unsigned char c : s) {
            if (std::isalnum(c)) continue;            // A-Z a-z 0-9
            if (c == '+' || c == '/' || c == '=') continue;  // Base64
            if (c == '_' || c == '-' || c == '.') continue;  // URL-safe / JWT
            non_secret_chars++;
        }

        // If any spaces at all → not a secret (natural language, SQL, etc.)
        for (char c : s) {
            if (c == ' ' || c == '\t') return false;
        }

        // Reject if > 10% of chars are outside the token alphabet
        double ratio = static_cast<double>(non_secret_chars) / static_cast<double>(s.size());
        if (ratio > 0.10) return false;

        // Reject common false-positive patterns:
        //   - File paths (contain :, \, //, ~)
        //   - URLs that aren't tokens (contain ://)
        //   - Format strings with % placeholders
        if (s.find("://") != std::string::npos) return false;
        if (s.find(":\\") != std::string::npos) return false;
        if (s.find("~/") != std::string::npos) return false;

        // Reject strings that are entirely hex digits shorter than 32
        // (likely not secrets — too short for keys/tokens)
        // 32 hex chars = 128-bit key minimum
        bool all_hex = true;
        for (char c : s) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) {
                all_hex = false;
                break;
            }
        }
        if (all_hex && s.size() < 32) return false;

        return true;
    }

    // Extract string literals from a line of code
    static std::vector<std::string> extract_string_literals(const std::string& line) {
        std::vector<std::string> strings;
        size_t i = 0;
        size_t len = line.size();

        while (i < len) {
            // Double-quoted string
            if (line[i] == '"') {
                i++;  // skip opening quote
                std::string s;
                while (i < len && line[i] != '"') {
                    if (line[i] == '\\' && i + 1 < len) {
                        i++;  // skip escaped char
                    }
                    s += line[i];
                    i++;
                }
                if (i < len) i++;  // skip closing quote
                if (!s.empty()) strings.push_back(s);
                continue;
            }

            // Single-quoted string
            if (line[i] == '\'') {
                i++;
                std::string s;
                while (i < len && line[i] != '\'') {
                    if (line[i] == '\\' && i + 1 < len) {
                        i++;
                    }
                    s += line[i];
                    i++;
                }
                if (i < len) i++;
                if (!s.empty()) strings.push_back(s);
                continue;
            }

            i++;
        }

        return strings;
    }

    // Check if the line contains variable names suggesting secrets
    static bool is_near_secret_context(const std::string& line) {
        static const qre::Regex secret_context(
            "(password|passwd|secret|api_key|apikey|token|private_key|"
            "access_key|auth_token|credentials|encryption_key|"
            "client_secret|jwt_secret|signing_key|master_key)",
            true  // case-insensitive
        );
        return secret_context.search(line);
    }

    // Format double to N decimal places
    static std::string format_double(double val, int precision) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(precision) << val;
        return oss.str();
    }
};
