#pragma once
// ============================================================================
// RuleEngine.hpp - Dynamic rule loading from rules.json
// ============================================================================
// Loads vulnerability detection rules from an external JSON configuration
// file, compiles regex patterns dynamically. Allows updating the
// vulnerability database without recompiling the scanner binary.
// ============================================================================

#include "../SimpleJson.hpp"
#include "ScanTypes.hpp"
#include <iostream>

class RuleEngine {
public:
    // Load rules from a JSON file
    bool load_from_file(const std::string& path) {
        try {
            json::Value root = json::Value::from_file(path);

            // Load settings
            if (root.has("settings")) {
                const auto& settings = root["settings"];
                entropy_threshold_ = settings["entropy_threshold"].as_number_or(4.5);
                proximity_window_ = static_cast<int>(settings["proximity_window"].as_number_or(3));
                default_fail_severity_ = settings["default_severity_fail"].as_string_or("warning");
            }

            // Load rules
            if (!root.has("rules")) {
                std::cerr << "[WARN] No 'rules' array found in " << path << std::endl;
                return false;
            }

            const auto& rules_arr = root["rules"].as_array();
            for (const auto& rule_val : rules_arr) {
                try {
                    Rule rule;
                    rule.id = rule_val["id"].as_string();
                    rule.keyword = rule_val["keyword"].as_string();
                    rule.description = rule_val["description"].as_string();
                    rule.severity = rule_val["severity"].as_string();
                    rule.pattern_str = rule_val["pattern"].as_string();
                    rule.remediation = rule_val["remediation"].as_string_or("");
                    rule.cwe_id = rule_val["cwe_id"].as_string_or("");

                    // Compile regex pattern
                    rule.compiled_pattern = qre::Regex(
                        rule.pattern_str, true  // case-insensitive
                    );

                    // Load language extensions
                    if (rule_val.has("languages") && rule_val["languages"].is_array()) {
                        for (const auto& lang : rule_val["languages"].as_array()) {
                            rule.languages.push_back(lang.as_string());
                        }
                    }

                    // Load fix patterns
                    if (rule_val.has("fix_patterns") && rule_val["fix_patterns"].is_array()) {
                        for (const auto& fp : rule_val["fix_patterns"].as_array()) {
                            FixPattern fix;
                            fix.match_str = fp["match"].as_string();
                            fix.replacement = fp["replace"].as_string();
                            try {
                                fix.match = qre::Regex(fix.match_str, true);
                            } catch (const std::runtime_error&) {
                                std::cerr << "[WARN] Invalid fix regex in rule "
                                          << rule.id << ": " << fix.match_str << std::endl;
                                continue;
                            }
                            rule.fix_patterns.push_back(std::move(fix));
                        }
                    }

                    // Load per-language Tree-sitter AST queries (optional)
                    // Format: "ast_queries": { ".cpp": "<ts-query>", ".py": "<ts-query>" }
                    if (rule_val.has("ast_queries") && rule_val["ast_queries"].is_object()) {
                        for (const auto& kv : rule_val["ast_queries"].as_object()) {
                            rule.ast_queries[kv.first] = kv.second.as_string_or("");
                        }
                    }

                    rules_.push_back(std::move(rule));
                } catch (const std::exception& e) {
                    std::cerr << "[WARN] Skipping malformed rule: " << e.what() << std::endl;
                }
            }

            std::cout << "[INFO] Loaded " << rules_.size() << " rules from " << path << std::endl;
            return !rules_.empty();

        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to load rules from " << path << ": " << e.what() << std::endl;
            return false;
        }
    }

    // Load built-in default rules (fallback when rules.json is not available)
    void load_defaults() {
        rules_.clear();
        struct DefaultRule {
            const char* id;
            const char* keyword;
            const char* desc;
            const char* severity;
            const char* pattern;
            const char* remediation;
            const char* cwe;
        };

        DefaultRule defaults[] = {
            {"VULN-RSA-001", "RSA",
             "RSA encryption detected - vulnerable to quantum attacks",
             "critical", "\\bRSA\\b",
             "Replace with Kyber-512 or other NIST PQC algorithm", "CWE-327"},
            {"VULN-AES128-001", "AES-128",
             "AES-128 detected - insufficient key length for quantum resistance",
             "high", "\\bAES[_-]?128\\b",
             "Upgrade to AES-256", "CWE-326"},
            {"VULN-MD5-001", "MD5",
             "MD5 hash detected - cryptographically broken",
             "high", "\\bMD5\\b",
             "Replace with SHA-256 or SHA-3", "CWE-328"},
            {"VULN-DES-001", "DES",
             "DES encryption detected - trivially brute-forced",
             "critical", "\\bDES\\b",
             "Replace with AES-256-GCM", "CWE-327"},
            {"VULN-SHA1-001", "SHA-1",
             "SHA-1 hash detected - collision attacks demonstrated",
             "high", "\\bSHA[-_]?1\\b",
             "Replace with SHA-256 or SHA-3", "CWE-328"},
            {"VULN-ECB-001", "ECB",
             "ECB cipher mode detected - deterministic, leaks patterns",
             "critical", "\\bECB\\b|MODE_ECB|_ecb\\(|_ecb_",
             "Use GCM authenticated encryption mode", "CWE-327"},
        };

        for (const auto& d : defaults) {
            Rule rule;
            rule.id = d.id;
            rule.keyword = d.keyword;
            rule.description = d.desc;
            rule.severity = d.severity;
            rule.pattern_str = d.pattern;
            rule.remediation = d.remediation;
            rule.cwe_id = d.cwe;
            rule.compiled_pattern = qre::Regex(
                rule.pattern_str, true  // case-insensitive
            );
            rules_.push_back(std::move(rule));
        }

        std::cout << "[INFO] Loaded " << rules_.size() << " built-in default rules" << std::endl;
    }

    const std::vector<Rule>& get_rules() const { return rules_; }
    double get_entropy_threshold() const { return entropy_threshold_; }
    int get_proximity_window() const { return proximity_window_; }
    const std::string& get_default_fail_severity() const { return default_fail_severity_; }

private:
    std::vector<Rule> rules_;
    double entropy_threshold_ = 4.5;
    int proximity_window_ = 3;
    std::string default_fail_severity_ = "warning";
};
