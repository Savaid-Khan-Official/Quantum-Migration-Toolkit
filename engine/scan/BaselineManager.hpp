#pragma once
// ============================================================================
// BaselineManager.hpp - Vulnerability baselining and fingerprinting
// ============================================================================
// Generates stable fingerprints for each finding and maintains a baseline
// file (.quantum-baseline.json). On subsequent runs, known baseline items
// are suppressed so only NEW vulnerabilities fail the build.
// ============================================================================

#include "ScanTypes.hpp"
#include "../SimpleJson.hpp"
#include <string>
#include <vector>
#include <unordered_set>
#include <fstream>
#include <iostream>
#include <functional>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <filesystem>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

class BaselineManager {
public:
    // Generate a stable fingerprint for a scan result
    static std::string generate_fingerprint(const ScanResult& result, const std::string& root_dir) {
        return generate_fingerprint(result.filename, result.rule_id,
                                    result.line_content, root_dir);
    }

    // Overload: generate fingerprint from individual fields
    // (used by scanner_main.cpp before the ScanResult is fully populated)
    static std::string generate_fingerprint(const std::string& filename,
                                            const std::string& rule_id,
                                            const std::string& line_content,
                                            const std::string& root_dir) {
        // Create relative path for portability
        std::string rel_path = filename;
        try {
            rel_path = fs::relative(filename, root_dir).string();
        } catch (...) {}

        // ---- Cross-platform path normalization (v2.1) ----
        // 1. Convert all backslashes to forward slashes
        std::replace(rel_path.begin(), rel_path.end(), '\\', '/');

        // 2. On Windows, lowercase the path for case-insensitive matching
        //    (C:\Foo\Bar.cpp and c:\foo\bar.cpp must produce the same fingerprint)
#ifdef _WIN32
        std::transform(rel_path.begin(), rel_path.end(), rel_path.begin(),
                       [](unsigned char c) { return std::tolower(c); });
#endif

        // 3. Remove leading ./ if present
        if (rel_path.size() >= 2 && rel_path[0] == '.' && rel_path[1] == '/') {
            rel_path = rel_path.substr(2);
        }

        // Build fingerprint source: filepath + rule_id + trimmed_line_content
        std::string source = rel_path + ":" + rule_id + ":" + trim(line_content);

        // Generate hash using FNV-1a
        uint64_t hash = fnv1a_hash(source);

        // Convert to hex string
        std::ostringstream oss;
        oss << std::hex << std::setfill('0') << std::setw(16) << hash;
        return oss.str();
    }

    // Load baseline from file
    bool load(const std::string& path) {
        baseline_path_ = path;
        if (!fs::exists(path)) {
            return false;
        }

        try {
            json::Value root = json::Value::from_file(path);

            if (root.has("fingerprints") && root["fingerprints"].is_object()) {
                for (const auto& [key, val] : root["fingerprints"].as_object()) {
                    fingerprints_.insert(key);
                }
            }

            std::cout << "[INFO] Loaded baseline with " << fingerprints_.size()
                      << " fingerprints from " << path << std::endl;
            return true;

        } catch (const std::exception& e) {
            std::cerr << "[WARN] Failed to load baseline: " << e.what() << std::endl;
            return false;
        }
    }

    // Save current findings as the new baseline
    bool save(const std::vector<ScanResult>& results, const std::string& path) {
        json::Value root = json::Value::object();
        root.set("version", json::Value::string_val("1.0"));
        root.set("scanner", json::Value::string_val("QuantumScanner v2.0"));

        // Current timestamp
        std::time_t now = std::time(nullptr);
        char date_buf[64];
        std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%dT%H:%M:%S", std::localtime(&now));
        root.set("created", json::Value::string_val(date_buf));
        root.set("total_findings", json::Value::number(static_cast<double>(results.size())));

        json::Value fingerprints = json::Value::object();
        for (const auto& result : results) {
            if (result.fingerprint.empty()) continue;

            json::Value entry = json::Value::object();
            entry.set("file", json::Value::string_val(result.filename));
            entry.set("rule", json::Value::string_val(result.rule_id));
            entry.set("keyword", json::Value::string_val(result.keyword));
            entry.set("severity", json::Value::string_val(result.severity));
            entry.set("line", json::Value::number(result.line_number));
            entry.set("snippet", json::Value::string_val(trim(result.line_content)));

            fingerprints.set(result.fingerprint, entry);
        }
        root.set("fingerprints", fingerprints);

        try {
            root.to_file(path);
            std::cout << "[INFO] Baseline saved with " << results.size()
                      << " fingerprints to " << path << std::endl;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "[ERROR] Failed to save baseline: " << e.what() << std::endl;
            return false;
        }
    }

    // Check if a fingerprint exists in the loaded baseline
    bool is_baselined(const std::string& fingerprint) const {
        return fingerprints_.find(fingerprint) != fingerprints_.end();
    }

    // Apply baseline to results: mark matching results as baselined
    void apply(std::vector<ScanResult>& results) const {
        for (auto& result : results) {
            if (!result.fingerprint.empty() && is_baselined(result.fingerprint)) {
                result.is_baseline = true;
            }
        }
    }

    // Alias for apply() - used by scanner_main.cpp
    void apply_baseline(std::vector<ScanResult>& results) const {
        apply(results);
    }

    size_t baseline_count() const { return fingerprints_.size(); }

private:
    std::string baseline_path_;
    std::unordered_set<std::string> fingerprints_;

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    // FNV-1a 64-bit hash - fast, good distribution, deterministic
    static uint64_t fnv1a_hash(const std::string& data) {
        uint64_t hash = 14695981039346656037ULL;  // FNV offset basis
        for (unsigned char c : data) {
            hash ^= static_cast<uint64_t>(c);
            hash *= 1099511628211ULL;  // FNV prime
        }
        return hash;
    }
};
