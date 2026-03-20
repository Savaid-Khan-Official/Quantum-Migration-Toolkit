#pragma once
// ============================================================================
// OutputFormatter.hpp - Text and SARIF output formatters
// ============================================================================
// Implements the OutputFormatter interface with two implementations:
//   - TextFormatter:  Human-readable console + audit_report.txt
//   - SarifFormatter: SARIF 2.1.0 JSON for CI/CD integration
//     (GitHub Advanced Security, GitLab, Azure DevOps)
// ============================================================================

#include "../scan/ScanTypes.hpp"
#include "../SimpleJson.hpp"
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <map>
#include <ctime>
#include <filesystem>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// TextFormatter - Human-readable output
// ---------------------------------------------------------------------------
class TextFormatter {
public:
    static void format(const std::vector<ScanResult>& results,
                       const std::string& output_path,
                       const std::string& scan_target,
                       int files_scanned) {
        std::ofstream log(output_path);
        if (!log.is_open()) {
            std::cerr << "[ERROR] Could not create log file: " << output_path << std::endl;
            return;
        }

        // Get current date/time
        std::time_t now = std::time(nullptr);
        char date_buf[64];
        std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

        std::string header =
            "==========================================================\n"
            "  QUANTUM SCANNER v2.0 - CRYPTOGRAPHIC VULNERABILITY AUDIT\n"
            "  Scan Date: " + std::string(date_buf) + "\n"
            "  Target:    " + scan_target + "\n"
            "  Files:     " + std::to_string(files_scanned) + " scanned\n"
            "==========================================================\n";

        auto write_both = [&](const std::string& s) {
            std::cout << s;
            log << s;
        };

        write_both("\n" + header);

        // Filter out baseline results for the report
        std::vector<const ScanResult*> active_results;
        std::vector<const ScanResult*> baseline_results;
        for (const auto& r : results) {
            if (r.is_baseline) baseline_results.push_back(&r);
            else active_results.push_back(&r);
        }

        if (active_results.empty()) {
            write_both("\n[SUCCESS] No new vulnerable cryptographic patterns detected!\n");
        } else {
            // Count by severity
            int critical = 0, high = 0, warning = 0;
            for (const auto* r : active_results) {
                if (r->severity == "critical") critical++;
                else if (r->severity == "high") high++;
                else warning++;
            }

            write_both("\n[FINDINGS] " + std::to_string(active_results.size()) +
                       " vulnerabilities detected:\n");
            write_both("  CRITICAL: " + std::to_string(critical) +
                       "  |  HIGH: " + std::to_string(high) +
                       "  |  WARNING: " + std::to_string(warning) + "\n\n");

            for (const auto* r : active_results) {
                std::string sev_tag = "[" + to_upper(r->severity) + "]";
                std::string entry =
                    sev_tag + " " + r->keyword + " (" + r->rule_id + ")\n"
                    "  File: " + r->filename + ":" + std::to_string(r->line_number) + "\n"
                    "  Code: " + trim(r->line_content) + "\n"
                    "  Risk: " + r->description + "\n"
                    "  Fix:  " + r->remediation + "\n";

                if (!r->cwe_id.empty()) {
                    entry += "  CWE:  " + r->cwe_id + "\n";
                }

                if (r->is_entropy_finding) {
                    std::ostringstream oss;
                    oss << r->entropy_value;
                    entry += "  Entropy: " + oss.str() + " (high-entropy secret detected)\n";
                }

                if (!r->proximity_findings.empty()) {
                    entry += "  Proximity warnings:\n";
                    for (const auto& pf : r->proximity_findings) {
                        entry += "    Line " + std::to_string(pf.line_number) +
                                 ": " + pf.description + "\n"
                                 "      " + trim(pf.line_content) + "\n";
                    }
                }

                if (!r->suggested_fix.empty()) {
                    entry += "  Suggested: " + r->suggested_fix + "\n";
                }

                entry += "\n";
                write_both(entry);
            }
        }

        if (!baseline_results.empty()) {
            write_both("[BASELINE] " + std::to_string(baseline_results.size()) +
                       " known issues suppressed by baseline\n");
        }

        // Summary
        std::string summary =
            "\n==========================================================\n"
            "SUMMARY:\n"
            "  New Vulnerabilities:      " + std::to_string(active_results.size()) + "\n"
            "  Baselined (suppressed):   " + std::to_string(baseline_results.size()) + "\n"
            "  Total Files Scanned:      " + std::to_string(files_scanned) + "\n"
            "  Action Required:          " +
            (active_results.empty() ? "None" : "Review and upgrade to quantum-safe algorithms") + "\n"
            "==========================================================\n";

        write_both(summary);
        log.close();
        std::cout << "\n[INFO] Report saved to: " << output_path << std::endl;
    }

private:
    static std::string to_upper(const std::string& s) {
        std::string r = s;
        std::transform(r.begin(), r.end(), r.begin(), ::toupper);
        return r;
    }

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
};

// ---------------------------------------------------------------------------
// SarifFormatter - SARIF 2.1.0 JSON output for CI/CD integration
// ---------------------------------------------------------------------------
class SarifFormatter {
public:
    static void format(const std::vector<ScanResult>& results,
                       const std::vector<Rule>& rules,
                       const std::string& output_path,
                       const std::string& scan_target) {
        // Build SARIF JSON structure
        json::Value sarif = json::Value::object();
        sarif.set("$schema", json::Value::string_val(
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json"));
        sarif.set("version", json::Value::string_val("2.1.0"));

        // Build runs array
        json::Value runs = json::Value::array();
        json::Value run = json::Value::object();

        // Tool section
        json::Value tool = json::Value::object();
        json::Value driver = json::Value::object();
        driver.set("name", json::Value::string_val("QuantumScanner"));
        driver.set("version", json::Value::string_val("2.0.0"));
        driver.set("informationUri", json::Value::string_val(
            "https://github.com/Savaid-KhanOfficial/Quantum-Migration-Toolkit"));
        driver.set("semanticVersion", json::Value::string_val("2.0.0"));

        // Rules definitions
        json::Value sarif_rules = json::Value::array();
        for (const auto& rule : rules) {
            json::Value r = json::Value::object();
            r.set("id", json::Value::string_val(rule.id));
            r.set("name", json::Value::string_val(rule.keyword));

            json::Value short_desc = json::Value::object();
            short_desc.set("text", json::Value::string_val(rule.keyword + " usage detected"));
            r.set("shortDescription", short_desc);

            json::Value full_desc = json::Value::object();
            full_desc.set("text", json::Value::string_val(rule.description));
            r.set("fullDescription", full_desc);

            json::Value config = json::Value::object();
            config.set("level", json::Value::string_val(severity_to_sarif_level(rule.severity)));
            r.set("defaultConfiguration", config);

            json::Value help = json::Value::object();
            help.set("text", json::Value::string_val(rule.remediation));
            r.set("help", help);

            if (!rule.cwe_id.empty()) {
                json::Value properties = json::Value::object();
                json::Value tags = json::Value::array();
                tags.push_back(json::Value::string_val("security"));
                tags.push_back(json::Value::string_val(rule.cwe_id));
                properties.set("tags", tags);
                r.set("properties", properties);
            }

            sarif_rules.push_back(r);
        }
        driver.set("rules", sarif_rules);
        tool.set("driver", driver);
        run.set("tool", tool);

        // Results
        json::Value sarif_results = json::Value::array();
        for (const auto& result : results) {
            if (result.is_baseline) continue;  // Skip baselined results

            json::Value r = json::Value::object();
            r.set("ruleId", json::Value::string_val(result.rule_id));
            r.set("level", json::Value::string_val(severity_to_sarif_level(result.severity)));

            json::Value msg = json::Value::object();
            msg.set("text", json::Value::string_val(
                "Found " + result.keyword + " in " + result.filename +
                " at line " + std::to_string(result.line_number) +
                ". " + result.description));
            r.set("message", msg);

            // Location
            json::Value locations = json::Value::array();
            json::Value loc = json::Value::object();
            json::Value physical = json::Value::object();
            json::Value artifact = json::Value::object();

            // Make path relative for SARIF
            std::string rel_path = result.filename;
            try {
                rel_path = fs::relative(result.filename, scan_target).string();
            } catch (...) {}
            std::replace(rel_path.begin(), rel_path.end(), '\\', '/');

            artifact.set("uri", json::Value::string_val(rel_path));
            physical.set("artifactLocation", artifact);

            json::Value region = json::Value::object();
            region.set("startLine", json::Value::number(result.line_number));
            json::Value snippet = json::Value::object();
            snippet.set("text", json::Value::string_val(trim(result.line_content)));
            region.set("snippet", snippet);
            physical.set("region", region);

            loc.set("physicalLocation", physical);
            locations.push_back(loc);
            r.set("locations", locations);

            // Fingerprint
            if (!result.fingerprint.empty()) {
                json::Value fingerprints = json::Value::object();
                fingerprints.set("quantumScanner/v1", json::Value::string_val(result.fingerprint));
                r.set("fingerprints", fingerprints);
            }

            // Fix suggestions
            if (!result.suggested_fix.empty()) {
                json::Value fixes = json::Value::array();
                json::Value fix = json::Value::object();
                json::Value fix_desc = json::Value::object();
                fix_desc.set("text", json::Value::string_val(result.suggested_fix));
                fix.set("description", fix_desc);
                fixes.push_back(fix);
                r.set("fixes", fixes);
            }

            sarif_results.push_back(r);
        }
        run.set("results", sarif_results);

        // Invocation
        json::Value invocations = json::Value::array();
        json::Value invocation = json::Value::object();

        bool has_errors = false;
        for (const auto& result : results) {
            if (!result.is_baseline && result.severity == "critical") {
                has_errors = true;
                break;
            }
        }
        // executionSuccessful = false when critical findings are present
        invocation.set("executionSuccessful", json::Value::boolean(!has_errors));
        invocations.push_back(invocation);
        run.set("invocations", invocations);

        runs.push_back(run);
        sarif.set("runs", runs);

        // Write to file
        std::ofstream file(output_path);
        if (!file) {
            std::cerr << "[ERROR] Cannot write SARIF file: " << output_path << std::endl;
            return;
        }
        file << sarif.serialize(2);
        file.close();

        std::cout << "[INFO] SARIF report saved to: " << output_path << std::endl;
    }

private:
    static std::string severity_to_sarif_level(const std::string& severity) {
        if (severity == "critical") return "error";
        if (severity == "high") return "warning";
        return "note";
    }

    static std::string trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
};
