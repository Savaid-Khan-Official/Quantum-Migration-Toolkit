// ============================================================================
// cli/main.cpp — Quantum Migration Toolkit v2.0 CLI
// ============================================================================
// Thin dispatcher over libquantum_migrate.  All detection, remediation, and
// vendoring logic lives in the engine/ library.
//
// Usage:
//   quantum-migrate <directory> [options]
//   quantum-migrate --help
//
// New v2.0 options (PQC Auto-Migration):
//   --vendor-into <dir>      Copy PQC SDK headers into target project
//   --patch-build-system     Auto-detect and patch CMake/pip/Maven/Cargo/etc.
//   --dry-run                Show what would be vendored without writing
//   --no-vendor              Skip vendoring (AI remediation only)
//   --backup                 Create .quantum_migrate_backup/ before changes
// ============================================================================

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <algorithm>
#include <cctype>
#include <mutex>
#include <atomic>
#include <set>
#include <map>
#include <chrono>

// Engine includes
#include "ScanTypes.hpp"
#include "RuleEngine.hpp"
#include "CommentStripper.hpp"
#include "ThreadPool.hpp"
#include "IgnoreHandler.hpp"
#include "OutputFormatter.hpp"
#include "BaselineManager.hpp"
#include "EntropyDetector.hpp"
#include "ProximityAnalyzer.hpp"
#include "AutoRemediator.hpp"
#include "AstEngine.hpp"
#include "AiRemediator.hpp"
#include "DependencyInjector.hpp"

using namespace std;
namespace fs = filesystem;

// ---------------------------------------------------------------------------
// File extension whitelist for scanning
// ---------------------------------------------------------------------------
const vector<string> SCAN_EXTENSIONS = {
    ".cpp", ".c", ".h", ".hpp",
    ".py",
    ".java",
    ".js", ".jsx", ".ts", ".tsx",
    ".cs",
    ".go",
    ".rb",
    ".rs",
    ".swift",
    ".kt",
    ".scala",
    ".m", ".mm"
};

bool is_scannable_file(const fs::path& filepath) {
    string extension = filepath.extension().string();
    transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    for (const auto& ext : SCAN_EXTENSIONS) {
        if (extension == ext) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Scan a single file for vulnerable patterns (thread-safe)
// ---------------------------------------------------------------------------
vector<ScanResult> scan_file(const fs::path& filepath,
                              const vector<Rule>& rules,
                              const ScanConfig& config,
                              const string& root_dir) {
    vector<ScanResult> results;
    ifstream file(filepath);
    if (!file.is_open()) return results;

    string extension = filepath.extension().string();
    transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

    vector<string> all_lines;
    vector<string> stripped_lines;
    string line;
    StripState strip_state;

    while (getline(file, line)) {
        all_lines.push_back(line);
        stripped_lines.push_back(
            CommentStripper::strip_line(line, extension, strip_state)
        );
    }
    file.close();

#ifdef USE_TREESITTER
    std::string source_blob;
    if (config.enable_ast) {
        source_blob.reserve(all_lines.size() * 80);
        for (const auto& l : all_lines) { source_blob += l; source_blob += '\n'; }
    }
#endif

    for (int i = 0; i < static_cast<int>(all_lines.size()); i++) {
        const string& original_line = all_lines[i];
        const string& clean_line = stripped_lines[i];

        for (const auto& rule : rules) {
            if (!rule.applies_to(extension)) continue;

            if (rule.compiled_pattern.search(clean_line)) {
                AstContext ast_ctx;
#ifdef USE_TREESITTER
                if (config.enable_ast && !source_blob.empty()) {
                    const std::string& ast_q = rule.ast_queries.count(extension)
                        ? rule.ast_queries.at(extension) : "";
                    ast_ctx = AstEngine::instance().validate(
                        source_blob, extension, ast_q, i + 1);
                    if (ast_ctx.valid && !ast_ctx.confirmed) continue;
                }
#endif
                ScanResult result;
                result.filename = filepath.string();
                result.rule_id = rule.id;
                result.keyword = rule.keyword;
                result.severity = rule.severity;
                result.line_number = i + 1;
                result.line_content = original_line;
                result.description = rule.description;
                result.remediation = rule.remediation;
                result.cwe_id = rule.cwe_id;
                result.language = extension;
                result.ast_context = ast_ctx;
                result.ast_validated = ast_ctx.valid;

                result.fingerprint = BaselineManager::generate_fingerprint(
                    result.filename, result.rule_id, result.line_content, root_dir
                );

                if (config.enable_remediation) {
                    result.suggested_fix = AutoRemediator::generate_suggestion(result, rules);
                }

                if (config.enable_proximity) {
                    ProximityAnalyzer::analyze(all_lines, i, rule, result);
                }

                results.push_back(result);
            }
        }

        if (config.enable_entropy) {
            auto entropy_results = EntropyDetector::scan_line(
                original_line, i + 1, filepath.string(), config.entropy_threshold
            );
            for (auto& er : entropy_results) {
                er.fingerprint = BaselineManager::generate_fingerprint(
                    er.filename, er.rule_id, er.line_content, root_dir
                );
                results.push_back(move(er));
            }
        }
    }

    return results;
}

// ---------------------------------------------------------------------------
// Discover scannable files
// ---------------------------------------------------------------------------
vector<fs::path> discover_files(const fs::path& directory,
                                 const IgnoreHandler& ignore_handler,
                                 bool no_ignore) {
    vector<fs::path> files;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(
                 directory, fs::directory_options::skip_permission_denied)) {
            if (!entry.is_regular_file()) continue;
            if (!is_scannable_file(entry.path())) continue;
            if (!no_ignore && ignore_handler.should_ignore(entry.path(), directory))
                continue;
            files.push_back(entry.path());
        }
    } catch (const fs::filesystem_error& e) {
        cerr << "[ERROR] Filesystem error: " << e.what() << endl;
    }
    return files;
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------
int severity_to_int(const string& severity) {
    if (severity == "critical") return 3;
    if (severity == "high") return 2;
    if (severity == "warning") return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// Parse command-line arguments
// ---------------------------------------------------------------------------
ScanConfig parse_args(int argc, char* argv[]) {
    ScanConfig config;

    for (int i = 1; i < argc; i++) {
        string arg = argv[i];

        if (arg.substr(0, 2) == "--") {
            size_t eq = arg.find('=');
            string key = (eq != string::npos) ? arg.substr(2, eq - 2) : arg.substr(2);
            string val = (eq != string::npos) ? arg.substr(eq + 1) : "";

            auto needs_value = [](const string& k) {
                return k == "rules" || k == "format" || k == "output" ||
                       k == "fail-on" || k == "baseline" || k == "threads" ||
                       k == "entropy-threshold" || k == "patch" || k == "model" ||
                       k == "ai-ctx" || k == "ai-threads" || k == "ai-temp" ||
                       k == "vendor-into";
            };
            if (val.empty() && needs_value(key) && i + 1 < argc && argv[i + 1][0] != '-') {
                val = argv[++i];
            }

            if      (key == "rules")               config.rules_path = val;
            else if (key == "format")               config.format = val;
            else if (key == "output")               config.output_path = val;
            else if (key == "fail-on")              config.fail_on = val;
            else if (key == "baseline")             config.baseline_path = val;
            else if (key == "update-baseline")      config.update_baseline = true;
            else if (key == "no-ignore")            config.no_ignore = true;
            else if (key == "threads")              { try { config.num_threads = stoi(val); } catch (...) { cerr << "[ERROR] Invalid --threads value: " << val << endl; return ScanConfig{}; } }
            else if (key == "entropy")              config.enable_entropy = true;
            else if (key == "entropy-threshold")    { try { config.entropy_threshold = stod(val); } catch (...) { cerr << "[ERROR] Invalid --entropy-threshold value: " << val << endl; return ScanConfig{}; } }
            else if (key == "proximity")            config.enable_proximity = true;
            else if (key == "remediate")            config.enable_remediation = true;
            else if (key == "patch")                config.patch_output = val;
            else if (key == "no-ast")               config.enable_ast = false;
            else if (key == "model")                config.model_path = val;
            else if (key == "ai-ctx")               { try { config.ai_ctx_size = stoi(val); } catch (...) { cerr << "[ERROR] Invalid --ai-ctx value: " << val << endl; return ScanConfig{}; } }
            else if (key == "ai-threads")           { try { config.ai_threads = stoi(val); } catch (...) { cerr << "[ERROR] Invalid --ai-threads value: " << val << endl; return ScanConfig{}; } }
            else if (key == "ai-temp")              { try { config.ai_temp = stof(val); } catch (...) { cerr << "[ERROR] Invalid --ai-temp value: " << val << endl; return ScanConfig{}; } }
            else if (key == "vendor-into")          config.vendor_target_dir = val;
            else if (key == "patch-build-system")   config.patch_build_system = true;
            else if (key == "dry-run")              config.dry_run = true;
            else if (key == "no-vendor")            config.no_vendor = true;
            else if (key == "backup")               config.enable_backup = true;
            else if (key == "help" || key == "h")   config.target_directory = "__HELP__";
        } else if (arg == "-h") {
            config.target_directory = "__HELP__";
        } else if (config.target_directory.empty()) {
            config.target_directory = arg;
        }
    }

    return config;
}

// ---------------------------------------------------------------------------
// Show help
// ---------------------------------------------------------------------------
void show_help() {
    cout <<
R"(==========================================================
  QUANTUM MIGRATION TOOLKIT v2.0 — PQC Auto-Migration Tool
  Scan → Detect → Rewrite → Vendor → Patch
==========================================================

USAGE:
  quantum-migrate <directory> [options]

SCAN OPTIONS:
  --rules=<path>             Path to rules.json (default: rules.json)
  --format=<text|sarif>      Output format (default: text)
  --output=<path>            Output file path (default: auto-generated)
  --fail-on=<severity>       Exit code threshold: critical|high|warning
  --baseline=<path>          Baseline file (default: .quantum-baseline.json)
  --update-baseline          Save findings as new baseline
  --no-ignore                Disable .gitignore/.quantumignore filtering
  --threads=<N>              Worker threads (default: auto-detect)
  --entropy                  Enable high-entropy secret detection
  --entropy-threshold=<N>    Entropy threshold (default: 4.5)
  --proximity                Enable cipher mode proximity analysis
  --no-ast                   Disable Tree-sitter AST validation

AI REMEDIATION:
  --remediate                Enable auto-remediation patch generation
  --model=<path>             Path to GGUF model for AI remediation
  --ai-ctx=<N>               AI context window in tokens (default: 4096)
  --ai-threads=<N>           CPU threads for AI inference (default: auto)
  --ai-temp=<N>              Sampling temperature (default: 0.1)
  --patch=<path>             Output patch file (default: quantum_fixes.patch)

PQC VENDORING (NEW in v2.0):
  --vendor-into <dir>        Copy PQC SDK headers into target project
  --patch-build-system       Auto-detect and patch CMake/pip/Maven/etc.
  --dry-run                  Show what would be vendored without writing
  --no-vendor                Skip vendoring (AI remediation only)
  --backup                   Create backup before modifying target files

EXAMPLES:
  # Basic scan
  quantum-migrate ./my_project

  # Full migration pipeline
  quantum-migrate ./my_project --remediate --model=models/qwen.gguf \
      --vendor-into ./my_project --patch-build-system --backup

  # CI/CD mode (SARIF output, fail on critical)
  quantum-migrate . --format=sarif --output=results.sarif --fail-on=critical

  # Review changes before applying
  quantum-migrate ./app --remediate --model=models/qwen.gguf --dry-run
  less quantum_fixes.patch
  git apply quantum_fixes.patch

SUPPORTED LANGUAGES:
  C/C++, Python, Java, JavaScript, TypeScript, Go, Rust,
  Ruby, Swift, Kotlin, Scala, C#, Objective-C
==========================================================
)";
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    if (argc < 2) { show_help(); return 1; }

    ScanConfig config = parse_args(argc, argv);

    if (config.target_directory == "__HELP__" || config.target_directory.empty()) {
        show_help();
        return 0;
    }

    // Validate target directory
    fs::path target_dir(config.target_directory);
    if (!fs::exists(target_dir) || !fs::is_directory(target_dir)) {
        cerr << "[ERROR] Invalid directory: " << config.target_directory << endl;
        return 1;
    }
    target_dir = fs::absolute(target_dir);
    string root_dir = target_dir.string();

    // Banner
    cout << "==========================================================\n"
         << "  QUANTUM MIGRATION TOOLKIT v2.0 — Starting Analysis\n"
         << "  Target: " << root_dir << "\n"
         << "==========================================================" << endl;

    auto start_time = chrono::high_resolution_clock::now();

    // -----------------------------------------------------------------------
    // Step 1: Load rules
    // -----------------------------------------------------------------------
    RuleEngine rule_engine;
    string rules_path = config.rules_path;
    if (!fs::exists(rules_path)) {
        fs::path exe_dir = fs::path(argv[0]).parent_path();
        if (fs::exists(exe_dir / "rules.json"))
            rules_path = (exe_dir / "rules.json").string();
        else if (fs::exists(exe_dir / ".." / "share" / "quantum-migrate" / "rules.json"))
            rules_path = (exe_dir / ".." / "share" / "quantum-migrate" / "rules.json").string();
        else if (fs::exists(target_dir / "rules.json"))
            rules_path = (target_dir / "rules.json").string();
    }

    if (fs::exists(rules_path)) {
        if (!rule_engine.load_from_file(rules_path)) {
            cout << "[WARN] Rules load failed, using defaults" << endl;
            rule_engine.load_defaults();
        }
    } else {
        cout << "[INFO] rules.json not found, using defaults" << endl;
        rule_engine.load_defaults();
    }
    const auto& rules = rule_engine.get_rules();

    // -----------------------------------------------------------------------
    // Step 2: Load ignore patterns
    // -----------------------------------------------------------------------
    IgnoreHandler ignore_handler;
    if (!config.no_ignore) {
        ignore_handler.load_gitignore(target_dir);
        ignore_handler.load_quantumignore(target_dir);
    }

    // -----------------------------------------------------------------------
    // Step 3: Load baseline
    // -----------------------------------------------------------------------
    BaselineManager baseline_mgr;
    bool has_baseline = baseline_mgr.load(config.baseline_path);

    // -----------------------------------------------------------------------
    // Step 4: Discover files
    // -----------------------------------------------------------------------
    cout << "\n[INFO] Discovering files..." << endl;
    vector<fs::path> files = discover_files(target_dir, ignore_handler, config.no_ignore);
    cout << "[INFO] Found " << files.size() << " files to scan" << endl;
    if (files.empty()) { cout << "[INFO] No scannable files found.\n"; return 0; }

    // -----------------------------------------------------------------------
    // Step 5: Multi-threaded scan
    // -----------------------------------------------------------------------
    int num_threads = config.num_threads > 0
        ? config.num_threads
        : max(1u, thread::hardware_concurrency());
    cout << "[INFO] Scanning with " << num_threads << " threads...\n" << endl;

    ThreadPool pool(num_threads);
    vector<future<vector<ScanResult>>> futures;
    atomic<int> files_scanned{0};

    for (const auto& filepath : files) {
        futures.push_back(pool.submit([&, filepath]() {
            auto results = scan_file(filepath, rules, config, root_dir);
            int count = ++files_scanned;
            if (count % 50 == 0 || files.size() < 20)
                cout << "[SCANNING] " << count << "/" << files.size()
                     << " - " << filepath.filename().string() << endl;
            return results;
        }));
    }

    vector<ScanResult> all_results;
    for (auto& f : futures) {
        auto results = f.get();
        all_results.insert(all_results.end(),
                           make_move_iterator(results.begin()),
                           make_move_iterator(results.end()));
    }

    cout << "\n[INFO] Scan complete. " << files_scanned.load() << " files, "
         << all_results.size() << " findings." << endl;

    // -----------------------------------------------------------------------
    // Step 6: Baseline filtering
    // -----------------------------------------------------------------------
    if (has_baseline) baseline_mgr.apply_baseline(all_results);
    if (config.update_baseline) baseline_mgr.save(all_results, config.baseline_path);

    // -----------------------------------------------------------------------
    // Step 7: Output report
    // -----------------------------------------------------------------------
    string output_path = config.output_path;
    if (config.format == "sarif") {
        if (output_path.empty()) output_path = "quantum_scan.sarif";
        SarifFormatter::format(all_results, rules, output_path, root_dir);
    } else {
        if (output_path.empty()) output_path = "audit_report.txt";
        TextFormatter::format(all_results, output_path, root_dir, files_scanned.load());
    }

    // -----------------------------------------------------------------------
    // Step 8: AI-driven PQC remediation (context-aware, batched per function)
    // -----------------------------------------------------------------------
    if (config.enable_remediation && !config.model_path.empty()) {
        cout << "\n[AI] Loading model for context-aware PQC remediation..." << endl;
        AiRemediator ai(config.model_path, config.ai_ctx_size,
                        config.ai_threads, config.ai_temp);

        if (ai.is_loaded()) {
            // Group findings by function key (filename:fn_start_line)
            // so ALL vulnerabilities in one function are batched into a single prompt.
            struct FnGroup {
                std::string fn_key;
                std::string source_ctx;
                std::string language;
                std::string filename;
                std::string display_name;   // e.g. "function_name()" or "line 42"
                bool has_ast;
                int fn_start_line;
                std::vector<size_t> result_indices; // indices into all_results
            };

            std::map<std::string, FnGroup> fn_groups;

            for (size_t idx = 0; idx < all_results.size(); ++idx) {
                const auto& r = all_results[idx];
                if (r.is_baseline) continue;

                bool has_ast_ctx = r.ast_validated && r.ast_context.confirmed
                                   && !r.ast_context.fn_source.empty();
                std::string source_ctx;
                std::string fn_key;

                if (has_ast_ctx) {
                    fn_key = r.filename + ":" + to_string(r.ast_context.fn_start_line);
                    source_ctx = r.ast_context.fn_source;
                } else if (!r.line_content.empty()) {
                    fn_key = r.filename + ":" + to_string(r.line_number);
                    source_ctx = r.line_content;
                } else {
                    continue;
                }

                auto it = fn_groups.find(fn_key);
                if (it == fn_groups.end()) {
                    FnGroup g;
                    g.fn_key = fn_key;
                    g.source_ctx = source_ctx;
                    g.language = r.language;
                    g.filename = r.filename;
                    g.has_ast = has_ast_ctx;
                    g.fn_start_line = has_ast_ctx ? r.ast_context.fn_start_line : r.line_number;
                    g.display_name = has_ast_ctx
                        ? r.ast_context.enclosing_fn + "()"
                        : "line " + to_string(r.line_number);
                    g.result_indices.push_back(idx);
                    fn_groups[fn_key] = std::move(g);
                } else {
                    it->second.result_indices.push_back(idx);
                }
            }

            int total_groups = static_cast<int>(fn_groups.size());
            if (total_groups == 0) {
                cout << "[AI] No findings eligible for AI remediation" << endl;
            } else {
                int total_findings = 0;
                for (const auto& [k, g] : fn_groups)
                    total_findings += static_cast<int>(g.result_indices.size());

                cout << "[AI] " << total_findings << " findings in "
                     << total_groups << " function(s) eligible for AI remediation"
                     << endl;

                int group_num = 0;
                for (auto& [key, group] : fn_groups) {
                    group_num++;

                    // Collect all matched rules for this function
                    std::vector<const Rule*> matched_rules;
                    std::set<std::string> seen_rule_ids;
                    for (size_t idx : group.result_indices) {
                        const auto& r = all_results[idx];
                        if (seen_rule_ids.insert(r.rule_id).second) {
                            for (const auto& rule : rules)
                                if (rule.id == r.rule_id) {
                                    matched_rules.push_back(&rule);
                                    break;
                                }
                        }
                    }
                    if (matched_rules.empty()) continue;

                    // Log what we're remediating
                    cout << "[AI] [" << group_num << "/" << total_groups << "] "
                         << group.display_name << " — "
                         << group.filename << ":" << group.fn_start_line
                         << " (" << matched_rules.size() << " vuln"
                         << (matched_rules.size() > 1 ? "s" : "") << ":";
                    for (size_t i = 0; i < matched_rules.size(); ++i) {
                        if (i > 0) cout << ",";
                        cout << " " << matched_rules[i]->id;
                    }
                    cout << ")" << endl;

                    // Send batched or single prompt
                    string fix = ai.generate_batched_remediation(
                        matched_rules, group.source_ctx, group.language);

                    if (!fix.empty()) {
                        // Apply fix to ALL results in this function group
                        for (size_t idx : group.result_indices)
                            all_results[idx].ai_remediation = fix;
                        cout << "[AI]   -> " << fix.size() << " chars generated"
                             << endl;
                    }
                }

                cout << "[AI] Remediation complete: " << group_num
                     << " function(s) rewritten" << endl;
            }
        } else {
            cerr << "[AI-ERROR] Model failed to load — AI remediation skipped" << endl;
        }
    }

    // -----------------------------------------------------------------------
    // Step 9: Create backup & generate patch
    // -----------------------------------------------------------------------
    if (config.enable_remediation) {
        // Safety: backup files before patching
        if (config.enable_backup) {
            fs::path backup_dir = fs::path(root_dir) / ".quantum_migrate_backup";
            fs::create_directories(backup_dir);
            set<string> backed_up;
            for (const auto& r : all_results) {
                if (r.is_baseline || r.ai_remediation.empty()) continue;
                if (backed_up.count(r.filename)) continue;
                backed_up.insert(r.filename);
                try {
                    fs::path rel = fs::relative(r.filename, root_dir);
                    fs::path dest = backup_dir / rel;
                    fs::create_directories(dest.parent_path());
                    fs::copy_file(r.filename, dest,
                                  fs::copy_options::overwrite_existing);
                    cout << "[BACKUP] " << rel.string() << endl;
                } catch (const exception& e) {
                    cerr << "[BACKUP-WARN] " << r.filename
                         << ": " << e.what() << endl;
                }
            }
            cout << "[BACKUP] " << backed_up.size()
                 << " file(s) backed up to .quantum_migrate_backup/" << endl;
        }

        AutoRemediator::generate_patch(all_results, rules,
                                        config.patch_output, root_dir);
    }

    // -----------------------------------------------------------------------
    // Step 10: PQC Dependency Vendoring (NEW in v2.0)
    // -----------------------------------------------------------------------
    if (!config.vendor_target_dir.empty() && !config.no_vendor) {
        cout << "\n[VENDOR] PQC Dependency Injection..." << endl;

        fs::path vendor_dir = fs::path(config.vendor_target_dir);
        if (!fs::exists(vendor_dir)) {
            cerr << "[ERROR] Vendor target directory not found: "
                 << config.vendor_target_dir << endl;
        } else {
            DependencyInjector injector;

            // Phase 1: Vendor PQC headers
            auto manifest = injector.vendor_headers(vendor_dir, config.dry_run);
            cout << "[VENDOR] " << manifest.files_added.size()
                 << " PQC SDK files "
                 << (config.dry_run ? "would be vendored" : "vendored")
                 << " into " << vendor_dir.string() << endl;

            // Phase 2: Patch build system
            if (config.patch_build_system) {
                auto patches = injector.patch_build_system(vendor_dir, config.dry_run);
                for (const auto& p : patches) {
                    cout << "[VENDOR] " << (config.dry_run ? "[DRY-RUN] " : "")
                         << p << endl;
                }
            }

            // Phase 3: Write manifest
            if (!config.dry_run) {
                manifest.migrated_files.reserve(all_results.size());
                for (const auto& r : all_results) {
                    if (!r.ai_remediation.empty())
                        manifest.migrated_files.push_back(r.filename);
                }
                injector.write_manifest(vendor_dir, manifest);
                cout << "[VENDOR] Manifest written to "
                     << (vendor_dir / "quantum_migrate_manifest.json").string() << endl;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Step 11: Performance summary
    // -----------------------------------------------------------------------
    auto end_time = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);
    cout << "\n[PERF] Completed in " << duration.count() << "ms ("
         << files_scanned.load() << " files, " << num_threads << " threads)" << endl;

    // -----------------------------------------------------------------------
    // Step 12: Exit code
    // -----------------------------------------------------------------------
    int fail_threshold = severity_to_int(config.fail_on);
    bool should_fail = false;
    for (const auto& r : all_results) {
        if (!r.is_baseline && severity_to_int(r.severity) >= fail_threshold) {
            should_fail = true;
            break;
        }
    }

    if (should_fail) {
        cout << "\n[EXIT] Code 1 (findings >= '" << config.fail_on << "')" << endl;
        return 1;
    }

    int active = 0;
    for (const auto& r : all_results)
        if (!r.is_baseline) active++;

    cout << "\n[EXIT] " << active << " findings, exit 0" << endl;
    return 0;
}
