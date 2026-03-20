#pragma once
// ============================================================================
// ScanTypes.hpp - Shared data structures for QuantumScanner v3.0
// ============================================================================

#include <string>
#include <vector>
#include <map>
#include "RegexEngine.hpp"

// ---------------------------------------------------------------------------
// AstContext: result produced by AstEngine for a confirmed (or rejected) hit.
// Stored on every ScanResult so the AI auto-remediation pipeline has full
// function-level context without needing to re-read the source file.
// ---------------------------------------------------------------------------
struct AstContext {
    bool        valid         = false; // Tree-sitter was available and parsed OK
    bool        confirmed     = false; // Match confirmed as real code
    std::string node_type;             // Leaf AST node type at the match site
    std::string enclosing_fn;          // Name of the enclosing function/method
    int         fn_start_line = 0;     // 1-based first line of enclosing scope
    int         fn_end_line   = 0;     // 1-based last  line of enclosing scope
    std::string fn_source;             // Full source text of enclosing function
    std::string note;                  // Human-readable validation explanation
};

// ---------------------------------------------------------------------------
// Proximity finding: weak cipher mode detected near a crypto keyword
// ---------------------------------------------------------------------------
struct ProximityFinding {
    int line_number;
    std::string description;
    std::string line_content;
};

// ---------------------------------------------------------------------------
// Fix pattern: regex match + replacement for auto-remediation
// ---------------------------------------------------------------------------
struct FixPattern {
    qre::Regex match;
    std::string match_str;
    std::string replacement;
};

// ---------------------------------------------------------------------------
// Rule: a single vulnerability detection rule loaded from rules.json
// ---------------------------------------------------------------------------
struct Rule {
    std::string id;
    std::string keyword;
    std::string description;
    std::string severity;       // "critical", "high", "warning"
    qre::Regex compiled_pattern;
    std::string pattern_str;
    std::vector<std::string> languages;
    std::string remediation;
    std::vector<FixPattern> fix_patterns;
    std::string cwe_id;
    // Optional per-language Tree-sitter S-expression queries.
    // Key   = file extension (e.g. ".cpp", ".py")
    // Value = TS query string (empty string → zero-config mode for that lang)
    std::map<std::string, std::string> ast_queries;

    bool applies_to(const std::string& ext) const {
        if (languages.empty()) return true;
        for (const auto& l : languages) {
            if (l == ext) return true;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------
// ScanResult: a single vulnerability finding
// ---------------------------------------------------------------------------
struct ScanResult {
    std::string filename;
    std::string rule_id;
    std::string keyword;
    std::string severity;       // "critical", "high", "warning"
    int line_number = 0;
    std::string line_content;
    std::string description;
    std::string remediation;
    std::string suggested_fix;
    std::string fingerprint;
    std::string cwe_id;
    bool is_baseline = false;
    bool is_entropy_finding = false;
    double entropy_value = 0.0;
    std::vector<ProximityFinding> proximity_findings;
    // AST hybrid fields (populated when USE_TREESITTER is compiled in)
    AstContext ast_context;    // full validation result + function context
    bool ast_validated = false; // true if AstEngine was invoked for this hit

    // AI remediation (populated in post-scan phase when USE_LLAMA is compiled in)
    // Contains the full rewritten function text produced by the local LLM.
    // When non-empty, AutoRemediator replaces lines fn_start..fn_end in the patch.
    std::string ai_remediation;

    // File language extension (e.g. ".cpp", ".py") — used by PqcContext for
    // language-aware prompt routing and dependency injection
    std::string language;
};

// ---------------------------------------------------------------------------
// VendorManifest: tracks what was injected into the target codebase
// ---------------------------------------------------------------------------
struct VendorManifest {
    std::string version = "2.0.0";
    std::string migrated_at;               // ISO-8601 timestamp
    std::vector<std::string> files_added;  // vendor/quantum_migrate/...
    std::vector<std::string> build_patches;// "CMakeLists.txt: added liboqs"
    std::vector<std::string> migrated_files; // files rewritten by AI
    std::string rollback_patch;            // path to rollback .patch
};

// ---------------------------------------------------------------------------
// ScanConfig: CLI configuration parsed from command-line arguments
// ---------------------------------------------------------------------------
struct ScanConfig {
    std::string rules_path = "rules.json";
    std::string format = "text";            // "text" or "sarif"
    std::string output_path;                // empty = auto-generate
    std::string fail_on = "warning";        // "critical", "high", "warning"
    std::string baseline_path = ".quantum-baseline.json";
    bool update_baseline = false;
    bool no_ignore = false;
    int num_threads = 0;                    // 0 = auto-detect
    bool enable_entropy = false;
    double entropy_threshold = 4.5;
    bool enable_proximity = false;
    bool enable_remediation = false;
    std::string patch_output = "quantum_fixes.patch";
    std::string target_directory;
    // Tree-sitter AST validation pass (active when USE_TREESITTER is compiled in)
    // Disable with --no-ast for benchmarking or debugging
    bool enable_ast = true;

    // AI remediation model path (e.g. models/qwen2.5-coder-7b-instruct-q4_k_m.gguf)
    // Requires --remediate --model=<path> at the CLI.  Empty = no AI.
    std::string model_path;
    int    ai_ctx_size   = 4096;  // context window (tokens)
    int    ai_threads    = 0;     // 0 = auto
    float  ai_temp       = 0.1f;  // low temp for deterministic code

    // PQC Vendoring (v2.0)
    std::string vendor_target_dir;       // --vendor-into <dir>
    bool patch_build_system = false;     // --patch-build-system
    bool dry_run            = false;     // --dry-run
    bool no_vendor          = false;     // --no-vendor
    bool enable_backup      = false;     // --backup
};
