#pragma once
// ============================================================================
// AstEngine.hpp — Tree-sitter AST validation layer (QuantumScanner v3.0)
// ============================================================================
//
// ARCHITECTURE: Hybrid Detection Pipeline
//   1. Fast Pass  — Regex pre-filter on comment-stripped lines (existing engine)
//   2. AST Pass   — Tree-sitter validates each regex hit:
//        a. QUERY MODE   : runs the S-expression query from rules.json for the
//                          specific language; checks if any capture falls on the
//                          matching line.
//        b. ZERO-CONFIG  : if no query is specified, simply verifies the match
//                          site is not inside a comment or string_literal node.
//                          Every rule gets false-positive reduction for free.
//   3. Context     — On confirmation, extracts enclosing function name, line
//                    range, and full source text → stored on ScanResult for the
//                    AI auto-remediation pipeline.
//   4. Fallback    — If tree-sitter cannot parse the file (or is not compiled
//                    in), AstContext::valid == false and the caller keeps the
//                    regex result unchanged.
//
// BUILD:
//   cmake -DUSE_TREESITTER=ON ..
//   (see CMakeLists.txt for FetchContent setup of grammars)
//
// THREAD SAFETY:
//   AstEngine::instance() is read-only after construction. Each call to
//   validate() creates its own TSParser and TSTree (cheap stack objects),
//   so the engine is fully re-entrant across all worker threads.
// ============================================================================

// AstContext is defined in ScanTypes.hpp (included transitively via the
// include chain scanner_main → ScanTypes → here).  AstEngine.hpp only needs
// to forward-declare it when used as a standalone include.
#include "ScanTypes.hpp"
#include <cstring>

// ============================================================================
#ifdef USE_TREESITTER
// ============================================================================

extern "C" {
#include <tree_sitter/api.h>

// Language grammar entry points — linked from the tree-sitter-* static libs
// added by CMakeLists.txt.  Only declare grammars actually compiled in.
extern const TSLanguage* tree_sitter_c(void);
extern const TSLanguage* tree_sitter_cpp(void);
extern const TSLanguage* tree_sitter_python(void);
extern const TSLanguage* tree_sitter_java(void);
extern const TSLanguage* tree_sitter_javascript(void);

#if defined(HAVE_TS_GO)
extern const TSLanguage* tree_sitter_go(void);
#endif
#if defined(HAVE_TS_RUST)
extern const TSLanguage* tree_sitter_rust(void);
#endif
#if defined(HAVE_TS_CSHARP)
extern const TSLanguage* tree_sitter_c_sharp(void);
#endif
} // extern "C"

// ============================================================================
// Internal helpers (in anonymous namespace to avoid ODR clashes)
// ============================================================================
namespace {

// Node types that represent non-executable content → false-positive sources
inline bool ast_is_non_code(const char* type) {
    if (!type) return false;
    // clang-format off
    static const char* const NC[] = {
        "comment", "line_comment", "block_comment", "documentation_comment",
        "string", "string_literal", "raw_string_literal",
        "interpreted_string_literal", "raw_string_fragment",
        "char_literal", "string_fragment", "string_content",
        nullptr
    };
    // clang-format on
    for (int i = 0; NC[i]; ++i)
        if (std::strcmp(type, NC[i]) == 0) return true;
    return false;
}

// Scope containers: walking up to the nearest of these gives the AI context
inline bool ast_is_fn_node(const char* type) {
    if (!type) return false;
    // clang-format off
    static const char* const FN[] = {
        "function_definition",        // C, C++, Python, Rust
        "function_declaration",       // JS, TS, Go
        "function",                   // anonymous JS
        "method_definition",          // JS/TS class methods
        "method_declaration",         // Java, C#
        "constructor_declaration",    // Java, C#
        "arrow_function",             // JS/TS =>
        "function_item",              // Rust fn
        "async_function_definition",  // Python async def
        "async_function_declaration", // JS async function
        nullptr
    };
    // clang-format on
    for (int i = 0; FN[i]; ++i)
        if (std::strcmp(type, FN[i]) == 0) return true;
    return false;
}

// Trim node source to the identifier before the first '(' (for C declarators)
inline std::string ast_trim_to_ident(std::string s) {
    auto p = s.find('(');
    if (p != std::string::npos) s.resize(p);
    // Trim leading whitespace/stars (pointer return types leak in sometimes)
    while (!s.empty() && (s.front() == ' ' || s.front() == '*')) s.erase(0, 1);
    while (!s.empty() && s.back()  == ' ')                        s.pop_back();
    return s;
}

} // anonymous namespace

// ============================================================================
// AstEngine — public interface
// ============================================================================
class AstEngine {
public:
    // Singleton: constructed once, all state is const after init,
    // fully safe to call from multiple threads simultaneously.
    static const AstEngine& instance() {
        static AstEngine e;
        return e;
    }

    // -----------------------------------------------------------------------
    // validate()
    //
    //   source      - complete file text (UTF-8, newline-terminated)
    //   ext         - lower-case extension e.g. ".cpp", ".py"
    //   query_str   - Tree-sitter S-expression query (may be empty)
    //   line_number - 1-based line where the regex matched
    //
    // Returns AstContext.  Caller should:
    //   if (ctx.valid && !ctx.confirmed)  →  skip result (false positive)
    //   if (!ctx.valid)                   →  keep result (AST unavailable)
    //   if (ctx.valid &&  ctx.confirmed)  →  keep result, attach ctx to ScanResult
    // -----------------------------------------------------------------------
    AstContext validate(const std::string& source,
                        const std::string& ext,
                        const std::string& query_str,
                        int                line_number) const
    {
        AstContext ctx;

        const TSLanguage* lang = lang_for(ext);
        if (!lang) {
            ctx.note = "No grammar available for extension '" + ext + "' — regex fallback";
            return ctx; // valid=false → caller keeps regex result
        }

        // ---- Parse the file ------------------------------------------------
        TSParser* psr = ts_parser_new();
        ts_parser_set_language(psr, lang);
        TSTree* tree = ts_parser_parse_string(
            psr, nullptr, source.c_str(), static_cast<uint32_t>(source.size()));
        ts_parser_delete(psr);

        if (!tree) {
            ctx.note = "Tree-sitter parse failed — regex fallback";
            return ctx;
        }

        ctx.valid = true;
        TSNode root = ts_tree_root_node(tree);

        // ---- Locate the deepest node that spans the matched line -----------
        // Use a wide column to reach leaf nodes rather than line-root nodes.
        TSPoint pt0 = { static_cast<uint32_t>(line_number - 1), 0u       };
        TSPoint pt1 = { static_cast<uint32_t>(line_number - 1), 100000u  };
        TSNode site = ts_node_descendant_for_point_range(root, pt0, pt1);
        ctx.node_type = ts_node_is_null(site) ? "(null)" : ts_node_type(site);

        // ---- Validate ------------------------------------------------------
        if (query_str.empty()) {
            // ZERO-CONFIG MODE: confirm site is not inside a comment/string
            ctx.confirmed = !ast_is_non_code(ctx.node_type.c_str());
            if (ctx.confirmed) {
                TSNode anc = ts_node_parent(site);
                while (!ts_node_is_null(anc)) {
                    if (ast_is_non_code(ts_node_type(anc))) {
                        ctx.confirmed = false;
                        ctx.note = "suppressed — match inside '"
                                   + std::string(ts_node_type(anc)) + "'";
                        break;
                    }
                    anc = ts_node_parent(anc);
                }
            }
            if (ctx.confirmed)
                ctx.note = "zero-config AST pass — match is in executable code";

        } else {
            // QUERY MODE: compile and run the S-expression query
            uint32_t     err_off  = 0;
            TSQueryError err_type = TSQueryErrorNone;
            TSQuery* q = ts_query_new(
                lang, query_str.c_str(),
                static_cast<uint32_t>(query_str.size()),
                &err_off, &err_type);

            if (!q) {
                // Graceful degradation: bad query → fall back to zero-config
                ctx.note = "query compile error at offset "
                           + std::to_string(err_off)
                           + " — falling back to zero-config";
                ctx.confirmed = !ast_is_non_code(ctx.node_type.c_str());
            } else {
                TSQueryCursor* qcur = ts_query_cursor_new();
                ts_query_cursor_exec(qcur, q, root);
                TSQueryMatch match;

                while (ts_query_cursor_next_match(qcur, &match)) {
                    for (uint16_t c = 0; c < match.capture_count; ++c) {
                        TSNode cap     = match.captures[c].node;
                        uint32_t c_row = ts_node_start_point(cap).row; // 0-based
                        if (static_cast<int>(c_row) == line_number - 1) {
                            ctx.confirmed = true;
                            site          = cap;   // use precise capture as new site
                            ctx.node_type = ts_node_type(cap);
                            ctx.note      = "query capture confirmed at line "
                                            + std::to_string(line_number);
                            break;
                        }
                    }
                    if (ctx.confirmed) break;
                }

                if (!ctx.confirmed)
                    ctx.note = "query found no capture on line "
                               + std::to_string(line_number)
                               + " — likely false positive";

                ts_query_cursor_delete(qcur);
                ts_query_delete(q);
            }
        }

        // ---- Extract enclosing function context (always, when site is valid)
        if (ctx.confirmed && !ts_node_is_null(site))
            extract_fn_context(site, source, ctx);

        ts_tree_delete(tree);
        return ctx;
    }

private:
    AstEngine() {
        // Register all compiled-in grammars
        const TSLanguage* lc   = tree_sitter_c();
        const TSLanguage* lcpp = tree_sitter_cpp();
        const TSLanguage* lpy  = tree_sitter_python();
        const TSLanguage* ljv  = tree_sitter_java();
        const TSLanguage* ljs  = tree_sitter_javascript();

        for (auto* e : {".c", ".h"})
            languages_[e] = lc;
        for (auto* e : {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h++"})
            languages_[e] = lcpp;
        languages_[".py"]  = lpy;
        languages_[".java"]= ljv;
        for (auto* e : {".js", ".jsx", ".mjs"})
            languages_[e] = ljs;

#if defined(HAVE_TS_GO)
        for (auto* e : {".go"})
            languages_[e] = tree_sitter_go();
#endif
#if defined(HAVE_TS_RUST)
        languages_[".rs"] = tree_sitter_rust();
#endif
#if defined(HAVE_TS_CSHARP)
        languages_[".cs"] = tree_sitter_c_sharp();
#endif
    }

    const TSLanguage* lang_for(const std::string& ext) const {
        auto it = languages_.find(ext);
        return it != languages_.end() ? it->second : nullptr;
    }

    // Walk from 'site' upward to the nearest function / method scope.
    // Fills ctx.enclosing_fn, ctx.fn_start_line, ctx.fn_end_line, ctx.fn_source.
    static void extract_fn_context(TSNode site,
                                   const std::string& src,
                                   AstContext& ctx)
    {
        // Walk up to find the nearest enclosing function-scope node
        TSNode fn = ts_node_parent(site);
        while (!ts_node_is_null(fn)) {
            if (ast_is_fn_node(ts_node_type(fn))) break;
            fn = ts_node_parent(fn);
        }
        if (ts_node_is_null(fn) || !ast_is_fn_node(ts_node_type(fn)))
            return; // top-level / global code — no enclosing function

        // Line range (0-based rows → 1-based lines)
        ctx.fn_start_line = static_cast<int>(ts_node_start_point(fn).row) + 1;
        ctx.fn_end_line   = static_cast<int>(ts_node_end_point(fn).row)   + 1;

        // Full source text of the function
        uint32_t sb = ts_node_start_byte(fn);
        uint32_t eb = ts_node_end_byte(fn);
        if (eb <= src.size())
            ctx.fn_source = src.substr(sb, eb - sb);

        // Function name: try "name" field first (Python, JS/TS, Rust, Java)
        TSNode name_node = ts_node_child_by_field_name(fn, "name", 4);
        if (!ts_node_is_null(name_node)) {
            uint32_t s = ts_node_start_byte(name_node);
            uint32_t e = ts_node_end_byte(name_node);
            if (e <= src.size())
                ctx.enclosing_fn = src.substr(s, e - s);
            return;
        }

        // C/C++: function_definition has "declarator" → function_declarator
        //        which itself has "declarator" → identifier
        TSNode decl = ts_node_child_by_field_name(fn, "declarator", 10);
        if (!ts_node_is_null(decl)) {
            TSNode inner = ts_node_child_by_field_name(decl, "declarator", 10);
            TSNode target = ts_node_is_null(inner) ? decl : inner;
            uint32_t s = ts_node_start_byte(target);
            uint32_t e = ts_node_end_byte(target);
            if (e <= src.size())
                ctx.enclosing_fn = ast_trim_to_ident(src.substr(s, e - s));
        }
    }

    std::map<std::string, const TSLanguage*> languages_;
};

// ============================================================================
#else  // USE_TREESITTER is NOT defined — zero-overhead stub
// ============================================================================

class AstEngine {
public:
    static const AstEngine& instance() { static AstEngine e; return e; }

    // Always returns AstContext{valid=false} → caller keeps the regex result.
    AstContext validate(const std::string& /*source*/,
                        const std::string& /*ext*/,
                        const std::string& /*query_str*/,
                        int                /*line_number*/) const
    {
        return AstContext{};
    }
};

#endif  // USE_TREESITTER
