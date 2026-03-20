#pragma once
// ============================================================================
// AiRemediator.hpp — Context-Aware PQC Auto-Remediation (v2.2)
// ============================================================================
//
// v2.2 UPGRADE: Multi-vulnerability batched prompts + FIPS 205 (SLH-DSA)
//   - generate_batched_remediation(): groups all vulns per function into ONE prompt
//   - build_batched_prompt(): merges API refs from multiple PqcCategories
//   - NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) / FIPS 205 (SLH-DSA) throughout
//   - Hybrid KEM (X25519+ML-KEM-768) API injected for transitional deployments
//
// v2.1: Optimized for Qwen2.5-Coder-14B-Instruct (F16)
//   - Expanded context window (16K default) for full function rewrites
//   - Structured system prompt with anti-hallucination framing
//   - Aggressive markdown/fence stripping in post-processing
//   - PqcContext injects VERBATIM API definitions (KEM, SIGNATURE, CIPHER, HASH)
//
// The model no longer hallucinates function names — it sees the actual API.
//
// BUILD:
//   cmake -DUSE_LLAMA=ON ..
//
// THREAD SAFETY:
//   Internal mutex serialises inference — safe to call from any thread.
// ============================================================================

#include "../scan/ScanTypes.hpp"
#include "PqcContext.hpp"
#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <iostream>
#include <sstream>
#include <cstring>

// ============================================================================
#ifdef USE_LLAMA
// ============================================================================

#include "llama.h"

class AiRemediator {
public:
    explicit AiRemediator(const std::string& model_path,
                          int   n_ctx     = 16384,
                          int   n_threads = 0,
                          float temp      = 0.05f)
        : n_ctx_(n_ctx), temp_(temp)
    {
        llama_backend_init();

        llama_model_params mp = llama_model_default_params();
        mp.n_gpu_layers = 0;

        model_ = llama_model_load_from_file(model_path.c_str(), mp);
        if (!model_) {
            std::cerr << "[AI-ERROR] Failed to load model: " << model_path << "\n";
            return;
        }

        vocab_ = llama_model_get_vocab(model_);

        llama_context_params cp = llama_context_default_params();
        cp.n_ctx      = static_cast<uint32_t>(n_ctx_);
        cp.n_batch    = 512;
        cp.n_threads  = n_threads > 0 ? static_cast<uint32_t>(n_threads) : 4;

        ctx_ = llama_init_from_model(model_, cp);
        if (!ctx_) {
            std::cerr << "[AI-ERROR] Failed to create llama context\n";
            llama_model_free(model_);
            model_ = nullptr;
            return;
        }

        build_sampler();

        std::cout << "[AI] Model loaded: " << model_path
                  << "  (ctx=" << n_ctx_ << ", temp=" << temp_ << ")\n";
    }

    AiRemediator(const AiRemediator&)            = delete;
    AiRemediator& operator=(const AiRemediator&) = delete;
    AiRemediator(AiRemediator&&)                 = delete;
    AiRemediator& operator=(AiRemediator&&)      = delete;

    ~AiRemediator() {
        if (sampler_) llama_sampler_free(sampler_);
        if (ctx_)     llama_free(ctx_);
        if (model_)   llama_model_free(model_);
        llama_backend_free();
    }

    bool is_loaded() const { return model_ != nullptr && ctx_ != nullptr; }

    // -----------------------------------------------------------------------
    // generate_remediation() — v2.1: context-aware with PqcContext (FIPS 203/204)
    //
    //   rule             : matched Rule (id, description, CWE, remediation)
    //   vulnerable_code  : function source text from AstEngine
    //   language         : file extension (e.g. ".cpp", ".py")
    //
    // Returns AI-rewritten function. Empty on error.
    // -----------------------------------------------------------------------
    std::string generate_remediation(const Rule&        rule,
                                     const std::string& vulnerable_code,
                                     const std::string& language = ".cpp")
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (!is_loaded()) return "";

        // v2.1: Build context-aware prompt (14B-optimized)
        std::string prompt = build_context_aware_prompt(rule, vulnerable_code, language);

        return run_inference(prompt);
    }

    // -----------------------------------------------------------------------
    // generate_batched_remediation() — v2.2: multi-vulnerability batched prompt
    //
    //   rules            : all Rules matched within the SAME function body
    //   vulnerable_code  : function source text (shared across all rules)
    //   language         : file extension (e.g. ".cpp", ".py")
    //
    // Sends ALL vulnerabilities for a function in a single prompt, so the
    // LLM rewrites the function once addressing every issue.
    // Returns AI-rewritten function. Empty on error.
    // -----------------------------------------------------------------------
    std::string generate_batched_remediation(
        const std::vector<const Rule*>& rules,
        const std::string&              vulnerable_code,
        const std::string&              language = ".cpp")
    {
        if (rules.empty()) return "";
        if (rules.size() == 1)
            return generate_remediation(*rules[0], vulnerable_code, language);

        std::lock_guard<std::mutex> lock(mtx_);
        if (!is_loaded()) return "";

        std::string prompt = build_batched_prompt(rules, vulnerable_code, language);

        return run_inference(prompt);
    }

private:
    llama_model*            model_   = nullptr;
    llama_context*          ctx_     = nullptr;
    const llama_vocab*      vocab_   = nullptr;
    llama_sampler*          sampler_ = nullptr;

    int   n_ctx_;
    float temp_;
    std::mutex mtx_;

    // -----------------------------------------------------------------------
    // run_inference() — shared tokenise → decode → sample → trim pipeline
    // Caller must hold mtx_.
    // -----------------------------------------------------------------------
    std::string run_inference(const std::string& prompt) {
        std::vector<llama_token> tokens = tokenize(prompt, true);
        if (tokens.empty()) {
            std::cerr << "[AI-WARN] Tokenization produced 0 tokens\n";
            return "";
        }

        int max_gen = n_ctx_ - static_cast<int>(tokens.size());
        if (max_gen < 64) {
            std::cerr << "[AI-WARN] Prompt too long (" << tokens.size()
                      << " tokens) for n_ctx=" << n_ctx_ << " — skipping\n";
            return "";
        }
        if (max_gen > 4096) max_gen = 4096;

        llama_kv_cache_clear(ctx_);

        int n_prompt = static_cast<int>(tokens.size());
        int batch_capacity = std::max(512, n_prompt);
        llama_batch batch = llama_batch_init(batch_capacity, 0, 1);
        for (int i = 0; i < n_prompt; i++)
            batch_add(batch, tokens[i], i, i == n_prompt - 1);

        if (llama_decode(ctx_, batch) != 0) {
            std::cerr << "[AI-WARN] Prefill decode failed\n";
            llama_batch_free(batch);
            return "";
        }

        std::string output;
        output.reserve(4096);

        llama_token eos = llama_vocab_eos(vocab_);
        llama_token eot = llama_vocab_eot(vocab_);
        int n_cur = n_prompt;

        for (int i = 0; i < max_gen; i++) {
            llama_token new_tok = llama_sampler_sample(sampler_, ctx_, -1);
            llama_sampler_accept(sampler_, new_tok);

            if (new_tok == eos || new_tok == eot || is_stop_token(new_tok))
                break;

            output += token_to_string(new_tok);

            llama_batch_clear(batch);
            batch_add(batch, new_tok, n_cur, true);
            n_cur++;

            if (llama_decode(ctx_, batch) != 0) {
                std::cerr << "[AI-WARN] Generation decode failed at token " << i << "\n";
                break;
            }
        }

        llama_batch_free(batch);
        llama_sampler_reset(sampler_);

        return trim_response(output);
    }

    // -----------------------------------------------------------------------
    // v2.1: Context-Aware Prompt — injects real PQC API definitions (FIPS 203/204/205)
    //
    // Optimized for Qwen2.5-Coder-14B-Instruct:
    //   - Structured numbered constraints prevent format drift
    //   - Negative examples block markdown/filler output
    //   - NIST standard names (ML-KEM, ML-DSA) in all user-facing text
    //   - Full API surface injected verbatim from PqcContext
    // -----------------------------------------------------------------------
    static std::string build_context_aware_prompt(
        const Rule&        rule,
        const std::string& vulnerable_code,
        const std::string& language)
    {
        // Classify the rule into a PQC category
        PqcCategory cat = PqcContext::classify(rule.id);

        // Get the API reference for this category
        std::string api_ref = PqcContext::get_api_reference(cat);

        // Get a working usage example for this language
        std::string example = PqcContext::get_usage_example(cat, language);

        // Get the include/import directive
        std::string include_dir = PqcContext::get_include_directive(cat, language);

        // Get language binding note
        std::string lang_note = PqcContext::get_language_binding_note(language);

        // ---- Build system prompt (14B-optimized) ----
        std::ostringstream sys;
        sys << "ROLE: You are a Post-Quantum Cryptography migration engine.\n"
            << "TASK: Rewrite vulnerable cryptographic code to use the "
               "QuantumMigrate PQC SDK, compliant with NIST FIPS 203 "
               "(ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).\n\n";

        if (!api_ref.empty()) {
            sys << "=== AUTHORIZED API (use ONLY these declarations) ===\n"
                << api_ref << "\n\n";
        }

        if (!include_dir.empty()) {
            sys << "=== REQUIRED IMPORT ===\n"
                << include_dir << "\n\n";
        }

        if (!example.empty()) {
            sys << "=== REFERENCE EXAMPLE ===\n"
                << example << "\n\n";
        }

        if (!lang_note.empty()) {
            sys << "=== LANGUAGE BINDING ===\n"
                << lang_note << "\n\n";
        }

        sys << "=== OUTPUT CONTRACT ===\n"
            << "1. Emit ONLY raw, compilable source code. No prose, no "
               "markdown, no ``` fences, no commentary before or after.\n"
            << "2. Use EXCLUSIVELY the API functions listed above. Inventing "
               "function names (e.g. kyber_keygen, pqc_encrypt) is a "
               "critical failure.\n"
            << "3. Preserve the original function signature, parameter names, "
               "return type, and error-handling idioms exactly.\n"
            << "4. Above each migrated call site, add a single-line comment:\n"
               "     // PQC-MIGRATE: <old> -> <new> (FIPS XXX)\n"
               "   Example: // PQC-MIGRATE: RSA_generate_key_ex -> "
               "QuantumWrapper::generate_keypair (FIPS 203)\n"
            << "5. If no direct API swap exists (protocol-level issue), "
               "insert: // TODO(pqc): <actionable description>\n"
            << "6. Never add #include lines that are not shown in "
               "REQUIRED IMPORT above.\n"
            << "7. Never output explanations, apologies, or alternatives. "
               "Code only.\n";

        // ---- Build user prompt ----
        std::ostringstream usr;
        usr << "VULNERABILITY: " << rule.id << " — " << rule.description << "\n"
            << "CWE: "           << rule.cwe_id  << "\n"
            << "NIST GUIDANCE: " << rule.remediation << "\n"
            << "FILE LANGUAGE: " << language << "\n\n"
            << "--- BEGIN VULNERABLE CODE ---\n"
            << vulnerable_code << "\n"
            << "--- END VULNERABLE CODE ---\n\n"
            << "Rewrite the code above. Output ONLY the corrected source.";

        // ---- Assemble ChatML (Qwen2.5 native format) ----
        std::string p;
        p.reserve(4096 + vulnerable_code.size());
        p += "<|im_start|>system\n";
        p += sys.str();
        p += "<|im_end|>\n";
        p += "<|im_start|>user\n";
        p += usr.str();
        p += "<|im_end|>\n";
        p += "<|im_start|>assistant\n";
        return p;
    }

    // -----------------------------------------------------------------------
    // v2.2: Batched Prompt — multiple vulnerabilities in ONE function
    //
    // Collects all distinct PqcCategories, merges their API references,
    // and lists every vulnerability in the user prompt so the model can
    // address them all in a single rewrite pass.
    // -----------------------------------------------------------------------
    static std::string build_batched_prompt(
        const std::vector<const Rule*>& rules,
        const std::string&              vulnerable_code,
        const std::string&              language)
    {
        // Collect unique PQC categories and deduplicate API references
        std::set<PqcCategory> categories;
        for (const auto* r : rules)
            categories.insert(PqcContext::classify(r->id));

        // Merge API references from all categories
        std::ostringstream api_block, example_block, include_block;
        std::set<std::string> seen_includes;
        for (PqcCategory cat : categories) {
            std::string api = PqcContext::get_api_reference(cat);
            if (!api.empty()) api_block << api << "\n";

            std::string ex = PqcContext::get_usage_example(cat, language);
            if (!ex.empty()) example_block << ex << "\n";

            std::string inc = PqcContext::get_include_directive(cat, language);
            if (!inc.empty() && seen_includes.insert(inc).second)
                include_block << inc << "\n";
        }

        std::string lang_note = PqcContext::get_language_binding_note(language);

        // ---- Build system prompt ----
        std::ostringstream sys;
        sys << "ROLE: You are a Post-Quantum Cryptography migration engine.\n"
            << "TASK: Rewrite vulnerable cryptographic code to use the "
               "QuantumMigrate PQC SDK, compliant with NIST FIPS 203 "
               "(ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA).\n"
            << "This function contains MULTIPLE vulnerabilities. Fix ALL "
               "of them in a single rewrite.\n\n";

        std::string api_str = api_block.str();
        if (!api_str.empty()) {
            sys << "=== AUTHORIZED API (use ONLY these declarations) ===\n"
                << api_str << "\n";
        }

        std::string inc_str = include_block.str();
        if (!inc_str.empty()) {
            sys << "=== REQUIRED IMPORTS ===\n"
                << inc_str << "\n";
        }

        std::string ex_str = example_block.str();
        if (!ex_str.empty()) {
            sys << "=== REFERENCE EXAMPLES ===\n"
                << ex_str << "\n";
        }

        if (!lang_note.empty()) {
            sys << "=== LANGUAGE BINDING ===\n"
                << lang_note << "\n\n";
        }

        sys << "=== OUTPUT CONTRACT ===\n"
            << "1. Emit ONLY raw, compilable source code. No prose, no "
               "markdown, no ``` fences, no commentary before or after.\n"
            << "2. Use EXCLUSIVELY the API functions listed above.\n"
            << "3. Preserve the original function signature, parameter names, "
               "return type, and error-handling idioms exactly.\n"
            << "4. Above each migrated call site, add a single-line comment:\n"
               "     // PQC-MIGRATE: <old> -> <new> (FIPS XXX)\n"
            << "5. If no direct API swap exists, insert: "
               "// TODO(pqc): <actionable description>\n"
            << "6. Never add #include lines not shown in REQUIRED IMPORTS.\n"
            << "7. Never output explanations, apologies, or alternatives. "
               "Code only.\n";

        // ---- Build user prompt with ALL vulnerabilities listed ----
        std::ostringstream usr;
        usr << "The following function contains " << rules.size()
            << " vulnerabilities. Fix ALL of them:\n\n";

        for (size_t i = 0; i < rules.size(); ++i) {
            usr << "VULNERABILITY " << (i + 1) << ": "
                << rules[i]->id << " — " << rules[i]->description << "\n"
                << "  CWE: " << rules[i]->cwe_id << "\n"
                << "  NIST GUIDANCE: " << rules[i]->remediation << "\n\n";
        }

        usr << "--- BEGIN VULNERABLE CODE ---\n"
            << vulnerable_code << "\n"
            << "--- END VULNERABLE CODE ---\n\n"
            << "Rewrite the code above fixing ALL " << rules.size()
            << " vulnerabilities. Output ONLY the corrected source.";

        // ---- Assemble ChatML ----
        std::string p;
        p.reserve(8192 + vulnerable_code.size());
        p += "<|im_start|>system\n";
        p += sys.str();
        p += "<|im_end|>\n";
        p += "<|im_start|>user\n";
        p += usr.str();
        p += "<|im_end|>\n";
        p += "<|im_start|>assistant\n";
        return p;
    }

    // -----------------------------------------------------------------------
    // Tokenization helpers (unchanged from v1)
    // -----------------------------------------------------------------------
    std::vector<llama_token> tokenize(const std::string& text, bool add_special) const {
        int n_max = static_cast<int>(text.size()) + 128;
        std::vector<llama_token> toks(n_max);
        int n = llama_tokenize(
            vocab_, text.c_str(), static_cast<int32_t>(text.size()),
            toks.data(), n_max, add_special, true);
        if (n < 0) {
            toks.resize(static_cast<size_t>(-n));
            n = llama_tokenize(
                vocab_, text.c_str(), static_cast<int32_t>(text.size()),
                toks.data(), static_cast<int32_t>(toks.size()),
                add_special, true);
        }
        if (n <= 0) return {};
        toks.resize(static_cast<size_t>(n));
        return toks;
    }

    std::string token_to_string(llama_token tok) const {
        char buf[128];
        int n = llama_token_to_piece(vocab_, tok, buf, sizeof(buf), 0, true);
        if (n < 0) {
            std::vector<char> big(static_cast<size_t>(-n));
            n = llama_token_to_piece(vocab_, tok, big.data(),
                                     static_cast<int32_t>(big.size()), 0, true);
            return (n > 0) ? std::string(big.data(), static_cast<size_t>(n)) : "";
        }
        return std::string(buf, static_cast<size_t>(n));
    }

    bool is_stop_token(llama_token tok) const {
        std::string piece = token_to_string(tok);
        if (piece.find("<|im_end|>") != std::string::npos) return true;
        if (piece.find("<|endoftext|>") != std::string::npos) return true;
        return false;
    }

    static void batch_add(llama_batch& b, llama_token tok,
                          llama_pos pos, bool logits) {
        b.token   [b.n_tokens] = tok;
        b.pos     [b.n_tokens] = pos;
        b.n_seq_id[b.n_tokens] = 1;
        b.seq_id  [b.n_tokens][0] = 0;
        b.logits  [b.n_tokens] = logits ? 1 : 0;
        b.n_tokens++;
    }

    static void batch_clear(llama_batch& b) {
        b.n_tokens = 0;
    }

    void build_sampler() {
        llama_sampler_chain_params sp = llama_sampler_chain_default_params();
        sampler_ = llama_sampler_chain_init(sp);
        // 14B model: tighter sampling for deterministic code output
        llama_sampler_chain_add(sampler_, llama_sampler_init_top_k(20));
        llama_sampler_chain_add(sampler_, llama_sampler_init_top_p(0.90f, 1));
        llama_sampler_chain_add(sampler_, llama_sampler_init_min_p(0.05f, 1));
        llama_sampler_chain_add(sampler_, llama_sampler_init_temp(temp_));
        llama_sampler_chain_add(sampler_, llama_sampler_init_dist(42));
    }

    static std::string trim_response(const std::string& raw) {
        std::string s = raw;

        auto ltrim = [](std::string& str) {
            str.erase(0, str.find_first_not_of(" \t\r\n"));
        };
        auto rtrim = [](std::string& str) {
            auto pos = str.find_last_not_of(" \t\r\n");
            if (pos != std::string::npos) str.resize(pos + 1);
        };

        // Strip ALL markdown code fences (```lang ... ``` or ``` ... ```)
        // Multi-pass: models sometimes emit nested or multiple fenced blocks
        for (int pass = 0; pass < 3; ++pass) {
            auto fence_open = s.find("```");
            if (fence_open == std::string::npos) break;

            // Find end of opening fence line
            auto nl = s.find('\n', fence_open);
            if (nl != std::string::npos)
                s.erase(fence_open, nl - fence_open + 1);
            else
                s.erase(fence_open);

            // Find and strip the closing fence
            auto fence_close = s.rfind("```");
            if (fence_close != std::string::npos)
                s.erase(fence_close);
        }

        // Strip ChatML markers
        for (const char* marker : {"<|im_end|>", "<|im_start|>", "<|endoftext|>"}) {
            size_t pos;
            while ((pos = s.find(marker)) != std::string::npos)
                s.erase(pos, std::strlen(marker));
        }

        // Strip conversational filler lines the 14B model may occasionally emit
        // (e.g. "Here is the corrected code:", "Sure,", "```cpp")
        {
            std::istringstream stream(s);
            std::ostringstream cleaned;
            std::string line;
            bool code_started = false;
            while (std::getline(stream, line)) {
                std::string trimmed = line;
                auto p1 = trimmed.find_first_not_of(" \t");
                if (p1 != std::string::npos) trimmed = trimmed.substr(p1);

                // Skip common preamble lines before actual code
                if (!code_started) {
                    if (trimmed.empty()) continue;
                    if (trimmed.find("Here") == 0 || trimmed.find("Sure") == 0 ||
                        trimmed.find("Below") == 0 || trimmed.find("The ") == 0 ||
                        trimmed.find("I ") == 0 || trimmed.find("Note:") == 0 ||
                        trimmed.find("Certainly") == 0)
                        continue;
                }
                code_started = true;
                cleaned << line << "\n";
            }
            s = cleaned.str();
        }

        ltrim(s);
        rtrim(s);
        return s;
    }
};

// ============================================================================
#else  // USE_LLAMA is NOT defined — zero-overhead stub
// ============================================================================

class AiRemediator {
public:
    explicit AiRemediator(const std::string& /*model_path*/,
                          int   /*n_ctx*/     = 16384,
                          int   /*n_threads*/ = 0,
                          float /*temp*/      = 0.05f) {}

    bool is_loaded() const { return false; }

    std::string generate_remediation(const Rule& /*rule*/,
                                     const std::string& /*code*/,
                                     const std::string& /*language*/ = ".cpp") {
        return "";
    }

    std::string generate_batched_remediation(
        const std::vector<const Rule*>& /*rules*/,
        const std::string&              /*code*/,
        const std::string&              /*language*/ = ".cpp") {
        return "";
    }
};

#endif // USE_LLAMA
