#pragma once
// ============================================================================
// AutoRemediator.hpp - Automatic patch/fix generation
// ============================================================================
// Generates unified diff (.patch) files with suggested code fixes for each
// vulnerability. Developers can apply fixes with: git apply quantum_fixes.patch
//
// Supports two remediation modes:
//   1. Regex-based:  line-level pattern replacement (fast, deterministic)
//   2. AI-driven:    function-level rewrite via local LLM (requires --model)
//      When ai_remediation is set on a ScanResult AND the AstContext contains
//      valid fn_start_line / fn_end_line, the patch replaces the entire
//      function body with the AI's output.
//
// Enterprise feature: In CI/CD pipelines, this can be extended to
// automatically open Pull Requests with fixes via the GitHub REST API.
// ============================================================================

#include "../scan/ScanTypes.hpp"
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <map>
#include <filesystem>

namespace fs = std::filesystem;

class AutoRemediator {
public:
    // Generate suggested fix text for a scan result using the rule's fix_patterns
    static std::string generate_suggestion(const ScanResult& result,
                                            const std::vector<Rule>& rules) {
        // Find the matching rule
        for (const auto& rule : rules) {
            if (rule.id == result.rule_id) {
                // Try each fix pattern against the line
                for (const auto& fix : rule.fix_patterns) {
                    if (fix.match.search(result.line_content)) {
                        return fix.match.replace(result.line_content, fix.replacement);
                    }
                }
                // If no specific fix pattern matches, provide generic remediation
                return "// TODO: " + rule.remediation;
            }
        }
        return "";
    }

    // Generate a unified diff patch file from all scan results
    static bool generate_patch(const std::vector<ScanResult>& results,
                                const std::vector<Rule>& rules,
                                const std::string& patch_path,
                                const std::string& root_dir) {
        std::ofstream patch(patch_path);
        if (!patch) {
            std::cerr << "[ERROR] Cannot create patch file: " << patch_path << std::endl;
            return false;
        }

        // Group results by file
        std::map<std::string, std::vector<const ScanResult*>> by_file;
        for (const auto& r : results) {
            if (r.is_baseline) continue;
            by_file[r.filename].push_back(&r);
        }

        int fixes_generated = 0;

        for (const auto& [filepath, file_results] : by_file) {
            // Read the original file
            std::ifstream original(filepath);
            if (!original) continue;

            std::vector<std::string> lines;
            std::string line;
            while (std::getline(original, line)) {
                lines.push_back(line);
            }
            original.close();

            // ---------------------------------------------------------------
            // Build edit list — each edit replaces a range of lines.
            //   PatchEdit { start (0-based), end (0-based inclusive),
            //               replacement lines }
            // ---------------------------------------------------------------
            struct PatchEdit {
                int start;  // 0-based, inclusive
                int end;    // 0-based, inclusive
                std::vector<std::string> replacement;
            };

            std::vector<PatchEdit> edits;
            std::set<std::string> emitted_fns;  // dedup AI function edits

            for (const auto* r : file_results) {
                // --- AI function-level replacement ---------------------------
                if (!r->ai_remediation.empty() &&
                    r->ast_context.fn_start_line > 0 &&
                    r->ast_context.fn_end_line > 0)
                {
                    // Dedup: only emit one edit per function
                    std::string fn_key = std::to_string(r->ast_context.fn_start_line);
                    if (emitted_fns.count(fn_key)) continue;
                    emitted_fns.insert(fn_key);

                    int start = r->ast_context.fn_start_line - 1;
                    int end   = r->ast_context.fn_end_line   - 1;
                    if (start < 0 || end >= static_cast<int>(lines.size()))
                        continue;

                    // Split AI output into lines
                    std::vector<std::string> new_lines;
                    std::istringstream stream(r->ai_remediation);
                    std::string ai_line;
                    while (std::getline(stream, ai_line))
                        new_lines.push_back(ai_line);

                    if (new_lines.empty()) continue;

                    edits.push_back(PatchEdit{start, end, std::move(new_lines)});
                    fixes_generated++;
                    continue;
                }

                // --- Regex line-level replacement ----------------------------
                int idx = r->line_number - 1;
                if (idx < 0 || idx >= static_cast<int>(lines.size())) continue;

                std::string fix = generate_suggestion(*r, rules);
                if (!fix.empty() && fix != lines[idx]) {
                    edits.push_back(PatchEdit{idx, idx, {fix}});
                    fixes_generated++;
                }
            }

            if (edits.empty()) continue;

            // Sort edits by start line (ascending) for correct patch ordering
            std::sort(edits.begin(), edits.end(),
                      [](const PatchEdit& a, const PatchEdit& b) {
                          return a.start < b.start;
                      });

            // Remove overlapping edits (keep the first / largest)
            std::vector<PatchEdit> merged;
            for (auto& e : edits) {
                if (!merged.empty() && e.start <= merged.back().end)
                    continue;   // overlaps with previous — skip
                merged.push_back(std::move(e));
            }

            // Relative path for diff header
            fs::path rel_path;
            try {
                rel_path = fs::relative(filepath, root_dir);
            } catch (...) {
                rel_path = filepath;
            }
            std::string rel_str = rel_path.string();
            std::replace(rel_str.begin(), rel_str.end(), '\\', '/');

            patch << "--- a/" << rel_str << "\n";
            patch << "+++ b/" << rel_str << "\n";

            // ---------------------------------------------------------------
            // Build hunks — merge edits that are within 3 context lines of
            // each other into a single hunk.
            // ---------------------------------------------------------------
            const int CTX = 3;
            struct Hunk {
                int ctx_start;   // first line of hunk (0-based, with context)
                int ctx_end;     // last  line of hunk (0-based, with context)
                std::vector<int> edit_indices;  // indices into `merged`
            };

            std::vector<Hunk> hunks;
            for (int ei = 0; ei < static_cast<int>(merged.size()); ei++) {
                int cs = std::max(0, merged[ei].start - CTX);
                int ce = std::min(static_cast<int>(lines.size()) - 1,
                                  merged[ei].end + CTX);

                if (!hunks.empty() && cs <= hunks.back().ctx_end + 1) {
                    // Merge into previous hunk
                    hunks.back().ctx_end = std::max(hunks.back().ctx_end, ce);
                    hunks.back().edit_indices.push_back(ei);
                } else {
                    hunks.push_back(Hunk{cs, ce, {ei}});
                }
            }

            // ---------------------------------------------------------------
            // Emit each hunk as a unified diff section
            // ---------------------------------------------------------------
            for (const auto& hunk : hunks) {
                // Compute old and new line counts for the @@ header
                int old_count = hunk.ctx_end - hunk.ctx_start + 1;
                int new_count = old_count;

                // Adjust new_count for edits that change the number of lines
                for (int ei : hunk.edit_indices) {
                    int orig_lines = merged[ei].end - merged[ei].start + 1;
                    int repl_lines = static_cast<int>(merged[ei].replacement.size());
                    new_count += (repl_lines - orig_lines);
                }

                patch << "@@ -" << (hunk.ctx_start + 1) << "," << old_count
                      << " +" << (hunk.ctx_start + 1) << "," << new_count << " @@\n";

                // Build a set of edit ranges for quick lookups
                // Map: start_line → edit index
                std::map<int, int> edit_at;
                for (int ei : hunk.edit_indices)
                    edit_at[merged[ei].start] = ei;

                int i = hunk.ctx_start;
                while (i <= hunk.ctx_end) {
                    auto it = edit_at.find(i);
                    if (it != edit_at.end()) {
                        const auto& e = merged[it->second];
                        // Emit removed (old) lines
                        for (int k = e.start; k <= e.end; k++)
                            patch << "-" << lines[k] << "\n";
                        // Emit added (new) lines
                        for (const auto& rpl : e.replacement)
                            patch << "+" << rpl << "\n";
                        i = e.end + 1;
                    } else {
                        // Context line (unchanged)
                        if (i < static_cast<int>(lines.size()))
                            patch << " " << lines[i] << "\n";
                        i++;
                    }
                }
            }
        }

        patch.close();

        if (fixes_generated > 0) {
            std::cout << "[PATCH] Generated " << fixes_generated
                      << " fix(es) in " << patch_path << std::endl;
            std::cout << "  Apply with: git apply " << patch_path << std::endl;
        } else {
            std::cout << "[PATCH] No auto-fixable patterns found for patch generation"
                      << std::endl;
        }

        return fixes_generated > 0;
    }
};
