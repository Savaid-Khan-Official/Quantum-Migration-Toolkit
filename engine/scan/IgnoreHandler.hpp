#pragma once
// ============================================================================
// IgnoreHandler.hpp - .gitignore and .quantumignore support
// ============================================================================
// Parses ignore files and filters paths that should not be scanned.
// Automatically skips hidden directories (.git, .svn, etc.).
// Supports basic glob patterns: *, **, ?, directory-only (trailing /)
// ============================================================================

#include <string>
#include <vector>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include "RegexEngine.hpp"

namespace fs = std::filesystem;

class IgnoreHandler {
public:
    // Load patterns from .gitignore file at the root
    bool load_gitignore(const fs::path& root_dir) {
        fs::path gitignore = root_dir / ".gitignore";
        if (fs::exists(gitignore)) {
            load_file(gitignore);
            return true;
        }
        return false;
    }

    // Load patterns from .quantumignore file at the root
    bool load_quantumignore(const fs::path& root_dir) {
        fs::path qi = root_dir / ".quantumignore";
        if (fs::exists(qi)) {
            load_file(qi);
            return true;
        }
        return false;
    }

    // Check if a given path (relative to root) should be ignored
    bool should_ignore(const fs::path& filepath, const fs::path& root_dir) const {
        // Get path relative to root for all checks
        fs::path rel;
        try {
            rel = fs::relative(filepath, root_dir);
        } catch (...) {
            rel = filepath;
        }

        // Skip hidden directories (.git, .svn, .hg, etc.) — check RELATIVE path only
        for (const auto& part : rel) {
            std::string s = part.string();
            if (!s.empty() && s[0] == '.' && s != "." && s != "..") {
                return true;
            }
        }

        std::string rel_str = rel.string();
        // Normalize separators to forward slash
        std::replace(rel_str.begin(), rel_str.end(), '\\', '/');

        // Check against all ignore patterns
        for (const auto& pattern : patterns_) {
            if (pattern.negated) continue;  // Skip negation for simplicity

            if (pattern.dir_only && !fs::is_directory(filepath)) continue;

            if (matches_pattern(rel_str, pattern.regex_pattern)) {
                return true;
            }
        }

        return false;
    }

    size_t pattern_count() const { return patterns_.size(); }

private:
    struct IgnorePattern {
        std::string original;
        qre::Regex regex_pattern;
        bool negated = false;
        bool dir_only = false;
    };

    std::vector<IgnorePattern> patterns_;

    void load_file(const fs::path& filepath) {
        std::ifstream file(filepath);
        if (!file) return;

        std::string line;
        while (std::getline(file, line)) {
            // Trim whitespace
            while (!line.empty() && (line.back() == ' ' || line.back() == '\r' || line.back() == '\t'))
                line.pop_back();
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
                line.erase(line.begin());

            // Skip empty lines and comments
            if (line.empty() || line[0] == '#') continue;

            IgnorePattern pat;
            pat.original = line;

            // Check for negation
            if (line[0] == '!') {
                pat.negated = true;
                line = line.substr(1);
            }

            // Check for directory-only pattern
            if (!line.empty() && line.back() == '/') {
                pat.dir_only = true;
                line.pop_back();
            }

            // Remove leading /
            if (!line.empty() && line[0] == '/') {
                line = line.substr(1);
            }

            // Convert glob pattern to regex
            try {
                pat.regex_pattern = qre::Regex(
                    glob_to_regex(line), true  // case-insensitive
                );
                patterns_.push_back(std::move(pat));
            } catch (const std::runtime_error&) {
                // Skip invalid patterns silently
            }
        }
    }

    // Convert a glob pattern to a regex string
    static std::string glob_to_regex(const std::string& glob) {
        std::string regex_str;
        size_t i = 0;
        size_t len = glob.size();

        // If pattern has no /, it can match anywhere in the path
        bool anchored = (glob.find('/') != std::string::npos);
        if (!anchored) {
            regex_str = "(^|.*/)";
        } else {
            regex_str = "^";
        }

        while (i < len) {
            char c = glob[i];
            switch (c) {
            case '*':
                if (i + 1 < len && glob[i + 1] == '*') {
                    // ** matches everything (including /)
                    if (i + 2 < len && glob[i + 2] == '/') {
                        regex_str += "(.*/)?";
                        i += 3;
                    } else {
                        regex_str += ".*";
                        i += 2;
                    }
                } else {
                    // * matches everything except /
                    regex_str += "[^/]*";
                    i++;
                }
                break;
            case '?':
                regex_str += "[^/]";
                i++;
                break;
            case '.': case '+': case '^': case '$':
            case '|': case '(': case ')': case '{':
            case '}': case '[': case ']':
                regex_str += '\\';
                regex_str += c;
                i++;
                break;
            default:
                regex_str += c;
                i++;
                break;
            }
        }

        regex_str += "(/.*)?$";
        return regex_str;
    }

    static bool matches_pattern(const std::string& path, const qre::Regex& pattern) {
        return pattern.match(path);
    }
};
