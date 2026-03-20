#pragma once
// ============================================================================
// RegexEngine.hpp - Production regex abstraction layer
// ============================================================================
// Provides a unified regex API that uses Google RE2 when available (via
// CMake -DUSE_RE2=ON) and falls back to std::regex otherwise.
//
// Why RE2 over std::regex?
//   - RE2 guarantees O(n) matching (no catastrophic backtracking / ReDoS)
//   - RE2 is 5-50x faster for typical patterns on large inputs
//   - std::regex in libstdc++ is notoriously slow and has known bugs
//
// NOTE on replacement syntax:
//   - std::regex (ECMAScript): uses $1, $2, ... for capture groups
//   - RE2:                     uses \1, \2, ... for capture groups
//   Current rules.json fix patterns do NOT use backreferences, so this
//   difference has no impact. If future rules need backrefs, add a
//   syntax translator in Regex::replace().
// ============================================================================

#include <string>
#include <memory>
#include <stdexcept>

#ifdef USE_RE2
#include <re2/re2.h>
#else
#include <regex>
#endif

namespace qre {

// ---- Regex: compiled pattern wrapper ----
class Regex {
public:
    Regex() = default;

    /// Compile a regex pattern.
    /// @param pattern   Regular expression string
    /// @param icase     If true, match case-insensitively
    explicit Regex(const std::string& pattern, bool icase = false)
        : pattern_str_(pattern), valid_(true)
    {
#ifdef USE_RE2
        re2::RE2::Options opts;
        opts.set_case_sensitive(!icase);
        opts.set_log_errors(false);  // Don't spam stderr
        re2_ = std::make_shared<re2::RE2>(pattern, opts);
        if (!re2_->ok()) {
            valid_ = false;
            throw std::runtime_error("RE2 compile error for pattern '" +
                                     pattern + "': " + re2_->error());
        }
#else
        try {
            auto flags = std::regex_constants::ECMAScript;
            if (icase) flags |= std::regex_constants::icase;
            std_regex_ = std::regex(pattern, flags);
        } catch (const std::regex_error& e) {
            valid_ = false;
            throw std::runtime_error("Regex compile error for pattern '" +
                                     pattern + "': " + e.what());
        }
#endif
    }

    /// Partial match: does the pattern appear anywhere in text?
    bool search(const std::string& text) const {
        if (!valid_) return false;
#ifdef USE_RE2
        return re2::RE2::PartialMatch(text, *re2_);
#else
        return std::regex_search(text, std_regex_);
#endif
    }

    /// Full match: does the pattern match the entire text?
    bool match(const std::string& text) const {
        if (!valid_) return false;
#ifdef USE_RE2
        return re2::RE2::FullMatch(text, *re2_);
#else
        return std::regex_match(text, std_regex_);
#endif
    }

    /// Replace all occurrences in text with replacement string.
    /// NOTE: backreference syntax differs between RE2 (\1) and std::regex ($1).
    std::string replace(const std::string& text, const std::string& rewrite) const {
        if (!valid_) return text;
#ifdef USE_RE2
        std::string result = text;
        RE2::GlobalReplace(&result, *re2_, rewrite);
        return result;
#else
        return std::regex_replace(text, std_regex_, rewrite);
#endif
    }

    bool valid() const { return valid_; }
    const std::string& pattern() const { return pattern_str_; }

private:
    std::string pattern_str_;
    bool valid_ = false;

#ifdef USE_RE2
    std::shared_ptr<re2::RE2> re2_;
#else
    std::regex std_regex_;
#endif
};

}  // namespace qre
