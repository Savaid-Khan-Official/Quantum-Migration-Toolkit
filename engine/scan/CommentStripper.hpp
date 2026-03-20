#pragma once
// ============================================================================
// CommentStripper.hpp - Context-aware comment and string literal removal
// ============================================================================
// Implements a state machine that strips comments and string literals from
// source code before vulnerability scanning, eliminating false positives.
//
// Supported languages:
//   C/C++/Java/JS/TS: // line comments, /* block comments */, "strings", 'chars'
//   Python:           # line comments, """triple strings""", '''triple strings'''
// ============================================================================

#include <string>
#include <algorithm>

// Tracks multi-line state across lines (block comments, triple-quoted strings)
struct StripState {
    bool in_block_comment = false;     // Inside /* ... */
    bool in_triple_double = false;     // Inside """ ... """
    bool in_triple_single = false;     // Inside ''' ... '''
};

class CommentStripper {
public:
    // Returns a copy of the line with comments and string literals replaced
    // by spaces (preserving line length and column positions).
    static std::string strip_line(const std::string& line,
                                  const std::string& extension,
                                  StripState& state) {
        bool is_python = (extension == ".py" || extension == ".rb");
        bool is_c_family = (extension == ".cpp" || extension == ".c" ||
                            extension == ".h"   || extension == ".hpp" ||
                            extension == ".java" || extension == ".js" ||
                            extension == ".jsx"  || extension == ".ts" ||
                            extension == ".tsx"  || extension == ".go" ||
                            extension == ".rs"   || extension == ".swift" ||
                            extension == ".kt"   || extension == ".kts" ||
                            extension == ".scala" || extension == ".cs");

        std::string result = line;
        size_t len = line.size();
        size_t i = 0;

        // ---- Continue multi-line states from previous lines ----
        if (state.in_block_comment) {
            while (i < len) {
                if (i + 1 < len && line[i] == '*' && line[i + 1] == '/') {
                    result[i] = ' '; result[i + 1] = ' ';
                    state.in_block_comment = false;
                    i += 2;
                    break;
                }
                result[i] = ' ';
                i++;
            }
            if (state.in_block_comment) {
                // Entire line is inside block comment
                return std::string(len, ' ');
            }
        }

        if (state.in_triple_double) {
            while (i < len) {
                if (i + 2 < len && line[i] == '"' && line[i+1] == '"' && line[i+2] == '"') {
                    result[i] = ' '; result[i+1] = ' '; result[i+2] = ' ';
                    state.in_triple_double = false;
                    i += 3;
                    break;
                }
                result[i] = ' ';
                i++;
            }
            if (state.in_triple_double) return std::string(len, ' ');
        }

        if (state.in_triple_single) {
            while (i < len) {
                if (i + 2 < len && line[i] == '\'' && line[i+1] == '\'' && line[i+2] == '\'') {
                    result[i] = ' '; result[i+1] = ' '; result[i+2] = ' ';
                    state.in_triple_single = false;
                    i += 3;
                    break;
                }
                result[i] = ' ';
                i++;
            }
            if (state.in_triple_single) return std::string(len, ' ');
        }

        // ---- Process remaining characters ----
        while (i < len) {
            char c = line[i];

            // C-family block comments: /* ... */
            if (is_c_family && i + 1 < len && c == '/' && line[i + 1] == '*') {
                result[i] = ' '; result[i + 1] = ' ';
                i += 2;
                while (i < len) {
                    if (i + 1 < len && line[i] == '*' && line[i + 1] == '/') {
                        result[i] = ' '; result[i + 1] = ' ';
                        i += 2;
                        break;
                    }
                    result[i] = ' ';
                    i++;
                }
                if (i >= len && !(i >= 2 && line[i-2] == '*' && line[i-1] == '/')) {
                    state.in_block_comment = true;
                }
                continue;
            }

            // C-family line comments: // ...
            if (is_c_family && i + 1 < len && c == '/' && line[i + 1] == '/') {
                for (size_t j = i; j < len; j++) result[j] = ' ';
                break;
            }

            // Python line comments: # ...
            if (is_python && c == '#') {
                for (size_t j = i; j < len; j++) result[j] = ' ';
                break;
            }

            // Python triple-quoted strings: """ or '''
            if (is_python && i + 2 < len) {
                if (c == '"' && line[i+1] == '"' && line[i+2] == '"') {
                    result[i] = ' '; result[i+1] = ' '; result[i+2] = ' ';
                    i += 3;
                    while (i < len) {
                        if (i + 2 < len && line[i] == '"' && line[i+1] == '"' && line[i+2] == '"') {
                            result[i] = ' '; result[i+1] = ' '; result[i+2] = ' ';
                            i += 3;
                            break;
                        }
                        result[i] = ' ';
                        i++;
                    }
                    if (i >= len) state.in_triple_double = true;
                    continue;
                }
                if (c == '\'' && line[i+1] == '\'' && line[i+2] == '\'') {
                    result[i] = ' '; result[i+1] = ' '; result[i+2] = ' ';
                    i += 3;
                    while (i < len) {
                        if (i + 2 < len && line[i] == '\'' && line[i+1] == '\'' && line[i+2] == '\'') {
                            result[i] = ' '; result[i+1] = ' '; result[i+2] = ' ';
                            i += 3;
                            break;
                        }
                        result[i] = ' ';
                        i++;
                    }
                    if (i >= len) state.in_triple_single = true;
                    continue;
                }
            }

            // String literals: "..." (with escape handling)
            if (c == '"') {
                result[i] = ' ';
                i++;
                while (i < len && line[i] != '"') {
                    if (line[i] == '\\' && i + 1 < len) {
                        result[i] = ' '; i++;
                    }
                    result[i] = ' ';
                    i++;
                }
                if (i < len) { result[i] = ' '; i++; }
                continue;
            }

            // Character/string literals: '...' (C-family: single char, Python: string)
            if (c == '\'') {
                result[i] = ' ';
                i++;
                while (i < len && line[i] != '\'') {
                    if (line[i] == '\\' && i + 1 < len) {
                        result[i] = ' '; i++;
                    }
                    result[i] = ' ';
                    i++;
                }
                if (i < len) { result[i] = ' '; i++; }
                continue;
            }

            // Normal code character - leave as-is
            i++;
        }

        return result;
    }
};
