#pragma once
// ============================================================================
// SimpleJson.hpp - Lightweight JSON parser & serializer for C++17
// Supports: objects, arrays, strings, numbers, booleans, null
// Used by: RuleEngine, BaselineManager, OutputFormatter (SARIF)
// ============================================================================

#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <sstream>
#include <fstream>
#include <cctype>
#include <cmath>
#include <algorithm>

namespace json {

enum class Type { Null, Bool, Number, String, Array, Object };

class Value {
public:
    Type type = Type::Null;

    Value() = default;

    // ---- Factory methods ----
    static Value null_val() { return Value(); }

    static Value boolean(bool b) {
        Value v; v.type = Type::Bool; v.bool_val_ = b; return v;
    }
    static Value number(double n) {
        Value v; v.type = Type::Number; v.num_val_ = n; return v;
    }
    static Value string_val(const std::string& s) {
        Value v; v.type = Type::String; v.str_val_ = s; return v;
    }
    static Value array() { Value v; v.type = Type::Array; return v; }
    static Value object() { Value v; v.type = Type::Object; return v; }

    // ---- Type checking ----
    bool is_null()   const { return type == Type::Null; }
    bool is_bool()   const { return type == Type::Bool; }
    bool is_number() const { return type == Type::Number; }
    bool is_string() const { return type == Type::String; }
    bool is_array()  const { return type == Type::Array; }
    bool is_object() const { return type == Type::Object; }

    // ---- Accessors ----
    bool as_bool() const {
        if (type != Type::Bool) throw std::runtime_error("JSON value is not a boolean");
        return bool_val_;
    }
    double as_number() const {
        if (type != Type::Number) throw std::runtime_error("JSON value is not a number");
        return num_val_;
    }
    int as_int() const { return static_cast<int>(as_number()); }

    const std::string& as_string() const {
        if (type != Type::String) throw std::runtime_error("JSON value is not a string");
        return str_val_;
    }
    // Return empty string instead of throwing when used for optional fields
    std::string as_string_or(const std::string& fallback) const {
        return (type == Type::String) ? str_val_ : fallback;
    }
    double as_number_or(double fallback) const {
        return (type == Type::Number) ? num_val_ : fallback;
    }
    bool as_bool_or(bool fallback) const {
        return (type == Type::Bool) ? bool_val_ : fallback;
    }

    const std::vector<Value>& as_array() const {
        if (type != Type::Array) throw std::runtime_error("JSON value is not an array");
        return arr_val_;
    }
    const std::map<std::string, Value>& as_object() const {
        if (type != Type::Object) throw std::runtime_error("JSON value is not an object");
        return obj_val_;
    }

    // ---- Convenience operators ----
    const Value& operator[](const std::string& key) const {
        static Value null_v;
        if (type != Type::Object) return null_v;
        auto it = obj_val_.find(key);
        return (it != obj_val_.end()) ? it->second : null_v;
    }
    const Value& operator[](size_t index) const {
        if (type != Type::Array || index >= arr_val_.size())
            throw std::runtime_error("JSON array index out of bounds");
        return arr_val_[index];
    }
    bool has(const std::string& key) const {
        return type == Type::Object && obj_val_.find(key) != obj_val_.end();
    }
    size_t size() const {
        if (type == Type::Array) return arr_val_.size();
        if (type == Type::Object) return obj_val_.size();
        return 0;
    }

    // ---- Mutation (for building JSON) ----
    void push_back(const Value& v) {
        if (type != Type::Array) throw std::runtime_error("Cannot push_back on non-array");
        arr_val_.push_back(v);
    }
    void set(const std::string& key, const Value& v) {
        if (type != Type::Object) throw std::runtime_error("Cannot set on non-object");
        obj_val_[key] = v;
    }

    // ---- Serialization ----
    std::string serialize(int indent = 2, int depth = 0) const {
        std::string pad(depth * indent, ' ');
        std::string inner((depth + 1) * indent, ' ');

        switch (type) {
        case Type::Null: return "null";
        case Type::Bool: return bool_val_ ? "true" : "false";
        case Type::Number: {
            if (num_val_ == std::floor(num_val_) && std::abs(num_val_) < 1e15) {
                return std::to_string(static_cast<long long>(num_val_));
            }
            std::ostringstream oss;
            oss << num_val_;
            return oss.str();
        }
        case Type::String: return escape_str(str_val_);
        case Type::Array: {
            if (arr_val_.empty()) return "[]";
            std::string r = "[\n";
            for (size_t i = 0; i < arr_val_.size(); i++) {
                r += inner + arr_val_[i].serialize(indent, depth + 1);
                if (i + 1 < arr_val_.size()) r += ",";
                r += "\n";
            }
            r += pad + "]";
            return r;
        }
        case Type::Object: {
            if (obj_val_.empty()) return "{}";
            std::string r = "{\n";
            size_t i = 0;
            for (const auto& [k, v] : obj_val_) {
                r += inner + escape_str(k) + ": " + v.serialize(indent, depth + 1);
                if (++i < obj_val_.size()) r += ",";
                r += "\n";
            }
            r += pad + "}";
            return r;
        }
        }
        return "null";
    }

    // ---- Parsing ----
    static constexpr int MAX_NESTING_DEPTH = 100;

    static Value parse(const std::string& json_text) {
        size_t pos = 0;
        Value result = parse_value(json_text, pos, 0);
        skip_ws(json_text, pos);
        return result;
    }

    static Value from_file(const std::string& path) {
        std::ifstream file(path);
        if (!file) throw std::runtime_error("Cannot open JSON file: " + path);
        std::string content((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
        return parse(content);
    }

    void to_file(const std::string& path, int indent = 2) const {
        std::ofstream file(path);
        if (!file) throw std::runtime_error("Cannot write JSON file: " + path);
        file << serialize(indent);
    }

private:
    bool bool_val_ = false;
    double num_val_ = 0.0;
    std::string str_val_;
    std::vector<Value> arr_val_;
    std::map<std::string, Value> obj_val_;

    // ---- Helpers ----
    static std::string escape_str(const std::string& s) {
        std::string r = "\"";
        for (char c : s) {
            switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\b': r += "\\b";  break;
            case '\f': r += "\\f";  break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            default:   r += c;      break;
            }
        }
        r += "\"";
        return r;
    }

    static void skip_ws(const std::string& s, size_t& pos) {
        while (pos < s.size() && std::isspace(static_cast<unsigned char>(s[pos]))) pos++;
    }

    static Value parse_value(const std::string& s, size_t& pos, int depth) {
        if (depth > MAX_NESTING_DEPTH) {
            throw std::runtime_error(
                "JSON nesting too deep (max " + std::to_string(MAX_NESTING_DEPTH) +
                ") — possible DoS or malformed input");
        }
        skip_ws(s, pos);
        if (pos >= s.size()) throw std::runtime_error("Unexpected end of JSON");

        char c = s[pos];
        if (c == '"') return parse_string_val(s, pos);
        if (c == '{') return parse_object_val(s, pos, depth + 1);
        if (c == '[') return parse_array_val(s, pos, depth + 1);
        if (c == 't' || c == 'f') return parse_bool_val(s, pos);
        if (c == 'n') return parse_null_val(s, pos);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c)))
            return parse_number_val(s, pos);

        throw std::runtime_error(std::string("Unexpected character in JSON: ") + c);
    }

    static std::string parse_raw_string(const std::string& s, size_t& pos) {
        if (pos >= s.size() || s[pos] != '"')
            throw std::runtime_error("Expected '\"' at position " + std::to_string(pos));
        pos++;  // skip opening "
        std::string result;
        while (pos < s.size() && s[pos] != '"') {
            if (s[pos] == '\\') {
                pos++;
                if (pos >= s.size()) throw std::runtime_error("Unterminated string escape");
                switch (s[pos]) {
                case '"':  result += '"';  break;
                case '\\': result += '\\'; break;
                case '/':  result += '/';  break;
                case 'b':  result += '\b'; break;
                case 'f':  result += '\f'; break;
                case 'n':  result += '\n'; break;
                case 'r':  result += '\r'; break;
                case 't':  result += '\t'; break;
                case 'u': {
                    // Basic \uXXXX support (ASCII range only for simplicity)
                    if (pos + 4 >= s.size()) throw std::runtime_error("Invalid \\u escape");
                    std::string hex = s.substr(pos + 1, 4);
                    unsigned long cp = std::stoul(hex, nullptr, 16);
                    if (cp < 128) result += static_cast<char>(cp);
                    else result += '?';  // non-ASCII placeholder
                    pos += 4;
                    break;
                }
                default: result += '\\'; result += s[pos]; break;
                }
            } else {
                result += s[pos];
            }
            pos++;
        }
        if (pos >= s.size()) throw std::runtime_error("Unterminated string");
        pos++;  // skip closing "
        return result;
    }

    static Value parse_string_val(const std::string& s, size_t& pos) {
        Value v;
        v.type = Type::String;
        v.str_val_ = parse_raw_string(s, pos);
        return v;
    }

    static Value parse_number_val(const std::string& s, size_t& pos) {
        size_t start = pos;
        if (s[pos] == '-') pos++;
        while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) pos++;
        if (pos < s.size() && s[pos] == '.') {
            pos++;
            while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) pos++;
        }
        if (pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
            pos++;
            if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) pos++;
            while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) pos++;
        }
        Value v;
        v.type = Type::Number;
        v.num_val_ = std::stod(s.substr(start, pos - start));
        return v;
    }

    static Value parse_bool_val(const std::string& s, size_t& pos) {
        if (s.compare(pos, 4, "true") == 0) {
            pos += 4;
            Value v; v.type = Type::Bool; v.bool_val_ = true; return v;
        }
        if (s.compare(pos, 5, "false") == 0) {
            pos += 5;
            Value v; v.type = Type::Bool; v.bool_val_ = false; return v;
        }
        throw std::runtime_error("Invalid boolean at position " + std::to_string(pos));
    }

    static Value parse_null_val(const std::string& s, size_t& pos) {
        if (s.compare(pos, 4, "null") == 0) {
            pos += 4;
            return Value();
        }
        throw std::runtime_error("Invalid null at position " + std::to_string(pos));
    }

    static Value parse_array_val(const std::string& s, size_t& pos, int depth) {
        pos++;  // skip [
        Value v;
        v.type = Type::Array;
        skip_ws(s, pos);
        if (pos < s.size() && s[pos] == ']') { pos++; return v; }
        while (true) {
            v.arr_val_.push_back(parse_value(s, pos, depth));
            skip_ws(s, pos);
            if (pos >= s.size()) throw std::runtime_error("Unterminated JSON array");
            if (s[pos] == ']') { pos++; return v; }
            if (s[pos] != ',') throw std::runtime_error("Expected ',' in array");
            pos++;
        }
    }

    static Value parse_object_val(const std::string& s, size_t& pos, int depth) {
        pos++;  // skip {
        Value v;
        v.type = Type::Object;
        skip_ws(s, pos);
        if (pos < s.size() && s[pos] == '}') { pos++; return v; }
        while (true) {
            skip_ws(s, pos);
            std::string key = parse_raw_string(s, pos);
            skip_ws(s, pos);
            if (pos >= s.size() || s[pos] != ':')
                throw std::runtime_error("Expected ':' after key \"" + key + "\"");
            pos++;
            v.obj_val_[key] = parse_value(s, pos, depth);
            skip_ws(s, pos);
            if (pos >= s.size()) throw std::runtime_error("Unterminated JSON object");
            if (s[pos] == '}') { pos++; return v; }
            if (s[pos] != ',') throw std::runtime_error("Expected ',' in object");
            pos++;
        }
    }
};

}  // namespace json

// ============================================================================
// simple_json::JsonWriter — Streaming JSON writer used by DependencyInjector
// ============================================================================
namespace simple_json {

class JsonWriter {
public:
    JsonWriter() = default;

    void start_object() {
        maybe_comma();
        buf_ += "{";
        first_.push_back(true);
    }
    void end_object() {
        buf_ += "}";
        first_.pop_back();
    }
    void start_array() {
        maybe_comma();
        buf_ += "[";
        first_.push_back(true);
    }
    void end_array() {
        buf_ += "]";
        first_.pop_back();
    }
    void key(const std::string& k) {
        maybe_comma();
        buf_ += escape(k) + ":";
        suppress_comma_ = true;
    }
    void value(const std::string& v) {
        maybe_comma();
        buf_ += escape(v);
    }
    void value(double v) {
        maybe_comma();
        std::ostringstream oss;
        oss << v;
        buf_ += oss.str();
    }
    void value(bool v) {
        maybe_comma();
        buf_ += v ? "true" : "false";
    }
    void null_value() {
        maybe_comma();
        buf_ += "null";
    }

    std::string str() const { return buf_; }

private:
    std::string buf_;
    std::vector<bool> first_;   // stack: true = first element at this level
    bool suppress_comma_ = false;

    void maybe_comma() {
        if (suppress_comma_) { suppress_comma_ = false; return; }
        if (!first_.empty()) {
            if (first_.back()) first_.back() = false;
            else buf_ += ",";
        }
    }

    static std::string escape(const std::string& s) {
        std::string r = "\"";
        for (char c : s) {
            switch (c) {
            case '"':  r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n";  break;
            case '\r': r += "\\r";  break;
            case '\t': r += "\\t";  break;
            default:   r += c;      break;
            }
        }
        return r + "\"";
    }
};

}  // namespace simple_json
