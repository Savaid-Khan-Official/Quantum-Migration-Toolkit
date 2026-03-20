# ============================================================================
# CMakeLists.txt — Quantum Migration Toolkit v2.0 (Root)
# ============================================================================
# Unified build: Scanner detection + PQC crypto + AI remediation + vendoring
#
# Quick start:
#   mkdir build && cd build
#   cmake .. -DCMAKE_BUILD_TYPE=Release
#   cmake --build . --parallel
#
# Full features:
#   cmake .. -DUSE_TREESITTER=ON -DUSE_LLAMA=ON -DUSE_RE2=ON
#
# Dependencies:
#   Required : OpenSSL, liboqs (fetched automatically if not found)
#   Optional : RE2, tree-sitter (FetchContent), llama.cpp (FetchContent)
# ============================================================================

cmake_minimum_required(VERSION 3.18)
project(QuantumMigrationToolkit VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---- Feature toggles -------------------------------------------------------
option(USE_RE2         "Use Google RE2 regex engine (O(n) guarantee)"   OFF)
option(USE_TREESITTER  "Use tree-sitter AST validation engine"          OFF)
option(USE_LLAMA       "Use llama.cpp for AI-driven PQC remediation"    OFF)

# ---- Core dependencies (always required) ------------------------------------
find_package(OpenSSL)
find_package(Threads REQUIRED)

# ---- liboqs: try system install, fall back to FetchContent ------------------
find_package(liboqs QUIET)
if(NOT liboqs_FOUND)
    message(STATUS "[QMT] liboqs not found — fetching via FetchContent...")
    include(FetchContent)
    FetchContent_Declare(liboqs
        GIT_REPOSITORY https://github.com/open-quantum-safe/liboqs.git
        GIT_TAG        0.12.0
        GIT_SHALLOW    TRUE
    )
    set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "" FORCE)
    set(OQS_MINIMAL_BUILD  "" CACHE STRING "" FORCE)
    FetchContent_MakeAvailable(liboqs)
endif()

# ---- Subdirectories ---------------------------------------------------------
add_subdirectory(engine)
add_subdirectory(cli)

message(STATUS "")
message(STATUS "========================================")
message(STATUS " Quantum Migration Toolkit v${PROJECT_VERSION}")
message(STATUS "   RE2         : ${USE_RE2}")
message(STATUS "   Tree-sitter : ${USE_TREESITTER}")
message(STATUS "   llama.cpp   : ${USE_LLAMA}")
message(STATUS "========================================")
message(STATUS "")
