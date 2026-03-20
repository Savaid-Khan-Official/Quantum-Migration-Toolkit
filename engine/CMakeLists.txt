# ============================================================================
# engine/CMakeLists.txt — libquantum_migrate static library
# ============================================================================
# Builds the core engine as a static library that can be linked by:
#   - cli/main.cpp    (command-line tool)
#   - QuantumSaaS     (server-side SARIF ingestion)
#   - Unit tests
# ============================================================================

include(FetchContent)

# ---- Gather PQC .cpp sources -----------------------------------------------
set(ENGINE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/pqc/QuantumKyber.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/pqc/FileEncryptor.cpp
)

add_library(quantum_migrate STATIC ${ENGINE_SOURCES})

target_include_directories(quantum_migrate PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}          # engine/ (SimpleJson.hpp)
    ${CMAKE_CURRENT_SOURCE_DIR}/scan     # ScanTypes, RuleEngine, etc.
    ${CMAKE_CURRENT_SOURCE_DIR}/pqc      # QuantumKyber, AES, FileEncryptor
    ${CMAKE_CURRENT_SOURCE_DIR}/ai       # AiRemediator, PqcContext
    ${CMAKE_CURRENT_SOURCE_DIR}/patch    # AutoRemediator, DependencyInjector, OutputFormatter
)

target_link_libraries(quantum_migrate PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# ---- liboqs linkage --------------------------------------------------------
if(TARGET oqs)
    target_link_libraries(quantum_migrate PUBLIC oqs)
    target_include_directories(quantum_migrate PUBLIC 
        ${liboqs_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}/_deps/liboqs-build/include
    )
else()
    target_link_libraries(quantum_migrate PUBLIC OQS::oqs)
endif()

# ---- Optional: RE2 ----------------------------------------------------------
if(USE_RE2)
    find_package(re2 QUIET)
    if(re2_FOUND)
        target_link_libraries(quantum_migrate PUBLIC re2::re2)
    else()
        find_library(RE2_LIB re2)
        find_path(RE2_INC re2/re2.h)
        if(RE2_LIB AND RE2_INC)
            target_include_directories(quantum_migrate PUBLIC ${RE2_INC})
            target_link_libraries(quantum_migrate PUBLIC ${RE2_LIB})
        else()
            message(FATAL_ERROR "USE_RE2=ON but re2 not found")
        endif()
    endif()
    target_compile_definitions(quantum_migrate PUBLIC USE_RE2)
endif()

# ---- Optional: Tree-sitter --------------------------------------------------
if(USE_TREESITTER)
    # Core tree-sitter library
    FetchContent_Declare(tree_sitter
        GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter.git
        GIT_TAG        v0.24.6
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(tree_sitter)

    # Build tree-sitter core as a static lib from its C source
    add_library(tree_sitter_core STATIC
        ${tree_sitter_SOURCE_DIR}/lib/src/lib.c
    )
    target_include_directories(tree_sitter_core PUBLIC
        ${tree_sitter_SOURCE_DIR}/lib/include
        ${tree_sitter_SOURCE_DIR}/lib/src
    )

    # Language grammars
    FetchContent_Declare(tree_sitter_c
        GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-c.git
        GIT_TAG        v0.23.5
        GIT_SHALLOW    TRUE
    )
    FetchContent_Declare(tree_sitter_cpp
        GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-cpp.git
        GIT_TAG        v0.23.4
        GIT_SHALLOW    TRUE
    )
    FetchContent_Declare(tree_sitter_python
        GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-python.git
        GIT_TAG        v0.23.6
        GIT_SHALLOW    TRUE
    )
    FetchContent_Declare(tree_sitter_java
        GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-java.git
        GIT_TAG        v0.23.5
        GIT_SHALLOW    TRUE
    )
    FetchContent_Declare(tree_sitter_javascript
        GIT_REPOSITORY https://github.com/tree-sitter/tree-sitter-javascript.git
        GIT_TAG        v0.23.1
        GIT_SHALLOW    TRUE
    )

    FetchContent_MakeAvailable(
        tree_sitter_c tree_sitter_cpp tree_sitter_python
        tree_sitter_java tree_sitter_javascript
    )

    # Build grammar static libs
    foreach(lang c cpp python java javascript)
        set(SRC_DIR ${tree_sitter_${lang}_SOURCE_DIR}/src)
        set(LIB_NAME tree_sitter_${lang}_grammar)
        if(EXISTS ${SRC_DIR}/scanner.c)
            add_library(${LIB_NAME} STATIC ${SRC_DIR}/parser.c ${SRC_DIR}/scanner.c)
        else()
            add_library(${LIB_NAME} STATIC ${SRC_DIR}/parser.c)
        endif()
        target_include_directories(${LIB_NAME} PUBLIC
            ${SRC_DIR}
            ${tree_sitter_SOURCE_DIR}/lib/include
        )
    endforeach()

    target_link_libraries(quantum_migrate PUBLIC
        tree_sitter_core
        tree_sitter_c_grammar
        tree_sitter_cpp_grammar
        tree_sitter_python_grammar
        tree_sitter_java_grammar
        tree_sitter_javascript_grammar
    )
    target_compile_definitions(quantum_migrate PUBLIC USE_TREESITTER)
endif()

# ---- Optional: llama.cpp ----------------------------------------------------
if(USE_LLAMA)
    FetchContent_Declare(llama_cpp
        GIT_REPOSITORY https://github.com/ggml-org/llama.cpp.git
        GIT_TAG        b4858
        GIT_SHALLOW    TRUE
    )
    set(GGML_CUDA    OFF CACHE BOOL "" FORCE)
    set(GGML_METAL   OFF CACHE BOOL "" FORCE)
    set(GGML_VULKAN  OFF CACHE BOOL "" FORCE)
    set(GGML_SYCL    OFF CACHE BOOL "" FORCE)
    set(GGML_AVX2    ON  CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(LLAMA_BUILD_SERVER   OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(llama_cpp)

    target_link_libraries(quantum_migrate PUBLIC llama ggml)
    target_compile_definitions(quantum_migrate PUBLIC USE_LLAMA)
endif()

# ---- Filesystem linkage (GCC < 9) ------------------------------------------
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
    target_link_libraries(quantum_migrate PUBLIC stdc++fs)
endif()
