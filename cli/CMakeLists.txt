# ============================================================================
# cli/CMakeLists.txt — quantum-migrate CLI executable
# ============================================================================
# Thin dispatcher over libquantum_migrate. All logic lives in the engine.
# ============================================================================

add_executable(quantum-migrate main.cpp)
target_link_libraries(quantum-migrate PRIVATE quantum_migrate)

# Install target
install(TARGETS quantum-migrate RUNTIME DESTINATION bin)
install(FILES ${CMAKE_SOURCE_DIR}/engine/rules.json
        DESTINATION share/quantum-migrate)
