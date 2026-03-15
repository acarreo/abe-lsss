include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(LIBRARIES
    ${ABE_LSSS_LIB}
    OpenSSL::SSL
    RELIC::relic
    gmp
    GTest::gtest_main
    pthread
)

include(GoogleTest)
macro (test TEST_NAME TEST_FILE EXTRA_SOURCES)
    add_executable(${TEST_NAME} ${TEST_FILE} ${EXTRA_SOURCES})
    target_link_libraries(${TEST_NAME} ${LIBRARIES})
    target_include_directories(${TEST_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    # add_custom_target(${CUSTOM_TARGET_NAME} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME})
endmacro()

set(ABE_SOURCES
  ../schemes/zcontextcpwaters.cpp
  ../schemes/zcontextkpgpsw.cpp
  ../utils/abecontext.cpp
)

test(test_demo test_demo.cpp "${ABE_SOURCES}")
test(test_keystore test_keystore.cpp "${ABE_SOURCES}")
test(test_abe test_abe.cpp "${ABE_SOURCES}")
test(test_ske test_ske.cpp "")
test(test_zsym test_zsym.cpp "")
test(test_bytestring test_bytestring.cpp "")

