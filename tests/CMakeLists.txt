include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

macro (test TEST_NAME TEST_FILE EXTRA_SOURCES)
    add_executable(${TEST_NAME} ${TEST_FILE} ${EXTRA_SOURCES})
		target_link_libraries(${TEST_NAME} PRIVATE ${ABE_LSSS_LIB} GTest::gtest_main pthread)
    target_include_directories(${TEST_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endmacro()

set(ABE_SOURCES
  ../schemes/zcontextcpwaters.cpp
  ../schemes/zcontextkpgpsw.cpp
  ../schemes/abecontext.cpp
)

test(test_demo test_demo.cpp "${ABE_SOURCES}")
test(test_keystore test_keystore.cpp "${ABE_SOURCES}")
test(test_abe test_abe.cpp "${ABE_SOURCES}")
test(test_policy test_policy.cpp "")
test(test_ske test_ske.cpp "")
test(test_zsym test_zsym.cpp "")
test(test_bytestring test_bytestring.cpp "")

