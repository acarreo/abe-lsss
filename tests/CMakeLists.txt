include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

set(LIBRARIES
    ${LIBRARY_NAME}
    OpenSSL::SSL
    ${RLC_LIBRARY} gmp
    GTest::gtest_main pthread
)

set(ABE_SOURCES
  ../schemes/zcontextcpwaters.cpp
  ../schemes/zcontextkpgpsw.cpp
  ../utils/abecontext.cpp
)

add_executable(test_ske_out test_ske.cpp)
add_executable(test_zsym_out test_zsym.cpp)

add_executable(
  test_keystore_out
  ${ABE_SOURCES}
  test_keystore.cpp
)
add_executable(
  test_abe_out
  ${ABE_SOURCES}
  test_abe.cpp
)

target_link_libraries(test_ske_out ${LIBRARIES})
target_link_libraries(test_zsym_out ${LIBRARIES})
target_link_libraries(test_abe_out ${LIBRARIES})
target_link_libraries(test_keystore_out ${LIBRARIES})

target_include_directories(test_ske_out PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(test_zsym_out PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(test_abe_out PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(test_keystore_out PRIVATE ${PROJECT_SOURCE_DIR}/include)

include(GoogleTest)
add_test(NAME test_ske COMMAND test_ske_out)
add_test(NAME test_zsym COMMAND test_zsym_out)
add_test(NAME test_keystore COMMAND test_keystore_out)
add_test(NAME test_abe COMMAND test_abe_out)
