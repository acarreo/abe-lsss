cmake_minimum_required(VERSION 3.10)
project(TEST)

set(CMAKE_C_COMPILER cc)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 20)
set(CXXFLAGS "-Wall")

find_package(OpenSSL REQUIRED)

add_executable(
    main_out
    main.cpp
)

add_executable(
    test_ske_out
    test_ske.cpp
)

add_executable(
    test_zsym_out
    test_zsym.cpp
)

target_link_libraries(main_out OpenSSL::SSL lsss_abe relic gmp)

target_link_libraries(test_ske_out gtest pthread OpenSSL::SSL lsss_abe relic gmp)
target_link_libraries(test_zsym_out gtest pthread OpenSSL::SSL lsss_abe relic gmp)

# Add make test
enable_testing()
add_test(NAME test_ske COMMAND test_ske_out)
add_test(NAME test_zsym COMMAND test_zsym_out)


# Add make run
add_custom_target(run
    COMMAND test_ske_out
    COMMAND test_zsym_out
    WORKING_DIRECTORY ${CMAKE_PROJECT_DIR}
)