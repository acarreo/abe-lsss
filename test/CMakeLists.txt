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

target_link_libraries(main_out OpenSSL::SSL lsss_abe relic gmp)
