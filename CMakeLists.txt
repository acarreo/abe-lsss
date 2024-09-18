cmake_minimum_required(VERSION 3.10)
project(LSSS_ABE VERSION 2.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CXXFLAGS "-Wall")


# By default, compression is enabled
option(COMPRESSION_ENABLED "Enable compression" ON)

if(COMPRESSION_ENABLED STREQUAL "ON")
    message(STATUS "Compression enabled")
    set(_COMPRESSION_ true)
    set(LIBRARY_NAME "lsss_abe_compression")
elseif(COMPRESSION_ENABLED STREQUAL "OFF")
    message(STATUS "Compression disabled")
    set(_COMPRESSION_ false)
    set(LIBRARY_NAME "lsss_abe_no_compression")
else()
    message(FATAL_ERROR "Invalid value for COMPRESSION_ENABLED. Please use ON or OFF")
endif()

# set value of _COMPRESSION_ in CXXFLAGS
set(CMAKE_CXX_FLAGS "${CXXFLAGS} -D_COMPRESSION_=${_COMPRESSION_}")

option(BUILD_TESTS "Build the tests" OFF)

find_package(OpenSSL REQUIRED)
find_library(RLC_LIBRARY NAMES relic)

set(LIBRARIES
    OpenSSL::SSL ${RLC_LIBRARY} gmp
)

file(GLOB ABE_SOURCES src/abe/*.cpp)
file(GLOB LSSS_SOURCES src/lsss/*.cpp)

set(SOURCE_FILES
    ${ABE_SOURCES}
    ${LSSS_SOURCES}
    src/lsss/zparser.tab.cc
    utils/utils.cpp
)

add_library(${LIBRARY_NAME} SHARED ${SOURCE_FILES})
target_link_libraries(${LIBRARY_NAME} ${LIBRARIES})
target_include_directories(${LIBRARY_NAME} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION /usr/local/include/lsss_abe)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/utils/common.h DESTINATION /usr/local/include/lsss_abe)

# Install the shared library with the custom name
install(TARGETS ${LIBRARY_NAME} DESTINATION /usr/local/lib)

# During the install phase, this code will replace the include path in zabe.h
# from "../../utils/common.h" to "../common.h"
install(CODE "
    file(READ /usr/local/include/lsss_abe/abe/zabe.h CONTENT)
    string(REPLACE \"#include \\\"../../utils/common.h\\\"\" \"#include \\\"../common.h\\\"\" MODIFIED_CONTENT \"\${CONTENT}\")
    file(WRITE /usr/local/include/lsss_abe/abe/zabe.h \"\${MODIFIED_CONTENT}\")
")

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
