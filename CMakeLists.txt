cmake_minimum_required(VERSION 3.10)
project(LSSS_ABE VERSION 2.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CXXFLAGS "-Wall")


# By default, compression is enabled
option(COMPRESSION_ENABLED "Enable compression" ON)

if(COMPRESSION_ENABLED)
    set(_COMPRESSION_ true)
else()
    set(_COMPRESSION_ false)
endif()

# set value of _COMPRESSION_ in CXXFLAGS
set(CMAKE_CXX_FLAGS "${CXXFLAGS} -D_COMPRESSION_=${_COMPRESSION_}")


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

add_library(lsss_abe SHARED ${SOURCE_FILES})
target_link_libraries(lsss_abe ${LIBRARIES})
target_include_directories(lsss_abe PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION /usr/local/include/lsss_abe)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/utils/common.h DESTINATION /usr/local/include/lsss_abe)
install(TARGETS lsss_abe DESTINATION /usr/local/lib)

# During the install phase, this code will replace the include path in zabe.h
# from "../../utils/common.h" to "../common.h"
install(CODE "
    file(READ /usr/local/include/lsss_abe/abe/zabe.h CONTENT)
    string(REPLACE \"#include \\\"../../utils/common.h\\\"\" \"#include \\\"../common.h\\\"\" MODIFIED_CONTENT \"\${CONTENT}\")
    file(WRITE /usr/local/include/lsss_abe/abe/zabe.h \"\${MODIFIED_CONTENT}\")
")

enable_testing()
add_subdirectory(tests)

add_subdirectory(abe)
