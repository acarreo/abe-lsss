cmake_minimum_required(VERSION 3.10)
project(LSSS_ABE)

set(CMAKE_C_COMPILER cc)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 20)
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

file(GLOB ABE_SOURCES src/abe/*.cpp)
file(GLOB LSSS_SOURCES src/lsss/*.cpp)

set(SOURCE_FILES
    ${ABE_SOURCES}
    ${LSSS_SOURCES}
    src/lsss/zparser.tab.cc
)

find_package(OpenSSL REQUIRED)
find_package(relic REQUIRED)

add_library(lsss_abe SHARED ${SOURCE_FILES})
target_link_libraries(lsss_abe OpenSSL::SSL relic gmp)
target_include_directories(lsss_abe PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION /usr/local/include/lsss_abe)
install(TARGETS lsss_abe DESTINATION /usr/local/lib)
