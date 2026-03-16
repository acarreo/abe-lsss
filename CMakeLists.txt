cmake_minimum_required(VERSION 3.10)
project(ABE_LSSS VERSION 2.1 LANGUAGES C CXX)

# ------------------------------------------------------------------------------
# Options et standards
# ------------------------------------------------------------------------------
set(ABE_LSSS_LIB "abe_lsss")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-Wall")

set(RELIC_CURVE "bls12-381" CACHE STRING "Courbe RELIC à compiler (ex: bls12-381, bn254, etc)")

# ------------------------------------------------------------------------------
# Dépendances système
# ------------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_library(GMP_LIBRARY gmp REQUIRED)
find_library(RLC_LIBRARY NAMES relic)

# TODO: Gérer le cas de la bibliothèque statique
# find_library(RLC_LIBRARY NAMES relic relic_s)

# ------------------------------------------------------------------------------
# RELIC: si pas trouvé, build automatique
# ------------------------------------------------------------------------------
if(NOT RLC_LIBRARY)
    include(ExternalProject)

    set(RELIC_SRC_DIR ${CMAKE_BINARY_DIR}/relic-src)
    set(RELIC_BUILD_DIR ${CMAKE_BINARY_DIR}/relic-build)

    file(MAKE_DIRECTORY ${RELIC_SRC_DIR})
    file(MAKE_DIRECTORY ${RELIC_BUILD_DIR})

    ExternalProject_Add(
        relic_project
        GIT_REPOSITORY https://github.com/relic-toolkit/relic.git
        GIT_TAG 0.6.0

        PREFIX ${CMAKE_BINARY_DIR}/relic
        SOURCE_DIR ${RELIC_SRC_DIR}
        BINARY_DIR ${RELIC_BUILD_DIR}

        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E echo "Running RELIC preset..."
        BUILD_COMMAND
            ${RELIC_SRC_DIR}/preset/x64-pbc-${RELIC_CURVE}.sh "-DSHLIB=ON -DSTBIN=OFF -DTESTS=OFF -DBENCH=OFF ${RELIC_SRC_DIR}"
            && ${CMAKE_MAKE_PROGRAM} -C ${RELIC_BUILD_DIR} -j

        INSTALL_COMMAND ""
    )

    # Déclare la librairie importée
    add_library(RELIC::relic SHARED IMPORTED GLOBAL)
    set_target_properties(RELIC::relic PROPERTIES
        IMPORTED_LOCATION ${RELIC_BUILD_DIR}/lib/librelic.so
    )
    add_dependencies(RELIC::relic relic_project)

else()
    # RELIC système trouvé
    # NOTE: Pour l'instant, je suppose que la lib trouvée est dynamique.
    # TODO: Gérer proporement cela
    add_library(RELIC::relic SHARED IMPORTED GLOBAL)

    set_target_properties(RELIC::relic PROPERTIES
        IMPORTED_LOCATION ${RLC_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES "/usr/local/include/relic"
    )
endif()


# ------------------------------------------------------------------------------
# Librairies à linker
# ------------------------------------------------------------------------------
set(LIBRARIES
    OpenSSL::SSL
    RELIC::relic
    gmp
)

# ------------------------------------------------------------------------------
# Sources ABE_LSSS
# ------------------------------------------------------------------------------
file(GLOB ABE_SOURCES src/abe/*.cpp)
file(GLOB LSSS_SOURCES src/lsss/*.cpp)

set(SOURCE_FILES
    ${ABE_SOURCES}
    ${LSSS_SOURCES}
    src/lsss/zparser.tab.cc
    utils/utils.cpp
)

# Crée la target avant d'ajouter les includes
add_library(${ABE_LSSS_LIB} SHARED ${SOURCE_FILES})

# Ajoute les include dirs du projet
target_include_directories(${ABE_LSSS_LIB} PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
		"${CMAKE_CURRENT_SOURCE_DIR}/utils"
)

# Ajouter les includes dirs de RELIC
if(NOT RLC_LIBRARY)
    target_include_directories(${ABE_LSSS_LIB} PUBLIC
        "${RELIC_SRC_DIR}/include"
        "${RELIC_BUILD_DIR}/include"
    )
    # Assure que RELIC est compilé avant ABE_LSSS
    add_dependencies(${ABE_LSSS_LIB} RELIC::relic relic_project)
endif()

target_link_libraries(${ABE_LSSS_LIB}
    PUBLIC
        OpenSSL::SSL
        RELIC::relic
        gmp
)

# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION /usr/local/include/abe_lsss)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/utils/common.h DESTINATION /usr/local/include/abe_lsss)
install(TARGETS ${ABE_LSSS_LIB} DESTINATION /usr/local/lib)

# Corrige l'include path dans zabe.h
install(CODE "
    file(READ /usr/local/include/abe_lsss/abe/zabe.h CONTENT)
    string(REPLACE \"#include \\\"../../utils/common.h\\\"\" \"#include \\\"../common.h\\\"\" MODIFIED_CONTENT \"\${CONTENT}\")
    file(WRITE /usr/local/include/abe_lsss/abe/zabe.h \"\${MODIFIED_CONTENT}\")
")

# Install RELIC if it is compiled by this project
if(NOT RLC_LIBRARY)
    install(CODE "execute_process(COMMAND ${CMAKE_MAKE_PROGRAM} install WORKING_DIRECTORY ${RELIC_BUILD_DIR})")
endif()

# ------------------------------------------------------------------------------
# Tests optionnels
# ------------------------------------------------------------------------------
option(TESTS "Build the tests" OFF)
if(TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

option(CLI "Build the tests" ON)
if(CLI)
    add_subdirectory(cli)
endif()
