cmake_minimum_required(VERSION 3.10)
project(abe-lsss VERSION 2.1 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# ------------------------------------------------------------------------------
# Options et standards
# ------------------------------------------------------------------------------
set(ABE_LSSS_LIB "abe_lsss")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(-Wall)

set(RELIC_CURVE "bls12-381" CACHE STRING "Courbe RELIC à compiler (ex: bls12-381, bn254, etc)")
set(RELIC_TAG "0.6.0" CACHE STRING "Version ou tag RELIC à compiler")
set(RELIC_ARITH "" CACHE STRING "Surcharge ARITH de RELIC (ex: gmp, nécessaire sur macOS car l'assembleur x64 est ELF)")
if(RELIC_ARITH)
    set(RELIC_ARITH_FLAG "-DARITH=${RELIC_ARITH} ")
endif()

# ------------------------------------------------------------------------------
# Dépendances système
# ------------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_library(GMP_LIBRARY NAMES gmp)
if(NOT GMP_LIBRARY)
    message(FATAL_ERROR "GMP library not found")
endif()
add_library(GMP::GMP UNKNOWN IMPORTED GLOBAL)
set_target_properties(GMP::GMP PROPERTIES IMPORTED_LOCATION ${GMP_LIBRARY})
find_library(RLC_LIBRARY NAMES relic)
find_path(RLC_INCLUDE_DIR NAMES relic.h PATH_SUFFIXES relic)

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
    # Les dossiers d'include doivent exister dès la configuration (cible importée exportée)
    file(MAKE_DIRECTORY ${RELIC_SRC_DIR}/include ${RELIC_BUILD_DIR}/include)

    ExternalProject_Add(
        relic_project
        GIT_REPOSITORY https://github.com/relic-toolkit/relic.git
        GIT_TAG ${RELIC_TAG}

        PREFIX ${CMAKE_BINARY_DIR}/relic
        SOURCE_DIR ${RELIC_SRC_DIR}
        BINARY_DIR ${RELIC_BUILD_DIR}

        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E echo "Running RELIC preset..."
        BUILD_COMMAND
            ${RELIC_SRC_DIR}/preset/x64-pbc-${RELIC_CURVE}.sh "-DCMAKE_POLICY_VERSION_MINIMUM=3.5 ${RELIC_ARITH_FLAG}-DSHLIB=ON -DSTBIN=OFF -DTESTS=OFF -DBENCH=OFF ${RELIC_SRC_DIR}"
            && ${CMAKE_MAKE_PROGRAM} -C ${RELIC_BUILD_DIR} -j

        INSTALL_COMMAND ""

				BUILD_BYPRODUCTS ${RELIC_BUILD_DIR}/lib/librelic.so
				UPDATE_COMMAND ""
    )

    # Déclare la librairie importée
    add_library(RELIC::relic SHARED IMPORTED GLOBAL)
    set_target_properties(RELIC::relic PROPERTIES
        IMPORTED_LOCATION ${RELIC_BUILD_DIR}/lib/librelic.so
        INTERFACE_INCLUDE_DIRECTORIES "${RELIC_SRC_DIR}/include;${RELIC_BUILD_DIR}/include"
    )
    add_dependencies(RELIC::relic relic_project)

else()
    # RELIC système trouvé
    # NOTE: Pour l'instant, je suppose que la lib trouvée est dynamique.
    # TODO: Gérer proporement cela
    add_library(RELIC::relic SHARED IMPORTED GLOBAL)

    if(NOT RLC_INCLUDE_DIR)
        message(FATAL_ERROR "RELIC headers not found")
    endif()
    set_target_properties(RELIC::relic PROPERTIES
        IMPORTED_LOCATION ${RLC_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES "${RLC_INCLUDE_DIR}"
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
    schemes/zcontextcpwaters.cpp
    schemes/zcontextkpgpsw.cpp
    schemes/abecontext.cpp
    src/lsss/zparser.tab.cc
    utils/utils.cpp
)

# Crée la target avant d'ajouter les includes
add_library(${ABE_LSSS_LIB} SHARED ${SOURCE_FILES})

# Ajoute les include dirs du projet
target_include_directories(${ABE_LSSS_LIB} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    # "${CMAKE_CURRENT_SOURCE_DIR}/utils"
)

# Assure que RELIC est compilé avant ABE_LSSS.
if(NOT RLC_LIBRARY)
    add_dependencies(${ABE_LSSS_LIB} RELIC::relic relic_project)
endif()

target_link_libraries(${ABE_LSSS_LIB}
    PUBLIC
        OpenSSL::SSL
        RELIC::relic
        GMP::GMP
)

# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS ${ABE_LSSS_LIB}
    EXPORT abe-lsssTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

configure_package_config_file(
    cmake/abe-lsss-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/abe-lsss-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/abe-lsss)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/abe-lsss-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(EXPORT abe-lsssTargets
    FILE abe-lsss-targets.cmake
    NAMESPACE abe-lsss::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/abe-lsss)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/abe-lsss-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/abe-lsss-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/abe-lsss)

configure_file(cmake/abe-lsss.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/abe-lsss.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/abe-lsss.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Install RELIC if it is compiled by this project
if(NOT RLC_LIBRARY)
    install(CODE "
        execute_process(
            COMMAND \"${CMAKE_COMMAND}\"
                -DCMAKE_INSTALL_PREFIX=\${CMAKE_INSTALL_PREFIX}
                -P \"${RELIC_BUILD_DIR}/cmake_install.cmake\"
            RESULT_VARIABLE relic_install_result
        )
        if(NOT relic_install_result EQUAL 0)
            message(FATAL_ERROR \"Failed to install the bundled RELIC dependency\")
        endif()
    ")
endif()

# ------------------------------------------------------------------------------
# Tests optionnels
# ------------------------------------------------------------------------------
option(TESTS "Build the tests" OFF)
if(BUILD_TESTS)
    set(TESTS ON)
endif()
if(TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

option(CLI "Build the CLI tools" ON)
if(CLI)
    add_subdirectory(cli)
endif()

option(BENCH "Build the benchmarks" OFF)
if(BENCH)
    find_package(benchmark REQUIRED)
    add_subdirectory(bench)
endif()
