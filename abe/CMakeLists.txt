file(GLOB SOURCES *.cpp)
add_executable(main_out ${SOURCES})

set(LIBRARIES
  lsss_abe
  OpenSSL::SSL
  ${RLC_LIBRARY} gmp
)

target_link_libraries(main_out ${LIBRARIES})
target_include_directories(main_out PRIVATE ${PROJECT_SOURCE_DIR}/include)
