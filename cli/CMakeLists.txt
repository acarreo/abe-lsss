set(ABE_SOURCES
  ../schemes/zcontextcpwaters.cpp
  ../schemes/zcontextkpgpsw.cpp
  ../schemes/abecontext.cpp
)

macro(cli CLI_NAME CLI_FILE)
	add_executable(${CLI_NAME} ${CLI_FILE} common_cli.cpp ${ABE_SOURCES})
    target_link_libraries(${CLI_NAME} PRIVATE ${ABE_LSSS_LIB})
    target_include_directories(${CLI_NAME}
			PRIVATE
				${PROJECT_SOURCE_DIR}/include
				${CMAKE_CURRENT_SOURCE_DIR}
    )
endmacro()

# Commandes CLI
cli(abe-setup   setup.cpp)
cli(abe-keygen  keygen.cpp)
cli(abe-encrypt encrypt.cpp)
cli(abe-decrypt decrypt.cpp)

# Installation
# install(TARGETS
#     abe-setup
#     abe-keygen
#     abe-encrypt
#     abe-decrypt
#     DESTINATION bin
# )
