
################################################################################
macro (add_bench BENCH_NAME CUSTOM_TARGET_NAME BENCH_FILE)
  add_executable(${BENCH_NAME} ${BENCH_FILE} ${BENCH_UTILS_SOURCE_FILE})
  target_link_libraries(${BENCH_NAME} PRIVATE ${ABE_LSSS_LIB} benchmark::benchmark)
  target_include_directories(${BENCH_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/include)
  add_custom_target(${CUSTOM_TARGET_NAME} COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${BENCH_NAME})
endmacro()

# Function to create a custom command for benchmarking efficiency
function(add_benchmark_target target_name)
  add_custom_command(
    OUTPUT run_${target_name}
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${target_name}
            --benchmark_out=${target_name}.json
            --benchmark_time_unit=ms
            --benchmark_counters_tabular=true
    DEPENDS ${target_name}
    COMMENT "Running ${target_name} benchmark"
  )
  add_custom_target(${target_name}_target DEPENDS run_${target_name})
endfunction()
################################################################################

set(BENCH_UTILS_SOURCE_FILE
  ../schemes/zcontextcpwaters.cpp
  ../schemes/zcontextkpgpsw.cpp
  ../schemes/abecontext.cpp
  ../utils/utils.cpp
)

if(BENCH)
add_bench(bench_policy policy bench-policy.cpp)
add_bench(bench_abe abe bench-abe.cpp)

add_benchmark_target(bench_policy)
add_benchmark_target(bench_abe)

add_custom_target(benchmarks
  DEPENDS
          # bench_policy_target
          bench_abe_target
  COMMENT "Running all benchmarks"
)
endif()
