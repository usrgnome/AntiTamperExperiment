# Use a fresh directory so previous payload files cannot hide a dependency.
string(RANDOM LENGTH 12 run_id)
set(run_dir "${TEST_ROOT}/${run_id}")
file(MAKE_DIRECTORY "${run_dir}")
configure_file("${EXE}" "${run_dir}/detour_check.exe" COPYONLY)
execute_process(COMMAND "${run_dir}/detour_check.exe" --self-test
    WORKING_DIRECTORY "${run_dir}" RESULT_VARIABLE result
    OUTPUT_VARIABLE output ERROR_VARIABLE errors TIMEOUT 10)
message(STATUS "${output}")
if(NOT "${result}" STREQUAL "0")
    message(FATAL_ERROR "Standalone EXE failed (${result}): ${errors}")
endif()
