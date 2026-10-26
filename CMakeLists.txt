cmake_minimum_required(VERSION 3.20)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not supported. Configure with: cmake -S . -B build -A x64")
endif()
project(EncryptedPagesLab LANGUAGES CXX)
if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This lab requires Windows x64 and MSVC. Configure with -A x64.")
endif()
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
foreach(payload IN ITEMS integrity game)
    add_library(${payload}_code OBJECT ${payload}_payload.cpp)
    target_compile_features(${payload}_code PRIVATE cxx_std_17)
    target_compile_options(${payload}_code PRIVATE /W4 /EHsc /Gy- /GL- /Ob0 /JMC-)
    set_property(TARGET ${payload}_code PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
    if(payload STREQUAL "integrity")
        set(section .integr)
        # Only the mapped kernel must avoid EXE cookie/CFG helper references.
        target_compile_options(${payload}_code PRIVATE /GS- /guard:cf-)
    else()
        set(section .game)
    endif()
    set(mapped "${CMAKE_CURRENT_BINARY_DIR}/mapped/$<CONFIG>/${payload}.obj")
    add_custom_command(OUTPUT "${mapped}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/mapped/$<CONFIG>"
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/pack_payload.py" place
            "$<TARGET_OBJECTS:${payload}_code>" "${mapped}" ${section}
        DEPENDS ${payload}_code $<TARGET_OBJECTS:${payload}_code> "${CMAKE_CURRENT_SOURCE_DIR}/pack_payload.py"
        COMMAND_EXPAND_LISTS VERBATIM)
    list(APPEND mapped_objects "${mapped}")
endforeach()
add_executable(detour_check_linked loader.cpp integrity_host.cpp IntegrityVeh.cpp ProtectedIntegrity.cpp ${mapped_objects})
set_source_files_properties(${mapped_objects} PROPERTIES GENERATED TRUE EXTERNAL_OBJECT TRUE)
target_compile_features(detour_check_linked PRIVATE cxx_std_17)
target_compile_options(detour_check_linked PRIVATE /W4 /EHsc /Ob0 /Gy- /GL-)
target_link_libraries(detour_check_linked PRIVATE bcrypt)
target_link_options(detour_check_linked PRIVATE /INCREMENTAL:NO /OPT:NOICF /SECTION:.integr,ER /SECTION:.game,ERW)
set_target_properties(detour_check_linked PROPERTIES
    OUTPUT_NAME detour_check_unsealed
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/unsealed")
set(sealed_exe "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/detour_check.exe")
add_custom_target(detour_check ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>"
    COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/pack_payload.py" seal
        "$<TARGET_FILE:detour_check_linked>" "${sealed_exe}"
    DEPENDS detour_check_linked "${CMAKE_CURRENT_SOURCE_DIR}/pack_payload.py"
    BYPRODUCTS "${sealed_exe}" VERBATIM)
enable_testing()
add_executable(veh_integrity_tests test_veh_integrity.cpp IntegrityVeh.cpp)
target_compile_features(veh_integrity_tests PRIVATE cxx_std_17)
target_compile_options(veh_integrity_tests PRIVATE /W4 /EHsc)
add_test(NAME veh_integrity_policy COMMAND veh_integrity_tests)
add_test(NAME loader_self_test COMMAND "${sealed_exe}" --self-test)
add_test(NAME standalone_exe COMMAND ${CMAKE_COMMAND}
    "-DEXE=${sealed_exe}" "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/standalone/$<CONFIG>"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/test_standalone.cmake")
