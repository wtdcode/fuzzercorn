cmake_minimum_required(VERSION 3.10)

project(fuzzercorn)

set(PROJECT_IS_TOP_LEVEL OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(PROJECT_IS_TOP_LEVEL ON)
    
    # Enable folder support
    set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

option(BUILD_SHARED_LIBS "Build shared instead of static library" ${PROJECT_IS_TOP_LEVEL})

add_subdirectory(libfuzzer)

add_library(fuzzercorn FuzzerCorn.cpp)

target_include_directories(fuzzercorn PUBLIC include/)

find_package(PkgConfig)
if (PKG_CONFIG_FOUND)
    pkg_check_modules(UNICORN unicorn>=2.0.0)
    if (UNICORN_FOUND)
        target_link_libraries(fuzzercorn PUBLIC ${UNICORN_LIBRARIES})
        target_include_directories(fuzzercorn PUBLIC ${UNICORN_INCLUDE_DIRS})
        target_link_directories(fuzzercorn PUBLIC ${UNICORN_LIBRARY_DIRS})
    else()
        add_subdirectory(unicorn)
        target_link_libraries(fuzzercorn PUBLIC unicorn)
    endif()
else()
    add_subdirectory(unicorn)
    target_link_libraries(fuzzercorn PUBLIC unicorn)
endif()

target_link_libraries(fuzzercorn PUBLIC fuzzer)