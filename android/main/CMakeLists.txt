cmake_minimum_required(VERSION 3.18.1)
project(zfm_client)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SDL_SHARED ON CACHE BOOL "" FORCE)
set(SDL_STATIC OFF CACHE BOOL "" FORCE)
set(SDL_TEST OFF CACHE BOOL "" FORCE)

add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/../SDL2
    ${CMAKE_BINARY_DIR}/SDL2
)

add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/../SDL2_ttf
    ${CMAKE_BINARY_DIR}/SDL2_ttf
)

add_library(main SHARED
    src/client_gui.cpp
)

set_target_properties(main PROPERTIES OUTPUT_NAME "main")

target_compile_definitions(main PRIVATE
    GUI
    MOBILE
)

target_include_directories(main PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

find_library(log-lib log)
find_library(android-lib android)
find_library(opensles-lib OpenSLES)
find_library(egl-lib EGL)
find_library(glesv2-lib GLESv2)

target_link_libraries(main
    SDL2
    SDL2_ttf
    ${android-lib}
    ${log-lib}
    ${opensles-lib}
    ${egl-lib}
    ${glesv2-lib}
)
