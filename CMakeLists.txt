cmake_minimum_required (VERSION 3.0)
project( NetFilter )

add_definitions( "-Wall -g3 -pthread -std=c++17" )

set( PROJECT_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/src")
set( CMAKE_LIBRARY_PATH "${CMAKE_SOURCE_DIR}/src")

add_subdirectory(src)
add_subdirectory(tests)
