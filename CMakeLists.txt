cmake_minimum_required (VERSION 2.6)
project (librtcdcpp)

# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# Find GLIB
find_package(GLIB REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS})

# Build our library
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
file(GLOB SOURCES src/*.cpp)
add_library (rtcdcpp SHARED ${SOURCES})
set_property(TARGET rtcdcpp PROPERTY CXX_STANDARD 14)
