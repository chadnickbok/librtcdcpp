cmake_minimum_required (VERSION 2.6)
project (librtcdcpp)

# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# Find GLIB
find_package(GLIB REQUIRED)
include_directories(${GLIB_INCLUDE_DIRS})

# Find usrsctp
find_package(Usrsctp REQUIRED)

# Build our library
include_directories(${CMAKE_SOURCE_DIR}/include)
file(GLOB SOURCES src/*.cpp)
add_library (rtcdcpp SHARED ${SOURCES})
set_property(TARGET rtcdcpp PROPERTY CXX_STANDARD 14)
target_compile_options(rtcdcpp PUBLIC ${USRSCTP_DEFINITIONS})

# Build examples
add_subdirectory (examples/websocket_client)

