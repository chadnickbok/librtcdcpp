cmake_minimum_required (VERSION 2.6)
project (librtcdcpp)

set(CMAKE_MACOSX_RPATH 1)

# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# Find GLIB

# Find packages
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(Log4cxx REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(GLIB REQUIRED COMPONENTS gio gobject gmodule gthread)
find_package(Libnice REQUIRED)
find_package(Usrsctp REQUIRED)

# Build our library
include_directories(${CMAKE_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR} ${GLIB_INCLUDE_DIRS} ${LIBNICE_INCLUDE_DIRS})
file(GLOB SOURCES src/*.cpp)
add_library (rtcdcpp SHARED ${SOURCES})
set_property(TARGET rtcdcpp PROPERTY CXX_STANDARD 14)
target_link_libraries(rtcdcpp Threads::Threads)
target_link_libraries(rtcdcpp ${LOG4CXX_LIBRARIES})
target_link_libraries(rtcdcpp ${OPENSSL_LIBRARIES})
MESSAGE ( STATUS "GLIB_LIBRARIES:  " ${GLIB_LIBRARIES})
MESSAGE ( STATUS "GLIB_GOBJECT_LIBRARIES:  " ${GLIB_GOBJECT_LIBRARIES})
target_link_libraries(rtcdcpp ${GLIB_LIBRARIES} ${GLIB_GOBJECT_LIBRARIES})
target_link_libraries(rtcdcpp ${LIBNICE_LIBRARIES})
target_link_libraries(rtcdcpp ${USRSCTP_LIBRARIES})
target_compile_options(rtcdcpp PUBLIC ${USRSCTP_DEFINITIONS} ${OPENSSL_DEFINITIONS})

# Build examples
add_subdirectory (examples/websocket_client)
