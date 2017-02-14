cmake_minimum_required(VERSION 3.0)

project(librtcdcpp
        VERSION 1.0.0
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_MACOSX_RPATH 1)

# Custom CMake modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake/Modules")

# Find packages
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(Spdlog QUIET)
find_package(OpenSSL REQUIRED)
find_package(LibNice REQUIRED)
find_package(UsrSCTP REQUIRED)

set(LIB_HEADERS
        include/rtcdcpp/Chunk.hpp
        include/rtcdcpp/ChunkQueue.hpp
        include/rtcdcpp/DataChannel.hpp
        include/rtcdcpp/DTLSWrapper.hpp
        include/rtcdcpp/Logging.hpp
        include/rtcdcpp/NiceWrapper.hpp
        include/rtcdcpp/PeerConnection.hpp
        include/rtcdcpp/RTCCertificate.hpp
        include/rtcdcpp/SCTPWrapper.hpp)

set(LIB_SOURCES
        src/DataChannel.cpp
        src/DTLSWrapper.cpp
        src/Logging.cpp
        src/NiceWrapper.cpp
        src/PeerConnection.cpp
        src/RTCCertificate.cpp
        src/SCTPWrapper.cpp)

add_library(rtcdcpp SHARED
        ${LIB_HEADERS}
        ${LIB_SOURCES})

if (SPDLOG_FOUND)
    message(STATUS "Found Spdlog. Use it!")
    target_compile_definitions(rtcdcpp PUBLIC -DHAVE_SPDLOG)
    target_link_libraries(rtcdcpp PUBLIC Gabime::Spdlog)
else ()
    message(WARN "No Spdlog found. Use stubbed out logging")
endif ()

target_include_directories(rtcdcpp
        PUBLIC
        ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(rtcdcpp
        PUBLIC
        LibNice::LibNice
        SctpLab::UsrSCTP
        OpenSSL::SSL
        Threads::Threads)

# Declare a namespaced alias for used in other projects
add_library(LibRtcdcpp::LibRtcdcpp ALIAS rtcdcpp)

# Build examples
add_subdirectory(examples/websocket_client)
