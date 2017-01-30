#   CMake module to find LOG4CXX library
if (NOT TARGET Apache::Log4cxx)
    include(FindPkgConfig)
    pkg_check_modules(PC_LOG4CXX liblog4cxx)

    find_path(LOG4CXX_INCLUDE_DIRS
            NAMES log4cxx/log4cxx.h
            HINTS $ENV{LOG4CXX_DIR}/include
            ${PC_LOG4CXX_INCLUDE_DIRS}
            PATHS /usr/local/include
            /usr/include)

    find_library(LOG4CXX_LIBRARIES
            NAMES log4cxx
            HINTS $ENV{LOG4CXX_DIR}/lib
            ${PC_LOG4CXX_LIBRARIES}
            PATHS /usr/local/lib
            /usr/local/lib64
            /usr/lib
            /usr/lib64
            /usr/lib/x86_64-linux-gnu)

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LOG4CXX DEFAULT_MSG LOG4CXX_LIBRARIES LOG4CXX_INCLUDE_DIRS)
    mark_as_advanced(LOG4CXX_LIBRARIES LOG4CXX_INCLUDE_DIRS)

    if (LOG4CXX_FOUND)
        add_library(Apache::Log4cxx UNKNOWN IMPORTED)
        set_target_properties(Apache::Log4cxx PROPERTIES
                IMPORTED_LOCATION "${LOG4CXX_LIBRARIES}"
                INTERFACE_INCLUDE_DIRECTORIES "${LOG4CXX_INCLUDE_DIRS}"
                IMPORTED_LINK_INTERFACE_LANGUAGES "C")
    endif ()
endif ()
