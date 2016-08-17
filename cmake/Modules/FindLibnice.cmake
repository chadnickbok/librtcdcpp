# Simple libnice cmake find

find_package(PkgConfig)
pkg_check_modules(PC_LIBNICE nice)
set(LIBNICE_DEFINITIONS ${PC_LIBNICE_CFLAGS_OTHER})

find_path(LIBNICE_INCLUDE_DIR nice/agent.h
          HINTS ${PC_LIBNICE_INCLUDEDIR} ${PC_LIBNICE_INCLUDE_DIRS}
          PATH_SUFFICES libnice )
find_library(LIBNICE_LIBRARY NAMES nice libnice
             HINTS ${PC_LIBNICE_LIBDIR} ${PC_LIBNICE_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Libnice DEFAULT_MSG
                                  LIBNICE_LIBRARY LIBNICE_INCLUDE_DIR)

mark_as_advanced(LIBNICE_INCLUDE_DIR LIBNICE_LIBRARY)

set(LIBNICE_LIBRARIES ${LIBNICE_LIBRARY})
set(LIBNICE_INCLUDE_DIRS ${LIBNICE_INCLUDE_DIR})
