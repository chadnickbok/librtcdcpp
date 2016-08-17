# Simple libnice cmake find

set(USRSCTP_DEFINITIONS -DINET -DINET6)
find_path(USRSCTP_INCLUDE_DIR usrsctp.h
          PATH_SUFFICES usrsctp )
find_library(USRSCTP_LIBRARY NAMES usrsctp libusrsctp )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Usrsctp DEFAULT_MSG
                                  USRSCTP_LIBRARY USRSCTP_INCLUDE_DIR)

mark_as_advanced(USRSCTP_INCLUDE_DIR USRSCTP_LIBRARY)

set(USRSCTP_LIBRARIES ${USRSCTP_LIBRARY})
set(USRSCTP_INCLUDE_DIRS ${USRSCTP_INCLUDE_DIR})
