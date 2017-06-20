cd ./usrsctp/usrsctplib/ && make
cd ../../
cd examples/websocket_client/cpslib/
make
cd ../../../
cmake -DUSRSCTP_LIBRARY=./usrsctp/usrsctplib/.libs/libusrsctp.so.1 -DUSRSCTP_INCLUDE_DIR=./usrsctp/usrsctplib -DSPDLOG_INCLUDE_DIR="./spdlog/include/" -DDISABLE_SPDLOG=off -DCMAKE_BUILD_TYPE=Debug
make
