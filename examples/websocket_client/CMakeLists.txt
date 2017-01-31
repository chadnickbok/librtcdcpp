if (CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    file(COPY logging.cfg DESTINATION ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
else ()
    file(COPY logging.cfg DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif ()

add_executable(testclient
        json/json.h
        json/json-forwards.h
        easywsclient.cpp
        easywsclient.hpp
        jsoncpp.cpp
        logging.cfg
        testclient.cpp
        WebSocketWrapper.cpp
        WebSocketWrapper.hpp)

target_link_libraries(testclient rtcdcpp)
