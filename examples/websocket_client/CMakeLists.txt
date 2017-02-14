add_executable(testclient
        json/json.h
        json/json-forwards.h
        easywsclient.cpp
        easywsclient.hpp
        jsoncpp.cpp
        testclient.cpp
        WebSocketWrapper.cpp
        WebSocketWrapper.hpp)

target_link_libraries(testclient rtcdcpp)
