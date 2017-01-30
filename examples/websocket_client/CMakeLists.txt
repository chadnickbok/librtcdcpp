add_executable(testclient
        easywsclient.cpp
        easywsclient.hpp
        testclient.cpp
        WebSocketWrapper.cpp
        WebSocketWrapper.hpp)
target_link_libraries(testclient rtcdcpp)
