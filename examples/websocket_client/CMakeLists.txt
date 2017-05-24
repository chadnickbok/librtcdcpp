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

add_executable(testclientoffer
        json/json.h
        json/json-forwards.h
        easywsclient.cpp
        easywsclient.hpp
        jsoncpp.cpp
        testclient_offer.cpp
        WebSocketWrapper.cpp
        WebSocketWrapper.hpp)
target_link_libraries(testclientoffer rtcdcpp)

add_executable(testclientanswer
        json/json.h
        json/json-forwards.h
        easywsclient.cpp
        easywsclient.hpp
        jsoncpp.cpp
        testclient_answer.cpp
        WebSocketWrapper.cpp
        WebSocketWrapper.hpp)
target_link_libraries(testclientanswer rtcdcpp)
