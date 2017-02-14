librtcdcpp - A Simple WebRTC DataChannels Library
=================================================

librtcdcpp is a simple C++ implementation of the WebRTC DataChannels API.

It was originally written by [Andrew Gault](https://github.com/abgault) and [Nick Chadwick](https://github.com/chadnickbok), and was inspired in no small part by [librtcdc](https://github.com/xhs/librtcdc)

Its goal is to be the easiest way to build native WebRTC DataChannels apps across PC/Mac/Linux/iOS/Android.

Why
---

Because building the WebRTC libraries from Chromium can be a real PITA, and slimming it down to just DataChannels can be really tough.


Dependencies
------------

 - libnice - https://github.com/libnice/libnice
 - usrsctp - https://github.com/sctplab/usrsctp
 - openssl - https://www.openssl.org/
 - spdlog  - https://github.com/gabime/spdlog. Header-only. Optional.

Building
--------

On Linux:

**TODO**: deb and rpm packages

  ./configure
  make
  sudo make install

On Mac:

**TODO**: homebrew integration

  brew install ...
  ./configure
  make
  sudo make install


On Windows:

**TODO**: Visual studio integration, or a script like that jsoncpp library does

 - We recommend you just copy-paste the cpp and hpp files into your own project and go from there


Licensing
---------

BSD style - see the accompanying LICENSE file for more information
