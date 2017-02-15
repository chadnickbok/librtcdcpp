/**
 * Copyright (c) 2017, Andrew Gault, Nick Chadwick and Guillaume Egles.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#pragma once

#include <memory>

#ifndef SPDLOG_DISABLED
#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>
#endif

namespace rtcdcpp {

#ifndef SPDLOG_DISABLED

typedef spdlog::logger Logger;

#else

class Logger {
 public:

  Logger() = default;

  Logger(const Logger &) = delete;
  void operator=(const Logger &) = delete;
  Logger(Logger &&) = delete;
  void operator=(Logger &&) = delete;

  template<typename... Args>
  void trace(const char *fmt, const Args &... args) {}
  template<typename... Args>
  void debug(const char *fmt, const Args &... args) {}
  template<typename... Args>
  void info(const char *fmt, const Args &... args) {}
  template<typename... Args>
  void warn(const char *fmt, const Args &... args) {}
  template<typename... Args>
  void error(const char *fmt, const Args &... args) {}
  template<typename... Args>
  void critical(const char *fmt, const Args &... args) {}

  template<typename T>
  void trace(const T &) {}
  template<typename T>
  void debug(const T &) {}
  template<typename T>
  void info(const T &) {}
  template<typename T>
  void warn(const T &) {}
  template<typename T>
  void error(const T &) {}
  template<typename T>
  void critical(const T &) {}
};

#define SPDLOG_TRACE(logger, ...)
#define SPDLOG_DEBUG(logger, ...)

#endif

std::shared_ptr<Logger> GetLogger(const std::string &logger_name);

}
