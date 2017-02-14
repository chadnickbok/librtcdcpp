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

/**
@file
This is the entry point for all text logging within Drake.
Once you've included this file, the suggested ways you
should write log messages include:
<pre>
  drake::log()->trace("Some trace message: {} {}", something, some_other);
</pre>
Similarly, it provides:
<pre>
  drake::log()->debug(...);
  drake::log()->info(...);
  drake::log()->warn(...);
  drake::log()->error(...);
  drake::log()->critical(...);
</pre>
If you want to log objects that are expensive to serialize, these macros will
not be compiled if debugging is turned off (-DNDEBUG is set):
<pre>
  SPDLOG_TRACE(drake::log(), "message: {}", something_conditionally_compiled);
  SPDLOG_DEBUG(drake::log(), "message: {}", something_conditionally_compiled);
</pre>
The format string syntax is fmtlib; see http://fmtlib.net/3.0.0/syntax.html.
In particular, any class that overloads `operator<<` for `ostream` can be
printed without any special handling.
*/

#include <memory>

#ifdef HAVE_SPDLOG
// Before including spdlog, activate the SPDLOG_DEBUG and SPDLOG_TRACE macros
// if and only if Drake is being compiled in debug mode.  When not in debug
// mode, they are no-ops and their arguments are not evaluated.
#ifndef NDEBUG
#define SPDLOG_DEBUG_ON 1
#define SPDLOG_TRACE_ON 1
#endif
#include <spdlog/spdlog.h>
#include <spdlog/fmt/ostr.h>
#endif

namespace rtcdcpp {

#ifdef HAVE_SPDLOG

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

#endif

std::shared_ptr<Logger> GetLogger(const std::string &logger_name);

}
