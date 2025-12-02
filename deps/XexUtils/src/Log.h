#pragma once

namespace XexUtils
{
namespace Log
{

/// @brief Equivalent to `printf` but with a final new line character (`\n`).
/// @param format The printf-like format.
/// @param ... The variadic arguments, one for each specifier from the `format`.
void Print(const char *format, ...);

/// @brief Writes `message` to `stdout` followed by a final new line character (`\n`).
/// @param message The message.
void Print(const std::string &message);

/// @brief Equivalent to `wprintf` but with a final new line character (`\n`).
/// @param format The wprintf-like format.
/// @param ... The variadic arguments, one for each specifier from the `format`.
void Print(const wchar_t *format, ...);

/// @brief Writes `message` to `stdout` followed by a final new line character (`\n`).
/// @param message The message.
void Print(const std::wstring &message);

}
}

#ifndef NDEBUG
    /// @brief Calls `Log::Print` with `format` and the variadic arguments only in debug
    /// builds.
    #define DebugPrint(format, ...) XexUtils::Log::Print(format, __VA_ARGS__)
#else
    #define DebugPrint(format, ...)
#endif
