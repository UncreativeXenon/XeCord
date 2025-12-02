#pragma once

namespace XexUtils
{
namespace Formatter
{

/// @brief Creates an `std::string` from a printf-like format.
/// @param format The printf-like format.
/// @param ... The variadic arguments, one for each specifier from the `format`.
/// @return An `std::string`.
std::string Format(const char *format, ...);

/// @brief Creates an `std::wstring` from a wprintf-like format.
/// @param format The wprintf-like format.
/// @param ... The variadic arguments, one for each specifier from the `format`.
/// @return An `std::wstring`.
std::wstring Format(const wchar_t *format, ...);

/// @brief Converts an `std::string` into an `std::wstring`.
/// @param narrowString The `std::string`.
/// @param encoding The code page used to perform the conversion (`CP_ACP` by default).
/// @return The `std::wstring`.
std::wstring ToWide(const std::string &narrowString, uint32_t encoding = CP_ACP);

/// @brief Converts an `std::wstring` into an `std::string`.
/// @param wideString The `std::wstring`.
/// @param encoding The code page used to perform the conversion (`CP_ACP` by default).
/// @return The `std::string`.
std::string ToNarrow(const std::wstring &wideString, uint32_t encoding = CP_ACP);

}
}
