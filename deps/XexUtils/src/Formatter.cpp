#include "pch.h"
#include "Formatter.h"

namespace XexUtils
{
namespace Formatter
{

std::string Format(const char *format, ...)
{
    XASSERT(format != nullptr);

    va_list args;
    va_start(args, format);

    char buffer[2048] = {};
    vsnprintf_s(buffer, _TRUNCATE, format, args);

    va_end(args);

    return std::string(buffer);
}

std::wstring Format(const wchar_t *format, ...)
{
    XASSERT(format != nullptr);

    va_list args;
    va_start(args, format);

    wchar_t buffer[2048] = {};
    _vsnwprintf_s(buffer, _TRUNCATE, format, args);

    va_end(args);

    return std::wstring(buffer);
}

std::wstring ToWide(const std::string &narrowString, uint32_t encoding)
{
    int wcharCount = MultiByteToWideChar(encoding, 0, narrowString.c_str(), -1, nullptr, 0);
    std::unique_ptr<wchar_t> wideBuffer(new wchar_t[wcharCount]);

    MultiByteToWideChar(encoding, 0, narrowString.c_str(), -1, wideBuffer.get(), wcharCount);
    std::wstring wideString(wideBuffer.get());

    return wideString;
}

std::string ToNarrow(const std::wstring &wideString, uint32_t encoding)
{
    int charCount = WideCharToMultiByte(encoding, 0, wideString.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::unique_ptr<char> narrowBuffer(new char[charCount]);

    WideCharToMultiByte(encoding, 0, wideString.c_str(), -1, narrowBuffer.get(), charCount, nullptr, nullptr);
    std::string narrowString(narrowBuffer.get());

    return narrowString;
}

}
}
