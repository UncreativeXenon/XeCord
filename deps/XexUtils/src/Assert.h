#pragma once

#ifndef NDEBUG
    /// @brief Triggers a breakpoint in debug builds when a condition is false.
    ///
    /// The assert macro from the standard library doesn't trigger a breakpoint,
    /// even with a debugger attached in Visual Studio so we need create our own.
    #define XASSERT(expr) \
        { \
            if (!(expr)) \
            { \
                printf_s("Assertion failed: %s, file %s, line %d\n", #expr, __FILE__, __LINE__); \
                __debugbreak(); \
            } \
        }
#else
    #define XASSERT(expr)
#endif
