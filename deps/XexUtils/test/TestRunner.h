#pragma once

namespace TestRunner
{

typedef std::function<void()> TestFunction;

void Describe(const std::string &sectionName);

void It(const std::string &testName, TestFunction testFunction);

void Run();

void PushError(const std::string &errorMessage);

void PushError(const std::wstring &errorMessage);

}

#define TEST_EQ(expression, value) \
    if ((expression) != (value)) \
    { \
        TestRunner::PushError(static_cast<const std::stringstream &>(std::stringstream() << std::boolalpha << "Expected " << (expression) << " to be " << (value) << " at " << __FILE__ << ":" << __LINE__).str()); \
        return; \
    }

#define TEST_EQ_W(expression, value) \
    if ((expression) != (value)) \
    { \
        TestRunner::PushError(static_cast<const std::wstringstream &>(std::wstringstream() << std::boolalpha << "Expected " << (expression) << " to be " << (value) << " at " << __FILE__ << ":" << __LINE__).str()); \
        return; \
    }

#define TEST_NEQ(expression, value) \
    if ((expression) == (value)) \
    { \
        TestRunner::PushError(static_cast<const std::stringstream &>(std::stringstream() << std::boolalpha << "Expected " << (expression) << " not to be " << (value) << " at " << __FILE__ << ":" << __LINE__).str()); \
        return; \
    }

#define TEST_NEQ_W(expression, value) \
    if ((expression) == (value)) \
    { \
        TestRunner::PushError(static_cast<const std::wstringstream &>(std::wstringstream() << std::boolalpha << "Expected " << (expression) << " not to be " << (value) << " at " << __FILE__ << ":" << __LINE__).str()); \
        return; \
    }

#define TEST_BETWEEN(expression, min, max) \
    if ((expression) < (min) || (expression) > (max)) \
    { \
        TestRunner::PushError(static_cast<const std::stringstream &>(std::stringstream() << std::boolalpha << "Expected " << (expression) << " to be between " << (min) << " and " << (max) << " at " << __FILE__ << ":" << __LINE__).str()); \
        return; \
    }
